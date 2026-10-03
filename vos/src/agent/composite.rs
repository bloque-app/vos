//! Composite invocations: one Linear transition across several of an
//! Agent's own actors.
//!
//! A composite rides on an ordinary Linear invocation, its **primary**. The
//! caller attaches one caller-availability blob that starts with
//! [`COMPOSITE_MAGIC`]: an ordered list of **steps**, each a Linear method of
//! an actor installed in the same Agent. A runtime built with
//! `runtime-composite` runs the primary as usual and then, in the same
//! invocation and against the state the primary left, every step in order.
//! The primary's one retained result covers the whole composite, so exact
//! retry, acknowledgement and recovery are those of any invocation.
//!
//! - **Atomic**: every step applies, or nothing does (not even the primary).
//! - **Isolated**: each step commits or is rolled back on its own. A step
//!   whose gas the invocation no longer has is **deferred**, not run, so a
//!   batch never loses its applied prefix to the gas cap.
//!
//! Two per-step markers give ordering and exactly-once delivery:
//!
//! - an **order key**: steps with the same key keep their submission order.
//!   Once one is not applied (deferred, waiting, failed), every later step
//!   with that key is deferred, so nothing overtakes it (a payer's debits).
//! - a **stream**: `(stream id, sequence)`. The runtime keeps each stream's
//!   last applied sequence in its own state. A step applies only at the
//!   successor of that head; a repeat is reported as a duplicate and not run,
//!   and a step past a gap waits. The head advances in the step's own commit.
//!
//! This module is the wire format only: hosts build composites with it and
//! read their replies. The engine is `wire::composite_engine`.

use alloc::vec::Vec;

/// First bytes of a composite blob.
pub const COMPOSITE_MAGIC: [u8; 4] = *b"VCMP";
/// First bytes of a composite's reply.
pub const COMPOSITE_REPLY_MAGIC: [u8; 4] = *b"VCRP";
/// Wire version of both.
pub const COMPOSITE_VERSION: u16 = 1;
/// Most steps in one composite.
/// Bounded so that a reply with every step's digest fits the 8-KiB retained result.
pub const MAX_COMPOSITE_STEPS: usize = 128;

/// How a composite's steps commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CompositeMode {
    /// All steps, and the primary, or nothing.
    Atomic = 0,
    /// Each step on its own; out-of-gas steps are deferred.
    Isolated = 1,
}

/// One step: a Linear method of one of the Agent's own actors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositeStep {
    /// The installed actor. Its incarnation, deployment and program are the
    /// directory's, never the caller's.
    pub actor: [u8; 32],
    /// Actor gas this step may use, drawn from the invocation's remainder.
    pub gas: u64,
    /// Steps with the same key keep their order (`None`: unordered).
    pub order: Option<[u8; 32]>,
    /// A numbered message: applied once, at its stream's next sequence.
    pub stream: Option<([u8; 32], u64)>,
    /// The method call, as the actor's own message (`TAG_DYNAMIC` ‖ Msg).
    pub message: Vec<u8>,
}

/// A composite: a mode and its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composite {
    pub mode: CompositeMode,
    pub steps: Vec<CompositeStep>,
}

/// What became of one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// Ran to `Done` and committed.
    Applied,
    /// Its stream had already applied this sequence: not run.
    Duplicate,
    /// Its stream's head is further behind: not run, waits for the gap.
    Waiting,
    /// Not run: no gas left for it, or an earlier step with its order key
    /// was not applied.
    Deferred,
    /// Ran, and ended Forbidden (1), Panicked (2), OutOfGas (3) or Yielded (4).
    Failed(u8),
    /// Refused before running: the code names the reason ([`refusal`]).
    Refused(u8),
}

/// Reasons a step is refused before it runs.
pub mod refusal {
    pub const NOT_INSTALLED: u8 = 1;
    pub const SUSPENDED: u8 = 2;
    pub const NOT_LINEAR: u8 = 3;
    pub const PROGRAM_UNAVAILABLE: u8 = 4;
    pub const ARTIFACT_UNAVAILABLE: u8 = 5;
    pub const UNSUPPORTED_METHOD: u8 = 6;
    pub const NOT_AUTHORIZED: u8 = 7;
    pub const INVALID_OUTPUT: u8 = 8;
    pub const CAPACITY: u8 = 9;
    pub const OTHER: u8 = 10;
}

/// One step's line in a composite's reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepReport {
    pub outcome: StepOutcome,
    pub gas_used: u64,
    /// The actor's reply bytes, or their 32-byte digest when the whole reply
    /// would not fit the retained result ([`CompositeReply::digested`]).
    pub reply: Vec<u8>,
}

/// A composite's reply: the primary's own reply, then one line per step
/// considered (a failed Atomic composite stops at its failing step).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositeReply {
    /// Step replies are BLAKE2b-256 digests, not bytes.
    pub digested: bool,
    pub primary: Vec<u8>,
    pub steps: Vec<StepReport>,
}

/// Malformed composite or reply bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompositeDecodeError;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CompositeDecodeError> {
        if self.0.len() < n {
            return Err(CompositeDecodeError);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, CompositeDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CompositeDecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, CompositeDecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CompositeDecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn fixed(&mut self) -> Result<[u8; 32], CompositeDecodeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, CompositeDecodeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(CompositeDecodeError);
        }
        Ok(self.take(len)?.to_vec())
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

const ORDER: u8 = 1;
const STREAM: u8 = 2;

impl Composite {
    /// Canonical bytes of the composite blob.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COMPOSITE_MAGIC);
        out.extend_from_slice(&COMPOSITE_VERSION.to_le_bytes());
        out.push(self.mode as u8);
        out.extend_from_slice(&(self.steps.len() as u16).to_le_bytes());
        for step in &self.steps {
            out.extend_from_slice(&step.actor);
            out.extend_from_slice(&step.gas.to_le_bytes());
            let flags = step.order.map_or(0, |_| ORDER) | step.stream.map_or(0, |_| STREAM);
            out.push(flags);
            if let Some(order) = &step.order {
                out.extend_from_slice(order);
            }
            if let Some((stream, sequence)) = &step.stream {
                out.extend_from_slice(stream);
                out.extend_from_slice(&sequence.to_le_bytes());
            }
            put_bytes(&mut out, &step.message);
        }
        out
    }

    /// Decode exactly one canonical composite blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompositeDecodeError> {
        let mut reader = Reader(bytes);
        if reader.take(4)? != COMPOSITE_MAGIC || reader.u16()? != COMPOSITE_VERSION {
            return Err(CompositeDecodeError);
        }
        let mode = match reader.u8()? {
            0 => CompositeMode::Atomic,
            1 => CompositeMode::Isolated,
            _ => return Err(CompositeDecodeError),
        };
        let count = reader.u16()? as usize;
        if count == 0 || count > MAX_COMPOSITE_STEPS {
            return Err(CompositeDecodeError);
        }
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let actor = reader.fixed()?;
            let gas = reader.u64()?;
            let flags = reader.u8()?;
            if flags & !(ORDER | STREAM) != 0 || gas == 0 {
                return Err(CompositeDecodeError);
            }
            let order = (flags & ORDER != 0).then(|| reader.fixed()).transpose()?;
            let stream = if flags & STREAM != 0 {
                let id = reader.fixed()?;
                let sequence = reader.u64()?;
                if sequence == 0 {
                    return Err(CompositeDecodeError);
                }
                Some((id, sequence))
            } else {
                None
            };
            let message = reader.bytes(crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES)?;
            steps.push(CompositeStep {
                actor,
                gas,
                order,
                stream,
                message,
            });
        }
        if !reader.0.is_empty() {
            return Err(CompositeDecodeError);
        }
        Ok(Self { mode, steps })
    }
}

impl StepOutcome {
    fn code(self) -> (u8, u8) {
        match self {
            Self::Applied => (0, 0),
            Self::Duplicate => (1, 0),
            Self::Waiting => (2, 0),
            Self::Deferred => (3, 0),
            Self::Failed(status) => (4, status),
            Self::Refused(reason) => (5, reason),
        }
    }

    fn of(code: u8, detail: u8) -> Result<Self, CompositeDecodeError> {
        Ok(match (code, detail) {
            (0, 0) => Self::Applied,
            (1, 0) => Self::Duplicate,
            (2, 0) => Self::Waiting,
            (3, 0) => Self::Deferred,
            (4, status) => Self::Failed(status),
            (5, reason) => Self::Refused(reason),
            _ => return Err(CompositeDecodeError),
        })
    }

    /// Whether the step's effects are in the state (applied, or applied by
    /// an earlier delivery).
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied | Self::Duplicate)
    }
}

impl CompositeReply {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COMPOSITE_REPLY_MAGIC);
        out.extend_from_slice(&COMPOSITE_VERSION.to_le_bytes());
        out.push(u8::from(self.digested));
        put_bytes(&mut out, &self.primary);
        out.extend_from_slice(&(self.steps.len() as u16).to_le_bytes());
        for step in &self.steps {
            let (code, detail) = step.outcome.code();
            out.push(code);
            out.push(detail);
            out.extend_from_slice(&step.gas_used.to_le_bytes());
            put_bytes(&mut out, &step.reply);
        }
        out
    }

    /// Decode a composite's reply.
    pub fn decode(bytes: &[u8]) -> Result<Self, CompositeDecodeError> {
        let mut reader = Reader(bytes);
        if reader.take(4)? != COMPOSITE_REPLY_MAGIC || reader.u16()? != COMPOSITE_VERSION {
            return Err(CompositeDecodeError);
        }
        let digested = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(CompositeDecodeError),
        };
        let primary = reader.bytes(usize::MAX)?;
        let count = reader.u16()? as usize;
        if count > MAX_COMPOSITE_STEPS {
            return Err(CompositeDecodeError);
        }
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let code = reader.u8()?;
            let detail = reader.u8()?;
            let gas_used = reader.u64()?;
            let reply = reader.bytes(usize::MAX)?;
            steps.push(StepReport {
                outcome: StepOutcome::of(code, detail)?,
                gas_used,
                reply,
            });
        }
        if !reader.0.is_empty() {
            return Err(CompositeDecodeError);
        }
        Ok(Self {
            digested,
            primary,
            steps,
        })
    }
}

/// The stream identity aledgent-style hosts use for one sender's numbered
/// messages of one kind: BLAKE2b-256 over a domain, the kind and the sender.
pub fn stream_id(kind: &[u8], sender: &[u8]) -> [u8; 32] {
    crate::service::Hash::digest(b"vos/composite/stream/v1", &[kind, sender]).0
}

/// The invocation identity of a composite's step `index`: derived from the
/// composite's own, never retained or acknowledged on its own.
pub fn step_invocation(composite: &[u8; 32], index: u16) -> [u8; 32] {
    crate::service::Hash::digest(b"vos/composite/step/v1", &[composite, &index.to_le_bytes()]).0
}
