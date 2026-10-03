//! Cooperative single-threaded executor for VOS actor programs.
//!
//! ## Lifecycle entry point
//!
//! Services built with the actor framework expose a single entry at
//! PC=0 — the PVM refine body:
//!
//! - [`run_refine_service`] (`_start`, PC=0): the **pure** refine body.
//!   Reads persisted state via the read-only `READ` hostcall, dispatches
//!   incoming FETCH messages, may issue child `INVOKE`s, and halts with
//!   a [`crate::refine_payload::RefinePayload`] blob in `a0`/`a1`.
//!   Side-effecting hostcalls are *forbidden* at this stage — the
//!   framework's `Context` honours an internal refine-mode flag and
//!   buffers `WRITE`/`TRANSFER`/`PROVIDE`/`NEW` into the payload's
//!   effects list instead of issuing them. The host absorbs that
//!   payload and applies the effects natively (`crate::runtime`); there
//!   is no second PVM invocation.
//!
//! Invoked actors (no `service` feature) use [`run_refine`] instead:
//! one PVM at PC=0 with state delivered as the first FETCH item and the
//! resulting state returned in the reply envelope rather than written
//! to storage.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn noop_raw_waker() -> RawWaker {
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// Create a no-op [`Waker`]. Used by the single-threaded executor and
/// worker entry points to satisfy the `poll` API.
pub fn noop_waker() -> Waker {
    // SAFETY: noop_raw_waker returns a valid RawWaker with a static
    // vtable whose methods are all no-ops (no resources to manage).
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

/// Result of a single poll: either the future completed or it yielded.
pub enum RunResult<T> {
    Complete(T),
    Yielded,
}

/// Poll a future exactly once. Returns `Complete(val)` if ready, `Yielded` if pending.
pub fn try_poll<F: Future>(mut fut: F) -> RunResult<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local that we never move after pinning; it
    // lives until the function returns and is not accessed again.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => RunResult::Complete(val),
        Poll::Pending => RunResult::Yielded,
    }
}

/// Poll a future to completion. Used by worker mode where handlers
/// run natively and can block.
///
/// # Panics
/// Panics if the future yields (`Pending`). Worker handlers should
/// not use `ctx.yield_now()` — yielding is a PVM concept.
pub fn run_blocking<F: Future>(mut fut: F) -> F::Output {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    // SAFETY: same as try_poll — local fut, never moved after pin.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("worker handler yielded — use an async runtime for I/O"),
    }
}

/// A future that yields once then completes.
pub struct Yield {
    yielded: bool,
}

impl Yield {
    /// Returns Pending once, then Ready — real suspension.
    pub fn once() -> Self {
        Self { yielded: false }
    }

    /// Construct the source-level await state after a VOS suspension call.
    /// A restored PVM has already crossed the durable boundary, so its first
    /// poll is immediately ready; the transition-finalization fork still
    /// returns pending and unwinds into its refine output.
    #[cfg(feature = "pvm")]
    pub(crate) fn after_checkpoint(restored: bool) -> Self {
        Self { yielded: restored }
    }
}

impl Future for Yield {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded {
            Poll::Ready(())
        } else {
            this.yielded = true;
            Poll::Pending
        }
    }
}

/// A future returned by `ctx.ask()`.
///
/// Two modes:
/// - **PVM**: `Ready` from the first poll — the synchronous `INVOKE`
///   hostcall has already populated the reply bytes.
/// - **Worker**: wraps a `HostIo` future — yields `Pending` on first
///   poll so the host can fulfill the request, then `Ready` on re-poll.
pub struct Ask {
    inner: AskInner,
}

enum AskInner {
    /// Immediate result (PVM path or error).
    Immediate(Result<alloc::vec::Vec<u8>, super::value::InvokeError>),
    /// Deferred host I/O (worker path).
    HostIo(HostIo),
    /// Deferred invocation with an explicit success/failure frame.
    HostIoResult(HostIo),
    /// Finalization fork of a durable service await. The exact machine snapshot
    /// resumes before this future is constructed, so this variant is never
    /// polled again after a committed reply is injected.
    #[cfg(feature = "pvm")]
    CheckpointPending,
}

impl Ask {
    pub fn ready(result: alloc::vec::Vec<u8>) -> Self {
        Self {
            inner: AskInner::Immediate(Ok(result)),
        }
    }
    pub fn ready_err(err: super::value::InvokeError) -> Self {
        Self {
            inner: AskInner::Immediate(Err(err)),
        }
    }
    pub fn host_io(io: HostIo) -> Self {
        Self {
            inner: AskInner::HostIo(io),
        }
    }
    pub fn host_io_result(io: HostIo) -> Self {
        Self {
            inner: AskInner::HostIoResult(io),
        }
    }
    #[cfg(feature = "pvm")]
    pub(crate) fn checkpoint_pending() -> Self {
        Self {
            inner: AskInner::CheckpointPending,
        }
    }
}

fn decode_reply(
    bytes: alloc::vec::Vec<u8>,
) -> Result<super::value::Value, super::value::InvokeError> {
    if bytes.is_empty() {
        Ok(super::value::Value::Unit)
    } else {
        <super::value::Value as super::codec::Decode>::try_decode(bytes.as_slice())
            .ok_or(super::value::InvokeError::Panicked)
    }
}

impl Future for Ask {
    type Output = Result<super::value::Value, super::value::InvokeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match &mut this.inner {
            AskInner::Immediate(result) => {
                let result = core::mem::replace(result, Err(super::value::InvokeError::Panicked));
                match result {
                    Ok(bytes) => Poll::Ready(decode_reply(bytes)),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            AskInner::HostIo(io) => match Pin::new(io).poll(cx) {
                Poll::Ready(bytes) => Poll::Ready(decode_reply(bytes)),
                Poll::Pending => Poll::Pending,
            },
            AskInner::HostIoResult(io) => match Pin::new(io).poll(cx) {
                Poll::Ready(bytes) => match crate::effects::result::decode(&bytes) {
                    Ok(reply) => Poll::Ready(decode_reply(reply)),
                    Err(crate::actors::run::STATUS_NOT_FOUND) => {
                        Poll::Ready(Err(super::value::InvokeError::NotFound))
                    }
                    Err(crate::actors::run::STATUS_FORBIDDEN) => {
                        Poll::Ready(Err(super::value::InvokeError::Forbidden))
                    }
                    Err(crate::actors::run::STATUS_OOG) => {
                        Poll::Ready(Err(super::value::InvokeError::OutOfGas))
                    }
                    Err(crate::actors::run::STATUS_TOO_BIG) => {
                        Poll::Ready(Err(super::value::InvokeError::TooBig))
                    }
                    Err(crate::actors::run::STATUS_PANICKED) => {
                        Poll::Ready(Err(super::value::InvokeError::Panicked))
                    }
                    Err(status) => Poll::Ready(Err(super::value::InvokeError::Unknown(status))),
                },
                Poll::Pending => Poll::Pending,
            },
            #[cfg(feature = "pvm")]
            AskInner::CheckpointPending => Poll::Pending,
        }
    }
}

/// In an **extension** build, `HostIo` is the executor-backed [`ExecIo`]
/// future: it carries the request bytes and registers them with the
/// per-instance `Exec` (reached via the task waker) instead of a ctx slot, so
/// many tasks can each have an op in flight. The single-slot future below is
/// used for the WASM / plain-host builds, which stay single-task.
#[cfg(feature = "extension")]
pub use crate::actors::exec::ExecIo as HostIo;

/// A future that yields once to let the host fulfill an I/O request,
/// then returns the result on re-poll.
///
/// Used by workers for async host calls (ask, fs_read, etc.).
/// The request is stored in `Context::host_io_request` before this
/// future is created. The host reads it, performs the I/O, writes
/// the result to the result slot, then re-polls.
#[cfg(not(feature = "extension"))]
pub struct HostIo {
    polled: bool,
    result_slot: *mut Option<alloc::vec::Vec<u8>>,
}

#[cfg(not(feature = "extension"))]
impl HostIo {
    /// Create a new HostIo future that reads its result from `result_slot`.
    ///
    /// # Safety contract (enforced by caller, not by this function):
    /// - `result_slot` must point to a valid `Option<Vec<u8>>` that
    ///   outlives this future (guaranteed: it lives in `Context` which
    ///   is owned by `WorkerState` alongside the future).
    /// - The host must write `Some(bytes)` to the slot before the
    ///   second poll (guaranteed: `provide_result` does this).
    /// - Only one `HostIo` is in flight per context at a time
    ///   (guaranteed: single-threaded, one dispatch at a time).
    pub(crate) fn new(result_slot: *mut Option<alloc::vec::Vec<u8>>) -> Self {
        Self {
            polled: false,
            result_slot,
        }
    }
}

#[cfg(not(feature = "extension"))]
impl Unpin for HostIo {}

#[cfg(not(feature = "extension"))]
impl Future for HostIo {
    type Output = alloc::vec::Vec<u8>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<alloc::vec::Vec<u8>> {
        if self.polled {
            // Second poll: host has provided the result.
            // SAFETY: result_slot points into Context which outlives
            // this future (both owned by WorkerState). The host called
            // provide_result before re-polling.
            let result = unsafe { &mut *self.result_slot };
            Poll::Ready(result.take().unwrap_or_default())
        } else {
            // First poll: yield so the host can fulfill the request
            self.polled = true;
            Poll::Pending
        }
    }
}

// ── Refine-mode flag (service framework) ──────────────────────────────

/// Global flag: are we currently inside `run_refine_service`?
///
/// In refine the service platform-pure hostcall table forbids state-mutating calls
/// (`WRITE`, `TRANSFER`, `PROVIDE`, `NEW`). The framework's
/// `Context::flush_effects` checks this flag and, when set, *buffers*
/// effects in the context's pending vectors instead of issuing hostcalls
/// — `run_refine_service` then drains them into the refine output payload,
/// which the host absorbs and applies natively. Service actors run
/// exclusively in refine, so the flag stays set for their whole life.
///
/// Safe because PVM is single-threaded.
#[cfg(feature = "service")]
static mut IN_REFINE: bool = false;

#[cfg(feature = "service")]
pub fn set_refine_mode(v: bool) {
    // SAFETY: PVM is single-threaded; no concurrent access to IN_REFINE.
    unsafe {
        IN_REFINE = v;
    }
}

#[cfg(feature = "service")]
pub fn is_refine_mode() -> bool {
    // SAFETY: PVM is single-threaded; read of static mut bool is sound.
    unsafe { IN_REFINE }
}

/// Stub for non-service builds so framework code can call it unconditionally.
#[cfg(not(feature = "service"))]
pub fn is_refine_mode() -> bool {
    false
}

// ── Halt ──────────────────────────────────────────────────────────────

/// PVM specification dynamic-jump halt address (2^32 - 2^16).
#[cfg(target_arch = "riscv64")]
const PVM_HALT_ADDR: u64 = 0xFFFF_0000;

/// Halt with output data in registers a0 (ptr) and a1 (len).
#[cfg(target_arch = "riscv64")]
fn halt_with_output(data: &[u8]) -> ! {
    // SAFETY: terminal PVM dynamic jump. The host reads `len` bytes from
    // `data.as_ptr()` after observing the GP halt address; the slice is owned
    // by the caller until then. Root REPLY (ecalli 0) is not a halt in PVM:
    // it is reserved for returning from a nested CALL and panics at the root.
    unsafe {
        core::arch::asm!(
            "jr t0",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            in("t0") PVM_HALT_ADDR,
            options(noreturn),
        );
    }
}

/// Halt with output (a0=ptr, a1=len) AND bind a 32-byte ZK actor-IO
/// hash into the final-state register window φ[9..12] (RISC-V a2-a5).
///
/// This is the ZK actor-IO ABI binding mechanism (see [`crate::zk`]).
/// The four little-endian hash words are passed as `in` operands on the
/// PVM specification halt jump, so the compiler materialises them into a2-a5 via
/// real instructions immediately before the jump. The dynamic jump consumes
/// only its target register, so a0-a5 persist unchanged into
/// `final_state.registers`, where the closing chip pins the
/// columns and the verifier's boundary-binding check equates the
/// metadata to them (`vos_pvm_proof::Proof::public_io_hash`). No new hostcall, no
/// tracer/prover cooperation, no register-ledger surgery: it is ordinary
/// register state at halt.  The closing-read column binds to the true
/// final register via the register-ledger read-consistency (cross-row
/// `prev_value` + `(reg, ts)` sortedness + `is_write` limb), which is
/// sound against a from-scratch prover (gate
/// `pvm/proof/tests/ledger_readconsistency_gate.rs`) — see `crate::zk` and
/// `vos_pvm_proof::chips::register_memory_closing`.
///
/// a2→φ[9], a3→φ[10], a4→φ[11], a5→φ[12] per the VOS RISC-V→PVM
/// mapping — the exact window `public_io_hash` reconstructs.
#[cfg(target_arch = "riscv64")]
fn halt_with_output_bound(data: &[u8], io_hash: &[u8; 32]) -> ! {
    let w0 = u64::from_le_bytes([
        io_hash[0], io_hash[1], io_hash[2], io_hash[3], io_hash[4], io_hash[5], io_hash[6],
        io_hash[7],
    ]);
    let w1 = u64::from_le_bytes([
        io_hash[8],
        io_hash[9],
        io_hash[10],
        io_hash[11],
        io_hash[12],
        io_hash[13],
        io_hash[14],
        io_hash[15],
    ]);
    let w2 = u64::from_le_bytes([
        io_hash[16],
        io_hash[17],
        io_hash[18],
        io_hash[19],
        io_hash[20],
        io_hash[21],
        io_hash[22],
        io_hash[23],
    ]);
    let w3 = u64::from_le_bytes([
        io_hash[24],
        io_hash[25],
        io_hash[26],
        io_hash[27],
        io_hash[28],
        io_hash[29],
        io_hash[30],
        io_hash[31],
    ]);
    // SAFETY: terminal PVM dynamic jump. The host reads `len` bytes from
    // `data.as_ptr()` after observing the GP halt address; a2-a5 carry the
    // io-hash (φ[9..12]) and are captured in `final_state`.
    unsafe {
        core::arch::asm!(
            "jr t0",
            in("a0") data.as_ptr() as u64,
            in("a1") data.len() as u64,
            in("a2") w0,
            in("a3") w1,
            in("a4") w2,
            in("a5") w3,
            in("t0") PVM_HALT_ADDR,
            options(noreturn),
        );
    }
}

#[cfg(all(feature = "pvm", not(target_arch = "riscv64")))]
fn halt_with_output(_data: &[u8]) -> ! {
    panic!("halt_with_output is only supported on RISC-V targets");
}

#[cfg(all(feature = "service", not(target_arch = "riscv64")))]
fn halt_with_output_bound(_data: &[u8], _io_hash: &[u8; 32]) -> ! {
    panic!("halt_with_output_bound is only supported on RISC-V targets");
}

/// First byte of a refine exit status / INVOKE reply envelope.
/// Wire-stable discriminants — do not renumber.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeStatus {
    /// Actor processed all messages normally.
    Done = 0x00,
    /// Handler yielded (wants re-invocation).
    Yielded = 0x01,
    /// Child actor trapped (panic / page fault) during invoke.
    Panicked = 0x02,
    /// Target service not found during invoke.
    NotFound = 0x03,
    /// Child actor ran out of gas during invoke.
    OutOfGas = 0x04,
    /// Dispatch-layer auth gate denied the call before the target
    /// ran. Distinct from `Panicked` so a refused caller surfaces
    /// "permission denied" rather than colliding with a real panic.
    Forbidden = 0x05,
    /// Child's reply exceeded the caller's output buffer. Distinct
    /// from `Panicked` so an oversize reply is not misreported as a
    /// crash.
    TooBig = 0x06,
}

pub const STATUS_DONE: u8 = InvokeStatus::Done as u8;
pub const STATUS_YIELDED: u8 = InvokeStatus::Yielded as u8;
pub const STATUS_PANICKED: u8 = InvokeStatus::Panicked as u8;
pub const STATUS_NOT_FOUND: u8 = InvokeStatus::NotFound as u8;
pub const STATUS_OOG: u8 = InvokeStatus::OutOfGas as u8;
pub const STATUS_FORBIDDEN: u8 = InvokeStatus::Forbidden as u8;
pub const STATUS_TOO_BIG: u8 = InvokeStatus::TooBig as u8;

// ── Service refine phase (PC=0, service platform-pure) ─────────────────────────────

/// service platform-pure refine entry for service actors.
///
/// Runs at PC=0. Cannot mutate state — issues only read-only hostcalls.
/// Side effects produced by handlers are buffered in the `Context` and
/// then encoded into a `RefinePayload` which is emitted as the refine
/// output bytes (registers a0/a1).
///
/// Lifecycle:
/// 1. Read persisted state via `READ(STATE_KEY)` (allowed in refine).
/// 2. `load_or_create::<A>(state)`.
/// 3. FETCH and dispatch each pending message; handler effects buffer
///    into `Context::pending_*` because `is_refine_mode() == true`.
/// 4. Encode the new actor state, the buffered effects, and any reply
///    bytes into a `RefinePayload`.
/// 5. `halt_with_output(payload)`.
#[cfg(feature = "service")]
pub fn run_refine_service<A: super::Actor>() {
    use super::context::ServiceId;
    use super::lifecycle::{self, BUF_SIZE, DispatchResult};
    use alloc::boxed::Box;
    use core::ptr::addr_of_mut;

    // Install the PVM `log::Log` impl on the first refine call.
    // `set_logger` returns Err on duplicate install — we ignore it
    // because an exact continuation retains the already-installed logger.
    crate::log_impl::install_pvm_logger();

    set_refine_mode(true);

    let id = lifecycle::service_id();
    let mut ctx = super::Context::new(ServiceId(id));

    // Actor holder. It lives in the PVM's mutable memory, so an exact kernel
    // continuation preserves both this pointer and the referenced allocation.
    // A fresh invocation starts with a zero slot and rehydrates from storage.
    //
    // Cold start (ACTOR_HOLDER == 0): reads STATE_KEY via READ hostcall
    // and deserializes the actor. This is the portable fresh-invocation path.
    //
    // Per-service uniqueness: each service has its own PVM instance
    // with its own mutable memory, so each one gets its own copy of this
    // static — even when two services share the same blob. Type-erased
    // as `usize` because `A` differs per service; safe because PVM is
    // single-threaded.
    static mut ACTOR_HOLDER: usize = 0;
    let holder_ptr = addr_of_mut!(ACTOR_HOLDER);
    let mut cold_start = false;
    // SAFETY: PVM is single-threaded; the static-mut access goes via
    // a raw pointer (no shared/exclusive ref conflict). The cast from
    // `usize` back to `*mut A` is sound because we stamped the slot
    // with a `Box::into_raw(Box::<A>::new(..))` value of the same A.
    let actor_ref: &mut A = unsafe {
        if *holder_ptr == 0 {
            cold_start = true;
            // Cold start: try to restore from persisted state in storage.
            // This is the service platform-compatible path — the guest reads its own
            // serialized state via READ (legal in refine) without any
            // host cooperation. Exact continuation restore skips it because
            // it resumes the existing call stack after the await boundary.
            //
            // The read grows onto the heap when the state outgrew the
            // probe buffer — a fixed-buffer read here would treat a
            // large state as missing and silently resurrect the actor
            // as default, persisting the wipe on the next save.
            let state = lifecycle::read_persisted_state_owned();
            let boxed = Box::new(lifecycle::load_or_create::<A>(state.as_deref()));
            *holder_ptr = Box::into_raw(boxed) as usize;
        }
        &mut *(*holder_ptr as *mut A)
    };
    let mut buf = [0u8; BUF_SIZE];

    // On cold start, run the on_start lifecycle hook before the message
    // loop. If on_start yields, the actor self-schedules and we skip
    // the message loop (same as a yielded dispatch).
    let mut started = true;
    if cold_start {
        match try_poll(actor_ref.on_start(&mut ctx)) {
            RunResult::Yielded => {
                ctx.flush_effects();
                started = false;
            }
            RunResult::Complete(Ok(())) => {}
            RunResult::Complete(Err(e)) => {
                actor_ref.on_error(&e);
                started = false;
            }
        }
    }

    // Dispatch messages. flush_effects() inside dispatch_one is a no-op
    // for service builds — effects accumulate in the context's pending_* vecs.
    if started {
        loop {
            let n = lifecycle::fetch_raw(&mut buf);
            if n == 0 {
                break;
            }
            let result = lifecycle::dispatch_one::<A>(&buf[..n], actor_ref, &mut ctx);
            if matches!(result, DispatchResult::Yielded | DispatchResult::Stopped) {
                break;
            }
        }
    }

    // Pack: state-bytes-from-actor + buffered effects + reply →
    // RefinePayload. Drop temporaries eagerly before halt_with_output
    // (which is `-> !` and never runs destructors).
    //
    // The output buffer is a static Vec reused across exact restores to
    // avoid leaking a fresh allocation on every halt (the `-> !` ecall
    // never runs destructors).
    static mut OUTPUT_BUF: usize = 0;
    let out_ptr = addr_of_mut!(OUTPUT_BUF);
    // SAFETY: same single-threaded PVM invariant as ACTOR_HOLDER —
    // the slot holds a `Box::into_raw(Vec<u8>)` value we stamped on
    // first use.
    let out_buf: &mut alloc::vec::Vec<u8> = unsafe {
        if *out_ptr == 0 {
            *out_ptr = Box::into_raw(Box::new(alloc::vec::Vec::<u8>::new())) as usize;
        }
        &mut *(*out_ptr as *mut alloc::vec::Vec<u8>)
    };
    {
        let new_state_bytes = super::codec::Encode::encode(&*actor_ref);
        let reply_bytes = ctx.take_reply_bytes();
        // Emit the post-dispatch state as the final Write{STATE_KEY}
        // effect only when the blob changed from the anchored state.
        // Genesis always emits: there is no prior blob to be equal to,
        // and the first work-result is what materializes the actor's
        // row.
        // The exact suspension snapshot is captured before the finalize fork
        // drains a checkpoint and advances its anchor. On resume, derive the
        // base from durable storage instead of retaining the pre-commit anchor
        // in VM memory. Non-reentrancy guarantees this is precisely the state
        // committed for the suspended workflow's previous slice.
        let prior_state = lifecycle::read_persisted_state_owned();
        let (plain_anchor_kind, plain_anchor) =
            crate::refine_payload::anchor_for(prior_state.as_deref());
        let prior_state_hash = match &prior_state {
            Some(bytes) if !bytes.is_empty() => crate::refine_payload::state_anchor(bytes),
            _ => [0u8; 32],
        };
        let (anchor_kind, anchor) =
            match A::COMMITTED.then(lifecycle::read_committed_root).flatten() {
                Some(root) => (crate::refine_payload::ANCHOR_SMT_ROOT, root),
                None => (plain_anchor_kind, plain_anchor),
            };
        let new_hash = crate::refine_payload::state_anchor(&new_state_bytes);
        // Empty state is genesis, not a hash anchor — the host's overlay
        // computes `anchor_for(Some(empty)) == GENESIS`, so a fieldless
        // (empty-encoding) actor must carry genesis forward or its next
        // self-message iteration would AnchorMismatch and silently drop.
        let new_is_empty = new_state_bytes.is_empty();
        let state_changed =
            anchor_kind == crate::refine_payload::ANCHOR_GENESIS || new_hash != prior_state_hash;

        // Committed actors: recompute the composite AFTER the handler
        // (the field root rows are current through the overlay) and
        // record it as an ordinary framework row — the host's
        // expected-anchor check reads it next dispatch. Written only
        // when the composite moved, so a pure read stays effect-free
        // (the durable-node rule). Must precede the drain: one drain
        // carries the handles' rows AND this one.
        let (next_kind, next_anchor) = match actor_ref.__committed_root(&new_hash) {
            Some(root) => (crate::refine_payload::ANCHOR_SMT_ROOT, root),
            None if new_is_empty => (crate::refine_payload::ANCHOR_GENESIS, [0u8; 32]),
            None => (crate::refine_payload::ANCHOR_STATE_HASH, new_hash),
        };
        if next_kind == crate::refine_payload::ANCHOR_SMT_ROOT
            && (next_kind, next_anchor) != (anchor_kind, anchor)
        {
            super::storage::store_raw(lifecycle::COMMITTED_ROOT_KEY.to_vec(), next_anchor.to_vec());
        }

        let payload = ctx.drain_into_refine_payload(
            anchor_kind,
            anchor,
            super::storage::end_dispatch(),
            state_changed.then_some(new_state_bytes),
            reply_bytes,
        );
        drop(ctx);
        let encoded = payload.encode();
        out_buf.clear();
        out_buf.extend_from_slice(&encoded);
        // encoded, new_state_bytes, reply_bytes, payload dropped here
    }
    // ZK actor-IO ABI: bind this execution's (public, return) into the
    // final-state register window φ[9..12] as part of the halt (see
    // `crate::zk` and `halt_with_output_bound`).  A handler that called
    // `vos::zk::bind_io` stashed the real `(public, return)` hash; drain
    // it.  Otherwise fall back to the tagless empty-public/empty-return
    // default, so every proof carries a well-defined io-hash (the program
    // commitment, not the io-hash, is what ties a proof to its actor).
    let io_hash =
        crate::zk::__take_pending_io_hash().unwrap_or_else(|| crate::zk::compute_io_hash(&[], &[]));
    halt_with_output_bound(out_buf, &io_hash);
}

// ── Task refine (witness-delivered input, always cold) ───────────────

/// Refine entry for **Task** blobs — anonymous, code-hash-identified
/// pure children (`vos::agent::Tasks`, `Child::Task`).
///
/// Input arrives exclusively through the witness buffer patched into
/// the initial memory image at `witness_ptr` (see [`crate::task_abi`]):
/// no `READ`, no `FETCH` — refine-pure by construction, so the live
/// invocation and a traced re-execution start from byte-identical
/// images and every Task is one `#[provable]` away from being a proof
/// guest.
///
/// Tasks are always cold: no `ACTOR_HOLDER`, no warm restart — a
/// suspended Task is its serialized state in the parent's TaskRecord,
/// and resume is a fresh invocation with that state patched back in.
/// One `(state, msg)` in, one work-result out:
///
/// 1. Decode `(state, msg)` from the witness buffer; anchor over the
///    exact state bytes (genesis when empty).
/// 2. `load_or_create::<A>(state)` and dispatch the single message
///    (effects buffer into the context — refine mode).
/// 3. Halt with the current `RefinePayload`: state as the final
///    `Write{STATE_KEY}` when changed, reply, effects, `continue_next`
///    from `yield_now`/`sleep`.
///
/// An unpatched buffer panics (fail loud): a Task blob is only
/// meaningful under a witness-delivering invoker — running one as a
/// registry service or bare refine is a deployment error, not a case
/// to limp through.
#[cfg(feature = "service")]
pub fn run_task_service<A: super::Actor>(witness_ptr: *const u8, witness_cap: usize) {
    use super::context::ServiceId;
    use super::lifecycle;

    crate::log_impl::install_pvm_logger();
    set_refine_mode(true);

    // SAFETY: the macro-emitted `__VOS_WITNESS` static spans exactly
    // `witness_cap` readable bytes.
    let (state, msg) = unsafe { crate::task_abi::read_task_input(witness_ptr, witness_cap) }
        .expect("task input not patched — Task blobs run only under a witness-delivering invoker");
    // SAFETY: same buffer, same bounds.
    let rows = unsafe { crate::task_abi::read_task_rows(witness_ptr, witness_cap) }
        .expect("task witness rows section malformed");
    // Always seed — even empty. A Task has no live storage (STORAGE_R
    // is an echo stub under the task hostcall table), so an
    // unwitnessed handle read must panic as unproven, never misread
    // the stub.
    super::storage::seed_witness_rows(rows.into_iter().collect());

    let (anchor_kind, anchor) = crate::refine_payload::anchor_for(Some(&state));
    let mut actor = lifecycle::load_or_create::<A>(Some(&state));
    let mut ctx = super::Context::new(ServiceId(0));

    let _ = lifecycle::dispatch_one::<A>(&msg, &mut actor, &mut ctx);

    let new_state_bytes = super::codec::Encode::encode(&actor);
    let reply_bytes = ctx.take_reply_bytes();
    let new_hash = crate::refine_payload::state_anchor(&new_state_bytes);
    let state_changed = anchor_kind == crate::refine_payload::ANCHOR_GENESIS || new_hash != anchor;
    let mut payload = ctx.drain_into_refine_payload(
        anchor_kind,
        anchor,
        super::storage::end_dispatch(),
        state_changed.then_some(new_state_bytes),
        reply_bytes,
    );
    // Provable-Task io-binding (work-result-contract.md §5): the framework
    // — not the handler — composes the io-hash, over the state TRANSITION.
    //   public' = folded_public(anchor_kind, anchor, transition_digest, app_public)
    //   io_hash = H(public', reply)
    // So a Task's proof commits to the anchored input state and the exact
    // applied effects (via the transition digest), plus any app-level
    // public bytes the handler designated with `vos::zk::bind_public`, plus
    // the reply. A verifier reconstructs `public'` identically from the
    // recorded (anchor, digest, app_public) and checks the bound io-hash.
    // bind_io's finished-hash form is not honored for Task blobs — drained
    // so it can't leak — because the handler does not own the composition.
    let _ = crate::zk::__take_pending_io_hash();
    let app_public = crate::zk::__take_pending_public().unwrap_or_default();
    let transition_digest = payload.transition_digest();
    let public_prime = crate::refine_payload::folded_public(
        payload.anchor_kind,
        &payload.anchor,
        &transition_digest,
        &app_public,
    );
    let io_hash = crate::zk::compute_io_hash(&public_prime, &payload.reply);
    // Surface the folded bytes in the payload so the host's record
    // capture can persist what a verifier reconstructs public' from.
    payload.app_public = app_public;
    let encoded = payload.encode();
    halt_with_output_bound(&encoded, &io_hash);
}

/// Execute one canonical actor message as a nested PVM VM and return its service
/// slice result through the move-only IPC DATA capability in slot 0.
///
/// The generic service owns scheduling and transition construction. This
/// entry only materializes the actor from imported bytes, dispatches once,
/// and reports buffered actor writes; it has no persistent host surface.
#[cfg(feature = "service")]
#[unsafe(link_section = ".bss.vos_actor_private")]
static mut ACTOR_PRIVATE_BUFFER: [u8; crate::service::ACTOR_PRIVATE_INPUT_MAX_BYTES] =
    [0; crate::service::ACTOR_PRIVATE_INPUT_MAX_BYTES];

#[cfg(feature = "service")]
pub fn run_nested_actor_service<A: super::Actor>(
    input_address: u64,
    input_len: u64,
    capacity: u64,
) -> ! {
    use super::context::ServiceId;
    use super::lifecycle::{self, DispatchResult};
    use crate::service::{
        ActorCallResult, ActorPrivateInput, ActorSliceInput, ActorSliceOutput, ServiceWire,
    };

    crate::log_impl::install_pvm_logger();
    set_refine_mode(true);
    crate::crdt::reset_actor_slice();

    let expected_address =
        crate::service::ACTOR_IPC_BASE_PAGE as u64 * pvm_page_size_for_guest() as u64;
    let page_size = pvm_page_size_for_guest() as u64;
    let input_len = usize::try_from(input_len).expect("actor IPC input length exceeds usize");
    let capacity = usize::try_from(capacity).expect("actor IPC capacity exceeds usize");
    assert_eq!(
        input_address, expected_address,
        "actor IPC address mismatch"
    );
    assert!(capacity > 0 && capacity.is_multiple_of(page_size as usize));
    assert!(input_len <= capacity);
    let page_count =
        u32::try_from(capacity / page_size as usize).expect("actor IPC page count exceeds u32");
    assert!(crate::abi::pvm::ecall::map_cap_rw(
        0,
        crate::service::ACTOR_IPC_BASE_PAGE,
        page_count,
    ));

    // SAFETY: MAP above established a readable DATA-cap range covering the
    // complete input. The service does not regain this cap until REPLY.
    let bytes = unsafe { core::slice::from_raw_parts(input_address as *const u8, input_len) };
    let input = ActorSliceInput::decode(bytes).expect("invalid actor slice input");
    // SAFETY: each actor VM has an isolated memory image and dispatch is
    // non-reentrant, so this active VM exclusively owns its static buffer.
    let private_buffer = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(ACTOR_PRIVATE_BUFFER).cast::<u8>(),
            crate::service::ACTOR_PRIVATE_INPUT_MAX_BYTES,
        )
    };
    let private_len = usize::try_from(crate::abi::pvm::hostcalls::actor_private_fetch(
        private_buffer,
    ))
    .expect("private actor input length exceeds usize");
    assert!(
        private_len > 0 && private_len <= private_buffer.len(),
        "private actor input exceeds its deterministic bound"
    );
    let ActorPrivateInput {
        actor: actor_id,
        actor_tree,
        external_actors,
        input: work_input,
        change,
        state,
        causal_states,
        active_actor_mask,
        origin,
        origin_service,
        space_role,
        actor_role,
    } = ActorPrivateInput::decode(&private_buffer[..private_len])
        .expect("invalid private actor input");
    assert_eq!(
        input.actor, actor_id,
        "shared actor route does not match the active private VM"
    );
    let ActorSliceInput {
        actor: _,
        first_await_ordinal,
        message,
    } = input;
    let mut actor = lifecycle::load_or_create::<A>(Some(&state));
    for causal_state in causal_states {
        let other = lifecycle::load_or_create::<A>(Some(&causal_state));
        actor
            .__merge_crdt(&other)
            .expect("invalid concurrent CRDT actor materialization");
    }
    // A route-only ServiceId is deliberately not derived by
    // truncating ActorId. Nested service actors retain their complete typed identity
    // in Context and all service scheduler effects use that value.
    let mut ctx = super::Context::new(ServiceId(0));
    ctx.__set_actor_id(actor_id);
    ctx.__set_actor_tree(
        actor_tree,
        external_actors,
        change.map(|change| change.change),
        capacity,
        first_await_ordinal,
        active_actor_mask,
    );
    ctx.__set_origin(origin, None, origin_service);
    ctx.set_caller_roles(space_role, actor_role);

    assert_eq!(
        A::CRDT,
        change.is_some(),
        "actor CRDT metadata does not match the service consistency mode"
    );
    let dispatch = match change {
        Some(change) => {
            let scoped_change =
                crate::crdt::ChangeId::for_dispatch(change.change, actor_id, change.ordinal);
            crate::crdt::with_change(scoped_change, || {
                Ok(lifecycle::dispatch_one_with_invocation::<A>(
                    &message,
                    &mut actor,
                    &mut ctx,
                    work_input.invocation,
                ))
            })
            .expect("nested CRDT actor dispatch must establish one change scope")
        }
        None => lifecycle::dispatch_one_with_invocation::<A>(
            &message,
            &mut actor,
            &mut ctx,
            work_input.invocation,
        ),
    };
    assert!(
        !matches!(dispatch, DispatchResult::Skipped),
        "actor message did not match the canonical program ABI"
    );
    let yielded = matches!(dispatch, DispatchResult::Yielded) || ctx.self_scheduled();
    let forbidden = ctx.was_forbidden();
    let reply = ctx.take_reply_bytes();
    let checkpoint = ctx.__take_checkpoint();
    let new_state = actor.encode();
    let state_changed = state.is_empty() || new_state != state;
    drop(actor);
    drop(state);
    drop(message);
    // A restored machine still owns the original decoded slice locals. The
    // resume token is the authority for the new slice identity and Context
    // has already rebound the live allocator to it before post-await code ran.
    let completed_change = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.change)
        .unwrap_or(change);
    let (crdt_operations, crdt_states, linear_state) = match (forbidden, completed_change) {
        (true, _) => (alloc::vec::Vec::new(), alloc::vec::Vec::new(), None),
        (false, Some(change)) => {
            let next_dispatch_ordinal = change
                .ordinal
                .checked_add(1)
                .expect("CRDT actor dispatch ordinal overflow");
            (
                crate::crdt::take_operations(actor_id, change)
                    .expect("nested CRDT actor must return its completed field operations"),
                alloc::vec![crate::service::ActorCrdtState {
                    actor: actor_id,
                    state: new_state,
                    next_dispatch_ordinal,
                }],
                None,
            )
        }
        (false, None) => (
            alloc::vec::Vec::new(),
            alloc::vec::Vec::new(),
            (!A::CRDT && state_changed).then_some(new_state),
        ),
    };
    let writes = ctx
        .__drain_actor_writes(actor_id, super::storage::end_dispatch(), linear_state)
        .expect("nested actor emitted an unsupported service effect");
    let outbox = ctx.__drain_actor_calls();
    let spawns = ctx.__drain_actor_spawns();
    let (first_await_ordinal, next_await_ordinal) = ctx.__await_ordinal_range();
    let output = ActorSliceOutput {
        actor: actor_id,
        first_await_ordinal,
        next_await_ordinal,
        writes,
        crdt_operations,
        crdt_states,
        spawns,
        outbox,
        reply,
        yielded,
        forbidden,
        checkpoint: checkpoint.clone(),
    };
    let effects = output.encode();
    assert!(
        effects.len() <= crate::service::ACTOR_PRIVATE_INPUT_MAX_BYTES,
        "actor slice effects exceed their deterministic bound"
    );
    assert_eq!(
        crate::abi::pvm::hostcalls::actor_effect_export(&effects),
        crate::abi::error::HOST_OK,
        "generic service rejected canonical actor effects"
    );
    let encoded = ActorCallResult {
        actor: actor_id,
        first_await_ordinal,
        next_await_ordinal,
        reply: output.reply,
        yielded,
        forbidden,
        checkpoint,
    }
    .encode();
    assert!(
        encoded.len() <= capacity,
        "actor call result exceeds IPC cap"
    );

    // SAFETY: the DATA cap is mapped RW over `capacity` bytes and `encoded`
    // was bounds-checked. Scrubbing the complete window prevents this actor's
    // longer input or output from being observed by the next sibling hop.
    unsafe {
        core::ptr::write_bytes(input_address as *mut u8, 0, capacity);
        core::ptr::copy_nonoverlapping(encoded.as_ptr(), input_address as *mut u8, encoded.len());
    }
    let encoded_len = encoded.len() as u64;
    core::mem::forget(encoded);
    // PVM REPLY never unwinds this Rust frame. Reset the actor-local arena
    // only after every output byte is copied so a later legal CALL starts
    // from the full deterministic heap instead of inheriting leaked frames.
    unsafe {
        crate::abi::pvm::alloc::reset_for_next_invocation();
    }
    crate::abi::pvm::ecall::reply(encoded_len)
}

#[cfg(feature = "service")]
const fn pvm_page_size_for_guest() -> usize {
    // This is the GP/PVM page size. Keep the guest free of a vos_pvm dependency;
    // the workspace-side host checks the same value through vos_pvm::PVM_PAGE_SIZE.
    1 << 12
}

// ── Refine phase (all actors) ─────────────────────────────────────────

/// Refine-only actor lifecycle — PVM refine phase (PC=0).
///
/// The agent runtime splits invoke input into separate FETCH items:
///   FETCH 1: linear lane (`0` = absent, `1 || lane` = present)
///   FETCH 2: merge lane
///   FETCH 3: local lane
///   FETCH 4: host-private invocation control
///   FETCH 5: one dynamic message
///
/// Output: `[status:u8][linear_len:u32][merge_len:u32][local_len:u32]`
/// followed by the three lane images and the typed reply.
#[cfg(feature = "pvm")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum AgentInvocationControl {
    Clean(crate::agent_sdk::InvocationContext),
    Legacy(crate::agent::wire::ActorDispatchControl),
}

#[cfg(feature = "pvm")]
fn decode_agent_invocation_control(input: &[u8]) -> Result<AgentInvocationControl, ()> {
    if input.get(..4) == Some(b"AIC1") {
        use crate::agent_sdk::wire::CanonicalWire as _;

        // Declaring AIC1 selects exactly one decoder. In particular, a
        // malformed clean context cannot be reinterpreted as legacy AGDC.
        return crate::agent_sdk::InvocationContext::decode(input)
            .map(AgentInvocationControl::Clean)
            .map_err(|_| ());
    }
    use crate::service::wire::ServiceWire as _;
    crate::agent::wire::ActorDispatchControl::decode(input)
        .map(AgentInvocationControl::Legacy)
        .map_err(|_| ())
}

#[cfg(feature = "pvm")]
pub fn run_refine<A: super::Actor>(args_address: u64, args_len: u64) {
    use super::context::ServiceId;
    use super::lifecycle;

    fn fetch_owned(limit: usize) -> Option<alloc::vec::Vec<u8>> {
        // Most control items and freshly-created lanes are tiny. Keeping a
        // full BUF_SIZE probe alive for each of the three lanes needlessly
        // consumes the actor's bounded heap before dispatch even begins.
        // FETCH reports the complete item length without consuming an item
        // that did not fit, so a small probe followed by one exact retry is
        // both safe and substantially cheaper.
        const PROBE_BYTES: usize = crate::agent::execution::ACTOR_FETCH_PROBE_BYTES;
        let mut bytes = alloc::vec![0u8; core::cmp::min(limit, PROBE_BYTES)];
        let mut len = crate::abi::pvm::ecall::ecall2(
            crate::abi::hostcall::FETCH,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
        );
        let required = usize::try_from(len).ok().filter(|len| *len <= limit)?;
        if required > bytes.len() {
            bytes.resize(required, 0);
            len = crate::abi::pvm::ecall::ecall2(
                crate::abi::hostcall::FETCH,
                bytes.as_mut_ptr() as u64,
                bytes.len() as u64,
            );
            if usize::try_from(len).ok()? != required {
                return None;
            }
        }
        let len = usize::try_from(len).ok()?;
        bytes.truncate(len);
        Some(bytes)
    }

    fn decode_lane(input: &[u8]) -> Option<Option<&[u8]>> {
        match input {
            [0] => Some(None),
            [1, bytes @ ..] => Some(Some(bytes)),
            _ => None,
        }
    }

    let args_len = usize::try_from(args_len)
        .ok()
        .filter(|len| *len <= crate::agent::MAX_INSTALLATION_DATA_BYTES + 1)
        .expect("invalid agent installation-data frame length");
    let args_address = usize::try_from(args_address)
        .ok()
        .filter(|address| *address != 0)
        .expect("invalid agent installation-data frame address");
    // The standard program loader owns this immutable argument mapping and
    // passes its exact base/length in the initial ABI registers.
    let args_frame = unsafe { core::slice::from_raw_parts(args_address as *const u8, args_len) };
    let installation_data = match args_frame {
        [0] => None,
        [1, bytes @ ..] => Some(bytes),
        _ => panic!("invalid agent installation-data frame tag"),
    };

    // The Agent's runtime bounds each lane by the Agent's own limit; an actor accepts
    // whatever any Agent may allow.
    const LANE_ITEM_CAPACITY: usize = crate::agent::execution::MAX_AGENT_LANE_STATE_BYTES + 1;
    let linear_item = fetch_owned(LANE_ITEM_CAPACITY).expect("missing linear agent lane");
    let merge_item = fetch_owned(LANE_ITEM_CAPACITY).expect("missing merge agent lane");
    let local_item = fetch_owned(LANE_ITEM_CAPACITY).expect("missing local agent lane");
    let _encoded_state_len = [&linear_item, &merge_item, &local_item]
        .into_iter()
        .try_fold(0usize, |total, item| {
            let payload = item.len().checked_sub(1)?;
            total.checked_add(payload)
        })
        .filter(|len| *len <= crate::agent::execution::MAX_AGENT_LANE_STATE_BYTES)
        .expect("agent state exceeds the execution aggregate cap");
    let linear = decode_lane(&linear_item).expect("invalid linear agent lane");
    let merge = decode_lane(&merge_item).expect("invalid merge agent lane");
    let local = decode_lane(&local_item).expect("invalid local agent lane");
    let linear_was_fresh_or_absent = linear.is_none_or(<[u8]>::is_empty);
    let merge_was_fresh_or_absent = merge.is_none_or(<[u8]>::is_empty);
    let local_was_fresh_or_absent = local.is_none_or(<[u8]>::is_empty);
    let mut actor = A::__load_agent_state(installation_data, linear, merge, local)
        .expect("invalid field-wise agent state or installation data");
    // Snapshot canonical field frames, rather than the host's fresh empty
    // sentinels, before application code runs. This is the only point that can
    // distinguish an untouched constructor default from a handler mutating a
    // different lane during its first invocation.
    let before_linear = actor.__save_agent_lane(crate::agent::StateLane::Linear);
    let before_merge = actor.__save_agent_lane(crate::agent::StateLane::Merge);
    let before_local = actor.__save_agent_lane(crate::agent::StateLane::Local);
    // The actor owns decoded field values now. Release the encoded input
    // frames before dispatch so the 256-KiB application heap is available to
    // the handler rather than retaining a second complete state image.
    drop(linear_item);
    drop(merge_item);
    drop(local_item);

    let mut ctx = super::Context::new(ServiceId(0));

    let control = fetch_owned(512).expect("missing agent invocation control");
    let (invocation, mode) = match decode_agent_invocation_control(&control)
        .expect("invalid agent invocation control")
    {
        AgentInvocationControl::Clean(clean) => {
            let invocation = crate::service::InvocationId(clean.invocation.0);
            let mode = match clean.mode {
                crate::agent_sdk::MethodMode::Query => crate::agent::MethodMode::Query,
                crate::agent_sdk::MethodMode::LinearizableQuery => {
                    crate::agent::MethodMode::LinearizableQuery
                }
                crate::agent_sdk::MethodMode::LocalQuery => crate::agent::MethodMode::LocalQuery,
                crate::agent_sdk::MethodMode::Linear => crate::agent::MethodMode::Linear,
                crate::agent_sdk::MethodMode::Merge => crate::agent::MethodMode::Merge,
                crate::agent_sdk::MethodMode::Local => crate::agent::MethodMode::Local,
            };
            ctx.__set_actor_id(crate::service::ActorId(clean.actor.0));
            ctx.__set_agent_invocation_context(clean);
            (invocation, mode)
        }
        AgentInvocationControl::Legacy(legacy) => {
            let caller = match legacy.auth.origin {
                crate::service::Origin::Anonymous => super::auth::Caller::Unauthenticated,
                crate::service::Origin::Member(subject) => super::auth::Caller::Member(subject),
                crate::service::Origin::Actor(_) => super::auth::Caller::Actor(ServiceId(0)),
                crate::service::Origin::System => super::auth::Caller::System,
            };
            ctx.__set_actor_id(legacy.actor);
            ctx.set_caller(caller);
            ctx.__set_origin(
                legacy.auth.origin,
                legacy.auth.principal,
                legacy.auth.origin_service,
            );
            ctx.set_caller_roles(legacy.auth.space_role, legacy.auth.actor_role);
            ctx.set_caller_capability(legacy.auth.capability);
            (legacy.invocation, legacy.mode)
        }
    };

    let message = fetch_owned(crate::agent::execution::MAX_EXECUTION_MESSAGE_BYTES)
        .expect("missing agent message");
    if message.is_empty() {
        panic!("empty agent message");
    }
    let mut dispatch =
        || lifecycle::dispatch_one_with_invocation::<A>(&message, &mut actor, &mut ctx, invocation);
    let result = if mode == crate::agent::MethodMode::Merge {
        crate::crdt::with_change(crate::crdt::ChangeId::from(invocation), || {
            core::result::Result::Ok(dispatch())
        })
        .expect("invalid merge change scope")
    } else {
        dispatch()
    };
    if matches!(result, lifecycle::DispatchResult::Skipped) {
        panic!("agent message does not match its signed method schema");
    }
    drop(dispatch);
    drop(message);
    if ctx.__has_unexported_agent_effects() {
        panic!("actor requested effects unsupported by this agent runtime");
    }
    let extra = fetch_owned(1).expect("agent fetch terminator");
    assert!(
        extra.is_empty(),
        "agent invocation contains multiple messages"
    );

    let status = lifecycle::exit_status::<A>(&ctx);

    let mut linear = actor.__save_agent_lane(crate::agent::StateLane::Linear);
    let mut merge = actor.__save_agent_lane(crate::agent::StateLane::Merge);
    let mut local = actor.__save_agent_lane(crate::agent::StateLane::Local);
    let write_lane = mode.write_lane();
    for (lane, before, after) in [
        (
            crate::agent::StateLane::Linear,
            before_linear.as_slice(),
            linear.as_slice(),
        ),
        (
            crate::agent::StateLane::Merge,
            before_merge.as_slice(),
            merge.as_slice(),
        ),
        (
            crate::agent::StateLane::Local,
            before_local.as_slice(),
            local.as_slice(),
        ),
    ] {
        assert!(
            Some(lane) == write_lane || before == after,
            "actor mutated a state lane not owned by its signed method mode"
        );
    }
    drop(before_linear);
    drop(before_merge);
    drop(before_local);
    // Preserve the runtime's canonical fresh sentinel for every lane this
    // method did not own. The host can therefore enforce exact byte equality
    // even on the first invocation, while the owned lane becomes initialized
    // by its first successful mutation.
    if write_lane != Some(crate::agent::StateLane::Linear) && linear_was_fresh_or_absent {
        linear.clear();
    }
    if write_lane != Some(crate::agent::StateLane::Merge) && merge_was_fresh_or_absent {
        merge.clear();
    }
    if write_lane != Some(crate::agent::StateLane::Local) && local_was_fresh_or_absent {
        local.clear();
    }

    if let Some(delta) =
        super::storage::finish_clean_dispatch(status[0]).expect("invalid clean actor storage delta")
    {
        assert!(
            ctx.agent_invocation_context().is_some(),
            "row export requires clean invocation context"
        );
        assert_eq!(
            crate::abi::pvm::hostcalls::actor_effect_export(&delta),
            0,
            "clean actor row export was rejected"
        );
    }

    // Pack output: status, three lane lengths/bytes, then reply.
    // Drop temporaries and ctx eagerly — halt_with_output is `-> !`
    // so destructors never run; without explicit drops the Vecs leak
    // on every invocation.
    let out = {
        drop(actor);
        let reply_bytes = ctx.take_reply_bytes();
        drop(ctx);
        let state_len = linear
            .len()
            .checked_add(merge.len())
            .and_then(|len| len.checked_add(local.len()))
            .filter(|len| *len <= crate::agent::execution::MAX_AGENT_LANE_STATE_BYTES)
            .expect("agent state exceeds the execution aggregate cap");
        assert!(
            reply_bytes.len() <= crate::agent::execution::MAX_EXECUTION_REPLY_BYTES,
            "agent reply exceeds the execution cap"
        );
        let linear_len = (linear.len() as u32).to_le_bytes();
        let merge_len = (merge.len() as u32).to_le_bytes();
        let local_len = (local.len() as u32).to_le_bytes();
        let mut out = alloc::vec![
            0u8;
            1 + 12 + state_len + reply_bytes.len()
        ];
        out[0] = status[0];
        out[1..5].copy_from_slice(&linear_len);
        out[5..9].copy_from_slice(&merge_len);
        out[9..13].copy_from_slice(&local_len);
        let linear_end = 13 + linear.len();
        let merge_end = linear_end + merge.len();
        let local_end = merge_end + local.len();
        out[13..linear_end].copy_from_slice(&linear);
        out[linear_end..merge_end].copy_from_slice(&merge);
        out[merge_end..local_end].copy_from_slice(&local);
        out[local_end..].copy_from_slice(&reply_bytes);
        out
    };
    halt_with_output(&out);
}

// ── Utilities ─────────────────────────────────────────────────────────

/// Build a code hash from a service ID (public, for agent use).
pub fn service_code_hash(service_id: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&service_id.to_le_bytes());
    hash
}

#[cfg(test)]
mod tests {
    use super::{Ask, run_blocking};
    use crate::actors::{codec::Encode as _, value::InvokeError};
    use crate::value::Value;
    use alloc::vec::Vec;

    #[test]
    fn ask_rejects_malformed_typed_replies() {
        assert_eq!(
            run_blocking(Ask::ready(Value::U32(17).encode())),
            Ok(Value::U32(17))
        );
        assert_eq!(run_blocking(Ask::ready(Vec::new())), Ok(Value::Unit));

        for malformed in [vec![0xff], vec![0xff; 32], vec![0, 1, 2]] {
            assert_eq!(
                run_blocking(Ask::ready(malformed)),
                Err(InvokeError::Panicked)
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_agent_control_decoder_never_falls_back_from_aic1() {
        use super::{AgentInvocationControl, decode_agent_invocation_control};
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::ServiceWire as _;

        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId([0x91; 32]),
            actor: crate::agent_sdk::ActorId([0x92; 32]),
            mode: crate::agent_sdk::MethodMode::Merge,
            origin: crate::agent_sdk::InvocationOrigin {
                principal: Some(crate::agent_sdk::PrincipalId([0x93; 32])),
                ..crate::agent_sdk::InvocationOrigin::anonymous()
            },
            roles: crate::agent_sdk::InvocationRoleClaims {
                space: Some(crate::agent_sdk::RoleId([0x94; 32])),
                actor: None,
            },
            observed_slot: 95,
        };
        let encoded = context.encode().unwrap();
        assert_eq!(
            decode_agent_invocation_control(&encoded),
            Ok(AgentInvocationControl::Clean(context))
        );

        let mut corrupt_aic1 = encoded;
        corrupt_aic1.push(0);
        assert_eq!(decode_agent_invocation_control(&corrupt_aic1), Err(()));

        let legacy = crate::agent::wire::ActorDispatchControl {
            invocation: crate::service::InvocationId([0x96; 32]),
            actor: crate::service::ActorId([0x97; 32]),
            mode: crate::agent::MethodMode::Linear,
            auth: crate::agent::execution::ActorInvocationAuth::anonymous(),
        };
        assert!(matches!(
            decode_agent_invocation_control(&legacy.encode()),
            Ok(AgentInvocationControl::Legacy(value)) if value == legacy
        ));
    }
}
