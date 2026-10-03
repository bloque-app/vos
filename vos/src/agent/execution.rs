//! Stable actor-execution contract of an agent runtime.
//!
//! The node supplies authenticated work and exact content-addressed program
//! availability. The runtime owns actor lookup, lane selection, inner-machine
//! host calls, and the next opaque runtime state.

#[cfg(feature = "pvm")]
use alloc::vec;
use alloc::vec::Vec;

use super::{MethodMode, StateLane};
use crate::service::wire::Encoder;
#[cfg(feature = "pvm")]
use crate::service::wire::ServiceWire;
use crate::service::{
    ActorId, BlobRef, CapabilityId, DeploymentId, Hash, InvocationId, Origin, PrincipalId,
    ProgramId, ServiceIdentity,
};

/// Maximum dynamic request passed to an application actor, identical to the
/// clean SDK admission bound and the guest's message-fetch bound.
pub const MAX_EXECUTION_MESSAGE_BYTES: usize = crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES;
/// Maximum typed reply retained by the runtime.
pub const MAX_EXECUTION_REPLY_BYTES: usize = 8 * 1024;
/// Maximum encoded size of one lane. The stricter aggregate bound below is
/// what makes a three-lane invocation fit the application actor's 256-KiB
/// heap while input, decoded fields, and output coexist.
pub const MAX_EXECUTION_STATE_BYTES: usize = 48 * 1024;
/// Maximum sum of the linear, merge, and local lane images visible to one
/// invocation.
pub const MAX_EXECUTION_STATE_TOTAL_BYTES: usize = 48 * 1024;
/// Maximum aggregate content-addressed availability supplied to one call.
pub const MAX_EXECUTION_AVAILABILITY_BYTES: usize =
    crate::agent_sdk::MAX_RUNTIME_CALLER_AVAILABILITY_BYTES;
/// Maximum application PVM accepted by the bundled runtime: the hard maximum
/// a declared actor may reach ([`crate::agent_sdk::MAX_RUNTIME_PROGRAM_BYTES`];
/// undeclared actors are admitted for install only up to
/// [`crate::agent_sdk::STANDARD_ACTOR_PROGRAM_BYTES`]). Parsing a PVM
/// materializes its data, code, bitmask, and compact-code form concurrently,
/// so this is intentionally much smaller than a generic service wire.
pub const MAX_EXECUTION_PROGRAM_BYTES: usize = crate::agent_sdk::MAX_RUNTIME_PROGRAM_BYTES;
/// Maximum instruction gas which an untrusted caller may assign to one actor
/// invocation. The host adds its separately configured runtime-management
/// budget around this value; actor-selected gas itself is never unbounded.
pub const MAX_EXECUTION_GAS: u64 = 1_000_000_000;
/// Maximum canonical signed method-policy artifact supplied to one call.
/// This is separate from actor availability because it is deployment
/// provenance, not caller-selected input.
pub const MAX_EXECUTION_POLICY_BYTES: usize = 64 * 1024;
/// Maximum opaque runtime image accepted by the bundled 32-MiB agent-runtime
/// guest. The runtime contract signs this ceiling and the wire decoder
/// enforces it before allocation.
/// Execution temporarily owns the decoded image, its runtime representation,
/// a snapshot, and the encoded successor in addition to the actor PVM.
pub const MAX_RUNTIME_STATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXECUTION_BLOBS: usize = 4;
const ACTOR_DISPATCH_CONTROL_CAPACITY: usize = 512;
/// Initial probe used by the guest before an exact-sized FETCH retry.
pub const ACTOR_FETCH_PROBE_BYTES: usize = 256;
const MAX_EXECUTION_HOST_CALLS: usize = 4 * 1024;
const MAX_EXECUTION_FETCH_CALLS: usize = 16 + MAX_EXECUTION_BLOBS;
// Five frames: three lane tags plus aggregate state, control and message.
// Include one bounded probe per frame so a full valid input is not rejected
// merely because the guest first discovers its exact frame lengths.
const MAX_EXECUTION_FETCH_BYTES: usize = MAX_EXECUTION_STATE_TOTAL_BYTES
    + 3 + ACTOR_DISPATCH_CONTROL_CAPACITY + MAX_EXECUTION_MESSAGE_BYTES
    + 5 * ACTOR_FETCH_PROBE_BYTES
    // One lookup per caller blob: hash input, content verification and copy.
    + MAX_EXECUTION_BLOBS * 32 + 2 * MAX_EXECUTION_AVAILABILITY_BYTES;
// Preserve the actor's baseline crypto allowance and budget one SDK content
// verification per admitted blob (128-byte BLAKE2b blocks plus framing). These
// counters, like fetch work, are retained across yields and are not per slice.
const MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS: usize =
    1024 + MAX_EXECUTION_AVAILABILITY_BYTES.div_ceil(128) + 2 * MAX_EXECUTION_BLOBS;
const MAX_EXECUTION_DEBUG_BYTES: usize = 16 * 1024;

#[cfg(feature = "pvm")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActorStateLanes {
    pub linear: Option<Vec<u8>>,
    pub merge: Option<Vec<u8>>,
    pub local: Option<Vec<u8>>,
}

#[cfg(feature = "pvm")]
impl ActorStateLanes {
    pub fn get(&self, lane: StateLane) -> Option<&[u8]> {
        match lane {
            StateLane::Linear => self.linear.as_deref(),
            StateLane::Merge => self.merge.as_deref(),
            StateLane::Local => self.local.as_deref(),
        }
    }

    pub fn take(&mut self, lane: StateLane) -> Option<Vec<u8>> {
        match lane {
            StateLane::Linear => self.linear.take(),
            StateLane::Merge => self.merge.take(),
            StateLane::Local => self.local.take(),
        }
    }

    pub fn encoded_len(&self) -> Option<usize> {
        execution_state_size([
            self.linear.as_deref(),
            self.merge.as_deref(),
            self.local.as_deref(),
        ])
    }

    /// Build the only lane image an actor running in `mode` is allowed to
    /// observe. The complete preimage stays inside the outer runtime so a
    /// hand-written actor PVM cannot learn a hidden lane merely by ignoring
    /// the generated Rust lane views.
    pub fn visible_for(&self, mode: super::MethodMode) -> Self {
        let visible =
            |lane, value: &Option<Vec<u8>>| mode.can_read(lane).then(|| value.clone()).flatten();
        Self {
            linear: visible(StateLane::Linear, &self.linear),
            merge: visible(StateLane::Merge, &self.merge),
            local: visible(StateLane::Local, &self.local),
        }
    }
}

/// Checked aggregate size for a set of optional lane images.
#[cfg(feature = "pvm")]
pub(crate) fn execution_state_size<'a>(
    lanes: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Option<usize> {
    lanes
        .into_iter()
        .flatten()
        .try_fold(0usize, |total, lane| total.checked_add(lane.len()))
}

/// One content-addressed preimage made available to the runtime invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

/// Hard allocation ceiling while decoding one untrusted inner-machine image.
/// The enclosing runtime applies its (possibly smaller) signed state limit to
/// the complete encoded continuation before committing it.
pub const MAX_PORTABLE_MACHINE_MEMORY_BYTES: usize = MAX_RUNTIME_STATE_BYTES;
pub const MAX_PORTABLE_MACHINE_REGIONS: usize = 2;

/// One complete mutable region in a portable inner-machine snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableMemoryRegion {
    pub base: u32,
    pub bytes: Vec<u8>,
}

/// Runtime-independent state needed to recreate one standard inner machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableMachineSnapshot {
    pub pc: u32,
    pub gas_remaining: u64,
    pub registers: [u64; vos_pvm_program::REGISTER_COUNT],
    pub memory: Vec<PortableMemoryRegion>,
}

impl PortableMachineSnapshot {
    /// Validate bounds independent of a program. Restore additionally checks
    /// exact region bases and lengths against the authenticated program.
    pub fn is_valid(&self) -> bool {
        if self.memory.len() > MAX_PORTABLE_MACHINE_REGIONS {
            return false;
        }
        let mut total = 0usize;
        let mut previous_end = None;
        for region in &self.memory {
            if region.bytes.is_empty()
                || region.base % vos_pvm_program::PAGE_SIZE != 0
                || region.bytes.len() % vos_pvm_program::PAGE_SIZE as usize != 0
            {
                return false;
            }
            let Ok(len) = u32::try_from(region.bytes.len()) else {
                return false;
            };
            let Some(end) = region.base.checked_add(len) else {
                return false;
            };
            if previous_end.is_some_and(|previous| region.base < previous) {
                return false;
            }
            previous_end = Some(end);
            let Some(next) = total.checked_add(region.bytes.len()) else {
                return false;
            };
            if next > MAX_PORTABLE_MACHINE_MEMORY_BYTES {
                return false;
            }
            total = next;
        }
        true
    }

    pub fn memory_bytes(&self) -> usize {
        self.memory.iter().map(|region| region.bytes.len()).sum()
    }
}

/// Caller context signed into an [`ActorInvocationReceipt`](super::authority::ActorInvocationReceipt).
/// Public actor message bytes never carry these fields; the runtime guest
/// verifies the receipt before using them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocationAuth {
    pub origin: Origin,
    /// Authority-authenticated application principal. Transport subjects and
    /// causal actor/service identities remain in `origin`; neither is a
    /// substitute for this authorization identity.
    pub principal: Option<PrincipalId>,
    pub origin_service: Option<ServiceIdentity>,
    pub space_role: Option<u8>,
    pub actor_role: Option<u8>,
    pub capability: Option<CapabilityId>,
}

impl ActorInvocationAuth {
    pub const fn anonymous() -> Self {
        Self {
            origin: Origin::Anonymous,
            principal: None,
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: None,
        }
    }

    pub fn validate(&self) -> bool {
        let claims_are_empty =
            self.space_role.is_none() && self.actor_role.is_none() && self.capability.is_none();
        let origin_valid = match self.origin {
            // Anonymous is an absence of authenticated authority, not merely
            // a caller label. Never let it carry host-trusted assertions.
            Origin::Anonymous => {
                self.principal.is_none() && self.origin_service.is_none() && claims_are_empty
            }
            // System work may carry one exact platform capability, but has no
            // principal or actor against which a role grant could be bound.
            Origin::System => {
                self.origin_service.is_none()
                    && self.principal.is_none()
                    && self.space_role.is_none()
                    && self.actor_role.is_none()
            }
            Origin::Member(subject) => {
                subject != crate::service::SubjectId::ZERO
                    && self
                        .principal
                        .is_some_and(|principal| principal != PrincipalId::ZERO)
                    && self.origin_service.is_none()
            }
            Origin::Actor(actor) => {
                actor != ActorId::ZERO
                    && self
                        .principal
                        .is_some_and(|principal| principal != PrincipalId::ZERO)
                    && self.origin_service.as_ref().is_some_and(|service| {
                        service.space != crate::service::SpaceId::ZERO
                            && service.root_service != crate::service::RootServiceId::ZERO
                            && service.deployment != DeploymentId::ZERO
                            && service.service_program != ProgramId::ZERO
                            && service.platform == crate::service::PLATFORM_ID
                            && service.execution_semantics == crate::service::EXECUTION_SEMANTICS_ID
                            && service.gas_schedule.is_valid()
                    })
            }
        };
        origin_valid
            && self
                .space_role
                .is_none_or(|role| crate::SpaceRole::from_u8(role).is_some())
            && self.actor_role != Some(u8::MAX)
            && self
                .capability
                .is_none_or(|capability| capability != CapabilityId::ZERO)
    }
}

impl Default for ActorInvocationAuth {
    fn default() -> Self {
        Self::anonymous()
    }
}

/// Authenticated actor work delivered to one agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    /// Immutable identity of the exact install targeted by this work.
    /// Removing and reinstalling the same ActorId changes this value, so an
    /// authorization issued for the retired install cannot reach its
    /// replacement even when deployment and program are reused.
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub auth: ActorInvocationAuth,
    pub message: Vec<u8>,
    pub availability: Vec<RuntimeBlob>,
    pub gas: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorExecutionStatus {
    Done = 0,
    Forbidden = 1,
    Panicked = 2,
    OutOfGas = 3,
    /// The actor committed one cooperative slice. Its exact machine
    /// continuation is runtime-owned state, not reply payload supplied by the
    /// caller.
    Yielded = 4,
}

/// Durable state observation which produced one exact actor reply.
///
/// Missing lanes are represented explicitly. Merge state uses a canonical
/// content frontier because the standard Local adapter has no causal DAG;
/// replicated adapters may map their canonical frontier to the same hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActorObservation {
    pub linear_revision: Option<u64>,
    pub merge_frontier: Option<Hash>,
    pub local_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorExecutionReply {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub mode: MethodMode,
    pub lane: Option<StateLane>,
    pub status: ActorExecutionStatus,
    pub reply: Vec<u8>,
    pub gas_remaining: u64,
    pub observation: ActorObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorExecutionError {
    NotCreated,
    NotFound,
    StaleIncarnation,
    Suspended,
    StaleDeployment,
    WrongProgram,
    UnsupportedMethod,
    /// The agent profile or runtime capabilities do not expose the durable
    /// component which owns this invocation mode's exact result.
    UnsupportedResultStorage,
    MissingState,
    InvalidAvailability,
    InvalidInput,
    InvalidActorOutput,
    DivergentInvocation,
    ResultCapacity,
    InvalidAuthorization,
    AuthorityExpired,
    AuthoritySlotRegressed,
    /// A valid continuation exists, but another continuation in the same
    /// physical component precedes it in the deterministic FIFO.
    ContinuationNotReady,
    UnsupportedHostCall(u64),
}

impl ActorExecutionError {
    /// Whether an authenticated, fresh, structurally admitted invocation must
    /// retain this deterministic rejection as an exact external outcome.
    ///
    /// The caller is still responsible for proving that the error arose after
    /// admission. In particular, [`Self::InvalidInput`] is durable only at the
    /// trusted runtime boundary; malformed host input is rejected before this
    /// classification is consulted.
    pub const fn is_durable_exact_outcome(self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::StaleIncarnation
                | Self::Suspended
                | Self::StaleDeployment
                | Self::WrongProgram
                | Self::UnsupportedMethod
                | Self::InvalidInput
                | Self::InvalidActorOutput
                | Self::UnsupportedHostCall(_)
        )
    }
}

/// Complete runtime execution call. `state` is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionCall {
    pub state: super::wire::RuntimeState,
    pub invocation: ActorInvocation,
    /// Complete authority evidence verified again by the runtime guest.
    pub authority: super::authority::ActorInvocationReceipt,
    /// Canonical logical slot selected by the host/replication transition.
    pub observed_slot: u64,
    /// Exact-result recovery when the historical actor package has already
    /// been retired after an upgrade. This mode may only recover a guest-owned
    /// disposition; it can never execute unseen work.
    pub recovery_only: bool,
    /// Exact content-addressed program resolved by the host from its durable
    /// package catalog. It is intentionally absent from [`ActorInvocation`]
    /// so callers cannot select executable bytes.
    pub actor_pvm: Vec<u8>,
    /// Exact signed execution schema staged from the actor deployment.
    pub actor_schema: RuntimeBlob,
    /// Exact signed method policies staged from the same deployment. Package
    /// signature verification happens at lifecycle admission; the runtime
    /// authenticates these bytes against the guest-owned reference and
    /// enforces the selected method before entering application code.
    pub actor_policies: RuntimeBlob,
    /// Exact canonical constructor-argument object selected by the installed
    /// directory entry. Absence and present-empty remain distinct; const fields
    /// are reconstructed by the constructor and are not serialized here.
    pub installation_data: Option<RuntimeBlob>,
}

/// Complete deterministic runtime execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionReturn {
    pub state: super::wire::RuntimeState,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

impl ActorInvocation {
    /// Stable identity of every execution-significant caller field. Program
    /// bytes are excluded because the host resolves them by `program` from
    /// its authenticated catalog.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.actor.0);
        encoder.fixed(&self.incarnation.0);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.program.0);
        encoder.u8(match self.mode {
            super::MethodMode::Query => 0,
            super::MethodMode::LinearizableQuery => 1,
            super::MethodMode::LocalQuery => 2,
            super::MethodMode::Linear => 3,
            super::MethodMode::Merge => 4,
            super::MethodMode::Local => 5,
        });
        crate::service::encode_origin(&mut encoder, self.auth.origin);
        encoder.option(&self.auth.principal, |encoder, principal| {
            encoder.fixed(&principal.0)
        });
        encoder.option(&self.auth.origin_service, crate::service::encode_service);
        encoder.option(&self.auth.space_role, |encoder, role| encoder.u8(*role));
        encoder.option(&self.auth.actor_role, |encoder, role| encoder.u8(*role));
        encoder.option(&self.auth.capability, |encoder, capability| {
            encoder.fixed(&capability.0)
        });
        encoder.bytes(&self.message);
        encoder.list(&self.availability, |encoder, blob| {
            encoder.fixed(&blob.reference.hash.0);
            encoder.u64(blob.reference.len);
            encoder.bytes(&blob.bytes);
        });
        encoder.u64(self.gas);
        Hash::digest(b"vos/agent/invocation", &[&bytes])
    }

    /// Message signed by the configured agent authority. It is deliberately
    /// distinct from the durable retry commitment so a receipt for one
    /// protocol cannot be replayed in the other.
    pub fn authorization_message(&self) -> Hash {
        Hash::digest(
            b"vos/agent/invocation-authorization",
            &[&self.commitment().0],
        )
    }

    /// Resolve only a preimage carried by this invocation. The caller still
    /// validates/authenticates the complete invocation before execution. This
    /// boundary checks collection bounds/order and the selected exact preimage;
    /// it never consults a store, network, or another invocation's availability.
    pub(crate) fn available_preimage(
        &self,
        reference: &BlobRef,
    ) -> Result<Option<&[u8]>, ActorExecutionError> {
        if self.availability.len() > MAX_EXECUTION_BLOBS
            || self
                .availability
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
            || self
                .availability
                .iter()
                .try_fold(0usize, |total, blob| {
                    (blob.bytes.len() <= MAX_EXECUTION_AVAILABILITY_BYTES)
                        .then(|| total.checked_add(blob.bytes.len()))
                        .flatten()
                })
                .is_none_or(|total| total > MAX_EXECUTION_AVAILABILITY_BYTES)
        {
            return Err(ActorExecutionError::InvalidInput);
        }
        let Ok(index) = self
            .availability
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
        else {
            return Ok(None);
        };
        let blob = &self.availability[index];
        if &blob.reference != reference || !reference.matches(&blob.bytes) {
            return Err(ActorExecutionError::InvalidInput);
        }
        Ok(Some(&blob.bytes))
    }

    pub fn validate(&self) -> Result<(), ActorExecutionError> {
        let availability_bytes = self
            .availability
            .iter()
            .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()));
        if self.invocation == InvocationId::ZERO
            || self.actor == ActorId::ZERO
            || self.incarnation == Hash::ZERO
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.gas == 0
            || self.gas > MAX_EXECUTION_GAS
            || !self.auth.validate()
            || self.message.is_empty()
            || self.message.len() > MAX_EXECUTION_MESSAGE_BYTES
            || self.availability.len() > MAX_EXECUTION_BLOBS
            || self
                .availability
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
            || self.availability.iter().any(|blob| {
                blob.bytes.len() > MAX_EXECUTION_AVAILABILITY_BYTES
                    || !blob.reference.matches(&blob.bytes)
            })
            || availability_bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_AVAILABILITY_BYTES)
        {
            return Err(ActorExecutionError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActorHostBudget {
    pub(crate) calls: u32,
    pub(crate) fetch_calls: u32,
    pub(crate) fetch_bytes: u32,
    pub(crate) blake2b_compressions: u32,
    pub(crate) debug_bytes: u32,
}

impl ActorHostBudget {
    #[cfg(feature = "pvm")]
    fn charge(total: &mut u32, amount: usize, maximum: usize) -> bool {
        let Ok(amount) = u32::try_from(amount) else {
            return false;
        };
        let Some(next) = total
            .checked_add(amount)
            .filter(|next| *next as usize <= maximum)
        else {
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some() {
                std::eprintln!(
                    "native quota exhausted: total={total} amount={amount} maximum={maximum}"
                );
            }
            return false;
        };
        *total = next;
        true
    }

    #[cfg(feature = "pvm")]
    fn host_call(&mut self) -> bool {
        Self::charge(&mut self.calls, 1, MAX_EXECUTION_HOST_CALLS)
    }

    #[cfg(feature = "pvm")]
    fn fetch(&mut self, bytes: usize) -> bool {
        Self::charge(&mut self.fetch_calls, 1, MAX_EXECUTION_FETCH_CALLS)
            && Self::charge(&mut self.fetch_bytes, bytes, MAX_EXECUTION_FETCH_BYTES)
    }

    #[cfg(feature = "agent-runtime")]
    fn blake2b_compression(&mut self) -> bool {
        Self::charge(
            &mut self.blake2b_compressions,
            1,
            MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS,
        )
    }

    #[cfg(feature = "pvm")]
    fn debug(&mut self, bytes: usize) -> bool {
        Self::charge(&mut self.debug_bytes, bytes, MAX_EXECUTION_DEBUG_BYTES)
    }

    pub(crate) fn validate(self) -> bool {
        self.calls as usize <= MAX_EXECUTION_HOST_CALLS
            && self.fetch_calls as usize <= MAX_EXECUTION_FETCH_CALLS
            && self.fetch_bytes as usize <= MAX_EXECUTION_FETCH_BYTES
            && self.blake2b_compressions as usize <= MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS
            && self.debug_bytes as usize <= MAX_EXECUTION_DEBUG_BYTES
    }

    fn includes(self, earlier: Self) -> bool {
        self.calls >= earlier.calls
            && self.fetch_calls >= earlier.fetch_calls
            && self.fetch_bytes >= earlier.fetch_bytes
            && self.blake2b_compressions >= earlier.blake2b_compressions
            && self.debug_bytes >= earlier.debug_bytes
    }
}

/// Exact portable state captured at an actor SUSPEND exit. The fetch cursor
/// and native-work counters are part of the continuation: resetting either on
/// resume would make restart behavior diverge or permit budget bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActorMachineContinuation {
    pub(crate) machine: PortableMachineSnapshot,
    pub(crate) fetch_index: u8,
    pub(crate) host_budget: ActorHostBudget,
}

impl ActorMachineContinuation {
    pub(crate) fn validate(&self) -> bool {
        self.fetch_index <= 5 && self.host_budget.validate() && self.machine.is_valid()
    }
}

#[cfg(feature = "pvm")]
fn charge_yield_finalizer(
    continuation: &mut ActorMachineContinuation,
    gas_remaining: u64,
    host_budget: ActorHostBudget,
) -> Result<(), ActorExecutionError> {
    if gas_remaining > continuation.machine.gas_remaining
        || !host_budget.includes(continuation.host_budget)
        || !host_budget.validate()
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    continuation.machine.gas_remaining = gas_remaining;
    continuation.host_budget = host_budget;
    Ok(())
}

#[cfg(feature = "pvm")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActorRunOutcome {
    Completed {
        reply: ActorExecutionReply,
        state: ActorStateLanes,
        rows: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    },
    Yielded {
        reply: ActorExecutionReply,
        state: ActorStateLanes,
        continuation: ActorMachineContinuation,
        rows: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    },
}

#[cfg(feature = "pvm")]
fn encode_inner_actor_control(
    invocation: &ActorInvocation,
    clean_context: Option<crate::agent_sdk::InvocationContext>,
) -> Result<Vec<u8>, ActorExecutionError> {
    match clean_context {
        Some(context) => {
            use crate::agent_sdk::wire::CanonicalWire as _;

            let context_mode = match context.mode {
                crate::agent_sdk::MethodMode::Query => super::MethodMode::Query,
                crate::agent_sdk::MethodMode::LinearizableQuery => {
                    super::MethodMode::LinearizableQuery
                }
                crate::agent_sdk::MethodMode::LocalQuery => super::MethodMode::LocalQuery,
                crate::agent_sdk::MethodMode::Linear => super::MethodMode::Linear,
                crate::agent_sdk::MethodMode::Merge => super::MethodMode::Merge,
                crate::agent_sdk::MethodMode::Local => super::MethodMode::Local,
            };
            if !context.validate()
                || context.invocation.0 != invocation.invocation.0
                || context.actor.0 != invocation.actor.0
                || context_mode != invocation.mode
            {
                return Err(ActorExecutionError::InvalidInput);
            }
            context
                .encode()
                .map_err(|_| ActorExecutionError::InvalidInput)
        }
        None => Ok(super::wire::ActorDispatchControl {
            invocation: invocation.invocation,
            actor: invocation.actor,
            mode: invocation.mode,
            auth: invocation.auth.clone(),
        }
        .encode()),
    }
}

#[cfg(feature = "pvm")]
pub(crate) fn run_inner_actor(
    invocation: &ActorInvocation,
    clean_context: Option<crate::agent_sdk::InvocationContext>,
    actor_pvm: &[u8],
    installation_data: Option<&[u8]>,
    actor_state: &ActorStateLanes,
    continuation: Option<ActorMachineContinuation>,
) -> Result<ActorRunOutcome, ActorExecutionError> {
    run_inner_actor_with_storage(
        invocation,
        clean_context,
        actor_pvm,
        installation_data,
        actor_state,
        continuation,
        None,
    )
}

/// Execute with an authenticated, runtime-owned row view. The caller must
/// resolve the view from the same installed actor/generation and separately
/// admit caller authorization. Row reads share the persisted native FETCH
/// work budget, so neither absent rows nor continuation resumes get free IO.
#[cfg(feature = "pvm")]
pub(crate) fn run_inner_actor_with_storage(
    invocation: &ActorInvocation,
    clean_context: Option<crate::agent_sdk::InvocationContext>,
    actor_pvm: &[u8],
    installation_data: Option<&[u8]>,
    actor_state: &ActorStateLanes,
    continuation: Option<ActorMachineContinuation>,
    storage: Option<&dyn super::actor_storage::ActorRowStorage>,
) -> Result<ActorRunOutcome, ActorExecutionError> {
    use super::machine::{ActorMachine, InnerExit};
    use crate::abi::{error, hostcall};

    if storage.is_some_and(|storage| {
        clean_context
            .as_ref()
            .is_none_or(|ctx| ctx.mode != storage.mode())
    }) {
        return Err(ActorExecutionError::InvalidInput);
    }
    if actor_state
        .encoded_len()
        .is_none_or(|len| len > MAX_EXECUTION_STATE_TOTAL_BYTES)
    {
        return Err(ActorExecutionError::InvalidInput);
    }
    let encode_lane = |lane: Option<&[u8]>| {
        let mut item = Vec::with_capacity(lane.map_or(1, |bytes| bytes.len() + 1));
        match lane {
            None => item.push(0),
            Some(bytes) => {
                item.push(1);
                item.extend_from_slice(bytes);
            }
        }
        item
    };
    let linear = encode_lane(actor_state.linear.as_deref());
    let merge = encode_lane(actor_state.merge.as_deref());
    let local = encode_lane(actor_state.local.as_deref());
    // FETCH item #4 is this exact frame. Clean calls use only AIC1; AGDC is
    // retained exclusively for the transitional legacy caller above us.
    let control = encode_inner_actor_control(invocation, clean_context)?;
    if control.len() > ACTOR_DISPATCH_CONTROL_CAPACITY {
        return Err(ActorExecutionError::InvalidInput);
    }
    let fetch = [
        linear.as_slice(),
        merge.as_slice(),
        local.as_slice(),
        control.as_slice(),
        invocation.message.as_slice(),
    ];
    let mut actor_args =
        Vec::with_capacity(installation_data.map_or(1, |bytes| bytes.len().saturating_add(1)));
    match installation_data {
        None => actor_args.push(0),
        Some(bytes) => {
            if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES {
                return Err(ActorExecutionError::InvalidInput);
            }
            actor_args.push(1);
            actor_args.extend_from_slice(bytes);
        }
    }
    let (mut machine, mut gas, mut fetch_index, mut host_budget) = match continuation {
        Some(continuation) => {
            if !continuation.validate() {
                return Err(ActorExecutionError::InvalidInput);
            }
            let mut machine = ActorMachine::restore(actor_pvm, &actor_args, &continuation.machine)
                .map_err(|_| ActorExecutionError::InvalidAvailability)?;
            // Agent SUSPEND is a private inner-actor ABI exit. Zero finalized
            // the fork which emitted the yielded lane image; one resumes the
            // captured successor without a service checkpoint token.
            machine.registers_mut()[7] = 1;
            machine.registers_mut()[8] = 0;
            (
                machine,
                continuation.machine.gas_remaining,
                continuation.fetch_index as usize,
                continuation.host_budget,
            )
        }
        None => (
            ActorMachine::load(actor_pvm, &actor_args)
                .map_err(|_| ActorExecutionError::InvalidInput)?,
            invocation.gas,
            0,
            ActorHostBudget::default(),
        ),
    };
    let mut yielded_continuation: Option<ActorMachineContinuation> = None;
    let mut exported_rows = None;

    loop {
        match machine.resume(gas) {
            InnerExit::Halt => {
                let registers = *machine.registers();
                let address = u32::try_from(registers[7])
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                let len = usize::try_from(registers[8])
                    .ok()
                    .filter(|len| {
                        *len <= MAX_EXECUTION_STATE_TOTAL_BYTES + MAX_EXECUTION_REPLY_BYTES + 13
                    })
                    .ok_or(ActorExecutionError::InvalidActorOutput)?;
                let mut output = alloc::vec![0u8; len];
                machine
                    .read(address, &mut output)
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                let (mut reply, state) =
                    decode_actor_output(invocation, machine.gas_remaining(), output)?;
                return match (reply.status, yielded_continuation.take()) {
                    (ActorExecutionStatus::Yielded, Some(mut continuation)) => {
                        // Memory/PC/registers remain the exact pre-result
                        // snapshot, while gas and native work performed by
                        // the disposable finalization fork are charged to the
                        // continuation. Repeated yields therefore cannot make
                        // state serialization or output construction free.
                        charge_yield_finalizer(
                            &mut continuation,
                            machine.gas_remaining(),
                            host_budget,
                        )?;
                        reply.gas_remaining = machine.gas_remaining();
                        Ok(ActorRunOutcome::Yielded {
                            reply,
                            state,
                            continuation,
                            rows: exported_rows.take().unwrap_or_default(),
                        })
                    }
                    (ActorExecutionStatus::Yielded, None) | (_, Some(_)) => {
                        Err(ActorExecutionError::InvalidActorOutput)
                    }
                    (_, None) => {
                        let rows = if reply.status == ActorExecutionStatus::Done {
                            exported_rows.take().unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        Ok(ActorRunOutcome::Completed { reply, state, rows })
                    }
                };
            }
            _failure @ (InnerExit::Panic | InnerExit::Fault(_)) => {
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some() {
                    std::eprintln!(
                        "inner failure: {_failure:?}, registers={:?}",
                        machine.registers()
                    );
                }
                return Ok(ActorRunOutcome::Completed {
                    reply: terminal_reply(
                        invocation,
                        ActorExecutionStatus::Panicked,
                        machine.gas_remaining(),
                    ),
                    state: actor_state.clone(),
                    rows: Vec::new(),
                });
            }
            InnerExit::OutOfGas => {
                return Ok(ActorRunOutcome::Completed {
                    reply: terminal_reply(invocation, ActorExecutionStatus::OutOfGas, 0),
                    state: actor_state.clone(),
                    rows: Vec::new(),
                });
            }
            InnerExit::InvalidResult(_) => return Err(ActorExecutionError::InvalidActorOutput),
            InnerExit::Host(id) => {
                gas = machine.gas_remaining();
                // PVM instruction gas bounds guest computation, but host
                // operations perform native work outside that schedule. Keep
                // a second deterministic per-invocation work budget so a
                // cheap ECALL loop cannot monopolize the agent thread.
                if !host_budget.host_call() {
                    return Ok(ActorRunOutcome::Completed {
                        reply: terminal_reply(invocation, ActorExecutionStatus::OutOfGas, 0),
                        state: actor_state.clone(),
                        rows: Vec::new(),
                    });
                }
                let registers = *machine.registers();
                if id == u64::from(hostcall::SUSPEND) {
                    if yielded_continuation.is_some() || exported_rows.is_some() {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    let snapshot = machine
                        .capture()
                        .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                    let continuation = ActorMachineContinuation {
                        machine: snapshot,
                        fetch_index: u8::try_from(fetch_index)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?,
                        host_budget,
                    };
                    let mut finalizer =
                        ActorMachine::restore(actor_pvm, &actor_args, &continuation.machine)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                    finalizer.registers_mut()[7] = 0;
                    finalizer.registers_mut()[8] = 0;
                    gas = continuation.machine.gas_remaining;
                    yielded_continuation = Some(continuation);
                    machine = finalizer;
                    continue;
                }
                let (result0, result1) = match id {
                    value if value == u64::from(hostcall::GAS) => (gas, 0),
                    value if value == u64::from(hostcall::ACTOR_EFFECT_EXPORT) => {
                        let storage =
                            storage.ok_or(ActorExecutionError::UnsupportedHostCall(id))?;
                        if exported_rows.is_some() {
                            return Err(ActorExecutionError::InvalidActorOutput);
                        }
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let len = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= super::actor_storage::MAX_ROW_DELTA_BYTES)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        // Account for guest-memory copy and owned decoded rows
                        // before allocating either representation.
                        if !host_budget.fetch(
                            len.checked_mul(2)
                                .ok_or(ActorExecutionError::InvalidInput)?,
                        ) {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                                rows: Vec::new(),
                            });
                        }
                        let mut bytes = vec![0; len];
                        machine
                            .read(address, &mut bytes)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let changes = super::actor_storage::decode_row_delta(&bytes)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                        storage
                            .validate_delta(&changes)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                        exported_rows = Some(changes);
                        (0, 0)
                    }
                    value if value == u64::from(hostcall::STORAGE_R) => {
                        let storage =
                            storage.ok_or(ActorExecutionError::UnsupportedHostCall(id))?;
                        let key_address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let key_len = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len > 0 && *len <= super::actor_storage::MAX_KEY_BYTES)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        let address = u32::try_from(registers[9])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let capacity = usize::try_from(registers[10])
                            .ok()
                            .filter(|len| *len <= crate::actors::storage::MAX_VALUE_BYTES)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        // Charge before allocating or touching guest memory, including
                        // absent-key probes. The full key participates in ownership.
                        if !host_budget.fetch(key_len) {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                                rows: Vec::new(),
                            });
                        }
                        let mut key = vec![0; key_len];
                        machine
                            .read(key_address, &mut key)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let row = storage.read(&key).map_err(|error| match error {
                            // Missing/corrupt blocks and exhausted provider
                            // budgets are not durable actor rejections.
                            #[cfg(feature = "experimental-state-blocks")]
                            super::actor_storage::StorageAccessError::External(_) => {
                                ActorExecutionError::InvalidAvailability
                            }
                            _ => ActorExecutionError::InvalidInput,
                        })?;
                        match row {
                            None => (error::HOST_NONE, 0),
                            Some(row) => {
                                // STORAGE_R returns full length and copies a prefix;
                                // a size probe does not copy or charge unseen bytes.
                                let copied = row.len().min(capacity);
                                if !ActorHostBudget::charge(
                                    &mut host_budget.fetch_bytes,
                                    copied,
                                    MAX_EXECUTION_FETCH_BYTES,
                                ) {
                                    return Ok(ActorRunOutcome::Completed {
                                        reply: terminal_reply(
                                            invocation,
                                            ActorExecutionStatus::OutOfGas,
                                            0,
                                        ),
                                        state: actor_state.clone(),
                                        rows: Vec::new(),
                                    });
                                }
                                if copied != 0 {
                                    machine
                                        .write(address, &row[..copied])
                                        .map_err(|_| ActorExecutionError::InvalidInput)?;
                                }
                                (row.len() as u64, 0)
                            }
                        }
                    }
                    value if value == u64::from(hostcall::PREIMAGE_LOOKUP) => {
                        let hash_address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let address = u32::try_from(registers[8])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let capacity = usize::try_from(registers[9])
                            .ok()
                            .filter(|len| *len <= MAX_EXECUTION_AVAILABILITY_BYTES)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        // Charge the key read even for an absent blob. The collection
                        // is validated on admission; lookup never consults ambient IO.
                        if !host_budget.fetch(32) {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                                rows: Vec::new(),
                            });
                        }
                        let mut hash = [0; 32];
                        machine
                            .read(hash_address, &mut hash)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        match invocation
                            .availability
                            .binary_search_by_key(&Hash(hash), |blob| blob.reference.hash)
                        {
                            Err(_) => (error::HOST_NONE, 0),
                            Ok(index) => {
                                let blob = &invocation.availability[index];
                                let work = blob
                                    .bytes
                                    .len()
                                    .checked_mul(2)
                                    .ok_or(ActorExecutionError::InvalidInput)?;
                                // Use the persisted FETCH byte counter, without
                                // consuming a second call, before hashing/copying.
                                if !ActorHostBudget::charge(
                                    &mut host_budget.fetch_bytes,
                                    work,
                                    MAX_EXECUTION_FETCH_BYTES,
                                ) {
                                    return Ok(ActorRunOutcome::Completed {
                                        reply: terminal_reply(
                                            invocation,
                                            ActorExecutionStatus::OutOfGas,
                                            0,
                                        ),
                                        state: actor_state.clone(),
                                        rows: Vec::new(),
                                    });
                                }
                                let bytes = invocation
                                    .available_preimage(&blob.reference)?
                                    .ok_or(ActorExecutionError::InvalidAvailability)?;
                                if capacity < bytes.len() {
                                    (error::HOST_FULL, 0)
                                } else {
                                    machine
                                        .write(address, bytes)
                                        .map_err(|_| ActorExecutionError::InvalidInput)?;
                                    (bytes.len() as u64, 0)
                                }
                            }
                        }
                    }
                    value if value == u64::from(hostcall::FETCH) => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let capacity = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= MAX_EXECUTION_STATE_BYTES + 1)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        if let Some(item) = fetch.get(fetch_index) {
                            let copied = item.len().min(capacity);
                            if !host_budget.fetch(copied) {
                                return Ok(ActorRunOutcome::Completed {
                                    reply: terminal_reply(
                                        invocation,
                                        ActorExecutionStatus::OutOfGas,
                                        0,
                                    ),
                                    state: actor_state.clone(),
                                    rows: Vec::new(),
                                });
                            }
                            machine
                                .write(address, &item[..copied])
                                .map_err(|_| ActorExecutionError::InvalidInput)?;
                            if item.len() <= capacity {
                                fetch_index += 1;
                            }
                            (item.len() as u64, 0)
                        } else {
                            (0, 0)
                        }
                    }
                    // The standard loader maps the program-declared heap up
                    // front. This call is therefore an accounting seam, not
                    // permission to mutate pages outside that declaration.
                    value if value == u64::from(hostcall::GROW_HEAP) => (error::HOST_OK, 0),
                    #[cfg(feature = "agent-runtime")]
                    value if value == u64::from(crate::crypto::ECALL_BLAKE2B_COMPRESS) => {
                        if !host_budget.blake2b_compression() {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                                rows: Vec::new(),
                            });
                        }
                        let h_address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let m_address = u32::try_from(registers[8])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let mut h = [0u8; 64];
                        let mut block = [0u8; 128];
                        machine
                            .read(h_address, &mut h)
                            .and_then(|()| machine.read(m_address, &mut block))
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        crate::crypto::blake2b::host_compress_block(
                            &mut h,
                            &block,
                            registers[9] as u128,
                            registers[10] != 0,
                        );
                        machine
                            .write(h_address, &h)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        // Crypto precompiles are memory transforms. Preserve
                        // their argument registers exactly like tracing does;
                        // actor code reads the digest through `h_address`.
                        (registers[7], registers[8])
                    }
                    // Guest diagnostics never cross the deterministic runtime
                    // boundary. Validate the readable window, then discard it.
                    value if value == u64::from(hostcall::DEBUG_WRITE) => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let len = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= 8 * 1024)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        if !host_budget.debug(len) {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                                rows: Vec::new(),
                            });
                        }
                        let mut discarded = alloc::vec![0u8; len];
                        machine
                            .read(address, &mut discarded)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        // Opt-in fixture diagnostics only: production execution
                        // continues to discard guest output deterministically.
                        #[cfg(test)]
                        if std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some() {
                            std::eprint!("{}", String::from_utf8_lossy(&discarded));
                        }
                        (len as u64, 0)
                    }
                    other => return Err(ActorExecutionError::UnsupportedHostCall(other)),
                };
                let registers = machine.registers_mut();
                registers[7] = result0;
                registers[8] = result1;
            }
        }
    }
}

#[cfg(feature = "pvm")]
fn terminal_reply(
    invocation: &ActorInvocation,
    status: ActorExecutionStatus,
    gas_remaining: u64,
) -> ActorExecutionReply {
    ActorExecutionReply {
        invocation: invocation.invocation,
        actor: invocation.actor,
        incarnation: invocation.incarnation,
        deployment: invocation.deployment,
        mode: invocation.mode,
        lane: invocation.mode.write_lane(),
        status,
        reply: Vec::new(),
        gas_remaining,
        observation: ActorObservation::default(),
    }
}

#[cfg(feature = "pvm")]
fn decode_actor_output(
    invocation: &ActorInvocation,
    gas_remaining: u64,
    output: Vec<u8>,
) -> Result<(ActorExecutionReply, ActorStateLanes), ActorExecutionError> {
    if output.len() < 13 {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let linear_len = u32::from_le_bytes(
        output[1..5]
            .try_into()
            .expect("the output length was checked above"),
    ) as usize;
    let merge_len = u32::from_le_bytes(output[5..9].try_into().unwrap()) as usize;
    let local_len = u32::from_le_bytes(output[9..13].try_into().unwrap()) as usize;
    if linear_len > MAX_EXECUTION_STATE_BYTES
        || merge_len > MAX_EXECUTION_STATE_BYTES
        || local_len > MAX_EXECUTION_STATE_BYTES
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let linear_end = 13usize
        .checked_add(linear_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    let merge_end = linear_end
        .checked_add(merge_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    let local_end = merge_end
        .checked_add(local_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    if linear_len
        .checked_add(merge_len)
        .and_then(|len| len.checked_add(local_len))
        .is_none_or(|len| len > MAX_EXECUTION_STATE_TOTAL_BYTES)
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    if output.len() - local_end > MAX_EXECUTION_REPLY_BYTES {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let status = match output[0] {
        crate::actors::STATUS_DONE => ActorExecutionStatus::Done,
        crate::actors::STATUS_FORBIDDEN => ActorExecutionStatus::Forbidden,
        crate::actors::STATUS_PANICKED => ActorExecutionStatus::Panicked,
        crate::actors::STATUS_OOG => ActorExecutionStatus::OutOfGas,
        crate::actors::STATUS_YIELDED => ActorExecutionStatus::Yielded,
        _ => return Err(ActorExecutionError::InvalidActorOutput),
    };
    let next_state = ActorStateLanes {
        linear: Some(output[13..linear_end].to_vec()),
        merge: Some(output[linear_end..merge_end].to_vec()),
        local: Some(output[merge_end..local_end].to_vec()),
    };
    let reply = output[local_end..].to_vec();
    Ok((
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: invocation.mode.write_lane(),
            status,
            reply,
            gas_remaining,
            observation: ActorObservation::default(),
        },
        next_state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> ActorInvocation {
        ActorInvocation {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([5; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        }
    }

    fn source_service() -> ServiceIdentity {
        ServiceIdentity {
            space: crate::service::SpaceId([0x11; 32]),
            root_service: crate::service::RootServiceId([0x12; 32]),
            deployment: DeploymentId([0x13; 32]),
            service_program: ProgramId([0x14; 32]),
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1, 1),
        }
    }

    #[test]
    fn inner_message_admission_matches_clean_sdk_boundary() {
        let mut call = invocation();
        call.message = vec![1; crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES];
        assert_eq!(call.validate(), Ok(()));
        call.message.push(1);
        assert_eq!(call.validate(), Err(ActorExecutionError::InvalidInput));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn maximum_clean_input_fetches_include_guest_probe_cost() {
        let mut budget = ActorHostBudget::default();
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        for bytes in [
            lane + 1,
            lane + 1,
            lane + 1,
            ACTOR_DISPATCH_CONTROL_CAPACITY,
            MAX_EXECUTION_MESSAGE_BYTES,
        ] {
            assert!(budget.fetch(ACTOR_FETCH_PROBE_BYTES));
            assert!(budget.fetch(bytes));
        }
        for _ in 0..MAX_EXECUTION_BLOBS {
            assert!(budget.fetch(32 + 2 * MAX_EXECUTION_AVAILABILITY_BYTES / MAX_EXECUTION_BLOBS));
        }
        assert_eq!(budget.fetch_bytes as usize, MAX_EXECUTION_FETCH_BYTES);
        assert!(!budget.fetch(1));
    }

    #[test]
    fn invocation_preimages_enforce_individual_and_aggregate_byte_limits() {
        let mut call = invocation();
        let oversized = vec![0x41; MAX_EXECUTION_AVAILABILITY_BYTES + 1];
        let reference = BlobRef::of_bytes(&oversized);
        call.availability.push(RuntimeBlob {
            reference: reference.clone(),
            bytes: oversized,
        });
        assert_eq!(
            call.available_preimage(&reference),
            Err(ActorExecutionError::InvalidInput)
        );

        let size = MAX_EXECUTION_AVAILABILITY_BYTES / 2 + 1;
        assert!(size <= MAX_EXECUTION_AVAILABILITY_BYTES);
        call.availability = [0x41, 0x42]
            .into_iter()
            .map(|marker| {
                let bytes = vec![marker; size];
                RuntimeBlob {
                    reference: BlobRef::of_bytes(&bytes),
                    bytes,
                }
            })
            .collect();
        call.availability.sort_by_key(|blob| blob.reference.hash);
        let selected = call.availability[0].reference.clone();
        assert_eq!(
            call.available_preimage(&selected),
            Err(ActorExecutionError::InvalidInput)
        );

        call.availability.truncate(1);
        let bytes = vec![0x41; MAX_EXECUTION_AVAILABILITY_BYTES];
        let reference = BlobRef::of_bytes(&bytes);
        call.availability[0] = RuntimeBlob {
            reference: reference.clone(),
            bytes,
        };
        assert_eq!(
            call.available_preimage(&reference).unwrap().unwrap().len(),
            MAX_EXECUTION_AVAILABILITY_BYTES
        );
    }

    #[test]
    fn invocation_preimages_are_exact_bounded_and_invocation_local() {
        let bytes = vec![0x61; 36 * 1024];
        let reference = BlobRef::of_bytes(&bytes);
        let mut call = invocation();
        assert_eq!(call.available_preimage(&reference), Ok(None));
        call.availability.push(RuntimeBlob {
            reference: reference.clone(),
            bytes: bytes.clone(),
        });
        assert_eq!(call.validate(), Ok(()));
        assert_eq!(
            call.available_preimage(&reference),
            Ok(Some(bytes.as_slice()))
        );
        assert_eq!(invocation().available_preimage(&reference), Ok(None));
        let mut wrong_length = reference.clone();
        wrong_length.len += 1;
        assert_eq!(
            call.available_preimage(&wrong_length),
            Err(ActorExecutionError::InvalidInput)
        );
        call.availability[0].bytes[0] ^= 1;
        assert_eq!(
            call.available_preimage(&reference),
            Err(ActorExecutionError::InvalidInput)
        );
        call.availability[0].bytes[0] ^= 1;
        call.availability.push(call.availability[0].clone());
        assert_eq!(
            call.available_preimage(&reference),
            Err(ActorExecutionError::InvalidInput)
        );
        call.availability = vec![call.availability[0].clone(); MAX_EXECUTION_BLOBS + 1];
        assert_eq!(
            call.available_preimage(&reference),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[test]
    fn anonymous_auth_cannot_smuggle_authenticated_claims() {
        assert!(ActorInvocationAuth::anonymous().validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.origin_service = Some(source_service());
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.space_role = Some(crate::SpaceRole::Member.as_u8());
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.actor_role = Some(1);
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.capability = Some(CapabilityId::named("actor.write"));
        assert!(!auth.validate());
    }

    #[test]
    fn authenticated_origin_shapes_are_canonical() {
        let capability = CapabilityId::named("actor.write");
        assert!(
            ActorInvocationAuth {
                origin: Origin::System,
                principal: None,
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: Some(capability),
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::System,
                principal: None,
                origin_service: None,
                space_role: Some(crate::SpaceRole::Member.as_u8()),
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId::ZERO),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: Some(crate::SpaceRole::Member.as_u8()),
                actor_role: Some(1),
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(source_service()),
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(source_service()),
                space_role: None,
                actor_role: Some(1),
                capability: None,
            }
            .validate()
        );

        let mut malformed_service = source_service();
        malformed_service.platform = Hash::ZERO;
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(malformed_service),
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
    }

    #[test]
    fn authorization_commitment_binds_principal_roles_and_complete_actor_source() {
        let capability = CapabilityId::named("actor.write");
        let mut member = invocation();
        member.auth = ActorInvocationAuth {
            origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
            principal: Some(crate::service::PrincipalId([0x31; 32])),
            origin_service: None,
            space_role: Some(crate::SpaceRole::Member.as_u8()),
            actor_role: Some(3),
            capability: Some(capability),
        };
        let member_authorization = member.authorization_message();

        let mut forged_member = member.clone();
        forged_member.auth.origin = Origin::Member(crate::service::SubjectId([0x22; 32]));
        assert_ne!(forged_member.authorization_message(), member_authorization);
        let mut forged_role = member;
        forged_role.auth.actor_role = Some(4);
        assert_ne!(forged_role.authorization_message(), member_authorization);

        let mut actor = invocation();
        actor.auth = ActorInvocationAuth {
            origin: Origin::Actor(ActorId([0x31; 32])),
            principal: Some(crate::service::PrincipalId([0x32; 32])),
            origin_service: Some(source_service()),
            space_role: None,
            actor_role: Some(2),
            capability: None,
        };
        let actor_authorization = actor.authorization_message();

        // Reusing the same ActorId from another root is not authenticated as
        // the original caller: the complete source identity is committed.
        let mut forged_source = actor;
        forged_source
            .auth
            .origin_service
            .as_mut()
            .unwrap()
            .root_service = crate::service::RootServiceId([0x41; 32]);
        assert_ne!(forged_source.authorization_message(), actor_authorization);
    }

    #[test]
    fn invocation_gas_is_explicitly_bounded() {
        let mut invocation = invocation();
        invocation.gas = MAX_EXECUTION_GAS;
        assert_eq!(invocation.validate(), Ok(()));
        invocation.gas = MAX_EXECUTION_GAS + 1;
        assert_eq!(
            invocation.validate(),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn inner_actor_control_uses_exact_aic1_only_for_clean_calls() {
        use crate::agent_sdk::wire::CanonicalWire as _;

        let invocation = invocation();
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(invocation.invocation.0),
            actor: crate::agent_sdk::ActorId(invocation.actor.0),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin {
                principal: Some(crate::agent_sdk::PrincipalId([0x81; 32])),
                transport_node: Some(crate::agent_sdk::NodeId([0x82; 32])),
                credential: Some(crate::agent_sdk::CredentialId([0x83; 32])),
                actor: Some(crate::agent_sdk::ActorId([0x84; 32])),
                capability: None,
            },
            roles: crate::agent_sdk::InvocationRoleClaims {
                space: None,
                actor: Some(crate::agent_sdk::RoleId([0x85; 32])),
            },
            observed_slot: 86,
        };
        let clean = encode_inner_actor_control(&invocation, Some(context)).unwrap();
        assert_eq!(clean, context.encode().unwrap());
        assert_eq!(clean.get(..4), Some(b"AIC1".as_slice()));

        let legacy = encode_inner_actor_control(&invocation, None).unwrap();
        assert_eq!(legacy.get(..4), Some(b"AGDC".as_slice()));
        assert_ne!(legacy, clean);

        let mut wrong_target = context;
        wrong_target.actor = crate::agent_sdk::ActorId([0x87; 32]);
        assert_eq!(
            encode_inner_actor_control(&invocation, Some(wrong_target)),
            Err(ActorExecutionError::InvalidInput)
        );
        let mut wrong_mode = context;
        wrong_mode.mode = crate::agent_sdk::MethodMode::Merge;
        assert_eq!(
            encode_inner_actor_control(&invocation, Some(wrong_mode)),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn native_host_work_has_independent_quotas() {
        let mut budget = ActorHostBudget {
            calls: u32::try_from(MAX_EXECUTION_HOST_CALLS - 1).unwrap(),
            fetch_calls: u32::try_from(MAX_EXECUTION_FETCH_CALLS - 1).unwrap(),
            fetch_bytes: u32::try_from(MAX_EXECUTION_FETCH_BYTES - 1).unwrap(),
            blake2b_compressions: u32::try_from(MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS - 1).unwrap(),
            debug_bytes: u32::try_from(MAX_EXECUTION_DEBUG_BYTES - 1).unwrap(),
        };
        assert!(budget.host_call());
        assert!(!budget.host_call());
        assert!(budget.fetch(1));
        assert!(!budget.fetch(0));
        #[cfg(feature = "agent-runtime")]
        {
            assert!(budget.blake2b_compression());
            assert!(!budget.blake2b_compression());
        }
        assert!(budget.debug(1));
        assert!(!budget.debug(1));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn repeated_yield_finalizers_cannot_replenish_gas_or_native_work_budget() {
        let mut continuation = ActorMachineContinuation {
            machine: PortableMachineSnapshot {
                pc: 2,
                gas_remaining: 1_000,
                registers: [0; vos_pvm_program::REGISTER_COUNT],
                memory: Vec::new(),
            },
            fetch_index: 5,
            host_budget: ActorHostBudget {
                calls: 2,
                fetch_calls: 1,
                fetch_bytes: 9,
                blake2b_compressions: 0,
                debug_bytes: 3,
            },
        };
        charge_yield_finalizer(
            &mut continuation,
            800,
            ActorHostBudget {
                calls: 4,
                fetch_calls: 1,
                fetch_bytes: 9,
                blake2b_compressions: 0,
                debug_bytes: 7,
            },
        )
        .unwrap();
        charge_yield_finalizer(
            &mut continuation,
            600,
            ActorHostBudget {
                calls: 7,
                fetch_calls: 2,
                fetch_bytes: 20,
                blake2b_compressions: 1,
                debug_bytes: 7,
            },
        )
        .unwrap();
        assert_eq!(continuation.machine.gas_remaining, 600);
        assert_eq!(continuation.host_budget.calls, 7);
        assert_eq!(continuation.host_budget.fetch_bytes, 20);

        let charged = continuation.clone();
        assert_eq!(
            charge_yield_finalizer(
                &mut continuation,
                601,
                ActorHostBudget {
                    calls: 7,
                    fetch_calls: 2,
                    fetch_bytes: 20,
                    blake2b_compressions: 1,
                    debug_bytes: 7,
                },
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        );
        assert_eq!(continuation, charged);
        assert_eq!(
            charge_yield_finalizer(
                &mut continuation,
                500,
                ActorHostBudget {
                    calls: 6,
                    fetch_calls: 2,
                    fetch_bytes: 20,
                    blake2b_compressions: 1,
                    debug_bytes: 7,
                },
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        );
        assert_eq!(continuation, charged);
    }

    #[test]
    fn availability_enforces_the_aggregate_guest_budget() {
        let mut invocation = invocation();
        invocation.availability = [
            vec![1; MAX_EXECUTION_AVAILABILITY_BYTES / 2],
            vec![2; MAX_EXECUTION_AVAILABILITY_BYTES / 2],
        ]
        .into_iter()
        .map(|bytes| RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        })
        .collect();
        invocation
            .availability
            .sort_unstable_by_key(|blob| blob.reference.hash);
        assert_eq!(invocation.validate(), Ok(()));

        let bytes = vec![3];
        invocation.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        invocation
            .availability
            .sort_unstable_by_key(|blob| blob.reference.hash);
        assert_eq!(
            invocation.validate(),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[test]
    fn exact_outcome_error_classification_is_exhaustive() {
        for error in [
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ] {
            assert!(error.is_durable_exact_outcome(), "{error:?}");
        }
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
            ActorExecutionError::ContinuationNotReady,
        ] {
            assert!(!error.is_durable_exact_outcome(), "{error:?}");
        }
    }

    #[cfg(feature = "pvm")]
    fn actor_output(lanes: [usize; 3], reply: usize) -> Vec<u8> {
        let mut output = vec![0; 13 + lanes.iter().sum::<usize>() + reply];
        output[0] = crate::actors::STATUS_DONE;
        output[1..5].copy_from_slice(&(lanes[0] as u32).to_le_bytes());
        output[5..9].copy_from_slice(&(lanes[1] as u32).to_le_bytes());
        output[9..13].copy_from_slice(&(lanes[2] as u32).to_le_bytes());
        output
    }

    #[cfg(feature = "agent-runtime")]
    #[test]
    #[ignore = "requires candidate Authority ELF and exported fixed-roster fixture"]
    fn compiled_authority_fixed_roster_queries_match_native() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        let root =
            std::path::PathBuf::from(std::env::var("AUTHORITY_FIXED_ROSTER_FIXTURE").unwrap());
        let read = |name: &str| std::fs::read(root.join(name)).unwrap();
        let elf = std::fs::read(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()).unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        assert!(program.len() <= MAX_EXECUTION_PROGRAM_BYTES);
        let schema = crate::agent_sdk::schema::decode(
            &super::super::schema::raw_section_from_elf(&elf).unwrap(),
        )
        .unwrap();
        let config_bytes = read("configuration");
        let config = system_authority::SystemAuthorityConfiguration::decode(&config_bytes).unwrap();
        assert!(config.bootstrap_additional_nodes.is_some());
        let image = ActorLaneImage::from_parts(read("linear"), Default::default());
        let access = ActorStorageAccess::new(
            &schema,
            "inventory_projection_page",
            crate::agent_sdk::MethodMode::Query,
        )
        .unwrap();
        let reader = ActorStorageReader::new(&access, Some(&image), None, None).unwrap();
        let before = ActorStateLanes {
            linear: Some(image.inline().to_vec()),
            merge: Some(Vec::new()),
            local: Some(Vec::new()),
        };
        for seed in [0x31, 0x32, 0x33] {
            let mut call = invocation();
            call.actor = ActorId(config.binding.issuer.actor);
            call.mode = MethodMode::Query;
            call.gas = MAX_EXECUTION_GAS;
            call.message = vec![TAG_DYNAMIC];
            call.message.extend(
                Msg::new("inventory_projection_page")
                    .with("query", Value::Bytes(read(&std::format!("query-{seed}"))))
                    .encode(),
            );
            let context = crate::agent_sdk::InvocationContext {
                invocation: crate::agent_sdk::InvocationId(call.invocation.0),
                actor: crate::agent_sdk::ActorId(call.actor.0),
                mode: crate::agent_sdk::MethodMode::Query,
                origin: crate::agent_sdk::InvocationOrigin::anonymous(),
                roles: crate::agent_sdk::InvocationRoleClaims::none(),
                observed_slot: 1,
            };
            // First execute the constructor from installation data alone;
            // then restore and repeat against the native canonical image.
            for input in [&ActorStateLanes::default(), &before, &before] {
                let ActorRunOutcome::Completed { reply, state, rows } =
                    run_inner_actor_with_storage(
                        &call,
                        Some(context),
                        &program,
                        Some(&config_bytes),
                        input,
                        None,
                        Some(&reader),
                    )
                    .expect("fixed-roster guest query")
                else {
                    panic!("query yielded")
                };
                assert_eq!(reply.status, ActorExecutionStatus::Done);
                assert_eq!(
                    Value::decode(&reply.reply),
                    Value::Bytes(read(&std::format!("reply-{seed}")))
                );
                // Query dispatch echoes its input lanes, even when the guest
                // constructs an ephemeral initial state to answer the query.
                // It must not persist that state as a side effect of inspection.
                assert_eq!(
                    state.linear.as_deref(),
                    Some(input.linear.as_deref().unwrap_or(&[]))
                );
                assert_eq!(state.merge.as_deref(), Some(&[][..]));
                assert_eq!(state.local.as_deref(), Some(&[][..]));
                assert!(rows.is_empty());
                std::eprintln!(
                    "fixed-roster node={seed} gas_remaining={}",
                    reply.gas_remaining
                );
            }
        }
    }

    #[cfg(feature = "agent-runtime")]
    #[test]
    #[ignore = "requires Authority candidate ELF and exported signed publication fixture"]
    fn compiled_authority_publication_matches_native_state_and_retry() {
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        use crate::agent_sdk::wire::CanonicalWire as _;
        let root = std::path::PathBuf::from(
            std::env::var("AUTHORITY_PUBLICATION_FIXTURE")
                .expect("set AUTHORITY_PUBLICATION_FIXTURE to the explicit exported fixture"),
        );
        let read = |name| std::fs::read(root.join(name)).expect("read publication fixture");
        let elf = std::fs::read(
            std::env::var("AUTHORITY_CANDIDATE_ELF").expect("set AUTHORITY_CANDIDATE_ELF"),
        )
        .expect("read Authority ELF");
        let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link Authority ELF");
        assert!(program.len() <= MAX_EXECUTION_PROGRAM_BYTES);
        if let Some(path) = std::env::var_os("VOS_TEST_INNER_PROGRAM_EXPORT") {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(&program)
                .unwrap();
        }
        let schema = crate::agent_sdk::schema::decode(
            &super::super::schema::raw_section_from_elf(&elf).expect("Authority schema"),
        )
        .unwrap();
        let access = super::super::actor_storage::ActorStorageAccess::new(
            &schema,
            "publish_genesis",
            crate::agent_sdk::MethodMode::Linear,
        )
        .unwrap();
        let image = super::super::actor_storage::ActorLaneImage::from_parts(
            Vec::new(),
            Decode::decode(&read("node-rows")),
        );
        let reader =
            super::super::actor_storage::ActorStorageReader::new(&access, Some(&image), None, None)
                .unwrap();
        let mut context = crate::agent_sdk::InvocationContext::decode(&read("context")).unwrap();
        let config = read("configuration");
        let provision = read("provision");
        let decoded =
            <super::super::genesis::AgentGenesisProvision as crate::service::ServiceWire>::decode(
                &provision,
            )
            .unwrap();
        for member in decoded.replicas().members() {
            assert_ne!(
                member.replica().principal,
                crate::service::PrincipalId::of_public_key(member.ed25519_public_key()),
                "publication fixture must exercise distinct logical owner and transport identity"
            );
        }
        let reference = BlobRef::of_bytes(&provision);
        let expected_state = read("published-linear");
        let expected_reply = read("decision");
        let mut state = ActorStateLanes {
            linear: Some(read("pending-linear")),
            ..Default::default()
        };
        let mut call = invocation();
        call.invocation = InvocationId(context.invocation.0);
        call.actor = ActorId(context.actor.0);
        call.mode = MethodMode::Linear;
        call.gas = MAX_EXECUTION_GAS;
        call.message = vec![TAG_DYNAMIC];
        call.message.extend(
            Msg::new("publish_genesis")
                .with("authorization", Value::Bytes(read("authorization")))
                .with("provision_hash", Value::Bytes(reference.hash.0.to_vec()))
                .with("provision_len", Value::U64(reference.len))
                .encode(),
        );
        for phase in 0..3 {
            if phase == 1 {
                call.availability.push(RuntimeBlob {
                    reference: reference.clone(),
                    bytes: provision.clone(),
                });
            }
            if phase == 2 {
                context.observed_slot = u64::MAX;
            }
            call.validate().unwrap();
            let ActorRunOutcome::Completed {
                reply,
                state: next,
                rows,
            } = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                Some(&config),
                &state,
                None,
                Some(&reader),
            )
            .expect("execute Authority publication")
            else {
                panic!("publication yielded")
            };
            assert!(
                rows.is_empty(),
                "publication must not rewrite enrollment certificates"
            );
            std::eprintln!(
                "Authority publication phase={phase} status={:?} gas_remaining={}",
                reply.status,
                reply.gas_remaining
            );
            assert_eq!(reply.status, ActorExecutionStatus::Done);
            let expected = if phase == 0 {
                Vec::new()
            } else {
                expected_reply.clone()
            };
            assert_eq!(Value::decode(&reply.reply), Value::Bytes(expected));
            if phase == 0 {
                assert_eq!(
                    next.linear, state.linear,
                    "missing blob changed pending state"
                );
            } else {
                assert_eq!(
                    next.linear.as_deref(),
                    Some(expected_state.as_slice()),
                    "guest/native publication state differs"
                );
            }
            state = next;
        }
    }

    #[cfg(feature = "agent-runtime")]
    #[test]
    #[ignore = "requires Authority candidate ELF and exported AUTHORITY_NODE_FIXTURE"]
    fn compiled_authority_genesis_committee_query_preserves_state() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use super::super::committee::{
            AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        };
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::ServiceWire as _;
        let root = std::path::PathBuf::from(std::env::var("AUTHORITY_NODE_FIXTURE").unwrap());
        let read = |name: &str| std::fs::read(root.join(name)).unwrap();
        let elf = std::fs::read(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()).unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        let schema = crate::agent_sdk::schema::decode(
            &super::super::schema::raw_section_from_elf(&elf).unwrap(),
        )
        .unwrap();
        let config_bytes = read("configuration");
        let config = system_authority::SystemAuthorityConfiguration::decode(&config_bytes).unwrap();
        let binding = crate::agent_sdk::authority::AgentAuthorityBinding {
            policy: crate::agent_sdk::Hash(config.binding.policy),
            issuer: crate::agent_sdk::authority::AuthorityIssuer {
                principal: crate::agent_sdk::PrincipalId(config.binding.issuer.principal),
                actor: crate::agent_sdk::ActorId(config.binding.issuer.actor),
                deployment: crate::agent_sdk::DeploymentId(config.binding.issuer.deployment),
                program: crate::agent_sdk::ProgramId(config.binding.issuer.program),
                producer: crate::agent_sdk::ProducerId(config.binding.issuer.producer),
            },
            public_key: config.binding.public_key,
            initial_epoch: config.binding.initial_epoch,
        };
        let expected = AuthorityCommittee::new(
            crate::service::SpaceId(config.space),
            crate::service::Hash(binding.commitment().0),
            1,
            None,
            vec![
                AuthorityCommitteeMember::new(
                    crate::service::NodeId(config.bootstrap_node),
                    config.bootstrap_credential_public_key,
                    AuthorityMemberRole::Voter,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let image = ActorLaneImage::from_parts(
            read("initial-linear"),
            Decode::decode(&read("initial-rows")),
        );
        let access = ActorStorageAccess::new(
            &schema,
            "genesis_signing_committee",
            crate::agent_sdk::MethodMode::Query,
        )
        .unwrap();
        let reader = ActorStorageReader::new(&access, Some(&image), None, None).unwrap();
        let mut context =
            crate::agent_sdk::InvocationContext::decode(&read("enroll-context")).unwrap();
        context.mode = crate::agent_sdk::MethodMode::Query;
        let mut call = invocation();
        call.invocation = InvocationId(context.invocation.0);
        call.actor = ActorId(context.actor.0);
        call.mode = MethodMode::Query;
        call.gas = MAX_EXECUTION_GAS;
        call.message = vec![TAG_DYNAMIC];
        call.message
            .extend(Msg::new("genesis_signing_committee").encode());
        call.validate().unwrap();
        let before = ActorStateLanes {
            linear: Some(image.inline().to_vec()),
            merge: Some(Vec::new()),
            local: Some(Vec::new()),
        };
        for _ in 0..2 {
            let ActorRunOutcome::Completed { reply, state, rows } = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                Some(&config_bytes),
                &before,
                None,
                Some(&reader),
            )
            .unwrap() else {
                panic!("committee query yielded");
            };
            assert_eq!(reply.status, ActorExecutionStatus::Done);
            assert_eq!(Value::decode(&reply.reply), Value::Bytes(expected.encode()));
            assert!(state == before, "committee query changed inline state");
            assert!(rows.is_empty(), "committee query exported rows");
        }
    }

    #[cfg(feature = "agent-runtime")]
    #[test]
    #[ignore = "requires Authority candidate ELF and exported AUTHORITY_NODE_FIXTURE"]
    fn compiled_authority_malformed_entrypoints_preserve_rows() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        use crate::agent_sdk::wire::CanonicalWire as _;
        let root = std::path::PathBuf::from(std::env::var("AUTHORITY_NODE_FIXTURE").unwrap());
        let read = |name: &str| std::fs::read(root.join(name)).unwrap();
        let elf = std::fs::read(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()).unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        let schema = crate::agent_sdk::schema::decode(
            &super::super::schema::raw_section_from_elf(&elf).unwrap(),
        )
        .unwrap();
        let config = read("configuration");
        let image = ActorLaneImage::from_parts(
            read("initial-linear"),
            Decode::decode(&read("initial-rows")),
        );
        let context = crate::agent_sdk::InvocationContext::decode(&read("enroll-context")).unwrap();
        for (method, argument, expected) in [
            ("authorize", "call", Value::Bytes(Vec::new())),
            ("authorize_operation", "call", Value::Bytes(Vec::new())),
            ("administer", "call", Value::Bytes(Vec::new())),
            ("finalize", "ack", Value::Bool(false)),
            ("acknowledge_issuance", "ack", Value::Bool(false)),
            ("resolve_private_application", "ack", Value::Bool(false)),
        ] {
            let access =
                ActorStorageAccess::new(&schema, method, crate::agent_sdk::MethodMode::Linear)
                    .unwrap();
            let reader = ActorStorageReader::new(&access, Some(&image), None, None).unwrap();
            let mut call = invocation();
            call.invocation = InvocationId(context.invocation.0);
            call.actor = ActorId(context.actor.0);
            call.mode = MethodMode::Linear;
            call.gas = MAX_EXECUTION_GAS;
            call.message = vec![TAG_DYNAMIC];
            call.message.extend(
                Msg::new(method)
                    .with(argument, Value::Bytes(Vec::new()))
                    .encode(),
            );
            call.validate().unwrap();
            let before = ActorStateLanes {
                linear: Some(image.inline().to_vec()),
                merge: Some(Vec::new()),
                local: Some(Vec::new()),
            };
            let ActorRunOutcome::Completed { reply, state, rows } = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                Some(&config),
                &before,
                None,
                Some(&reader),
            )
            .unwrap() else {
                panic!("malformed request yielded");
            };
            assert_eq!(reply.status, ActorExecutionStatus::Done, "{method}");
            assert_eq!(Value::decode(&reply.reply), expected, "{method}");
            assert!(
                state == before,
                "{method}: refused request changed inline state"
            );
            assert!(rows.is_empty(), "{method}: refused request exported rows");
        }
    }

    #[cfg(feature = "agent-runtime")]
    #[test]
    #[ignore = "requires Authority candidate ELF and exported AUTHORITY_NODE_FIXTURE"]
    fn compiled_authority_node_mutations_match_native_rows_and_retry() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        use crate::agent_sdk::wire::CanonicalWire as _;
        let root = std::path::PathBuf::from(std::env::var("AUTHORITY_NODE_FIXTURE").unwrap());
        let read = |name: &str| std::fs::read(root.join(name)).expect("read node mutation fixture");
        let elf = std::fs::read(std::env::var("AUTHORITY_CANDIDATE_ELF").unwrap()).unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        let schema = crate::agent_sdk::schema::decode(
            &super::super::schema::raw_section_from_elf(&elf).unwrap(),
        )
        .unwrap();
        let access =
            ActorStorageAccess::new(&schema, "administer", crate::agent_sdk::MethodMode::Linear)
                .unwrap();
        let config = read("configuration");
        let mut image = ActorLaneImage::from_parts(
            read("initial-linear"),
            Decode::decode(&read("initial-rows")),
        );
        for (phase, (message, context, expected_reply, expected_state, mutation)) in [
            ("bad-call", "enroll-context", None, "initial", false),
            (
                "enroll-call",
                "enroll-context",
                Some("enroll-reply"),
                "enrolled",
                true,
            ),
            (
                "enroll-call",
                "enroll-context",
                Some("enroll-reply"),
                "enrolled",
                false,
            ),
            ("bad-call", "enroll-context", None, "enrolled", false),
            (
                "remove-call",
                "remove-context",
                Some("remove-reply"),
                "removed",
                true,
            ),
            (
                "remove-call",
                "remove-context",
                Some("remove-reply"),
                "removed",
                false,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let context = crate::agent_sdk::InvocationContext::decode(&read(context)).unwrap();
            let mut call = invocation();
            call.invocation = InvocationId(context.invocation.0);
            call.actor = ActorId(context.actor.0);
            call.mode = MethodMode::Linear;
            call.gas = MAX_EXECUTION_GAS;
            call.message = vec![TAG_DYNAMIC];
            call.message.extend(
                Msg::new("administer")
                    .with("call", Value::Bytes(read(message)))
                    .encode(),
            );
            call.validate().unwrap();
            let reader = ActorStorageReader::new(&access, Some(&image), None, None).unwrap();
            let state = ActorStateLanes {
                linear: Some(image.inline().to_vec()),
                ..Default::default()
            };
            let ActorRunOutcome::Completed {
                reply,
                state: next,
                rows,
            } = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                Some(&config),
                &state,
                None,
                Some(&reader),
            )
            .unwrap()
            else {
                panic!("node mutation yielded");
            };
            std::eprintln!(
                "Authority node phase={phase} status={:?} gas_remaining={} rows={}",
                reply.status,
                reply.gas_remaining,
                rows.len()
            );
            assert_eq!(reply.status, ActorExecutionStatus::Done);
            assert_eq!(
                Value::decode(&reply.reply),
                Value::Bytes(expected_reply.map(&read).unwrap_or_default())
            );
            assert_eq!(
                !rows.is_empty(),
                mutation,
                "retry/refusal must not export rows"
            );
            if phase == 4 {
                assert!(
                    rows.iter().any(|(_, value)| value.is_none()),
                    "removal must export a tombstone"
                );
            }
            access
                .apply_batch(
                    crate::agent_sdk::StateLane::Linear,
                    &mut image,
                    next.linear.unwrap(),
                    rows,
                )
                .unwrap();
            // Reconstruct both inline state and rows before each subsequent
            // slice; compare the full image, including untouched bootstrap data.
            image = ActorLaneImage::decode(&image.encode().unwrap()).unwrap();
            let expected = ActorLaneImage::from_parts(
                read(&format!("{expected_state}-linear")),
                Decode::decode(&read(&format!("{expected_state}-rows"))),
            );
            assert!(
                image.encode().unwrap() == expected.encode().unwrap(),
                "phase {phase}: native/guest row image differs"
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AUTHORITY_CANDIDATE_ELF built from current system-authority source"]
    fn compiled_authority_candidate_fits_inner_loader() {
        let path = std::env::var("AUTHORITY_CANDIDATE_ELF")
            .expect("set AUTHORITY_CANDIDATE_ELF to the freshly built Authority ELF");
        let elf = std::fs::read(path).expect("read Authority ELF");
        let schema_bytes = super::super::schema::raw_section_from_elf(&elf)
            .expect("Authority must publish its signed clean schema");
        let schema =
            crate::agent_sdk::schema::decode(&schema_bytes).expect("decode Authority clean schema");
        let storage = schema
            .fields
            .iter()
            .filter_map(|field| match field {
                crate::agent_sdk::schema::ParsedField::Storage(field) => Some(field),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(storage.len(), 1);
        assert_eq!(storage[0].name, "node_certificates");
        assert_eq!(storage[0].prefix, b"s/authority-nodes/");
        assert_eq!(storage[0].lane, crate::agent_sdk::StateLane::Linear);
        assert!(!storage[0].committed);
        let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link Authority ELF");
        std::eprintln!("Authority candidate PVM bytes={}", program.len());
        assert!(
            program.len() <= MAX_EXECUTION_PROGRAM_BYTES,
            "Authority program exceeds the inner actor admission bound"
        );
        super::super::machine::ActorMachine::load(&program, &[])
            .expect("Authority candidate must load in the real inner machine");
        // Loading is not execution or package/release qualification. The full
        // authenticated publication campaign must supply real configuration,
        // pending state, availability and context before it can prove that.
    }

    #[cfg(feature = "pvm")]
    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn inner_actor_reads_external_rows_without_changing_its_abi() {
        use super::super::actor_storage::{
            ActorStorageAccess, ExternalActorStorageReader,
            tests::{external_rows_fixture, schema},
        };
        use crate::agent_sdk::{
            ActorId as SdkActorId, Hash as SdkHash, MethodMode as CleanMode,
            state_blocks::ReadBudget,
        };
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let mut call = invocation();
        call.gas = 100_000;
        let actor = SdkActorId(call.actor.0);
        let incarnation = SdkHash([5; 32]);
        let (tree, blocks) = external_rows_fixture(actor, incarnation, 1024);
        let access = ActorStorageAccess::new(&schema(), "method_3", CleanMode::Linear).unwrap();
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor,
            mode: CleanMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            observed_slot: 1,
        };
        let state = ActorStateLanes {
            linear: Some(Vec::new()),
            merge: Some(Vec::new()),
            local: Some(Vec::new()),
        };
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        let mut data = actor_output([0, 0, 0], 8);
        let key_address = base + data.len() as u32;
        data.extend_from_slice(b"s/0/42");
        let mut program = Assembler::new();
        program
            .set_rw_data(data)
            .load_imm_64(Reg::A0, key_address as u64)
            .load_imm_64(Reg::A1, 6)
            .load_imm_64(Reg::A2, (base + 13) as u64)
            .load_imm_64(Reg::A3, 8)
            .ecalli(crate::abi::hostcall::STORAGE_R)
            .load_imm_64(Reg::A0, base as u64)
            .load_imm_64(Reg::A1, 21)
            .jump_ind(Reg::RA, 0);
        let program = program.build_standard();
        for fault in 0..3 {
            let mut source = blocks.clone();
            if fault == 1 {
                source.blocks.clear();
            } else if fault == 2 {
                source
                    .blocks
                    .get_mut(&tree.root().unwrap().hash().0)
                    .unwrap()[0] ^= 0xff;
            }
            let mut budget = ReadBudget::new(100, 100000);
            let reader = ExternalActorStorageReader::new(
                access.clone(),
                actor,
                incarnation,
                [Some((tree, source)), None, None],
                &mut budget,
            )
            .unwrap();
            let outcome = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                None,
                &state,
                None,
                Some(&reader),
            );
            if fault != 0 {
                assert_eq!(outcome, Err(ActorExecutionError::InvalidAvailability));
                assert!(!ActorExecutionError::InvalidAvailability.is_durable_exact_outcome());
            } else {
                let ActorRunOutcome::Completed {
                    reply,
                    state: next,
                    rows,
                } = outcome.unwrap()
                else {
                    panic!("read yielded")
                };
                assert_eq!(reply.status, ActorExecutionStatus::Done);
                assert_eq!(reply.reply, 42u64.to_le_bytes());
                assert_eq!(next, state);
                assert!(rows.is_empty());
            }
            drop(reader);
            assert!(budget.remaining().0 < 100);
        }
        let mut budget = ReadBudget::new(0, 0);
        let reader = ExternalActorStorageReader::new(
            access,
            actor,
            incarnation,
            [Some((tree, blocks)), None, None],
            &mut budget,
        )
        .unwrap();
        assert_eq!(
            run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                None,
                &state,
                None,
                Some(&reader)
            ),
            Err(ActorExecutionError::InvalidAvailability)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn inner_storage_reads_are_scoped_bounded_and_preserve_state() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedMethod, ParsedSchema, ParsedStorageField,
        };
        use crate::agent_sdk::{MethodMode as CleanMode, StateLane as CleanLane};
        use vos_pvm_compiler::assembler::{Assembler, Reg};

        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: [CleanLane::Linear, CleanLane::Local]
                .into_iter()
                .enumerate()
                .map(|(index, lane)| {
                    ParsedField::Storage(ParsedStorageField {
                        source_index: index as u16,
                        name: alloc::format!("rows_{index}"),
                        type_identity: "test::StorageMap<u32,u64>".into(),
                        prefix: alloc::format!("s/{index}/").into_bytes(),
                        lane,
                        committed: false,
                        leaf_domain: None,
                        node_domain: None,
                    })
                })
                .collect(),
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "read".into(),
                mode: CleanMode::Linear,
                explicit: true,
            }],
        };
        let access = ActorStorageAccess::new(&schema, "read", CleanMode::Linear).unwrap();
        let mut image = ActorLaneImage::default();
        let max_row = crate::actors::storage::MAX_VALUE_BYTES;
        access
            .write(
                CleanLane::Linear,
                &mut image,
                b"s/0/value".to_vec(),
                Some(vec![0x71; max_row]),
            )
            .unwrap();
        access
            .write(
                CleanLane::Linear,
                &mut image,
                b"s/0/empty".to_vec(),
                Some(Vec::new()),
            )
            .unwrap();
        let reader = ActorStorageReader::new(&access, Some(&image), None, None).unwrap();
        let before_image = image.encode().unwrap();
        let mut call = invocation();
        call.gas = 100_000;
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor: crate::agent_sdk::ActorId(call.actor.0),
            mode: CleanMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            observed_slot: 1,
        };
        // The raw return frame represents empty lanes as present-empty.
        let state = ActorStateLanes {
            linear: Some(Vec::new()),
            merge: Some(Vec::new()),
            local: Some(Vec::new()),
        };
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        for (key, capacity, repeats, expected) in [
            (b"s/0/value".as_slice(), max_row, 1, Some(max_row as u64)),
            (b"s/0/value".as_slice(), 8, 1, Some(max_row as u64)),
            (b"s/0/value".as_slice(), 0, 1, Some(max_row as u64)),
            (b"s/0/empty".as_slice(), 8, 1, Some(0)),
            (
                b"s/0/missing".as_slice(),
                8,
                1,
                Some(crate::abi::error::HOST_NONE),
            ),
            (b"s/1/missing".as_slice(), 8, 1, None),
            (b"other/value".as_slice(), 8, 1, None),
            (b"".as_slice(), 8, 1, None),
            (b"s/0/value".as_slice(), max_row + 1, 1, None),
            (
                b"s/0/value".as_slice(),
                max_row,
                MAX_EXECUTION_FETCH_BYTES / max_row + 1,
                Some(0),
            ),
            (
                b"s/0/missing".as_slice(),
                0,
                MAX_EXECUTION_FETCH_CALLS + 1,
                Some(0),
            ),
        ] {
            let mut data = actor_output([0, 0, 0], 16);
            data.extend_from_slice(key);
            let buffer = base + data.len() as u32;
            data.resize(data.len() + max_row, 0);
            let mut program = Assembler::new();
            program.set_rw_data(data);
            for _ in 0..repeats {
                program
                    .load_imm_64(Reg::A0, u64::from(base + 29))
                    .load_imm_64(Reg::A1, key.len() as u64)
                    .load_imm_64(Reg::A2, u64::from(buffer))
                    .load_imm_64(Reg::A3, capacity as u64)
                    .ecalli(crate::abi::hostcall::STORAGE_R)
                    .store_u64(Reg::A0, base + 13);
            }
            program
                .load_imm_64(Reg::A0, u64::from(buffer))
                .load_ind_u64(Reg::A1, Reg::A0, 0)
                .store_u64(Reg::A1, base + 21)
                .load_imm_64(Reg::A0, u64::from(base))
                .load_imm_64(Reg::A1, 29)
                .jump_ind(Reg::RA, 0);
            let program = program.build_standard();
            let outcome = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                None,
                &state,
                None,
                Some(&reader),
            );
            if let Some(expected) = expected {
                let ActorRunOutcome::Completed {
                    reply, state: next, ..
                } = outcome.unwrap()
                else {
                    panic!("read yielded")
                };
                assert_eq!(next, state);
                if repeats > 1 {
                    assert_eq!(reply.status, ActorExecutionStatus::OutOfGas);
                } else {
                    assert_eq!(reply.status, ActorExecutionStatus::Done);
                    assert_eq!(
                        u64::from_le_bytes(reply.reply[..8].try_into().unwrap()),
                        expected
                    );
                    assert_eq!(
                        &reply.reply[8..],
                        &[if key == b"s/0/value" && capacity >= 8 {
                            0x71
                        } else {
                            0
                        }; 8]
                    );
                }
            } else {
                assert_eq!(outcome, Err(ActorExecutionError::InvalidInput));
            }
            assert_eq!(image.encode().unwrap(), before_image);
            assert_eq!(
                run_inner_actor(&call, Some(context), &program, None, &state, None),
                Err(ActorExecutionError::UnsupportedHostCall(u64::from(
                    crate::abi::hostcall::STORAGE_R
                )))
            );
            assert_eq!(
                run_inner_actor_with_storage(
                    &call,
                    None,
                    &program,
                    None,
                    &state,
                    None,
                    Some(&reader)
                ),
                Err(ActorExecutionError::InvalidInput)
            );
        }

        // The same row work quota survives real capture/restore boundaries.
        // Exhaust the configured byte budget across real slice boundaries.
        let successful_reads = (MAX_EXECUTION_FETCH_BYTES / (b"s/0/value".len() + max_row)) as u32;
        let finish = |program: &mut Assembler| {
            program
                .load_imm_64(Reg::A0, u64::from(base))
                .load_imm_64(Reg::A1, 13)
                .jump_ind(Reg::RA, 0);
        };
        let mut prefix = Assembler::new();
        prefix.jump(0);
        let finalizer_pc = prefix.current_offset();
        finish(&mut prefix);
        let entry_pc = prefix.current_offset();
        let key = b"s/0/value";
        let mut data = actor_output([0, 0, 0], 0);
        data[0] = crate::actors::STATUS_YIELDED;
        data.extend_from_slice(key);
        let buffer = base + data.len() as u32;
        data.resize(data.len() + max_row, 0);
        let mut program = Assembler::new();
        program.set_rw_data(data).jump(entry_pc);
        finish(&mut program);
        assert_eq!(program.current_offset(), entry_pc);
        for phase in 0..=successful_reads {
            program
                .load_imm_64(Reg::A0, u64::from(base + 13))
                .load_imm_64(Reg::A1, key.len() as u64)
                .load_imm_64(Reg::A2, u64::from(buffer))
                .load_imm_64(Reg::A3, max_row as u64)
                .ecalli(crate::abi::hostcall::STORAGE_R);
            if phase < successful_reads {
                program.ecalli(crate::abi::hostcall::SUSPEND);
                let pc = program.current_offset();
                program.branch_eq_imm(Reg::A0, 0, finalizer_pc.wrapping_sub(pc));
            }
        }
        program.trap();
        let program = program.build_standard();
        let mut state = state;
        let mut saved = None;
        for phase in 0..=successful_reads {
            match run_inner_actor_with_storage(
                &call,
                Some(context),
                &program,
                None,
                &state,
                saved.take(),
                Some(&reader),
            )
            .unwrap()
            {
                ActorRunOutcome::Yielded {
                    reply,
                    state: next,
                    continuation,
                    ..
                } => {
                    assert!(phase < successful_reads);
                    assert_eq!(reply.status, ActorExecutionStatus::Yielded);
                    assert_eq!(continuation.host_budget.fetch_calls, phase + 1);
                    assert_eq!(
                        continuation.host_budget.fetch_bytes as usize,
                        (phase as usize + 1) * (key.len() + max_row)
                    );
                    assert!(continuation.validate());
                    state = next;
                    saved = Some(continuation);
                }
                ActorRunOutcome::Completed {
                    reply, state: next, ..
                } => {
                    assert_eq!(phase, successful_reads);
                    assert_eq!(reply.status, ActorExecutionStatus::OutOfGas);
                    assert_eq!(next, state);
                }
            }
        }
        assert_eq!(image.encode().unwrap(), before_image);
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AGENT_STORAGE_PROBE_ELF built from current agent-yield fixture"]
    fn compiled_storage_map_reads_writes_and_resumes_clean_slices() {
        use super::super::actor_storage::{ActorLaneImage, ActorStorageAccess, ActorStorageReader};
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedMethod, ParsedSchema, ParsedStorageField,
        };
        use crate::agent_sdk::{MethodMode as Mode, StateLane as Lane};
        let elf = std::fs::read(std::env::var("AGENT_STORAGE_PROBE_ELF").expect("set fixture ELF"))
            .unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        // Explicit fixture scope for this inner-machine behavior test; package
        // signature/schema admission is covered separately at runtime dispatch.
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: vec![ParsedField::Storage(ParsedStorageField {
                source_index: 0,
                name: "rows".into(),
                type_identity: "test::StorageMap<u64,u64>".into(),
                prefix: b"s/rows/".to_vec(),
                lane: Lane::Local,
                committed: false,
                leaf_domain: None,
                node_domain: None,
            })],
            methods: [
                ("row_set", Mode::Local),
                ("row_get", Mode::LocalQuery),
                ("row_yield", Mode::Local),
                ("row_rejected", Mode::Local),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (name, mode))| ParsedMethod {
                source_index: index as u16,
                name: name.into(),
                mode,
                explicit: true,
            })
            .collect(),
        };
        let mut image = ActorLaneImage::default();
        for (step, (method, key, value, expected)) in [
            ("row_set", 7, Some(41), 41),
            ("row_rejected", 7, None, 41),
            ("row_get", 7, None, 41),
            ("row_rejected", 9, None, u64::MAX),
            ("row_get", 9, None, u64::MAX),
            ("row_yield", 8, None, 2),
            ("row_get", 8, None, 2),
        ]
        .into_iter()
        .enumerate()
        {
            image = ActorLaneImage::decode(&image.encode().unwrap()).unwrap();
            let mode = if method == "row_get" {
                Mode::LocalQuery
            } else {
                Mode::Local
            };
            let access = ActorStorageAccess::new(&schema, method, mode).unwrap();
            let mut call = invocation();
            call.invocation.0[0] = step as u8 + 1;
            call.mode = if method == "row_get" {
                MethodMode::LocalQuery
            } else {
                MethodMode::Local
            };
            call.gas = 100_000_000;
            let mut message = Msg::new(method).with("key", Value::U64(key));
            if let Some(value) = value {
                message = message.with("value", Value::U64(value));
            }
            call.message = vec![TAG_DYNAMIC];
            call.message.extend(message.encode());
            let context = crate::agent_sdk::InvocationContext {
                invocation: crate::agent_sdk::InvocationId(call.invocation.0),
                actor: crate::agent_sdk::ActorId(call.actor.0),
                mode,
                origin: crate::agent_sdk::InvocationOrigin::anonymous(),
                roles: crate::agent_sdk::InvocationRoleClaims::none(),
                observed_slot: 1,
            };
            let mut saved = None;
            let mut yields = 0;
            loop {
                let state = ActorStateLanes {
                    local: Some(image.inline().to_vec()),
                    ..Default::default()
                };
                let reader = ActorStorageReader::new(&access, None, None, Some(&image)).unwrap();
                let outcome = run_inner_actor_with_storage(
                    &call,
                    Some(context),
                    &program,
                    None,
                    &state,
                    saved.take(),
                    Some(&reader),
                )
                .unwrap();
                match outcome {
                    ActorRunOutcome::Yielded {
                        state: next,
                        rows,
                        continuation,
                        ..
                    } => {
                        yields += 1;
                        assert_eq!(yields, 1);
                        assert_eq!(method, "row_yield");
                        assert!(!rows.is_empty());
                        access
                            .apply_batch(Lane::Local, &mut image, next.local.unwrap(), rows)
                            .unwrap();
                        image = ActorLaneImage::decode(&image.encode().unwrap()).unwrap();
                        saved = Some(continuation);
                    }
                    ActorRunOutcome::Completed {
                        reply,
                        state: next,
                        rows,
                    } => {
                        assert_eq!(reply.status, ActorExecutionStatus::Done, "{method}");
                        assert_eq!(Value::decode(&reply.reply), Value::U64(expected));
                        if method == "row_get" || method == "row_rejected" {
                            assert!(rows.is_empty());
                            assert_eq!(next.local.as_deref(), Some(image.inline()));
                        } else {
                            access
                                .apply_batch(Lane::Local, &mut image, next.local.unwrap(), rows)
                                .unwrap();
                        }
                        assert_eq!(yields, usize::from(method == "row_yield"));
                        break;
                    }
                }
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn row_export_rejects_duplicate_exports_and_suspend_after_export() {
        use super::super::actor_storage::{
            ActorStorageAccess, ActorStorageReader, encode_row_delta,
        };
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedMethod, ParsedSchema, ParsedStorageField,
        };
        use crate::agent_sdk::{MethodMode as Mode, StateLane as Lane};
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: vec![ParsedField::Storage(ParsedStorageField {
                source_index: 0,
                name: "rows".into(),
                type_identity: "test::StorageMap<u32,u64>".into(),
                prefix: b"rows/".to_vec(),
                lane: Lane::Linear,
                committed: false,
                leaf_domain: None,
                node_domain: None,
            })],
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: Mode::Linear,
                explicit: true,
            }],
        };
        let access = ActorStorageAccess::new(&schema, "write", Mode::Linear).unwrap();
        let reader = ActorStorageReader::new(&access, None, None, None).unwrap();
        let mut call = invocation();
        call.gas = 100_000;
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor: crate::agent_sdk::ActorId(call.actor.0),
            mode: Mode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            observed_slot: 1,
        };
        let state = ActorStateLanes::default();
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        for case in 0..5 {
            let changes = if case == 4 {
                (0..=MAX_EXECUTION_FETCH_BYTES / (2 * 64 * 1024))
                    .map(|index| {
                        (
                            alloc::format!("rows/{index:04}").into_bytes(),
                            Some(vec![1; 64 * 1024]),
                        )
                    })
                    .collect()
            } else {
                vec![(
                    if case == 2 {
                        b"other/a".to_vec()
                    } else {
                        b"rows/a".to_vec()
                    },
                    Some(vec![1]),
                )]
            };
            let mut delta = encode_row_delta(&changes).unwrap();
            if case == 3 {
                delta[0] ^= 1;
            }
            let mut data = actor_output([0, 0, 0], 0);
            data.extend_from_slice(&delta);
            let mut program = Assembler::new();
            program.set_rw_data(data);
            for _ in 0..if case == 0 { 2 } else { 1 } {
                program
                    .load_imm_64(Reg::A0, u64::from(base + 13))
                    .load_imm_64(Reg::A1, delta.len() as u64)
                    .ecalli(crate::abi::hostcall::ACTOR_EFFECT_EXPORT);
            }
            if case == 1 {
                program.ecalli(crate::abi::hostcall::SUSPEND);
            }
            program
                .load_imm_64(Reg::A0, u64::from(base))
                .load_imm_64(Reg::A1, 13)
                .jump_ind(Reg::RA, 0);
            let outcome = run_inner_actor_with_storage(
                &call,
                Some(context),
                &program.build_standard(),
                None,
                &state,
                None,
                Some(&reader),
            );
            if case == 4 {
                let ActorRunOutcome::Completed {
                    reply,
                    state: next,
                    rows,
                } = outcome.unwrap()
                else {
                    panic!("oversized export yielded")
                };
                assert_eq!(reply.status, ActorExecutionStatus::OutOfGas);
                assert_eq!(next, state);
                assert!(rows.is_empty());
            } else {
                assert_eq!(outcome, Err(ActorExecutionError::InvalidActorOutput));
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn preimage_work_budget_survives_real_yield_and_resume() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let bytes = vec![0x63; MAX_EXECUTION_FETCH_BYTES / 5];
        let reference = BlobRef::of_bytes(&bytes);
        let base = 2 * u64::from(vos_pvm::PVM_ZONE_SIZE);
        let finish = |program: &mut Assembler| {
            program
                .load_imm_64(Reg::A0, base)
                .load_imm_64(Reg::A1, 13)
                .jump_ind(Reg::RA, 0);
        };
        let mut prefix = Assembler::new();
        prefix.jump(0);
        let finalizer_pc = prefix.current_offset();
        finish(&mut prefix);
        let entry_pc = prefix.current_offset();
        let mut output = actor_output([0, 0, 0], 0);
        output[0] = crate::actors::STATUS_YIELDED;
        output.extend_from_slice(&reference.hash.0);
        output.resize(45 + bytes.len(), 0);
        let mut program = Assembler::new();
        program.set_rw_data(output).jump(entry_pc);
        finish(&mut program);
        assert_eq!(program.current_offset(), entry_pc);
        for phase in 0..3 {
            program
                .load_imm_64(Reg::A0, base + 13)
                .load_imm_64(Reg::A1, base + 45)
                .load_imm_64(Reg::A2, bytes.len() as u64)
                .ecalli(crate::abi::hostcall::PREIMAGE_LOOKUP);
            if phase < 2 {
                program.ecalli(crate::abi::hostcall::SUSPEND);
                let branch_pc = program.current_offset();
                program.branch_eq_imm(Reg::A0, 0, finalizer_pc.wrapping_sub(branch_pc));
            }
        }
        // Reaching this trap means the third lookup incorrectly got fresh quota.
        program.trap();
        let program = program.build_standard();
        let mut call = invocation();
        call.gas = 100_000;
        call.availability.push(RuntimeBlob { reference, bytes });
        call.validate().unwrap();
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor: crate::agent_sdk::ActorId(call.actor.0),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            observed_slot: 1,
        };
        let mut state = ActorStateLanes::default();
        let mut saved = None;
        for phase in 0..3 {
            match run_inner_actor(&call, Some(context), &program, None, &state, saved.take())
                .unwrap()
            {
                ActorRunOutcome::Yielded {
                    reply,
                    state: next,
                    continuation,
                    ..
                } => {
                    assert!(phase < 2);
                    assert_eq!(reply.status, ActorExecutionStatus::Yielded);
                    assert_eq!(continuation.host_budget.fetch_calls, phase + 1);
                    assert_eq!(
                        continuation.host_budget.fetch_bytes as usize,
                        (phase as usize + 1) * (32 + 2 * call.availability[0].bytes.len())
                    );
                    assert!(continuation.validate());
                    state = next;
                    saved = Some(continuation);
                }
                ActorRunOutcome::Completed {
                    reply, state: next, ..
                } => {
                    assert_eq!(phase, 2);
                    assert_eq!(reply.status, ActorExecutionStatus::OutOfGas);
                    assert_eq!(next, state);
                }
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn inner_preimage_lookup_is_local_bounded_and_charged() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let bytes = vec![0x61; MAX_EXECUTION_FETCH_BYTES / 5];
        let reference = BlobRef::of_bytes(&bytes);
        let mut call = invocation();
        call.gas = 100_000;
        call.availability.push(RuntimeBlob {
            reference: reference.clone(),
            bytes: bytes.clone(),
        });
        call.validate().unwrap();
        let state = ActorStateLanes::default();
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        for (available, capacity, repeats, expected) in [
            (true, bytes.len(), 1, bytes.len() as u64),
            (false, bytes.len(), 1, crate::abi::error::HOST_NONE),
            (true, bytes.len() - 1, 1, crate::abi::error::HOST_FULL),
            (true, bytes.len(), 3, 0),
        ] {
            let mut input = call.clone();
            if !available {
                input.availability.clear();
            }
            let mut output = actor_output([0, 0, 0], 16);
            output.extend_from_slice(&reference.hash.0);
            output.resize(61 + bytes.len(), 0);
            let mut program = Assembler::new();
            program.set_rw_data(output);
            for _ in 0..repeats {
                program
                    .load_imm_64(Reg::A0, u64::from(base + 29))
                    .load_imm_64(Reg::A1, u64::from(base + 61))
                    .load_imm_64(Reg::A2, capacity as u64)
                    .ecalli(crate::abi::hostcall::PREIMAGE_LOOKUP)
                    .store_u64(Reg::A0, base + 13);
            }
            // Return the lookup result and first copied payload word.
            program.load_imm_64(Reg::A0, u64::from(base + 61));
            program
                .load_ind_u64(Reg::A1, Reg::A0, 0)
                .store_u64(Reg::A1, base + 21)
                .load_imm_64(Reg::A0, u64::from(base))
                .load_imm_64(Reg::A1, 29)
                .jump_ind(Reg::RA, 0);
            let ActorRunOutcome::Completed {
                reply, state: next, ..
            } = run_inner_actor(&input, None, &program.build_standard(), None, &state, None)
                .unwrap()
            else {
                panic!("lookup yielded")
            };
            if repeats == 3 {
                assert_eq!(reply.status, ActorExecutionStatus::OutOfGas);
                assert_eq!(next, state);
            } else {
                assert_eq!(reply.status, ActorExecutionStatus::Done);
                assert_eq!(
                    u64::from_le_bytes(reply.reply[..8].try_into().unwrap()),
                    expected
                );
                assert_eq!(
                    &reply.reply[8..],
                    &[if available && capacity == bytes.len() {
                        0x61
                    } else {
                        0
                    }; 8]
                );
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AGENT_INPUT_PROBE_ELF built from the agent-yield fixture"]
    fn compiled_clean_guest_accepts_maximum_encoded_input() {
        use crate::actors::codec::{Decode, Encode};
        use crate::actors::value::{Msg, TAG_DYNAMIC, Value};

        let path = std::env::var("AGENT_INPUT_PROBE_ELF")
            .expect("set AGENT_INPUT_PROBE_ELF to the freshly built agent-yield ELF");
        let elf = std::fs::read(path).expect("read fixture ELF");
        let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link fixture ELF");
        let message = |len| {
            let mut bytes = vec![TAG_DYNAMIC];
            bytes.extend(
                Msg::new("input_len")
                    .with("bytes", Value::Bytes(vec![0x5a; len]))
                    .encode(),
            );
            bytes
        };
        // Archive alignment means not every total byte length is expressible.
        // Use the largest real message below the limit, without synthetic padding.
        let payload_len = (0..=MAX_EXECUTION_MESSAGE_BYTES)
            .rev()
            .find(|len| message(*len).len() <= MAX_EXECUTION_MESSAGE_BYTES)
            .unwrap();
        let mut call = invocation();
        call.mode = MethodMode::LocalQuery;
        call.gas = 100_000_000;
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor: crate::agent_sdk::ActorId(call.actor.0),
            mode: crate::agent_sdk::MethodMode::LocalQuery,
            origin: crate::agent_sdk::InvocationOrigin {
                principal: Some(crate::agent_sdk::PrincipalId([0x31; 32])),
                ..crate::agent_sdk::InvocationOrigin::anonymous()
            },
            roles: crate::agent_sdk::InvocationRoleClaims {
                space: None,
                actor: Some(crate::agent_sdk::RoleId([0x51; 32])),
            },
            observed_slot: 1,
        };
        assert!(context.validate());
        let mut state = ActorStateLanes {
            local: Some(Vec::new()),
            ..Default::default()
        };
        for len in [0, payload_len] {
            call.message = message(len);
            call.validate().unwrap();
            let ActorRunOutcome::Completed {
                reply, state: next, ..
            } = run_inner_actor(&call, Some(context), &program, None, &state, None)
                .expect("execute compiled input probe")
            else {
                panic!("query yielded")
            };
            assert_eq!(reply.status, ActorExecutionStatus::Done);
            assert_eq!(Value::decode(&reply.reply), Value::U64(len as u64));
            if len != 0 {
                assert_eq!(next, state, "query changed canonical state");
            }
            state = next;
        }
        std::eprintln!(
            "compiled guest: message={} payload={payload_len}",
            call.message.len()
        );
        // Exercise the Rust context API with a caller blob larger than the
        // message ceiling, then repeat without availability and with bad length.
        let blob_bytes = vec![0x62; MAX_EXECUTION_AVAILABILITY_BYTES];
        let reference = crate::agent_sdk::BlobRef::of_bytes(&blob_bytes);
        for (present, len, expected) in [
            (true, reference.len, reference.len),
            (false, reference.len, u64::MAX),
            (true, reference.len - 1, u64::MAX - 1),
            (
                true,
                MAX_EXECUTION_AVAILABILITY_BYTES as u64 + 1,
                u64::MAX - 1,
            ),
        ] {
            call.availability.clear();
            if present {
                call.availability.push(RuntimeBlob {
                    reference: BlobRef::of_bytes(&blob_bytes),
                    bytes: blob_bytes.clone(),
                });
            }
            call.message = vec![TAG_DYNAMIC];
            call.message.extend(
                Msg::new("blob_len")
                    .with("hash", Value::Bytes(reference.hash.0.to_vec()))
                    .with("len", Value::U64(len))
                    .encode(),
            );
            call.validate().unwrap();
            let ActorRunOutcome::Completed {
                reply, state: next, ..
            } = run_inner_actor(&call, Some(context), &program, None, &state, None).unwrap()
            else {
                panic!("blob query yielded")
            };
            assert_eq!(reply.status, ActorExecutionStatus::Done);
            assert_eq!(Value::decode(&reply.reply), Value::U64(expected));
            assert_eq!(next, state, "blob query changed Local state");
        }
        call.message = message(payload_len + 1);
        assert!(call.message.len() > MAX_EXECUTION_MESSAGE_BYTES);
        assert_eq!(call.validate(), Err(ActorExecutionError::InvalidInput));
        call.message.resize(MAX_EXECUTION_MESSAGE_BYTES + 1, 0);
        assert_eq!(call.validate(), Err(ActorExecutionError::InvalidInput));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_inner_execution_enforces_actor_lane_limit_not_outer_state_limit() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let mut program = Assembler::new();
        program
            .set_rw_data(actor_output([0, 0, 0], 0))
            .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
            .load_imm_64(Reg::A1, 13)
            .jump_ind(Reg::RA, 0);
        let program = program.build_standard();
        let mut call = invocation();
        call.gas = 100_000;
        let context = crate::agent_sdk::InvocationContext {
            invocation: crate::agent_sdk::InvocationId(call.invocation.0),
            actor: crate::agent_sdk::ActorId(call.actor.0),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin {
                principal: None,
                transport_node: None,
                credential: None,
                actor: None,
                capability: None,
            },
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            observed_slot: 1,
        };
        assert!(context.validate());
        let mut state = ActorStateLanes {
            linear: Some(vec![0; MAX_EXECUTION_STATE_TOTAL_BYTES]),
            merge: None,
            local: None,
        };
        assert!(run_inner_actor(&call, Some(context), &program, None, &state, None).is_ok());
        // Exercise the actual ECALL dispatcher with the same probe/retry
        // pattern as the guest, including the full SDK-sized message.
        call.message = vec![1; MAX_EXECUTION_MESSAGE_BYTES];
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        let split_state = ActorStateLanes {
            linear: Some(vec![0; lane]),
            merge: Some(vec![0; lane]),
            local: Some(vec![0; lane]),
        };
        let control_len = encode_inner_actor_control(&call, Some(context))
            .unwrap()
            .len();
        let mut output = actor_output([0, 0, 0], 0);
        let output_len = output.len();
        output.resize(output_len + lane + 1, 0);
        let base = 2 * u64::from(vos_pvm::PVM_ZONE_SIZE);
        let mut fetching = Assembler::new();
        fetching.set_rw_data(output);
        for bytes in [
            lane + 1,
            lane + 1,
            lane + 1,
            control_len,
            call.message.len(),
        ] {
            fetching
                .load_imm_64(Reg::A0, base + output_len as u64)
                .load_imm_64(Reg::A1, ACTOR_FETCH_PROBE_BYTES as u64)
                .ecalli(crate::abi::hostcall::FETCH);
            if bytes > ACTOR_FETCH_PROBE_BYTES {
                fetching
                    .load_imm_64(Reg::A0, base + output_len as u64)
                    .load_imm_64(Reg::A1, bytes as u64)
                    .ecalli(crate::abi::hostcall::FETCH);
            }
        }
        fetching
            .load_imm_64(Reg::A0, base)
            .load_imm_64(Reg::A1, output_len as u64)
            .jump_ind(Reg::RA, 0);
        assert!(matches!(
            run_inner_actor(&call, Some(context), &fetching.build_standard(), None, &split_state, None),
            Ok(ActorRunOutcome::Completed { reply, .. }) if reply.status == ActorExecutionStatus::Done,
        ));
        for bytes in [MAX_EXECUTION_STATE_TOTAL_BYTES + 1, 99_200] {
            assert!(bytes < crate::agent_sdk::MAX_RUNTIME_STATE_BYTES);
            state.linear = Some(vec![0; bytes]);
            assert!(matches!(
                run_inner_actor(&call, Some(context), &program, None, &state, None),
                Err(ActorExecutionError::InvalidInput),
            ));
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn yielded_status_requires_an_actual_suspend_capture() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let mut output = actor_output([0, 0, 0], 0);
        output[0] = crate::actors::STATUS_YIELDED;
        let mut program = Assembler::new();
        program
            .set_rw_data(output)
            .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
            .load_imm_64(Reg::A1, 13)
            .jump_ind(Reg::RA, 0);
        let mut call = invocation();
        call.gas = 100_000;
        assert!(matches!(
            run_inner_actor(
                &call,
                None,
                &program.build_standard(),
                None,
                &ActorStateLanes {
                    linear: None,
                    merge: None,
                    local: None
                },
                None
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_output_accepts_exact_aggregate_state_and_reply_limits() {
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        let remainder = MAX_EXECUTION_STATE_TOTAL_BYTES - lane * 2;
        let output = actor_output([lane, lane, remainder], MAX_EXECUTION_REPLY_BYTES);
        assert!(decode_actor_output(&invocation(), 1, output).is_ok());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_output_rejects_aggregate_state_overflow() {
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        let remainder = MAX_EXECUTION_STATE_TOTAL_BYTES - lane * 2 + 1;
        let output = actor_output([lane, lane, remainder], 0);
        assert_eq!(
            decode_actor_output(&invocation(), 1, output),
            Err(ActorExecutionError::InvalidActorOutput)
        );
    }
}
