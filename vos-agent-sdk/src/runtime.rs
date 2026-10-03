use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::authority::{AuthorityOperationKind, AuthorityReceipt};
use crate::contract::{RuntimePackageContract, RuntimeResourcePolicy};
use crate::private::{PrivateActorLifecycleKind, PrivateControlRecord};
use crate::{
    ActorDirectoryPage, ActorEntry, ActorId, ActorLifecycleDebt, AgentDescriptor, AgentIdentity,
    AgentReplica, BlobRef, CallId, CapabilityId, CredentialId, DeploymentId, Hash, InstallActor,
    InvocationId, InvocationResultStorage, MethodMode, NodeId, PrincipalId, ProducerId, ProgramId,
    RuntimeCapabilities, SpaceId, StateLane, UpgradeActor,
};

pub const MAX_INVOCATION_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_INVOCATION_REPLY_BYTES: usize = 16 * 1024;
pub const MAX_RESUME_INPUT_BYTES: usize = 8 * 1024;
pub const MAX_RUNTIME_AVAILABILITY_ITEMS: usize = 16;
/// Caller-selected actor inputs retained across one invocation. This matches
/// the standard execution ABI's aggregate availability window. The window
/// accommodates the complete bounded clean-Create genesis provision, including
/// the maximum replica roster; inline actor state has a separate smaller cap.
pub const MAX_RUNTIME_CALLER_AVAILABILITY_BYTES: usize = 192 * 1024;
/// Largest actor PVM a package may carry without declaring its resources
/// ([`crate::package::ActorResources`]), and the ceiling an Agent's owner
/// admits new installations under unless it chooses a higher one.
pub const STANDARD_ACTOR_PROGRAM_BYTES: usize = 1_280 * 1024;
/// Largest standard actor PVM staged into one runtime work item: the hard
/// maximum a declared actor may reach. Execution materializes the program
/// several times beside the state images, so the ceiling is what the bundled
/// runtime's 32-MiB arena holds at the state ceiling, with margin. Before the
/// runtime loaded programs in place, a 1 920-KiB program still ran at 4 MiB
/// of state and 31 unacknowledged results and a 2 048-KiB one exhausted the
/// arena; loading in place removes about 3.5 program copies from the peak, and
/// 2 560 KiB runs at the state ceiling. Hashing it once (one decode copy, no
/// ProgramId or public-I/O pass over it) leaves room for 4 608 KiB, which an
/// actor built for speed rather than size (`opt-level = 3`) needs; measured
/// with small state, not yet at the 4 MiB state ceiling. Under the VOS-native
/// profile the program is one looked-up copy. Its load stays inside the
/// default management gas budget.
pub const MAX_RUNTIME_PROGRAM_BYTES: usize = 4_608 * 1024;
/// Largest signed actor schema staged alongside the actor PVM.
pub const MAX_RUNTIME_SCHEMA_BYTES: usize = 16 * 1024;
/// Largest signed method-policy preimage staged alongside the actor PVM.
pub const MAX_RUNTIME_EXECUTION_ARTIFACT_BYTES: usize = 64 * 1024;
/// Complete outer-input availability ceiling: one actor PVM, schema and
/// policy artifacts, immutable installation data, plus the bounded
/// caller-selected availability map.
pub const MAX_RUNTIME_AVAILABILITY_BYTES: usize = MAX_RUNTIME_PROGRAM_BYTES
    + MAX_RUNTIME_SCHEMA_BYTES
    + MAX_RUNTIME_EXECUTION_ARTIFACT_BYTES
    + crate::MAX_INSTALLATION_DATA_BYTES
    + MAX_RUNTIME_CALLER_AVAILABILITY_BYTES;
pub const MAX_AFTER_COMMIT_MERGE_MESSAGES: usize = 256;

/// Runtime-owned durable state split only at replication boundaries. Hosts
/// persist/order components but never interpret their bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub control: Vec<u8>,
    pub linear: Vec<u8>,
    pub merge: Vec<u8>,
    pub local: Vec<u8>,
}

impl RuntimeState {
    pub fn is_empty(&self) -> bool {
        self.control.is_empty()
            && self.linear.is_empty()
            && self.merge.is_empty()
            && self.local.is_empty()
    }

    pub fn component(&self, lane: StateLane) -> &[u8] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    pub fn encoded_len(&self) -> Option<usize> {
        self.control
            .len()
            .checked_add(self.linear.len())?
            .checked_add(self.merge.len())?
            .checked_add(self.local.len())
    }

    pub fn validate(&self) -> bool {
        self.encoded_len()
            .is_some_and(|length| length <= crate::MAX_RUNTIME_STATE_BYTES)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

impl RuntimeBlob {
    pub fn validate(&self) -> bool {
        self.bytes.len() <= MAX_RUNTIME_AVAILABILITY_BYTES && self.reference.matches(&self.bytes)
    }
}

fn installation_reference_valid(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO && reference.len <= crate::MAX_INSTALLATION_DATA_BYTES as u64
}

fn availability_valid(values: &[RuntimeBlob], installation_data: Option<&BlobRef>) -> bool {
    values.len() <= MAX_RUNTIME_AVAILABILITY_ITEMS
        && values.iter().all(RuntimeBlob::validate)
        && installation_data.is_none_or(installation_reference_valid)
        && installation_data
            .is_none_or(|required| values.iter().any(|blob| blob.reference == *required))
        && values
            .iter()
            .all(|blob| blob.reference.len != 0 || installation_data == Some(&blob.reference))
        && values
            .windows(2)
            .all(|pair| pair[0].reference < pair[1].reference)
        && values
            .iter()
            .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()))
            .is_some_and(|total| total <= MAX_RUNTIME_AVAILABILITY_BYTES)
}

fn required_refs_valid(values: &[BlobRef], installation_data: Option<&BlobRef>) -> bool {
    values.len() <= MAX_RUNTIME_AVAILABILITY_ITEMS
        && installation_data.is_none_or(installation_reference_valid)
        && installation_data.is_none_or(|required| values.iter().any(|value| value == required))
        && values.iter().all(|reference| {
            reference.hash != Hash::ZERO
                && (reference.len != 0 || installation_data == Some(reference))
                && reference.len <= MAX_RUNTIME_AVAILABILITY_BYTES as u64
        })
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .try_fold(0u64, |total, reference| total.checked_add(reference.len))
            .is_some_and(|total| total <= MAX_RUNTIME_AVAILABILITY_BYTES as u64)
}

/// Explicit caller identity fields. Their authentication comes from the
/// selected authorization path: a normal authority receipt covers them via
/// the work commitment, while a self-authenticating Public actor verifies the
/// corresponding signed message itself. Principals, transport nodes, and
/// credentials are non-interchangeable; actor provenance is independent of
/// all three.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvocationOrigin {
    pub principal: Option<PrincipalId>,
    pub transport_node: Option<NodeId>,
    pub credential: Option<CredentialId>,
    pub actor: Option<ActorId>,
    pub capability: Option<CapabilityId>,
}

impl InvocationOrigin {
    pub const fn anonymous() -> Self {
        Self {
            principal: None,
            transport_node: None,
            credential: None,
            actor: None,
            capability: None,
        }
    }

    pub fn validate(&self) -> bool {
        if self.principal == Some(PrincipalId::ZERO)
            || self.transport_node == Some(NodeId::ZERO)
            || self.credential == Some(CredentialId::ZERO)
            || self.actor == Some(ActorId::ZERO)
            || self.capability == Some(CapabilityId::ZERO)
        {
            return false;
        }
        // A credential authenticates a principal; it is never itself an
        // actor origin or a replica identity.
        self.credential.is_none() || self.principal.is_some()
    }
}

/// Exact portable role claims authenticated by the authority receipt which
/// selects an [`InvocationWork`]. A call carries at most one role claim; the
/// target actor scopes an actor-local role without another caller-selected
/// identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvocationRoleClaims {
    pub space: Option<crate::RoleId>,
    pub actor: Option<crate::RoleId>,
}

impl InvocationRoleClaims {
    pub const fn none() -> Self {
        Self {
            space: None,
            actor: None,
        }
    }

    pub fn validate_for(self, origin: InvocationOrigin) -> bool {
        self.space.is_none_or(|role| role != crate::RoleId::ZERO)
            && self.actor.is_none_or(|role| role != crate::RoleId::ZERO)
            && !(self.space.is_some() && self.actor.is_some())
            // Roles belong to Principals. Neither a transport Node nor a
            // Credential may stand in for the application identity.
            && (self.space.is_none() && self.actor.is_none() || origin.principal.is_some())
            // AMP2 selects one exact authorization predicate. Carrying a
            // role and a capability together would leave an ambiguous claim
            // for actor code to reinterpret.
            && (self.space.is_none() && self.actor.is_none() || origin.capability.is_none())
    }
}

/// Exact invocation context delivered unchanged across the standard runtime's
/// private inner-actor ABI.
///
/// On the normal path these fields become trusted only after the runtime
/// verifies the enclosing authority receipt against the exact
/// [`InvocationWork`] commitment. A [`PublicPreflight`] authenticates no
/// identity; a self-authenticating Public actor must verify any identity it
/// consumes from this context against its signed message. The logical slot is
/// the monotonic observation at which unseen work was accepted, not an actor
/// message field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationContext {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub mode: MethodMode,
    pub origin: InvocationOrigin,
    pub roles: InvocationRoleClaims,
    pub observed_slot: u64,
}

impl InvocationContext {
    pub fn from_work(work: &InvocationWork, observed_slot: u64) -> Self {
        Self {
            invocation: work.invocation,
            actor: work.actor,
            mode: work.mode,
            origin: work.origin,
            roles: work.roles,
            observed_slot,
        }
    }

    pub fn validate(self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.origin.validate()
            && self.roles.validate_for(self.origin)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationWork {
    pub space: SpaceId,
    pub agent: crate::AgentId,
    pub runtime_deployment: DeploymentId,
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub origin: InvocationOrigin,
    pub roles: InvocationRoleClaims,
    pub message: Vec<u8>,
    /// Exact installed constructor-argument object, when this actor has one.
    /// This role marker is required because a present-empty object has a
    /// legitimate zero-length BlobRef while all other availability does not.
    pub installation_data: Option<BlobRef>,
    pub availability: Vec<RuntimeBlob>,
    pub gas: u64,
    /// Exact-result recovery may read an existing disposition but cannot run
    /// unseen application work.
    pub recovery_only: bool,
}

impl InvocationWork {
    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != crate::AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.origin.validate()
            && self.roles.validate_for(self.origin)
            && self.message.len() <= MAX_INVOCATION_MESSAGE_BYTES
            && availability_valid(&self.availability, self.installation_data.as_ref())
            && self.gas != 0
    }

    /// Commitment matched by an Invoke authority selector. Binds all metadata
    /// and the exact ordered availability references, not their preimages.
    /// Admission must separately call `validate()` to authenticate blob bytes.
    pub fn commitment(&self) -> Hash {
        crate::wire::invocation_work_commitment(self)
    }
}

/// Reference-only description of an already accepted invocation for retirement.
/// This is not executable work and does not authenticate artifact preimages.
/// A runtime must verify the authorization and match its exact retained result
/// before using this description to retire anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationRetirement {
    pub space: SpaceId,
    pub agent: crate::AgentId,
    pub runtime_deployment: DeploymentId,
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub origin: InvocationOrigin,
    pub roles: InvocationRoleClaims,
    pub gas: u64,
    pub recovery_only: bool,
    pub message: Vec<u8>,
    pub installation_data: Option<BlobRef>,
    pub required: Vec<BlobRef>,
}

impl InvocationRetirement {
    /// Project metadata only. This does not assert that the original work was
    /// valid or accepted; those are checked at invocation and retained-state
    /// boundaries, not inferred from this projection.
    pub fn from_work(work: &InvocationWork) -> Self {
        Self {
            space: work.space,
            agent: work.agent,
            runtime_deployment: work.runtime_deployment,
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            origin: work.origin,
            roles: work.roles,
            gas: work.gas,
            recovery_only: work.recovery_only,
            message: work.message.clone(),
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
        }
    }

    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != crate::AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.origin.validate()
            && self.roles.validate_for(self.origin)
            && self.message.len() <= MAX_INVOCATION_MESSAGE_BYTES
            && required_refs_valid(&self.required, self.installation_data.as_ref())
            && self.gas != 0
    }

    /// Identical to the originating InvocationWork commitment. References
    /// bind artifact content without carrying it in a retirement request.
    pub fn commitment(&self) -> Hash {
        crate::wire::invocation_retirement_commitment(self)
    }

    /// Persisted acceptance cannot originate from recovery-only delivery.
    pub fn validate_accepted(&self) -> bool {
        !self.recovery_only && self.validate()
    }

    /// Reattach supplied bytes for execution/resume. This is construction, not
    /// validation: the caller must require the exact reference set and validate
    /// every preimage before execution. Retirement never needs this conversion.
    pub fn with_availability(&self, availability: Vec<RuntimeBlob>) -> InvocationWork {
        InvocationWork {
            space: self.space,
            agent: self.agent,
            runtime_deployment: self.runtime_deployment,
            invocation: self.invocation,
            actor: self.actor,
            incarnation: self.incarnation,
            deployment: self.deployment,
            program: self.program,
            mode: self.mode,
            origin: self.origin,
            roles: self.roles,
            message: self.message.clone(),
            installation_data: self.installation_data.clone(),
            availability,
            gas: self.gas,
            recovery_only: self.recovery_only,
        }
    }
}

/// Unsigned structural admission for one invocation of an installed AMP2
/// `Public` method. This value authenticates no caller identity: the runtime
/// must resolve the exact installed policy and accept this variant only when
/// that method selects [`crate::method_policy::AuthorizationPolicySelector::Public`].
/// Repeating the work commitment, origin, and observation slot makes any
/// substitution across retry, continuation, or acknowledgement boundaries
/// structurally divergent; it does not turn an untrusted host into an identity
/// authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicPreflight {
    pub work: Hash,
    pub origin: InvocationOrigin,
    pub observed_slot: u64,
}

impl PublicPreflight {
    pub fn for_work(work: &InvocationWork, observed_slot: u64) -> Self {
        Self {
            work: work.commitment(),
            origin: work.origin,
            observed_slot,
        }
    }

    /// Match the immutable application work independently of the host's
    /// current logical observation. An exact retry may be observed after the
    /// original acceptance slot, but the preflight itself never changes.
    pub fn matches_work(&self, work: &InvocationWork) -> bool {
        self.work != Hash::ZERO
            && self.origin.validate()
            && self.work == work.commitment()
            && self.origin == work.origin
            && work.roles == InvocationRoleClaims::none()
            && work.origin.capability.is_none()
    }

    /// Match an unseen acceptance at one exact trusted logical slot.
    pub fn matches(&self, work: &InvocationWork, observed_slot: u64) -> bool {
        self.matches_work(work) && self.observed_slot == observed_slot
    }
}

/// Exact authorization accepted with one portable actor invocation. A normal
/// authority receipt remains guest-signature-verified. [`PublicPreflight`] is
/// deliberately unsigned and is useful only after the runtime resolves the
/// installed AMP2 method selector as Public.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "retain inline receipt verification without adding an allocation to every authorization"
)]
pub enum InvocationAuthorization {
    AuthorityReceipt(AuthorityReceipt),
    PublicPreflight(PublicPreflight),
}

impl InvocationAuthorization {
    pub fn validate_shape(&self) -> bool {
        match self {
            Self::AuthorityReceipt(receipt) => receipt.validate_shape().is_ok(),
            Self::PublicPreflight(preflight) => {
                preflight.work != Hash::ZERO
                    && preflight.origin.validate()
                    && preflight.origin.capability.is_none()
            }
        }
    }

    pub fn matches_invoke(&self, work: &InvocationWork, observed_slot: u64) -> bool {
        if !self.matches_work(work) {
            return false;
        }
        match self {
            Self::AuthorityReceipt(_) => true,
            // `observed_slot` is the host's current trusted observation. It
            // equals the immutable preflight slot for unseen work, while an
            // exact durable retry may occur later. The runtime distinguishes
            // those cases from its retained result/continuation before it can
            // execute application code.
            Self::PublicPreflight(preflight) => {
                // matches_work above already checked this exact immutable
                // preflight/work pair, including the work commitment. Only
                // the observation bound remains; do not hash the work twice.
                observed_slot >= preflight.observed_slot
            }
        }
    }

    /// Match all immutable invocation fields without making a claim about the
    /// host's current logical observation. Transport and durable replay use
    /// this before the live runtime resolves the installed method policy.
    pub fn matches_work(&self, work: &InvocationWork) -> bool {
        match self {
            Self::AuthorityReceipt(receipt) => {
                receipt.validate_shape().is_ok()
                    && receipt.selector.operation == AuthorityOperationKind::InvokeActor
                    && receipt.selector.space == work.space
                    && receipt.selector.agent == work.agent
                    && receipt.selector.runtime_deployment == work.runtime_deployment
                    && receipt.selector.actor == Some(work.actor)
                    && receipt.selector.actor_deployment == Some(work.deployment)
                    && receipt.selector.request == work.commitment()
            }
            Self::PublicPreflight(preflight) => preflight.matches_work(work),
        }
    }

    pub fn matches_acknowledgement(&self, work: &InvocationWork) -> bool {
        self.matches_work(work)
    }

    /// Structural authorization binding for reference-only retirement. This
    /// neither verifies a receipt signature nor proves prior acceptance. The
    /// runtime must check both against its authenticated retained state.
    pub fn matches_retirement(&self, work: &InvocationRetirement) -> bool {
        match self {
            Self::AuthorityReceipt(receipt) => {
                receipt.validate_shape().is_ok()
                    && receipt.selector.operation == AuthorityOperationKind::InvokeActor
                    && receipt.selector.space == work.space
                    && receipt.selector.agent == work.agent
                    && receipt.selector.runtime_deployment == work.runtime_deployment
                    && receipt.selector.actor == Some(work.actor)
                    && receipt.selector.actor_deployment == Some(work.deployment)
                    && receipt.selector.request == work.commitment()
            }
            Self::PublicPreflight(preflight) => {
                preflight.work != Hash::ZERO
                    && preflight.origin.validate()
                    && preflight.work == work.commitment()
                    && preflight.origin == work.origin
                    && work.roles == InvocationRoleClaims::none()
                    && work.origin.capability.is_none()
            }
        }
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::invocation_authorization_commitment(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementRequest {
    Create(Box<AgentDescriptor>),
    InspectActors {
        after: Option<ActorId>,
        limit: u16,
    },
    InspectResources,
    /// Read-only recovery projection of all retained consumed management
    /// decisions. The reply must be derived from the supplied runtime state;
    /// no authority receipt is accepted and the state must remain unchanged.
    InspectManagementHistory,
    Install(Box<InstallActor>),
    UpgradeActor(Box<UpgradeActor>),
    Suspend {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    Resume {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    UpgradeRuntime(Box<RuntimeUpgrade>),
    ChangeReplicas {
        expected_generation: Hash,
        replicas: Vec<AgentReplica>,
    },
    /// Select the Agent's per-invocation execution bounds
    /// ([`crate::contract::ExecutionLimits`]). Refused while any actor's
    /// current state lanes exceed the requested lane bound.
    SetExecutionLimits(crate::contract::ExecutionLimits),
    /// Apply one exact owner-signed Private control through the admitted
    /// runtime. The nested mutation is deliberately nonrecursive: a PCTL can
    /// never smuggle another management envelope or authority selector.
    PrivateControl {
        control: Box<PrivateControlRecord>,
        mutation: Box<PrivateRuntimeMutation>,
    },
}

impl ManagementRequest {
    /// Whether this request is one canonical SDK management value.
    pub fn is_valid(&self) -> bool {
        crate::wire::management_request_valid(self)
    }

    /// Commitment matched by a management authority selector.
    pub fn commitment(&self) -> Hash {
        crate::wire::management_request_commitment(self)
    }

    /// Bounded authority policy projection for a mutating request. Read-only
    /// inspection has no authorization plan and cannot enter ACC3.
    pub fn authorization_plan(&self) -> Option<crate::authority::ManagementAuthorizationPlan> {
        crate::authority::ManagementAuthorizationPlan::from_request(self)
    }

    /// Commitment of the complete canonical request used for durable replay
    /// equality. For Private controls this is distinct from [`Self::commitment`],
    /// because the authority selector intentionally commits the PCTL while
    /// replay must additionally bind its exact runtime mutation preimage.
    pub fn replay_commitment(&self) -> Hash {
        crate::wire::management_request_replay_commitment(self)
    }

    /// Whether an admitted Private runtime reply is the exact result shape
    /// selected by this request. Non-Private requests always return false.
    pub fn private_runtime_reply_matches(&self, reply: &ManagementReply) -> bool {
        crate::wire::private_runtime_reply_matches(self, reply)
    }

    /// Signed authority operation required for a mutating management request.
    /// Read-only inspection deliberately has no authority operation.
    pub fn authority_operation(&self) -> Option<crate::authority::AuthorityOperationKind> {
        crate::wire::required_management_operation(self)
    }

    /// Exact actor/deployment selector required by this request, when any.
    pub fn authority_actor(&self) -> Option<(ActorId, DeploymentId)> {
        crate::wire::management_actor(self)
    }

    /// Exact actor fields carried by the authority selector. Private actor
    /// controls expose the ActorId but keep their deployment inside the
    /// signed PCTL mutation commitment.
    pub fn authority_actor_selector(&self) -> (Option<ActorId>, Option<DeploymentId>) {
        crate::wire::management_actor_selector(self)
    }
}

/// Exact runtime mutation selected by a Private control. This type cannot
/// contain a [`ManagementRequest`], preventing recursive envelopes and
/// keeping the PCTL-to-runtime binding finite and canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "keep finite Private mutation records inline without changing their public allocation contract"
)]
pub enum PrivateRuntimeMutation {
    SetResourcePolicy(RuntimeResourcePolicy),
    Install(InstallActor),
    UpgradeActor(UpgradeActor),
    Suspend {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    Resume {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
}

impl PrivateRuntimeMutation {
    pub fn is_valid(&self) -> bool {
        crate::wire::private_runtime_mutation_valid(self)
    }

    /// Commitment placed in a Private ActorLifecycle PCTL's `request` field.
    pub fn commitment(&self) -> Hash {
        crate::wire::private_runtime_mutation_commitment(self)
    }

    pub const fn lifecycle_kind(&self) -> Option<PrivateActorLifecycleKind> {
        match self {
            Self::SetResourcePolicy(_) => None,
            Self::Install(_) => Some(PrivateActorLifecycleKind::Install),
            Self::UpgradeActor(_) => Some(PrivateActorLifecycleKind::Upgrade),
            Self::Suspend { .. } => Some(PrivateActorLifecycleKind::Suspend),
            Self::Resume { .. } => Some(PrivateActorLifecycleKind::Resume),
            Self::RemoveLeaf { .. } => Some(PrivateActorLifecycleKind::Remove),
        }
    }

    pub const fn actor(&self) -> Option<ActorId> {
        match self {
            Self::SetResourcePolicy(_) => None,
            Self::Install(value) => Some(value.entry.actor),
            Self::UpgradeActor(value) => Some(value.actor),
            Self::Suspend { actor, .. }
            | Self::Resume { actor, .. }
            | Self::RemoveLeaf { actor, .. } => Some(*actor),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeUpgrade {
    pub from_deployment: DeploymentId,
    pub to_deployment: DeploymentId,
    pub to_program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeResourceUsage {
    pub actors: u32,
    pub active_machines: u8,
    pub continuations: u32,
    pub inbox: u32,
    pub outbox: u32,
    pub schedules: u32,
    pub proof_artifacts: u32,
    pub state_bytes: u32,
    pub artifact_references: u32,
    pub artifact_referenced_bytes: u64,
    pub proof_material_bytes: u64,
}

/// Authenticated execution mode carried by every runtime work item.
/// Current executors admit only [`Self::Direct`]; Attested is reserved for a
/// proof-host adapter which must explicitly select and validate its system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeExecutionContext {
    Direct,
    Attested { proof_system: Hash },
}

impl RuntimeExecutionContext {
    pub fn is_valid(self) -> bool {
        match self {
            Self::Direct => true,
            Self::Attested { proof_system } => proof_system.0 != Hash::ZERO.0,
        }
    }

    pub const fn is_direct(self) -> bool {
        matches!(self, Self::Direct)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementReply {
    Created(AgentIdentity),
    Actors(ActorDirectoryPage),
    Resources(RuntimeResourceUsage),
    ManagementHistory(Hash),
    Installed(ActorEntry),
    Upgraded(ActorEntry),
    Suspended(ActorEntry),
    Resumed(ActorEntry),
    Removed(ActorId),
    RuntimeUpgraded(AgentIdentity),
    ReplicasChanged {
        generation: Hash,
    },
    /// Exact mutable RRP1 policy retained after a Private resource-policy
    /// control succeeds.
    ResourcePolicySet(RuntimeResourcePolicy),
    /// The Agent's execution bounds after `SetExecutionLimits`.
    ExecutionLimitsSet(crate::contract::ExecutionLimits),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementError {
    NotCreated,
    AlreadyCreated,
    NotFound,
    AlreadyExists,
    StaleDeployment,
    UnsupportedRuntime,
    UnsupportedLane,
    Busy(ActorLifecycleDebt),
    DirectoryFull,
    InvalidRequest,
    AuthoritySequenceRegressed,
    AuthoritySequenceConflict,
    AuthoritySlotRegressed,
    ResourceLimit,
    /// A valid Install receipt expired before first application. The runtime
    /// records a non-execution fence; it must not invoke or install the actor.
    ExpiredBeforeApplication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeWork {
    Manage {
        context: RuntimeExecutionContext,
        space: SpaceId,
        agent: crate::AgentId,
        runtime_deployment: DeploymentId,
        state: RuntimeState,
        request: Box<ManagementRequest>,
        authority: Option<Box<AuthorityReceipt>>,
        observed_slot: u64,
    },
    /// Invoke or recover one exact application operation. `observed_slot` is
    /// the host's current trusted observation. For unseen PublicPreflight
    /// work it must equal the preflight's immutable acceptance slot; a retry
    /// may carry a later current observation only when guest state already
    /// retains the exact original authorization and result/continuation.
    Invoke {
        context: RuntimeExecutionContext,
        state: RuntimeState,
        invocation: Box<InvocationWork>,
        authorization: Box<InvocationAuthorization>,
        observed_slot: u64,
    },
    Resume {
        context: RuntimeExecutionContext,
        state: RuntimeState,
        resume: Box<ResumeWork>,
    },
    /// Retire one delivered exact invocation result. Metadata and ordered
    /// artifact references bind the original work without resending preimages.
    /// The guest must authenticate the exact retained work and authorization.
    Acknowledge {
        context: RuntimeExecutionContext,
        state: RuntimeState,
        invocation: Box<InvocationRetirement>,
        authorization: Box<InvocationAuthorization>,
    },
    /// Experimental read-only lookup of a retained exact clean result.
    /// Unlike Invoke, absence can never execute unseen actor work. The guest
    /// returns `NotReady` for absence, `Completed` for a retained result,
    /// and `Acknowledged` for a retained retirement marker.
    #[cfg(feature = "experimental-state-blocks")]
    InspectInvocation {
        context: RuntimeExecutionContext,
        state: RuntimeState,
        invocation: Box<InvocationRetirement>,
        authorization: Box<InvocationAuthorization>,
        observed_slot: u64,
    },
}

impl RuntimeWork {
    pub const fn execution_context(&self) -> RuntimeExecutionContext {
        match self {
            Self::Manage { context, .. }
            | Self::Invoke { context, .. }
            | Self::Resume { context, .. }
            | Self::Acknowledge { context, .. } => *context,
            #[cfg(feature = "experimental-state-blocks")]
            Self::InspectInvocation { context, .. } => *context,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YieldReason {
    Cooperative,
    Await { call: CallId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeInput {
    Ready(Vec<u8>),
    Failed(u32),
}

impl ResumeInput {
    pub fn validate(&self) -> bool {
        match self {
            Self::Ready(bytes) => bytes.len() <= MAX_RESUME_INPUT_BYTES,
            Self::Failed(code) => *code != 0,
        }
    }
}

/// Exact tuple required to resume the FIFO head. The referenced opaque
/// continuation snapshot additionally binds the invocation commitment and
/// actor state generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeWork {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub continuation: BlobRef,
    pub ready_sequence: u64,
    /// Role marker for the exact installation-data ref retained in the
    /// accepted invocation. It is part of the resume tuple.
    pub installation_data: Option<BlobRef>,
    /// Exact preimages named by the yielded continuation. This map must cover
    /// the yielded `required` set with no missing, extra, or aliased entry.
    pub availability: Vec<RuntimeBlob>,
    pub input: Option<ResumeInput>,
}

impl ResumeWork {
    pub fn validate(&self) -> bool {
        valid_continuation_identity(
            self.invocation,
            self.actor,
            self.incarnation,
            self.deployment,
            self.program,
            &self.continuation,
        ) && self.ready_sequence != 0
            && availability_valid(&self.availability, self.installation_data.as_ref())
            && self.input.as_ref().is_none_or(ResumeInput::validate)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InvocationObservation {
    pub linear_revision: Option<u64>,
    pub merge_frontier: Option<Hash>,
    pub local_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InvocationStatus {
    Done = 0,
    Forbidden = 1,
    Panicked = 2,
    OutOfGas = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationReply {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub mode: MethodMode,
    pub lane: Option<StateLane>,
    pub status: InvocationStatus,
    pub reply: Vec<u8>,
    pub gas_remaining: u64,
    pub observation: InvocationObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationError {
    NotCreated,
    NotFound,
    StaleIncarnation,
    Suspended,
    StaleDeployment,
    WrongProgram,
    UnsupportedMethod,
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
    UnsupportedHostCall(u64),
    StaleContinuation,
    NotReady,
    /// Authenticated non-execution fence retained after receipt expiry.
    /// Unlike `AuthorityExpired`, this is an exact, acknowledgeable outcome.
    ExpiredBeforeExecution,
}

impl InvocationError {
    /// Whether a structurally admitted invocation retains this deterministic
    /// rejection by advancing its owning exact-result clock.
    ///
    /// Malformed work is rejected before this classification is consulted.
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
                | Self::ExpiredBeforeExecution
        )
    }
}

/// Exact durable result retired by one clean acknowledgement transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationAcknowledgement {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub mode: MethodMode,
    /// Commitment of the original canonical [`InvocationWork`].
    pub work: Hash,
    /// Commitment of the exact typed authorization accepted with it.
    pub authorization: Hash,
}

impl InvocationAcknowledgement {
    pub fn validate(&self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.work != Hash::ZERO
            && self.authorization != Hash::ZERO
    }
}

/// Prefix of every sequenced invocation identity.
pub const SEQUENCED_INVOCATION_PREFIX: [u8; 16] = *b"vos/sequenced/v1";

/// An invocation identity that states its own position in one Agent's
/// per-result-storage sequence.
///
/// Arbitrary identities remain valid and keep their unconditional retained
/// retirement fact. A sequenced identity additionally lets the standard
/// runtime replace the oldest contiguous acknowledgements of one result
/// storage by a watermark once that storage's acknowledgement component is
/// full: an identity at or below the watermark is refused as divergent and
/// never becomes unseen work again. The identity is a pure function of
/// `(storage, sequence)`, so no second identity can name a retired position.
///
/// Layout: 16-byte [`SEQUENCED_INVOCATION_PREFIX`], one storage tag byte
/// (Control 0, Linear 1, Merge 2, Local 3), seven zero bytes, then the
/// nonzero big-endian sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequencedInvocation {
    pub storage: InvocationResultStorage,
    pub sequence: core::num::NonZeroU64,
}

/// Classification of an invocation identity against the sequenced layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequencedInvocationId {
    /// Not a sequenced identity: exact retirement facts are never compacted.
    Unsequenced,
    Sequenced(SequencedInvocation),
    /// Carries the sequenced prefix without the canonical layout.
    Malformed,
}

impl SequencedInvocation {
    pub const fn new(storage: InvocationResultStorage, sequence: core::num::NonZeroU64) -> Self {
        Self { storage, sequence }
    }

    pub fn invocation_id(self) -> InvocationId {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&SEQUENCED_INVOCATION_PREFIX);
        bytes[16] = sequenced_storage_tag(self.storage);
        bytes[24..].copy_from_slice(&self.sequence.get().to_be_bytes());
        InvocationId(bytes)
    }

    pub fn classify(invocation: InvocationId) -> SequencedInvocationId {
        let bytes = invocation.0;
        if bytes[..16] != SEQUENCED_INVOCATION_PREFIX {
            return SequencedInvocationId::Unsequenced;
        }
        let storage = match bytes[16] {
            0 => InvocationResultStorage::Control,
            1 => InvocationResultStorage::Lane(StateLane::Linear),
            2 => InvocationResultStorage::Lane(StateLane::Merge),
            3 => InvocationResultStorage::Lane(StateLane::Local),
            _ => return SequencedInvocationId::Malformed,
        };
        if bytes[17..24] != [0; 7] {
            return SequencedInvocationId::Malformed;
        }
        let sequence = u64::from_be_bytes(bytes[24..].try_into().expect("eight bytes"));
        match core::num::NonZeroU64::new(sequence) {
            Some(sequence) => SequencedInvocationId::Sequenced(Self { storage, sequence }),
            None => SequencedInvocationId::Malformed,
        }
    }
}

const fn sequenced_storage_tag(storage: InvocationResultStorage) -> u8 {
    match storage {
        InvocationResultStorage::Control => 0,
        InvocationResultStorage::Lane(StateLane::Linear) => 1,
        InvocationResultStorage::Lane(StateLane::Merge) => 2,
        InvocationResultStorage::Lane(StateLane::Local) => 3,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YieldedInvocation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub continuation: BlobRef,
    pub ready_sequence: u64,
    /// Role marker permitting this exact required ref, and only this ref, to
    /// have length zero for a present-empty constructor argument object.
    pub installation_data: Option<BlobRef>,
    /// Strictly sorted immutable preimages which the host must re-supply on
    /// resume. The continuation retains references, never catalog bytes.
    pub required: Vec<BlobRef>,
    pub reason: YieldReason,
}

impl YieldedInvocation {
    pub fn validate(&self) -> bool {
        valid_continuation_identity(
            self.invocation,
            self.actor,
            self.incarnation,
            self.deployment,
            self.program,
            &self.continuation,
        ) && self.ready_sequence != 0
            && required_refs_valid(&self.required, self.installation_data.as_ref())
            && match self.reason {
                YieldReason::Cooperative => true,
                YieldReason::Await { call } => call != CallId::ZERO,
            }
    }
}

fn valid_continuation_identity(
    invocation: InvocationId,
    actor: ActorId,
    incarnation: Hash,
    deployment: DeploymentId,
    program: ProgramId,
    continuation: &BlobRef,
) -> bool {
    invocation != InvocationId::ZERO
        && actor != ActorId::ZERO
        && incarnation != Hash::ZERO
        && deployment != DeploymentId::ZERO
        && program != ProgramId::ZERO
        && continuation.hash != Hash::ZERO
        && continuation.len != 0
        && continuation.len <= crate::MAX_RUNTIME_STATE_BYTES as u64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOutcome {
    Management(Result<ManagementReply, ManagementError>),
    Completed(Result<InvocationReply, InvocationError>),
    Yielded(YieldedInvocation),
    /// Delivery-retirement result for [`RuntimeWork::Acknowledge`].
    ///
    /// For canonical Standard runtime state/work, acknowledgement emits
    /// `NotCreated`, `NotFound`, `InvalidAuthorization`, or
    /// `DivergentInvocation`. `ResultCapacity` is reserved as a fail-closed
    /// representation error. In particular, acknowledgement does not
    /// reapply current-time authority expiry or authority high-water checks:
    /// those were fixed at the retained result's acceptance slot.
    Acknowledged(Result<InvocationAcknowledgement, InvocationError>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTransition {
    pub state: RuntimeState,
    pub outcome: RuntimeOutcome,
}

impl RuntimeTransition {
    pub fn validate(&self) -> bool {
        self.state.validate()
            && match &self.outcome {
                RuntimeOutcome::Management(Ok(reply)) => crate::wire::management_reply_valid(reply),
                RuntimeOutcome::Completed(Ok(reply)) => {
                    reply.invocation != InvocationId::ZERO
                        && reply.actor != ActorId::ZERO
                        && reply.incarnation != Hash::ZERO
                        && reply.deployment != DeploymentId::ZERO
                        && reply.reply.len() <= MAX_INVOCATION_REPLY_BYTES
                        && reply.observation.merge_frontier != Some(Hash::ZERO)
                }
                RuntimeOutcome::Yielded(yielded) => yielded.validate(),
                RuntimeOutcome::Acknowledged(Ok(acknowledgement)) => acknowledgement.validate(),
                _ => true,
            }
    }
}

/// Public-I/O commitment for one exact canonical runtime execution.
///
/// `canonical_work` must be the complete [`RuntimeWork`] wire bytes supplied
/// to the guest, and `canonical_transition` must be the complete
/// [`RuntimeTransition`] wire bytes returned by that same execution. The
/// guest boundary and the physical host independently establish canonicality;
/// this allocation-free primitive only commits the two already-canonical
/// byte strings.
///
/// Work and transition use distinct leaf domains before the fixed-width
/// leaves are combined. This makes their boundary and roles unambiguous even
/// though [`Hash::digest`] accepts an unframed list of byte slices.
pub fn runtime_transition_public_io(canonical_work: &[u8], canonical_transition: &[u8]) -> Hash {
    let work = Hash::digest(b"vos/agent/runtime-public-io/work/v1", &[canonical_work]);
    let transition = Hash::digest(
        b"vos/agent/runtime-public-io/transition/v1",
        &[canonical_transition],
    );
    Hash::digest(
        b"vos/agent/runtime-public-io/v1",
        &[
            crate::RUNTIME_ABI_ID.as_bytes(),
            work.as_bytes(),
            transition.as_bytes(),
        ],
    )
}

/// Public-I/O commitment for one canonical runtime execution, with the work
/// committed by reference ([`crate::wire::runtime_work_reference_commitment`]).
///
/// It binds the same bytes as [`runtime_transition_public_io`]: the work's
/// decoder authenticates every availability preimage against its reference
/// before the runtime executes, so the reference form identifies the complete
/// canonical work. The guest no longer hashes caller-sized availability a
/// second time to produce it. The domain differs from the byte form's, so the
/// two definitions can never be confused for one another.
pub fn runtime_transition_public_io_by_reference(
    work_by_reference: Hash,
    canonical_transition: &[u8],
) -> Hash {
    let transition = Hash::digest(
        b"vos/agent/runtime-public-io/transition/v1",
        &[canonical_transition],
    );
    Hash::digest(
        b"vos/agent/runtime-public-io/v2",
        &[
            crate::RUNTIME_ABI_ID.as_bytes(),
            work_by_reference.as_bytes(),
            transition.as_bytes(),
        ],
    )
}

/// Native counterpart of the guest's by-reference public I/O, for verifiers
/// and replicas holding the exact canonical work bytes. It decodes the work,
/// which authenticates every availability preimage, and refuses a work whose
/// blob bytes do not match their references, exactly as the guest traps.
pub fn runtime_transition_public_io_of_work(
    canonical_work: &[u8],
    canonical_transition: &[u8],
) -> Result<Hash, crate::wire::WireError> {
    use crate::wire::CanonicalWire as _;
    let work = RuntimeWork::decode(canonical_work)?;
    Ok(runtime_transition_public_io_by_reference(
        crate::wire::runtime_work_reference_commitment(&work),
        canonical_transition,
    ))
}

/// Host-independent contract implemented by every custom AgentRuntime.
pub trait AgentRuntime {
    fn capabilities(&self) -> RuntimeCapabilities;
    fn apply(&mut self, work: RuntimeWork) -> RuntimeTransition;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_and_private_mutation_inline_footprints_remain_bounded() {
        // These guard inline layout growth, not heap data or wire limits.
        assert!(core::mem::size_of::<InvocationAuthorization>() <= 1024);
        assert!(core::mem::size_of::<PrivateRuntimeMutation>() <= 2 * 1024);
    }

    #[test]
    fn runtime_transition_public_io_is_domain_stable_and_role_sensitive() {
        let commitment = runtime_transition_public_io(b"work", b"transition");
        assert_eq!(
            commitment.0,
            [
                0xfa, 0xf8, 0xe1, 0xc3, 0xdb, 0x75, 0x0a, 0xa7, 0x5d, 0x3b, 0x2c, 0xa0, 0x59, 0x2b,
                0x32, 0x52, 0x9a, 0x83, 0xa1, 0x60, 0xd6, 0x34, 0xd3, 0xaf, 0xdf, 0xde, 0x80, 0x9c,
                0x47, 0xc5, 0x84, 0x6e,
            ]
        );
        assert_ne!(
            commitment,
            runtime_transition_public_io(b"transition", b"work")
        );
        assert_ne!(
            commitment,
            runtime_transition_public_io(b"wor", b"ktransition")
        );
        assert_ne!(
            commitment,
            runtime_transition_public_io(b"work!", b"transition")
        );
        assert_ne!(
            commitment,
            runtime_transition_public_io(b"work", b"transition!")
        );
    }

    #[test]
    fn management_authority_metadata_is_derived_from_the_typed_request() {
        let actor = ActorId([1; 32]);
        let deployment = DeploymentId([2; 32]);
        let mut request = ManagementRequest::Suspend {
            actor,
            expected_deployment: deployment,
        };
        assert!(request.is_valid());
        assert_eq!(
            request.authority_operation(),
            Some(crate::authority::AuthorityOperationKind::SuspendActor)
        );
        assert_eq!(request.authority_actor(), Some((actor, deployment)));

        request = ManagementRequest::InspectResources;
        assert!(request.is_valid());
        assert_eq!(request.authority_operation(), None);
        assert_eq!(request.authority_actor(), None);

        request = ManagementRequest::Suspend {
            actor: ActorId::ZERO,
            expected_deployment: deployment,
        };
        assert!(!request.is_valid());
    }

    #[test]
    fn continuation_tuple_rejects_zero_or_oversized_references() {
        let mut resume = ResumeWork {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([3; 32]),
            deployment: DeploymentId([4; 32]),
            program: ProgramId([5; 32]),
            mode: MethodMode::Linear,
            continuation: BlobRef {
                hash: Hash([6; 32]),
                len: 128,
            },
            ready_sequence: 7,
            installation_data: None,
            availability: alloc::vec![],
            input: None,
        };
        assert!(resume.validate());
        resume.ready_sequence = 0;
        assert!(!resume.validate());
        resume.ready_sequence = 7;
        resume.continuation.len = crate::MAX_RUNTIME_STATE_BYTES as u64 + 1;
        assert!(!resume.validate());
    }

    #[test]
    fn resume_preimages_and_yielded_requirements_are_canonical_maps() {
        let runtime_blob = |bytes: &[u8]| RuntimeBlob {
            reference: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        };
        let mut availability = alloc::vec![runtime_blob(b"first"), runtime_blob(b"second")];
        availability.sort_unstable_by_key(|blob| blob.reference.clone());
        let mut resume = ResumeWork {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([3; 32]),
            deployment: DeploymentId([4; 32]),
            program: ProgramId([5; 32]),
            mode: MethodMode::Linear,
            continuation: BlobRef::of_bytes(b"continuation"),
            ready_sequence: 1,
            installation_data: None,
            availability: availability.clone(),
            input: None,
        };
        assert!(resume.validate());
        resume.availability[0].bytes[0] ^= 1;
        assert!(
            !resume.validate(),
            "aliases with mismatched bytes fail closed"
        );

        let mut required = availability
            .iter()
            .map(|blob| blob.reference.clone())
            .collect::<Vec<_>>();
        let mut yielded = YieldedInvocation {
            invocation: resume.invocation,
            actor: resume.actor,
            incarnation: resume.incarnation,
            deployment: resume.deployment,
            program: resume.program,
            mode: resume.mode,
            continuation: resume.continuation,
            ready_sequence: 1,
            installation_data: None,
            required: required.clone(),
            reason: YieldReason::Cooperative,
        };
        assert!(yielded.validate());
        required.swap(0, 1);
        yielded.required = required;
        assert!(!yielded.validate());
    }

    #[test]
    fn credentials_never_stand_in_for_principals() {
        let origin = InvocationOrigin {
            credential: Some(CredentialId([1; 32])),
            ..InvocationOrigin::anonymous()
        };
        assert!(!origin.validate());
    }

    #[test]
    fn invocation_roles_are_exact_single_predicates_owned_by_a_principal() {
        let principal = InvocationOrigin {
            principal: Some(PrincipalId([1; 32])),
            transport_node: Some(NodeId([2; 32])),
            credential: Some(CredentialId([3; 32])),
            actor: Some(ActorId([4; 32])),
            capability: None,
        };
        let space = InvocationRoleClaims {
            space: Some(crate::RoleId([5; 32])),
            actor: None,
        };
        let actor = InvocationRoleClaims {
            space: None,
            actor: Some(crate::RoleId([6; 32])),
        };
        assert!(space.validate_for(principal));
        assert!(actor.validate_for(principal));
        assert!(!space.validate_for(InvocationOrigin::anonymous()));
        assert!(
            !InvocationRoleClaims {
                space: space.space,
                actor: actor.actor,
            }
            .validate_for(principal)
        );
        assert!(
            !InvocationRoleClaims {
                space: Some(crate::RoleId::ZERO),
                actor: None,
            }
            .validate_for(principal)
        );

        let capability = InvocationOrigin {
            capability: Some(CapabilityId([7; 32])),
            ..principal
        };
        assert!(!space.validate_for(capability));
        assert!(InvocationRoleClaims::none().validate_for(capability));
    }

    #[test]
    fn invocation_availability_is_a_strictly_sorted_content_map() {
        let blob = |bytes: &[u8]| RuntimeBlob {
            reference: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        };
        let mut availability = alloc::vec![blob(b"first"), blob(b"second")];
        availability.sort_by(|left, right| left.reference.cmp(&right.reference));
        let mut invocation = InvocationWork {
            space: SpaceId([1; 32]),
            agent: crate::AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([4; 32]),
            actor: ActorId([5; 32]),
            incarnation: Hash([6; 32]),
            deployment: DeploymentId([7; 32]),
            program: ProgramId([8; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            message: alloc::vec![],
            installation_data: None,
            availability,
            gas: 1,
            recovery_only: false,
        };

        assert!(invocation.validate());
        invocation.availability.swap(0, 1);
        assert!(!invocation.validate());
        invocation.availability[1] = invocation.availability[0].clone();
        assert!(!invocation.validate());
    }

    #[test]
    fn present_empty_installation_data_is_the_only_zero_length_required_role() {
        let installation = BlobRef::of_bytes(&[]);
        let empty = RuntimeBlob {
            reference: installation.clone(),
            bytes: alloc::vec![],
        };
        let mut resume = ResumeWork {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([3; 32]),
            deployment: DeploymentId([4; 32]),
            program: ProgramId([5; 32]),
            mode: MethodMode::Linear,
            continuation: BlobRef::of_bytes(b"continuation"),
            ready_sequence: 1,
            installation_data: Some(installation.clone()),
            availability: alloc::vec![empty],
            input: None,
        };
        assert!(resume.validate());
        resume.installation_data = None;
        assert!(!resume.validate());

        let mut yielded = YieldedInvocation {
            invocation: resume.invocation,
            actor: resume.actor,
            incarnation: resume.incarnation,
            deployment: resume.deployment,
            program: resume.program,
            mode: resume.mode,
            continuation: resume.continuation,
            ready_sequence: 1,
            installation_data: Some(installation.clone()),
            required: alloc::vec![installation],
            reason: YieldReason::Cooperative,
        };
        assert!(yielded.validate());
        yielded.installation_data = None;
        assert!(!yielded.validate());
    }
}
