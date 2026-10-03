//! Agent programming model.
//!
//! An agent is a durable runtime instance inside a space. It owns zero or
//! more actors and has one immutable storage/replication profile. Actor fields
//! select state lanes; methods select the lane they may mutate.

use alloc::boxed::Box;
use alloc::string::String;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

pub use crate::actors::tasks::{Child, TaskId, TaskRecord, TaskStatus, Tasks};
/// Portable clean-generation ABI. This namespace is deliberately separate
/// from the transitional in-crate runtime implementation below, so no legacy
/// service wire can be decoded as an SDK message.
pub mod sdk {
    pub use vos_agent_sdk::*;
}
pub(crate) mod actor_storage;
pub mod authority;
#[cfg(feature = "std")]
pub mod authority_operation_coordinator;
#[cfg(feature = "std")]
pub mod authority_operation_issuer;
pub mod bootstrap;
pub mod catalog_finality;
pub mod composite;
#[cfg(feature = "std")]
pub mod clean_authority_issuer;
#[cfg(feature = "std")]
pub mod clean_bootstrap;
#[cfg(all(
    feature = "std",
    feature = "storage",
    feature = "network",
    target_os = "linux"
))]
pub mod clean_control;
#[cfg(feature = "std")]
pub(crate) mod clean_management_intent;
pub mod committee;
pub mod contract;
#[cfg(feature = "std")]
pub mod driver;
pub mod execution;
#[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
pub(crate) mod external_local_executor;
pub mod genesis;
pub mod genesis_archive;
#[cfg(feature = "std")]
pub mod host;
pub(crate) mod invocation_history;
pub(crate) mod invocation_index;
#[cfg(feature = "std")]
pub(crate) mod invocation_preparation;
pub mod journal;
#[cfg(feature = "std")]
pub(crate) mod journal_store;
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
pub use journal_store::{ExternalLocalJournalDirectory, JournalStoreError};
#[cfg(feature = "std")]
pub(crate) mod local_journal_driver;
#[cfg(all(
    feature = "std",
    feature = "storage",
    feature = "network",
    target_os = "linux"
))]
pub mod local_lifecycle;
#[cfg(all(feature = "std", feature = "network"))]
pub use local_journal_driver::Ed25519NodeMergeAuthenticator;
#[cfg(feature = "std")]
pub mod local_management;
#[cfg(feature = "std")]
pub mod local_sdk_host;
#[cfg(feature = "pvm")]
pub mod machine;
pub mod package;
#[cfg(feature = "std")]
pub mod package_admission;
#[cfg(feature = "private-agent-crypto")]
pub mod private_crypto;
#[cfg(all(
    feature = "std",
    feature = "storage",
    feature = "network",
    target_os = "linux"
))]
pub mod production_owner;
#[cfg(all(
    feature = "std",
    feature = "storage",
    feature = "network",
    target_os = "linux"
))]
pub(crate) mod production_worker;
pub(crate) mod replay;
#[cfg(feature = "std")]
pub(crate) mod runtime_pvm;
pub mod schema;
pub mod shared_commit;
#[cfg(all(feature = "std", feature = "storage", target_os = "linux"))]
pub mod shared_host;
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) mod shared_journal_driver;
pub mod shared_raft;
pub mod shared_recovery;
pub mod standard;
#[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
pub(crate) mod state_block_pvm;
#[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
pub(crate) mod state_block_store;
#[cfg(feature = "std")]
pub mod supervisor;
#[cfg(feature = "std")]
pub mod supervisor_adapters;
pub mod system_authority;
pub(crate) mod system_authority_ledger;
#[cfg(feature = "std")]
// Sealed two-phase proof boundary awaiting the clean replay/Standard-runtime
// integration described in the module docs; its complete API is exercised by
// focused tests in the meantime.
#[allow(dead_code)]
pub(crate) mod transition_proof_host;
#[allow(dead_code)]
pub(crate) mod transition_proof_journal;
pub mod wire;
use crate::service::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, InstallationId, NodeId, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

/// Stable lifecycle contract implemented by every agent runtime.
pub const RUNTIME_ABI_ID: Hash = Hash(*b"vos-agent-runtime-abi-20260906r0");

/// Consensus-visible execution semantics for standard-PVM agent packages.
///
/// This is intentionally distinct from [`crate::service::EXECUTION_SEMANTICS_ID`]:
/// the transitional Service package path executes the frozen
/// capability-manifest profile, while Agent Actor and AgentRuntime packages
/// execute the standard SPI profile. A semantics change in one profile must
/// not silently accept—or unnecessarily invalidate—packages for the other
/// profile. Generation `r05` adds globally ordered, quorum-certified catalog
/// finalization to Standard Control. Generation `r03` additionally binds exact durable terminal and
/// execution-error outcomes to their authenticated invocation ownership and
/// acknowledgement protocol. Generation `r02` introduced the full v0.8
/// reorder-buffer gas scheduler, full-Ψ deblob/entry failure boundary, and
/// sign-extended 64-bit `ecalli` identifiers; older generations are
/// incompatible. Generation `r04` adds the replay-authenticated journal
/// context and the root-seeded live system-authority state machine to
/// Standard Control; its direct finalize/rotate operations are therefore
/// incompatible with every earlier Standard runtime image. Generation `r06`
/// passes the exact immutable constructor-argument frame to every fresh or
/// restored inner actor machine.
pub const EXECUTION_SEMANTICS_ID: Hash = Hash(*b"vos-pvm-41d31e6-standard-gas-r06");

/// Maximum bytes named by one content-addressed artifact reference in an
/// authenticated Agent catalog closure.
pub const MAX_CATALOG_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum canonical constructor-argument bytes attached to one actor
/// installation. The bytes are catalog data, never a mutable lane;
/// `#[state(const)]` fields are reconstructed by the constructor.
pub const MAX_INSTALLATION_DATA_BYTES: usize = 64 * 1024;
/// Maximum distinct `(hash, encoded_len)` references in a Standard Agent
/// catalog: one runtime package plus package/schema/policy/constructor data
/// for every actor.
pub const MAX_CATALOG_ARTIFACT_REFERENCES: u32 = 1 + 4 * contract::STANDARD_MAX_ACTORS;
/// Maximum aggregate bytes reachable through one authenticated Agent catalog
/// closure, independently of its encoded manifest size.
pub const MAX_CATALOG_ARTIFACT_REFERENCED_BYTES: u64 = 64 * 1024 * 1024;

/// Program identity of the bundled standard runtime artifact.
pub const STANDARD_RUNTIME_PROGRAM_ID: ProgramId = ProgramId([
    0x20, 0xf5, 0xc8, 0x01, 0xe9, 0x66, 0xa6, 0xe6, 0xbc, 0x14, 0xcd, 0x1b, 0xdf, 0x00, 0xb7, 0x21,
    0xf2, 0xff, 0xc5, 0xbc, 0x86, 0xbf, 0xf6, 0x99, 0xcc, 0x07, 0x08, 0x71, 0x15, 0x68, 0x90, 0x9a,
]);

/// Immutable storage and publication profile of an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentProfile {
    /// One node. Linear and node-local state are available; no network
    /// replication is configured.
    Local = 0,
    /// Published to the space. Linear state uses consensus, merge state uses
    /// causal replication, and local state remains per replica. This profile
    /// requires a replicated host adapter; the process-local `AgentDriver`
    /// rejects it rather than weakening Merge into replacement semantics.
    Shared = 1,
    /// Unpublished, owner-node-only causal replication. Linear state is not
    /// available in the initial private profile. This likewise requires an
    /// owner-authenticated causal host adapter and is not accepted by the
    /// process-local driver.
    Private = 2,
}

impl AgentProfile {
    pub const fn supports(self, lane: StateLane) -> bool {
        match self {
            Self::Local => true,
            Self::Shared => true,
            Self::Private => matches!(lane, StateLane::Merge | StateLane::Local),
        }
    }

    pub const fn is_published(self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// A durable state lane selected by an actor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StateLane {
    /// Totally ordered state. Plain persisted fields use this lane.
    Linear = 0,
    /// Causally replicated, convergent state. `crdt::*` fields use this lane.
    Merge = 1,
    /// Per-replica state which is never synchronized.
    Local = 2,
}

/// Exactly-once namespace selected by an invocation's consistency mode.
///
/// Ordered invocations share one namespace across control/query and Linear
/// execution. Merge invocations are deduplicated at the canonical Merge
/// replay position. Local invocations are deduplicated in the replica-local
/// component, so the physical Local state additionally scopes them to the
/// owning node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum InvocationScope {
    Ordered = 0,
    Merge = 1,
    Local = 2,
}

/// Guest-owned durable component retaining one exact invocation result.
/// Ordinary coherent queries span Linear and Merge snapshots, so their
/// disposition belongs to topology-neutral control state rather than either
/// data lane. Other modes retain the result with their consistency lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationResultStorage {
    Control,
    Lane(StateLane),
}

/// Complete persistence classification of an actor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPersistence {
    State(StateLane),
    /// Immutable configuration committed at actor installation.
    Constant,
    /// Derived or transient data omitted from durable actor state.
    Skipped,
}

/// Execution mode of a generated actor method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodMode {
    /// Replica-coherent query over shared Linear and Merge state; writes are
    /// forbidden and replica-local fields are hidden.
    Query,
    /// Query after a linear read barrier.
    LinearizableQuery,
    /// Same-replica query which may additionally observe Local state.
    LocalQuery,
    /// Mutate linear state and read a pinned merge frontier.
    Linear,
    /// Mutate and read Merge state only.
    Merge,
    /// Mutate this replica's Local state while reading immutable Linear and
    /// Merge snapshots selected by the agent.
    Local,
}

impl MethodMode {
    /// The one lane a mutating method owns. Queries read snapshots without
    /// owning a write lane.
    pub const fn write_lane(self) -> Option<StateLane> {
        match self {
            Self::Linear => Some(StateLane::Linear),
            Self::Merge => Some(StateLane::Merge),
            Self::Local => Some(StateLane::Local),
            Self::Query | Self::LinearizableQuery | Self::LocalQuery => None,
        }
    }

    /// Durable component which owns the exact result disposition. This is
    /// distinct from [`Self::write_lane`]: query execution never mutates
    /// actor state.
    pub const fn result_storage(self) -> InvocationResultStorage {
        match self {
            Self::Query => InvocationResultStorage::Control,
            Self::LinearizableQuery | Self::Linear => {
                InvocationResultStorage::Lane(StateLane::Linear)
            }
            Self::Merge => InvocationResultStorage::Lane(StateLane::Merge),
            Self::LocalQuery | Self::Local => InvocationResultStorage::Lane(StateLane::Local),
        }
    }

    /// Exactly-once namespace for this invocation mode.
    pub const fn invocation_scope(self) -> InvocationScope {
        match self {
            Self::Query | Self::LinearizableQuery | Self::Linear => InvocationScope::Ordered,
            Self::Merge => InvocationScope::Merge,
            Self::LocalQuery | Self::Local => InvocationScope::Local,
        }
    }
}

impl MethodMode {
    pub const fn can_read(self, lane: StateLane) -> bool {
        match self {
            Self::Query | Self::LinearizableQuery => {
                matches!(lane, StateLane::Linear | StateLane::Merge)
            }
            Self::LocalQuery | Self::Local => true,
            Self::Linear => matches!(lane, StateLane::Linear | StateLane::Merge),
            Self::Merge => matches!(lane, StateLane::Merge),
        }
    }

    pub const fn can_write(self, lane: StateLane) -> bool {
        matches!(
            (self, lane),
            (Self::Linear, StateLane::Linear)
                | (Self::Merge, StateLane::Merge)
                | (Self::Local, StateLane::Local)
        )
    }
}

/// Compact set of state lanes required or implemented by a package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneSet(u8);

impl LaneSet {
    const LINEAR: u8 = 1 << 0;
    const MERGE: u8 = 1 << 1;
    const LOCAL: u8 = 1 << 2;
    const VALID: u8 = Self::LINEAR | Self::MERGE | Self::LOCAL;

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(Self::VALID);

    pub const fn of(lane: StateLane) -> Self {
        Self(match lane {
            StateLane::Linear => Self::LINEAR,
            StateLane::Merge => Self::MERGE,
            StateLane::Local => Self::LOCAL,
        })
    }

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::VALID == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, lane: StateLane) -> bool {
        self.0 & Self::of(lane).0 != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn supported_by(self, profile: AgentProfile) -> bool {
        (!self.contains(StateLane::Linear) || profile.supports(StateLane::Linear))
            && (!self.contains(StateLane::Merge) || profile.supports(StateLane::Merge))
            && (!self.contains(StateLane::Local) || profile.supports(StateLane::Local))
    }
}

/// Consensus participation of one authorized agent replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplicaRole {
    Voter = 0,
    Observer = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentReplica {
    pub node: NodeId,
    /// Principal bound to this node's signed replica identity.
    pub principal: PrincipalId,
    pub role: ReplicaRole,
}

/// Runtime features actor packages may require.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeRequirements {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proofs: bool,
}

/// Immutable capability declaration signed into an agent-runtime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub lanes: LaneSet,
    pub scheduling: bool,
    pub proofs: bool,
    /// Durable directory capacity. This is independent of the maximum 63
    /// simultaneously active standard inner machines.
    pub max_actors: u32,
}

/// Typed payload of one signed `.vos` package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Actor {
        contract: contract::ActorPackageContract,
        requirements: RuntimeRequirements,
    },
    AgentRuntime {
        contract: contract::RuntimePackageContract,
        capabilities: RuntimeCapabilities,
    },
}

impl PackageKind {
    pub fn is_compatible_with(
        self,
        runtime_contract: contract::RuntimePackageContract,
        runtime: RuntimeCapabilities,
    ) -> bool {
        match self {
            Self::Actor {
                contract,
                requirements,
            } => runtime_contract.supports(contract) && runtime.satisfies(requirements),
            Self::AgentRuntime { contract, .. } => contract.is_valid(),
        }
    }
}

impl RuntimeCapabilities {
    /// Standard agent policy. The separately signed runtime-state byte limit
    /// still bounds aggregate directory and actor state.
    pub const STANDARD_MAX_ACTORS: u32 = contract::STANDARD_MAX_ACTORS;

    pub const fn standard() -> Self {
        Self {
            lanes: LaneSet::ALL,
            scheduling: false,
            // Recorded/provable Tasks need a separate private-witness and
            // proof-result ABI. The standard AGEX runtime currently exports
            // only state lanes and a typed reply, so it must fail closed on
            // packages which require proof execution.
            proofs: false,
            max_actors: Self::STANDARD_MAX_ACTORS,
        }
    }

    pub const fn satisfies(self, requirements: RuntimeRequirements) -> bool {
        (requirements.lanes.bits() & !self.lanes.bits()) == 0
            && (!requirements.scheduling || self.scheduling)
            && (!requirements.proofs || self.proofs)
    }
}

/// Stable identity of one runtime instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub profile: AgentProfile,
    pub runtime_deployment: DeploymentId,
    pub runtime_program: ProgramId,
    pub runtime_producer: ProducerId,
    /// Stable producer identity authorized to sign transition proofs. Runtime
    /// upgrades must preserve this independently owned online identity.
    pub transition_producer: ProducerId,
}

/// Durable actor-directory entry. `parent = None` denotes a top-level actor;
/// no actor is privileged as an agent root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorEntry {
    pub actor: ActorId,
    pub name: String,
    pub parent: Option<ActorId>,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    /// Exact signed package which selected this deployment. Exposing the
    /// reference lets the host reconcile catalog ownership without treating
    /// a process-local package cache as authority.
    pub package: BlobRef,
    /// Exact signed execution schema selected by this deployment. Directory
    /// inspection exposes the commitment so a host can authenticate the
    /// deployment-keyed schema sidecar before publishing an actor route.
    pub agent_schema: BlobRef,
    /// Exact canonical method-policy artifact selected by the signed
    /// package. The agent runtime, rather than application actor code,
    /// enforces this policy before dispatch.
    pub role_policies: BlobRef,
    /// Nonzero commitment of the exact signed constructor ABI, including the
    /// zero-argument/raw-byte/named-typed encoding mode and ordered fields.
    pub constructor_abi: Hash,
    /// Exact canonical constructor-argument object replayed verbatim on each
    /// fresh inner-machine load. `Some(empty)` is distinct from `None`; const
    /// fields are reconstructed by the constructor rather than stored here.
    pub installation_data: Option<BlobRef>,
    /// State-layout commitment derived from `agent_schema`.
    pub state_layout: Hash,
    pub lanes: LaneSet,
    pub suspended: bool,
}

/// Atomic content-addressed installation input. Keeping the bytes beside the
/// reference in the install request makes commitment and catalog admission a
/// single canonical operation; durable directory state stores only the ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationData {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

impl InstallationData {
    pub fn is_valid(&self) -> bool {
        self.reference.hash != Hash::ZERO
            && self.bytes.len() <= MAX_INSTALLATION_DATA_BYTES
            && self.reference.matches(&self.bytes)
    }
}

/// One installed actor together with the immutable identity of this exact
/// installation. The incarnation changes when an ActorId is removed and
/// installed again, but remains stable across an in-place upgrade.
///
/// Keeping this separate from [`ActorEntry`] avoids giving install callers a
/// generation field which the guest, rather than the caller, must derive from
/// the admitted lifecycle operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorDirectoryRecord {
    pub entry: ActorEntry,
    pub incarnation: Hash,
    /// Stable catalog identity of the install operation which created this
    /// actor. It does not change across an in-place actor upgrade.
    pub installation_id: InstallationId,
    /// Commitment of the finality-backed registry reservation which admitted
    /// this install. Hosts compare this exact value when completing/retrying
    /// the registry lifecycle protocol.
    pub registry_reservation: Hash,
}

/// One deterministic page of the potentially large actor forest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorDirectoryPage {
    pub entries: Vec<ActorDirectoryRecord>,
    pub next: Option<ActorId>,
}

/// Canonical install request consumed by an agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallActor {
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub role_policies: BlobRef,
    pub constructor_abi: Hash,
    pub installation_data: Option<InstallationData>,
    pub state_layout: Hash,
    pub contract: contract::ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

/// Canonical actor upgrade request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeActor {
    pub actor: ActorId,
    pub from_deployment: DeploymentId,
    pub to_deployment: DeploymentId,
    pub to_program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub role_policies: BlobRef,
    /// Exact signed target constructor ABI. Upgrades preserve the meaning of
    /// the original immutable constructor-argument object byte for byte.
    pub constructor_abi: Hash,
    pub state_layout: Hash,
    pub contract: contract::ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

/// Complete durable provenance and lane roots of one installed actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRecord {
    pub entry: ActorEntry,
    /// Guest-derived identity of this exact install. It is stable across
    /// upgrades and prevents sparse lane bytes left by a removed actor from
    /// being attached to a later install which reuses the same [`ActorId`].
    pub state_generation: Hash,
    /// Stable catalog install identity retained across upgrades and reopen.
    pub installation_id: InstallationId,
    /// Exact finality-backed registry reservation which admitted the install.
    pub registry_reservation: Hash,
    /// Immutable commitment of the complete original [`InstallActor`]
    /// request. Mutable actor deployment state must never redefine what an
    /// exact retry of this installation means.
    pub install_request_commitment: Hash,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub agent_schema: BlobRef,
    pub role_policies: BlobRef,
    pub constructor_abi: Hash,
    pub installation_data: Option<BlobRef>,
    pub state_layout: Hash,
    pub contract: contract::ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

/// Durable work that prevents safe leaf removal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActorLifecycleDebt {
    pub children: u32,
    pub continuations: u32,
    pub inbox: u32,
    pub outbox: u32,
    pub schedules: u32,
    pub proof_artifacts: u32,
    pub lifecycle_operations: u32,
}

impl ActorLifecycleDebt {
    pub const fn is_clear(self) -> bool {
        self.children == 0
            && self.continuations == 0
            && self.inbox == 0
            && self.outbox == 0
            && self.schedules == 0
            && self.proof_artifacts == 0
            && self.lifecycle_operations == 0
    }
}

/// Lifecycle operation sent to the runtime's management entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleRequest {
    Create(AgentConfig),
    Inspect {
        after: Option<ActorId>,
        limit: u16,
    },
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
    /// Retire one durable exact-result record after the caller has received
    /// it. The request commitment prevents an unrelated invocation holder
    /// from deleting another result.
    AcknowledgeInvocation {
        scope: InvocationScope,
        invocation: crate::service::InvocationId,
        request: Hash,
        authority: Box<authority::ActorInvocationReceipt>,
    },
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    UpgradeRuntime {
        from_deployment: DeploymentId,
        to_deployment: DeploymentId,
        to_program: ProgramId,
        producer: ProducerId,
        package: BlobRef,
        contract: contract::RuntimePackageContract,
        capabilities: RuntimeCapabilities,
    },
    /// Finalize one quorum-certified ordinary Agent genesis decision in the
    /// root system Agent's permanent decision tree. This is a direct
    /// management command: its embedded committee QC is the authority, so it
    /// must never be wrapped in a generic lifecycle receipt.
    FinalizeSystemAuthority(system_authority::SystemAuthorityFinalize),
    /// Rotate the live system-authority committee under the retiring and
    /// incoming committees' joint certificate.
    RotateSystemAuthority(system_authority::SystemAuthorityRotation),
    /// Finalize one exact catalog mutation result in the root system Agent's
    /// globally ordered authority state. The embedded QC is the authority;
    /// the sparse proof is replaceable transport evidence for permanent
    /// OperationId membership and must not be wrapped in a lifecycle receipt.
    FinalizeCatalog(system_authority::SystemAuthorityCatalogFinalize),
    /// Authority-signed lifecycle operation. The bundled runtime verifies
    /// its sequence exactly once and retains a bounded durable disposition so
    /// retries cannot reapply an older transition after later operations.
    Authorized {
        admission: LifecycleAuthorityAdmission,
        request: Box<LifecycleRequest>,
    },
}

/// Complete authority evidence admitted at one canonical logical slot.
/// Signature verification and claim binding occur again inside the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleAuthorityAdmission {
    pub receipt: authority::AgentAuthorityReceipt,
    /// Trusted logical slot observed by the host while verifying this claim.
    /// The runtime persists a monotone high-water so a regressed clock cannot
    /// reopen an older receipt's validity window after restart.
    pub observed_slot: u64,
}

impl LifecycleRequest {
    /// Authority capability which must sign this lifecycle operation.
    ///
    /// Keeping this mapping beside the canonical request prevents the host,
    /// issuer, and standard runtime from drifting onto different policy
    /// identities. Read-only and already-authorized envelope variants do not
    /// accept a new lifecycle receipt.
    pub const fn required_capability(&self) -> Option<&'static str> {
        match self {
            Self::Create(config) => Some(match config.identity.profile {
                AgentProfile::Local => authority::CAPABILITY_AGENT_CREATE_LOCAL,
                AgentProfile::Private => authority::CAPABILITY_AGENT_CREATE_PRIVATE,
                AgentProfile::Shared => authority::CAPABILITY_AGENT_CREATE_SHARED,
            }),
            Self::Install(_) => Some(authority::CAPABILITY_ACTOR_INSTALL),
            Self::UpgradeActor(_) => Some(authority::CAPABILITY_ACTOR_UPGRADE),
            Self::Suspend { .. } | Self::Resume { .. } | Self::RemoveLeaf { .. } => {
                Some(authority::CAPABILITY_ACTOR_LIFECYCLE)
            }
            Self::UpgradeRuntime { .. } => Some(authority::CAPABILITY_AGENT_RUNTIME_UPGRADE),
            Self::Inspect { .. }
            | Self::AcknowledgeInvocation { .. }
            | Self::FinalizeSystemAuthority(_)
            | Self::RotateSystemAuthority(_)
            | Self::FinalizeCatalog(_)
            | Self::Authorized { .. } => None,
        }
    }

    /// Stable commitment used by authority receipts. It includes the runtime
    /// ABI and every request field, but no mutable runtime state.
    pub fn commitment(&self) -> Hash {
        // Sparse membership proofs are replaceable transport evidence. The
        // logical operation identity is the exact certified decision or
        // rotation, not the path against whichever permanent root is current
        // when a retry is submitted.
        match self {
            Self::FinalizeSystemAuthority(finalize) => return finalize.operation_commitment(),
            Self::RotateSystemAuthority(rotation) => return rotation.operation_commitment(),
            Self::FinalizeCatalog(finalize) => return finalize.operation_commitment(),
            _ => {}
        }
        let call = wire::RuntimeCall::new(wire::RuntimeState::default(), self.clone());
        Hash::digest(
            b"vos/agent/lifecycle-operation",
            &[&crate::service::wire::ServiceWire::encode(&call)],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
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
    /// Exact deterministic refusal from the live system-authority state
    /// machine. Keeping the structured cause in the lifecycle ABI makes the
    /// native replay and guest executions byte-for-byte comparable.
    SystemAuthority(system_authority::SystemAuthorityError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleReply {
    Created(AgentIdentity),
    Directory(ActorDirectoryPage),
    Installed(ActorEntry),
    Upgraded(ActorEntry),
    Suspended(ActorEntry),
    Resumed(ActorEntry),
    InvocationAcknowledged {
        scope: InvocationScope,
        invocation: crate::service::InvocationId,
    },
    Removed(ActorId),
    RuntimeUpgraded(AgentIdentity),
    SystemAuthorityFinalized(system_authority::SystemAuthorityFinalizeOutcome),
    SystemAuthorityRotated {
        rotation: system_authority::SystemAuthorityRotationId,
        epoch: u64,
        exact_retry: bool,
    },
    CatalogFinalized(system_authority::SystemAuthorityCatalogFinalizeOutcome),
}

/// Public Rust contract custom agent runtimes implement. The PVM entry glue
/// is deliberately separate from policy: alternate runtimes may choose
/// scheduling or actor-priority behavior while preserving this lifecycle.
pub trait AgentRuntime {
    fn capabilities(&self) -> RuntimeCapabilities;
    fn apply(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, LifecycleError>;
    fn lifecycle_debt(&self, actor: ActorId) -> Result<ActorLifecycleDebt, LifecycleError>;
}

/// Structural validation of immutable agent configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentConfigError {
    InvalidIdentity,
    NoReplicas,
    TooManyReplicas,
    InvalidReplicaIdentity,
    DuplicateReplica,
    ReplicaOrder,
    UnsupportedLane,
    InvalidLocalReplicaSet,
    NoSharedVoter,
    InvalidPrivateReplicaRole,
    InvalidPrivateReplicaOwner,
    InvalidRuntimeCapacity,
    InvalidRuntimePackage,
    InvalidSystemAuthorityGenesis,
}

/// Maximum replicas admitted by one immutable Agent configuration.
///
/// This matches both authority-committee and Raft membership bounds. Wire
/// decoders enforce the limit before allocating the caller-declared list.
pub const MAX_AGENT_REPLICAS: usize = 256;

/// Immutable creation descriptor consumed by an agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentConfig {
    pub identity: AgentIdentity,
    /// Caller-selected, authority-signed creation nonce used to derive the
    /// globally stable AgentId from `(space, owner, nonce)`.
    pub creation_nonce: Hash,
    /// Exact system-authority deployment allowed to issue lifecycle receipts
    /// for this agent.
    pub authority: authority::AgentAuthorityBinding,
    /// Root-only immutable seed for the live system authority. Ordinary
    /// Agents carry `None`; a root system Agent carries the exact root-pinned
    /// genesis descriptor which Standard Control revalidates on every restore.
    pub system_authority_genesis: Option<system_authority::SystemAuthorityGenesis>,
    pub runtime_package: BlobRef,
    pub runtime_contract: contract::RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
    pub replicas: Vec<AgentReplica>,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentConfigError> {
        if self.identity.space == SpaceId::ZERO
            || self.identity.agent == AgentId::ZERO
            || self.identity.owner == PrincipalId::ZERO
            || self.creation_nonce == Hash::ZERO
            || AgentId::derive(
                self.identity.space,
                self.identity.owner,
                &self.creation_nonce.0,
            ) != self.identity.agent
        {
            return Err(AgentConfigError::InvalidIdentity);
        }
        if !self.authority.validate() {
            return Err(AgentConfigError::InvalidIdentity);
        }
        if let Some(genesis) = &self.system_authority_genesis {
            if genesis.validate().is_err()
                || self.identity.agent != self.authority.agent
                || genesis.initial_committee().space() != self.identity.space
                || genesis.initial_committee().authority_binding() != self.authority.commitment()
            {
                return Err(AgentConfigError::InvalidSystemAuthorityGenesis);
            }
        }
        if self.capabilities.max_actors == 0 || !self.runtime_contract.is_valid() {
            return Err(AgentConfigError::InvalidRuntimeCapacity);
        }
        if self.identity.runtime_deployment == DeploymentId::ZERO
            || self.identity.runtime_program == ProgramId::ZERO
            || self.identity.runtime_producer == ProducerId::ZERO
            || self.identity.transition_producer == ProducerId::ZERO
            || self.identity.transition_producer == self.identity.runtime_producer
            || self.runtime_package.hash == Hash::ZERO
            || self.runtime_package.len == 0
        {
            return Err(AgentConfigError::InvalidRuntimePackage);
        }
        if !self.capabilities.lanes.supported_by(self.identity.profile) {
            return Err(AgentConfigError::UnsupportedLane);
        }
        if self.replicas.is_empty() {
            return Err(AgentConfigError::NoReplicas);
        }
        if self.replicas.len() > MAX_AGENT_REPLICAS {
            return Err(AgentConfigError::TooManyReplicas);
        }
        if self
            .replicas
            .iter()
            .any(|replica| replica.node == NodeId::ZERO || replica.principal == PrincipalId::ZERO)
        {
            return Err(AgentConfigError::InvalidReplicaIdentity);
        }
        if self.identity.profile == AgentProfile::Local && self.replicas.len() != 1 {
            return Err(AgentConfigError::InvalidLocalReplicaSet);
        }
        if self.identity.profile == AgentProfile::Shared
            && !self
                .replicas
                .iter()
                .any(|replica| replica.role == ReplicaRole::Voter)
        {
            // Linear state and lifecycle control require a consensus writer.
            // An observer-only Shared descriptor could otherwise be accepted
            // even though no replica is allowed to advance it.
            return Err(AgentConfigError::NoSharedVoter);
        }
        for pair in self.replicas.windows(2) {
            if pair[0].node == pair[1].node {
                return Err(AgentConfigError::DuplicateReplica);
            }
            if pair[0].node > pair[1].node {
                return Err(AgentConfigError::ReplicaOrder);
            }
        }
        if self.identity.profile == AgentProfile::Private
            && self
                .replicas
                .iter()
                .any(|replica| replica.role != ReplicaRole::Observer)
        {
            return Err(AgentConfigError::InvalidPrivateReplicaRole);
        }
        if self.identity.profile == AgentProfile::Private
            && self
                .replicas
                .iter()
                .any(|replica| replica.principal != self.identity.owner)
        {
            return Err(AgentConfigError::InvalidPrivateReplicaOwner);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority_binding() -> authority::AgentAuthorityBinding {
        let public_key = authority::ed25519_public_key_wire([0x41; 32]);
        authority::AgentAuthorityBinding {
            agent: AgentId([10; 32]),
            actor: ActorId([11; 32]),
            deployment: DeploymentId([12; 32]),
            program: ProgramId([13; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    #[test]
    fn private_profile_rejects_linear_state() {
        assert!(!AgentProfile::Private.supports(StateLane::Linear));
        assert!(AgentProfile::Private.supports(StateLane::Merge));
        assert!(AgentProfile::Private.supports(StateLane::Local));
        assert!(!LaneSet::of(StateLane::Linear).supported_by(AgentProfile::Private));
    }

    #[test]
    fn method_access_matrix_is_explicit() {
        assert!(MethodMode::Linear.can_read(StateLane::Merge));
        assert!(MethodMode::Linear.can_write(StateLane::Linear));
        assert!(!MethodMode::Linear.can_write(StateLane::Merge));
        assert!(!MethodMode::Merge.can_read(StateLane::Linear));
        assert!(MethodMode::Merge.can_write(StateLane::Merge));
        assert!(MethodMode::Local.can_read(StateLane::Linear));
        assert!(MethodMode::Local.can_write(StateLane::Local));
        assert!(!MethodMode::Query.can_write(StateLane::Linear));
        assert!(!MethodMode::Query.can_read(StateLane::Local));
        assert!(MethodMode::LocalQuery.can_read(StateLane::Local));
        assert_eq!(
            MethodMode::Query.invocation_scope(),
            InvocationScope::Ordered
        );
        assert_eq!(
            MethodMode::LinearizableQuery.invocation_scope(),
            InvocationScope::Ordered
        );
        assert_eq!(
            MethodMode::Linear.invocation_scope(),
            InvocationScope::Ordered
        );
        assert_eq!(MethodMode::Merge.invocation_scope(), InvocationScope::Merge);
        assert_eq!(
            MethodMode::LocalQuery.invocation_scope(),
            InvocationScope::Local
        );
        assert_eq!(MethodMode::Local.invocation_scope(), InvocationScope::Local);
    }

    #[test]
    fn runtime_requirements_are_checked_without_actor_count_coupling() {
        let standard = RuntimeCapabilities::standard();
        assert_eq!(
            standard.max_actors,
            RuntimeCapabilities::STANDARD_MAX_ACTORS
        );
        assert!(!standard.satisfies(RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge)),
            scheduling: false,
            proofs: true,
        }));
        assert!(standard.satisfies(RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge)),
            scheduling: false,
            proofs: false,
        }));
        assert!(!standard.satisfies(RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: true,
            proofs: false,
        }));
        assert!(
            PackageKind::Actor {
                contract: contract::ActorPackageContract::canonical(),
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(StateLane::Merge),
                    scheduling: false,
                    proofs: false,
                },
            }
            .is_compatible_with(contract::RuntimePackageContract::canonical(), standard)
        );
        assert!(
            PackageKind::AgentRuntime {
                contract: contract::RuntimePackageContract::canonical(),
                capabilities: standard,
            }
            .is_compatible_with(contract::RuntimePackageContract::canonical(), standard)
        );
    }

    #[test]
    fn identities_do_not_collapse_principals_nodes_and_credentials() {
        let key = b"same source bytes";
        let principal = PrincipalId::of_public_key(key);
        let node = NodeId::of_authenticated_peer(key);
        let credential = crate::service::CredentialId::of_public_key(key);
        assert_ne!(principal.as_bytes(), node.as_bytes());
        assert_ne!(principal.as_bytes(), credential.as_bytes());
        assert_ne!(node.as_bytes(), credential.as_bytes());
    }

    #[test]
    fn private_agents_accept_only_owner_nodes() {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x15; 32]);
        let mut config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &creation_nonce.0),
                owner,
                profile: AgentProfile::Private,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([8; 32]),
                transition_producer: ProducerId([9; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local)),
                scheduling: false,
                proofs: false,
                max_actors: 4096,
            },
            runtime_package: BlobRef {
                hash: Hash([9; 32]),
                len: 100,
            },
            runtime_contract: contract::RuntimePackageContract::canonical(),
            replicas: vec![AgentReplica {
                node: NodeId([6; 32]),
                principal: owner,
                role: ReplicaRole::Observer,
            }],
        };
        assert_eq!(config.validate(), Ok(()));
        let mut missing_transition_producer = config.clone();
        missing_transition_producer.identity.transition_producer = ProducerId::ZERO;
        assert_eq!(
            missing_transition_producer.validate(),
            Err(AgentConfigError::InvalidRuntimePackage),
        );
        let mut reused_runtime_producer = config.clone();
        reused_runtime_producer.identity.transition_producer =
            reused_runtime_producer.identity.runtime_producer;
        assert_eq!(
            reused_runtime_producer.validate(),
            Err(AgentConfigError::InvalidRuntimePackage),
        );
        config.replicas[0].node = NodeId::ZERO;
        assert_eq!(
            config.validate(),
            Err(AgentConfigError::InvalidReplicaIdentity)
        );
        config.replicas[0].node = NodeId([6; 32]);
        config.replicas[0].principal = PrincipalId::ZERO;
        assert_eq!(
            config.validate(),
            Err(AgentConfigError::InvalidReplicaIdentity)
        );
        config.replicas[0].principal = PrincipalId([7; 32]);
        assert_eq!(
            config.validate(),
            Err(AgentConfigError::InvalidPrivateReplicaOwner)
        );
    }

    #[test]
    fn shared_linear_agents_require_a_voter() {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x16; 32]);
        let mut config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &creation_nonce.0),
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
                transition_producer: ProducerId([8; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef {
                hash: Hash([11; 32]),
                len: 100,
            },
            runtime_contract: contract::RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node: NodeId([12; 32]),
                principal: owner,
                role: ReplicaRole::Observer,
            }],
        };
        assert_eq!(config.validate(), Err(AgentConfigError::NoSharedVoter));
        config.capabilities.lanes = LaneSet::of(StateLane::Merge);
        assert_eq!(
            config.validate(),
            Err(AgentConfigError::NoSharedVoter),
            "the lifecycle control lane is ordered even for a Merge-only package set"
        );
        config.replicas[0].role = ReplicaRole::Voter;
        assert_eq!(config.validate(), Ok(()));

        config.replicas = (0..=MAX_AGENT_REPLICAS)
            .map(|index| {
                let mut node = [0u8; 32];
                node[..2].copy_from_slice(&(index as u16 + 1).to_be_bytes());
                AgentReplica {
                    node: NodeId(node),
                    principal: owner,
                    role: ReplicaRole::Voter,
                }
            })
            .collect();
        assert_eq!(config.validate(), Err(AgentConfigError::TooManyReplicas));
    }

    #[test]
    fn every_lifecycle_debt_blocks_leaf_removal() {
        let clear = ActorLifecycleDebt::default();
        assert!(clear.is_clear());
        for debt in [
            ActorLifecycleDebt {
                children: 1,
                ..clear
            },
            ActorLifecycleDebt {
                continuations: 1,
                ..clear
            },
            ActorLifecycleDebt { inbox: 1, ..clear },
            ActorLifecycleDebt { outbox: 1, ..clear },
            ActorLifecycleDebt {
                schedules: 1,
                ..clear
            },
            ActorLifecycleDebt {
                proof_artifacts: 1,
                ..clear
            },
            ActorLifecycleDebt {
                lifecycle_operations: 1,
                ..clear
            },
        ] {
            assert!(!debt.is_clear());
        }
    }
}
