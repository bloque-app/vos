//! Canonical lane-journal protocol for durable agents.
//!
//! Journal inputs are the durable source of truth. Runtime lane images and
//! checkpoints are derived materializations which can always be authenticated
//! against the exact input suffix that produced them. Control and Linear
//! inputs share one ordered chain, Merge inputs form an authenticated causal
//! DAG, and Local inputs form one chain per exact replica node.
//!
//! This module deliberately contains no filesystem or network policy. Its
//! strict, `no_std` codec is shared by local storage, Raft application entries,
//! causal anti-entropy, and recovery tooling.

use alloc::vec::Vec;
use core::fmt;

use crate::agent_sdk::wire::CanonicalWire as AgentCanonicalWire;

use super::authority::{ActorInvocationReceipt, AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES};
use super::committee::GenesisIntentId;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth, MAX_EXECUTION_AVAILABILITY_BYTES, MAX_EXECUTION_BLOBS, MAX_EXECUTION_GAS,
    MAX_EXECUTION_MESSAGE_BYTES, MAX_EXECUTION_REPLY_BYTES, MAX_RUNTIME_STATE_BYTES, RuntimeBlob,
};
use super::genesis::AgentGenesisAdmissionId;
use super::transition_proof_journal::TransitionProofIndexManifest;
use super::wire::{RuntimeCall, RuntimeState};
use super::{InvocationResultStorage, LifecycleRequest, MethodMode, StateLane};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, CredentialId, DeploymentId, Hash, InvocationId,
    NodeId, PrincipalId, ProducerId, ProgramId, SpaceId,
};

/// Maximum complete canonical replay input, including its wire header.
///
/// A clean invocation retains the complete bounded SDK availability closure
/// so every replica replays exactly the work authorized by the receipt.
pub const MAX_REPLAY_INPUT_BYTES: usize =
    crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES + MAX_CLEAN_YIELDED_WIRE_BYTES + 1024;
/// Maximum canonical empty-state transition used to retain one yielded
/// continuation selector beside an exact clean resume request.
const MAX_CLEAN_YIELDED_WIRE_BYTES: usize = 8 * 1024;
/// Maximum complete ordered, local, or Merge journal record.
pub const MAX_JOURNAL_RECORD_BYTES: usize = MAX_REPLAY_INPUT_BYTES + 32 * 1024;
/// Maximum parents on a Merge event and entries in a Merge frontier.
pub const MAX_MERGE_FRONTIER_ENTRIES: usize = 512;
/// Maximum complete checkpoint or lane-state manifest.
pub const MAX_CHECKPOINT_MANIFEST_BYTES: usize = 128 * 1024;
/// Maximum complete artifact-closure manifest.
pub const MAX_ARTIFACT_CLOSURE_BYTES: usize = super::MAX_CATALOG_ARTIFACT_BYTES as usize;
/// Standard runtime closure: one runtime package plus package/schema/policy
/// artifacts for every possible actor.
pub const MAX_ARTIFACT_CLOSURE_ENTRIES: usize = super::MAX_CATALOG_ARTIFACT_REFERENCES as usize;
/// Maximum aggregate bytes reachable through one artifact closure. This is
/// independent of the encoded manifest bound and prevents a small list of
/// individually valid BlobRefs from forcing multi-gigabyte recovery work.
pub const MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES: u64 = super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES;
/// Maximum Local lane states named by one aggregate checkpoint.
/// A physical replica checkpoint may bind only that replica's Local lane.
/// Multi-node backup/export uses a separately certified aggregate bundle.
pub const MAX_CHECKPOINT_LOCAL_LANES: usize = 1;
/// Maximum input records replayed after one checkpoint.
pub const MAX_REPLAY_SUFFIX_ENTRIES: usize = 1024;
/// Maximum aggregate canonical bytes replayed after one checkpoint.
pub const MAX_REPLAY_SUFFIX_BYTES: usize = 64 * 1024 * 1024;
/// Maximum Merge events accepted in one bounded anti-entropy import.
pub const MAX_IMPORT_EVENTS: usize = 256;
/// Maximum aggregate canonical bytes in one Merge import.
pub const MAX_IMPORT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum complete ownership-index manifest.
pub const MAX_INVOCATION_INDEX_MANIFEST_BYTES: usize = 4 * 1024;
/// Maximum canonical Patricia branch/leaf node. Node persistence is reserved
/// for the next bounded index slice.
pub const MAX_INVOCATION_INDEX_NODE_BYTES: usize = 4 * 1024;
/// Maximum canonical key/value leaf stored by an ownership index.
pub const MAX_INVOCATION_OWNERSHIP_LEAF_BYTES: usize = 1024;
/// Maximum retained, pending, or otherwise live invocation identities in one
/// ownership scope. Acknowledged identities move to the separate cumulative
/// history root and therefore do not consume a live slot.
pub const MAX_INVOCATION_INDEX_LIVE_ENTRIES: u64 = 256;
/// Maximum exact-result bytes reserved by one ownership scope. Pending Merge
/// results reserve the complete record bound until finalization reveals the
/// exact encoded length.
pub const MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum complete acknowledged-history fact embedded in a history leaf.
pub const MAX_INVOCATION_HISTORY_FACT_BYTES: usize = 1024;
/// Maximum canonical acknowledged-history Patricia node.
pub const MAX_INVOCATION_HISTORY_NODE_BYTES: usize = 1024;
/// Maximum complete exact invocation-outcome record. A result may retain the
/// actor ABI's full 8-KiB reply; the remaining half is a fixed-size audit and
/// replay-authentication envelope.
pub const MAX_INVOCATION_OUTCOME_BYTES: usize = 16 * 1024;
/// Maximum standalone content reference to an invocation outcome.
pub const MAX_INVOCATION_OUTCOME_REF_BYTES: usize = 128;
/// Maximum complete authority receipt nested in a replay operation.
const MAX_AUTHORITY_RECEIPT_BYTES: usize = 4 * 1024;
/// Four-byte magic plus the canonical 32-byte platform identifier.
const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;

macro_rules! journal_id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl JournalObjectId for $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "("))?;
                for byte in &self.0[..4] {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str("…)")
            }
        }
    };
}

/// Fixed-width identity accepted by the typed journal store.
pub trait JournalObjectId:
    Copy + Eq + Ord + core::hash::Hash + fmt::Debug + Send + Sync + 'static
{
    fn from_bytes(bytes: [u8; 32]) -> Self;
    fn as_bytes(&self) -> &[u8; 32];
}

journal_id_type!(ReplayInputId, "ReplayInputId");
journal_id_type!(AgentJournalGenesisId, "AgentJournalGenesisId");
journal_id_type!(OrderedEntryId, "OrderedEntryId");
journal_id_type!(LocalEntryId, "LocalEntryId");
journal_id_type!(MergeEventId, "MergeEventId");
journal_id_type!(MergeFrontierId, "MergeFrontierId");
journal_id_type!(MergeSealId, "MergeSealId");
journal_id_type!(LaneStateId, "LaneStateId");
journal_id_type!(ArtifactClosureId, "ArtifactClosureId");
journal_id_type!(InvocationIndexNodeId, "InvocationIndexNodeId");
journal_id_type!(InvocationIndexId, "InvocationIndexId");
journal_id_type!(InvocationHistoryNodeId, "InvocationHistoryNodeId");
journal_id_type!(InvocationOutcomeId, "InvocationOutcomeId");
journal_id_type!(TransitionProofEntryId, "TransitionProofEntryId");
journal_id_type!(TransitionProofIndexId, "TransitionProofIndexId");
journal_id_type!(CheckpointId, "CheckpointId");
journal_id_type!(JournalHeadsId, "JournalHeadsId");

/// Stable storage namespace for a canonical journal object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum JournalStorageClass {
    ReplayInput = 0,
    Genesis = 1,
    OrderedEntry = 2,
    LocalEntry = 3,
    MergeEvent = 4,
    MergeFrontier = 5,
    MergeSeal = 6,
    LaneState = 7,
    ArtifactClosure = 8,
    InvocationIndex = 9,
    /// Reserved for authenticated Patricia branch/leaf nodes. Manifests and
    /// nodes deliberately use distinct storage namespaces.
    InvocationIndexNode = 10,
    Checkpoint = 11,
    Heads = 12,
    /// Exact deterministic invocation reply/error retained independently of
    /// the opaque runtime image and authenticated ownership index.
    InvocationOutcome = 13,
    /// Permanent insert-only acknowledged-history Patricia nodes. These use
    /// a distinct namespace from mutable live-owner tree generations.
    InvocationHistoryNode = 14,
    /// One exact replay-position-bound public transition proof tuple.
    TransitionProof = 15,
    /// Bounded authenticated map from transition proof keys to proof tuples.
    TransitionProofIndex = 16,
}

pub(super) mod sealed {
    pub trait Sealed {}
}

/// A self-validating, content-identified journal object.
///
/// Storage implementations must call [`Self::validate`] before encoding and
/// must recompute [`Self::id`] after decoding. The sealed implementations keep
/// storage classes and identity domains consensus-stable.
pub trait CanonicalJournalRecord: ServiceWire + sealed::Sealed {
    type Id: JournalObjectId;

    const STORAGE_CLASS: JournalStorageClass;

    fn validate(&self) -> Result<(), DecodeError>;
    fn id(&self) -> Self::Id;
}

/// Runtime identity which must be used to replay one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBinding {
    pub space: SpaceId,
    pub agent: AgentId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub producer: ProducerId,
    pub package: BlobRef,
    pub runtime_abi: Hash,
    pub execution_semantics: Hash,
}

impl RuntimeBinding {
    pub fn validate(&self) -> Result<(), DecodeError> {
        let supported = self.runtime_abi == super::RUNTIME_ABI_ID
            && self.execution_semantics == super::EXECUTION_SEMANTICS_ID;
        #[cfg(feature = "experimental-state-blocks")]
        let supported = supported || self.is_external_state();
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.producer == ProducerId::ZERO
            || !valid_blob_ref(&self.package, false, MAX_ARTIFACT_CLOSURE_BYTES as u64)
            || !supported
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn is_external_state(&self) -> bool {
        self.runtime_abi.0 == crate::agent_sdk::state_execution::STATE_EXECUTION_ABI_ID.0
            && self.execution_semantics.0
                == crate::agent_sdk::state_execution::STATE_EXECUTION_SEMANTICS_ID.0
    }

    /// Canonical authority-facing commitment to this exact replay runtime.
    /// System-genesis intent combines this value with the commitment of the
    /// unauthenticated inner `Create` request, never its evidence-bearing
    /// `Authorized` wrapper.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_runtime_binding(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/agent/runtime-binding/v1", &[&bytes])
    }
}

/// Canonical commitment to the complete post-Create runtime image. Length
/// prefixes preserve lane boundaries and lane order is protocol-fixed.
pub fn system_genesis_post_create_state_commitment(
    state: &RuntimeState,
) -> Result<Hash, DecodeError> {
    if state
        .encoded_len()
        .is_none_or(|bytes| bytes > MAX_RUNTIME_STATE_BYTES)
    {
        return Err(DecodeError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    let mut encoder = Encoder(&mut bytes);
    encoder.bytes(&state.control);
    encoder.bytes(&state.linear);
    encoder.bytes(&state.merge);
    encoder.bytes(&state.local);
    Ok(Hash::digest(
        b"vos/agent/system-genesis-post-create-state/v1",
        &[&bytes],
    ))
}

/// One independently persisted runtime-state component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PersistedLane {
    Control = 0,
    Linear = 1,
    Merge = 2,
    Local = 3,
}

impl PersistedLane {
    pub const fn state_lane(self) -> Option<StateLane> {
        match self {
            Self::Control => None,
            Self::Linear => Some(StateLane::Linear),
            Self::Merge => Some(StateLane::Merge),
            Self::Local => Some(StateLane::Local),
        }
    }

    const fn from_result_storage(storage: InvocationResultStorage) -> Self {
        match storage {
            InvocationResultStorage::Control => Self::Control,
            InvocationResultStorage::Lane(StateLane::Linear) => Self::Linear,
            InvocationResultStorage::Lane(StateLane::Merge) => Self::Merge,
            InvocationResultStorage::Lane(StateLane::Local) => Self::Local,
        }
    }
}

/// Exact Control/Linear snapshot visible to a non-ordered input.
///
/// `post_genesis()` names the state produced by the genesis `Create` input.
/// Every later base carries both the ordered index and its content-identified
/// head, preventing lifecycle changes under one runtime deployment from being
/// observed in a different order during replay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderedBase {
    pub index: u64,
    pub head: Option<OrderedEntryId>,
}

impl OrderedBase {
    pub const fn post_genesis() -> Self {
        Self {
            index: 0,
            head: None,
        }
    }

    pub fn validate(self) -> Result<(), DecodeError> {
        if (self.index == 0) != self.head.is_none() || self.head == Some(OrderedEntryId::ZERO) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Ordering domain which owns an invocation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvocationOwnershipScope {
    /// Control and Linear share one total ownership index.
    Ordered,
    /// Merge ownership is finalized by causal replay and lifecycle seals.
    Merge,
    /// Replica-private ownership. Equal public InvocationIds on distinct
    /// nodes are intentionally independent.
    Local(NodeId),
}

impl InvocationOwnershipScope {
    pub fn validate(self) -> Result<(), DecodeError> {
        if matches!(self, Self::Local(NodeId::ZERO)) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Scoped key used by the authenticated invocation-ownership index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvocationOwnershipKey {
    pub scope: InvocationOwnershipScope,
    pub invocation: InvocationId,
}

impl InvocationOwnershipKey {
    pub fn validate(self) -> Result<(), DecodeError> {
        self.scope.validate()?;
        if self.invocation == InvocationId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Replay disposition retained by an ownership leaf.
///
/// Discriminants intentionally match `replay::ReplayDisposition`; conversion
/// remains in the replay layer so the foundational codec has no dependency on
/// the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InvocationDisposition {
    Applied = 0,
    Rejected = 1,
    Forbidden = 2,
    Panicked = 3,
    OutOfGas = 4,
}

/// Durable exact-result lifecycle for one invocation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationResultState {
    /// A Merge invocation owns its identity at the signed source event, but
    /// its exact result is not public until an ordered seal finalizes it.
    PendingMerge { source_event: MergeEventId },
    /// Exact result is durably retrievable.
    Retained {
        disposition: InvocationDisposition,
        outcome: InvocationOutcomeRef,
    },
    /// Acknowledgement itself is Merge work and remains unfinalized until an
    /// ordered seal includes this exact acknowledgement event.
    PendingMergeAcknowledgement {
        acknowledgement_event: MergeEventId,
        disposition: InvocationDisposition,
        outcome: InvocationOutcomeRef,
    },
}

impl InvocationResultState {
    pub const fn disposition(self) -> Option<InvocationDisposition> {
        match self {
            Self::PendingMerge { .. } => None,
            Self::Retained { disposition, .. }
            | Self::PendingMergeAcknowledgement { disposition, .. } => Some(disposition),
        }
    }

    pub const fn outcome(self) -> Option<InvocationOutcomeRef> {
        match self {
            Self::Retained { outcome, .. } | Self::PendingMergeAcknowledgement { outcome, .. } => {
                Some(outcome)
            }
            Self::PendingMerge { .. } => None,
        }
    }

    pub const fn is_unfinalized(self) -> bool {
        matches!(
            self,
            Self::PendingMerge { .. } | Self::PendingMergeAcknowledgement { .. }
        )
    }

    pub const fn outcome_records(self) -> u64 {
        if self.outcome().is_some() { 1 } else { 0 }
    }

    pub const fn reserved_outcome_bytes(self) -> u64 {
        match self {
            Self::PendingMerge { .. } => MAX_INVOCATION_OUTCOME_BYTES as u64,
            Self::Retained { outcome, .. } | Self::PendingMergeAcknowledgement { outcome, .. } => {
                outcome.encoded_bytes as u64
            }
        }
    }
}

/// Authenticated owner of one scoped InvocationId.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationOwner {
    pub scope: InvocationOwnershipScope,
    pub request_commitment: Hash,
    /// Audit identity of the first winning input. Idempotency compares the
    /// request commitment, not this content ID.
    pub first_input: ReplayInputId,
    pub lane: PersistedLane,
    /// Present exactly when `lane` and `scope` are Local, and equal to the
    /// scope's exact node.
    pub node: Option<NodeId>,
    pub result_state: InvocationResultState,
}

impl InvocationOwner {
    pub const fn disposition(self) -> Option<InvocationDisposition> {
        self.result_state.disposition()
    }

    pub const fn outcome(self) -> Option<InvocationOutcomeRef> {
        self.result_state.outcome()
    }

    pub const fn is_unfinalized(self) -> bool {
        self.result_state.is_unfinalized()
    }

    pub const fn outcome_records(self) -> u64 {
        self.result_state.outcome_records()
    }

    pub const fn reserved_outcome_bytes(self) -> u64 {
        self.result_state.reserved_outcome_bytes()
    }

    pub fn validate(self) -> Result<(), DecodeError> {
        self.scope.validate()?;
        let owner_matches_scope = match (self.scope, self.lane, self.node) {
            (
                InvocationOwnershipScope::Ordered,
                PersistedLane::Control | PersistedLane::Linear,
                None,
            ) => true,
            (InvocationOwnershipScope::Merge, PersistedLane::Merge, None) => true,
            (
                InvocationOwnershipScope::Local(scope_node),
                PersistedLane::Local,
                Some(owner_node),
            ) => scope_node == owner_node && owner_node != NodeId::ZERO,
            _ => false,
        };
        let state_matches_scope = match (self.scope, self.result_state) {
            (
                InvocationOwnershipScope::Merge,
                InvocationResultState::PendingMerge { source_event },
            ) => source_event != MergeEventId::ZERO,
            (
                InvocationOwnershipScope::Merge,
                InvocationResultState::PendingMergeAcknowledgement {
                    acknowledgement_event,
                    outcome,
                    ..
                },
            ) => acknowledgement_event != MergeEventId::ZERO && outcome.validate().is_ok(),
            (_, InvocationResultState::Retained { outcome, .. }) => outcome.validate().is_ok(),
            _ => false,
        };
        if self.request_commitment == Hash::ZERO
            || self.first_input == ReplayInputId::ZERO
            || !owner_matches_scope
            || !state_matches_scope
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Permanent authenticated fact that one exact winning invocation owner was
/// acknowledged. The acknowledgement receipt and its suffix-scoped journal
/// anchor are deliberately not retained: a fresh acknowledgement retry is
/// authenticated independently and resolves this fact by the original
/// request commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvocationHistoryFactPurpose {
    Acknowledgement,
    TransitionProofRetirement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationAcknowledgedFact {
    purpose: InvocationHistoryFactPurpose,
    genesis: AgentJournalGenesisId,
    key: InvocationOwnershipKey,
    request_commitment: Hash,
    first_input: ReplayInputId,
    lane: PersistedLane,
    node: Option<NodeId>,
    disposition: InvocationDisposition,
}

impl InvocationAcknowledgedFact {
    pub(crate) const fn is_transition_proof_retirement(&self) -> bool {
        matches!(
            self.purpose,
            InvocationHistoryFactPurpose::TransitionProofRetirement
        )
    }

    /// Canonical leaf representation used by the separate transition-proof
    /// retirement history. That history deliberately reuses the bounded,
    /// crash-safe Patricia machinery, but never shares a root with invocation
    /// acknowledgement history. The logical invocation is the tree key, so one
    /// permanent leaf makes every execution of that invocation terminal. The
    /// exact final execution is duplicated in both committed payload fields so
    /// decoding the leaf back to the acknowledged proof key is unambiguous.
    pub(crate) fn for_transition_proof_retirement(
        genesis: AgentJournalGenesisId,
        key: crate::agent_sdk::proof::TransitionProofKey,
    ) -> Result<Self, DecodeError> {
        if !key.validate() {
            return Err(DecodeError::NonCanonical);
        }
        let invocation = InvocationId(*key.invocation.as_bytes());
        let execution = *key.execution.as_bytes();
        let fact = Self {
            purpose: InvocationHistoryFactPurpose::TransitionProofRetirement,
            genesis,
            key: InvocationOwnershipKey {
                scope: InvocationOwnershipScope::Ordered,
                invocation,
            },
            request_commitment: Hash(execution),
            first_input: ReplayInputId(execution),
            lane: PersistedLane::Control,
            node: None,
            disposition: InvocationDisposition::Applied,
        };
        fact.validate_inner()?;
        Ok(fact)
    }

    /// Recover an exact key only from the dedicated retirement-history leaf
    /// shape. Ordinary acknowledgement facts cannot be mistaken for proof
    /// retirement evidence by merely sharing an InvocationId.
    pub(crate) fn transition_proof_retirement_key(
        self,
    ) -> Option<crate::agent_sdk::proof::TransitionProofKey> {
        if self.purpose != InvocationHistoryFactPurpose::TransitionProofRetirement
            || self.key.scope != InvocationOwnershipScope::Ordered
            || self.lane != PersistedLane::Control
            || self.node.is_some()
            || self.disposition != InvocationDisposition::Applied
            || self.request_commitment.0 != self.first_input.0
        {
            return None;
        }
        let key = crate::agent_sdk::proof::TransitionProofKey {
            invocation: crate::agent_sdk::InvocationId(self.key.invocation.0),
            execution: crate::agent_sdk::Hash(self.first_input.0),
        };
        key.validate().then_some(key)
    }

    /// Derive the only canonical permanent fact from an authenticated live
    /// owner. Pending source invocations cannot be acknowledged; a Merge
    /// acknowledgement becomes archivable only after it owns an exact result.
    pub fn from_owner(
        genesis: AgentJournalGenesisId,
        key: InvocationOwnershipKey,
        owner: InvocationOwner,
    ) -> Result<Self, DecodeError> {
        owner.validate()?;
        let disposition = match (owner.scope, owner.result_state) {
            (
                InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_),
                InvocationResultState::Retained { disposition, .. },
            )
            | (
                InvocationOwnershipScope::Merge,
                InvocationResultState::PendingMergeAcknowledgement { disposition, .. },
            ) => disposition,
            _ => {
                return Err(DecodeError::NonCanonical);
            }
        };
        let fact = Self {
            purpose: InvocationHistoryFactPurpose::Acknowledgement,
            genesis,
            key,
            request_commitment: owner.request_commitment,
            first_input: owner.first_input,
            lane: owner.lane,
            node: owner.node,
            disposition,
        };
        fact.validate_inner()?;
        Ok(fact)
    }

    pub const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn key(&self) -> InvocationOwnershipKey {
        self.key
    }

    pub const fn request_commitment(&self) -> Hash {
        self.request_commitment
    }

    pub const fn first_input(&self) -> ReplayInputId {
        self.first_input
    }

    pub const fn lane(&self) -> PersistedLane {
        self.lane
    }

    pub const fn node(&self) -> Option<NodeId> {
        self.node
    }

    pub const fn disposition(&self) -> InvocationDisposition {
        self.disposition
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_INVOCATION_HISTORY_FACT_BYTES)
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.key.validate()?;
        if self.purpose == InvocationHistoryFactPurpose::TransitionProofRetirement {
            return self
                .transition_proof_retirement_key()
                .filter(|key| key.validate())
                .map(|_| ())
                .ok_or(DecodeError::NonCanonical)
                .and_then(|()| {
                    (self.genesis != AgentJournalGenesisId::ZERO)
                        .then_some(())
                        .ok_or(DecodeError::NonCanonical)
                });
        }
        let owner_matches_scope = match (self.key.scope, self.lane, self.node) {
            (
                InvocationOwnershipScope::Ordered,
                PersistedLane::Control | PersistedLane::Linear,
                None,
            ) => true,
            (InvocationOwnershipScope::Merge, PersistedLane::Merge, None) => true,
            (
                InvocationOwnershipScope::Local(scope_node),
                PersistedLane::Local,
                Some(owner_node),
            ) => scope_node == owner_node && owner_node != NodeId::ZERO,
            _ => false,
        };
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.request_commitment == Hash::ZERO
            || self.first_input == ReplayInputId::ZERO
            || !owner_matches_scope
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for InvocationAcknowledgedFact {
    const MAGIC: [u8; 4] = *b"AHF4";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u8(match self.purpose {
            InvocationHistoryFactPurpose::Acknowledgement => 0,
            InvocationHistoryFactPurpose::TransitionProofRetirement => 1,
        });
        encoder.fixed(&self.genesis.0);
        encode_invocation_scope(&mut encoder, self.key.scope);
        encoder.fixed(&self.key.invocation.0);
        encoder.fixed(&self.request_commitment.0);
        encoder.fixed(&self.first_input.0);
        encoder.u8(self.lane as u8);
        encoder.option(&self.node, |encoder, node| encoder.fixed(&node.0));
        encode_invocation_disposition(&mut encoder, self.disposition);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_INVOCATION_HISTORY_FACT_BYTES)?;
        let fact = Self {
            purpose: match decoder.u8()? {
                0 => InvocationHistoryFactPurpose::Acknowledgement,
                1 => InvocationHistoryFactPurpose::TransitionProofRetirement,
                _ => return Err(DecodeError::InvalidTag),
            },
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            key: InvocationOwnershipKey {
                scope: decode_invocation_scope(decoder)?,
                invocation: InvocationId(decoder.fixed()?),
            },
            request_commitment: Hash(decoder.fixed()?),
            first_input: ReplayInputId(decoder.fixed()?),
            lane: decode_persisted_lane(decoder.u8()?)?,
            node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
            disposition: decode_invocation_disposition(decoder)?,
        };
        fact.validate()?;
        Ok(fact)
    }
}

/// Domain-separated content commitment to one opaque runtime-state
/// component visible at an invocation boundary. The length is consensus
/// data, rather than metadata supplied by storage, so truncation and
/// zero-extension cannot share a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VisibleStateComponentCommitment {
    pub hash: Hash,
    pub len: u64,
}

impl VisibleStateComponentCommitment {
    pub fn of_bytes(component: PersistedLane, bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let len = bytes.len() as u64;
        let component_tag = [component as u8];
        let commitment = Self {
            hash: Hash::digest(
                b"vos/agent/journal/visible-state-component/v1",
                &[&component_tag, &len.to_le_bytes(), bytes],
            ),
            len,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn matches_bytes(self, component: PersistedLane, bytes: &[u8]) -> bool {
        Self::of_bytes(component, bytes).is_ok_and(|expected| expected == self)
    }

    fn validate(self) -> Result<(), DecodeError> {
        if self.hash == Hash::ZERO || self.len > MAX_RUNTIME_STATE_BYTES as u64 {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Exact opaque state components visible to one invocation scope.
///
/// Control is always committed because it authenticates the actor directory,
/// install incarnation, and result authority state. Ordered work additionally
/// observes Linear and a pinned Merge snapshot, Merge work observes only its
/// ordered Control base plus Merge, and Local work observes all four
/// components. An omitted component is therefore meaningful and cannot be
/// substituted for a commitment to empty bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleStateCommitment {
    pub control: VisibleStateComponentCommitment,
    pub linear: Option<VisibleStateComponentCommitment>,
    pub merge: Option<VisibleStateComponentCommitment>,
    pub local: Option<VisibleStateComponentCommitment>,
}

impl VisibleStateCommitment {
    pub fn from_runtime_state(
        scope: InvocationOwnershipScope,
        state: &RuntimeState,
    ) -> Result<Self, DecodeError> {
        scope.validate()?;
        if state
            .encoded_len()
            .is_none_or(|bytes| bytes > MAX_RUNTIME_STATE_BYTES)
        {
            return Err(DecodeError::LimitExceeded);
        }
        let control =
            VisibleStateComponentCommitment::of_bytes(PersistedLane::Control, &state.control)?;
        let linear = matches!(
            scope,
            InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_)
        )
        .then(|| VisibleStateComponentCommitment::of_bytes(PersistedLane::Linear, &state.linear))
        .transpose()?;
        let merge = Some(VisibleStateComponentCommitment::of_bytes(
            PersistedLane::Merge,
            &state.merge,
        )?);
        let local = matches!(scope, InvocationOwnershipScope::Local(_))
            .then(|| VisibleStateComponentCommitment::of_bytes(PersistedLane::Local, &state.local))
            .transpose()?;
        let commitment = Self {
            control,
            linear,
            merge,
            local,
        };
        commitment.validate(scope)?;
        Ok(commitment)
    }

    pub fn validate(self, scope: InvocationOwnershipScope) -> Result<(), DecodeError> {
        scope.validate()?;
        self.control.validate()?;
        for component in [self.linear, self.merge, self.local].into_iter().flatten() {
            component.validate()?;
        }
        let exact_components = match scope {
            InvocationOwnershipScope::Ordered => {
                self.linear.is_some() && self.merge.is_some() && self.local.is_none()
            }
            InvocationOwnershipScope::Merge => {
                self.linear.is_none() && self.merge.is_some() && self.local.is_none()
            }
            InvocationOwnershipScope::Local(_) => {
                self.linear.is_some() && self.merge.is_some() && self.local.is_some()
            }
        };
        let aggregate = [Some(self.control), self.linear, self.merge, self.local]
            .into_iter()
            .flatten()
            .try_fold(0u64, |total, component| total.checked_add(component.len));
        if !exact_components || aggregate.is_none_or(|bytes| bytes > MAX_RUNTIME_STATE_BYTES as u64)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Compact duplicate of the request fields needed to validate an exact
/// execution reply without resolving the historical input first. All other
/// execution-significant fields remain bound by `request_commitment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationOutcomeRequestFacts {
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub gas_limit: u64,
}

impl InvocationOutcomeRequestFacts {
    pub fn from_invocation(invocation: &ActorInvocation) -> Result<Self, DecodeError> {
        invocation
            .validate()
            .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            program: invocation.program,
            mode: invocation.mode,
            gas_limit: invocation.gas,
        })
    }

    pub fn matches_invocation(self, invocation: &ActorInvocation) -> bool {
        invocation.validate().is_ok()
            && self.actor == invocation.actor
            && self.incarnation == invocation.incarnation
            && self.deployment == invocation.deployment
            && self.program == invocation.program
            && self.mode == invocation.mode
            && self.gas_limit == invocation.gas
    }

    fn validate(self) -> Result<(), DecodeError> {
        if self.actor == ActorId::ZERO
            || self.incarnation == Hash::ZERO
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.gas_limit == 0
            || self.gas_limit > super::execution::MAX_INVOCATION_GAS_CEILING
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

/// Exact journal publication which makes an outcome recoverable. Merge work
/// is intentionally not recoverable at its source event alone: the causal
/// result becomes public only after an ordered entry names the exact seal
/// which finalized it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationOutcomeAnchor {
    Ordered {
        entry: OrderedEntryId,
    },
    Local {
        entry: LocalEntryId,
    },
    Merge {
        source_event: MergeEventId,
        finalizing_entry: OrderedEntryId,
        seal: MergeSealId,
    },
}

impl InvocationOutcomeAnchor {
    pub fn validate(self, scope: InvocationOwnershipScope) -> Result<(), DecodeError> {
        let valid = match (scope, self) {
            (InvocationOwnershipScope::Ordered, Self::Ordered { entry }) => {
                entry != OrderedEntryId::ZERO
            }
            (InvocationOwnershipScope::Local(_), Self::Local { entry }) => {
                entry != LocalEntryId::ZERO
            }
            (
                InvocationOwnershipScope::Merge,
                Self::Merge {
                    source_event,
                    finalizing_entry,
                    seal,
                },
            ) => {
                source_event != MergeEventId::ZERO
                    && finalizing_entry != OrderedEntryId::ZERO
                    && seal != MergeSealId::ZERO
            }
            _ => false,
        };
        valid.then_some(()).ok_or(DecodeError::NonCanonical)
    }
}

/// Complete exact deterministic result owned by one scoped InvocationId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationOutcomeRecord {
    pub genesis: AgentJournalGenesisId,
    pub key: InvocationOwnershipKey,
    pub request_commitment: Hash,
    pub first_input: ReplayInputId,
    pub request: InvocationOutcomeRequestFacts,
    pub anchor: InvocationOutcomeAnchor,
    pub lane: PersistedLane,
    pub node: Option<NodeId>,
    pub before: VisibleStateCommitment,
    pub after: VisibleStateCommitment,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

impl InvocationOutcomeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        anchor: InvocationOutcomeAnchor,
        input: &ReplayInput,
        before: VisibleStateCommitment,
        after: VisibleStateCommitment,
        result: Result<ActorExecutionReply, ActorExecutionError>,
    ) -> Result<Self, DecodeError> {
        input.validate()?;
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            return Err(DecodeError::NonCanonical);
        };
        let lane = PersistedLane::from_result_storage(invocation.mode.result_storage());
        let record = Self {
            genesis,
            key: InvocationOwnershipKey {
                scope,
                invocation: invocation.invocation,
            },
            request_commitment: invocation.commitment(),
            first_input: input.id(),
            request: InvocationOutcomeRequestFacts::from_invocation(invocation)?,
            anchor,
            lane,
            node: match scope {
                InvocationOwnershipScope::Local(node) => Some(node),
                InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
            },
            before,
            after,
            result,
        };
        record.validate_for(input)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_runtime_states(
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        anchor: InvocationOutcomeAnchor,
        input: &ReplayInput,
        before: &RuntimeState,
        after: &RuntimeState,
        result: Result<ActorExecutionReply, ActorExecutionError>,
    ) -> Result<Self, DecodeError> {
        Self::new(
            genesis,
            scope,
            anchor,
            input,
            VisibleStateCommitment::from_runtime_state(scope, before)?,
            VisibleStateCommitment::from_runtime_state(scope, after)?,
            result,
        )
    }

    /// Derive the ownership disposition from the exact runtime result. It is
    /// never encoded a second time where it could disagree with that result.
    pub const fn disposition(&self) -> InvocationDisposition {
        match &self.result {
            Ok(reply) => match reply.status {
                ActorExecutionStatus::Done => InvocationDisposition::Applied,
                ActorExecutionStatus::Forbidden => InvocationDisposition::Forbidden,
                ActorExecutionStatus::Panicked => InvocationDisposition::Panicked,
                ActorExecutionStatus::OutOfGas => InvocationDisposition::OutOfGas,
                // Yield is an intermediate runtime transition, never a
                // terminal invocation outcome retained by this legacy
                // journal record.
                ActorExecutionStatus::Yielded => InvocationDisposition::Rejected,
            },
            Err(_) => InvocationDisposition::Rejected,
        }
    }

    /// Rebind the self-contained outcome to its exact canonical first input.
    /// Storage/replay callers must use this after resolving `first_input`.
    pub fn validate_for(&self, input: &ReplayInput) -> Result<(), DecodeError> {
        self.validate_inner()?;
        input.validate()?;
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            return Err(DecodeError::NonCanonical);
        };
        if input.id() != self.first_input
            || invocation.invocation != self.key.invocation
            || invocation.commitment() != self.request_commitment
            || !self.request.matches_invocation(invocation)
            || input.persisted_lane() != self.lane
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Validate both the exact journal namespace and first input. This is the
    /// boundary used by stores and ownership indexes, where accepting a valid
    /// outcome transplanted from another agent would be a security failure.
    pub fn validate_for_genesis(
        &self,
        expected_genesis: AgentJournalGenesisId,
        input: &ReplayInput,
    ) -> Result<(), DecodeError> {
        if expected_genesis == AgentJournalGenesisId::ZERO || self.genesis != expected_genesis {
            return Err(DecodeError::NonCanonical);
        }
        self.validate_for(input)
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.key.validate()?;
        self.request.validate()?;
        self.anchor.validate(self.key.scope)?;
        self.before.validate(self.key.scope)?;
        self.after.validate(self.key.scope)?;
        let expected_lane = PersistedLane::from_result_storage(self.request.mode.result_storage());
        let scope_matches_mode = matches!(
            (self.key.scope, self.request.mode),
            (
                InvocationOwnershipScope::Ordered,
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::Linear
            ) | (InvocationOwnershipScope::Merge, MethodMode::Merge)
                | (
                    InvocationOwnershipScope::Local(_),
                    MethodMode::LocalQuery | MethodMode::Local
                )
        );
        let node_matches_scope = match (self.key.scope, self.node) {
            (InvocationOwnershipScope::Local(scope_node), Some(node)) => scope_node == node,
            (InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge, None) => true,
            _ => false,
        };
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.request_commitment == Hash::ZERO
            || self.first_input == ReplayInputId::ZERO
            || self.lane != expected_lane
            || !scope_matches_mode
            || !node_matches_scope
            || self.result == Err(ActorExecutionError::DivergentInvocation)
            || matches!(
                &self.result,
                Ok(reply) if reply.status == ActorExecutionStatus::Yielded
            )
        {
            return Err(DecodeError::NonCanonical);
        }

        if let Ok(reply) = &self.result {
            super::wire::validate_execution_reply(reply)?;
            if reply.invocation != self.key.invocation
                || reply.actor != self.request.actor
                || reply.incarnation != self.request.incarnation
                || reply.deployment != self.request.deployment
                || reply.mode != self.request.mode
                || reply.gas_remaining > self.request.gas_limit
                || (reply.status != ActorExecutionStatus::Done
                    && reply.observation != super::execution::ActorObservation::default())
                || reply.reply.len() > MAX_EXECUTION_REPLY_BYTES
            {
                return Err(DecodeError::NonCanonical);
            }
        }

        // Every authenticated execution attempt may advance the authority-slot
        // high-water in its owning result component, including rejected and
        // non-Done results. Replay validates that narrower semantic delta;
        // this self-contained protocol record prevents any other visible
        // component from changing.
        let non_owner_unchanged = match self.lane {
            PersistedLane::Control => {
                self.before.linear == self.after.linear
                    && self.before.merge == self.after.merge
                    && self.before.local == self.after.local
            }
            PersistedLane::Linear => {
                self.before.control == self.after.control
                    && self.before.merge == self.after.merge
                    && self.before.local == self.after.local
            }
            PersistedLane::Merge => {
                self.before.control == self.after.control
                    && self.before.linear == self.after.linear
                    && self.before.local == self.after.local
            }
            PersistedLane::Local => {
                self.before.control == self.after.control
                    && self.before.linear == self.after.linear
                    && self.before.merge == self.after.merge
            }
        };
        if !non_owner_unchanged {
            return Err(DecodeError::NonCanonical);
        }
        validate_encoded_bound(self, MAX_INVOCATION_OUTCOME_BYTES)
    }
}

impl ServiceWire for InvocationOutcomeRecord {
    const MAGIC: [u8; 4] = *b"AGJU";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encode_invocation_scope(&mut encoder, self.key.scope);
        encoder.fixed(&self.key.invocation.0);
        encoder.fixed(&self.request_commitment.0);
        encoder.fixed(&self.first_input.0);
        encode_invocation_outcome_request(&mut encoder, self.request);
        encode_invocation_outcome_anchor(&mut encoder, self.anchor);
        encoder.u8(self.lane as u8);
        encoder.option(&self.node, |encoder, node| encoder.fixed(&node.0));
        encode_visible_state_commitment(&mut encoder, self.before);
        encode_visible_state_commitment(&mut encoder, self.after);
        super::wire::encode_execution_result(&mut encoder, &self.result);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_INVOCATION_OUTCOME_BYTES)?;
        let record = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            key: InvocationOwnershipKey {
                scope: decode_invocation_scope(decoder)?,
                invocation: InvocationId(decoder.fixed()?),
            },
            request_commitment: Hash(decoder.fixed()?),
            first_input: ReplayInputId(decoder.fixed()?),
            request: decode_invocation_outcome_request(decoder)?,
            anchor: decode_invocation_outcome_anchor(decoder)?,
            lane: decode_persisted_lane(decoder.u8()?)?,
            node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
            before: decode_visible_state_commitment(decoder)?,
            after: decode_visible_state_commitment(decoder)?,
            result: super::wire::decode_execution_result(decoder)?,
        };
        record.validate_inner()?;
        Ok(record)
    }
}

impl sealed::Sealed for InvocationOutcomeRecord {}

impl CanonicalJournalRecord for InvocationOutcomeRecord {
    type Id = InvocationOutcomeId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::InvocationOutcome;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()
    }

    fn id(&self) -> Self::Id {
        InvocationOutcomeId(content_id(b"vos/agent/journal/invocation-outcome/v1", self))
    }
}

/// Bounded reference embedded by an authenticated invocation-owner leaf.
/// `encoded_bytes` supports deterministic per-scope byte quotas without
/// loading every retained outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationOutcomeRef {
    pub outcome: InvocationOutcomeId,
    pub encoded_bytes: u32,
}

impl InvocationOutcomeRef {
    pub fn for_record(record: &InvocationOutcomeRecord) -> Result<Self, DecodeError> {
        record.validate()?;
        let encoded_bytes =
            u32::try_from(record.encode().len()).map_err(|_| DecodeError::LimitExceeded)?;
        let reference = Self {
            outcome: record.id(),
            encoded_bytes,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(self) -> Result<(), DecodeError> {
        if self.outcome == InvocationOutcomeId::ZERO
            || self.encoded_bytes as usize <= SERVICE_WIRE_HEADER_BYTES
            || self.encoded_bytes as usize > MAX_INVOCATION_OUTCOME_BYTES
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub fn authenticates(self, record: &InvocationOutcomeRecord) -> bool {
        record.validate().is_ok()
            && self.outcome == record.id()
            && self.encoded_bytes as usize == record.encode().len()
    }
}

impl ServiceWire for InvocationOutcomeRef {
    const MAGIC: [u8; 4] = *b"AGJR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.outcome.0);
        encoder.u32(self.encoded_bytes);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_INVOCATION_OUTCOME_REF_BYTES)?;
        let reference = Self {
            outcome: InvocationOutcomeId(decoder.fixed()?),
            encoded_bytes: decoder.u32()?,
        };
        reference.validate()?;
        Ok(reference)
    }
}

/// Compatibility name used by the replay ownership trait.
pub type InvocationOwnershipValue = InvocationOwner;

/// One Patricia-tree leaf. Manifests retain only the authenticated root and
/// counts; they never flatten all ownership entries into a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationOwnershipLeaf {
    /// Agent journal whose ownership tree contains this leaf. Including the
    /// genesis in every node hash prevents transplanting a valid root between
    /// otherwise shape-compatible agents.
    pub genesis: AgentJournalGenesisId,
    pub key: InvocationOwnershipKey,
    pub owner: InvocationOwner,
}

impl InvocationOwnershipLeaf {
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.genesis == AgentJournalGenesisId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        self.key.validate()?;
        self.owner.validate()?;
        if self.key.scope != self.owner.scope {
            return Err(DecodeError::NonCanonical);
        }
        validate_encoded_bound(self, MAX_INVOCATION_OWNERSHIP_LEAF_BYTES)
    }

    /// Canonical authenticated leaf hash used by the future Patricia index.
    pub fn hash(&self) -> Hash {
        Hash::digest(
            b"vos/agent/journal/invocation-ownership-leaf",
            &[&self.encode()],
        )
    }
}

impl ServiceWire for InvocationOwnershipLeaf {
    const MAGIC: [u8; 4] = *b"AGIL";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encode_invocation_scope(&mut encoder, self.key.scope);
        encoder.fixed(&self.key.invocation.0);
        encode_invocation_owner(&mut encoder, self.owner);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_INVOCATION_OWNERSHIP_LEAF_BYTES)?;
        let leaf = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            key: InvocationOwnershipKey {
                scope: decode_invocation_scope(decoder)?,
                invocation: InvocationId(decoder.fixed()?),
            },
            owner: decode_invocation_owner(decoder)?,
        };
        leaf.validate()?;
        Ok(leaf)
    }
}

/// Authenticated root and cardinality of one scoped invocation index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationIndexManifest {
    pub genesis: AgentJournalGenesisId,
    pub scope: InvocationOwnershipScope,
    /// Root Patricia node. Empty indexes are represented only as `None`;
    /// their scoped manifest IDs remain nonzero and independently stored.
    /// Resolution must reject any reachable node or leaf whose embedded
    /// genesis/scope differs from this manifest.
    pub root: Option<InvocationIndexNodeId>,
    /// Total live leaves. Acknowledged identities are committed by
    /// `history_root` and do not consume this bounded working set.
    pub entries: u64,
    /// Pending source events plus pending Merge acknowledgements.
    pub unfinalized: u64,
    /// Leaves which retain an exact outcome reference.
    pub outcome_records: u64,
    /// Aggregate exact or conservatively reserved outcome bytes.
    pub reserved_outcome_bytes: u64,
    /// Root of the cumulative insert-only acknowledged invocation history.
    /// It remains present when the live tree is empty.
    pub history_root: Option<InvocationHistoryNodeId>,
}

impl InvocationIndexManifest {
    pub const fn empty(genesis: AgentJournalGenesisId, scope: InvocationOwnershipScope) -> Self {
        Self {
            genesis,
            scope,
            root: None,
            entries: 0,
            unfinalized: 0,
            outcome_records: 0,
            reserved_outcome_bytes: 0,
            history_root: None,
        }
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.scope.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.root == Some(InvocationIndexNodeId::ZERO)
            || self.history_root == Some(InvocationHistoryNodeId::ZERO)
            || (self.entries == 0) != self.root.is_none()
            || self.entries > MAX_INVOCATION_INDEX_LIVE_ENTRIES
            || self.unfinalized > self.entries
            || self.outcome_records > self.entries
            || ((self.reserved_outcome_bytes == 0) != (self.entries == 0))
            || self.reserved_outcome_bytes > MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES
            || (self.entries == 0
                && (self.unfinalized != 0
                    || self.outcome_records != 0
                    || self.reserved_outcome_bytes != 0))
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for InvocationIndexManifest {
    const MAGIC: [u8; 4] = *b"AJX2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encode_invocation_scope(&mut encoder, self.scope);
        encoder.option(&self.root, |encoder, root| encoder.fixed(&root.0));
        encoder.u64(self.entries);
        encoder.u64(self.unfinalized);
        encoder.u64(self.outcome_records);
        encoder.u64(self.reserved_outcome_bytes);
        encoder.option(&self.history_root, |encoder, root| encoder.fixed(&root.0));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_INVOCATION_INDEX_MANIFEST_BYTES)?;
        let manifest = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            scope: decode_invocation_scope(decoder)?,
            root: decoder.option(|decoder| Ok(InvocationIndexNodeId(decoder.fixed()?)))?,
            entries: decoder.u64()?,
            unfinalized: decoder.u64()?,
            outcome_records: decoder.u64()?,
            reserved_outcome_bytes: decoder.u64()?,
            history_root: decoder
                .option(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))?,
        };
        manifest.validate_inner()?;
        Ok(manifest)
    }
}

impl sealed::Sealed for InvocationIndexManifest {}

impl CanonicalJournalRecord for InvocationIndexManifest {
    type Id = InvocationIndexId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::InvocationIndex;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_INVOCATION_INDEX_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        InvocationIndexId(content_id(b"vos/agent/journal/invocation-index/v2", self))
    }
}

/// One exact guest operation retained as replay truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOperation {
    /// Authority-admitted management mutation. Read-only inspection and
    /// invocation acknowledgement are not accepted through this variant.
    Management { request: LifecycleRequest },
    /// Exact clean-generation management mutation. The SDK request and its
    /// durable authority receipt are retained without projecting either value
    /// into the transitional lifecycle protocol. Read-only inspection is not
    /// journaled through this variant.
    CleanManage {
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
    },
    /// Exact authenticated actor invocation. Executable and policy artifacts
    /// are resolved from the checkpoint/catalog closure during replay.
    Invoke {
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
        observed_slot: u64,
    },
    /// Clean-generation invocation retained without conversion to the legacy
    /// actor invocation or signed-only authority model. The SDK work and
    /// typed authorization remain distinct values even when their initial
    /// caller identity was derived from the same authenticator.
    CleanInvoke {
        context: crate::agent_sdk::RuntimeExecutionContext,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    },
    /// Resume the exact clean invocation retained in the named yielded FIFO
    /// record. The original work and authorization are retained verbatim;
    /// replay derives `ResumeWork` from guest state and never trusts a caller
    /// supplied method, artifact list, or continuation body.
    CleanResume {
        context: crate::agent_sdk::RuntimeExecutionContext,
        expected_live: Option<crate::agent_sdk::proof::TransitionProofKey>,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
        observed_slot: u64,
    },
    /// Retire the exact clean terminal result. This is deliberately distinct
    /// from the legacy signed-only acknowledgement variant.
    CleanAcknowledge {
        context: crate::agent_sdk::RuntimeExecutionContext,
        expected_live: Option<crate::agent_sdk::proof::TransitionProofKey>,
        work: crate::agent_sdk::InvocationRetirement,
        authorization: crate::agent_sdk::InvocationAuthorization,
    },
    /// Retire the exact result produced by `invocation`. Keeping the complete
    /// invocation and receipt makes its owning result lane independently
    /// derivable; a bare invocation ID is deliberately insufficient.
    Acknowledge {
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    },
    /// Ordered maintenance entry which finalizes the exact Merge frontier
    /// named by its enclosing [`OrderedEntry`]. It carries no guest request or
    /// authority receipt: the ordered/Raft admission of the entry is its sole
    /// authority, and replay requires the runtime transition itself to be a
    /// byte-exact no-op apart from finalizing authenticated Merge outcomes.
    SealMerge,
}

impl ReplayOperation {
    pub const fn persisted_lane(&self) -> PersistedLane {
        match self {
            Self::Management { .. } | Self::CleanManage { .. } | Self::SealMerge => {
                PersistedLane::Control
            }
            Self::Invoke { invocation, .. } | Self::Acknowledge { invocation, .. } => {
                PersistedLane::from_result_storage(invocation.mode.result_storage())
            }
            Self::CleanInvoke {
                work: crate::agent_sdk::InvocationWork { mode, .. },
                ..
            }
            | Self::CleanResume {
                work: crate::agent_sdk::InvocationWork { mode, .. },
                ..
            }
            | Self::CleanAcknowledge {
                work: crate::agent_sdk::InvocationRetirement { mode, .. },
                ..
            } => match mode.result_storage() {
                crate::agent_sdk::InvocationResultStorage::Control => PersistedLane::Control,
                crate::agent_sdk::InvocationResultStorage::Lane(
                    crate::agent_sdk::StateLane::Linear,
                ) => PersistedLane::Linear,
                crate::agent_sdk::InvocationResultStorage::Lane(
                    crate::agent_sdk::StateLane::Merge,
                ) => PersistedLane::Merge,
                crate::agent_sdk::InvocationResultStorage::Lane(
                    crate::agent_sdk::StateLane::Local,
                ) => PersistedLane::Local,
            },
        }
    }
}

/// Canonical replay source shared by all physical journal classes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayInput {
    pub runtime: RuntimeBinding,
    pub operation: ReplayOperation,
}

impl ReplayInput {
    pub const fn persisted_lane(&self) -> PersistedLane {
        self.operation.persisted_lane()
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        match &self.operation {
            ReplayOperation::CleanInvoke { work, .. }
            | ReplayOperation::CleanResume { work, .. } => {
                if !work.validate() {
                    return Err(DecodeError::NonCanonical);
                }
            }
            ReplayOperation::CleanAcknowledge { work, .. } => {
                if !work.validate() {
                    return Err(DecodeError::NonCanonical);
                }
            }
            _ => {}
        }
        self.validate_runtime_and_operation_bindings()
    }

    /// The caller must have validated the owned invocation work: either above
    /// for a constructed value, or in decode_replay_operation's SDK decoder.
    /// This check does not establish any validity that survives mutation.
    fn validate_runtime_and_operation_bindings(&self) -> Result<(), DecodeError> {
        self.runtime.validate()?;
        // Logical-slot freshness is execution state, not wire canonicality.
        // Both lifecycle and invocation runtimes recover an exact committed
        // request before applying the freshness check for unseen work; making
        // the window structural would make a valid retry undecodable after
        // expiry. Receipt shape and exact claim linkage remain canonical here,
        // while replay authentication verifies the signature and fresh
        // execution enforces the observed slot.
        match &self.operation {
            ReplayOperation::Management { request } => {
                validate_management_request(&self.runtime, request)?;
            }
            ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot,
            } => validate_clean_management_request(
                &self.runtime,
                request,
                authority,
                *observed_slot,
            )?,
            ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot: _,
            } => {
                validate_invocation_receipt(&self.runtime, invocation, authority)?;
            }
            ReplayOperation::CleanInvoke {
                context,
                work,
                authorization,
                observed_slot,
            } => {
                if !context.is_valid() {
                    return Err(DecodeError::NonCanonical);
                }
                validate_clean_invocation_authorization_binding(
                    &self.runtime,
                    work,
                    authorization,
                    *observed_slot,
                )?;
            }
            ReplayOperation::CleanResume {
                context,
                expected_live,
                work,
                authorization,
                yielded,
                observed_slot,
            } => {
                if !context.is_valid() {
                    return Err(DecodeError::NonCanonical);
                }
                validate_transition_proof_lifecycle_condition(
                    *context,
                    *expected_live,
                    work.invocation,
                )?;
                validate_clean_invocation_authorization_binding(
                    &self.runtime,
                    work,
                    authorization,
                    *observed_slot,
                )?;
                if !yielded.validate()
                    || yielded.invocation != work.invocation
                    || yielded.actor != work.actor
                    || yielded.incarnation != work.incarnation
                    || yielded.deployment != work.deployment
                    || yielded.program != work.program
                    || yielded.mode != work.mode
                    || yielded.installation_data != work.installation_data
                    || yielded.required
                        != work
                            .availability
                            .iter()
                            .map(|blob| blob.reference.clone())
                            .collect::<Vec<_>>()
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
            ReplayOperation::CleanAcknowledge {
                context,
                expected_live,
                work,
                authorization,
            } => {
                validate_transition_proof_lifecycle_condition(
                    *context,
                    *expected_live,
                    work.invocation,
                )?;
                validate_clean_exact_request_binding(&self.runtime, work, authorization)?;
            }
            ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => validate_invocation_receipt(&self.runtime, invocation, authority)?,
            ReplayOperation::SealMerge => {}
        }
        Ok(())
    }
}

impl ServiceWire for ReplayInput {
    const MAGIC: [u8; 4] = *b"AJI4";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_runtime_binding(&mut encoder, &self.runtime);
        encode_replay_operation(&mut encoder, &self.operation);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_REPLAY_INPUT_BYTES)?;
        let input = Self {
            runtime: decode_runtime_binding(decoder)?,
            operation: decode_replay_operation(decoder)?,
        };
        // Each clean invocation variant came from decode_canonical_runtime_work,
        // which authenticated its blob preimages. Nothing has mutated the owned
        // work since then; still verify every enclosing runtime/operation binding.
        input.validate_runtime_and_operation_bindings()?;
        Ok(input)
    }
}

impl sealed::Sealed for ReplayInput {}

impl CanonicalJournalRecord for ReplayInput {
    type Id = ReplayInputId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::ReplayInput;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        // `self` stays immutably borrowed: the size pass can reuse the exact
        // Invoke validation above, but ordinary public encoding cannot.
        let mut body = Vec::new();
        let mut encoder = Encoder(&mut body);
        encode_runtime_binding(&mut encoder, &self.runtime);
        encode_replay_operation_inner(&mut encoder, &self.operation, true);
        body.len()
            .checked_add(SERVICE_WIRE_HEADER_BYTES)
            .filter(|length| *length <= MAX_REPLAY_INPUT_BYTES)
            .map(|_| ())
            .ok_or(DecodeError::LimitExceeded)
    }

    fn id(&self) -> Self::Id {
        ReplayInputId(content_id(b"vos/agent/journal/replay-input/v3", self))
    }
}

/// Immutable root of one clean-generation agent journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentJournalGenesis {
    /// Content ID of the tagged Agent-genesis admission record. For the first
    /// system Agent this names an `AGNA/v2` `RootBootstrap` wrapper around the
    /// independently root-verified system admission. This is part of the
    /// final genesis ID but deliberately not part of the upstream signed
    /// genesis intent.
    pub admission: AgentGenesisAdmissionId,
    /// The first input is always an authority-admitted `Create` mutation.
    pub create: ReplayInput,
}

impl AgentJournalGenesis {
    pub fn runtime(&self) -> &RuntimeBinding {
        &self.create.runtime
    }

    /// Recompute the cycle-free intent certified by the system authority.
    pub fn genesis_intent(&self) -> Result<GenesisIntentId, DecodeError> {
        Self::create_intent(&self.create)
    }

    /// Cycle-free Create intent, available before the post-state-dependent
    /// genesis admission record exists. Caller still authenticates the input.
    pub(crate) fn create_intent(create: &ReplayInput) -> Result<GenesisIntentId, DecodeError> {
        let request = match &create.operation {
            ReplayOperation::Management { request } => {
                let LifecycleRequest::Authorized { request, .. } = request else {
                    return Err(DecodeError::NonCanonical);
                };
                let LifecycleRequest::Create(_) = request.as_ref() else {
                    return Err(DecodeError::NonCanonical);
                };
                request.commitment()
            }
            ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(descriptor),
                ..
            } => Hash(
                crate::agent_sdk::ManagementRequest::Create(descriptor.clone())
                    .commitment()
                    .0,
            ),
            ReplayOperation::CleanManage { .. }
            | ReplayOperation::Invoke { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::Acknowledge { .. }
            | ReplayOperation::SealMerge => return Err(DecodeError::NonCanonical),
        };
        GenesisIntentId::from_commitments(create.runtime.commitment(), request)
            .map_err(|_| DecodeError::NonCanonical)
    }

    /// Authority sequence of the exact receipt which admits the inner Create.
    pub fn genesis_authority_sequence(&self) -> Result<u64, DecodeError> {
        Self::create_authority_sequence(&self.create)
    }

    pub(crate) fn create_authority_sequence(create: &ReplayInput) -> Result<u64, DecodeError> {
        let sequence = match &create.operation {
            ReplayOperation::Management { request } => {
                let LifecycleRequest::Authorized { admission, request } = request else {
                    return Err(DecodeError::NonCanonical);
                };
                let LifecycleRequest::Create(_) = request.as_ref() else {
                    return Err(DecodeError::NonCanonical);
                };
                admission.receipt.claim.sequence
            }
            ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(_),
                authority,
                ..
            } => authority.selector.decision_sequence,
            ReplayOperation::CleanManage { .. }
            | ReplayOperation::Invoke { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::Acknowledge { .. }
            | ReplayOperation::SealMerge => return Err(DecodeError::NonCanonical),
        };
        (sequence != 0)
            .then_some(sequence)
            .ok_or(DecodeError::NonCanonical)
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        if self.admission == AgentGenesisAdmissionId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        self.create.validate()?;
        let runtime = &self.create.runtime;
        match &self.create.operation {
            ReplayOperation::Management { request } => {
                let LifecycleRequest::Authorized { request, .. } = request else {
                    return Err(DecodeError::NonCanonical);
                };
                let LifecycleRequest::Create(config) = request.as_ref() else {
                    return Err(DecodeError::NonCanonical);
                };
                if config.validate().is_err()
                    || config.identity.space != runtime.space
                    || config.identity.agent != runtime.agent
                    || config.identity.runtime_deployment != runtime.deployment
                    || config.identity.runtime_program != runtime.program
                    || config.identity.runtime_producer != runtime.producer
                    || config.runtime_package != runtime.package
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
            ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(descriptor),
                ..
            } => {
                if descriptor.validate().is_err()
                    || descriptor.identity.space.0 != runtime.space.0
                    || descriptor.identity.agent.0 != runtime.agent.0
                    || descriptor.identity.runtime_deployment.0 != runtime.deployment.0
                    || descriptor.identity.runtime_program.0 != runtime.program.0
                    || descriptor.identity.runtime_producer.0 != runtime.producer.0
                    || descriptor.runtime_package.hash.0 != runtime.package.hash.0
                    || descriptor.runtime_package.len != runtime.package.len
                {
                    return Err(DecodeError::NonCanonical);
                }
            }
            ReplayOperation::CleanManage { .. }
            | ReplayOperation::Invoke { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::Acknowledge { .. }
            | ReplayOperation::SealMerge => return Err(DecodeError::NonCanonical),
        }
        self.genesis_intent()?;
        self.genesis_authority_sequence()?;
        Ok(())
    }
}

impl ServiceWire for AgentJournalGenesis {
    const MAGIC: [u8; 4] = *b"AJG2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.admission.as_bytes());
        encoder.bytes(&self.create.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_JOURNAL_RECORD_BYTES)?;
        let admission = AgentGenesisAdmissionId::from_bytes(decoder.fixed()?);
        let bytes = bounded_bytes_ref(decoder, MAX_REPLAY_INPUT_BYTES)?;
        let genesis = Self {
            admission,
            create: ReplayInput::decode(bytes)?,
        };
        genesis.validate_inner()?;
        Ok(genesis)
    }
}

impl sealed::Sealed for AgentJournalGenesis {}

impl CanonicalJournalRecord for AgentJournalGenesis {
    type Id = AgentJournalGenesisId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::Genesis;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_JOURNAL_RECORD_BYTES)
    }

    fn id(&self) -> Self::Id {
        AgentJournalGenesisId(content_id(b"vos/agent/journal/genesis/v2", self))
    }
}

/// One Control or Linear input in the shared ordered chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedEntry {
    pub genesis: AgentJournalGenesisId,
    pub index: u64,
    pub parent: Option<OrderedEntryId>,
    /// Exact Merge snapshot visible at admission. Before the first event this
    /// is the content ID of the explicit empty frontier, never an absent alias.
    pub merge_frontier: MergeFrontierId,
    /// Raft/local-ordered fence over `merge_frontier`. Every directory or
    /// runtime lifecycle mutation requires one, as does a seal-only maintenance
    /// entry; ordinary invocation and acknowledgement entries must not carry
    /// one.
    pub merge_seal: Option<MergeSealId>,
    pub input: ReplayInput,
}

impl OrderedEntry {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.input.validate()?;
        self.validate_ordering_bindings()
    }

    /// Requires a validated input, either from validate_inner or its decoder.
    fn validate_ordering_bindings(&self) -> Result<(), DecodeError> {
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.index == 0
            || (self.index == 1) != self.parent.is_none()
            || self.parent == Some(OrderedEntryId::ZERO)
            || self.merge_frontier == MergeFrontierId::ZERO
            || self.merge_seal == Some(MergeSealId::ZERO)
            || !matches!(
                self.input.persisted_lane(),
                PersistedLane::Control | PersistedLane::Linear
            )
            || is_create_operation(&self.input.operation)
            || (matches!(
                &self.input.operation,
                ReplayOperation::Management { .. }
                    | ReplayOperation::CleanManage { .. }
                    | ReplayOperation::SealMerge
            ) != self.merge_seal.is_some())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for OrderedEntry {
    const MAGIC: [u8; 4] = *b"AGJO";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.u64(self.index);
        encoder.option(&self.parent, |encoder, parent| encoder.fixed(&parent.0));
        encoder.fixed(&self.merge_frontier.0);
        encoder.option(&self.merge_seal, |encoder, seal| encoder.fixed(&seal.0));
        encoder.bytes(&self.input.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_JOURNAL_RECORD_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let index = decoder.u64()?;
        let parent = decoder.option(|decoder| Ok(OrderedEntryId(decoder.fixed()?)))?;
        let merge_frontier = MergeFrontierId(decoder.fixed()?);
        let merge_seal = decoder.option(|decoder| Ok(MergeSealId(decoder.fixed()?)))?;
        let input = ReplayInput::decode(bounded_bytes_ref(decoder, MAX_REPLAY_INPUT_BYTES)?)?;
        let entry = Self {
            genesis,
            index,
            parent,
            merge_frontier,
            merge_seal,
            input,
        };
        // ReplayInput::decode already validated this owned, unchanged input
        // and its complete wire bound. Check only the enclosing entry fields.
        entry.validate_ordering_bindings()?;
        Ok(entry)
    }
}

impl sealed::Sealed for OrderedEntry {}

impl CanonicalJournalRecord for OrderedEntry {
    type Id = OrderedEntryId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::OrderedEntry;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_JOURNAL_RECORD_BYTES)
    }

    fn id(&self) -> Self::Id {
        OrderedEntryId(content_id(b"vos/agent/journal/ordered-entry", self))
    }
}

/// One Local input in an exact replica node's private chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEntry {
    pub genesis: AgentJournalGenesisId,
    pub node: NodeId,
    pub revision: u64,
    pub parent: Option<LocalEntryId>,
    /// Lifecycle/directory and Linear snapshot visible at admission.
    pub ordered_base: OrderedBase,
    /// Exact Merge snapshot visible at admission, including the explicit empty
    /// frontier before the first event.
    pub merge_frontier: MergeFrontierId,
    pub input: ReplayInput,
}

impl LocalEntry {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.input.validate()?;
        self.ordered_base.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.node == NodeId::ZERO
            || self.revision == 0
            || (self.revision == 1) != self.parent.is_none()
            || self.parent == Some(LocalEntryId::ZERO)
            || self.merge_frontier == MergeFrontierId::ZERO
            || self.input.persisted_lane() != PersistedLane::Local
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for LocalEntry {
    const MAGIC: [u8; 4] = *b"AGJL";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(&self.node.0);
        encoder.u64(self.revision);
        encoder.option(&self.parent, |encoder, parent| encoder.fixed(&parent.0));
        encode_ordered_base(&mut encoder, self.ordered_base);
        encoder.fixed(&self.merge_frontier.0);
        encoder.bytes(&self.input.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_JOURNAL_RECORD_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let node = NodeId(decoder.fixed()?);
        let revision = decoder.u64()?;
        let parent = decoder.option(|decoder| Ok(LocalEntryId(decoder.fixed()?)))?;
        let ordered_base = decode_ordered_base(decoder)?;
        let merge_frontier = MergeFrontierId(decoder.fixed()?);
        let input = ReplayInput::decode(bounded_bytes_ref(decoder, MAX_REPLAY_INPUT_BYTES)?)?;
        let entry = Self {
            genesis,
            node,
            revision,
            parent,
            ordered_base,
            merge_frontier,
            input,
        };
        entry.validate_inner()?;
        Ok(entry)
    }
}

impl sealed::Sealed for LocalEntry {}

impl CanonicalJournalRecord for LocalEntry {
    type Id = LocalEntryId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::LocalEntry;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_JOURNAL_RECORD_BYTES)
    }

    fn id(&self) -> Self::Id {
        LocalEntryId(content_id(b"vos/agent/journal/local-entry", self))
    }
}

/// One authenticated Merge input in the causal DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeEvent {
    pub genesis: AgentJournalGenesisId,
    pub author: NodeId,
    /// Shared events bind the exact authority-certified replica committee
    /// active when the host admitted them. Local events leave this absent.
    /// The field is signed and content-addressed, so a removed replica cannot
    /// relabel a newly produced event as current after a stable transition.
    pub committee: Option<super::genesis::AgentReplicaCommitteeId>,
    /// Exact lifecycle/directory snapshot used to admit this event.
    pub ordered_base: OrderedBase,
    /// One plus the maximum verified parent height. Importers independently
    /// verify this value after resolving every parent.
    pub causal_height: u64,
    /// Strictly sorted, duplicate-free causal parents.
    pub parents: Vec<MergeEventId>,
    pub input: ReplayInput,
    /// Signature by the authority-certified key of `author` over
    /// [`Self::signing_message`]. Key resolution and cryptographic checking
    /// remain membership policy, outside this canonical codec.
    pub signature: Vec<u8>,
}

impl MergeEvent {
    pub fn signing_message(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(&self.author.0);
        encoder.option(&self.committee, |encoder, committee| {
            encoder.fixed(committee.as_bytes())
        });
        encode_ordered_base(&mut encoder, self.ordered_base);
        encoder.u64(self.causal_height);
        encoder.list(&self.parents, |encoder, parent| encoder.fixed(&parent.0));
        encoder.bytes(&self.input.encode());
        Hash::digest(b"vos/agent/journal/merge-event-signature", &[&bytes])
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.input.validate()?;
        self.ordered_base.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.author == NodeId::ZERO
            || self.committee == Some(super::genesis::AgentReplicaCommitteeId::ZERO)
            || self.causal_height == 0
            || self.parents.len() > MAX_MERGE_FRONTIER_ENTRIES
            || (self.parents.is_empty() != (self.causal_height == 1))
            || !strictly_increasing(&self.parents)
            || self.parents.contains(&MergeEventId::ZERO)
            || self.input.persisted_lane() != PersistedLane::Merge
            || self.signature.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for MergeEvent {
    const MAGIC: [u8; 4] = *b"AGJ2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(&self.author.0);
        encoder.option(&self.committee, |encoder, committee| {
            encoder.fixed(committee.as_bytes())
        });
        encode_ordered_base(&mut encoder, self.ordered_base);
        encoder.u64(self.causal_height);
        encoder.list(&self.parents, |encoder, parent| encoder.fixed(&parent.0));
        encoder.bytes(&self.input.encode());
        encoder.bytes(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_JOURNAL_RECORD_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let author = NodeId(decoder.fixed()?);
        let committee = decoder.option(|decoder| {
            Ok(super::genesis::AgentReplicaCommitteeId::from_bytes(
                decoder.fixed()?,
            ))
        })?;
        let ordered_base = decode_ordered_base(decoder)?;
        let causal_height = decoder.u64()?;
        let parents = decode_fixed_id_list::<MergeEventId>(decoder, MAX_MERGE_FRONTIER_ENTRIES)?;
        let input = ReplayInput::decode(bounded_bytes_ref(decoder, MAX_REPLAY_INPUT_BYTES)?)?;
        let signature = bounded_bytes_ref(decoder, ED25519_SIGNATURE_BYTES)?.to_vec();
        let event = Self {
            genesis,
            author,
            committee,
            ordered_base,
            causal_height,
            parents,
            input,
            signature,
        };
        event.validate_inner()?;
        Ok(event)
    }
}

impl sealed::Sealed for MergeEvent {}

impl CanonicalJournalRecord for MergeEvent {
    type Id = MergeEventId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::MergeEvent;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_JOURNAL_RECORD_BYTES)
    }

    fn id(&self) -> Self::Id {
        MergeEventId(content_id(b"vos/agent/journal/merge-event", self))
    }
}

/// Canonical, minimal Merge DAG frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeFrontier {
    pub genesis: AgentJournalGenesisId,
    /// Strictly sorted, duplicate-free maximal events. The empty frontier is
    /// canonical before the first Merge event.
    pub events: Vec<MergeEventId>,
}

impl MergeFrontier {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.events.len() > MAX_MERGE_FRONTIER_ENTRIES
            || !strictly_increasing(&self.events)
            || self.events.contains(&MergeEventId::ZERO)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for MergeFrontier {
    const MAGIC: [u8; 4] = *b"AGJF";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.list(&self.events, |encoder, event| encoder.fixed(&event.0));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CHECKPOINT_MANIFEST_BYTES)?;
        let frontier = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            events: decode_fixed_id_list::<MergeEventId>(decoder, MAX_MERGE_FRONTIER_ENTRIES)?,
        };
        frontier.validate_inner()?;
        Ok(frontier)
    }
}

impl sealed::Sealed for MergeFrontier {}

impl CanonicalJournalRecord for MergeFrontier {
    type Id = MergeFrontierId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::MergeFrontier;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_CHECKPOINT_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        MergeFrontierId(content_id(b"vos/agent/journal/merge-frontier", self))
    }
}

/// Materialized Merge state sealed at an authenticated frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeSeal {
    pub genesis: AgentJournalGenesisId,
    pub frontier: MergeFrontierId,
    /// Ordered snapshot immediately before the lifecycle fence that consumes
    /// this seal.
    pub ordered_base: OrderedBase,
    pub merge_state: LaneStateId,
}

impl MergeSeal {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.ordered_base.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.frontier == MergeFrontierId::ZERO
            || self.merge_state == LaneStateId::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for MergeSeal {
    const MAGIC: [u8; 4] = *b"AGJS";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(&self.frontier.0);
        encode_ordered_base(&mut encoder, self.ordered_base);
        encoder.fixed(&self.merge_state.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CHECKPOINT_MANIFEST_BYTES)?;
        let seal = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            frontier: MergeFrontierId(decoder.fixed()?),
            ordered_base: decode_ordered_base(decoder)?,
            merge_state: LaneStateId(decoder.fixed()?),
        };
        seal.validate_inner()?;
        Ok(seal)
    }
}

impl sealed::Sealed for MergeSeal {}

impl CanonicalJournalRecord for MergeSeal {
    type Id = MergeSealId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::MergeSeal;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_CHECKPOINT_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        MergeSealId(content_id(b"vos/agent/journal/merge-seal", self))
    }
}

/// Replay cursor which authenticated one materialized lane image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneCursor {
    Ordered {
        base: OrderedBase,
    },
    Merge {
        frontier: MergeFrontierId,
    },
    Local {
        node: NodeId,
        revision: u64,
        /// Revision zero is the explicit post-genesis Local cursor and has no
        /// journal entry. Every later revision names its exact Local head.
        head: Option<LocalEntryId>,
    },
}

/// Provenance of the descriptor's last change, independent of the newest
/// materialized journal position. Retaining a root does not rewrite guest state.
/// These are untrusted record fields until replay authenticates their lineage.
#[cfg(feature = "experimental-state-blocks")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalStateRoot {
    pub descriptor: crate::agent_sdk::state_root::StateRootDescriptor,
    pub runtime: RuntimeBinding,
    pub cursor: LaneCursor,
}

/// Content reference for one derived runtime-state lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneStateManifest {
    pub genesis: AgentJournalGenesisId,
    pub runtime: RuntimeBinding,
    pub lane: PersistedLane,
    pub cursor: LaneCursor,
    /// Canonical opaque bytes for this runtime-state component. Empty lane
    /// bytes use `BlobRef::of_bytes(&[])`, never the zero reference.
    pub state: BlobRef,
    /// Explicit public graph root, never inferred by inspecting opaque state
    /// bytes. Experimental roots are not yet admitted by production replay.
    #[cfg(feature = "experimental-state-blocks")]
    pub external_root: Option<ExternalStateRoot>,
}

impl LaneStateManifest {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.runtime.validate()?;
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(root) = &self.external_root {
            root.runtime.validate()?;
            let scope = root.descriptor.context().scope();
            if scope.space().0 != self.runtime.space.0
                || scope.agent().0 != self.runtime.agent.0
                || root.runtime.space != self.runtime.space
                || root.runtime.agent != self.runtime.agent
                || self.lane.state_lane().map(|lane| lane as u8) != Some(scope.lane() as u8)
                || self.state != BlobRef::of_bytes(&root.descriptor.encode())
            {
                return Err(DecodeError::NonCanonical);
            }
            // Cheap canonical bounds only, NOT proof of ancestor membership.
            match (&root.cursor, &self.cursor) {
                (LaneCursor::Ordered { base: origin }, LaneCursor::Ordered { base })
                    if origin.validate().is_ok()
                        && origin.index <= base.index
                        && (origin.index != base.index || origin == base) => {}
                (LaneCursor::Merge { frontier }, LaneCursor::Merge { .. })
                    if *frontier != MergeFrontierId::ZERO => {}
                (
                    LaneCursor::Local {
                        node: owner,
                        revision: old,
                        head: prior,
                    },
                    LaneCursor::Local {
                        node,
                        revision,
                        head,
                    },
                ) if owner == node
                    && old <= revision
                    && ((*old == 0 && prior.is_none())
                        || (*old != 0 && prior.is_some_and(|id| id != LocalEntryId::ZERO)))
                    && (old != revision || prior == head) => {}
                _ => return Err(DecodeError::NonCanonical),
            }
        }
        if self.genesis == AgentJournalGenesisId::ZERO
            || !valid_blob_ref(&self.state, true, MAX_RUNTIME_STATE_BYTES as u64)
        {
            return Err(DecodeError::NonCanonical);
        }
        match (&self.lane, &self.cursor) {
            (PersistedLane::Control | PersistedLane::Linear, LaneCursor::Ordered { base })
                if base.validate().is_ok() => {}
            (PersistedLane::Merge, LaneCursor::Merge { frontier })
                if *frontier != MergeFrontierId::ZERO => {}
            (
                PersistedLane::Local,
                LaneCursor::Local {
                    node,
                    revision,
                    head,
                },
            ) if *node != NodeId::ZERO
                && ((*revision == 0 && head.is_none())
                    || (*revision != 0 && head.is_some_and(|head| head != LocalEntryId::ZERO))) => {
            }
            _ => return Err(DecodeError::NonCanonical),
        }
        Ok(())
    }
}

impl ServiceWire for LaneStateManifest {
    const MAGIC: [u8; 4] = *b"AGJN";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encode_runtime_binding(&mut encoder, &self.runtime);
        encoder.u8(self.lane as u8);
        encode_lane_cursor(&mut encoder, &self.cursor);
        encode_blob_ref(&mut encoder, &self.state);
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(root) = &self.external_root {
            // No extension for opaque r19 state: its bytes and IDs stay exact.
            encoder.u8(2);
            encoder.bytes(&root.descriptor.encode());
            encode_runtime_binding(&mut encoder, &root.runtime);
            encode_lane_cursor(&mut encoder, &root.cursor);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CHECKPOINT_MANIFEST_BYTES)?;
        let manifest = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            runtime: decode_runtime_binding(decoder)?,
            lane: decode_persisted_lane(decoder.u8()?)?,
            cursor: decode_lane_cursor(decoder)?,
            state: decode_blob_ref(decoder)?,
            #[cfg(feature = "experimental-state-blocks")]
            external_root: if decoder.remaining() == 0 {
                None
            } else {
                if decoder.u8()? != 2 {
                    return Err(DecodeError::InvalidTag);
                }
                Some(ExternalStateRoot {
                    descriptor: crate::agent_sdk::state_root::StateRootDescriptor::decode(
                        bounded_bytes_ref(
                            decoder,
                            crate::agent_sdk::state_root::MAX_STATE_ROOT_BYTES,
                        )?,
                    )
                    .map_err(|_| DecodeError::NonCanonical)?,
                    runtime: decode_runtime_binding(decoder)?,
                    cursor: decode_lane_cursor(decoder)?,
                })
            },
        };
        manifest.validate_inner()?;
        Ok(manifest)
    }
}

impl sealed::Sealed for LaneStateManifest {}

impl CanonicalJournalRecord for LaneStateManifest {
    type Id = LaneStateId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::LaneState;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_CHECKPOINT_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        LaneStateId(content_id(b"vos/agent/journal/lane-state", self))
    }
}

/// Complete content-addressed artifact reachability set of a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactClosure {
    pub genesis: AgentJournalGenesisId,
    /// Strictly ordered by hash with one canonical length per content
    /// identity. The catalog retained by guest state supplies the artifact's
    /// semantic role; closure only needs exact byte reachability.
    pub artifacts: Vec<BlobRef>,
}

impl ArtifactClosure {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        validate_system_genesis_artifacts(&self.artifacts)?;
        if self.genesis == AgentJournalGenesisId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Genesis-safe commitment to the exact artifact reachability set. The
    /// physical closure record's final genesis scope is intentionally omitted
    /// because that genesis ID itself includes the authority admission ID.
    pub fn system_genesis_commitment(&self) -> Result<Hash, DecodeError> {
        system_genesis_artifact_closure_commitment(&self.artifacts)
    }
}

/// Commit to a canonical artifact closure before the final journal genesis ID
/// exists. Callers must later construct an [`ArtifactClosure`] with these same
/// references and the admitted final genesis scope.
pub fn system_genesis_artifact_closure_commitment(
    artifacts: &[BlobRef],
) -> Result<Hash, DecodeError> {
    validate_system_genesis_artifacts(artifacts)?;
    let mut bytes = Vec::new();
    Encoder(&mut bytes).list(artifacts, encode_blob_ref);
    Ok(Hash::digest(
        b"vos/agent/system-genesis-artifact-closure/v1",
        &[&bytes],
    ))
}

fn validate_system_genesis_artifacts(artifacts: &[BlobRef]) -> Result<(), DecodeError> {
    let referenced_bytes = artifacts.iter().try_fold(0_u64, |bytes, artifact| {
        bytes
            .checked_add(artifact.len)
            .ok_or(DecodeError::LimitExceeded)
    })?;
    if artifacts.len() > MAX_ARTIFACT_CLOSURE_ENTRIES
        || referenced_bytes > MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES
    {
        return Err(DecodeError::LimitExceeded);
    }
    if artifacts.is_empty()
        || artifacts
            .iter()
            .any(|artifact| !valid_blob_ref(artifact, true, MAX_ARTIFACT_CLOSURE_BYTES as u64))
        || artifacts
            .windows(2)
            .any(|pair| pair[0].hash >= pair[1].hash)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

impl ServiceWire for ArtifactClosure {
    const MAGIC: [u8; 4] = *b"AGJA";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.list(&self.artifacts, encode_blob_ref);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ARTIFACT_CLOSURE_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let count = decoder.u32()? as usize;
        if count > MAX_ARTIFACT_CLOSURE_ENTRIES {
            return Err(DecodeError::LimitExceeded);
        }
        let maximum = max_fixed_items(decoder, count, 40, MAX_ARTIFACT_CLOSURE_BYTES)?;
        if count > maximum {
            return Err(DecodeError::LimitExceeded);
        }
        let mut artifacts = Vec::new();
        for _ in 0..count {
            artifacts
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            artifacts.push(decode_blob_ref(decoder)?);
        }
        let closure = Self { genesis, artifacts };
        closure.validate_inner()?;
        Ok(closure)
    }
}

impl sealed::Sealed for ArtifactClosure {}

impl CanonicalJournalRecord for ArtifactClosure {
    type Id = ArtifactClosureId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::ArtifactClosure;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_ARTIFACT_CLOSURE_BYTES)
    }

    fn id(&self) -> Self::Id {
        ArtifactClosureId(content_id(b"vos/agent/journal/artifact-closure", self))
    }
}

/// One lane-state reference in an aggregate checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointLane {
    pub lane: PersistedLane,
    /// Present exactly for replica-local state.
    pub node: Option<NodeId>,
    pub state: LaneStateId,
    /// Present exactly for Local state and scoped to `node`.
    pub invocations: Option<InvocationIndexId>,
}

impl CheckpointLane {
    fn key(&self) -> (PersistedLane, Option<NodeId>) {
        (self.lane, self.node)
    }

    fn validate(&self) -> bool {
        self.state != LaneStateId::ZERO
            && self.invocations != Some(InvocationIndexId::ZERO)
            && match self.lane {
                PersistedLane::Local => {
                    self.node.is_some_and(|node| node != NodeId::ZERO) && self.invocations.is_some()
                }
                _ => self.node.is_none() && self.invocations.is_none(),
            }
    }
}

/// Latest replay-validated portable management mutation at an Ordered boundary.
/// Authentication comes from the enclosing checkpoint or replayed input, not
/// from decoding this public record. No private runtime-state layout is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanManagementEvidence {
    pub input: ReplayInputId,
    pub ordered: OrderedBase,
    pub authority: crate::agent_sdk::Hash,
    pub request: crate::agent_sdk::Hash,
    pub epoch: u64,
    pub sequence: u64,
    pub observed_slot: u64,
    pub result: Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
}

impl CleanManagementEvidence {
    pub(crate) fn validate_at(&self, boundary: OrderedBase) -> Result<(), DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        self.ordered.validate()?;
        boundary.validate()?;
        if self.input == ReplayInputId::ZERO
            || self.authority == crate::agent_sdk::Hash::ZERO
            || self.request == crate::agent_sdk::Hash::ZERO
            || self.epoch == 0
            || self.sequence == 0
            || self.ordered.index > boundary.index
            || (self.ordered.index == boundary.index && self.ordered != boundary)
        {
            return Err(DecodeError::NonCanonical);
        }
        let bytes = crate::agent_sdk::RuntimeTransition {
            state: crate::agent_sdk::RuntimeState::default(),
            outcome: crate::agent_sdk::RuntimeOutcome::Management(self.result.clone()),
        }
        .encode()
        .map_err(|_| DecodeError::NonCanonical)?;
        if bytes.len() > super::wire::MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(())
    }
}

/// Coherent aggregate checkpoint across every materialized lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointManifest {
    pub clean_management: Option<CleanManagementEvidence>,
    pub genesis: AgentJournalGenesisId,
    /// Immutable tagged Agent-genesis admission inherited from genesis.
    pub admission: AgentGenesisAdmissionId,
    pub runtime: RuntimeBinding,
    pub publication_revision: u64,
    pub ordered_head: Option<OrderedEntryId>,
    pub ordered_index: u64,
    pub merge_frontier: MergeFrontierId,
    /// Ordered base immediately after the latest lifecycle mutation. Events
    /// admitted against an older base are late across that fence unless they
    /// were already covered by `merge_seal`.
    pub merge_fence: OrderedBase,
    /// Seal consumed by the lifecycle entry at `merge_fence`. This is not
    /// necessarily a seal of the newer `merge_frontier`.
    pub merge_seal: Option<MergeSealId>,
    /// Checkpoint-authenticated ownership roots for shared ordering domains.
    pub ordered_invocations: InvocationIndexId,
    pub merge_invocations: InvocationIndexId,
    /// Exact authenticated live transition-proof map at this checkpoint.
    pub transition_proofs: TransitionProofIndexId,
    /// Control, Linear, Merge, then zero or more node-sorted Local states.
    pub lanes: Vec<CheckpointLane>,
    pub artifacts: ArtifactClosureId,
}

impl CheckpointManifest {
    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.runtime.validate()?;
        self.merge_fence.validate()?;
        if let Some(evidence) = &self.clean_management {
            evidence.validate_at(OrderedBase {
                index: self.ordered_index,
                head: self.ordered_head,
            })?;
        }
        let local_count = self
            .lanes
            .iter()
            .filter(|lane| lane.lane == PersistedLane::Local)
            .count();
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
            || (self.ordered_index == 0) != self.ordered_head.is_none()
            || self.ordered_head == Some(OrderedEntryId::ZERO)
            || self.merge_frontier == MergeFrontierId::ZERO
            || self.merge_seal == Some(MergeSealId::ZERO)
            || self.ordered_invocations == InvocationIndexId::ZERO
            || self.merge_invocations == InvocationIndexId::ZERO
            || self.transition_proofs == TransitionProofIndexId::ZERO
            || ((self.merge_fence == OrderedBase::post_genesis()) != self.merge_seal.is_none())
            || self.merge_fence.index > self.ordered_index
            || (self.merge_fence.index == self.ordered_index
                && self.merge_fence.head != self.ordered_head)
            || self.lanes.is_empty()
            || local_count > MAX_CHECKPOINT_LOCAL_LANES
            || self.lanes.iter().any(|lane| !lane.validate())
            || self
                .lanes
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
            || self.artifacts == ArtifactClosureId::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        if !self
            .lanes
            .iter()
            .any(|lane| lane.lane == PersistedLane::Control)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for CheckpointManifest {
    const MAGIC: [u8; 4] = *b"AJC4";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(self.admission.as_bytes());
        encode_runtime_binding(&mut encoder, &self.runtime);
        encoder.u64(self.publication_revision);
        encoder.option(&self.ordered_head, |encoder, head| encoder.fixed(&head.0));
        encoder.u64(self.ordered_index);
        encoder.fixed(&self.merge_frontier.0);
        encode_ordered_base(&mut encoder, self.merge_fence);
        encoder.option(&self.merge_seal, |encoder, seal| encoder.fixed(&seal.0));
        encoder.fixed(&self.ordered_invocations.0);
        encoder.fixed(&self.merge_invocations.0);
        encoder.fixed(&self.transition_proofs.0);
        encoder.list(&self.lanes, |encoder, lane| {
            encoder.u8(lane.lane as u8);
            encoder.option(&lane.node, |encoder, node| encoder.fixed(&node.0));
            encoder.fixed(&lane.state.0);
            encoder.option(&lane.invocations, |encoder, index| encoder.fixed(&index.0));
        });
        encoder.fixed(&self.artifacts.0);
        encoder.option(&self.clean_management, |encoder, evidence| {
            encoder.fixed(evidence.input.as_bytes());
            encode_ordered_base(encoder, evidence.ordered);
            encoder.fixed(evidence.authority.as_bytes());
            encoder.fixed(evidence.request.as_bytes());
            encoder.u64(evidence.epoch);
            encoder.u64(evidence.sequence);
            encoder.u64(evidence.observed_slot);
            encoder.bytes(&super::wire::encode_clean_management_result(
                &evidence.result,
            ));
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CHECKPOINT_MANIFEST_BYTES)?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        let admission = AgentGenesisAdmissionId::from_bytes(decoder.fixed()?);
        let runtime = decode_runtime_binding(decoder)?;
        let publication_revision = decoder.u64()?;
        let ordered_head = decoder.option(|decoder| Ok(OrderedEntryId(decoder.fixed()?)))?;
        let ordered_index = decoder.u64()?;
        let merge_frontier = MergeFrontierId(decoder.fixed()?);
        let merge_fence = decode_ordered_base(decoder)?;
        let merge_seal = decoder.option(|decoder| Ok(MergeSealId(decoder.fixed()?)))?;
        let ordered_invocations = InvocationIndexId(decoder.fixed()?);
        let merge_invocations = InvocationIndexId(decoder.fixed()?);
        let transition_proofs = TransitionProofIndexId(decoder.fixed()?);
        let count = decoder.u32()? as usize;
        if count > MAX_CHECKPOINT_LOCAL_LANES + 3 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut lanes = Vec::new();
        for _ in 0..count {
            lanes
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            lanes.push(CheckpointLane {
                lane: decode_persisted_lane(decoder.u8()?)?,
                node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
                state: LaneStateId(decoder.fixed()?),
                invocations: decoder.option(|decoder| Ok(InvocationIndexId(decoder.fixed()?)))?,
            });
        }
        let manifest = Self {
            genesis,
            admission,
            runtime,
            publication_revision,
            ordered_head,
            ordered_index,
            merge_frontier,
            merge_fence,
            merge_seal,
            ordered_invocations,
            merge_invocations,
            transition_proofs,
            lanes,
            artifacts: ArtifactClosureId(decoder.fixed()?),
            clean_management: decoder.option(|decoder| {
                let input = ReplayInputId(decoder.fixed()?);
                let ordered = decode_ordered_base(decoder)?;
                let authority = crate::agent_sdk::Hash(decoder.fixed()?);
                let request = crate::agent_sdk::Hash(decoder.fixed()?);
                let epoch = decoder.u64()?;
                let sequence = decoder.u64()?;
                let observed_slot = decoder.u64()?;
                let bytes = decoder.bytes_ref()?;
                if bytes.len() > super::wire::MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                let result = super::wire::decode_clean_management_result(bytes)?;
                Ok(CleanManagementEvidence {
                    input,
                    ordered,
                    authority,
                    request,
                    epoch,
                    sequence,
                    observed_slot,
                    result,
                })
            })?,
        };
        manifest.validate_inner()?;
        Ok(manifest)
    }
}

impl sealed::Sealed for CheckpointManifest {}

impl CanonicalJournalRecord for CheckpointManifest {
    type Id = CheckpointId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::Checkpoint;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_CHECKPOINT_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        CheckpointId(content_id(b"vos/agent/journal/checkpoint/v4", self))
    }
}

/// Atomically published journal tips for one physical replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalHeads {
    pub genesis: AgentJournalGenesisId,
    /// Immutable tagged Agent-genesis admission inherited from genesis.
    pub admission: AgentGenesisAdmissionId,
    pub node: NodeId,
    /// Runtime selected after replaying `ordered_head`. Genesis initializes
    /// this binding; only validated ordered replay may change it.
    pub runtime: RuntimeBinding,
    /// CAS generation of this envelope, independent of ordered/local indexes.
    pub publication_revision: u64,
    /// Exact predecessor envelope. A staged `heads.next` therefore proves the
    /// CAS candidate it was intended to replace.
    pub previous: Option<JournalHeadsId>,
    pub ordered_head: Option<OrderedEntryId>,
    pub ordered_index: u64,
    /// Always names a concrete frontier object, including the empty frontier.
    pub merge_frontier: MergeFrontierId,
    /// Ordered base immediately after the latest lifecycle mutation.
    pub merge_fence: OrderedBase,
    /// Seal consumed by that lifecycle mutation. It may cover an older
    /// frontier than `merge_frontier` after later Merge publications.
    pub merge_seal: Option<MergeSealId>,
    pub ordered_invocations: InvocationIndexId,
    pub merge_invocations: InvocationIndexId,
    /// Current physical node's Local ownership index.
    pub local_invocations: InvocationIndexId,
    /// Authenticated live transition-proof map. Ordinary journal and
    /// checkpoint publications preserve this root exactly.
    pub transition_proofs: TransitionProofIndexId,
    pub local_head: Option<LocalEntryId>,
    pub local_revision: u64,
    pub checkpoint: Option<CheckpointId>,
}

impl JournalHeads {
    /// Empty envelope written when a genesis is installed.
    pub fn initial(
        genesis: AgentJournalGenesisId,
        admission: AgentGenesisAdmissionId,
        node: NodeId,
        empty_merge_frontier: MergeFrontierId,
        runtime: RuntimeBinding,
    ) -> Self {
        let ordered_invocations =
            InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Ordered).id();
        let merge_invocations =
            InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Merge).id();
        let local_invocations =
            InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Local(node)).id();
        let transition_proofs = TransitionProofIndexManifest::empty(genesis).id();
        Self {
            genesis,
            admission,
            node,
            runtime,
            publication_revision: 0,
            previous: None,
            ordered_head: None,
            ordered_index: 0,
            merge_frontier: empty_merge_frontier,
            merge_fence: OrderedBase::post_genesis(),
            merge_seal: None,
            ordered_invocations,
            merge_invocations,
            local_invocations,
            transition_proofs,
            local_head: None,
            local_revision: 0,
            checkpoint: None,
        }
    }

    fn validate_inner(&self) -> Result<(), DecodeError> {
        self.runtime.validate()?;
        self.merge_fence.validate()?;
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
            || self.node == NodeId::ZERO
            || (self.publication_revision == 0) != self.previous.is_none()
            || self.previous == Some(JournalHeadsId::ZERO)
            || (self.ordered_index == 0) != self.ordered_head.is_none()
            || self.ordered_head == Some(OrderedEntryId::ZERO)
            || self.merge_frontier == MergeFrontierId::ZERO
            || self.merge_seal == Some(MergeSealId::ZERO)
            || self.ordered_invocations == InvocationIndexId::ZERO
            || self.merge_invocations == InvocationIndexId::ZERO
            || self.local_invocations == InvocationIndexId::ZERO
            || self.transition_proofs == TransitionProofIndexId::ZERO
            || ((self.merge_fence == OrderedBase::post_genesis()) != self.merge_seal.is_none())
            || self.merge_fence.index > self.ordered_index
            || (self.merge_fence.index == self.ordered_index
                && self.merge_fence.head != self.ordered_head)
            || (self.local_revision == 0) != self.local_head.is_none()
            || self.local_head == Some(LocalEntryId::ZERO)
            || self.checkpoint == Some(CheckpointId::ZERO)
        {
            return Err(DecodeError::NonCanonical);
        }
        if self.publication_revision == 0
            && (self.ordered_head.is_some()
                || self.merge_seal.is_some()
                || self.local_head.is_some()
                || self.checkpoint.is_some())
        {
            return Err(DecodeError::NonCanonical);
        }
        if self.publication_revision == 0
            && (self.ordered_invocations
                != InvocationIndexManifest::empty(self.genesis, InvocationOwnershipScope::Ordered)
                    .id()
                || self.merge_invocations
                    != InvocationIndexManifest::empty(
                        self.genesis,
                        InvocationOwnershipScope::Merge,
                    )
                    .id()
                || self.local_invocations
                    != InvocationIndexManifest::empty(
                        self.genesis,
                        InvocationOwnershipScope::Local(self.node),
                    )
                    .id()
                || self.transition_proofs != TransitionProofIndexManifest::empty(self.genesis).id())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Validate the immutable scope and one-step CAS relationship between two
    /// head envelopes. Record-specific tip advancement is checked by storage.
    pub fn validate_successor(&self, next: &Self) -> Result<(), DecodeError> {
        self.validate()?;
        next.validate()?;
        if next.genesis != self.genesis
            || next.admission != self.admission
            || next.node != self.node
            || next.runtime.space != self.runtime.space
            || next.runtime.agent != self.runtime.agent
            || next.publication_revision
                != self
                    .publication_revision
                    .checked_add(1)
                    .ok_or(DecodeError::LimitExceeded)?
            || next.previous != Some(self.id())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }
}

impl ServiceWire for JournalHeads {
    const MAGIC: [u8; 4] = *b"AJH3";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(self.admission.as_bytes());
        encoder.fixed(&self.node.0);
        encode_runtime_binding(&mut encoder, &self.runtime);
        encoder.u64(self.publication_revision);
        encoder.option(&self.previous, |encoder, previous| {
            encoder.fixed(&previous.0)
        });
        encoder.option(&self.ordered_head, |encoder, head| encoder.fixed(&head.0));
        encoder.u64(self.ordered_index);
        encoder.fixed(&self.merge_frontier.0);
        encode_ordered_base(&mut encoder, self.merge_fence);
        encoder.option(&self.merge_seal, |encoder, seal| encoder.fixed(&seal.0));
        encoder.fixed(&self.ordered_invocations.0);
        encoder.fixed(&self.merge_invocations.0);
        encoder.fixed(&self.local_invocations.0);
        encoder.fixed(&self.transition_proofs.0);
        encoder.option(&self.local_head, |encoder, head| encoder.fixed(&head.0));
        encoder.u64(self.local_revision);
        encoder.option(&self.checkpoint, |encoder, checkpoint| {
            encoder.fixed(&checkpoint.0)
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CHECKPOINT_MANIFEST_BYTES)?;
        let heads = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            admission: AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            node: NodeId(decoder.fixed()?),
            runtime: decode_runtime_binding(decoder)?,
            publication_revision: decoder.u64()?,
            previous: decoder.option(|decoder| Ok(JournalHeadsId(decoder.fixed()?)))?,
            ordered_head: decoder.option(|decoder| Ok(OrderedEntryId(decoder.fixed()?)))?,
            ordered_index: decoder.u64()?,
            merge_frontier: MergeFrontierId(decoder.fixed()?),
            merge_fence: decode_ordered_base(decoder)?,
            merge_seal: decoder.option(|decoder| Ok(MergeSealId(decoder.fixed()?)))?,
            ordered_invocations: InvocationIndexId(decoder.fixed()?),
            merge_invocations: InvocationIndexId(decoder.fixed()?),
            local_invocations: InvocationIndexId(decoder.fixed()?),
            transition_proofs: TransitionProofIndexId(decoder.fixed()?),
            local_head: decoder.option(|decoder| Ok(LocalEntryId(decoder.fixed()?)))?,
            local_revision: decoder.u64()?,
            checkpoint: decoder.option(|decoder| Ok(CheckpointId(decoder.fixed()?)))?,
        };
        heads.validate_inner()?;
        Ok(heads)
    }
}

impl sealed::Sealed for JournalHeads {}

impl CanonicalJournalRecord for JournalHeads {
    type Id = JournalHeadsId;

    const STORAGE_CLASS: JournalStorageClass = JournalStorageClass::Heads;

    fn validate(&self) -> Result<(), DecodeError> {
        self.validate_inner()?;
        validate_encoded_bound(self, MAX_CHECKPOINT_MANIFEST_BYTES)
    }

    fn id(&self) -> Self::Id {
        JournalHeadsId(content_id(b"vos/agent/journal/heads/v3", self))
    }
}

fn encode_runtime_binding(encoder: &mut Encoder<'_>, binding: &RuntimeBinding) {
    encoder.fixed(&binding.space.0);
    encoder.fixed(&binding.agent.0);
    encoder.fixed(&binding.deployment.0);
    encoder.fixed(&binding.program.0);
    encoder.fixed(&binding.producer.0);
    encode_blob_ref(encoder, &binding.package);
    encoder.fixed(&binding.runtime_abi.0);
    encoder.fixed(&binding.execution_semantics.0);
}

fn encode_ordered_base(encoder: &mut Encoder<'_>, base: OrderedBase) {
    encoder.u64(base.index);
    encoder.option(&base.head, |encoder, head| encoder.fixed(&head.0));
}

fn decode_ordered_base(decoder: &mut Decoder<'_>) -> Result<OrderedBase, DecodeError> {
    let base = OrderedBase {
        index: decoder.u64()?,
        head: decoder.option(|decoder| Ok(OrderedEntryId(decoder.fixed()?)))?,
    };
    base.validate()?;
    Ok(base)
}

fn decode_runtime_binding(decoder: &mut Decoder<'_>) -> Result<RuntimeBinding, DecodeError> {
    let binding = RuntimeBinding {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob_ref(decoder)?,
        runtime_abi: Hash(decoder.fixed()?),
        execution_semantics: Hash(decoder.fixed()?),
    };
    binding.validate()?;
    Ok(binding)
}

fn encode_transition_proof_lifecycle_key(
    encoder: &mut Encoder<'_>,
    key: &Option<crate::agent_sdk::proof::TransitionProofKey>,
) {
    encoder.option(key, |encoder, key| {
        encoder.fixed(key.invocation.as_bytes());
        encoder.fixed(key.execution.as_bytes());
    });
}

fn decode_transition_proof_lifecycle_key(
    decoder: &mut Decoder<'_>,
) -> Result<Option<crate::agent_sdk::proof::TransitionProofKey>, DecodeError> {
    decoder.option(|decoder| {
        let key = crate::agent_sdk::proof::TransitionProofKey {
            invocation: crate::agent_sdk::InvocationId(decoder.fixed()?),
            execution: crate::agent_sdk::Hash(decoder.fixed()?),
        };
        key.validate()
            .then_some(key)
            .ok_or(DecodeError::NonCanonical)
    })
}

fn encode_replay_operation(encoder: &mut Encoder<'_>, operation: &ReplayOperation) {
    encode_replay_operation_inner(encoder, operation, false);
}

fn encode_replay_operation_inner(
    encoder: &mut Encoder<'_>,
    operation: &ReplayOperation,
    invocation_already_validated: bool,
) {
    match operation {
        ReplayOperation::Management { request } => {
            encoder.u8(0);
            let call = RuntimeCall::new(RuntimeState::default(), request.clone());
            encoder.bytes(&call.encode());
        }
        ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } => {
            encoder.u8(5);
            let canonical = crate::agent_sdk::RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: authority.selector.space,
                agent: authority.selector.agent,
                runtime_deployment: authority.selector.runtime_deployment,
                state: crate::agent_sdk::RuntimeState::default(),
                request: alloc::boxed::Box::new(request.clone()),
                authority: Some(alloc::boxed::Box::new(authority.clone())),
                observed_slot: *observed_slot,
            }
            .encode()
            .expect("validated CleanManage must have a canonical SDK encoding");
            encoder.bytes(&canonical);
        }
        ReplayOperation::Invoke {
            invocation,
            authority,
            observed_slot,
        } => {
            encoder.u8(1);
            encode_actor_invocation(encoder, invocation);
            encoder.bytes(&authority.encode());
            encoder.u64(*observed_slot);
        }
        ReplayOperation::CleanInvoke {
            context,
            work,
            authorization,
            observed_slot,
        } => {
            encoder.u8(4);
            let canonical = crate::agent_sdk::RuntimeWork::Invoke {
                context: *context,
                state: crate::agent_sdk::RuntimeState::default(),
                invocation: alloc::boxed::Box::new(work.clone()),
                authorization: alloc::boxed::Box::new(authorization.clone()),
                observed_slot: *observed_slot,
            };
            let canonical = encode_journal_invoke(&canonical, invocation_already_validated)
                .expect("validated CleanInvoke must have a canonical SDK encoding");
            encoder.bytes(&canonical);
        }
        ReplayOperation::CleanResume {
            context,
            expected_live,
            work,
            authorization,
            yielded,
            observed_slot,
        } => {
            encoder.u8(6);
            let canonical = crate::agent_sdk::RuntimeWork::Invoke {
                context: *context,
                state: crate::agent_sdk::RuntimeState::default(),
                invocation: alloc::boxed::Box::new(work.clone()),
                authorization: alloc::boxed::Box::new(authorization.clone()),
                observed_slot: *observed_slot,
            };
            let canonical = encode_journal_invoke(&canonical, invocation_already_validated)
                .expect("validated CleanResume must have a canonical exact-work encoding");
            encoder.bytes(&canonical);
            let yielded = crate::agent_sdk::RuntimeTransition {
                state: crate::agent_sdk::RuntimeState::default(),
                outcome: crate::agent_sdk::RuntimeOutcome::Yielded(yielded.clone()),
            }
            .encode()
            .expect("validated CleanResume must have a canonical yielded selector");
            encoder.bytes(&yielded);
            encode_transition_proof_lifecycle_key(encoder, expected_live);
        }
        ReplayOperation::CleanAcknowledge {
            context,
            expected_live,
            work,
            authorization,
        } => {
            encoder.u8(7);
            let canonical = crate::agent_sdk::RuntimeWork::Acknowledge {
                context: *context,
                state: crate::agent_sdk::RuntimeState::default(),
                invocation: alloc::boxed::Box::new(work.clone()),
                authorization: alloc::boxed::Box::new(authorization.clone()),
            }
            .encode()
            .expect("validated CleanAcknowledge must have a canonical SDK encoding");
            encoder.bytes(&canonical);
            encode_transition_proof_lifecycle_key(encoder, expected_live);
        }
        ReplayOperation::Acknowledge {
            invocation,
            authority,
        } => {
            encoder.u8(2);
            encode_actor_invocation(encoder, invocation);
            encoder.bytes(&authority.encode());
        }
        ReplayOperation::SealMerge => encoder.u8(3),
    }
}

/// Only the immutable size pass after ReplayInput::validate_inner may bypass
/// repeated Invoke validation. The public ServiceWire encoder passes false.
fn encode_journal_invoke(
    work: &crate::agent_sdk::RuntimeWork,
    already_validated: bool,
) -> Result<Vec<u8>, crate::agent_sdk::wire::WireError> {
    if !already_validated {
        return work.encode();
    }
    debug_assert!(matches!(work, crate::agent_sdk::RuntimeWork::Invoke { .. }));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&crate::agent_sdk::RuntimeWork::MAGIC);
    bytes.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
    work.encode_body(&mut vos_protocol::wire::Encoder(&mut bytes));
    if bytes.len() > crate::agent_sdk::RuntimeWork::MAX_ENCODED_BYTES {
        return Err(crate::agent_sdk::wire::WireError::LimitExceeded);
    }
    Ok(bytes)
}

/// Check exact canonical bytes after the SDK decoder has authenticated all
/// nested blob preimages. The owned value cannot change between decode and
/// this comparison, so encode its body without re-running blob validation.
/// Keep this private: constructed or mutated work must use normal SDK encode.
fn decode_canonical_runtime_work(
    encoded: &[u8],
) -> Result<crate::agent_sdk::RuntimeWork, DecodeError> {
    use crate::agent_sdk::RuntimeWork;
    let canonical = RuntimeWork::decode(encoded).map_err(|_| DecodeError::NonCanonical)?;
    let mut checked = Vec::new();
    checked
        .try_reserve_exact(encoded.len())
        .map_err(|_| DecodeError::LimitExceeded)?;
    checked.extend_from_slice(&RuntimeWork::MAGIC);
    checked.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
    canonical.encode_body(&mut vos_protocol::wire::Encoder(&mut checked));
    if checked != encoded {
        return Err(DecodeError::NonCanonical);
    }
    Ok(canonical)
}

fn decode_replay_operation(decoder: &mut Decoder<'_>) -> Result<ReplayOperation, DecodeError> {
    match decoder.u8()? {
        0 => {
            let bytes = bounded_bytes_ref(decoder, MAX_REPLAY_INPUT_BYTES)?;
            let call = RuntimeCall::decode(bytes)?;
            if !call.state.is_empty() || call.journal_context().is_some() {
                return Err(DecodeError::NonCanonical);
            }
            Ok(ReplayOperation::Management {
                request: call.request,
            })
        }
        1 => Ok(ReplayOperation::Invoke {
            invocation: decode_actor_invocation(decoder)?,
            authority: ActorInvocationReceipt::decode(bounded_bytes_ref(
                decoder,
                MAX_AUTHORITY_RECEIPT_BYTES,
            )?)?,
            observed_slot: decoder.u64()?,
        }),
        2 => Ok(ReplayOperation::Acknowledge {
            invocation: decode_actor_invocation(decoder)?,
            authority: ActorInvocationReceipt::decode(bounded_bytes_ref(
                decoder,
                MAX_AUTHORITY_RECEIPT_BYTES,
            )?)?,
        }),
        3 => Ok(ReplayOperation::SealMerge),
        4 => {
            let encoded =
                bounded_bytes_ref(decoder, crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES)?;
            let canonical = decode_canonical_runtime_work(encoded)?;
            let crate::agent_sdk::RuntimeWork::Invoke {
                context,
                state,
                invocation,
                authorization,
                observed_slot,
            } = canonical
            else {
                return Err(DecodeError::NonCanonical);
            };
            if !context.is_valid() || !state.is_empty() {
                return Err(DecodeError::NonCanonical);
            }
            Ok(ReplayOperation::CleanInvoke {
                context,
                work: *invocation,
                authorization: *authorization,
                observed_slot,
            })
        }
        5 => {
            let encoded =
                bounded_bytes_ref(decoder, crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES)?;
            let canonical = decode_canonical_runtime_work(encoded)?;
            let crate::agent_sdk::RuntimeWork::Manage {
                context,
                space,
                agent,
                runtime_deployment,
                state,
                request,
                authority: Some(authority),
                observed_slot,
            } = canonical
            else {
                return Err(DecodeError::NonCanonical);
            };
            if !context.is_direct()
                || !state.is_empty()
                || request.authority_operation().is_none()
                || space != authority.selector.space
                || agent != authority.selector.agent
                || runtime_deployment != authority.selector.runtime_deployment
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(ReplayOperation::CleanManage {
                request: *request,
                authority: *authority,
                observed_slot,
            })
        }
        6 => {
            let encoded =
                bounded_bytes_ref(decoder, crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES)?;
            let canonical = decode_canonical_runtime_work(encoded)?;
            let crate::agent_sdk::RuntimeWork::Invoke {
                context,
                state,
                invocation,
                authorization,
                observed_slot,
            } = canonical
            else {
                return Err(DecodeError::NonCanonical);
            };
            if !context.is_valid() || !state.is_empty() {
                return Err(DecodeError::NonCanonical);
            }
            let yielded_encoded = bounded_bytes_ref(decoder, MAX_CLEAN_YIELDED_WIRE_BYTES)?;
            let yielded_transition = crate::agent_sdk::RuntimeTransition::decode(yielded_encoded)
                .map_err(|_| DecodeError::NonCanonical)?;
            if yielded_transition
                .encode()
                .map_err(|_| DecodeError::NonCanonical)?
                != yielded_encoded
                || !yielded_transition.state.is_empty()
            {
                return Err(DecodeError::NonCanonical);
            }
            let crate::agent_sdk::RuntimeOutcome::Yielded(yielded) = yielded_transition.outcome
            else {
                return Err(DecodeError::NonCanonical);
            };
            let expected_live = decode_transition_proof_lifecycle_key(decoder)?;
            Ok(ReplayOperation::CleanResume {
                context,
                expected_live,
                work: *invocation,
                authorization: *authorization,
                yielded,
                observed_slot,
            })
        }
        7 => {
            let encoded =
                bounded_bytes_ref(decoder, crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES)?;
            let canonical = decode_canonical_runtime_work(encoded)?;
            let crate::agent_sdk::RuntimeWork::Acknowledge {
                context,
                state,
                invocation,
                authorization,
            } = canonical
            else {
                return Err(DecodeError::NonCanonical);
            };
            if !context.is_valid() || !state.is_empty() {
                return Err(DecodeError::NonCanonical);
            }
            let expected_live = decode_transition_proof_lifecycle_key(decoder)?;
            Ok(ReplayOperation::CleanAcknowledge {
                context,
                expected_live,
                work: *invocation,
                authorization: *authorization,
            })
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn validate_clean_exact_request_binding(
    runtime: &RuntimeBinding,
    work: &crate::agent_sdk::InvocationRetirement,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Result<(), DecodeError> {
    if !authorization.matches_retirement(work)
        || work.space.0 != runtime.space.0
        || work.agent.0 != runtime.agent.0
        || work.runtime_deployment.0 != runtime.deployment.0
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn validate_transition_proof_lifecycle_condition(
    context: crate::agent_sdk::RuntimeExecutionContext,
    expected_live: Option<crate::agent_sdk::proof::TransitionProofKey>,
    invocation: crate::agent_sdk::InvocationId,
) -> Result<(), DecodeError> {
    match (context, expected_live) {
        (crate::agent_sdk::RuntimeExecutionContext::Direct, None) => Ok(()),
        (crate::agent_sdk::RuntimeExecutionContext::Attested { .. }, Some(expected))
            if expected.validate() && expected.invocation == invocation =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }
}

fn validate_clean_management_request(
    runtime: &RuntimeBinding,
    request: &crate::agent_sdk::ManagementRequest,
    authority: &crate::agent_sdk::authority::AuthorityReceipt,
    observed_slot: u64,
) -> Result<(), DecodeError> {
    // Private controls are executed only by the dedicated Private host over
    // its PCTL/store transaction. Persisting them as generic Ordered/Raft
    // CleanManage would split guest state from Private control truth.
    if matches!(
        request,
        crate::agent_sdk::ManagementRequest::PrivateControl { .. }
    ) {
        return Err(DecodeError::NonCanonical);
    }
    let selector_deployment = authority.selector.runtime_deployment;
    let current_deployment = selector_deployment.0 == runtime.deployment.0;
    let retained_runtime_upgrade = matches!(
        request,
        crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade)
            if selector_deployment == upgrade.from_deployment
                && upgrade.to_deployment.0 == runtime.deployment.0
                && upgrade.to_program.0 == runtime.program.0
                && upgrade.producer.0 == runtime.producer.0
                && upgrade.package.hash.0 == runtime.package.hash.0
                && upgrade.package.len == runtime.package.len
    );
    if request.authority_operation().is_none()
        || authority.selector.space.0 != runtime.space.0
        || authority.selector.agent.0 != runtime.agent.0
        || (!current_deployment && !retained_runtime_upgrade)
    {
        return Err(DecodeError::NonCanonical);
    }
    let canonical = crate::agent_sdk::RuntimeWork::Manage {
        context: crate::agent_sdk::RuntimeExecutionContext::Direct,
        space: crate::agent_sdk::SpaceId(runtime.space.0),
        agent: crate::agent_sdk::AgentId(runtime.agent.0),
        runtime_deployment: selector_deployment,
        state: crate::agent_sdk::RuntimeState::default(),
        request: alloc::boxed::Box::new(request.clone()),
        authority: Some(alloc::boxed::Box::new(authority.clone())),
        observed_slot,
    };
    if canonical.encode().is_err() {
        return Err(DecodeError::NonCanonical);
    }
    match request {
        crate::agent_sdk::ManagementRequest::Create(descriptor) => {
            if descriptor.identity.space.0 != runtime.space.0
                || descriptor.identity.agent.0 != runtime.agent.0
                || descriptor.identity.runtime_deployment.0 != runtime.deployment.0
                || descriptor.identity.runtime_program.0 != runtime.program.0
                || descriptor.identity.runtime_producer.0 != runtime.producer.0
                || descriptor.runtime_package.hash.0 != runtime.package.hash.0
                || descriptor.runtime_package.len != runtime.package.len
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => {
            if upgrade.from_deployment != selector_deployment
                || (!current_deployment && !retained_runtime_upgrade)
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_clean_invocation_authorization_binding(
    runtime: &RuntimeBinding,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
) -> Result<(), DecodeError> {
    // This is the SDK Invoke predicate with a known-valid Direct context and
    // empty state and an already validated work value. Check the borrowed
    // authorization and enclosing runtime, not a cloned serialized copy.
    // The bounded message, <=16 blob references and fixed authorization fit
    // comfortably within AWRK's non-state/non-preimage framing allowance.
    const _: () = assert!(
        crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES
            + crate::agent_sdk::MAX_RUNTIME_AVAILABILITY_ITEMS * (32 + 8 + 4)
            + crate::agent_sdk::wire::MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES
            + 4096
            <= crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES
                - crate::agent_sdk::MAX_RUNTIME_AVAILABILITY_BYTES
    );
    if !authorization.matches_invoke(work, observed_slot)
        || work.space.0 != runtime.space.0
        || work.agent.0 != runtime.agent.0
        || work.runtime_deployment.0 != runtime.deployment.0
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn validate_management_request(
    runtime: &RuntimeBinding,
    request: &LifecycleRequest,
) -> Result<(), DecodeError> {
    // Live system-authority commands are self-authorizing through their
    // embedded committee certificates. They are admitted only as bare
    // management requests; wrapping one in the generic lifecycle receipt
    // would create a second, drifting authority domain.
    if matches!(
        request,
        LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
    ) {
        return Ok(());
    }
    let LifecycleRequest::Authorized { admission, request } = request else {
        return Err(DecodeError::NonCanonical);
    };
    let inner = request.as_ref();
    if matches!(
        inner,
        LifecycleRequest::Inspect { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
            | LifecycleRequest::Authorized { .. }
    ) {
        return Err(DecodeError::NonCanonical);
    }
    validate_agent_authority_receipt(&admission.receipt)?;
    let claim = &admission.receipt.claim;
    let capability = inner
        .required_capability()
        .ok_or(DecodeError::NonCanonical)?;
    if claim.space != runtime.space
        || claim.agent != runtime.agent
        || claim.capability != CapabilityId::named(capability)
        || claim.operation != inner.commitment()
    {
        return Err(DecodeError::NonCanonical);
    }
    match inner {
        LifecycleRequest::Create(config) => {
            if config.validate().is_err()
                || config.identity.space != runtime.space
                || config.identity.agent != runtime.agent
                || config.identity.owner != claim.principal
                || config.identity.runtime_deployment != runtime.deployment
                || config.identity.runtime_program != runtime.program
                || config.identity.runtime_producer != runtime.producer
                || config.runtime_package != runtime.package
                || config.authority != claim.authority
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        LifecycleRequest::UpgradeRuntime {
            from_deployment, ..
        } if *from_deployment != runtime.deployment => return Err(DecodeError::NonCanonical),
        _ => {}
    }
    Ok(())
}

fn is_create_operation(operation: &ReplayOperation) -> bool {
    matches!(
        operation,
        ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. }
        } if matches!(request.as_ref(), LifecycleRequest::Create(_))
    ) || matches!(
        operation,
        ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(_),
            ..
        }
    )
}

fn validate_agent_authority_receipt(receipt: &AgentAuthorityReceipt) -> Result<(), DecodeError> {
    let claim = &receipt.claim;
    if !claim.authority.validate()
        || claim.space == SpaceId::ZERO
        || claim.agent == AgentId::ZERO
        || claim.principal == PrincipalId::ZERO
        || claim.credential == CredentialId::ZERO
        || claim.capability == CapabilityId::ZERO
        || claim.operation == Hash::ZERO
        || claim.sequence == 0
        || claim.valid_until < claim.valid_from
        || receipt.signature.len() != ED25519_SIGNATURE_BYTES
        || receipt.encode().len() > MAX_AUTHORITY_RECEIPT_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn validate_invocation_receipt(
    runtime: &RuntimeBinding,
    invocation: &ActorInvocation,
    receipt: &ActorInvocationReceipt,
) -> Result<(), DecodeError> {
    invocation
        .validate()
        .map_err(|_| DecodeError::NonCanonical)?;
    let claim = &receipt.claim;
    let authenticated = matches!(
        claim.auth.origin,
        crate::service::Origin::Member(_) | crate::service::Origin::Actor(_)
    );
    if !claim.authority.validate()
        || claim.space != runtime.space
        || claim.agent != runtime.agent
        || claim.principal == Some(PrincipalId::ZERO)
        || claim.credential == Some(CredentialId::ZERO)
        || authenticated != claim.principal.is_some()
        || authenticated != claim.credential.is_some()
        || claim.authorization != invocation.authorization_message()
        || claim.auth != invocation.auth
        || claim.principal != invocation.auth.principal
        || claim.valid_until < claim.valid_from
        || receipt.signature.len() != ED25519_SIGNATURE_BYTES
        || receipt.encode().len() > MAX_AUTHORITY_RECEIPT_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

fn encode_actor_invocation(encoder: &mut Encoder<'_>, invocation: &ActorInvocation) {
    encoder.fixed(&invocation.invocation.0);
    encoder.fixed(&invocation.actor.0);
    encoder.fixed(&invocation.incarnation.0);
    encoder.fixed(&invocation.deployment.0);
    encoder.fixed(&invocation.program.0);
    encoder.u8(encode_method_mode(invocation.mode));
    encode_invocation_auth(encoder, &invocation.auth);
    encoder.bytes(&invocation.message);
    encoder.list(&invocation.availability, |encoder, blob| {
        encode_blob_ref(encoder, &blob.reference);
        encoder.bytes(&blob.bytes);
    });
    encoder.u64(invocation.gas);
}

fn decode_actor_invocation(decoder: &mut Decoder<'_>) -> Result<ActorInvocation, DecodeError> {
    let invocation = crate::service::InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    if incarnation == Hash::ZERO {
        return Err(DecodeError::NonCanonical);
    }
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder.u8()?)?;
    let auth = decode_invocation_auth(decoder)?;
    let message = bounded_bytes_ref(decoder, MAX_EXECUTION_MESSAGE_BYTES)?.to_vec();
    let count = decoder.u32()? as usize;
    if count > MAX_EXECUTION_BLOBS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut availability = Vec::new();
    let mut remaining = MAX_EXECUTION_AVAILABILITY_BYTES;
    for _ in 0..count {
        let reference = decode_blob_ref(decoder)?;
        let bytes = bounded_bytes_ref(decoder, remaining)?;
        remaining -= bytes.len();
        availability
            .try_reserve(1)
            .map_err(|_| DecodeError::LimitExceeded)?;
        availability.push(RuntimeBlob {
            reference,
            bytes: bytes.to_vec(),
        });
    }
    let invocation = ActorInvocation {
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        auth,
        message,
        availability,
        gas: decoder.u64()?,
    };
    invocation
        .validate()
        .map_err(|_| DecodeError::NonCanonical)?;
    Ok(invocation)
}

fn encode_invocation_auth(encoder: &mut Encoder<'_>, auth: &ActorInvocationAuth) {
    crate::service::encode_origin(encoder, auth.origin);
    encoder.option(&auth.principal, |encoder, principal| {
        encoder.fixed(&principal.0)
    });
    encoder.option(&auth.origin_service, crate::service::encode_service);
    encoder.option(&auth.space_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.actor_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.capability, |encoder, capability| {
        encoder.fixed(&capability.0)
    });
}

fn decode_invocation_auth(decoder: &mut Decoder<'_>) -> Result<ActorInvocationAuth, DecodeError> {
    let auth = ActorInvocationAuth {
        origin: crate::service::decode_origin(decoder)?,
        principal: decoder.option(|decoder| Ok(PrincipalId(decoder.fixed()?)))?,
        origin_service: decoder.option(crate::service::decode_service)?,
        space_role: decoder.option(Decoder::u8)?,
        actor_role: decoder.option(Decoder::u8)?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    auth.validate()
        .then_some(auth)
        .ok_or(DecodeError::NonCanonical)
}

const fn encode_method_mode(mode: MethodMode) -> u8 {
    match mode {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::LocalQuery => 2,
        MethodMode::Linear => 3,
        MethodMode::Merge => 4,
        MethodMode::Local => 5,
    }
}

fn decode_method_mode(value: u8) -> Result<MethodMode, DecodeError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

pub(crate) fn encode_lane_cursor(encoder: &mut Encoder<'_>, cursor: &LaneCursor) {
    match cursor {
        LaneCursor::Ordered { base } => {
            encoder.u8(0);
            encode_ordered_base(encoder, *base);
        }
        LaneCursor::Merge { frontier } => {
            encoder.u8(1);
            encoder.fixed(&frontier.0);
        }
        LaneCursor::Local {
            node,
            revision,
            head,
        } => {
            encoder.u8(2);
            encoder.fixed(&node.0);
            encoder.u64(*revision);
            encoder.option(head, |encoder, head| encoder.fixed(&head.0));
        }
    }
}

fn decode_lane_cursor(decoder: &mut Decoder<'_>) -> Result<LaneCursor, DecodeError> {
    match decoder.u8()? {
        0 => Ok(LaneCursor::Ordered {
            base: decode_ordered_base(decoder)?,
        }),
        1 => Ok(LaneCursor::Merge {
            frontier: MergeFrontierId(decoder.fixed()?),
        }),
        2 => Ok(LaneCursor::Local {
            node: NodeId(decoder.fixed()?),
            revision: decoder.u64()?,
            head: decoder.option(|decoder| Ok(LocalEntryId(decoder.fixed()?)))?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_persisted_lane(value: u8) -> Result<PersistedLane, DecodeError> {
    match value {
        0 => Ok(PersistedLane::Control),
        1 => Ok(PersistedLane::Linear),
        2 => Ok(PersistedLane::Merge),
        3 => Ok(PersistedLane::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_invocation_scope(encoder: &mut Encoder<'_>, scope: InvocationOwnershipScope) {
    match scope {
        InvocationOwnershipScope::Ordered => encoder.u8(0),
        InvocationOwnershipScope::Merge => encoder.u8(1),
        InvocationOwnershipScope::Local(node) => {
            encoder.u8(2);
            encoder.fixed(&node.0);
        }
    }
}

fn decode_invocation_scope(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationOwnershipScope, DecodeError> {
    let scope = match decoder.u8()? {
        0 => InvocationOwnershipScope::Ordered,
        1 => InvocationOwnershipScope::Merge,
        2 => InvocationOwnershipScope::Local(NodeId(decoder.fixed()?)),
        _ => return Err(DecodeError::InvalidTag),
    };
    scope.validate()?;
    Ok(scope)
}

fn encode_invocation_outcome_request(
    encoder: &mut Encoder<'_>,
    request: InvocationOutcomeRequestFacts,
) {
    encoder.fixed(&request.actor.0);
    encoder.fixed(&request.incarnation.0);
    encoder.fixed(&request.deployment.0);
    encoder.fixed(&request.program.0);
    encoder.u8(encode_method_mode(request.mode));
    encoder.u64(request.gas_limit);
}

fn decode_invocation_outcome_request(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationOutcomeRequestFacts, DecodeError> {
    let request = InvocationOutcomeRequestFacts {
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: decode_method_mode(decoder.u8()?)?,
        gas_limit: decoder.u64()?,
    };
    request.validate()?;
    Ok(request)
}

fn encode_invocation_outcome_anchor(encoder: &mut Encoder<'_>, anchor: InvocationOutcomeAnchor) {
    match anchor {
        InvocationOutcomeAnchor::Ordered { entry } => {
            encoder.u8(0);
            encoder.fixed(&entry.0);
        }
        InvocationOutcomeAnchor::Local { entry } => {
            encoder.u8(1);
            encoder.fixed(&entry.0);
        }
        InvocationOutcomeAnchor::Merge {
            source_event,
            finalizing_entry,
            seal,
        } => {
            encoder.u8(2);
            encoder.fixed(&source_event.0);
            encoder.fixed(&finalizing_entry.0);
            encoder.fixed(&seal.0);
        }
    }
}

fn decode_invocation_outcome_anchor(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationOutcomeAnchor, DecodeError> {
    match decoder.u8()? {
        0 => Ok(InvocationOutcomeAnchor::Ordered {
            entry: OrderedEntryId(decoder.fixed()?),
        }),
        1 => Ok(InvocationOutcomeAnchor::Local {
            entry: LocalEntryId(decoder.fixed()?),
        }),
        2 => Ok(InvocationOutcomeAnchor::Merge {
            source_event: MergeEventId(decoder.fixed()?),
            finalizing_entry: OrderedEntryId(decoder.fixed()?),
            seal: MergeSealId(decoder.fixed()?),
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_visible_state_component(
    encoder: &mut Encoder<'_>,
    component: VisibleStateComponentCommitment,
) {
    encoder.fixed(&component.hash.0);
    encoder.u64(component.len);
}

fn decode_visible_state_component(
    decoder: &mut Decoder<'_>,
) -> Result<VisibleStateComponentCommitment, DecodeError> {
    let component = VisibleStateComponentCommitment {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    };
    component.validate()?;
    Ok(component)
}

fn encode_visible_state_commitment(encoder: &mut Encoder<'_>, state: VisibleStateCommitment) {
    encode_visible_state_component(encoder, state.control);
    encoder.option(&state.linear, |encoder, component| {
        encode_visible_state_component(encoder, *component)
    });
    encoder.option(&state.merge, |encoder, component| {
        encode_visible_state_component(encoder, *component)
    });
    encoder.option(&state.local, |encoder, component| {
        encode_visible_state_component(encoder, *component)
    });
}

fn decode_visible_state_commitment(
    decoder: &mut Decoder<'_>,
) -> Result<VisibleStateCommitment, DecodeError> {
    Ok(VisibleStateCommitment {
        control: decode_visible_state_component(decoder)?,
        linear: decoder.option(decode_visible_state_component)?,
        merge: decoder.option(decode_visible_state_component)?,
        local: decoder.option(decode_visible_state_component)?,
    })
}

fn encode_invocation_owner(encoder: &mut Encoder<'_>, owner: InvocationOwner) {
    encode_invocation_scope(encoder, owner.scope);
    encoder.fixed(&owner.request_commitment.0);
    encoder.fixed(&owner.first_input.0);
    encoder.u8(owner.lane as u8);
    encoder.option(&owner.node, |encoder, node| encoder.fixed(&node.0));
    match owner.result_state {
        InvocationResultState::PendingMerge { source_event } => {
            encoder.u8(0);
            encoder.fixed(&source_event.0);
        }
        InvocationResultState::Retained {
            disposition,
            outcome,
        } => {
            encoder.u8(1);
            encode_invocation_disposition(encoder, disposition);
            encode_invocation_outcome_ref(encoder, outcome);
        }
        InvocationResultState::PendingMergeAcknowledgement {
            acknowledgement_event,
            disposition,
            outcome,
        } => {
            encoder.u8(2);
            encoder.fixed(&acknowledgement_event.0);
            encode_invocation_disposition(encoder, disposition);
            encode_invocation_outcome_ref(encoder, outcome);
        }
    }
}

fn decode_invocation_owner(decoder: &mut Decoder<'_>) -> Result<InvocationOwner, DecodeError> {
    let owner = InvocationOwner {
        scope: decode_invocation_scope(decoder)?,
        request_commitment: Hash(decoder.fixed()?),
        first_input: ReplayInputId(decoder.fixed()?),
        lane: decode_persisted_lane(decoder.u8()?)?,
        node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
        result_state: match decoder.u8()? {
            0 => InvocationResultState::PendingMerge {
                source_event: MergeEventId(decoder.fixed()?),
            },
            1 => InvocationResultState::Retained {
                disposition: decode_invocation_disposition(decoder)?,
                outcome: decode_invocation_outcome_ref(decoder)?,
            },
            2 => InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event: MergeEventId(decoder.fixed()?),
                disposition: decode_invocation_disposition(decoder)?,
                outcome: decode_invocation_outcome_ref(decoder)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    owner.validate()?;
    Ok(owner)
}

fn encode_invocation_disposition(encoder: &mut Encoder<'_>, disposition: InvocationDisposition) {
    encoder.u8(disposition as u8);
}

fn decode_invocation_disposition(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationDisposition, DecodeError> {
    match decoder.u8()? {
        0 => Ok(InvocationDisposition::Applied),
        1 => Ok(InvocationDisposition::Rejected),
        2 => Ok(InvocationDisposition::Forbidden),
        3 => Ok(InvocationDisposition::Panicked),
        4 => Ok(InvocationDisposition::OutOfGas),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_invocation_outcome_ref(encoder: &mut Encoder<'_>, outcome: InvocationOutcomeRef) {
    encoder.fixed(&outcome.outcome.0);
    encoder.u32(outcome.encoded_bytes);
}

fn decode_invocation_outcome_ref(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationOutcomeRef, DecodeError> {
    let outcome = InvocationOutcomeRef {
        outcome: InvocationOutcomeId(decoder.fixed()?),
        encoded_bytes: decoder.u32()?,
    };
    outcome.validate()?;
    Ok(outcome)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(&reference.hash.0);
    encoder.u64(reference.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn valid_blob_ref(reference: &BlobRef, allow_empty: bool, maximum: u64) -> bool {
    reference.hash != Hash::ZERO && reference.len <= maximum && (allow_empty || reference.len != 0)
}

fn bounded_bytes_ref<'a>(
    decoder: &mut Decoder<'a>,
    maximum: usize,
) -> Result<&'a [u8], DecodeError> {
    let len = decoder.u32()? as usize;
    if len > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    decoder.take(len)
}

fn decode_fixed_id_list<I: JournalObjectId>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<I>, DecodeError> {
    let count = decoder.u32()? as usize;
    if count > maximum || count > decoder.remaining() / 32 {
        return Err(DecodeError::LimitExceeded);
    }
    let mut values = Vec::new();
    for _ in 0..count {
        values
            .try_reserve(1)
            .map_err(|_| DecodeError::LimitExceeded)?;
        values.push(I::from_bytes(decoder.fixed()?));
    }
    Ok(values)
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn max_fixed_items(
    decoder: &Decoder<'_>,
    claimed: usize,
    encoded_item_bytes: usize,
    complete_maximum: usize,
) -> Result<usize, DecodeError> {
    if claimed
        .checked_mul(encoded_item_bytes)
        .is_none_or(|bytes| bytes > decoder.remaining())
    {
        return Err(DecodeError::LimitExceeded);
    }
    Ok((complete_maximum.saturating_sub(SERVICE_WIRE_HEADER_BYTES)) / encoded_item_bytes)
}

fn enforce_complete_bound(
    decoder: &Decoder<'_>,
    complete_maximum: usize,
) -> Result<(), DecodeError> {
    if decoder
        .remaining()
        .checked_add(SERVICE_WIRE_HEADER_BYTES)
        .is_none_or(|len| len > complete_maximum)
    {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(())
}

fn validate_encoded_bound<T: ServiceWire>(
    value: &T,
    complete_maximum: usize,
) -> Result<(), DecodeError> {
    (value.encode().len() <= complete_maximum)
        .then_some(())
        .ok_or(DecodeError::LimitExceeded)
}

fn content_id<T: ServiceWire>(domain: &[u8], value: &T) -> [u8; 32] {
    Hash::digest(domain, &[&value.encode()]).0
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec};

    use super::*;
    use crate::agent::authority::{
        ActorInvocationClaim, AgentAuthorityBinding, AgentAuthorityClaim, ed25519_public_key_wire,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LaneSet,
        LifecycleAuthorityAdmission, ReplicaRole, RuntimeCapabilities,
    };
    use crate::service::{InvocationId, Origin};

    fn authority_binding() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x41; 32]);
        AgentAuthorityBinding {
            agent: AgentId([0xa1; 32]),
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn config() -> AgentConfig {
        let space = SpaceId([1; 32]);
        let owner = PrincipalId([2; 32]);
        let creation_nonce = Hash([3; 32]);
        let agent = AgentId::derive(space, owner, &creation_nonce.0);
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
                transition_producer: ProducerId([16; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 4096,
            },
            replicas: vec![AgentReplica {
                node: NodeId([7; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn runtime_binding() -> RuntimeBinding {
        let config = config();
        RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package,
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    fn create_input() -> ReplayInput {
        let runtime = runtime_binding();
        let inner = LifecycleRequest::Create(config());
        let claim = AgentAuthorityClaim {
            authority: authority_binding(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config().identity.owner,
            credential: CredentialId([8; 32]),
            capability: CapabilityId::named("agent.create.local"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 20,
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim,
                            signature: vec![9; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 15,
                    },
                    request: Box::new(inner),
                },
            },
        }
    }

    #[test]
    fn runtime_binding_requires_a_matching_execution_contract_pair() {
        let released = runtime_binding();
        assert!(released.validate().is_ok());
        let mut external = released.clone();
        external.runtime_abi = Hash(*b"vos-agent-state-experimental-001");
        assert!(
            external.validate().is_err(),
            "mixed ABI/semantics must fail"
        );
        external.execution_semantics = Hash(*b"vos-agent-state-experimental-s01");
        assert!(
            external.validate().is_err(),
            "pre-selector experimental ABI is not compatible"
        );
        external.runtime_abi = Hash(*b"vos-agent-state-experimental-004");
        assert!(
            external.validate().is_err(),
            "mixed experimental revisions must fail"
        );
        external.execution_semantics = Hash(*b"vos-agent-state-experimental-s04");
        assert_eq!(
            external.validate().is_ok(),
            cfg!(feature = "experimental-state-blocks")
        );
        external.runtime_abi = released.runtime_abi;
        assert!(external.validate().is_err());
    }

    fn genesis_admission() -> AgentGenesisAdmissionId {
        AgentGenesisAdmissionId::from_bytes([0xad; 32])
    }

    fn invocation(mode: MethodMode) -> ActorInvocation {
        ActorInvocation {
            invocation: InvocationId([0x11; 32]),
            actor: ActorId([0x12; 32]),
            incarnation: Hash([0x15; 32]),
            deployment: DeploymentId([0x13; 32]),
            program: ProgramId([0x14; 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1, 2, 3],
            availability: Vec::new(),
            gas: 1_000,
        }
    }

    fn invocation_receipt(invocation: &ActorInvocation) -> ActorInvocationReceipt {
        let runtime = runtime_binding();
        ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: authority_binding(),
                space: runtime.space,
                agent: runtime.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 10,
                valid_until: 20,
            },
            signature: vec![0x22; ED25519_SIGNATURE_BYTES],
        }
    }

    fn replay_input(mode: MethodMode, acknowledge: bool) -> ReplayInput {
        let invocation = invocation(mode);
        let authority = invocation_receipt(&invocation);
        ReplayInput {
            runtime: runtime_binding(),
            operation: if acknowledge {
                ReplayOperation::Acknowledge {
                    invocation,
                    authority,
                }
            } else {
                ReplayOperation::Invoke {
                    invocation,
                    authority,
                    observed_slot: 15,
                }
            },
        }
    }

    fn clean_replay_input(mode: crate::agent_sdk::MethodMode) -> ReplayInput {
        let runtime = runtime_binding();
        let work = crate::agent_sdk::InvocationWork {
            space: crate::agent_sdk::SpaceId(runtime.space.0),
            agent: crate::agent_sdk::AgentId(runtime.agent.0),
            runtime_deployment: crate::agent_sdk::DeploymentId(runtime.deployment.0),
            invocation: crate::agent_sdk::InvocationId([0x81; 32]),
            actor: crate::agent_sdk::ActorId([0x82; 32]),
            incarnation: crate::agent_sdk::Hash([0x83; 32]),
            deployment: crate::agent_sdk::DeploymentId([0x84; 32]),
            program: crate::agent_sdk::ProgramId([0x85; 32]),
            mode,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::default(),
            message: b"clean replay".to_vec(),
            installation_data: None,
            availability: Vec::new(),
            gas: 10_000,
            recovery_only: false,
        };
        let public_key = [0x91; 32];
        let authority = crate::agent_sdk::authority::AuthorityReceipt {
            selector: crate::agent_sdk::authority::AuthorityReceiptSelector {
                policy: crate::agent_sdk::Hash([0x92; 32]),
                issuer: crate::agent_sdk::authority::AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([0x93; 32]),
                    actor: crate::agent_sdk::ActorId([0x94; 32]),
                    deployment: crate::agent_sdk::DeploymentId([0x95; 32]),
                    program: crate::agent_sdk::ProgramId([0x96; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                space: work.space,
                agent: work.agent,
                operation: crate::agent_sdk::authority::AuthorityOperationKind::InvokeActor,
                runtime_deployment: work.runtime_deployment,
                actor: Some(work.actor),
                actor_deployment: Some(work.deployment),
                evidence: crate::agent_sdk::authority::AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x97; 32]),
                },
                lane_roots: crate::agent_sdk::authority::AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 5,
                expires_at: 50,
                request: work.commitment(),
            },
            public_key,
            signature: [0x98; 64],
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization: crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                    authority,
                ),
                observed_slot: 12,
            },
        }
    }

    fn public_clean_replay_input(mode: crate::agent_sdk::MethodMode) -> ReplayInput {
        let mut input = clean_replay_input(mode);
        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            observed_slot,
            ..
        } = &mut input.operation
        else {
            unreachable!()
        };
        work.roles = crate::agent_sdk::InvocationRoleClaims::none();
        *authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(work, *observed_slot),
        );
        input
    }

    fn clean_management_input(request: crate::agent_sdk::ManagementRequest) -> ReplayInput {
        let runtime = runtime_binding();
        let public_key = [0x91; 32];
        let (actor, actor_deployment) = request.authority_actor_selector();
        let operation = request
            .authority_operation()
            .expect("fixture request is mutating");
        let decision_sequence = u64::from(operation.uses_management_decision_journal());
        let authority = crate::agent_sdk::authority::AuthorityReceipt {
            selector: crate::agent_sdk::authority::AuthorityReceiptSelector {
                policy: crate::agent_sdk::Hash([0x92; 32]),
                issuer: crate::agent_sdk::authority::AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([0x93; 32]),
                    actor: crate::agent_sdk::ActorId([0x94; 32]),
                    deployment: crate::agent_sdk::DeploymentId([0x95; 32]),
                    program: crate::agent_sdk::ProgramId([0x96; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                space: crate::agent_sdk::SpaceId(runtime.space.0),
                agent: crate::agent_sdk::AgentId(runtime.agent.0),
                operation,
                runtime_deployment: crate::agent_sdk::DeploymentId(runtime.deployment.0),
                actor,
                actor_deployment,
                evidence: crate::agent_sdk::authority::AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x97; 32]),
                },
                lane_roots: crate::agent_sdk::authority::AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence,
                acknowledged_through: 0,
                valid_from: 5,
                expires_at: 50,
                request: request.commitment(),
            },
            public_key,
            signature: [0x98; 64],
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot: 12,
            },
        }
    }

    fn management_input(inner: LifecycleRequest, capability: &str) -> ReplayInput {
        let runtime = runtime_binding();
        let claim = AgentAuthorityClaim {
            authority: authority_binding(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config().identity.owner,
            credential: CredentialId([8; 32]),
            capability: CapabilityId::named(capability),
            operation: inner.commitment(),
            sequence: 2,
            valid_from: 10,
            valid_until: 20,
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim,
                            signature: vec![9; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 15,
                    },
                    request: Box::new(inner),
                },
            },
        }
    }

    fn empty_frontier(genesis: AgentJournalGenesisId) -> MergeFrontierId {
        MergeFrontier {
            genesis,
            events: Vec::new(),
        }
        .id()
    }

    fn empty_index(
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
    ) -> InvocationIndexId {
        InvocationIndexManifest::empty(genesis, scope).id()
    }

    fn empty_transition_proof_index(genesis: AgentJournalGenesisId) -> TransitionProofIndexId {
        TransitionProofIndexManifest::empty(genesis).id()
    }

    fn ownership_leaf(
        genesis: AgentJournalGenesisId,
        scope: InvocationOwnershipScope,
        lane: PersistedLane,
        node: Option<NodeId>,
    ) -> InvocationOwnershipLeaf {
        InvocationOwnershipLeaf {
            genesis,
            key: InvocationOwnershipKey {
                scope,
                invocation: InvocationId([0xb1; 32]),
            },
            owner: InvocationOwner {
                scope,
                request_commitment: Hash([0xb2; 32]),
                first_input: replay_input(MethodMode::Linear, false).id(),
                lane,
                node,
                result_state: InvocationResultState::Retained {
                    disposition: InvocationDisposition::Applied,
                    outcome: InvocationOutcomeRef {
                        outcome: InvocationOutcomeId([0xb3; 32]),
                        encoded_bytes: 512,
                    },
                },
            },
        }
    }

    fn roundtrip<T>(value: &T)
    where
        T: ServiceWire + PartialEq + fmt::Debug,
    {
        let decoded = T::decode(&value.encode());
        assert_eq!(decoded.as_ref(), Ok(value));
    }

    fn outcome_genesis() -> AgentJournalGenesisId {
        AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id()
    }

    fn outcome_scope(mode: MethodMode) -> InvocationOwnershipScope {
        match mode {
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::Linear => {
                InvocationOwnershipScope::Ordered
            }
            MethodMode::Merge => InvocationOwnershipScope::Merge,
            MethodMode::LocalQuery | MethodMode::Local => {
                InvocationOwnershipScope::Local(NodeId([7; 32]))
            }
        }
    }

    fn outcome_anchor(mode: MethodMode) -> InvocationOutcomeAnchor {
        match mode {
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::Linear => {
                InvocationOutcomeAnchor::Ordered {
                    entry: OrderedEntryId([0x31; 32]),
                }
            }
            MethodMode::Merge => InvocationOutcomeAnchor::Merge {
                source_event: MergeEventId([0x32; 32]),
                finalizing_entry: OrderedEntryId([0x33; 32]),
                seal: MergeSealId([0x34; 32]),
            },
            MethodMode::LocalQuery | MethodMode::Local => InvocationOutcomeAnchor::Local {
                entry: LocalEntryId([0x35; 32]),
            },
        }
    }

    fn outcome_state() -> RuntimeState {
        RuntimeState {
            control: vec![0x41, 0x42],
            linear: vec![0x51, 0x52],
            merge: vec![0x61, 0x62],
            local: vec![0x71, 0x72],
        }
    }

    fn exact_reply(
        invocation: &ActorInvocation,
        status: ActorExecutionStatus,
        bytes: Vec<u8>,
    ) -> ActorExecutionReply {
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: invocation.mode.write_lane(),
            status,
            reply: bytes,
            gas_remaining: invocation.gas - 1,
            observation: super::super::execution::ActorObservation::default(),
        }
    }

    fn outcome_record(
        mode: MethodMode,
        result: impl FnOnce(&ActorInvocation) -> Result<ActorExecutionReply, ActorExecutionError>,
    ) -> (ReplayInput, InvocationOutcomeRecord) {
        let input = replay_input(mode, false);
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            unreachable!()
        };
        let result = result(invocation);
        let before = outcome_state();
        let mut after = before.clone();
        if matches!(
            result,
            Ok(ActorExecutionReply {
                status: ActorExecutionStatus::Done,
                ..
            })
        ) {
            match PersistedLane::from_result_storage(mode.result_storage()) {
                PersistedLane::Control => after.control.push(0x81),
                PersistedLane::Linear => after.linear.push(0x82),
                PersistedLane::Merge => after.merge.push(0x83),
                PersistedLane::Local => after.local.push(0x84),
            }
        }
        let record = InvocationOutcomeRecord::from_runtime_states(
            outcome_genesis(),
            outcome_scope(mode),
            outcome_anchor(mode),
            &input,
            &before,
            &after,
            result,
        )
        .unwrap();
        (input, record)
    }

    #[test]
    fn invocation_outcomes_roundtrip_every_scope_and_derive_disposition() {
        for (mode, expected_lane) in [
            (MethodMode::Query, PersistedLane::Control),
            (MethodMode::LinearizableQuery, PersistedLane::Linear),
            (MethodMode::Linear, PersistedLane::Linear),
            (MethodMode::Merge, PersistedLane::Merge),
            (MethodMode::LocalQuery, PersistedLane::Local),
            (MethodMode::Local, PersistedLane::Local),
        ] {
            let (input, record) = outcome_record(mode, |invocation| {
                Ok(exact_reply(
                    invocation,
                    ActorExecutionStatus::Done,
                    vec![1, 2, 3],
                ))
            });
            assert_eq!(record.lane, expected_lane);
            assert_eq!(record.disposition(), InvocationDisposition::Applied);
            record.validate().unwrap();
            record.validate_for(&input).unwrap();
            record
                .validate_for_genesis(outcome_genesis(), &input)
                .unwrap();
            roundtrip(&record);

            let reference = InvocationOutcomeRef::for_record(&record).unwrap();
            assert!(reference.authenticates(&record));
            roundtrip(&reference);
            assert!(record.encode().len() <= MAX_INVOCATION_OUTCOME_BYTES);

            match record.key.scope {
                InvocationOwnershipScope::Ordered => {
                    assert!(record.before.linear.is_some());
                    assert!(record.before.merge.is_some());
                    assert!(record.before.local.is_none());
                }
                InvocationOwnershipScope::Merge => {
                    assert!(record.before.linear.is_none());
                    assert!(record.before.merge.is_some());
                    assert!(record.before.local.is_none());
                }
                InvocationOwnershipScope::Local(_) => {
                    assert!(record.before.linear.is_some());
                    assert!(record.before.merge.is_some());
                    assert!(record.before.local.is_some());
                }
            }
        }
    }

    #[test]
    fn invocation_outcome_error_variants_roundtrip_exactly() {
        let errors = [
            ActorExecutionError::NotCreated,
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
            ActorExecutionError::UnsupportedResultStorage,
        ];
        for error in errors {
            let (_, mut record) = outcome_record(MethodMode::Linear, |_| Err(error));
            assert_eq!(record.result, Err(error));
            assert_eq!(record.disposition(), InvocationDisposition::Rejected);
            assert_eq!(record.before, record.after);
            record.after.linear.as_mut().unwrap().hash = Hash([0x91; 32]);
            record.validate().unwrap();
            roundtrip(&record);
        }

        let input = replay_input(MethodMode::Linear, false);
        let before = outcome_state();
        assert_eq!(
            InvocationOutcomeRecord::from_runtime_states(
                outcome_genesis(),
                InvocationOwnershipScope::Ordered,
                outcome_anchor(MethodMode::Linear),
                &input,
                &before,
                &before,
                Err(ActorExecutionError::DivergentInvocation),
            ),
            Err(DecodeError::NonCanonical)
        );

        for (status, disposition) in [
            (
                ActorExecutionStatus::Forbidden,
                InvocationDisposition::Forbidden,
            ),
            (
                ActorExecutionStatus::Panicked,
                InvocationDisposition::Panicked,
            ),
            (
                ActorExecutionStatus::OutOfGas,
                InvocationDisposition::OutOfGas,
            ),
        ] {
            let (_, record) = outcome_record(MethodMode::Local, |invocation| {
                Ok(exact_reply(invocation, status, vec![0xa5]))
            });
            assert_eq!(record.disposition(), disposition);
            assert_eq!(record.before, record.after);
            roundtrip(&record);
        }
    }

    #[test]
    fn yielded_slice_cannot_be_encoded_as_a_terminal_invocation_outcome() {
        let input = replay_input(MethodMode::Linear, false);
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            unreachable!()
        };
        let state = outcome_state();
        assert_eq!(
            InvocationOutcomeRecord::from_runtime_states(
                outcome_genesis(),
                InvocationOwnershipScope::Ordered,
                outcome_anchor(MethodMode::Linear),
                &input,
                &state,
                &state,
                Ok(exact_reply(
                    invocation,
                    ActorExecutionStatus::Yielded,
                    Vec::new(),
                )),
            ),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn invocation_outcome_reply_boundary_is_exactly_eight_kibibytes() {
        let (_, record) = outcome_record(MethodMode::Query, |invocation| {
            Ok(exact_reply(
                invocation,
                ActorExecutionStatus::Done,
                vec![0xa5; MAX_EXECUTION_REPLY_BYTES],
            ))
        });
        record.validate().unwrap();
        roundtrip(&record);
        assert!(record.encode().len() <= MAX_INVOCATION_OUTCOME_BYTES);

        let mut oversized = record;
        let Ok(reply) = &mut oversized.result else {
            unreachable!()
        };
        reply.reply.push(0xff);
        assert!(oversized.validate().is_err());
        assert_eq!(
            InvocationOutcomeRecord::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn invocation_outcome_ids_are_sensitive_to_every_security_boundary() {
        let (_, record) = outcome_record(MethodMode::Linear, |invocation| {
            Ok(exact_reply(
                invocation,
                ActorExecutionStatus::Done,
                vec![1, 2, 3],
            ))
        });
        let id = record.id();
        let assert_changed = |candidate: InvocationOutcomeRecord| assert_ne!(candidate.id(), id);

        let mut candidate = record.clone();
        candidate.genesis = AgentJournalGenesisId([0x91; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.key.invocation = InvocationId([0x92; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.request_commitment = Hash([0x93; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.first_input = ReplayInputId([0x94; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.request.program = ProgramId([0x95; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.anchor = InvocationOutcomeAnchor::Ordered {
            entry: OrderedEntryId([0x96; 32]),
        };
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.lane = PersistedLane::Control;
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.node = Some(NodeId([0x97; 32]));
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.before.control.hash = Hash([0x98; 32]);
        assert_changed(candidate);
        let mut candidate = record.clone();
        candidate.after.linear.as_mut().unwrap().hash = Hash([0x99; 32]);
        assert_changed(candidate);
        let mut candidate = record;
        let Ok(reply) = &mut candidate.result else {
            unreachable!()
        };
        reply.reply.push(4);
        assert_changed(candidate);
    }

    #[test]
    fn invocation_outcomes_reject_scope_anchor_node_reply_and_state_mismatches() {
        let (_, record) = outcome_record(MethodMode::Linear, |invocation| {
            Ok(exact_reply(invocation, ActorExecutionStatus::Done, vec![1]))
        });

        let mut invalid = record.clone();
        invalid.anchor = InvocationOutcomeAnchor::Local {
            entry: LocalEntryId([1; 32]),
        };
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = record.clone();
        invalid.node = Some(NodeId([1; 32]));
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = record.clone();
        invalid.lane = PersistedLane::Merge;
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = record.clone();
        invalid.request.actor = ActorId([0xa1; 32]);
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = record.clone();
        invalid.request.gas_limit = 1;
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = record.clone();
        invalid.after.merge.as_mut().unwrap().hash = Hash([0xa2; 32]);
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));

        let (_, terminal) = outcome_record(MethodMode::Merge, |invocation| {
            Ok(exact_reply(
                invocation,
                ActorExecutionStatus::Forbidden,
                Vec::new(),
            ))
        });
        let mut owner_advanced = terminal.clone();
        owner_advanced.after.merge.as_mut().unwrap().hash = Hash([0xa3; 32]);
        owner_advanced.validate().unwrap();
        roundtrip(&owner_advanced);
        let mut invalid = terminal.clone();
        invalid.after.control.hash = Hash([0xa3; 32]);
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));
        let mut invalid = terminal;
        let Ok(reply) = &mut invalid.result else {
            unreachable!()
        };
        reply.observation.merge_frontier = Some(Hash([0xa4; 32]));
        assert_eq!(invalid.validate(), Err(DecodeError::NonCanonical));

        for invalid_anchor in [
            InvocationOutcomeAnchor::Merge {
                source_event: MergeEventId::ZERO,
                finalizing_entry: OrderedEntryId([1; 32]),
                seal: MergeSealId([2; 32]),
            },
            InvocationOutcomeAnchor::Merge {
                source_event: MergeEventId([1; 32]),
                finalizing_entry: OrderedEntryId::ZERO,
                seal: MergeSealId([2; 32]),
            },
            InvocationOutcomeAnchor::Merge {
                source_event: MergeEventId([1; 32]),
                finalizing_entry: OrderedEntryId([2; 32]),
                seal: MergeSealId::ZERO,
            },
        ] {
            assert_eq!(
                invalid_anchor.validate(InvocationOwnershipScope::Merge),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn visible_state_commitments_bind_component_domain_length_and_scope() {
        let state = outcome_state();
        let control =
            VisibleStateComponentCommitment::of_bytes(PersistedLane::Control, &state.control)
                .unwrap();
        let same_bytes_linear =
            VisibleStateComponentCommitment::of_bytes(PersistedLane::Linear, &state.control)
                .unwrap();
        assert_ne!(control, same_bytes_linear);
        assert!(control.matches_bytes(PersistedLane::Control, &state.control));
        assert!(!control.matches_bytes(PersistedLane::Control, &[0x41]));
        assert_ne!(
            VisibleStateComponentCommitment::of_bytes(PersistedLane::Merge, &[])
                .unwrap()
                .hash,
            Hash::ZERO
        );

        let ordered =
            VisibleStateCommitment::from_runtime_state(InvocationOwnershipScope::Ordered, &state)
                .unwrap();
        let merge =
            VisibleStateCommitment::from_runtime_state(InvocationOwnershipScope::Merge, &state)
                .unwrap();
        let local = VisibleStateCommitment::from_runtime_state(
            InvocationOwnershipScope::Local(NodeId([1; 32])),
            &state,
        )
        .unwrap();
        assert_eq!(ordered.local, None);
        assert_eq!(merge.linear, None);
        assert!(local.local.is_some());

        let mut wrong_shape = ordered;
        wrong_shape.local = Some(control);
        assert_eq!(
            wrong_shape.validate(InvocationOwnershipScope::Ordered),
            Err(DecodeError::NonCanonical)
        );
        let mut excessive = local;
        excessive.control.len = MAX_RUNTIME_STATE_BYTES as u64;
        assert_eq!(
            excessive.validate(InvocationOwnershipScope::Local(NodeId([1; 32]))),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn invocation_outcomes_reject_cross_input_and_cross_genesis_transplants() {
        let (input, record) = outcome_record(MethodMode::Local, |invocation| {
            Ok(exact_reply(invocation, ActorExecutionStatus::Done, vec![1]))
        });
        let mut divergent = input.clone();
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = &mut divergent.operation
        else {
            unreachable!()
        };
        invocation.message.push(0xfe);
        authority.claim.authorization = invocation.authorization_message();
        divergent.validate().unwrap();
        assert_eq!(
            record.validate_for(&divergent),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            record.validate_for_genesis(AgentJournalGenesisId([0xee; 32]), &input),
            Err(DecodeError::NonCanonical)
        );

        let reference = InvocationOutcomeRef::for_record(&record).unwrap();
        let mut transplanted = record;
        transplanted.genesis = AgentJournalGenesisId([0xef; 32]);
        assert!(!reference.authenticates(&transplanted));
        assert_ne!(reference.outcome, transplanted.id());
    }

    #[test]
    fn invocation_ownership_leaves_bind_genesis_scope_and_first_input() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let ordered = ownership_leaf(
            genesis,
            InvocationOwnershipScope::Ordered,
            PersistedLane::Linear,
            None,
        );
        ordered.validate().unwrap();
        roundtrip(&ordered);

        let merge = ownership_leaf(
            genesis,
            InvocationOwnershipScope::Merge,
            PersistedLane::Merge,
            None,
        );
        merge.validate().unwrap();
        assert_ne!(ordered.hash(), merge.hash());

        let other_genesis = InvocationOwnershipLeaf {
            genesis: AgentJournalGenesisId([0xc1; 32]),
            ..ordered
        };
        other_genesis.validate().unwrap();
        assert_ne!(other_genesis.hash(), ordered.hash());

        let mut mismatched_scope = merge;
        mismatched_scope.owner.scope = InvocationOwnershipScope::Ordered;
        assert_eq!(mismatched_scope.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn invocation_owner_result_states_bind_exact_lifecycle_data() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let retained = ownership_leaf(
            genesis,
            InvocationOwnershipScope::Ordered,
            PersistedLane::Control,
            None,
        );
        assert_eq!(
            retained.owner.disposition(),
            Some(InvocationDisposition::Applied)
        );
        assert!(retained.owner.outcome().is_some());
        assert!(!retained.owner.is_unfinalized());

        let acknowledged =
            InvocationAcknowledgedFact::from_owner(genesis, retained.key, retained.owner).unwrap();
        acknowledged.validate().unwrap();
        roundtrip(&acknowledged);
        assert_eq!(acknowledged.genesis(), genesis);
        assert_eq!(acknowledged.key(), retained.key);
        assert_eq!(
            acknowledged.request_commitment(),
            retained.owner.request_commitment
        );
        assert_eq!(acknowledged.first_input(), retained.owner.first_input);
        assert_eq!(acknowledged.lane(), retained.owner.lane);
        assert_eq!(acknowledged.node(), retained.owner.node);
        assert_eq!(acknowledged.disposition(), InvocationDisposition::Applied);
        let mut invalid_fact = acknowledged;
        invalid_fact.first_input = ReplayInputId::ZERO;
        assert_eq!(invalid_fact.validate(), Err(DecodeError::NonCanonical));
        let mut invalid_fact = acknowledged;
        invalid_fact.request_commitment = Hash::ZERO;
        assert_eq!(invalid_fact.validate(), Err(DecodeError::NonCanonical));
        assert_eq!(
            InvocationAcknowledgedFact::from_owner(
                genesis,
                InvocationOwnershipKey {
                    scope: InvocationOwnershipScope::Merge,
                    invocation: retained.key.invocation,
                },
                retained.owner,
            ),
            Err(DecodeError::NonCanonical)
        );

        let mut pending_merge = ownership_leaf(
            genesis,
            InvocationOwnershipScope::Merge,
            PersistedLane::Merge,
            None,
        );
        pending_merge.owner.result_state = InvocationResultState::PendingMerge {
            source_event: MergeEventId([0xc2; 32]),
        };
        pending_merge.validate().unwrap();
        assert_eq!(pending_merge.owner.disposition(), None);
        assert!(pending_merge.owner.is_unfinalized());
        assert_eq!(
            pending_merge.owner.reserved_outcome_bytes(),
            MAX_INVOCATION_OUTCOME_BYTES as u64
        );

        let mut pending_acknowledgement = pending_merge;
        pending_acknowledgement.owner.result_state =
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event: MergeEventId([0xc3; 32]),
                disposition: InvocationDisposition::Forbidden,
                outcome: InvocationOutcomeRef {
                    outcome: InvocationOutcomeId([0xc4; 32]),
                    encoded_bytes: 640,
                },
            };
        pending_acknowledgement.validate().unwrap();
        assert!(pending_acknowledgement.owner.is_unfinalized());
        assert_eq!(
            pending_acknowledgement.owner.disposition(),
            Some(InvocationDisposition::Forbidden)
        );
        assert_eq!(pending_acknowledgement.owner.reserved_outcome_bytes(), 640);
        let merge_acknowledged = InvocationAcknowledgedFact::from_owner(
            genesis,
            pending_acknowledgement.key,
            pending_acknowledgement.owner,
        )
        .unwrap();
        assert_eq!(
            merge_acknowledged.disposition(),
            InvocationDisposition::Forbidden
        );

        let mut merge_retained = pending_acknowledgement;
        merge_retained.owner.result_state = InvocationResultState::Retained {
            disposition: InvocationDisposition::Forbidden,
            outcome: InvocationOutcomeRef {
                outcome: InvocationOutcomeId([0xc4; 32]),
                encoded_bytes: 640,
            },
        };
        merge_retained.validate().unwrap();
        assert_eq!(
            InvocationAcknowledgedFact::from_owner(
                genesis,
                merge_retained.key,
                merge_retained.owner,
            ),
            Err(DecodeError::NonCanonical)
        );

        let mut ordered_pending = retained;
        ordered_pending.owner.result_state = InvocationResultState::PendingMerge {
            source_event: MergeEventId([0xc2; 32]),
        };
        assert_eq!(ordered_pending.validate(), Err(DecodeError::NonCanonical));

        pending_merge.owner.result_state = InvocationResultState::PendingMerge {
            source_event: MergeEventId::ZERO,
        };
        assert_eq!(pending_merge.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn transition_proof_retirement_facts_bind_the_exact_key_and_wire_purpose() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let invocation = crate::agent_sdk::InvocationId([0xd1; 32]);
        let first_key = crate::agent_sdk::proof::TransitionProofKey {
            invocation,
            execution: crate::agent_sdk::Hash([0xd2; 32]),
        };
        let second_key = crate::agent_sdk::proof::TransitionProofKey {
            invocation,
            execution: crate::agent_sdk::Hash([0xd3; 32]),
        };
        let first = InvocationAcknowledgedFact::for_transition_proof_retirement(genesis, first_key)
            .unwrap();
        let second =
            InvocationAcknowledgedFact::for_transition_proof_retirement(genesis, second_key)
                .unwrap();

        assert_eq!(first.transition_proof_retirement_key(), Some(first_key));
        assert_eq!(second.transition_proof_retirement_key(), Some(second_key));
        assert_eq!(first.key(), second.key());
        assert_eq!(first.key().invocation.0, invocation.0);
        assert_eq!(first.request_commitment().0, first_key.execution.0);
        assert_eq!(first.first_input().0, first_key.execution.0);
        assert_ne!(first.encode(), second.encode());
        roundtrip(&first);
        roundtrip(&second);

        // Neither the pre-purpose fact nor the prior work-key generation is
        // upgraded implicitly.
        for magic in [b"AGHF", b"AHF2", b"AHF3"] {
            let mut predecessor_wire = first.encode();
            predecessor_wire[..4].copy_from_slice(magic);
            assert!(InvocationAcknowledgedFact::decode(&predecessor_wire).is_err());
        }

        // A purpose-tag substitution can only produce an ordinary fact. It
        // cannot be queried as retirement evidence or admitted to the
        // transition-proof history root.
        let mut cross_purpose = first.encode();
        cross_purpose[4 + 32] = 0;
        let cross_purpose = InvocationAcknowledgedFact::decode(&cross_purpose).unwrap();
        assert_eq!(cross_purpose.transition_proof_retirement_key(), None);
        assert_ne!(cross_purpose.encode(), first.encode());
    }

    #[test]
    fn empty_invocation_indexes_are_explicit_and_scope_separated() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let node = NodeId([7; 32]);
        let ordered = InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Ordered);
        let merge = InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Merge);
        let local = InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Local(node));
        for manifest in [ordered, merge, local] {
            manifest.validate().unwrap();
            roundtrip(&manifest);
            assert_ne!(manifest.id(), InvocationIndexId::ZERO);
        }
        assert_ne!(ordered.id(), merge.id());
        assert_ne!(merge.id(), local.id());

        let missing_root = InvocationIndexManifest {
            entries: 1,
            ..ordered
        };
        assert_eq!(missing_root.validate(), Err(DecodeError::NonCanonical));

        let empty_with_root = InvocationIndexManifest {
            root: Some(InvocationIndexNodeId([0xd1; 32])),
            ..ordered
        };
        assert_eq!(empty_with_root.validate(), Err(DecodeError::NonCanonical));

        let excess_live_entries = InvocationIndexManifest {
            root: Some(InvocationIndexNodeId([0xd1; 32])),
            entries: MAX_INVOCATION_INDEX_LIVE_ENTRIES + 1,
            reserved_outcome_bytes: 1,
            ..ordered
        };
        assert_eq!(
            excess_live_entries.validate(),
            Err(DecodeError::NonCanonical)
        );

        let live_without_reserved_bytes = InvocationIndexManifest {
            root: Some(InvocationIndexNodeId([0xd1; 32])),
            entries: 1,
            ..ordered
        };
        assert_eq!(
            live_without_reserved_bytes.validate(),
            Err(DecodeError::NonCanonical)
        );

        let impossible_unfinalized = InvocationIndexManifest {
            root: Some(InvocationIndexNodeId([0xd1; 32])),
            entries: 2,
            unfinalized: 3,
            reserved_outcome_bytes: 1,
            ..ordered
        };
        assert_eq!(
            impossible_unfinalized.validate(),
            Err(DecodeError::NonCanonical)
        );

        let impossible_outcomes = InvocationIndexManifest {
            root: Some(InvocationIndexNodeId([0xd1; 32])),
            entries: 2,
            outcome_records: 3,
            reserved_outcome_bytes: 1,
            ..ordered
        };
        assert_eq!(
            impossible_outcomes.validate(),
            Err(DecodeError::NonCanonical)
        );

        let history_only = InvocationIndexManifest {
            history_root: Some(InvocationHistoryNodeId([0xd2; 32])),
            ..ordered
        };
        history_only.validate().unwrap();
        roundtrip(&history_only);
        assert_ne!(history_only.id(), ordered.id());

        let zero_history_root = InvocationIndexManifest {
            history_root: Some(InvocationHistoryNodeId::ZERO),
            ..ordered
        };
        assert_eq!(zero_history_root.validate(), Err(DecodeError::NonCanonical));

        let invalid_local =
            InvocationIndexManifest::empty(genesis, InvocationOwnershipScope::Local(NodeId::ZERO));
        assert_eq!(invalid_local.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn replay_inputs_roundtrip_and_bind_the_current_runtime() {
        let create = create_input();
        create.validate().unwrap();
        roundtrip(&create);

        let mut wrong_runtime = create.clone();
        wrong_runtime.runtime.runtime_abi = Hash([0xff; 32]);
        assert_eq!(wrong_runtime.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn replay_size_pass_matches_normal_encoding_and_rejects_changed_blobs() {
        for mode in [
            crate::agent_sdk::MethodMode::Query,
            crate::agent_sdk::MethodMode::LinearizableQuery,
            crate::agent_sdk::MethodMode::Linear,
            crate::agent_sdk::MethodMode::Merge,
            crate::agent_sdk::MethodMode::LocalQuery,
            crate::agent_sdk::MethodMode::Local,
        ] {
            let mut input = public_clean_replay_input(mode);
            let ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } = &mut input.operation
            else {
                unreachable!()
            };
            let bytes = vec![0xab; 128 * 1024];
            work.availability.push(crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
                bytes,
            });
            *authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(work, *observed_slot),
            );
            input.validate_inner().unwrap();
            let normal = input.encode();
            let mut checked = Vec::new();
            checked.extend_from_slice(&ReplayInput::MAGIC);
            checked.extend_from_slice(&crate::service::PLATFORM_ID.0);
            let mut encoder = Encoder(&mut checked);
            encode_runtime_binding(&mut encoder, &input.runtime);
            encode_replay_operation_inner(&mut encoder, &input.operation, true);
            assert_eq!(checked, normal);
            input.validate().unwrap();
            let ReplayOperation::CleanInvoke { work, .. } = &mut input.operation else {
                unreachable!()
            };
            work.availability[0].bytes[0] ^= 1;
            assert_eq!(
                input.validate(),
                Err(DecodeError::NonCanonical),
                "no validation survives mutation of its borrowed input"
            );
        }
    }

    #[test]
    fn borrowed_invocation_authorization_matches_sdk_encoder_validation() {
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight, RuntimeWork};
        for public in [false, true] {
            let input = if public {
                public_clean_replay_input(crate::agent_sdk::MethodMode::Linear)
            } else {
                clean_replay_input(crate::agent_sdk::MethodMode::Linear)
            };
            let ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } = input.operation
            else {
                unreachable!()
            };
            for case in 0..9 {
                let mut work = work.clone();
                let mut authorization = authorization.clone();
                match case {
                    1 => work.gas = 0,
                    2 => work.agent = crate::agent_sdk::AgentId::ZERO,
                    3 => work.message = vec![0; crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES + 1],
                    4..=7 => {
                        let bytes = vec![
                            0xa7;
                            if case == 7 {
                                crate::agent_sdk::MAX_RUNTIME_AVAILABILITY_BYTES
                            } else {
                                128
                            }
                        ];
                        let blob = crate::agent_sdk::RuntimeBlob {
                            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
                            bytes,
                        };
                        work.availability.push(blob.clone());
                        if case == 5 {
                            work.availability[0].bytes[0] ^= 1;
                        }
                        if case == 6 {
                            work.availability.push(blob);
                        }
                    }
                    _ => {}
                }
                // Refresh only the work binding, preserving the malformed
                // preimages/shape being compared by the two validators.
                match &mut authorization {
                    InvocationAuthorization::PublicPreflight(value) => {
                        *value = PublicPreflight::for_work(&work, observed_slot)
                    }
                    InvocationAuthorization::AuthorityReceipt(value) => {
                        value.selector.request = work.commitment()
                    }
                }
                let slot = if case == 8 { 0 } else { observed_slot };
                let sdk = RuntimeWork::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    state: crate::agent_sdk::RuntimeState::default(),
                    invocation: Box::new(work.clone()),
                    authorization: Box::new(authorization.clone()),
                    observed_slot: slot,
                };
                let expected = sdk.encode().is_ok()
                    && work.space.0 == input.runtime.space.0
                    && work.agent.0 == input.runtime.agent.0
                    && work.runtime_deployment.0 == input.runtime.deployment.0;
                assert_eq!(
                    ReplayInput {
                        runtime: input.runtime.clone(),
                        operation: ReplayOperation::CleanInvoke {
                            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                            work,
                            authorization,
                            observed_slot: slot,
                        },
                    }
                    .validate_inner()
                    .is_ok(),
                    expected,
                    "public={public} case={case}"
                );
            }
        }
    }

    #[test]
    fn canonical_runtime_roundtrip_keeps_blob_authentication() {
        use crate::agent_sdk::{
            InvocationAuthorization, PublicPreflight, RuntimeState, RuntimeWork,
        };
        let input = public_clean_replay_input(crate::agent_sdk::MethodMode::Linear);
        let ReplayOperation::CleanInvoke {
            context,
            mut work,
            observed_slot,
            ..
        } = input.operation
        else {
            unreachable!()
        };
        let payload = b"journal single-pass blob validation regression".to_vec();
        let payload_reference = crate::agent_sdk::BlobRef::of_bytes(&payload);
        work.availability.push(crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&payload),
            bytes: payload.clone(),
        });
        let authorization = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
            &work,
            observed_slot,
        ));
        for acknowledgement in [false, true] {
            let canonical = if acknowledgement {
                RuntimeWork::Acknowledge {
                    context,
                    state: RuntimeState::default(),
                    invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
                    authorization: Box::new(authorization.clone()),
                }
            } else {
                RuntimeWork::Invoke {
                    context,
                    state: RuntimeState::default(),
                    invocation: Box::new(work.clone()),
                    authorization: Box::new(authorization.clone()),
                    observed_slot,
                }
            };
            let bytes = canonical.encode().unwrap();
            assert_eq!(decode_canonical_runtime_work(&bytes).unwrap(), canonical);
            let transported = if acknowledgement {
                assert!(!bytes.windows(payload.len()).any(|part| part == payload));
                payload_reference.hash.as_bytes().as_slice()
            } else {
                payload.as_slice()
            };
            let offset = bytes
                .windows(transported.len())
                .position(|part| part == transported)
                .unwrap();
            let mut corrupted = bytes.clone();
            corrupted[offset] ^= 1;
            assert!(
                decode_canonical_runtime_work(&corrupted).is_err(),
                "validation must authenticate the transported preimage or reference"
            );
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode_canonical_runtime_work(&trailing).is_err());
            assert!(decode_canonical_runtime_work(&bytes[..bytes.len() - 1]).is_err());

            let replay = ReplayInput {
                runtime: input.runtime.clone(),
                operation: if acknowledgement {
                    ReplayOperation::CleanAcknowledge {
                        context,
                        expected_live: None,
                        work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                        authorization: authorization.clone(),
                    }
                } else {
                    ReplayOperation::CleanInvoke {
                        context,
                        work: work.clone(),
                        authorization: authorization.clone(),
                        observed_slot,
                    }
                },
            };
            let encoded = replay.encode();
            let mut decoded = ReplayInput::decode(&encoded).unwrap();
            assert_eq!(decoded, replay);
            decoded.validate().unwrap();
            let offset = encoded
                .windows(transported.len())
                .position(|part| part == transported)
                .unwrap();
            let mut corrupted = encoded;
            corrupted[offset] ^= 1;
            assert!(ReplayInput::decode(&corrupted).is_err());

            let mut wrong_runtime = replay.clone();
            wrong_runtime.runtime.agent = AgentId([0x77; 32]);
            assert!(ReplayInput::decode(&wrong_runtime.encode()).is_err());

            match &mut decoded.operation {
                ReplayOperation::CleanInvoke { work, .. } => work.availability[0].bytes[0] ^= 1,
                ReplayOperation::CleanAcknowledge { work, .. } => {
                    work.required[0].hash = crate::agent_sdk::Hash::ZERO
                }
                _ => unreachable!(),
            }
            assert_eq!(decoded.validate(), Err(DecodeError::NonCanonical));
        }
    }

    #[test]
    fn clean_replay_input_roundtrips_losslessly_and_refuses_hidden_state_or_unbound_authority() {
        for (mode, expected_lane) in [
            (crate::agent_sdk::MethodMode::Query, PersistedLane::Control),
            (
                crate::agent_sdk::MethodMode::LinearizableQuery,
                PersistedLane::Linear,
            ),
            (crate::agent_sdk::MethodMode::Linear, PersistedLane::Linear),
            (crate::agent_sdk::MethodMode::Merge, PersistedLane::Merge),
            (
                crate::agent_sdk::MethodMode::LocalQuery,
                PersistedLane::Local,
            ),
            (crate::agent_sdk::MethodMode::Local, PersistedLane::Local),
        ] {
            let input = clean_replay_input(mode);
            input.validate().unwrap();
            assert_eq!(input.persisted_lane(), expected_lane);
            roundtrip(&input);
        }

        let mut unbound = clean_replay_input(crate::agent_sdk::MethodMode::Linear);
        let ReplayOperation::CleanInvoke { authorization, .. } = &mut unbound.operation else {
            unreachable!()
        };
        let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority) = authorization
        else {
            unreachable!()
        };
        authority.selector.request = crate::agent_sdk::Hash([0xa1; 32]);
        assert_eq!(unbound.validate(), Err(DecodeError::NonCanonical));

        let input = clean_replay_input(crate::agent_sdk::MethodMode::Merge);
        let ReplayOperation::CleanInvoke {
            context,
            work,
            authorization,
            observed_slot,
        } = input.operation
        else {
            unreachable!()
        };
        let hidden_state = crate::agent_sdk::RuntimeWork::Invoke {
            context,
            state: crate::agent_sdk::RuntimeState {
                control: vec![1],
                ..crate::agent_sdk::RuntimeState::default()
            },
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot,
        }
        .encode()
        .unwrap();
        let mut encoded = Vec::new();
        let mut encoder = Encoder(&mut encoded);
        encoder.u8(4);
        encoder.bytes(&hidden_state);
        assert_eq!(
            decode_replay_operation(&mut Decoder::new(&encoded)),
            Err(DecodeError::NonCanonical)
        );

        let public = public_clean_replay_input(crate::agent_sdk::MethodMode::Linear);
        public.validate().unwrap();
        roundtrip(&public);
        let mut later_retry = public.clone();
        let ReplayOperation::CleanInvoke { observed_slot, .. } = &mut later_retry.operation else {
            unreachable!()
        };
        *observed_slot += 1;
        later_retry.validate().unwrap();
        roundtrip(&later_retry);
        let mut regressed = public;
        let ReplayOperation::CleanInvoke { observed_slot, .. } = &mut regressed.operation else {
            unreachable!()
        };
        *observed_slot -= 1;
        assert_eq!(regressed.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn clean_resume_and_acknowledgement_replay_inputs_are_exact_bounded_and_state_free() {
        let mut invoked = public_clean_replay_input(crate::agent_sdk::MethodMode::Linear);
        let payload = b"resume decoder blob authentication".to_vec();
        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            observed_slot,
            ..
        } = &mut invoked.operation
        else {
            unreachable!()
        };
        work.availability.push(crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&payload),
            bytes: payload.clone(),
        });
        *authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(work, *observed_slot),
        );
        let ReplayOperation::CleanInvoke {
            context,
            work,
            authorization,
            observed_slot,
        } = &invoked.operation
        else {
            unreachable!()
        };
        let yielded = crate::agent_sdk::YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: crate::agent_sdk::BlobRef::of_bytes(b"durable-clean-continuation"),
            ready_sequence: 3,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        let resume = ReplayInput {
            runtime: invoked.runtime.clone(),
            operation: ReplayOperation::CleanResume {
                context: *context,
                expected_live: None,
                work: work.clone(),
                authorization: authorization.clone(),
                yielded: yielded.clone(),
                observed_slot: observed_slot + 1,
            },
        };
        resume.validate().unwrap();
        assert_eq!(resume.persisted_lane(), PersistedLane::Linear);
        assert!(resume.encode().len() <= MAX_REPLAY_INPUT_BYTES);
        roundtrip(&resume);
        let mut corrupted = resume.encode();
        let offset = corrupted
            .windows(payload.len())
            .position(|part| part == payload)
            .unwrap();
        corrupted[offset] ^= 1;
        assert!(ReplayInput::decode(&corrupted).is_err());
        let mut mutated = ReplayInput::decode(&resume.encode()).unwrap();
        let ReplayOperation::CleanResume {
            work: mutated_work, ..
        } = &mut mutated.operation
        else {
            unreachable!()
        };
        mutated_work.availability[0].bytes[0] ^= 1;
        assert_eq!(mutated.validate(), Err(DecodeError::NonCanonical));

        let acknowledgement = ReplayInput {
            runtime: invoked.runtime.clone(),
            operation: ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                authorization: authorization.clone(),
            },
        };
        acknowledgement.validate().unwrap();
        assert_eq!(acknowledgement.persisted_lane(), PersistedLane::Linear);
        assert!(acknowledgement.encode().len() <= MAX_REPLAY_INPUT_BYTES);
        roundtrip(&acknowledgement);

        let expected_live = crate::agent_sdk::proof::TransitionProofKey {
            invocation: work.invocation,
            execution: crate::agent_sdk::Hash([0xa1; 32]),
        };
        let mut attested_resume = resume.clone();
        let ReplayOperation::CleanResume {
            context,
            expected_live: retained,
            ..
        } = &mut attested_resume.operation
        else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Attested {
            proof_system: crate::agent_sdk::Hash([0xa2; 32]),
        };
        *retained = Some(expected_live);
        attested_resume.validate().unwrap();
        roundtrip(&attested_resume);

        let mut attested_acknowledgement = acknowledgement.clone();
        let ReplayOperation::CleanAcknowledge {
            context,
            expected_live: retained,
            ..
        } = &mut attested_acknowledgement.operation
        else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Attested {
            proof_system: crate::agent_sdk::Hash([0xa2; 32]),
        };
        *retained = Some(expected_live);
        attested_acknowledgement.validate().unwrap();
        roundtrip(&attested_acknowledgement);

        let substituted_live = crate::agent_sdk::proof::TransitionProofKey {
            invocation: work.invocation,
            execution: crate::agent_sdk::Hash([0xa3; 32]),
        };
        let ReplayOperation::CleanResume { expected_live, .. } = &mut attested_resume.operation
        else {
            unreachable!()
        };
        *expected_live = Some(substituted_live);
        assert_ne!(attested_resume.id(), resume.id());
        // The substituted key remains a structurally valid *different*
        // request; storage must compare it to the staged proof capability.
        attested_resume.validate().unwrap();

        for magic in [b"AJI2", b"AJI3"] {
            let mut predecessor_wire = resume.encode();
            predecessor_wire[..4].copy_from_slice(magic);
            assert!(ReplayInput::decode(&predecessor_wire).is_err());
        }

        let mut substituted = resume.clone();
        let ReplayOperation::CleanResume {
            yielded: substituted_yielded,
            ..
        } = &mut substituted.operation
        else {
            unreachable!()
        };
        substituted_yielded.actor = crate::agent_sdk::ActorId([0xd1; 32]);
        assert_eq!(substituted.validate(), Err(DecodeError::NonCanonical));
        assert!(ReplayInput::decode(&substituted.encode()).is_err());

        let hidden_invoke = crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: crate::agent_sdk::RuntimeState {
                linear: vec![1],
                ..crate::agent_sdk::RuntimeState::default()
            },
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: observed_slot + 1,
        }
        .encode()
        .unwrap();
        let yielded_bytes = crate::agent_sdk::RuntimeTransition {
            state: crate::agent_sdk::RuntimeState::default(),
            outcome: crate::agent_sdk::RuntimeOutcome::Yielded(yielded.clone()),
        }
        .encode()
        .unwrap();
        let mut hidden_resume = Vec::new();
        let mut encoder = Encoder(&mut hidden_resume);
        encoder.u8(6);
        encoder.bytes(&hidden_invoke);
        encoder.bytes(&yielded_bytes);
        assert_eq!(
            decode_replay_operation(&mut Decoder::new(&hidden_resume)),
            Err(DecodeError::NonCanonical)
        );

        let hidden_acknowledgement = crate::agent_sdk::RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: crate::agent_sdk::RuntimeState {
                control: vec![1],
                ..crate::agent_sdk::RuntimeState::default()
            },
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        }
        .encode()
        .unwrap();
        let mut hidden_ack = Vec::new();
        let mut encoder = Encoder(&mut hidden_ack);
        encoder.u8(7);
        encoder.bytes(&hidden_acknowledgement);
        assert_eq!(
            decode_replay_operation(&mut Decoder::new(&hidden_ack)),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn clean_manage_tag_five_is_lossless_and_rejects_hostile_sdk_envelopes() {
        let request = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0x31; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0x32; 32]),
        };
        let input = clean_management_input(request.clone());
        input.validate().unwrap();
        assert_eq!(input.persisted_lane(), PersistedLane::Control);
        roundtrip(&input);

        let ReplayOperation::CleanManage {
            authority: base_authority,
            observed_slot: base_observed_slot,
            ..
        } = &input.operation
        else {
            unreachable!()
        };
        let authority = base_authority.clone();
        let observed_slot = *base_observed_slot;
        let canonical_work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: authority.selector.space,
            agent: authority.selector.agent,
            runtime_deployment: authority.selector.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(request.clone()),
            authority: Some(Box::new(authority.clone())),
            observed_slot,
        }
        .encode()
        .unwrap();

        let decode_wrapped = |work: &[u8]| {
            let mut bytes = Vec::new();
            let mut encoder = Encoder(&mut bytes);
            encoder.u8(5);
            encoder.bytes(work);
            decode_replay_operation(&mut Decoder::new(&bytes))
        };

        let mut wrong_space = input.clone();
        {
            let ReplayOperation::CleanManage { authority, .. } = &mut wrong_space.operation else {
                unreachable!()
            };
            authority.selector.space = crate::agent_sdk::SpaceId([0xa1; 32]);
        }
        assert_eq!(wrong_space.validate(), Err(DecodeError::NonCanonical));

        let mut wrong_deployment = input.clone();
        {
            let ReplayOperation::CleanManage { authority, .. } = &mut wrong_deployment.operation
            else {
                unreachable!()
            };
            authority.selector.runtime_deployment = crate::agent_sdk::DeploymentId([0xa2; 32]);
        }
        assert_eq!(wrong_deployment.validate(), Err(DecodeError::NonCanonical));

        let mut hidden_state = crate::agent_sdk::RuntimeWork::decode(&canonical_work).unwrap();
        let crate::agent_sdk::RuntimeWork::Manage { state, .. } = &mut hidden_state else {
            unreachable!()
        };
        state.control.push(1);
        assert_eq!(
            decode_wrapped(&hidden_state.encode().unwrap()),
            Err(DecodeError::NonCanonical)
        );

        let mut attested = crate::agent_sdk::RuntimeWork::decode(&canonical_work).unwrap();
        let crate::agent_sdk::RuntimeWork::Manage { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Attested {
            proof_system: crate::agent_sdk::Hash([0xa4; 32]),
        };
        assert_eq!(
            decode_wrapped(&attested.encode().unwrap()),
            Err(DecodeError::NonCanonical),
            "durable replay must not turn attested work into direct work"
        );

        let missing_receipt = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: authority.selector.space,
            agent: authority.selector.agent,
            runtime_deployment: authority.selector.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(request.clone()),
            authority: None,
            observed_slot,
        }
        .encode();
        assert!(missing_receipt.is_err());

        let inspect = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: authority.selector.space,
            agent: authority.selector.agent,
            runtime_deployment: authority.selector.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(crate::agent_sdk::ManagementRequest::InspectResources),
            authority: None,
            observed_slot,
        }
        .encode()
        .unwrap();
        assert_eq!(decode_wrapped(&inspect), Err(DecodeError::NonCanonical));

        let mut divergent = input.clone();
        let ReplayOperation::CleanManage { authority, .. } = &mut divergent.operation else {
            unreachable!()
        };
        authority.selector.request = crate::agent_sdk::Hash([0xa3; 32]);
        assert_eq!(divergent.validate(), Err(DecodeError::NonCanonical));

        let mut old_magic = canonical_work.clone();
        old_magic[0] ^= 0xff;
        assert!(decode_wrapped(&old_magic).is_err());

        let mut trailing_inner = canonical_work;
        trailing_inner.push(0);
        assert!(decode_wrapped(&trailing_inner).is_err());

        use crate::agent_sdk::wire::CanonicalWire as _;
        let policy = crate::agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_reference = crate::agent_sdk::BlobRef::of_bytes(&policy.encode().unwrap());
        let runtime = runtime_binding();
        let private_request = crate::agent_sdk::ManagementRequest::PrivateControl {
            control: Box::new(crate::agent_sdk::private::PrivateControlRecord {
                space: crate::agent_sdk::SpaceId(runtime.space.0),
                agent: crate::agent_sdk::AgentId(runtime.agent.0),
                sequence: 0,
                previous: None,
                operation: crate::agent_sdk::private::PrivateControlOperation::SetResourcePolicy {
                    policy: policy_reference,
                },
                signer: crate::agent_sdk::private::PrivateControlSigner::Owner,
                signer_public_key: [0xa5; 32],
                signature: [0xa6; crate::agent_sdk::private::PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: Box::new(crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(
                policy,
            )),
        };
        assert!(private_request.is_valid());
        let private = clean_management_input(private_request);
        assert_eq!(
            private.validate(),
            Err(DecodeError::NonCanonical),
            "Private runtime controls must never enter generic CleanManage replay"
        );

        let old_runtime_call = RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
        )
        .encode();
        assert!(decode_wrapped(&old_runtime_call).is_err());

        let mut trailing_outer = input.encode();
        trailing_outer.push(0);
        assert!(ReplayInput::decode(&trailing_outer).is_err());
    }

    #[test]
    fn receipt_window_is_execution_state_not_wire_canonicality() {
        let mut invoke = replay_input(MethodMode::Linear, false);
        let ReplayOperation::Invoke { observed_slot, .. } = &mut invoke.operation else {
            unreachable!();
        };
        *observed_slot = 21;
        invoke.validate().unwrap();
        roundtrip(&invoke);

        let mut management = management_input(
            LifecycleRequest::Suspend {
                actor: ActorId([0x31; 32]),
                expected_deployment: DeploymentId([0x32; 32]),
            },
            "actor.lifecycle",
        );
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, .. },
        } = &mut management.operation
        else {
            unreachable!();
        };
        admission.observed_slot = 21;
        management.validate().unwrap();
        roundtrip(&management);
    }

    #[test]
    fn replay_input_codec_rejects_a_zero_actor_incarnation() {
        let mut input = replay_input(MethodMode::Linear, false);
        let ReplayOperation::Invoke { invocation, .. } = &mut input.operation else {
            unreachable!();
        };
        invocation.incarnation = Hash::ZERO;
        assert_eq!(
            ReplayInput::decode(&input.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn invocation_and_acknowledgement_derive_the_same_result_lane() {
        for (mode, lane) in [
            (MethodMode::Query, PersistedLane::Control),
            (MethodMode::LinearizableQuery, PersistedLane::Linear),
            (MethodMode::Linear, PersistedLane::Linear),
            (MethodMode::Merge, PersistedLane::Merge),
            (MethodMode::LocalQuery, PersistedLane::Local),
            (MethodMode::Local, PersistedLane::Local),
        ] {
            let invoke = replay_input(mode, false);
            let acknowledge = replay_input(mode, true);
            assert_eq!(invoke.persisted_lane(), lane);
            assert_eq!(acknowledge.persisted_lane(), lane);
            invoke.validate().unwrap();
            acknowledge.validate().unwrap();
            roundtrip(&invoke);
            roundtrip(&acknowledge);
        }
    }

    #[test]
    fn seal_merge_is_a_canonical_unit_control_operation() {
        let input = ReplayInput {
            runtime: runtime_binding(),
            operation: ReplayOperation::SealMerge,
        };
        assert_eq!(input.persisted_lane(), PersistedLane::Control);
        input.validate().unwrap();
        roundtrip(&input);

        let mut encoded = Vec::new();
        encode_replay_operation(&mut Encoder(&mut encoded), &ReplayOperation::SealMerge);
        assert_eq!(encoded, vec![3]);
        let mut decoder = Decoder::new(&encoded);
        assert_eq!(
            decode_replay_operation(&mut decoder),
            Ok(ReplayOperation::SealMerge)
        );
        assert!(decoder.exhausted());

        let mut unknown = Decoder::new(&[0xff]);
        assert_eq!(
            decode_replay_operation(&mut unknown),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn raw_replay_management_rejects_a_runtime_journal_context() {
        let scope = super::super::system_authority::SystemAuthorityJournalScope::for_test(
            AgentJournalGenesisId::new([0x91; 32]),
            AgentGenesisAdmissionId::from_bytes([0x92; 32]),
        )
        .unwrap();
        let call = RuntimeCall::scoped_system_authority(
            RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
            scope,
        );
        let mut encoded = Vec::new();
        let mut encoder = Encoder(&mut encoded);
        encoder.u8(0);
        encoder.bytes(&call.encode());

        let mut decoder = Decoder::new(&encoded);
        assert_eq!(
            decode_replay_operation(&mut decoder),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn acknowledgement_retains_the_exact_original_invocation_and_receipt() {
        let mut acknowledge = replay_input(MethodMode::Merge, true);
        let ReplayOperation::Acknowledge {
            invocation,
            authority,
        } = &mut acknowledge.operation
        else {
            unreachable!();
        };
        invocation.message.push(4);
        let _ = authority;
        assert_eq!(acknowledge.validate(), Err(DecodeError::NonCanonical));

        let ReplayOperation::Acknowledge { authority, .. } = &mut acknowledge.operation else {
            unreachable!();
        };
        authority.claim.authorization = Hash([0x55; 32]);
        assert_eq!(acknowledge.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn read_only_or_unadmitted_management_work_is_not_journal_input() {
        let mut input = create_input();
        input.operation = ReplayOperation::Management {
            request: LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
        };
        assert_eq!(input.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn genesis_binds_the_authorized_create_input() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        };
        genesis.validate().unwrap();
        roundtrip(&genesis);
        assert_eq!(
            *genesis.id().as_bytes(),
            [
                100, 126, 151, 208, 79, 161, 120, 93, 229, 99, 189, 130, 254, 12, 113, 234, 91, 57,
                29, 10, 29, 215, 81, 217, 222, 212, 99, 231, 214, 145, 243, 72,
            ]
        );
        let legacy_id = content_id(b"vos/agent/journal/genesis", &genesis);
        assert_eq!(
            legacy_id,
            [
                66, 18, 155, 91, 217, 154, 10, 183, 124, 57, 176, 0, 40, 2, 87, 193, 179, 180, 140,
                137, 194, 175, 160, 76, 227, 210, 26, 182, 43, 113, 127, 133,
            ]
        );
        assert_ne!(*genesis.id().as_bytes(), legacy_id);
        let mut legacy_wire = genesis.encode();
        legacy_wire[..4].copy_from_slice(b"AGJG");
        assert_eq!(
            AgentJournalGenesis::decode(&legacy_wire),
            Err(DecodeError::InvalidTag)
        );
        let ReplayOperation::Management { request: outer } = &genesis.create.operation else {
            unreachable!();
        };
        let LifecycleRequest::Authorized { request, .. } = outer else {
            unreachable!();
        };
        assert_eq!(
            genesis.genesis_intent().unwrap(),
            GenesisIntentId::from_commitments(genesis.runtime().commitment(), request.commitment())
                .unwrap()
        );
        assert_eq!(genesis.genesis_authority_sequence(), Ok(1));

        let mut wrong = genesis.clone();
        wrong.create.runtime.program = ProgramId([0xee; 32]);
        assert_eq!(wrong.validate(), Err(DecodeError::NonCanonical));

        let mut missing_admission = genesis.clone();
        missing_admission.admission = AgentGenesisAdmissionId::ZERO;
        assert_eq!(missing_admission.validate(), Err(DecodeError::NonCanonical));

        let mut alternate_admission = genesis.clone();
        alternate_admission.admission = AgentGenesisAdmissionId::from_bytes([0xae; 32]);
        alternate_admission.validate().unwrap();
        assert_ne!(alternate_admission.id(), genesis.id());

        let mut alternate_runtime = genesis.runtime().clone();
        alternate_runtime.package = BlobRef::of_bytes(b"alternate-runtime");
        assert_ne!(
            alternate_runtime.commitment(),
            genesis.runtime().commitment()
        );
    }

    #[test]
    fn physical_record_classes_reject_the_wrong_lane() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let ordered = OrderedEntry {
            genesis,
            index: 1,
            parent: None,
            merge_frontier: empty_frontier(genesis),
            merge_seal: None,
            input: replay_input(MethodMode::Linear, false),
        };
        ordered.validate().unwrap();
        roundtrip(&ordered);

        let wrong_ordered = OrderedEntry {
            input: replay_input(MethodMode::Merge, false),
            ..ordered.clone()
        };
        assert_eq!(wrong_ordered.validate(), Err(DecodeError::NonCanonical));

        let local = LocalEntry {
            genesis,
            node: NodeId([7; 32]),
            revision: 1,
            parent: None,
            ordered_base: OrderedBase::post_genesis(),
            merge_frontier: empty_frontier(genesis),
            input: replay_input(MethodMode::Local, false),
        };
        local.validate().unwrap();
        roundtrip(&local);
    }

    #[test]
    fn management_and_seal_only_entries_require_a_merge_fence() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let input = management_input(
            LifecycleRequest::Suspend {
                actor: ActorId([0x31; 32]),
                expected_deployment: DeploymentId([0x32; 32]),
            },
            "actor.lifecycle",
        );
        let mut entry = OrderedEntry {
            genesis,
            index: 1,
            parent: None,
            merge_frontier: empty_frontier(genesis),
            merge_seal: None,
            input,
        };
        assert_eq!(entry.validate(), Err(DecodeError::NonCanonical));
        entry.merge_seal = Some(MergeSealId([0x33; 32]));
        entry.validate().unwrap();
        roundtrip(&entry);

        let mut seal_only = OrderedEntry {
            input: ReplayInput {
                runtime: runtime_binding(),
                operation: ReplayOperation::SealMerge,
            },
            ..entry.clone()
        };
        seal_only.validate().unwrap();
        roundtrip(&seal_only);
        seal_only.merge_seal = None;
        assert_eq!(seal_only.validate(), Err(DecodeError::NonCanonical));

        let invoke_with_seal = OrderedEntry {
            input: replay_input(MethodMode::Linear, false),
            ..entry.clone()
        };
        assert_eq!(invoke_with_seal.validate(), Err(DecodeError::NonCanonical));
        let acknowledge_with_seal = OrderedEntry {
            input: replay_input(MethodMode::Linear, true),
            ..entry.clone()
        };
        assert_eq!(
            acknowledge_with_seal.validate(),
            Err(DecodeError::NonCanonical)
        );

        let create = OrderedEntry {
            input: create_input(),
            ..entry
        };
        assert_eq!(create.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn merge_parents_and_frontiers_are_strictly_bounded_and_sorted() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let event = MergeEvent {
            genesis,
            committee: None,
            author: NodeId([7; 32]),
            ordered_base: OrderedBase::post_genesis(),
            causal_height: 1,
            parents: Vec::new(),
            input: replay_input(MethodMode::Merge, false),
            signature: vec![3; ED25519_SIGNATURE_BYTES],
        };
        event.validate().unwrap();
        roundtrip(&event);

        let event_id = event.id();
        let frontier = MergeFrontier {
            genesis,
            events: vec![event_id],
        };
        frontier.validate().unwrap();
        roundtrip(&frontier);

        let duplicate = MergeFrontier {
            genesis,
            events: vec![event_id, event_id],
        };
        assert_eq!(duplicate.validate(), Err(DecodeError::NonCanonical));

        let oversized = MergeFrontier {
            genesis,
            events: (0..=MAX_MERGE_FRONTIER_ENTRIES)
                .map(|index| MergeEventId([(index & 0xff) as u8; 32]))
                .collect(),
        };
        assert_eq!(oversized.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn derived_manifests_roundtrip_with_explicit_lane_cursors() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let ordered_head = OrderedEntryId([1; 32]);
        let lane_state = LaneStateManifest {
            #[cfg(feature = "experimental-state-blocks")]
            external_root: None,
            genesis,
            runtime: runtime_binding(),
            lane: PersistedLane::Control,
            cursor: LaneCursor::Ordered {
                base: OrderedBase {
                    index: 1,
                    head: Some(ordered_head),
                },
            },
            state: BlobRef::of_bytes(b"control-state"),
        };
        lane_state.validate().unwrap();
        roundtrip(&lane_state);

        let closure = ArtifactClosure {
            genesis,
            artifacts: vec![BlobRef::of_bytes(b"artifact")],
        };
        closure.validate().unwrap();
        roundtrip(&closure);

        let checkpoint = CheckpointManifest {
            clean_management: None,
            genesis,
            admission: genesis_admission(),
            runtime: runtime_binding(),
            publication_revision: 1,
            ordered_head: Some(ordered_head),
            ordered_index: 1,
            merge_frontier: empty_frontier(genesis),
            merge_fence: OrderedBase::post_genesis(),
            merge_seal: None,
            ordered_invocations: empty_index(genesis, InvocationOwnershipScope::Ordered),
            merge_invocations: empty_index(genesis, InvocationOwnershipScope::Merge),
            transition_proofs: empty_transition_proof_index(genesis),
            lanes: vec![CheckpointLane {
                lane: PersistedLane::Control,
                node: None,
                state: lane_state.id(),
                invocations: None,
            }],
            artifacts: closure.id(),
        };
        checkpoint.validate().unwrap();
        roundtrip(&checkpoint);
        let mut with_evidence = checkpoint.clone();
        with_evidence.clean_management = Some(CleanManagementEvidence {
            input: ReplayInputId([0x71; 32]),
            ordered: OrderedBase {
                index: 1,
                head: Some(ordered_head),
            },
            authority: crate::agent_sdk::Hash([0x72; 32]),
            request: crate::agent_sdk::Hash([0x73; 32]),
            epoch: 1,
            sequence: 2,
            observed_slot: 10,
            result: Ok(crate::agent_sdk::ManagementReply::Removed(
                crate::agent_sdk::ActorId([0x74; 32]),
            )),
        });
        roundtrip(&with_evidence);
        assert_ne!(with_evidence.id(), checkpoint.id());
        let mut substituted = with_evidence.clone();
        substituted.clean_management.as_mut().unwrap().request = crate::agent_sdk::Hash([0x75; 32]);
        assert_ne!(substituted.id(), with_evidence.id());
        substituted.clean_management.as_mut().unwrap().authority = crate::agent_sdk::Hash::ZERO;
        assert!(substituted.validate().is_err());
        let mut future = with_evidence.clone();
        future.clean_management.as_mut().unwrap().ordered.index = 2;
        assert!(future.validate().is_err());
        let mut wrong_head = with_evidence.clone();
        wrong_head.clean_management.as_mut().unwrap().ordered.head =
            Some(OrderedEntryId([0x76; 32]));
        assert!(wrong_head.validate().is_err());
        assert_eq!(
            *checkpoint.id().as_bytes(),
            [
                161, 174, 35, 10, 111, 12, 202, 156, 167, 99, 174, 146, 191, 35, 252, 61, 214, 238,
                121, 138, 157, 62, 104, 143, 140, 36, 106, 14, 113, 101, 235, 189,
            ]
        );
        let legacy_id = content_id(b"vos/agent/journal/checkpoint", &checkpoint);
        assert_eq!(
            legacy_id,
            [
                212, 45, 120, 182, 125, 38, 68, 204, 173, 57, 164, 38, 42, 217, 36, 53, 159, 10,
                234, 17, 33, 167, 73, 76, 69, 154, 139, 241, 245, 66, 129, 176,
            ]
        );
        assert_ne!(*checkpoint.id().as_bytes(), legacy_id);
        for predecessor_magic in [b"AJC3", b"AJC2", b"AGJC"] {
            let mut predecessor_wire = checkpoint.encode();
            predecessor_wire[..4].copy_from_slice(predecessor_magic);
            assert_eq!(
                CheckpointManifest::decode(&predecessor_wire),
                Err(DecodeError::InvalidTag)
            );
        }
    }

    #[test]
    fn post_genesis_empty_agent_checkpoint_is_representable() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let node = NodeId([0x71; 32]);
        let control = LaneStateManifest {
            #[cfg(feature = "experimental-state-blocks")]
            external_root: None,
            genesis,
            runtime: runtime_binding(),
            lane: PersistedLane::Control,
            cursor: LaneCursor::Ordered {
                base: OrderedBase::post_genesis(),
            },
            state: BlobRef::of_bytes(b"post-genesis-control"),
        };
        control.validate().unwrap();
        roundtrip(&control);

        let local = LaneStateManifest {
            #[cfg(feature = "experimental-state-blocks")]
            external_root: None,
            genesis,
            runtime: runtime_binding(),
            lane: PersistedLane::Local,
            cursor: LaneCursor::Local {
                node,
                revision: 0,
                head: None,
            },
            state: BlobRef::of_bytes(b"post-genesis-local"),
        };
        local.validate().unwrap();
        roundtrip(&local);

        let mut noncanonical_local = local.clone();
        noncanonical_local.cursor = LaneCursor::Local {
            node,
            revision: 0,
            head: Some(LocalEntryId([0x72; 32])),
        };
        assert_eq!(
            noncanonical_local.validate(),
            Err(DecodeError::NonCanonical)
        );

        let closure = ArtifactClosure {
            genesis,
            artifacts: vec![runtime_binding().package],
        };
        closure.validate().unwrap();
        let checkpoint = CheckpointManifest {
            genesis,
            clean_management: None,
            admission: genesis_admission(),
            runtime: runtime_binding(),
            publication_revision: 0,
            ordered_head: None,
            ordered_index: 0,
            merge_frontier: empty_frontier(genesis),
            merge_fence: OrderedBase::post_genesis(),
            merge_seal: None,
            ordered_invocations: empty_index(genesis, InvocationOwnershipScope::Ordered),
            merge_invocations: empty_index(genesis, InvocationOwnershipScope::Merge),
            transition_proofs: empty_transition_proof_index(genesis),
            lanes: vec![CheckpointLane {
                lane: PersistedLane::Control,
                node: None,
                state: control.id(),
                invocations: None,
            }],
            artifacts: closure.id(),
        };
        checkpoint.validate().unwrap();
        roundtrip(&checkpoint);
    }

    #[test]
    fn checkpoint_lane_keys_are_unique_and_local_state_is_node_scoped() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let base = CheckpointManifest {
            clean_management: None,
            genesis,
            admission: genesis_admission(),
            runtime: runtime_binding(),
            publication_revision: 1,
            ordered_head: Some(OrderedEntryId([1; 32])),
            ordered_index: 1,
            merge_frontier: empty_frontier(genesis),
            merge_fence: OrderedBase::post_genesis(),
            merge_seal: None,
            ordered_invocations: empty_index(genesis, InvocationOwnershipScope::Ordered),
            merge_invocations: empty_index(genesis, InvocationOwnershipScope::Merge),
            transition_proofs: empty_transition_proof_index(genesis),
            lanes: vec![CheckpointLane {
                lane: PersistedLane::Control,
                node: None,
                state: LaneStateId([2; 32]),
                invocations: None,
            }],
            artifacts: ArtifactClosureId([3; 32]),
        };
        let mut duplicate = base.clone();
        duplicate.lanes.push(duplicate.lanes[0].clone());
        assert_eq!(duplicate.validate(), Err(DecodeError::NonCanonical));

        let mut scoped_local = base.clone();
        scoped_local.lanes.push(CheckpointLane {
            lane: PersistedLane::Local,
            node: Some(NodeId([7; 32])),
            state: LaneStateId([4; 32]),
            invocations: Some(empty_index(
                genesis,
                InvocationOwnershipScope::Local(NodeId([7; 32])),
            )),
        });
        scoped_local.validate().unwrap();
        roundtrip(&scoped_local);

        let mut unscoped_local = base;
        unscoped_local.lanes.push(CheckpointLane {
            lane: PersistedLane::Local,
            node: None,
            state: LaneStateId([4; 32]),
            invocations: Some(empty_index(
                genesis,
                InvocationOwnershipScope::Local(NodeId([7; 32])),
            )),
        });
        assert_eq!(unscoped_local.validate(), Err(DecodeError::NonCanonical));

        let mut local_without_index = unscoped_local.clone();
        let local = local_without_index.lanes.last_mut().unwrap();
        local.node = Some(NodeId([7; 32]));
        local.invocations = None;
        assert_eq!(
            local_without_index.validate(),
            Err(DecodeError::NonCanonical)
        );

        let mut indexed_control = unscoped_local;
        indexed_control.lanes.pop();
        indexed_control.lanes[0].invocations =
            Some(empty_index(genesis, InvocationOwnershipScope::Ordered));
        assert_eq!(indexed_control.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn heads_are_predecessor_bound_cas_envelopes() {
        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        }
        .id();
        let initial = JournalHeads::initial(
            genesis,
            genesis_admission(),
            NodeId([7; 32]),
            empty_frontier(genesis),
            runtime_binding(),
        );
        initial.validate().unwrap();
        roundtrip(&initial);
        assert_eq!(
            *initial.id().as_bytes(),
            [
                240, 29, 90, 69, 13, 29, 186, 4, 142, 154, 83, 21, 145, 7, 44, 151, 54, 168, 203,
                135, 111, 135, 248, 109, 178, 191, 95, 61, 66, 254, 23, 39,
            ]
        );
        let legacy_id = content_id(b"vos/agent/journal/heads", &initial);
        assert_eq!(
            legacy_id,
            [
                209, 0, 21, 146, 65, 130, 33, 62, 53, 212, 55, 81, 230, 75, 228, 253, 127, 151,
                123, 251, 39, 204, 61, 29, 161, 45, 105, 183, 149, 36, 109, 139,
            ]
        );
        assert_ne!(*initial.id().as_bytes(), legacy_id);
        for predecessor_magic in [b"AJH2", b"AGJH"] {
            let mut predecessor_wire = initial.encode();
            predecessor_wire[..4].copy_from_slice(predecessor_magic);
            assert_eq!(
                JournalHeads::decode(&predecessor_wire),
                Err(DecodeError::InvalidTag)
            );
        }
        assert_eq!(initial.runtime, runtime_binding());
        assert_eq!(
            initial.ordered_invocations,
            empty_index(genesis, InvocationOwnershipScope::Ordered)
        );
        assert_eq!(
            initial.merge_invocations,
            empty_index(genesis, InvocationOwnershipScope::Merge)
        );
        assert_eq!(
            initial.local_invocations,
            empty_index(genesis, InvocationOwnershipScope::Local(NodeId([7; 32])))
        );
        assert_eq!(
            initial.transition_proofs,
            empty_transition_proof_index(genesis)
        );

        let mut zero_proof_root = initial.clone();
        zero_proof_root.transition_proofs = TransitionProofIndexId::ZERO;
        assert_eq!(zero_proof_root.validate(), Err(DecodeError::NonCanonical));
        let nonempty_proof_root =
            super::super::transition_proof_journal::TransitionProofIndexManifest::empty(genesis)
                .publish(
                    super::super::transition_proof_journal::TransitionProofIndexEntry {
                        key: crate::agent_sdk::proof::TransitionProofKey {
                            invocation: crate::agent_sdk::InvocationId([0xeb; 32]),
                            execution: crate::agent_sdk::Hash([0xec; 32]),
                        },
                        record: TransitionProofEntryId([0xed; 32]),
                        proof_material_bytes: 1,
                    },
                    None,
                )
                .unwrap()
                .id();
        let mut nonempty_initial_root = initial.clone();
        nonempty_initial_root.transition_proofs = nonempty_proof_root;
        assert_eq!(
            nonempty_initial_root.validate(),
            Err(DecodeError::NonCanonical)
        );

        let next = JournalHeads {
            publication_revision: 1,
            previous: Some(initial.id()),
            ordered_head: Some(OrderedEntryId([1; 32])),
            ordered_index: 1,
            ..initial.clone()
        };
        initial.validate_successor(&next).unwrap();
        roundtrip(&next);

        // Generic envelope validation permits the dedicated proof publisher to
        // advance only this authenticated root. Ordinary publication
        // validators enforce preservation for their own record classes.
        let proof_successor = JournalHeads {
            publication_revision: 1,
            previous: Some(initial.id()),
            transition_proofs: nonempty_proof_root,
            ..initial.clone()
        };
        initial.validate_successor(&proof_successor).unwrap();
        roundtrip(&proof_successor);

        let mut wrong = next;
        wrong.previous = Some(JournalHeadsId([0xff; 32]));
        assert_eq!(
            initial.validate_successor(&wrong),
            Err(DecodeError::NonCanonical)
        );

        let mut wrong_runtime = JournalHeads {
            previous: Some(initial.id()),
            ..initial.clone()
        };
        wrong_runtime.publication_revision = 1;
        wrong_runtime.runtime.agent = AgentId([0xee; 32]);
        assert_eq!(
            initial.validate_successor(&wrong_runtime),
            Err(DecodeError::NonCanonical)
        );

        let mut wrong_admission = JournalHeads {
            previous: Some(initial.id()),
            ..initial.clone()
        };
        wrong_admission.publication_revision = 1;
        wrong_admission.admission = AgentGenesisAdmissionId::from_bytes([0xaf; 32]);
        assert_eq!(
            initial.validate_successor(&wrong_admission),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn object_id_domains_are_stable_and_separate() {
        let input = replay_input(MethodMode::Linear, false);
        assert_eq!(input.id(), input.clone().id());

        let genesis = AgentJournalGenesis {
            admission: genesis_admission(),
            create: create_input(),
        };
        let ordered = OrderedEntry {
            genesis: genesis.id(),
            index: 1,
            parent: None,
            merge_frontier: empty_frontier(genesis.id()),
            merge_seal: None,
            input,
        };
        assert_ne!(genesis.id().0, ordered.id().0);
    }

    #[test]
    fn decode_rejects_trailing_or_over_limit_envelopes() {
        let input = replay_input(MethodMode::Linear, false);
        let mut trailing = input.encode();
        trailing.push(0);
        assert_eq!(
            ReplayInput::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );

        let mut oversized = input.encode();
        oversized.resize(MAX_REPLAY_INPUT_BYTES + 1, 0);
        assert_eq!(
            ReplayInput::decode(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn clean_platform_header_rejects_previous_generation_bytes() {
        let input = replay_input(MethodMode::Linear, false);
        let mut bytes = input.encode();
        bytes[4] ^= 1;
        assert_eq!(
            ReplayInput::decode(&bytes),
            Err(DecodeError::InvalidPlatform)
        );
    }

    #[test]
    fn profile_lane_assumptions_remain_explicit() {
        assert!(AgentProfile::Local.supports(StateLane::Linear));
        assert!(AgentProfile::Shared.supports(StateLane::Merge));
        assert!(!AgentProfile::Private.supports(StateLane::Linear));
    }

    #[test]
    fn anonymous_receipt_shape_does_not_smuggle_an_authenticated_origin() {
        let mut input = replay_input(MethodMode::Merge, false);
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = &mut input.operation
        else {
            unreachable!();
        };
        invocation.auth.origin = Origin::Member(crate::service::SubjectId([1; 32]));
        authority.claim.auth = invocation.auth.clone();
        authority.claim.authorization = invocation.authorization_message();
        assert_eq!(input.validate(), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn artifact_closure_bounds_count_and_aggregate_referenced_bytes() {
        let genesis = AgentJournalGenesisId([0xa7; 32]);
        let artifacts = (1..=MAX_ARTIFACT_CLOSURE_ENTRIES)
            .map(|index| {
                let mut hash = [0_u8; 32];
                hash[24..].copy_from_slice(&(index as u64).to_be_bytes());
                BlobRef {
                    hash: Hash(hash),
                    len: 1,
                }
            })
            .collect::<Vec<_>>();
        let at_count_limit = ArtifactClosure { genesis, artifacts };
        at_count_limit.validate().unwrap();
        roundtrip(&at_count_limit);

        let mut over_count = at_count_limit.clone();
        let mut hash = [0_u8; 32];
        hash[24..].copy_from_slice(&((MAX_ARTIFACT_CLOSURE_ENTRIES + 1) as u64).to_be_bytes());
        over_count.artifacts.push(BlobRef {
            hash: Hash(hash),
            len: 1,
        });
        assert_eq!(over_count.validate(), Err(DecodeError::LimitExceeded));
        assert_eq!(
            ArtifactClosure::decode(&over_count.encode()),
            Err(DecodeError::LimitExceeded)
        );

        let over_bytes = ArtifactClosure {
            genesis,
            artifacts: (1_u8..=9)
                .map(|tag| BlobRef {
                    hash: Hash([tag; 32]),
                    len: MAX_ARTIFACT_CLOSURE_BYTES as u64,
                })
                .collect(),
        };
        assert!(
            over_bytes
                .artifacts
                .iter()
                .map(|artifact| artifact.len)
                .sum::<u64>()
                > MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES
        );
        assert_eq!(over_bytes.validate(), Err(DecodeError::LimitExceeded));
        assert_eq!(
            ArtifactClosure::decode(&over_bytes.encode()),
            Err(DecodeError::LimitExceeded)
        );

        let same_hash_different_length = ArtifactClosure {
            genesis,
            artifacts: vec![
                BlobRef {
                    hash: Hash([0x44; 32]),
                    len: 1,
                },
                BlobRef {
                    hash: Hash([0x44; 32]),
                    len: 2,
                },
            ],
        };
        assert_eq!(
            same_hash_different_length.validate(),
            Err(DecodeError::NonCanonical)
        );
        assert_eq!(
            ArtifactClosure::decode(&same_hash_different_length.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn genesis_output_commitments_are_canonical_and_cycle_free() {
        let state = RuntimeState {
            control: vec![1, 2],
            linear: vec![3],
            merge: vec![4, 5],
            local: vec![6],
        };
        let state_commitment = system_genesis_post_create_state_commitment(&state).unwrap();
        assert_eq!(
            state_commitment,
            system_genesis_post_create_state_commitment(&state).unwrap()
        );
        let mut lane_swapped = state.clone();
        core::mem::swap(&mut lane_swapped.linear, &mut lane_swapped.local);
        lane_swapped.local.push(7);
        assert_ne!(
            state_commitment,
            system_genesis_post_create_state_commitment(&lane_swapped).unwrap()
        );

        let mut artifacts = vec![
            BlobRef::of_bytes(b"artifact-a"),
            BlobRef::of_bytes(b"artifact-b"),
        ];
        artifacts.sort_by_key(|artifact| (artifact.hash, artifact.len));
        let first = ArtifactClosure {
            genesis: AgentJournalGenesisId([0xa7; 32]),
            artifacts: artifacts.clone(),
        };
        let second = ArtifactClosure {
            genesis: AgentJournalGenesisId([0xa8; 32]),
            artifacts,
        };
        first.validate().unwrap();
        second.validate().unwrap();
        assert_ne!(first.id(), second.id());
        assert_eq!(
            first.system_genesis_commitment().unwrap(),
            second.system_genesis_commitment().unwrap()
        );

        let mut alternate = second.artifacts.clone();
        alternate.push(BlobRef::of_bytes(b"artifact-c"));
        alternate.sort_by_key(|artifact| (artifact.hash, artifact.len));
        assert_ne!(
            first.system_genesis_commitment().unwrap(),
            system_genesis_artifact_closure_commitment(&alternate).unwrap()
        );
    }
}
