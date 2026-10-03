//! Crash-safe Raft routing and application evidence for Shared Agents.
//!
//! The clean-generation storage foundation classifies every committed physical
//! Raft slot as a leader no-op, canonical [`AgentRaftCommand`], or bounded
//! membership change. It advances its V2 audit cursor and Raft `last_applied`
//! atomically for leader no-ops and the application-authorized two-slot
//! committee-transition barrier. Ordinary commands cross a generation/store/
//! replica-bound reservation before the Shared journal driver executes them;
//! live transport-worker attachment remains a later integration slice.
//! Applying an ordered command and publishing its exact [`OrderedCommitClaim`]
//! are separate from signing: the evidence ledger first anchors that applied
//! claim, then commits an immutable pledge, and only then invokes a replica
//! signer.
//!
//! The V2 application ledger installs only an exact voter-majority Agent
//! snapshot certificate. Snapshot identity includes the full generation,
//! physical journal store and local replica, active committee and transition
//! evidence, ordered boundary, and journal roots. Certificate installation
//! atomically advances the Raft snapshot cursor and retires only that
//! generation's authenticated log/audit prefix.

use alloc::vec::Vec;
use core::fmt;

use super::genesis::{
    AgentGenesisAdmissionId, AgentReplicaCommittee, AgentReplicaCommitteeId,
    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
};
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, JournalHeadsId, MAX_JOURNAL_RECORD_BYTES,
    OrderedEntry, OrderedEntryId,
};
#[cfg(feature = "storage")]
use super::journal::{OrderedBase, ReplayInput, ReplayOperation};
#[cfg(all(feature = "std", feature = "storage"))]
use super::replay::PublishedSharedOrdered;
#[cfg(feature = "storage")]
use super::shared_commit::{
    MAX_ORDERED_COMMIT_CLAIM_BYTES, MAX_REPLICA_COMMIT_SIGNATURE_BYTES,
    MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
    MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
    MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES,
    MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES, MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES,
    ReplicaCommitSignature, ReplicaQuorumCertificate, SharedAgentCommonSnapshotCertificate,
    SharedAgentLocalSnapshotBinding, SharedAgentPortableSnapshotCertificate,
    SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim, VerifiedSharedAgentPortableSnapshot,
};
use super::shared_commit::{OrderedCommitClaim, SharedCommitError};
#[cfg(feature = "storage")]
use super::shared_recovery::SharedRecoveryExpiryTerminal;
#[cfg(feature = "storage")]
use super::shared_recovery::SharedRecoverySlot;
use super::shared_recovery::{
    MAX_SHARED_RECOVERY_EXPIRY_CERTIFICATE_BYTES, MAX_SHARED_RECOVERY_REGISTRATION_BYTES,
    SharedRecoveryExpiryCertificate, SharedRecoveryRegistration,
};
#[cfg(feature = "storage")]
use super::shared_recovery::{
    MAX_SHARED_RECOVERY_MANIFEST_BYTES, SharedRecoveryManifest, SharedRecoveryObservation,
    VerifiedSharedRecoveryObservation,
};
use super::{
    AgentProfile, MAX_AGENT_REPLICAS, MAX_CATALOG_ARTIFACT_BYTES,
    MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES, ReplicaRole,
};
use crate::agent_sdk::NodeId as AgentNodeId;
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;

/// Full authenticated-node vote used by the clean Agent transport. Shared
/// checkpoint restore must update it in the same term transaction, not only
/// the legacy two-byte service-Raft vote carried by `RaftMeta`.
pub(crate) const META_AGENT_VOTED_FOR: &str = "agent_node_voted_for_v1";
pub(crate) const META_AGENT_ACTIVE_CONFIG: &str = "agent_node_active_config_v1";
pub(crate) const META_LEGACY_ACTIVE_CONFIG: &str = "active_config";
pub(crate) const ACTIVE_CONFIG_MAGIC: &[u8; 4] = b"ANC1";

const ARTIFACT_BATCH_ID_DOMAIN: &[u8] = b"vos/agent/shared/artifact-batch/v1";
const ARTIFACT_CHUNK_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/shared/artifact-batch-chunk/v1";
const AGENT_RAFT_COMMAND_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/shared/raft-command/v1";
const AGENT_RAFT_REPLICATION_ID_DOMAIN: &[u8] = b"vos/agent/shared/raft-replication/v1";
const AGENT_RAFT_APPLY_RESERVATION_DOMAIN: &[u8] = b"vos/agent/shared/raft-apply-reservation/v1";
const COMMITTEE_TRANSITION_ID_DOMAIN: &[u8] = b"vos/agent/shared/committee-transition/v2";
#[cfg(feature = "storage")]
const AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/shared/raft-physical-slot/v3";
#[cfg(feature = "storage")]
const AGENT_RAFT_PHYSICAL_MAGIC: [u8; 4] = *b"ASR1";
#[cfg(feature = "storage")]
const AGENT_RAFT_PHYSICAL_DATA: u8 = 0;
#[cfg(feature = "storage")]
const AGENT_RAFT_PHYSICAL_CONFIGURATION: u8 = 1;
#[cfg(feature = "storage")]
const AGENT_RAFT_PHYSICAL_HEADER_BYTES: usize = AGENT_RAFT_PHYSICAL_MAGIC.len() + 1;

/// Maximum complete stable generation route key.
pub const MAX_AGENT_GENERATION_ROUTE_KEY_BYTES: usize = 224;
/// Maximum complete generation-scoped route key.
pub const MAX_AGENT_ROUTE_KEY_BYTES: usize = 256;
/// Maximum complete artifact-batch manifest.
pub const MAX_ARTIFACT_BATCH_MANIFEST_BYTES: usize = 16 * 1024;
/// Canonical non-final artifact-chunk width.
pub const ARTIFACT_CHUNK_DATA_BYTES: usize = 64 * 1024;
/// Maximum complete artifact chunk, including its repeated manifest.
pub const MAX_ARTIFACT_CHUNK_WIRE_BYTES: usize = 96 * 1024;
/// Maximum complete Shared Agent Raft command.
///
/// An Ordered command retains the complete canonical journal record, which in
/// turn may retain a maximum-size clean `InvocationWork`.  The route and
/// command envelopes are small but independently bounded, so reserve their
/// complete declared bound instead of imposing a legacy small-message cap on
/// otherwise valid clean work.
pub const MAX_AGENT_RAFT_COMMAND_BYTES: usize =
    MAX_JOURNAL_RECORD_BYTES + MAX_AGENT_ROUTE_KEY_BYTES + 512;
const _: () = assert!(
    MAX_AGENT_RAFT_COMMAND_BYTES
        >= MAX_SHARED_RECOVERY_REGISTRATION_BYTES + MAX_AGENT_ROUTE_KEY_BYTES + 128
);
/// Maximum complete authorized committee-change preparation.
pub const MAX_PREPARE_COMMITTEE_CHANGE_BYTES: usize = 160 * 1024;
/// Maximum complete encoded physical `vos-raft` slot admitted by the Shared
/// adapter. The versioned magic and one-byte entry-kind tag are included.
#[cfg(feature = "storage")]
pub const MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES: usize =
    MAX_AGENT_RAFT_COMMAND_BYTES + AGENT_RAFT_PHYSICAL_HEADER_BYTES;
/// Maximum complete apply-audit disposition.
pub const MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES: usize = 256;
/// Maximum complete durable apply metadata record.
pub const MAX_AGENT_RAFT_APPLY_META_BYTES: usize = 1024;

/// Stable identity of one exact, authority-certified committee transition.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitteeTransitionId([u8; 32]);

impl CommitteeTransitionId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CommitteeTransitionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommitteeTransitionId(")?;
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Ceiling on retained ordered evidence after the latest authenticated
/// checkpoint. Reaching it backpressures apply without partial mutation;
/// successful snapshot installation retires the certified prefix and resets
/// the relative window.
pub const MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES: usize = 4096;
/// Maximum persisted shares across the bounded per-route evidence window.
pub const MAX_AGENT_RAFT_SHARE_BACKLOG: usize =
    MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES * MAX_AGENT_REPLICAS;

/// Stable physical identity of the one journal store paired with an evidence
/// ledger.
///
/// The filesystem adapter derives this from its pinned external root and
/// stable-lock identity; an in-memory adapter assigns a fresh identity at
/// construction. Copying otherwise matching heads must not reproduce this
/// value. It is deliberately available without the storage feature so the
/// opaque pre-publication reservation has the same shape in every build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct JournalStoreInstanceId([u8; 32]);

impl JournalStoreInstanceId {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0; 32]).then_some(Self(bytes))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity of one Shared-Agent journal generation.
///
/// Unlike [`AgentRouteKey`], this key deliberately excludes the active
/// committee. Committee epochs may change while the journal generation and
/// its physical Raft log remain the same. Durable application cursors and
/// snapshot identities must therefore be keyed by this value, while
/// committee-scoped commands and certificates continue to use
/// [`AgentRouteKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentGenerationRouteKey {
    space: SpaceId,
    agent: AgentId,
    genesis: AgentJournalGenesisId,
    admission: AgentGenesisAdmissionId,
}

impl AgentGenerationRouteKey {
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        genesis: AgentJournalGenesisId,
        admission: AgentGenesisAdmissionId,
    ) -> Result<Self, AgentRaftWireError> {
        let route = Self {
            space,
            agent,
            genesis,
            admission,
        };
        route.validate()?;
        Ok(route)
    }

    pub const fn space(self) -> SpaceId {
        self.space
    }

    pub const fn agent(self) -> AgentId {
        self.agent
    }

    pub const fn genesis(self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn admission(self) -> AgentGenesisAdmissionId {
        self.admission
    }

    pub fn validate(self) -> Result<(), AgentRaftWireError> {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
        {
            return Err(AgentRaftWireError::InvalidRoute);
        }
        enforce_wire_bound(&self, MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)
    }

    /// Network replication group shared by every committee epoch of this
    /// exact journal generation. Full Agent identity and admission remain in
    /// the preimage; committee transitions therefore never create a second
    /// overlapping Raft group for the same Agent.
    pub fn replication_id(self) -> [u8; 32] {
        Hash::digest(AGENT_RAFT_REPLICATION_ID_DOMAIN, &[&self.encode()]).0
    }
}

impl ServiceWire for AgentGenerationRouteKey {
    const MAGIC: [u8; 4] = *b"AGGR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_generation_route(&mut Encoder(output), *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_GENERATION_ROUTE_KEY_BYTES)?;
        decode_generation_route(decoder)
    }
}

/// Full immutable Shared-Agent generation route.
///
/// Space and Agent alone are insufficient: delayed traffic from a retired
/// generation must not enter a new journal or committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentRouteKey {
    space: SpaceId,
    agent: AgentId,
    genesis: AgentJournalGenesisId,
    admission: AgentGenesisAdmissionId,
    committee: AgentReplicaCommitteeId,
}

impl AgentRouteKey {
    pub fn new(
        space: SpaceId,
        agent: AgentId,
        genesis: AgentJournalGenesisId,
        admission: AgentGenesisAdmissionId,
        committee: AgentReplicaCommitteeId,
    ) -> Result<Self, AgentRaftWireError> {
        let route = Self {
            space,
            agent,
            genesis,
            admission,
            committee,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn from_claim(claim: &OrderedCommitClaim) -> Result<Self, AgentRaftWireError> {
        Self::new(
            claim.space(),
            claim.agent(),
            claim.genesis(),
            claim.admission(),
            claim.committee(),
        )
    }

    pub const fn space(self) -> SpaceId {
        self.space
    }

    pub const fn agent(self) -> AgentId {
        self.agent
    }

    pub const fn genesis(self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub const fn admission(self) -> AgentGenesisAdmissionId {
        self.admission
    }

    pub const fn committee(self) -> AgentReplicaCommitteeId {
        self.committee
    }

    pub const fn generation(self) -> AgentGenerationRouteKey {
        AgentGenerationRouteKey {
            space: self.space,
            agent: self.agent,
            genesis: self.genesis,
            admission: self.admission,
        }
    }

    pub fn validate(self) -> Result<(), AgentRaftWireError> {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.genesis == AgentJournalGenesisId::ZERO
            || self.admission == AgentGenesisAdmissionId::ZERO
            || self.committee == AgentReplicaCommitteeId::ZERO
        {
            return Err(AgentRaftWireError::InvalidRoute);
        }
        enforce_wire_bound(&self, MAX_AGENT_ROUTE_KEY_BYTES)
    }
}

impl ServiceWire for AgentRouteKey {
    const MAGIC: [u8; 4] = *b"AGRR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_route(&mut Encoder(output), *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_ROUTE_KEY_BYTES)?;
        decode_route(decoder)
    }
}

/// Stable content identity of one exact artifact manifest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactBatchId([u8; 32]);

impl ArtifactBatchId {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ArtifactBatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArtifactBatchId(")?;
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Canonical, generation-scoped set of artifacts staged before ordered apply.
///
/// References are strictly ordered by hash, exactly like the journal artifact
/// closure.  Repeating the manifest in every chunk makes every Raft command
/// independently bounded and routable; a receiver never has to interpret a
/// chunk under ambient batch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBatchManifest {
    route: AgentRouteKey,
    artifacts: Vec<BlobRef>,
}

impl ArtifactBatchManifest {
    pub fn new(route: AgentRouteKey, artifacts: Vec<BlobRef>) -> Result<Self, AgentRaftWireError> {
        let manifest = Self { route, artifacts };
        manifest.validate()?;
        Ok(manifest)
    }

    pub const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub fn artifacts(&self) -> &[BlobRef] {
        &self.artifacts
    }

    pub fn id(&self) -> ArtifactBatchId {
        ArtifactBatchId(Hash::digest(ARTIFACT_BATCH_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.route.validate()?;
        let referenced_bytes = self.artifacts.iter().try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.len)
                .ok_or(AgentRaftWireError::LimitExceeded)
        })?;
        if self.artifacts.is_empty()
            || self.artifacts.len() > MAX_CATALOG_ARTIFACT_REFERENCES as usize
            || referenced_bytes > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        {
            return Err(AgentRaftWireError::LimitExceeded);
        }
        if self.artifacts.iter().any(|artifact| {
            artifact.hash == Hash::ZERO || artifact.len > MAX_CATALOG_ARTIFACT_BYTES
        }) || self
            .artifacts
            .windows(2)
            .any(|pair| pair[0].hash >= pair[1].hash)
        {
            return Err(AgentRaftWireError::NonCanonical);
        }
        enforce_wire_bound(self, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)
    }
}

impl ServiceWire for ArtifactBatchManifest {
    const MAGIC: [u8; 4] = *b"AGBM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_route(&mut encoder, self.route);
        encoder.list(&self.artifacts, encode_blob_ref);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)?;
        let route = decode_route(decoder)?;
        let count = decoder.u32()? as usize;
        if count > MAX_CATALOG_ARTIFACT_REFERENCES as usize
            || count > decoder.remaining() / (32 + 8)
        {
            return Err(DecodeError::LimitExceeded);
        }
        let mut artifacts = Vec::new();
        for _ in 0..count {
            artifacts
                .try_reserve(1)
                .map_err(|_| DecodeError::LimitExceeded)?;
            artifacts.push(decode_blob_ref(decoder)?);
        }
        let manifest = Self { route, artifacts };
        manifest.validate().map_err(map_wire_decode_error)?;
        Ok(manifest)
    }
}

/// One uniquely positioned chunk of one artifact in a canonical batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactChunk {
    manifest: ArtifactBatchManifest,
    artifact_index: u32,
    offset: u64,
    bytes: Vec<u8>,
    commitment: Hash,
}

impl ArtifactChunk {
    pub fn new(
        manifest: ArtifactBatchManifest,
        artifact_index: u32,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, AgentRaftWireError> {
        let commitment =
            artifact_chunk_commitment(manifest.id(), artifact_index, offset, bytes.as_slice());
        let chunk = Self {
            manifest,
            artifact_index,
            offset,
            bytes,
            commitment,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub const fn manifest(&self) -> &ArtifactBatchManifest {
        &self.manifest
    }

    pub fn batch(&self) -> ArtifactBatchId {
        self.manifest.id()
    }

    pub const fn artifact_index(&self) -> u32 {
        self.artifact_index
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn commitment(&self) -> Hash {
        self.commitment
    }

    pub fn artifact(&self) -> &BlobRef {
        &self.manifest.artifacts[self.artifact_index as usize]
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.manifest.validate()?;
        let artifact = self
            .manifest
            .artifacts
            .get(self.artifact_index as usize)
            .ok_or(AgentRaftWireError::InvalidArtifactChunk)?;
        let remaining = artifact
            .len
            .checked_sub(self.offset)
            .filter(|_| self.offset < artifact.len)
            .ok_or(AgentRaftWireError::InvalidArtifactChunk)?;
        let expected = remaining.min(ARTIFACT_CHUNK_DATA_BYTES as u64) as usize;
        if self.offset % ARTIFACT_CHUNK_DATA_BYTES as u64 != 0
            || self.bytes.len() != expected
            || self.commitment
                != artifact_chunk_commitment(
                    self.manifest.id(),
                    self.artifact_index,
                    self.offset,
                    self.bytes.as_slice(),
                )
        {
            return Err(AgentRaftWireError::InvalidArtifactChunk);
        }
        enforce_wire_bound(self, MAX_ARTIFACT_CHUNK_WIRE_BYTES)
    }
}

impl ServiceWire for ArtifactChunk {
    const MAGIC: [u8; 4] = *b"AGBC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.manifest.encode());
        encoder.u32(self.artifact_index);
        encoder.u64(self.offset);
        encoder.bytes(&self.bytes);
        encoder.fixed(&self.commitment.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_ARTIFACT_CHUNK_WIRE_BYTES)?;
        let manifest =
            decode_nested::<ArtifactBatchManifest>(decoder, MAX_ARTIFACT_BATCH_MANIFEST_BYTES)?;
        let artifact_index = decoder.u32()?;
        let offset = decoder.u64()?;
        let bytes = bounded_bytes(decoder, ARTIFACT_CHUNK_DATA_BYTES)?;
        let commitment = Hash(decoder.fixed()?);
        let chunk = Self {
            manifest,
            artifact_index,
            offset,
            bytes,
            commitment,
        };
        chunk.validate().map_err(map_wire_decode_error)?;
        Ok(chunk)
    }
}

/// Canonical application command which opens the two-entry Raft membership
/// barrier for one Shared Agent.
///
/// The authority receipt is the clean SDK `ChangeReplicas` receipt: its typed
/// operation must be `ChangeReplicaSet` and its request hash must equal the
/// SDK commitment of `ChangeReplicas { expected_generation, replicas }`,
/// where `replicas` is the canonical roster of the complete next committee.
/// Every member identity is bound by that roster: a `NodeId` is the digest of
/// its canonical Ed25519 PeerId, and both the member key and its Raft slot
/// are derived from that PeerId. `expected_generation` is the descriptor
/// replica generation the authority approved replacing; the ledger binds
/// the previous committee separately by requiring it to be active. The
/// receipt is checked at the leader-observed logical slot, exactly like an
/// ordered clean management input. The transition ID additionally covers the
/// complete signed receipt, so two authority decisions for the same
/// membership intent remain distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareCommitteeChange {
    transition: CommitteeTransitionId,
    generation: AgentGenerationRouteKey,
    previous: AgentReplicaCommittee,
    next: AgentReplicaCommittee,
    previous_voters: Vec<AgentNodeId>,
    next_voters: Vec<AgentNodeId>,
    expected_generation: crate::agent_sdk::Hash,
    observed_slot: u64,
    authority: crate::agent_sdk::authority::AuthorityReceipt,
}

impl PrepareCommitteeChange {
    /// Exact SDK request an authority actor must approve in a typed
    /// `ChangeReplicaSet` receipt before the preparation can be constructed.
    pub fn authority_request(
        generation: AgentGenerationRouteKey,
        previous: &AgentReplicaCommittee,
        next: &AgentReplicaCommittee,
        expected_generation: crate::agent_sdk::Hash,
    ) -> Result<crate::agent_sdk::ManagementRequest, AgentRaftWireError> {
        validate_committee_change_scope(generation, previous, next)?;
        committee_voter_nodes(previous)?;
        committee_voter_nodes(next)?;
        committee_change_request(next, expected_generation)
    }

    pub fn new(
        generation: AgentGenerationRouteKey,
        previous: AgentReplicaCommittee,
        next: AgentReplicaCommittee,
        expected_generation: crate::agent_sdk::Hash,
        observed_slot: u64,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<Self, AgentRaftWireError> {
        validate_committee_change_scope(generation, &previous, &next)?;
        let previous_voters = committee_voter_nodes(&previous)?;
        let next_voters = committee_voter_nodes(&next)?;
        let request = committee_change_request(&next, expected_generation)?.commitment();
        let transition = committee_transition_id(request, &authority)?;
        let change = Self {
            transition,
            generation,
            previous,
            next,
            previous_voters,
            next_voters,
            expected_generation,
            observed_slot,
            authority,
        };
        change.validate()?;
        Ok(change)
    }

    pub const fn transition(&self) -> CommitteeTransitionId {
        self.transition
    }

    pub const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }

    pub const fn previous(&self) -> &AgentReplicaCommittee {
        &self.previous
    }

    pub const fn next(&self) -> &AgentReplicaCommittee {
        &self.next
    }

    pub fn previous_voters(&self) -> &[AgentNodeId] {
        &self.previous_voters
    }

    pub fn next_voters(&self) -> &[AgentNodeId] {
        &self.next_voters
    }

    /// Descriptor replica generation the authority approved replacing.
    pub const fn expected_generation(&self) -> crate::agent_sdk::Hash {
        self.expected_generation
    }

    /// Leader-observed logical slot at which the receipt is verified.
    pub const fn observed_slot(&self) -> u64 {
        self.observed_slot
    }

    pub const fn authority(&self) -> &crate::agent_sdk::authority::AuthorityReceipt {
        &self.authority
    }

    pub fn authority_commitment(&self) -> Hash {
        Hash(self.authority.commitment().0)
    }

    fn route(&self) -> AgentRouteKey {
        AgentRouteKey {
            space: self.generation.space,
            agent: self.generation.agent,
            genesis: self.generation.genesis,
            admission: self.generation.admission,
            committee: self.previous.id(),
        }
    }

    fn validate(&self) -> Result<(), AgentRaftWireError> {
        use crate::agent_sdk::authority::AuthorityOperationKind;
        use crate::agent_sdk::wire::CanonicalWire as _;

        validate_committee_change_scope(self.generation, &self.previous, &self.next)?;
        if committee_voter_nodes(&self.previous)? != self.previous_voters
            || committee_voter_nodes(&self.next)? != self.next_voters
        {
            return Err(AgentRaftWireError::InvalidCommitteeTransition);
        }
        self.authority
            .validate_shape()
            .map_err(|_| AgentRaftWireError::InvalidAuthorityEvidence)?;
        let authority_bytes = self
            .authority
            .encode()
            .map_err(|_| AgentRaftWireError::InvalidAuthorityEvidence)?;
        if crate::agent_sdk::authority::AuthorityReceipt::decode(&authority_bytes)
            .ok()
            .as_ref()
            != Some(&self.authority)
        {
            return Err(AgentRaftWireError::InvalidAuthorityEvidence);
        }
        let expected_request =
            committee_change_request(&self.next, self.expected_generation)?.commitment();
        let selector = &self.authority.selector;
        if selector.operation != AuthorityOperationKind::ChangeReplicaSet
            || selector.space.as_bytes() != &self.generation.space.0
            || selector.agent.as_bytes() != &self.generation.agent.0
            || selector.request != expected_request
            || selector.actor.is_some()
            || selector.actor_deployment.is_some()
            || committee_transition_id(expected_request, &self.authority)? != self.transition
        {
            return Err(AgentRaftWireError::InvalidAuthorityEvidence);
        }
        enforce_wire_bound(self, MAX_PREPARE_COMMITTEE_CHANGE_BYTES)
    }
}

impl ServiceWire for PrepareCommitteeChange {
    const MAGIC: [u8; 4] = *b"APC4";

    fn encode_body(&self, output: &mut Vec<u8>) {
        use crate::agent_sdk::wire::CanonicalWire as _;

        let mut encoder = Encoder(output);
        encoder.fixed(self.transition.as_bytes());
        encode_generation_route(&mut encoder, self.generation);
        encoder.bytes(&self.previous.encode());
        encoder.bytes(&self.next.encode());
        encode_raft_nodes(&mut encoder, &self.previous_voters);
        encode_raft_nodes(&mut encoder, &self.next_voters);
        encoder.fixed(self.expected_generation.as_bytes());
        encoder.u64(self.observed_slot);
        // Every constructor and decoder validates this private field. If a
        // future internal mutation violates that invariant, abort at the
        // canonical-record boundary instead of silently substituting bytes
        // that could acquire a different commitment.
        encoder.bytes(
            &self
                .authority
                .encode()
                .expect("validated committee authority must encode canonically"),
        );
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;

        enforce_complete_bound(decoder, MAX_PREPARE_COMMITTEE_CHANGE_BYTES)?;
        let change = Self {
            transition: CommitteeTransitionId::from_bytes(decoder.fixed()?),
            generation: decode_generation_route(decoder)?,
            previous: decode_nested::<AgentReplicaCommittee>(
                decoder,
                MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            next: decode_nested::<AgentReplicaCommittee>(
                decoder,
                MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            previous_voters: decode_raft_nodes(decoder)?,
            next_voters: decode_raft_nodes(decoder)?,
            expected_generation: crate::agent_sdk::Hash(decoder.fixed()?),
            observed_slot: decoder.u64()?,
            authority: {
                let bytes = bounded_bytes(
                    decoder,
                    crate::agent_sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES,
                )?;
                crate::agent_sdk::authority::AuthorityReceipt::decode(&bytes)
                    .map_err(|_| DecodeError::NonCanonical)?
            },
        };
        change.validate().map_err(map_wire_decode_error)?;
        Ok(change)
    }
}

fn validate_committee_change_scope(
    generation: AgentGenerationRouteKey,
    previous: &AgentReplicaCommittee,
    next: &AgentReplicaCommittee,
) -> Result<(), AgentRaftWireError> {
    generation.validate()?;
    previous
        .validate()
        .map_err(|_| AgentRaftWireError::InvalidCommitteeTransition)?;
    next.validate()
        .map_err(|_| AgentRaftWireError::InvalidCommitteeTransition)?;
    if previous.profile() != AgentProfile::Shared
        || next.profile() != AgentProfile::Shared
        || previous.space() != generation.space
        || next.space() != generation.space
        || previous.agent() != generation.agent
        || next.agent() != generation.agent
        || previous.id() == next.id()
    {
        return Err(AgentRaftWireError::InvalidCommitteeTransition);
    }
    Ok(())
}

fn committee_voter_nodes(
    committee: &AgentReplicaCommittee,
) -> Result<Vec<AgentNodeId>, AgentRaftWireError> {
    let mut voters = committee
        .members()
        .iter()
        .filter_map(|member| match member.replica().role {
            ReplicaRole::Voter => Some(AgentNodeId(member.replica().node.0)),
            ReplicaRole::Observer => None,
        })
        .collect::<Vec<_>>();
    voters.sort_unstable();
    validate_raft_nodes(&voters)?;
    Ok(voters)
}

fn validate_raft_nodes(nodes: &[AgentNodeId]) -> Result<(), AgentRaftWireError> {
    if nodes.is_empty()
        || nodes.len() > MAX_AGENT_REPLICAS
        || nodes.iter().any(|node| *node == AgentNodeId::ZERO)
        || nodes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AgentRaftWireError::InvalidConfiguration);
    }
    Ok(())
}

fn encode_raft_nodes(encoder: &mut Encoder<'_>, nodes: &[AgentNodeId]) {
    encoder.u16(nodes.len() as u16);
    for node in nodes {
        encoder.fixed(node.as_bytes());
    }
}

fn decode_raft_nodes(decoder: &mut Decoder<'_>) -> Result<Vec<AgentNodeId>, DecodeError> {
    let count = decoder.u16()? as usize;
    if count == 0 || count > MAX_AGENT_REPLICAS {
        return Err(DecodeError::LimitExceeded);
    }
    if count > decoder.remaining() / 32 {
        return Err(DecodeError::Truncated);
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(count)
        .map_err(|_| DecodeError::LimitExceeded)?;
    for _ in 0..count {
        nodes.push(AgentNodeId(decoder.fixed()?));
    }
    validate_raft_nodes(&nodes).map_err(map_wire_decode_error)?;
    Ok(nodes)
}

/// Canonical SDK replica roster of one complete committee, in node order.
pub(crate) fn committee_sdk_replicas(
    committee: &AgentReplicaCommittee,
) -> Vec<crate::agent_sdk::AgentReplica> {
    committee
        .members()
        .iter()
        .map(|member| {
            let replica = member.replica();
            crate::agent_sdk::AgentReplica {
                node: crate::agent_sdk::NodeId(replica.node.0),
                principal: crate::agent_sdk::PrincipalId(replica.principal.0),
                role: match replica.role {
                    ReplicaRole::Voter => crate::agent_sdk::ReplicaRole::Voter,
                    ReplicaRole::Observer => crate::agent_sdk::ReplicaRole::Observer,
                },
            }
        })
        .collect()
}

/// The exact SDK `ChangeReplicas` request whose authority receipt admits a
/// transition to `next`. Production authorities sign this commitment.
fn committee_change_request(
    next: &AgentReplicaCommittee,
    expected_generation: crate::agent_sdk::Hash,
) -> Result<crate::agent_sdk::ManagementRequest, AgentRaftWireError> {
    let request = crate::agent_sdk::ManagementRequest::ChangeReplicas {
        expected_generation,
        replicas: committee_sdk_replicas(next),
    };
    if !request.is_valid() {
        return Err(AgentRaftWireError::InvalidCommitteeTransition);
    }
    Ok(request)
}

fn committee_transition_id(
    request: crate::agent_sdk::Hash,
    authority: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<CommitteeTransitionId, AgentRaftWireError> {
    use crate::agent_sdk::wire::CanonicalWire as _;

    let authority = authority
        .encode()
        .map_err(|_| AgentRaftWireError::InvalidAuthorityEvidence)?;
    Ok(CommitteeTransitionId(
        Hash::digest(
            COMMITTEE_TRANSITION_ID_DOMAIN,
            &[request.as_bytes(), &authority],
        )
        .0,
    ))
}

/// Canonical application payload placed in the ordinary Raft data log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentRaftCommand {
    ArtifactChunk(ArtifactChunk),
    ArtifactAbort {
        route: AgentRouteKey,
        batch: ArtifactBatchId,
    },
    Ordered {
        route: AgentRouteKey,
        artifact_batch: Option<ArtifactBatchId>,
        entry: OrderedEntry,
    },
    PrepareCommitteeChange(PrepareCommitteeChange),
    RegisterRecovery {
        route: AgentRouteKey,
        registration: SharedRecoveryRegistration,
    },
    ExpireRecovery {
        route: AgentRouteKey,
        certificate: SharedRecoveryExpiryCertificate,
    },
}

impl AgentRaftCommand {
    pub fn route(&self) -> AgentRouteKey {
        match self {
            Self::ArtifactChunk(chunk) => chunk.manifest.route,
            Self::ArtifactAbort { route, .. }
            | Self::Ordered { route, .. }
            | Self::RegisterRecovery { route, .. }
            | Self::ExpireRecovery { route, .. } => *route,
            Self::PrepareCommitteeChange(change) => change.route(),
        }
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(AGENT_RAFT_COMMAND_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.validate_enclosing_bindings()?;
        match self {
            Self::ArtifactChunk(chunk) => chunk.validate()?,
            Self::Ordered { entry, .. } => entry
                .validate()
                .map_err(|_| AgentRaftWireError::InvalidOrderedCommand)?,
            Self::PrepareCommitteeChange(change) => change.validate()?,
            Self::RegisterRecovery { registration, .. } => registration
                .validate()
                .map_err(|_| AgentRaftWireError::InvalidOrderedCommand)?,
            Self::ExpireRecovery { certificate, .. } => certificate
                .validate()
                .map_err(|_| AgentRaftWireError::InvalidOrderedCommand)?,
            Self::ArtifactAbort { .. } => {}
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_COMMAND_BYTES)
    }

    /// Does not validate nested records. Public validation checks them
    /// separately; the decoder owns validated values from decode_nested.
    fn validate_enclosing_bindings(&self) -> Result<(), AgentRaftWireError> {
        match self {
            Self::ArtifactAbort { route, batch } => {
                route.validate()?;
                if *batch == ArtifactBatchId::ZERO {
                    return Err(AgentRaftWireError::InvalidArtifactBatch);
                }
            }
            Self::Ordered {
                route,
                artifact_batch,
                entry,
            } => {
                route.validate()?;
                if *artifact_batch == Some(ArtifactBatchId::ZERO)
                    || entry.genesis != route.genesis
                    || entry.input.runtime.space != route.space
                    || entry.input.runtime.agent != route.agent
                {
                    return Err(AgentRaftWireError::InvalidOrderedCommand);
                }
            }
            Self::ArtifactChunk(_) | Self::PrepareCommitteeChange(_) => {}
            Self::RegisterRecovery {
                route,
                registration,
            } => {
                route.validate()?;
                if registration.generation() != route.generation()
                    || registration.committee() != route.committee()
                {
                    return Err(AgentRaftWireError::InvalidOrderedCommand);
                }
            }
            Self::ExpireRecovery { route, certificate } => {
                route.validate()?;
                if certificate.claim().generation() != route.generation()
                    || certificate.claim().committee().id() != route.committee()
                {
                    return Err(AgentRaftWireError::InvalidOrderedCommand);
                }
            }
        }
        Ok(())
    }
}

impl ServiceWire for AgentRaftCommand {
    const MAGIC: [u8; 4] = *b"AGRC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match self {
            Self::ArtifactChunk(chunk) => {
                encoder.u8(0);
                encoder.bytes(&chunk.encode());
            }
            Self::ArtifactAbort { route, batch } => {
                encoder.u8(1);
                encode_route(&mut encoder, *route);
                encoder.fixed(batch.as_bytes());
            }
            Self::Ordered {
                route,
                artifact_batch,
                entry,
            } => {
                encoder.u8(2);
                encode_route(&mut encoder, *route);
                encoder.option(artifact_batch, |encoder, batch| {
                    encoder.fixed(batch.as_bytes())
                });
                encoder.bytes(&entry.encode());
            }
            Self::PrepareCommitteeChange(change) => {
                encoder.u8(3);
                encoder.bytes(&change.encode());
            }
            Self::RegisterRecovery {
                route,
                registration,
            } => {
                encoder.u8(4);
                encode_route(&mut encoder, *route);
                encoder.bytes(&registration.encode());
            }
            Self::ExpireRecovery { route, certificate } => {
                encoder.u8(5);
                encode_route(&mut encoder, *route);
                encoder.bytes(&certificate.encode());
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_COMMAND_BYTES)?;
        let command = match decoder.u8()? {
            0 => Self::ArtifactChunk(decode_nested::<ArtifactChunk>(
                decoder,
                MAX_ARTIFACT_CHUNK_WIRE_BYTES,
            )?),
            1 => Self::ArtifactAbort {
                route: decode_route(decoder)?,
                batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
            },
            2 => Self::Ordered {
                route: decode_route(decoder)?,
                artifact_batch: decoder
                    .option(|decoder| Ok(ArtifactBatchId::from_bytes(decoder.fixed()?)))?,
                entry: decode_nested::<OrderedEntry>(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            },
            3 => Self::PrepareCommitteeChange(decode_nested::<PrepareCommitteeChange>(
                decoder,
                MAX_PREPARE_COMMITTEE_CHANGE_BYTES,
            )?),
            4 => Self::RegisterRecovery {
                route: decode_route(decoder)?,
                registration: decode_nested::<SharedRecoveryRegistration>(
                    decoder,
                    MAX_SHARED_RECOVERY_REGISTRATION_BYTES,
                )?,
            },
            5 => Self::ExpireRecovery {
                route: decode_route(decoder)?,
                certificate: decode_nested(decoder, MAX_SHARED_RECOVERY_EXPIRY_CERTIFICATE_BYTES)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        // The complete incoming frame was bounded above, and decode_nested
        // validated each child and compared its exact canonical encoding.
        // Revalidating those owned children would repeat blob authentication.
        command
            .validate_enclosing_bindings()
            .map_err(map_wire_decode_error)?;
        Ok(command)
    }
}

/// Deterministic record of what the Shared application did at `applied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRaftAuditDisposition {
    ArtifactChunkStored {
        batch: ArtifactBatchId,
        artifact: Hash,
        offset: u64,
        chunk: Hash,
    },
    ArtifactBatchAborted {
        batch: ArtifactBatchId,
    },
    OrderedApplied {
        entry: OrderedEntryId,
        claim: Hash,
        successor: JournalHeadsId,
    },
}

impl AgentRaftAuditDisposition {
    fn validate(self) -> Result<(), AgentRaftWireError> {
        match self {
            Self::ArtifactChunkStored {
                batch,
                artifact,
                chunk,
                ..
            } if batch != ArtifactBatchId::ZERO
                && artifact != Hash::ZERO
                && chunk != Hash::ZERO => {}
            Self::ArtifactBatchAborted { batch } if batch != ArtifactBatchId::ZERO => {}
            Self::OrderedApplied {
                entry,
                claim,
                successor,
            } if entry != OrderedEntryId::ZERO
                && claim != Hash::ZERO
                && successor != JournalHeadsId::ZERO => {}
            _ => return Err(AgentRaftWireError::InvalidApplyMeta),
        }
        enforce_wire_bound(&self, MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES)
    }
}

impl ServiceWire for AgentRaftAuditDisposition {
    const MAGIC: [u8; 4] = *b"AGAD";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_disposition(&mut encoder, *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES)?;
        decode_disposition(decoder)
    }
}

/// Durable dual cursor for Shared-Agent Raft application.
///
/// `applied` advances after deterministic local publication. `compact_safe`
/// advances only after the ledger persists a verified application QC for an
/// anchored claim.  The latter is diagnostic input for a future adapter; it
/// is not itself a snapshot or compaction authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRaftApplyMeta {
    route: AgentRouteKey,
    applied_index: u64,
    applied_term: u64,
    applied_payload: Hash,
    disposition: Option<AgentRaftAuditDisposition>,
    compact_safe_index: u64,
    compact_safe_term: u64,
    compact_safe_qc: Option<Hash>,
}

impl AgentRaftApplyMeta {
    fn post_genesis(route: AgentRouteKey) -> Self {
        Self {
            route,
            applied_index: 0,
            applied_term: 0,
            applied_payload: Hash::ZERO,
            disposition: None,
            compact_safe_index: 0,
            compact_safe_term: 0,
            compact_safe_qc: None,
        }
    }

    pub const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub const fn applied(&self) -> (u64, u64) {
        (self.applied_index, self.applied_term)
    }

    pub const fn applied_payload(&self) -> Hash {
        self.applied_payload
    }

    pub const fn disposition(&self) -> Option<AgentRaftAuditDisposition> {
        self.disposition
    }

    /// Legacy evidence-ledger audit cursor. Agent V2 snapshot retirement uses
    /// its independently authenticated snapshot record instead.
    pub const fn compact_safe(&self) -> (u64, u64) {
        (self.compact_safe_index, self.compact_safe_term)
    }

    pub const fn compact_safe_qc(&self) -> Option<Hash> {
        self.compact_safe_qc
    }

    fn advance_applied(
        &self,
        committed: &CommittedAgentRaftEntry,
        disposition: AgentRaftAuditDisposition,
    ) -> Result<Self, AgentRaftLedgerError> {
        disposition.validate().map_err(AgentRaftLedgerError::Wire)?;
        if committed.route() != self.route {
            return Err(AgentRaftLedgerError::WrongRoute);
        }
        if committed.index != self.applied_index.saturating_add(1)
            || (self.applied_index != 0 && committed.term < self.applied_term)
        {
            return Err(AgentRaftLedgerError::ApplyGap);
        }
        let next = Self {
            route: self.route,
            applied_index: committed.index,
            applied_term: committed.term,
            applied_payload: committed.payload_commitment,
            disposition: Some(disposition),
            compact_safe_index: self.compact_safe_index,
            compact_safe_term: self.compact_safe_term,
            compact_safe_qc: self.compact_safe_qc,
        };
        next.validate().map_err(AgentRaftLedgerError::Wire)?;
        Ok(next)
    }

    fn advance_compact_safe(
        &self,
        claim: &OrderedCommitClaim,
        qc: Hash,
    ) -> Result<Self, AgentRaftLedgerError> {
        if qc == Hash::ZERO
            || AgentRouteKey::from_claim(claim).map_err(AgentRaftLedgerError::Wire)? != self.route
            || claim.raft_index() > self.applied_index
        {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        if claim.raft_index() < self.compact_safe_index {
            return Ok(self.clone());
        }
        if claim.raft_index() == self.compact_safe_index {
            if claim.raft_term() == self.compact_safe_term && self.compact_safe_qc == Some(qc) {
                return Ok(self.clone());
            }
            return Err(AgentRaftLedgerError::ConflictingCertificate);
        }
        let mut next = self.clone();
        next.compact_safe_index = claim.raft_index();
        next.compact_safe_term = claim.raft_term();
        next.compact_safe_qc = Some(qc);
        next.validate().map_err(AgentRaftLedgerError::Wire)?;
        Ok(next)
    }

    pub fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.route.validate()?;
        let applied_empty = self.applied_index == 0
            && self.applied_term == 0
            && self.applied_payload == Hash::ZERO
            && self.disposition.is_none();
        let applied_present = self.applied_index != 0
            && self.applied_term != 0
            && self.applied_payload != Hash::ZERO
            && self.disposition.is_some();
        let compact_empty = self.compact_safe_index == 0
            && self.compact_safe_term == 0
            && self.compact_safe_qc.is_none();
        let compact_present = self.compact_safe_index != 0
            && self.compact_safe_term != 0
            && self.compact_safe_qc.is_some_and(|qc| qc != Hash::ZERO);
        if (!applied_empty && !applied_present)
            || (!compact_empty && !compact_present)
            || self.compact_safe_index > self.applied_index
            || (self.compact_safe_index == self.applied_index
                && self.compact_safe_index != 0
                && self.compact_safe_term != self.applied_term)
        {
            return Err(AgentRaftWireError::InvalidApplyMeta);
        }
        if let Some(disposition) = self.disposition {
            disposition.validate()?;
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_APPLY_META_BYTES)
    }
}

impl ServiceWire for AgentRaftApplyMeta {
    const MAGIC: [u8; 4] = *b"AGAM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_route(&mut encoder, self.route);
        encoder.u64(self.applied_index);
        encoder.u64(self.applied_term);
        encoder.fixed(&self.applied_payload.0);
        encoder.option(&self.disposition, |encoder, disposition| {
            encode_disposition(encoder, *disposition)
        });
        encoder.u64(self.compact_safe_index);
        encoder.u64(self.compact_safe_term);
        encoder.option(&self.compact_safe_qc, |encoder, qc| encoder.fixed(&qc.0));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_APPLY_META_BYTES)?;
        let meta = Self {
            route: decode_route(decoder)?,
            applied_index: decoder.u64()?,
            applied_term: decoder.u64()?,
            applied_payload: Hash(decoder.fixed()?),
            disposition: decoder.option(decode_disposition)?,
            compact_safe_index: decoder.u64()?,
            compact_safe_term: decoder.u64()?,
            compact_safe_qc: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
        };
        meta.validate().map_err(map_wire_decode_error)?;
        Ok(meta)
    }
}

/// Opaque proof that a canonical Agent command occupies an exact committed
/// durable Raft-log slot.
///
/// There is no raw constructor and no wire decoder for this type.
#[derive(Clone, Debug)]
pub struct CommittedAgentRaftEntry {
    index: u64,
    term: u64,
    committed_index: u64,
    command: AgentRaftCommand,
    payload_commitment: Hash,
}

impl CommittedAgentRaftEntry {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn term(&self) -> u64 {
        self.term
    }

    pub const fn committed_index(&self) -> u64 {
        self.committed_index
    }

    pub const fn command(&self) -> &AgentRaftCommand {
        &self.command
    }

    pub fn route(&self) -> AgentRouteKey {
        self.command.route()
    }

    pub const fn payload_commitment(&self) -> Hash {
        self.payload_commitment
    }

    pub(crate) fn from_durable_log<W: DurableAgentRaftLogWitness>(
        witness: &W,
        index: u64,
    ) -> Result<Self, CommittedAgentRaftEntryError<W::Error>> {
        if index == 0 {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let (stored_index, term, committed_index, payload) = witness
            .read_committed_payload(index)
            .map_err(CommittedAgentRaftEntryError::Witness)?
            .ok_or(CommittedAgentRaftEntryError::Missing)?;
        if stored_index != index
            || term == 0
            || committed_index < index
            || payload.len() > MAX_AGENT_RAFT_COMMAND_BYTES
        {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let command = AgentRaftCommand::decode(&payload).map_err(|_| {
            CommittedAgentRaftEntryError::Invalid(AgentRaftWireError::InvalidCommittedEntry)
        })?;
        if command.encode() != payload {
            return Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry,
            ));
        }
        let payload_commitment = command.commitment();
        Ok(Self {
            index,
            term,
            committed_index,
            command,
            payload_commitment,
        })
    }
}

/// Opaque committed empty-data slot inserted by a Raft leader.
///
/// The private fields prevent application code from manufacturing a durable
/// witness. Obtain this only by matching [`CommittedSharedRaftSlot`].
#[cfg(feature = "storage")]
#[derive(Clone, Debug)]
pub struct CommittedRaftLeaderNoop {
    index: u64,
    term: u64,
    committed_index: u64,
    raw_payload_commitment: Hash,
}

#[cfg(feature = "storage")]
impl CommittedRaftLeaderNoop {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn term(&self) -> u64 {
        self.term
    }

    pub const fn committed_index(&self) -> u64 {
        self.committed_index
    }

    pub const fn raw_payload_commitment(&self) -> Hash {
        self.raw_payload_commitment
    }
}

/// Opaque committed canonical Shared command and its complete physical-slot
/// commitment.
#[cfg(feature = "storage")]
#[derive(Clone, Debug)]
pub struct CommittedSharedRaftCommand {
    entry: CommittedAgentRaftEntry,
    raw_payload_commitment: Hash,
}

#[cfg(feature = "storage")]
impl CommittedSharedRaftCommand {
    pub const fn entry(&self) -> &CommittedAgentRaftEntry {
        &self.entry
    }

    pub const fn raw_payload_commitment(&self) -> Hash {
        self.raw_payload_commitment
    }
}

/// Opaque committed, structurally valid `vos-raft` membership slot.
///
/// Structural admission here does not authorize a Shared committee change.
/// The V2 foundation ledger admits this slot only as the exact next leg of a
/// persisted, authority-certified committee transition.
#[cfg(feature = "storage")]
#[derive(Clone, Debug)]
pub struct CommittedRaftConfiguration {
    index: u64,
    term: u64,
    committed_index: u64,
    joint_old: Option<Vec<AgentNodeId>>,
    members: Vec<AgentNodeId>,
    raw_payload_commitment: Hash,
}

#[cfg(feature = "storage")]
impl CommittedRaftConfiguration {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn term(&self) -> u64 {
        self.term
    }

    pub const fn committed_index(&self) -> u64 {
        self.committed_index
    }

    pub fn joint_old(&self) -> Option<&[AgentNodeId]> {
        self.joint_old.as_deref()
    }

    pub fn members(&self) -> &[AgentNodeId] {
        &self.members
    }

    pub const fn raw_payload_commitment(&self) -> Hash {
        self.raw_payload_commitment
    }
}

/// One exact, committed physical `vos-raft` slot.
///
/// Every committed index is decoded: empty `Data` is a leader no-op,
/// non-empty `Data` must be an exact canonical [`AgentRaftCommand`], and a
/// `ConfigChange` must carry bounded, non-empty, sorted-unique full Node lists.
/// There is intentionally no public or raw constructor.
#[cfg(feature = "storage")]
#[derive(Clone, Debug)]
pub enum CommittedSharedRaftSlot {
    LeaderNoop(CommittedRaftLeaderNoop),
    Command(CommittedSharedRaftCommand),
    Configuration(CommittedRaftConfiguration),
}

#[cfg(feature = "storage")]
impl CommittedSharedRaftSlot {
    pub const fn index(&self) -> u64 {
        match self {
            Self::LeaderNoop(slot) => slot.index,
            Self::Command(slot) => slot.entry.index,
            Self::Configuration(slot) => slot.index,
        }
    }

    pub const fn term(&self) -> u64 {
        match self {
            Self::LeaderNoop(slot) => slot.term,
            Self::Command(slot) => slot.entry.term,
            Self::Configuration(slot) => slot.term,
        }
    }

    pub const fn committed_index(&self) -> u64 {
        match self {
            Self::LeaderNoop(slot) => slot.committed_index,
            Self::Command(slot) => slot.entry.committed_index,
            Self::Configuration(slot) => slot.committed_index,
        }
    }

    pub const fn raw_payload_commitment(&self) -> Hash {
        match self {
            Self::LeaderNoop(slot) => slot.raw_payload_commitment,
            Self::Command(slot) => slot.raw_payload_commitment,
            Self::Configuration(slot) => slot.raw_payload_commitment,
        }
    }

    pub(crate) fn from_durable_log<W: DurableSharedRaftLogWitness>(
        witness: &W,
        index: u64,
    ) -> Result<Self, CommittedSharedRaftSlotError<W::Error>> {
        use vos_raft::EntryKind;

        if index == 0 {
            return Err(CommittedSharedRaftSlotError::Invalid(
                AgentRaftWireError::InvalidPhysicalSlot,
            ));
        }
        let (stored_index, term, committed_index, raw) = witness
            .read_committed_physical_slot(index)
            .map_err(CommittedSharedRaftSlotError::Witness)?
            .ok_or(CommittedSharedRaftSlotError::Missing)?;
        if stored_index != index
            || term == 0
            || committed_index < index
            || raw.is_empty()
            || raw.len() > MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES
        {
            return Err(CommittedSharedRaftSlotError::Invalid(
                AgentRaftWireError::InvalidPhysicalSlot,
            ));
        }
        let kind =
            decode_agent_raft_entry_kind(&raw).map_err(CommittedSharedRaftSlotError::Invalid)?;
        let canonical =
            encode_agent_raft_entry_kind(&kind).map_err(CommittedSharedRaftSlotError::Invalid)?;
        if canonical != raw {
            return Err(CommittedSharedRaftSlotError::Invalid(
                AgentRaftWireError::NonCanonical,
            ));
        }
        let raw_payload_commitment = Hash::digest(
            AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN,
            &[raw.as_slice()],
        );
        match kind {
            EntryKind::Data { payload } if payload.is_empty() => {
                Ok(Self::LeaderNoop(CommittedRaftLeaderNoop {
                    index,
                    term,
                    committed_index,
                    raw_payload_commitment,
                }))
            }
            EntryKind::Data { payload } => {
                if payload.len() > MAX_AGENT_RAFT_COMMAND_BYTES {
                    return Err(CommittedSharedRaftSlotError::Invalid(
                        AgentRaftWireError::LimitExceeded,
                    ));
                }
                let command = AgentRaftCommand::decode(&payload).map_err(|_| {
                    CommittedSharedRaftSlotError::Invalid(AgentRaftWireError::InvalidCommittedEntry)
                })?;
                if command.encode() != payload {
                    return Err(CommittedSharedRaftSlotError::Invalid(
                        AgentRaftWireError::NonCanonical,
                    ));
                }
                let payload_commitment = command.commitment();
                Ok(Self::Command(CommittedSharedRaftCommand {
                    entry: CommittedAgentRaftEntry {
                        index,
                        term,
                        committed_index,
                        command,
                        payload_commitment,
                    },
                    raw_payload_commitment,
                }))
            }
            EntryKind::ConfigChange { joint_old, members } => {
                validate_raft_configuration(joint_old.as_deref(), &members)
                    .map_err(CommittedSharedRaftSlotError::Invalid)?;
                Ok(Self::Configuration(CommittedRaftConfiguration {
                    index,
                    term,
                    committed_index,
                    joint_old,
                    members,
                    raw_payload_commitment,
                }))
            }
            _ => Err(CommittedSharedRaftSlotError::Invalid(
                AgentRaftWireError::InvalidPhysicalSlot,
            )),
        }
    }
}

#[cfg(feature = "storage")]
fn validate_raft_configuration(
    joint_old: Option<&[AgentNodeId]>,
    members: &[AgentNodeId],
) -> Result<(), AgentRaftWireError> {
    validate_raft_nodes(members)?;
    if let Some(joint_old) = joint_old {
        validate_raft_nodes(joint_old)?;
    }
    Ok(())
}

/// Canonical clean-generation encoding for Shared-Agent physical Raft slots.
///
/// This is intentionally distinct from the generic Service Raft adapter's
/// legacy `EntryKind<u16>` bytes. The magic/version prevents a compact row
/// from being reinterpreted as a full authenticated Node configuration.
#[cfg(feature = "storage")]
pub(crate) fn encode_agent_raft_entry_kind(
    kind: &vos_raft::EntryKind<AgentNodeId>,
) -> Result<Vec<u8>, AgentRaftWireError> {
    use vos_raft::EntryKind;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&AGENT_RAFT_PHYSICAL_MAGIC);
    let mut encoder = Encoder(&mut bytes);
    match kind {
        EntryKind::Data { payload } => {
            if payload.len() > MAX_AGENT_RAFT_COMMAND_BYTES {
                return Err(AgentRaftWireError::LimitExceeded);
            }
            encoder.u8(AGENT_RAFT_PHYSICAL_DATA);
            encoder.0.extend_from_slice(payload);
        }
        EntryKind::ConfigChange { joint_old, members } => {
            validate_raft_configuration(joint_old.as_deref(), members)?;
            encoder.u8(AGENT_RAFT_PHYSICAL_CONFIGURATION);
            encoder.option(joint_old, |encoder, nodes| {
                encode_raft_nodes(encoder, nodes)
            });
            encode_raft_nodes(&mut encoder, members);
        }
        _ => return Err(AgentRaftWireError::InvalidPhysicalSlot),
    }
    if bytes.len() > MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES {
        return Err(AgentRaftWireError::LimitExceeded);
    }
    Ok(bytes)
}

#[cfg(feature = "storage")]
pub(crate) fn decode_agent_raft_entry_kind(
    bytes: &[u8],
) -> Result<vos_raft::EntryKind<AgentNodeId>, AgentRaftWireError> {
    use vos_raft::EntryKind;

    if bytes.is_empty() || bytes.len() > MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES {
        return Err(AgentRaftWireError::InvalidPhysicalSlot);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder
        .take(AGENT_RAFT_PHYSICAL_MAGIC.len())
        .map_err(|_| AgentRaftWireError::InvalidPhysicalSlot)?
        != AGENT_RAFT_PHYSICAL_MAGIC
    {
        return Err(AgentRaftWireError::InvalidPhysicalSlot);
    }
    let tag = decoder
        .u8()
        .map_err(|_| AgentRaftWireError::InvalidPhysicalSlot)?;
    let kind = match tag {
        AGENT_RAFT_PHYSICAL_DATA => EntryKind::Data {
            payload: decoder
                .take(decoder.remaining())
                .map_err(|_| AgentRaftWireError::InvalidPhysicalSlot)?
                .to_vec(),
        },
        AGENT_RAFT_PHYSICAL_CONFIGURATION => {
            let joint_old = decoder
                .option(decode_raft_nodes)
                .map_err(|_| AgentRaftWireError::InvalidConfiguration)?;
            let members = decode_raft_nodes(&mut decoder)
                .map_err(|_| AgentRaftWireError::InvalidConfiguration)?;
            if !decoder.exhausted() {
                return Err(AgentRaftWireError::InvalidConfiguration);
            }
            validate_raft_configuration(joint_old.as_deref(), &members)?;
            EntryKind::ConfigChange { joint_old, members }
        }
        _ => return Err(AgentRaftWireError::InvalidPhysicalSlot),
    };
    Ok(kind)
}

/// Read-only production boundary for exact committed physical slots.
///
/// The tuple is `(stored_index, term, durable_commit_index,
/// complete_encoded_entry_kind)` and must come from one durable read view.
#[cfg(feature = "storage")]
pub(crate) trait DurableSharedRaftLogWitness {
    type Error;

    fn read_committed_physical_slot(
        &self,
        index: u64,
    ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error>;
}

#[cfg(feature = "storage")]
#[derive(Debug)]
pub(crate) enum CommittedSharedRaftSlotError<E> {
    Witness(E),
    Missing,
    Invalid(AgentRaftWireError),
}

/// The redb-backed durable physical-slot witness. It performs no application
/// work and is not attached to a live worker in this foundation slice.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct RedbSharedRaftLogWitness {
    database: alloc::sync::Arc<redb::Database>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl RedbSharedRaftLogWitness {
    pub(crate) const fn new(database: alloc::sync::Arc<redb::Database>) -> Self {
        Self { database }
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl DurableSharedRaftLogWitness for RedbSharedRaftLogWitness {
    type Error = crate::commit::CommitError;

    fn read_committed_physical_slot(
        &self,
        index: u64,
    ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error> {
        crate::raft::RaftLog::committed_payload_at(&self.database, index)
    }
}

/// Clean-generation disposition for one physically applied Raft slot.
///
/// Command dispositions wrap the existing deterministic Shared application
/// result. Committee dispositions carry the exact authorized transition
/// identity and complete committee epochs. Unsolicited or out-of-order
/// configuration slots are rejected before cursor advancement.
#[cfg(feature = "storage")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentRaftApplyDispositionV2 {
    LeaderNoop,
    RecoveryRegistered {
        registration: Hash,
        manifest: Hash,
    },
    RecoveryExpired {
        certificate: Hash,
        manifest: Hash,
    },
    Command(AgentRaftAuditDisposition),
    CommitteeChangePrepared {
        transition: CommitteeTransitionId,
        previous: AgentReplicaCommitteeId,
        next: AgentReplicaCommitteeId,
        authority: Hash,
    },
    CommitteeJointConfiguration {
        transition: CommitteeTransitionId,
        previous: AgentReplicaCommitteeId,
        next: AgentReplicaCommitteeId,
    },
    CommitteeStableConfiguration {
        transition: CommitteeTransitionId,
        committee: AgentReplicaCommitteeId,
    },
}

#[cfg(feature = "storage")]
impl AgentRaftApplyDispositionV2 {
    fn validate(self) -> Result<(), AgentRaftWireError> {
        match self {
            Self::LeaderNoop => {}
            Self::RecoveryRegistered {
                registration,
                manifest,
            } if registration != Hash::ZERO && manifest != Hash::ZERO => {}
            Self::RecoveryExpired {
                certificate,
                manifest,
            } if certificate != Hash::ZERO && manifest != Hash::ZERO => {}
            Self::Command(disposition) => disposition.validate()?,
            Self::CommitteeChangePrepared {
                transition,
                previous,
                next,
                authority,
            } if transition != CommitteeTransitionId::ZERO
                && previous != AgentReplicaCommitteeId::ZERO
                && next != AgentReplicaCommitteeId::ZERO
                && previous != next
                && authority != Hash::ZERO => {}
            Self::CommitteeJointConfiguration {
                transition,
                previous,
                next,
            } if transition != CommitteeTransitionId::ZERO
                && previous != AgentReplicaCommitteeId::ZERO
                && next != AgentReplicaCommitteeId::ZERO
                && previous != next => {}
            Self::CommitteeStableConfiguration {
                transition,
                committee,
            } if transition != CommitteeTransitionId::ZERO
                && committee != AgentReplicaCommitteeId::ZERO => {}
            _ => return Err(AgentRaftWireError::InvalidApplyMeta),
        }
        Ok(())
    }
}

#[cfg(feature = "storage")]
impl ServiceWire for AgentRaftApplyDispositionV2 {
    const MAGIC: [u8; 4] = *b"AGD2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        encode_disposition_v2(&mut Encoder(output), *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_AUDIT_DISPOSITION_BYTES)?;
        decode_disposition_v2(decoder)
    }
}

/// Clean-generation durable cursor over every physical committed Raft index.
#[cfg(feature = "storage")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentRaftApplyMetaV2 {
    generation: AgentGenerationRouteKey,
    journal_store: JournalStoreInstanceId,
    applied_index: u64,
    applied_term: u64,
    raw_payload_commitment: Hash,
    disposition: Option<AgentRaftApplyDispositionV2>,
}

#[cfg(feature = "storage")]
impl AgentRaftApplyMetaV2 {
    fn post_genesis(
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
    ) -> Self {
        Self {
            generation,
            journal_store,
            applied_index: 0,
            applied_term: 0,
            raw_payload_commitment: Hash::ZERO,
            disposition: None,
        }
    }

    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn applied(&self) -> (u64, u64) {
        (self.applied_index, self.applied_term)
    }

    pub(crate) const fn raw_payload_commitment(&self) -> Hash {
        self.raw_payload_commitment
    }

    pub(crate) const fn disposition(&self) -> Option<AgentRaftApplyDispositionV2> {
        self.disposition
    }

    fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.generation.validate()?;
        if self.journal_store.as_bytes() == &[0; 32] {
            return Err(AgentRaftWireError::InvalidApplyMeta);
        }
        let empty = self.applied_index == 0
            && self.applied_term == 0
            && self.raw_payload_commitment == Hash::ZERO
            && self.disposition.is_none();
        let populated = self.applied_index != 0
            && self.applied_term != 0
            && self.raw_payload_commitment != Hash::ZERO
            && self.disposition.is_some();
        if !empty && !populated {
            return Err(AgentRaftWireError::InvalidApplyMeta);
        }
        if let Some(disposition) = self.disposition {
            disposition.validate()?;
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_APPLY_META_BYTES)
    }
}

#[cfg(feature = "storage")]
impl ServiceWire for AgentRaftApplyMetaV2 {
    const MAGIC: [u8; 4] = *b"AGM2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_generation_route(&mut encoder, self.generation);
        encoder.fixed(self.journal_store.as_bytes());
        encoder.u64(self.applied_index);
        encoder.u64(self.applied_term);
        encoder.fixed(&self.raw_payload_commitment.0);
        encoder.option(&self.disposition, |encoder, disposition| {
            encode_disposition_v2(encoder, *disposition)
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_APPLY_META_BYTES)?;
        let meta = Self {
            generation: decode_generation_route(decoder)?,
            journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                .ok_or(DecodeError::NonCanonical)?,
            applied_index: decoder.u64()?,
            applied_term: decoder.u64()?,
            raw_payload_commitment: Hash(decoder.fixed()?),
            disposition: decoder.option(decode_disposition_v2)?,
        };
        meta.validate().map_err(map_wire_decode_error)?;
        Ok(meta)
    }
}

/// Immutable V2 audit row. Duplicate admission compares this complete record,
/// including the raw physical-slot commitment and final disposition.
#[cfg(feature = "storage")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentRaftApplyAuditRecordV2 {
    generation: AgentGenerationRouteKey,
    index: u64,
    term: u64,
    raw_payload_commitment: Hash,
    disposition: AgentRaftApplyDispositionV2,
}

#[cfg(feature = "storage")]
impl AgentRaftApplyAuditRecordV2 {
    fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.generation.validate()?;
        self.disposition.validate()?;
        if self.index == 0 || self.term == 0 || self.raw_payload_commitment == Hash::ZERO {
            return Err(AgentRaftWireError::InvalidApplyMeta);
        }
        enforce_wire_bound(self, MAX_AGENT_RAFT_APPLY_META_BYTES)
    }
}

#[cfg(feature = "storage")]
impl ServiceWire for AgentRaftApplyAuditRecordV2 {
    const MAGIC: [u8; 4] = *b"AGA2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_generation_route(&mut encoder, self.generation);
        encoder.u64(self.index);
        encoder.u64(self.term);
        encoder.fixed(&self.raw_payload_commitment.0);
        encode_disposition_v2(&mut encoder, self.disposition);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_AGENT_RAFT_APPLY_META_BYTES)?;
        let record = Self {
            generation: decode_generation_route(decoder)?,
            index: decoder.u64()?,
            term: decoder.u64()?,
            raw_payload_commitment: Hash(decoder.fixed()?),
            disposition: decode_disposition_v2(decoder)?,
        };
        record.validate().map_err(map_wire_decode_error)?;
        Ok(record)
    }
}

#[cfg(feature = "storage")]
const MAX_COMMITTEE_AUTHORITY_BINDING_BYTES: usize = 512;
#[cfg(feature = "storage")]
const MAX_COMMITTEE_APPLICATION_STATE_BYTES: usize = 256 * 1024;

/// Independently supplied trust root for typed committee-change receipts.
///
/// This binding is written into the immutable generation configuration. A
/// receipt's embedded producer/key relationship is therefore never allowed
/// to select its own authority. `initial_epoch` is the exact authority epoch
/// expected for the initial committee; successful stable transitions advance
/// it by one.
#[cfg(feature = "storage")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeChangeAuthorityBinding {
    policy: crate::agent_sdk::Hash,
    issuer: crate::agent_sdk::authority::AuthorityIssuer,
    runtime_deployment: crate::agent_sdk::DeploymentId,
    public_key: [u8; 32],
    initial_epoch: u64,
}

#[cfg(feature = "storage")]
impl CommitteeChangeAuthorityBinding {
    pub fn new(
        policy: crate::agent_sdk::Hash,
        issuer: crate::agent_sdk::authority::AuthorityIssuer,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        public_key: [u8; 32],
        initial_epoch: u64,
    ) -> Result<Self, AgentRaftWireError> {
        let binding = Self {
            policy,
            issuer,
            runtime_deployment,
            public_key,
            initial_epoch,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) const fn initial_epoch(self) -> u64 {
        self.initial_epoch
    }

    fn validate(self) -> Result<(), AgentRaftWireError> {
        if self.policy == crate::agent_sdk::Hash::ZERO
            || !self.issuer.is_valid()
            || self.runtime_deployment == crate::agent_sdk::DeploymentId::ZERO
            || self.public_key == [0; 32]
            || self.initial_epoch == 0
            || crate::agent_sdk::ProducerId::of_public_key(&self.public_key) != self.issuer.producer
        {
            return Err(AgentRaftWireError::InvalidAuthorityEvidence);
        }
        enforce_wire_bound(&self, MAX_COMMITTEE_AUTHORITY_BINDING_BYTES)
    }

    /// The receipt is verified at the change's leader-observed logical slot,
    /// the same clock an ordered clean management input uses. A physical
    /// Raft index is not an authority clock.
    fn verify(
        self,
        generation: AgentGenerationRouteKey,
        expected_epoch: u64,
        change: &PrepareCommitteeChange,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        use crate::agent_sdk::authority::AuthorityOperationKind;

        let receipt = change.authority();
        let selector = &receipt.selector;
        let logical_slot = change.observed_slot();
        let expected_request =
            committee_change_request(change.next(), change.expected_generation())
                .map_err(|_| AgentRaftApplicationErrorV2::WrongAuthority)?
                .commitment();
        if change.generation() != generation
            || selector.policy != self.policy
            || selector.issuer != self.issuer
            || selector.runtime_deployment != self.runtime_deployment
            || receipt.public_key != self.public_key
            || selector.operation != AuthorityOperationKind::ChangeReplicaSet
            || selector.space.as_bytes() != &generation.space.0
            || selector.agent.as_bytes() != &generation.agent.0
            || selector.epoch != expected_epoch
            || selector.request != expected_request
        {
            return Err(AgentRaftApplicationErrorV2::WrongAuthority);
        }
        if !selector.is_live_at(logical_slot) {
            return Err(AgentRaftApplicationErrorV2::StaleAuthority);
        }
        receipt
            .verify_at(logical_slot, &RawCommitteeAuthorityVerifier)
            .map_err(|_| AgentRaftApplicationErrorV2::WrongAuthority)
    }
}

#[cfg(feature = "storage")]
struct RawCommitteeAuthorityVerifier;

#[cfg(feature = "storage")]
impl crate::agent_sdk::authority::AuthorityVerifier for RawCommitteeAuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

#[cfg(feature = "storage")]
impl ServiceWire for CommitteeChangeAuthorityBinding {
    const MAGIC: [u8; 4] = *b"ACB2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.policy.as_bytes());
        encoder.fixed(self.issuer.principal.as_bytes());
        encoder.fixed(self.issuer.actor.as_bytes());
        encoder.fixed(self.issuer.deployment.as_bytes());
        encoder.fixed(self.issuer.program.as_bytes());
        encoder.fixed(self.issuer.producer.as_bytes());
        encoder.fixed(self.runtime_deployment.as_bytes());
        encoder.fixed(&self.public_key);
        encoder.u64(self.initial_epoch);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_COMMITTEE_AUTHORITY_BINDING_BYTES)?;
        let binding = Self {
            policy: crate::agent_sdk::Hash(decoder.fixed()?),
            issuer: crate::agent_sdk::authority::AuthorityIssuer {
                principal: crate::agent_sdk::PrincipalId(decoder.fixed()?),
                actor: crate::agent_sdk::ActorId(decoder.fixed()?),
                deployment: crate::agent_sdk::DeploymentId(decoder.fixed()?),
                program: crate::agent_sdk::ProgramId(decoder.fixed()?),
                producer: crate::agent_sdk::ProducerId(decoder.fixed()?),
            },
            runtime_deployment: crate::agent_sdk::DeploymentId(decoder.fixed()?),
            public_key: decoder.fixed()?,
            initial_epoch: decoder.u64()?,
        };
        binding.validate().map_err(map_wire_decode_error)?;
        Ok(binding)
    }
}

#[cfg(feature = "storage")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingCommitteePhaseV2 {
    Prepared,
    Joint {
        index: u64,
        term: u64,
        raw_payload_commitment: Hash,
    },
}

#[cfg(feature = "storage")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCommitteeChangeV2 {
    change: PrepareCommitteeChange,
    prepare_index: u64,
    prepare_term: u64,
    prepare_payload_commitment: Hash,
    phase: PendingCommitteePhaseV2,
}

#[cfg(feature = "storage")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommitteeApplicationStateV2 {
    generation: AgentGenerationRouteKey,
    active: AgentReplicaCommittee,
    authority_epoch: u64,
    pending: Option<PendingCommitteeChangeV2>,
}

#[cfg(feature = "storage")]
impl CommitteeApplicationStateV2 {
    fn initial(
        generation: AgentGenerationRouteKey,
        active: AgentReplicaCommittee,
        authority_epoch: u64,
    ) -> Self {
        Self {
            generation,
            active,
            authority_epoch,
            pending: None,
        }
    }

    fn validate(&self) -> Result<(), AgentRaftWireError> {
        self.generation.validate()?;
        self.active
            .validate()
            .map_err(|_| AgentRaftWireError::InvalidCommitteeTransition)?;
        if self.active.profile() != AgentProfile::Shared
            || self.active.space() != self.generation.space
            || self.active.agent() != self.generation.agent
            || self.authority_epoch == 0
        {
            return Err(AgentRaftWireError::InvalidCommitteeTransition);
        }
        if let Some(pending) = &self.pending {
            pending.change.validate()?;
            if pending.change.generation() != self.generation
                || pending.change.previous() != &self.active
                || pending.change.authority().selector.epoch != self.authority_epoch
                || pending.prepare_index == 0
                || pending.prepare_term == 0
                || pending.prepare_payload_commitment == Hash::ZERO
            {
                return Err(AgentRaftWireError::InvalidCommitteeTransition);
            }
            if let PendingCommitteePhaseV2::Joint {
                index,
                term,
                raw_payload_commitment,
            } = pending.phase
                && (index != pending.prepare_index.saturating_add(1)
                    || term < pending.prepare_term
                    || raw_payload_commitment == Hash::ZERO)
            {
                return Err(AgentRaftWireError::InvalidCommitteeTransition);
            }
        }
        enforce_wire_bound(self, MAX_COMMITTEE_APPLICATION_STATE_BYTES)
    }
}

#[cfg(feature = "storage")]
impl ServiceWire for CommitteeApplicationStateV2 {
    const MAGIC: [u8; 4] = *b"ACS2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encode_generation_route(&mut encoder, self.generation);
        encoder.bytes(&self.active.encode());
        encoder.u64(self.authority_epoch);
        encoder.option(&self.pending, |encoder, pending| {
            encoder.bytes(&pending.change.encode());
            encoder.u64(pending.prepare_index);
            encoder.u64(pending.prepare_term);
            encoder.fixed(&pending.prepare_payload_commitment.0);
            match pending.phase {
                PendingCommitteePhaseV2::Prepared => encoder.u8(0),
                PendingCommitteePhaseV2::Joint {
                    index,
                    term,
                    raw_payload_commitment,
                } => {
                    encoder.u8(1);
                    encoder.u64(index);
                    encoder.u64(term);
                    encoder.fixed(&raw_payload_commitment.0);
                }
            }
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_COMMITTEE_APPLICATION_STATE_BYTES)?;
        let state = Self {
            generation: decode_generation_route(decoder)?,
            active: decode_nested::<AgentReplicaCommittee>(
                decoder,
                MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            )?,
            authority_epoch: decoder.u64()?,
            pending: decoder.option(|decoder| {
                let change = decode_nested::<PrepareCommitteeChange>(
                    decoder,
                    MAX_PREPARE_COMMITTEE_CHANGE_BYTES,
                )?;
                let prepare_index = decoder.u64()?;
                let prepare_term = decoder.u64()?;
                let prepare_payload_commitment = Hash(decoder.fixed()?);
                let phase = match decoder.u8()? {
                    0 => PendingCommitteePhaseV2::Prepared,
                    1 => PendingCommitteePhaseV2::Joint {
                        index: decoder.u64()?,
                        term: decoder.u64()?,
                        raw_payload_commitment: Hash(decoder.fixed()?),
                    },
                    _ => return Err(DecodeError::InvalidTag),
                };
                Ok(PendingCommitteeChangeV2 {
                    change,
                    prepare_index,
                    prepare_term,
                    prepare_payload_commitment,
                    phase,
                })
            })?,
        };
        state.validate().map_err(map_wire_decode_error)?;
        Ok(state)
    }
}

/// Opaque proof that the evidence ledger durably reserved capacity for this
/// exact next committed application before replay may publish it.
///
/// Only [`AgentRaftEvidenceLedger::reserve_ordered_application`] can mint a
/// production value. An exact retry may mint another equivalent value for the
/// same durable reservation, so safety does not rely on bearer uniqueness:
/// replay is restricted to the bound journal-store instance and an exact
/// idempotent CAS, while the first successful anchor atomically consumes the
/// one durable reservation. The ledger later rejects every duplicate receipt.
#[derive(Debug)]
pub(crate) struct ReservedAgentRaftApplication {
    committed: CommittedAgentRaftEntry,
    local_node: NodeId,
    journal_store: JournalStoreInstanceId,
    artifact_batch: Option<ArtifactBatchId>,
}

/// Read-only recovery evidence for an exact application already anchored
/// after journal publication. Unlike a reservation, this value cannot
/// authorize replay or another CAS.
#[derive(Clone, Debug)]
pub(crate) struct AnchoredAgentRaftApplication {
    route: AgentRouteKey,
    index: u64,
    term: u64,
    payload: Hash,
    journal_store: JournalStoreInstanceId,
    entry: OrderedEntryId,
    claim: OrderedCommitClaim,
    successor: JournalHeadsId,
}

impl AnchoredAgentRaftApplication {
    pub(crate) const fn route(&self) -> AgentRouteKey {
        self.route
    }

    pub(crate) const fn index(&self) -> u64 {
        self.index
    }

    pub(crate) const fn term(&self) -> u64 {
        self.term
    }

    pub(crate) const fn payload_commitment(&self) -> Hash {
        self.payload
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn entry(&self) -> OrderedEntryId {
        self.entry
    }

    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn successor(&self) -> JournalHeadsId {
        self.successor
    }
}

impl ReservedAgentRaftApplication {
    #[cfg(test)]
    pub(crate) fn reserved_for_test(
        committed: CommittedAgentRaftEntry,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
    ) -> Self {
        let artifact_batch = match committed.command() {
            AgentRaftCommand::Ordered { artifact_batch, .. } => *artifact_batch,
            _ => None,
        };
        Self {
            committed,
            local_node,
            journal_store,
            artifact_batch,
        }
    }

    pub(crate) const fn committed(&self) -> &CommittedAgentRaftEntry {
        &self.committed
    }

    pub(crate) fn route(&self) -> AgentRouteKey {
        self.committed.route()
    }

    pub(crate) const fn index(&self) -> u64 {
        self.committed.index()
    }

    pub(crate) const fn term(&self) -> u64 {
        self.committed.term()
    }

    pub(crate) const fn payload_commitment(&self) -> Hash {
        self.committed.payload_commitment()
    }

    pub(crate) const fn local_node(&self) -> NodeId {
        self.local_node
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn artifact_batch(&self) -> Option<ArtifactBatchId> {
        self.artifact_batch
    }
}

/// Read-only contract implemented later by the production durable Raft log.
///
/// The tuple is `(stored_index, term, durable_commit_index, canonical_payload)`.
/// Implementations must take all four values from one durable read view.  The
/// constructor above independently rejects zeros, a non-committed slot, the
/// wrong index, an over-limit payload, or a non-canonical command.
pub(crate) trait DurableAgentRaftLogWitness {
    type Error;

    fn read_committed_payload(
        &self,
        index: u64,
    ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error>;
}

#[derive(Debug)]
pub(crate) enum CommittedAgentRaftEntryError<E> {
    Witness(E),
    Missing,
    Invalid(AgentRaftWireError),
}

/// Structural failure for a canonical Shared-Agent Raft wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRaftWireError {
    InvalidRoute,
    InvalidConfiguration,
    InvalidArtifactBatch,
    InvalidArtifactChunk,
    InvalidOrderedCommand,
    InvalidCommitteeTransition,
    InvalidAuthorityEvidence,
    InvalidApplyMeta,
    InvalidCommittedEntry,
    InvalidPhysicalSlot,
    NonCanonical,
    LimitExceeded,
}

impl fmt::Display for AgentRaftWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Shared Agent Raft wire: {self:?}")
    }
}

impl core::error::Error for AgentRaftWireError {}

/// Durable-ledger, application-ordering, or evidence-validation failure.
#[derive(Debug)]
pub enum AgentRaftLedgerError {
    Wire(AgentRaftWireError),
    SharedCommit(SharedCommitError),
    InvalidCommittee,
    WrongRoute,
    WrongJournalStore,
    LocalReplicaNotVoter,
    UnknownSigner,
    ObserverSigner,
    InvalidSignature,
    OrderedClaimRequired,
    ArtifactBatchReceiptRequired,
    InvalidClaim,
    ClaimNotAnchored,
    ApplyGap,
    AppliedConflict,
    DivergentClaim,
    DivergentReservation,
    ConflictingCertificate,
    BacklogLimit,
    LocalShareRequiresPledge,
    ConfigurationMismatch,
    CorruptLedger,
    FailStopped,
    #[cfg(all(feature = "std", feature = "storage"))]
    Backend(alloc::boxed::Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for AgentRaftLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::SharedCommit(error) => error.fmt(formatter),
            #[cfg(all(feature = "std", feature = "storage"))]
            Self::Backend(error) => write!(formatter, "Shared Agent evidence backend: {error}"),
            _ => write!(formatter, "Shared Agent Raft evidence failure: {self:?}"),
        }
    }
}

impl core::error::Error for AgentRaftLedgerError {
    #[cfg(all(feature = "std", feature = "storage"))]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::SharedCommit(error) => Some(error),
            Self::Backend(error) => Some(&**error),
            _ => None,
        }
    }
}

impl From<AgentRaftWireError> for AgentRaftLedgerError {
    fn from(error: AgentRaftWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<SharedCommitError> for AgentRaftLedgerError {
    fn from(error: SharedCommitError) -> Self {
        Self::SharedCommit(error)
    }
}

fn artifact_chunk_commitment(
    batch: ArtifactBatchId,
    artifact_index: u32,
    offset: u64,
    bytes: &[u8],
) -> Hash {
    let artifact_index = artifact_index.to_le_bytes();
    let offset = offset.to_le_bytes();
    Hash::digest(
        ARTIFACT_CHUNK_COMMITMENT_DOMAIN,
        &[batch.as_bytes(), &artifact_index, &offset, bytes],
    )
}

fn encode_route(encoder: &mut Encoder<'_>, route: AgentRouteKey) {
    encode_generation_route(encoder, route.generation());
    encoder.fixed(route.committee.as_bytes());
}

fn decode_route(decoder: &mut Decoder<'_>) -> Result<AgentRouteKey, DecodeError> {
    let generation = decode_generation_route(decoder)?;
    AgentRouteKey::new(
        generation.space(),
        generation.agent(),
        generation.genesis(),
        generation.admission(),
        AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
    )
    .map_err(map_wire_decode_error)
}

fn encode_generation_route(encoder: &mut Encoder<'_>, route: AgentGenerationRouteKey) {
    encoder.fixed(&route.space.0);
    encoder.fixed(&route.agent.0);
    encoder.fixed(route.genesis.as_bytes());
    encoder.fixed(route.admission.as_bytes());
}

fn decode_generation_route(
    decoder: &mut Decoder<'_>,
) -> Result<AgentGenerationRouteKey, DecodeError> {
    AgentGenerationRouteKey::new(
        SpaceId(decoder.fixed()?),
        AgentId(decoder.fixed()?),
        AgentJournalGenesisId(decoder.fixed()?),
        AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
    )
    .map_err(map_wire_decode_error)
}

fn encode_blob_ref(encoder: &mut Encoder<'_>, artifact: &BlobRef) {
    encoder.fixed(&artifact.hash.0);
    encoder.u64(artifact.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_disposition(encoder: &mut Encoder<'_>, disposition: AgentRaftAuditDisposition) {
    match disposition {
        AgentRaftAuditDisposition::ArtifactChunkStored {
            batch,
            artifact,
            offset,
            chunk,
        } => {
            encoder.u8(0);
            encoder.fixed(batch.as_bytes());
            encoder.fixed(&artifact.0);
            encoder.u64(offset);
            encoder.fixed(&chunk.0);
        }
        AgentRaftAuditDisposition::ArtifactBatchAborted { batch } => {
            encoder.u8(1);
            encoder.fixed(batch.as_bytes());
        }
        AgentRaftAuditDisposition::OrderedApplied {
            entry,
            claim,
            successor,
        } => {
            encoder.u8(2);
            encoder.fixed(entry.as_bytes());
            encoder.fixed(&claim.0);
            encoder.fixed(successor.as_bytes());
        }
    }
}

fn decode_disposition(decoder: &mut Decoder<'_>) -> Result<AgentRaftAuditDisposition, DecodeError> {
    let disposition = match decoder.u8()? {
        0 => AgentRaftAuditDisposition::ArtifactChunkStored {
            batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
            artifact: Hash(decoder.fixed()?),
            offset: decoder.u64()?,
            chunk: Hash(decoder.fixed()?),
        },
        1 => AgentRaftAuditDisposition::ArtifactBatchAborted {
            batch: ArtifactBatchId::from_bytes(decoder.fixed()?),
        },
        2 => AgentRaftAuditDisposition::OrderedApplied {
            entry: OrderedEntryId(decoder.fixed()?),
            claim: Hash(decoder.fixed()?),
            successor: JournalHeadsId(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    disposition.validate().map_err(map_wire_decode_error)?;
    Ok(disposition)
}

#[cfg(feature = "storage")]
fn encode_disposition_v2(encoder: &mut Encoder<'_>, disposition: AgentRaftApplyDispositionV2) {
    match disposition {
        AgentRaftApplyDispositionV2::LeaderNoop => encoder.u8(0),
        AgentRaftApplyDispositionV2::RecoveryRegistered {
            registration,
            manifest,
        } => {
            encoder.u8(5);
            encoder.fixed(&registration.0);
            encoder.fixed(&manifest.0);
        }
        AgentRaftApplyDispositionV2::RecoveryExpired {
            certificate,
            manifest,
        } => {
            encoder.u8(6);
            encoder.fixed(&certificate.0);
            encoder.fixed(&manifest.0);
        }
        AgentRaftApplyDispositionV2::Command(disposition) => {
            encoder.u8(1);
            encode_disposition(encoder, disposition);
        }
        AgentRaftApplyDispositionV2::CommitteeChangePrepared {
            transition,
            previous,
            next,
            authority,
        } => {
            encoder.u8(4);
            encoder.fixed(transition.as_bytes());
            encoder.fixed(previous.as_bytes());
            encoder.fixed(next.as_bytes());
            encoder.fixed(&authority.0);
        }
        AgentRaftApplyDispositionV2::CommitteeJointConfiguration {
            transition,
            previous,
            next,
        } => {
            encoder.u8(2);
            encoder.fixed(transition.as_bytes());
            encoder.fixed(previous.as_bytes());
            encoder.fixed(next.as_bytes());
        }
        AgentRaftApplyDispositionV2::CommitteeStableConfiguration {
            transition,
            committee,
        } => {
            encoder.u8(3);
            encoder.fixed(transition.as_bytes());
            encoder.fixed(committee.as_bytes());
        }
    }
}

#[cfg(feature = "storage")]
fn decode_disposition_v2(
    decoder: &mut Decoder<'_>,
) -> Result<AgentRaftApplyDispositionV2, DecodeError> {
    let disposition = match decoder.u8()? {
        0 => AgentRaftApplyDispositionV2::LeaderNoop,
        1 => AgentRaftApplyDispositionV2::Command(decode_disposition(decoder)?),
        2 => AgentRaftApplyDispositionV2::CommitteeJointConfiguration {
            transition: CommitteeTransitionId::from_bytes(decoder.fixed()?),
            previous: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
            next: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
        },
        3 => AgentRaftApplyDispositionV2::CommitteeStableConfiguration {
            transition: CommitteeTransitionId::from_bytes(decoder.fixed()?),
            committee: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
        },
        4 => AgentRaftApplyDispositionV2::CommitteeChangePrepared {
            transition: CommitteeTransitionId::from_bytes(decoder.fixed()?),
            previous: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
            next: AgentReplicaCommitteeId::from_bytes(decoder.fixed()?),
            authority: Hash(decoder.fixed()?),
        },
        5 => AgentRaftApplyDispositionV2::RecoveryRegistered {
            registration: Hash(decoder.fixed()?),
            manifest: Hash(decoder.fixed()?),
        },
        6 => AgentRaftApplyDispositionV2::RecoveryExpired {
            certificate: Hash(decoder.fixed()?),
            manifest: Hash(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    disposition.validate().map_err(map_wire_decode_error)?;
    Ok(disposition)
}

fn bounded_bytes(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(decoder.take(len)?.to_vec())
}

fn decode_nested<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    T::decode(bytes)
}

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    let maximum_body = maximum
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > maximum_body {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn enforce_wire_bound<T: ServiceWire>(value: &T, maximum: usize) -> Result<(), AgentRaftWireError> {
    if value.encode().len() > maximum {
        Err(AgentRaftWireError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_wire_decode_error(error: AgentRaftWireError) -> DecodeError {
    match error {
        AgentRaftWireError::LimitExceeded => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
mod evidence_ledger {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use ed25519_dalek::VerifyingKey;
    use redb::{Database, ReadableTable, TableDefinition};

    use super::*;

    const LEDGER_SCHEMA_VERSION: u32 = 1;
    const MAX_CONFIG_RECORD_BYTES: usize = 72 * 1024;
    const MAX_RESERVATION_RECORD_BYTES: usize = 512;
    const MAX_ANCHOR_RECORD_BYTES: usize = 8 * 1024;
    const MAX_PLEDGE_RECORD_BYTES: usize = 8 * 1024;
    const MAX_SHARE_RECORD_BYTES: usize = 512;
    const MAX_FAIL_STOP_RECORD_BYTES: usize = 512;

    const CONFIG_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_config");
    const APPLY_META_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_meta");
    const RESERVATION_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_reservation");
    const ANCHOR_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_claim_anchors");
    const PLEDGE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_sign_pledges");
    const SHARE_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_commit_shares");
    const QC_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_quorum_certificates");
    const FAIL_STOP_TABLE: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_fail_stop");

    const ROUTE_STORAGE_KEY_BYTES: usize = 32 * 5;
    const ENTRY_STORAGE_KEY_BYTES: usize = ROUTE_STORAGE_KEY_BYTES + 8;
    const SHARE_STORAGE_KEY_BYTES: usize = ENTRY_STORAGE_KEY_BYTES + 32;

    /// Signer invoked only after the ledger has durably committed an exact
    /// `(route, Raft index, claim)` pledge.
    pub(crate) trait ReplicaCommitSigner {
        type Error;

        fn node(&self) -> NodeId;
        fn sign_commit_message(&self, message: Hash) -> Result<[u8; 64], Self::Error>;
    }

    #[derive(Debug)]
    pub(crate) enum AgentRaftSignError<E> {
        Ledger(AgentRaftLedgerError),
        Signer(E),
    }

    impl<E: fmt::Display> fmt::Display for AgentRaftSignError<E> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ledger(error) => error.fmt(formatter),
                Self::Signer(error) => write!(formatter, "replica commit signer failed: {error}"),
            }
        }
    }

    impl<E: core::error::Error + 'static> core::error::Error for AgentRaftSignError<E> {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Ledger(error) => Some(error),
                Self::Signer(error) => Some(error),
            }
        }
    }

    impl<E> From<AgentRaftLedgerError> for AgentRaftSignError<E> {
        fn from(error: AgentRaftLedgerError) -> Self {
            Self::Ledger(error)
        }
    }

    /// Result of persisting one exact share. A certificate is present once
    /// the independently admitted voter threshold has been verified.
    #[derive(Clone, Debug)]
    pub(crate) struct AgentRaftShareOutcome {
        share: ReplicaCommitSignature,
        certificate: Option<ReplicaQuorumCertificate>,
    }

    impl AgentRaftShareOutcome {
        pub(crate) const fn share(&self) -> &ReplicaCommitSignature {
            &self.share
        }

        pub(crate) const fn certificate(&self) -> Option<&ReplicaQuorumCertificate> {
            self.certificate.as_ref()
        }
    }

    /// Crash-safe sign-once and application-QC ledger for one exact route.
    ///
    /// The database may be shared with other routes. Every key and every value
    /// repeats the complete route, so table selection never supplies ambient
    /// identity. All writes are serialized per handle; redb supplies the
    /// durable cross-handle transaction boundary.
    pub(crate) struct AgentRaftEvidenceLedger {
        database: Arc<Database>,
        route: AgentRouteKey,
        committee: AgentReplicaCommittee,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
        writes: std::sync::Mutex<()>,
    }

    impl AgentRaftEvidenceLedger {
        pub(crate) fn open(
            database: Arc<Database>,
            route: AgentRouteKey,
            committee: AgentReplicaCommittee,
            local_node: NodeId,
            journal_store: JournalStoreInstanceId,
        ) -> Result<Self, AgentRaftLedgerError> {
            validate_configuration(route, &committee, local_node)?;
            let expected = ConfigRecord {
                version: LEDGER_SCHEMA_VERSION,
                route,
                committee: committee.clone(),
                local_node,
                journal_store,
            };
            let route_key = route_storage_key(route);
            let transaction = database.begin_write()?;
            {
                let mut table = transaction.open_table(CONFIG_TABLE)?;
                let existing = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec());
                match existing {
                    Some(bytes) => {
                        if ConfigRecord::decode(&bytes)
                            .map_err(|_| AgentRaftLedgerError::CorruptLedger)?
                            != expected
                        {
                            return Err(AgentRaftLedgerError::ConfigurationMismatch);
                        }
                    }
                    None => {
                        table.insert(route_key.as_slice(), expected.encode().as_slice())?;
                    }
                }
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE)?;
                if table.get(route_key.as_slice())?.is_none() {
                    table.insert(
                        route_key.as_slice(),
                        AgentRaftApplyMeta::post_genesis(route).encode().as_slice(),
                    )?;
                }
            }
            // Opening all tables in the initialization transaction pins their
            // schemas before any later pledge or share can be written.
            {
                let _ = transaction.open_table(ANCHOR_TABLE)?;
            }
            {
                let _ = transaction.open_table(RESERVATION_TABLE)?;
            }
            {
                let _ = transaction.open_table(PLEDGE_TABLE)?;
            }
            {
                let _ = transaction.open_table(SHARE_TABLE)?;
            }
            {
                let _ = transaction.open_table(QC_TABLE)?;
            }
            {
                let _ = transaction.open_table(FAIL_STOP_TABLE)?;
            }
            transaction.commit()?;

            let ledger = Self {
                database,
                route,
                committee,
                local_node,
                journal_store,
                writes: std::sync::Mutex::new(()),
            };
            ledger.audit_recovery()?;
            Ok(ledger)
        }

        pub(crate) const fn route(&self) -> AgentRouteKey {
            self.route
        }

        pub(crate) const fn committee(&self) -> &AgentReplicaCommittee {
            &self.committee
        }

        pub(crate) const fn local_node(&self) -> NodeId {
            self.local_node
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.journal_store
        }

        pub(crate) fn apply_meta(&self) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let key = route_storage_key(self.route);
            let bytes = read_exact(&self.database, APPLY_META_TABLE, key.as_slice())?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            let meta = AgentRaftApplyMeta::decode(&bytes)
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if meta.route != self.route {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(meta)
        }

        pub(crate) fn is_fail_stopped(&self) -> Result<bool, AgentRaftLedgerError> {
            let key = route_storage_key(self.route);
            Ok(read_exact(&self.database, FAIL_STOP_TABLE, key.as_slice())?.is_some())
        }

        /// Durably reserve the one next Ordered slot before replay is allowed
        /// to perform its journal CAS. Exact reopen/retry returns the same
        /// opaque authority; a different slot under the same pending route
        /// permanently fail-stops new work. Because a returned authority may
        /// already have crossed the journal CAS, the exact originally stored
        /// reservation remains drainable into one anchor after fail-stop.
        pub(crate) fn reserve_ordered_application(
            &self,
            committed: &CommittedAgentRaftEntry,
        ) -> Result<ReservedAgentRaftApplication, AgentRaftLedgerError> {
            if committed.route() != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    ..
                } => {}
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            }
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let route_key = route_storage_key(self.route);
            let expected = ReservationRecord::from_committed(committed, self.journal_store)?;
            let transaction = self.database.begin_write()?;
            let fail_stopped = {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                table.get(route_key.as_slice())?.is_some()
            };
            let existing = {
                let table = transaction.open_table(RESERVATION_TABLE)?;
                table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
            }
            .map(|bytes| {
                ReservationRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)
            })
            .transpose()?;
            if fail_stopped && existing.as_ref().is_none_or(|stored| stored != &expected) {
                return Err(AgentRaftLedgerError::FailStopped);
            }
            let current = {
                let table = transaction.open_table(APPLY_META_TABLE)?;
                let bytes = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                AgentRaftApplyMeta::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?
            };
            if current.route != self.route {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }

            if committed.index() <= current.applied_index {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            if committed.index() != current.applied_index.saturating_add(1)
                || (current.applied_index != 0 && committed.term() < current.applied_term)
            {
                return Err(AgentRaftLedgerError::ApplyGap);
            }

            if let Some(existing) = existing {
                if existing == expected {
                    return Ok(ReservedAgentRaftApplication {
                        committed: committed.clone(),
                        local_node: self.local_node,
                        journal_store: self.journal_store,
                        artifact_batch: None,
                    });
                }
                let fail_stop = FailStopRecord {
                    route: self.route,
                    index: committed.index(),
                    expected: existing.commitment(),
                    observed: expected.commitment(),
                };
                fail_stop.validate()?;
                {
                    let mut table = transaction.open_table(FAIL_STOP_TABLE)?;
                    if table.get(route_key.as_slice())?.is_none() {
                        table.insert(route_key.as_slice(), fail_stop.encode().as_slice())?;
                    }
                }
                transaction.commit()?;
                return Err(AgentRaftLedgerError::DivergentReservation);
            }

            {
                let table = transaction.open_table(ANCHOR_TABLE)?;
                let prefix = route_storage_key(self.route);
                let mut count = 0_usize;
                for row in table.range(prefix.as_slice()..)? {
                    let (key, _) = row?;
                    if !key.value().starts_with(prefix.as_slice()) {
                        break;
                    }
                    if count == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                        return Err(AgentRaftLedgerError::BacklogLimit);
                    }
                    count += 1;
                }
                if count == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                    return Err(AgentRaftLedgerError::BacklogLimit);
                }
            }
            {
                let mut table = transaction.open_table(RESERVATION_TABLE)?;
                table.insert(route_key.as_slice(), expected.encode().as_slice())?;
            }
            transaction.commit()?;
            Ok(ReservedAgentRaftApplication {
                committed: committed.clone(),
                local_node: self.local_node,
                journal_store: self.journal_store,
                artifact_batch: None,
            })
        }

        /// Read the exact post-CAS anchor for an application which already
        /// completed. This recovery value is intentionally not a reservation
        /// and cannot authorize another replay publication.
        pub(crate) fn recover_applied_ordered(
            &self,
            committed: &CommittedAgentRaftEntry,
        ) -> Result<Option<AnchoredAgentRaftApplication>, AgentRaftLedgerError> {
            if committed.route() != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            let entry = match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    entry,
                    ..
                } => entry,
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            };
            let Some(anchor) = self.anchor(committed.index())? else {
                return Ok(None);
            };
            validate_claim_link(self.route, committed, &anchor.claim)?;
            if anchor.journal_store != self.journal_store
                || anchor.term != committed.term()
                || anchor.payload != committed.payload_commitment()
                || anchor.claim.ordered().head != Some(entry.id())
            {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            Ok(Some(AnchoredAgentRaftApplication {
                route: anchor.route,
                index: anchor.index,
                term: anchor.term,
                payload: anchor.payload,
                journal_store: anchor.journal_store,
                entry: entry.id(),
                claim: anchor.claim,
                successor: anchor.successor,
            }))
        }

        // Artifact dispositions remain canonical audit wires, but this first
        // slice intentionally exposes no method that can mint one from a Raft
        // command alone. A later artifact-store adapter must supply an opaque
        // successful-publication receipt before advancing `applied` for a
        // chunk or abort.

        /// Anchor only the exact claim carried by replay's opaque successful
        /// Shared-publication receipt. A raw claim cannot cross this boundary.
        pub(crate) fn anchor_applied_ordered(
            &self,
            published: PublishedSharedOrdered,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let reserved = published.reservation();
            if published.journal_store() != self.journal_store
                || reserved.journal_store() != self.journal_store
                || published.journal_store() != reserved.journal_store()
            {
                return Err(AgentRaftLedgerError::WrongJournalStore);
            }
            let committed = reserved.committed();
            let claim = published.claim();
            validate_claim_link(self.route, committed, claim)?;
            let entry = match committed.command() {
                AgentRaftCommand::Ordered { entry, .. } => entry,
                _ => return Err(AgentRaftLedgerError::InvalidClaim),
            };
            if published.entry() != entry.id()
                || published.raft_index() != committed.index()
                || published.raft_term() != committed.term()
                || published.raft_payload_commitment() != committed.payload_commitment()
            {
                return Err(AgentRaftLedgerError::InvalidClaim);
            }
            self.anchor_validated_ordered(reserved, claim, entry, published.successor())
        }

        #[cfg(test)]
        pub(super) fn anchor_applied_ordered_for_test(
            &self,
            reserved: ReservedAgentRaftApplication,
            claim: &OrderedCommitClaim,
            successor: JournalHeadsId,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let committed = reserved.committed();
            validate_claim_link(self.route, committed, claim)?;
            let entry = match committed.command() {
                AgentRaftCommand::Ordered { entry, .. } => entry,
                _ => return Err(AgentRaftLedgerError::InvalidClaim),
            };
            self.anchor_validated_ordered(&reserved, claim, entry, successor)
        }

        #[cfg(test)]
        pub(super) fn delete_anchor_for_test(
            &self,
            index: u64,
        ) -> Result<(), AgentRaftLedgerError> {
            let transaction = self.database.begin_write()?;
            {
                let mut table = transaction.open_table(ANCHOR_TABLE)?;
                table.remove(entry_storage_key(self.route, index).as_slice())?;
            }
            transaction.commit()?;
            Ok(())
        }

        fn anchor_validated_ordered(
            &self,
            reserved: &ReservedAgentRaftApplication,
            claim: &OrderedCommitClaim,
            entry: &OrderedEntry,
            successor: JournalHeadsId,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let disposition = AgentRaftAuditDisposition::OrderedApplied {
                entry: entry.id(),
                claim: claim.commitment(),
                successor,
            };
            self.record_apply(reserved, disposition, claim)
        }

        fn record_apply(
            &self,
            reserved: &ReservedAgentRaftApplication,
            disposition: AgentRaftAuditDisposition,
            claim: &OrderedCommitClaim,
        ) -> Result<AgentRaftApplyMeta, AgentRaftLedgerError> {
            let committed = reserved.committed();
            if committed.route() != self.route || reserved.local_node() != self.local_node {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            if reserved.journal_store() != self.journal_store {
                return Err(AgentRaftLedgerError::WrongJournalStore);
            }
            // A durable reservation is irrevocably admitted: its authority
            // may already have crossed the separate journal CAS before a
            // later conflict records fail-stop. Drain only that exact stored
            // reservation so journal and evidence cursors cannot split.
            // Fail-stop still gates every new reserve, pledge, share, and QC.
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let current = self.apply_meta()?;
            if committed.index <= current.applied_index {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            let next = current.advance_applied(committed, disposition)?;

            let route_key = route_storage_key(self.route);
            let entry_key = entry_storage_key(self.route, committed.index);
            let expected_reservation =
                ReservationRecord::from_committed(committed, self.journal_store)?;
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(RESERVATION_TABLE)?;
                let bytes = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                let stored = ReservationRecord::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if stored != expected_reservation {
                    return Err(AgentRaftLedgerError::DivergentReservation);
                }
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE)?;
                let stored = table
                    .get(route_key.as_slice())?
                    .map(|value| value.value().to_vec())
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                let stored = AgentRaftApplyMeta::decode(&stored)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if stored != current {
                    return Err(AgentRaftLedgerError::AppliedConflict);
                }
                table.insert(route_key.as_slice(), next.encode().as_slice())?;
            }
            let anchor = AnchorRecord {
                route: self.route,
                index: committed.index,
                term: committed.term,
                payload: committed.payload_commitment,
                journal_store: self.journal_store,
                successor: match disposition {
                    AgentRaftAuditDisposition::OrderedApplied { successor, .. } => successor,
                    _ => return Err(AgentRaftLedgerError::InvalidClaim),
                },
                claim: claim.clone(),
            };
            anchor.validate()?;
            {
                let mut table = transaction.open_table(ANCHOR_TABLE)?;
                if let Some(existing) = table
                    .get(entry_key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = AnchorRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != anchor {
                        return Err(AgentRaftLedgerError::DivergentClaim);
                    }
                } else {
                    table.insert(entry_key.as_slice(), anchor.encode().as_slice())?;
                }
            }
            {
                let mut table = transaction.open_table(RESERVATION_TABLE)?;
                if table.remove(route_key.as_slice())?.is_none() {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            transaction.commit()?;
            Ok(next)
        }

        /// Sign the exact anchored claim. The signer callback cannot run until
        /// the pledge transaction below has successfully committed.
        pub(crate) fn sign_local<S: ReplicaCommitSigner>(
            &self,
            claim: &OrderedCommitClaim,
            signer: &S,
        ) -> Result<AgentRaftShareOutcome, AgentRaftSignError<S::Error>> {
            if self
                .committee
                .member_by_node(self.local_node)
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
            {
                return Err(AgentRaftLedgerError::LocalReplicaNotVoter.into());
            }
            if signer.node() != self.local_node {
                return Err(AgentRaftLedgerError::UnknownSigner.into());
            }
            self.ensure_anchored(claim)?;
            if let Some(share) = self.share(claim.raft_index(), self.local_node)? {
                if self.pledged_claim(claim.raft_index())? != Some(claim.commitment()) {
                    return Err(AgentRaftLedgerError::CorruptLedger.into());
                }
                return Ok(AgentRaftShareOutcome {
                    share,
                    certificate: self.certificate(claim.raft_index())?,
                });
            }

            self.ensure_pledge(claim)?;
            // There is deliberately no fallible storage work between the
            // committed pledge above and this first signer invocation.
            let message =
                ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
            let bytes = signer
                .sign_commit_message(message)
                .map_err(AgentRaftSignError::Signer)?;
            let share = ReplicaCommitSignature::new(self.local_node, bytes)
                .map_err(AgentRaftLedgerError::SharedCommit)?;
            validate_share(&self.committee, claim, &share)?;
            self.record_share(claim, share).map_err(Into::into)
        }

        /// Validate and durably retain one remote voter share. Shares are not
        /// accepted ahead of local apply; this keeps the total backlog bounded
        /// and prevents a remote claim from creating local certification state
        /// before its exact journal projection exists.
        pub(crate) fn record_remote_share(
            &self,
            claim: &OrderedCommitClaim,
            share: ReplicaCommitSignature,
        ) -> Result<AgentRaftShareOutcome, AgentRaftLedgerError> {
            if share.signer() == self.local_node {
                return Err(AgentRaftLedgerError::LocalShareRequiresPledge);
            }
            self.ensure_anchored(claim)?;
            validate_share(&self.committee, claim, &share)?;
            self.record_share(claim, share)
        }

        pub(crate) fn pledged_claim(
            &self,
            index: u64,
        ) -> Result<Option<Hash>, AgentRaftLedgerError> {
            Ok(self.pledge(index)?.map(|pledge| pledge.claim.commitment()))
        }

        pub(crate) fn certificate(
            &self,
            index: u64,
        ) -> Result<Option<ReplicaQuorumCertificate>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, QC_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let certificate = ReplicaQuorumCertificate::decode(&bytes)
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let anchor = self
                .anchor(index)?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            certificate.verify(&self.committee, &anchor.claim)?;
            Ok(Some(certificate))
        }

        fn ensure_operational(&self) -> Result<(), AgentRaftLedgerError> {
            if self.is_fail_stopped()? {
                Err(AgentRaftLedgerError::FailStopped)
            } else {
                Ok(())
            }
        }

        fn ensure_anchored(&self, claim: &OrderedCommitClaim) -> Result<(), AgentRaftLedgerError> {
            self.ensure_operational()?;
            if AgentRouteKey::from_claim(claim).map_err(AgentRaftLedgerError::Wire)? != self.route {
                return Err(AgentRaftLedgerError::WrongRoute);
            }
            let Some(anchor) = self.anchor(claim.raft_index())? else {
                return Err(AgentRaftLedgerError::ClaimNotAnchored);
            };
            if anchor.claim != *claim {
                self.persist_fail_stop(
                    claim.raft_index(),
                    anchor.claim.commitment(),
                    claim.commitment(),
                )?;
                return Err(AgentRaftLedgerError::DivergentClaim);
            }
            Ok(())
        }

        fn ensure_pledge(&self, claim: &OrderedCommitClaim) -> Result<(), AgentRaftLedgerError> {
            self.ensure_operational()?;
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if let Some(existing) = self.pledge(claim.raft_index())? {
                if existing.claim == *claim {
                    return Ok(());
                }
                drop(_write);
                self.persist_fail_stop(
                    claim.raft_index(),
                    existing.claim.commitment(),
                    claim.commitment(),
                )?;
                return Err(AgentRaftLedgerError::DivergentClaim);
            }
            let pledge = PledgeRecord {
                route: self.route,
                index: claim.raft_index(),
                claim: claim.clone(),
            };
            pledge.validate()?;
            let key = entry_storage_key(self.route, claim.raft_index());
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table
                    .get(route_storage_key(self.route).as_slice())?
                    .is_some()
                {
                    return Err(AgentRaftLedgerError::FailStopped);
                }
            }
            {
                let mut table = transaction.open_table(PLEDGE_TABLE)?;
                if let Some(existing) = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = PledgeRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != pledge {
                        return Err(AgentRaftLedgerError::DivergentClaim);
                    }
                } else {
                    table.insert(key.as_slice(), pledge.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(())
        }

        fn record_share(
            &self,
            claim: &OrderedCommitClaim,
            share: ReplicaCommitSignature,
        ) -> Result<AgentRaftShareOutcome, AgentRaftLedgerError> {
            self.ensure_operational()?;
            self.ensure_anchored(claim)?;
            if share.signer() == self.local_node
                && self.pledged_claim(claim.raft_index())? != Some(claim.commitment())
            {
                return Err(AgentRaftLedgerError::LocalShareRequiresPledge);
            }
            validate_share(&self.committee, claim, &share)?;
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let key = share_storage_key(self.route, claim.raft_index(), share.signer());
            let record = ShareRecord {
                route: self.route,
                index: claim.raft_index(),
                claim: claim.commitment(),
                share: share.clone(),
            };
            record.validate()?;

            let route_key = route_storage_key(self.route);
            let transaction = self.database.begin_write()?;
            {
                let table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table.get(route_key.as_slice())?.is_some() {
                    return Err(AgentRaftLedgerError::FailStopped);
                }
            }
            let mut shares = Vec::new();
            {
                let mut table = transaction.open_table(SHARE_TABLE)?;
                if let Some(existing) = table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
                {
                    let existing = ShareRecord::decode(&existing)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if existing != record {
                        return Err(AgentRaftLedgerError::AppliedConflict);
                    }
                } else {
                    table.insert(key.as_slice(), record.encode().as_slice())?;
                }
                let prefix = entry_storage_key(self.route, claim.raft_index());
                for row in table.range(prefix.as_slice()..)? {
                    let (row_key, row_value) = row?;
                    if !row_key.value().starts_with(prefix.as_slice()) {
                        break;
                    }
                    let record = ShareRecord::decode(row_value.value())
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    if record.route != self.route
                        || record.index != claim.raft_index()
                        || record.claim != claim.commitment()
                    {
                        return Err(AgentRaftLedgerError::CorruptLedger);
                    }
                    validate_share(&self.committee, claim, &record.share)?;
                    if shares.len() == MAX_AGENT_REPLICAS {
                        return Err(AgentRaftLedgerError::BacklogLimit);
                    }
                    shares.push(record.share);
                }
            }
            if shares.len() > MAX_AGENT_REPLICAS {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            shares.sort_by_key(ReplicaCommitSignature::signer);
            if shares
                .windows(2)
                .any(|pair| pair[0].signer() >= pair[1].signer())
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }

            let certificate_key = entry_storage_key(self.route, claim.raft_index());
            let existing_certificate = {
                let table = transaction.open_table(QC_TABLE)?;
                table
                    .get(certificate_key.as_slice())?
                    .map(|value| value.value().to_vec())
            };
            let certificate = if let Some(bytes) = existing_certificate {
                let existing = ReplicaQuorumCertificate::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if existing.claim() != claim {
                    return Err(AgentRaftLedgerError::ConflictingCertificate);
                }
                existing.verify(&self.committee, claim)?;
                Some(existing)
            } else if shares.len() >= self.committee.quorum_threshold() {
                let certificate = ReplicaQuorumCertificate::new(claim.clone(), shares)?;
                certificate.verify(&self.committee, claim)?;
                {
                    let mut table = transaction.open_table(QC_TABLE)?;
                    table.insert(certificate_key.as_slice(), certificate.encode().as_slice())?;
                }
                Some(certificate)
            } else {
                None
            };
            if let Some(certificate) = &certificate {
                {
                    let mut table = transaction.open_table(APPLY_META_TABLE)?;
                    let bytes = table
                        .get(route_key.as_slice())?
                        .map(|value| value.value().to_vec())
                        .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                    let meta = AgentRaftApplyMeta::decode(&bytes)
                        .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                    let next = meta.advance_compact_safe(claim, certificate.commitment())?;
                    table.insert(route_key.as_slice(), next.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(AgentRaftShareOutcome { share, certificate })
        }

        fn anchor(&self, index: u64) -> Result<Option<AnchorRecord>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, ANCHOR_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                AnchorRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route
                || record.index != index
                || record.journal_store != self.journal_store
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record))
        }

        fn pledge(&self, index: u64) -> Result<Option<PledgeRecord>, AgentRaftLedgerError> {
            let key = entry_storage_key(self.route, index);
            let Some(bytes) = read_exact(&self.database, PLEDGE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                PledgeRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route || record.index != index {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record))
        }

        fn share(
            &self,
            index: u64,
            signer: NodeId,
        ) -> Result<Option<ReplicaCommitSignature>, AgentRaftLedgerError> {
            let key = share_storage_key(self.route, index, signer);
            let Some(bytes) = read_exact(&self.database, SHARE_TABLE, key.as_slice())? else {
                return Ok(None);
            };
            let record =
                ShareRecord::decode(&bytes).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if record.route != self.route
                || record.index != index
                || record.share.signer() != signer
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(Some(record.share))
        }

        fn persist_fail_stop(
            &self,
            index: u64,
            expected: Hash,
            observed: Hash,
        ) -> Result<(), AgentRaftLedgerError> {
            if index == 0
                || expected == Hash::ZERO
                || observed == Hash::ZERO
                || expected == observed
            {
                return Err(AgentRaftLedgerError::AppliedConflict);
            }
            let _write = self
                .writes
                .lock()
                .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            let record = FailStopRecord {
                route: self.route,
                index,
                expected,
                observed,
            };
            record.validate()?;
            let key = route_storage_key(self.route);
            let transaction = self.database.begin_write()?;
            {
                let mut table = transaction.open_table(FAIL_STOP_TABLE)?;
                if table.get(key.as_slice())?.is_none() {
                    table.insert(key.as_slice(), record.encode().as_slice())?;
                }
            }
            transaction.commit()?;
            Ok(())
        }

        fn audit_recovery(&self) -> Result<(), AgentRaftLedgerError> {
            let route_key = route_storage_key(self.route);
            let config = read_exact(&self.database, CONFIG_TABLE, route_key.as_slice())?
                .ok_or(AgentRaftLedgerError::CorruptLedger)?;
            let config =
                ConfigRecord::decode(&config).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
            if config.route != self.route
                || config.committee != self.committee
                || config.local_node != self.local_node
                || config.journal_store != self.journal_store
            {
                return Err(AgentRaftLedgerError::ConfigurationMismatch);
            }
            let meta = self.apply_meta()?;

            let anchor_rows = rows_for_route_bounded(
                &self.database,
                ANCHOR_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )?;
            let mut anchors = BTreeMap::new();
            for (key, value) in anchor_rows {
                let anchor = AnchorRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != entry_storage_key(self.route, anchor.index)
                    || anchor.route != self.route
                    || anchor.journal_store != self.journal_store
                    || anchor.index > meta.applied_index
                    || anchors.insert(anchor.index, anchor).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            if meta.applied_index > MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64
                || anchors.len() != meta.applied_index as usize
                || (1..=meta.applied_index).any(|index| !anchors.contains_key(&index))
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            if let Some(AgentRaftAuditDisposition::OrderedApplied {
                entry,
                claim,
                successor,
            }) = meta.disposition
            {
                let anchor = anchors
                    .get(&meta.applied_index)
                    .ok_or(AgentRaftLedgerError::CorruptLedger)?;
                if anchor.term != meta.applied_term
                    || anchor.payload != meta.applied_payload
                    || anchor.claim.ordered().head != Some(entry)
                    || anchor.claim.commitment() != claim
                    || anchor.successor != successor
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let reservation_rows =
                rows_for_route_bounded(&self.database, RESERVATION_TABLE, self.route, 1)?;
            if let Some((key, value)) = reservation_rows.into_iter().next() {
                let reservation = ReservationRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != route_key
                    || reservation.route != self.route
                    || reservation.journal_store != self.journal_store
                    || reservation.index != meta.applied_index.saturating_add(1)
                    || (meta.applied_index != 0 && reservation.term < meta.applied_term)
                    || anchors.contains_key(&reservation.index)
                    || anchors.len() == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let mut pledges = BTreeMap::new();
            for (key, value) in rows_for_route_bounded(
                &self.database,
                PLEDGE_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )? {
                let pledge = PledgeRecord::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if key != entry_storage_key(self.route, pledge.index)
                    || anchors
                        .get(&pledge.index)
                        .is_none_or(|anchor| anchor.claim != pledge.claim)
                    || pledges.insert(pledge.index, pledge).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }

            let share_rows = rows_for_route_bounded(
                &self.database,
                SHARE_TABLE,
                self.route,
                MAX_AGENT_RAFT_SHARE_BACKLOG,
            )?;
            for (key, value) in share_rows {
                let share =
                    ShareRecord::decode(&value).map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                let Some(anchor) = anchors.get(&share.index) else {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                };
                if key != share_storage_key(self.route, share.index, share.share.signer())
                    || share.route != self.route
                    || share.claim != anchor.claim.commitment()
                    || (share.share.signer() == self.local_node
                        && pledges
                            .get(&share.index)
                            .is_none_or(|pledge| pledge.claim != anchor.claim))
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
                validate_share(&self.committee, &anchor.claim, &share.share)?;
            }

            let mut certificates = BTreeMap::new();
            for (key, value) in rows_for_route_bounded(
                &self.database,
                QC_TABLE,
                self.route,
                MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES,
            )? {
                let certificate = ReplicaQuorumCertificate::decode(&value)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                let index = certificate.claim().raft_index();
                let Some(anchor) = anchors.get(&index) else {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                };
                if key != entry_storage_key(self.route, index)
                    || certificate.claim() != &anchor.claim
                    || certificates.insert(index, certificate.clone()).is_some()
                {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
                certificate.verify(&self.committee, &anchor.claim)?;
            }
            match certificates.last_key_value() {
                Some((&index, certificate))
                    if meta.compact_safe_index == index
                        && meta.compact_safe_term == certificate.claim().raft_term()
                        && meta.compact_safe_qc == Some(certificate.commitment()) => {}
                None if meta.compact_safe_index == 0
                    && meta.compact_safe_term == 0
                    && meta.compact_safe_qc.is_none() => {}
                _ => return Err(AgentRaftLedgerError::CorruptLedger),
            }

            if let Some(bytes) = read_exact(&self.database, FAIL_STOP_TABLE, route_key.as_slice())?
            {
                let record = FailStopRecord::decode(&bytes)
                    .map_err(|_| AgentRaftLedgerError::CorruptLedger)?;
                if record.route != self.route {
                    return Err(AgentRaftLedgerError::CorruptLedger);
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ConfigRecord {
        version: u32,
        route: AgentRouteKey,
        committee: AgentReplicaCommittee,
        local_node: NodeId,
        journal_store: JournalStoreInstanceId,
    }

    impl ConfigRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            if self.version != LEDGER_SCHEMA_VERSION {
                return Err(AgentRaftLedgerError::ConfigurationMismatch);
            }
            validate_configuration(self.route, &self.committee, self.local_node)?;
            if JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_CONFIG_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            Ok(())
        }
    }

    impl ServiceWire for ConfigRecord {
        const MAGIC: [u8; 4] = *b"AGCF";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encode_route(&mut encoder, self.route);
            encoder.bytes(&self.committee.encode());
            encoder.fixed(&self.local_node.0);
            encoder.fixed(self.journal_store.as_bytes());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_CONFIG_RECORD_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                route: decode_route(decoder)?,
                committee: decode_nested::<AgentReplicaCommittee>(
                    decoder,
                    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
                )?,
                local_node: NodeId(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReservationRecord {
        route: AgentRouteKey,
        index: u64,
        term: u64,
        payload: Hash,
        journal_store: JournalStoreInstanceId,
    }

    impl ReservationRecord {
        fn from_committed(
            committed: &CommittedAgentRaftEntry,
            journal_store: JournalStoreInstanceId,
        ) -> Result<Self, AgentRaftLedgerError> {
            match committed.command() {
                AgentRaftCommand::Ordered {
                    artifact_batch: None,
                    ..
                } => {}
                AgentRaftCommand::Ordered {
                    artifact_batch: Some(_),
                    ..
                } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
                _ => return Err(AgentRaftLedgerError::OrderedClaimRequired),
            }
            let record = Self {
                route: committed.route(),
                index: committed.index(),
                term: committed.term(),
                payload: committed.payload_commitment(),
                journal_store,
            };
            record.validate()?;
            Ok(record)
        }

        fn commitment(&self) -> Hash {
            Hash::digest(AGENT_RAFT_APPLY_RESERVATION_DOMAIN, &[&self.encode()])
        }

        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.route.validate()?;
            if self.index == 0
                || self.term == 0
                || self.payload == Hash::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.encode().len() > MAX_RESERVATION_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for ReservationRecord {
        const MAGIC: [u8; 4] = *b"AGRV";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.u64(self.term);
            encoder.fixed(&self.payload.0);
            encoder.fixed(self.journal_store.as_bytes());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_RESERVATION_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                term: decoder.u64()?,
                payload: Hash(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AnchorRecord {
        route: AgentRouteKey,
        index: u64,
        term: u64,
        payload: Hash,
        journal_store: JournalStoreInstanceId,
        successor: JournalHeadsId,
        claim: OrderedCommitClaim,
    }

    impl AnchorRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.claim.validate()?;
            if self.index == 0
                || self.term == 0
                || self.payload == Hash::ZERO
                || JournalStoreInstanceId::from_bytes(*self.journal_store.as_bytes()).is_none()
                || self.successor == JournalHeadsId::ZERO
                || self.index != self.claim.raft_index()
                || self.term != self.claim.raft_term()
                || AgentRouteKey::from_claim(&self.claim)? != self.route
                || self.encode().len() > MAX_ANCHOR_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for AnchorRecord {
        const MAGIC: [u8; 4] = *b"AGCA";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.u64(self.term);
            encoder.fixed(&self.payload.0);
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(self.successor.as_bytes());
            encoder.bytes(&self.claim.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_ANCHOR_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                term: decoder.u64()?,
                payload: Hash(decoder.fixed()?),
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                successor: JournalHeadsId(decoder.fixed()?),
                claim: decode_nested::<OrderedCommitClaim>(
                    decoder,
                    MAX_ORDERED_COMMIT_CLAIM_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PledgeRecord {
        route: AgentRouteKey,
        index: u64,
        claim: OrderedCommitClaim,
    }

    impl PledgeRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.claim.validate()?;
            if self.index == 0
                || self.index != self.claim.raft_index()
                || AgentRouteKey::from_claim(&self.claim)? != self.route
                || self.encode().len() > MAX_PLEDGE_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for PledgeRecord {
        const MAGIC: [u8; 4] = *b"AGPL";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.bytes(&self.claim.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_PLEDGE_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                claim: decode_nested::<OrderedCommitClaim>(
                    decoder,
                    MAX_ORDERED_COMMIT_CLAIM_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ShareRecord {
        route: AgentRouteKey,
        index: u64,
        claim: Hash,
        share: ReplicaCommitSignature,
    }

    impl ShareRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            if self.index == 0
                || self.claim == Hash::ZERO
                || self.share.signer() == NodeId::ZERO
                || self.encode().len() > MAX_SHARE_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            self.route.validate()?;
            Ok(())
        }
    }

    impl ServiceWire for ShareRecord {
        const MAGIC: [u8; 4] = *b"AGSH";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.fixed(&self.claim.0);
            encoder.bytes(&self.share.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_SHARE_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                claim: Hash(decoder.fixed()?),
                share: decode_nested::<ReplicaCommitSignature>(
                    decoder,
                    MAX_REPLICA_COMMIT_SIGNATURE_BYTES,
                )?,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FailStopRecord {
        route: AgentRouteKey,
        index: u64,
        expected: Hash,
        observed: Hash,
    }

    impl FailStopRecord {
        fn validate(&self) -> Result<(), AgentRaftLedgerError> {
            self.route.validate()?;
            if self.index == 0
                || self.expected == Hash::ZERO
                || self.observed == Hash::ZERO
                || self.expected == self.observed
                || self.encode().len() > MAX_FAIL_STOP_RECORD_BYTES
            {
                return Err(AgentRaftLedgerError::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for FailStopRecord {
        const MAGIC: [u8; 4] = *b"AGFS";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_route(&mut encoder, self.route);
            encoder.u64(self.index);
            encoder.fixed(&self.expected.0);
            encoder.fixed(&self.observed.0);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, MAX_FAIL_STOP_RECORD_BYTES)?;
            let record = Self {
                route: decode_route(decoder)?,
                index: decoder.u64()?,
                expected: Hash(decoder.fixed()?),
                observed: Hash(decoder.fixed()?),
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    fn validate_configuration(
        route: AgentRouteKey,
        committee: &AgentReplicaCommittee,
        local_node: NodeId,
    ) -> Result<(), AgentRaftLedgerError> {
        route.validate()?;
        committee
            .validate()
            .map_err(|_| AgentRaftLedgerError::InvalidCommittee)?;
        if committee.profile() != AgentProfile::Shared
            || committee.space() != route.space
            || committee.agent() != route.agent
            || committee.id() != route.committee
        {
            return Err(AgentRaftLedgerError::InvalidCommittee);
        }
        committee
            .member_by_node(local_node)
            .ok_or(AgentRaftLedgerError::LocalReplicaNotVoter)?;
        Ok(())
    }

    pub(super) fn validate_claim_link(
        route: AgentRouteKey,
        committed: &CommittedAgentRaftEntry,
        claim: &OrderedCommitClaim,
    ) -> Result<(), AgentRaftLedgerError> {
        validate_claim_link_inner(route, committed, claim, false)
    }

    pub(super) fn validate_claim_link_with_artifact_batch(
        route: AgentRouteKey,
        committed: &CommittedAgentRaftEntry,
        claim: &OrderedCommitClaim,
    ) -> Result<(), AgentRaftLedgerError> {
        validate_claim_link_inner(route, committed, claim, true)
    }

    fn validate_claim_link_inner(
        route: AgentRouteKey,
        committed: &CommittedAgentRaftEntry,
        claim: &OrderedCommitClaim,
        artifact_batch_receipted: bool,
    ) -> Result<(), AgentRaftLedgerError> {
        claim.validate()?;
        if AgentRouteKey::from_claim(claim)? != route
            || committed.route() != route
            || committed.index != claim.raft_index()
            || committed.term != claim.raft_term()
        {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        let entry = match committed.command() {
            AgentRaftCommand::Ordered {
                artifact_batch: None,
                entry,
                ..
            } => entry,
            AgentRaftCommand::Ordered {
                artifact_batch: Some(_),
                entry,
                ..
            } if artifact_batch_receipted => entry,
            AgentRaftCommand::Ordered {
                artifact_batch: Some(_),
                ..
            } => return Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired),
            _ => return Err(AgentRaftLedgerError::InvalidClaim),
        };
        let expected = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        if claim.ordered() != expected || claim.merge_frontier() != entry.merge_frontier {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        // The entry's seal describes this transition, while a claim retains
        // the most recent sealed projection across later ordinary Ordered
        // entries. Comparing `claim.merge_seal()` directly with the entry
        // therefore rejects every ordinary successor after a fence.
        let fence_linked = match entry.merge_seal {
            Some(seal) => {
                claim.merge_fence() == expected
                    && claim
                        .sealed_merge()
                        .is_some_and(|projection| projection.seal() == seal)
            }
            None => claim.merge_fence() != expected,
        };
        if !fence_linked {
            return Err(AgentRaftLedgerError::InvalidClaim);
        }
        Ok(())
    }

    fn validate_share(
        committee: &AgentReplicaCommittee,
        claim: &OrderedCommitClaim,
        share: &ReplicaCommitSignature,
    ) -> Result<(), AgentRaftLedgerError> {
        claim.validate()?;
        if claim.committee() != committee.id() {
            return Err(AgentRaftLedgerError::InvalidCommittee);
        }
        let member = committee
            .member_by_node(share.signer())
            .ok_or(AgentRaftLedgerError::UnknownSigner)?;
        if member.replica().role != ReplicaRole::Voter {
            return Err(AgentRaftLedgerError::ObserverSigner);
        }
        let key = VerifyingKey::from_bytes(member.ed25519_public_key())
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_slice(share.signature())
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)?;
        let message =
            ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
        key.verify_strict(&message.0, &signature)
            .map_err(|_| AgentRaftLedgerError::InvalidSignature)
    }

    fn route_storage_key(route: AgentRouteKey) -> [u8; ROUTE_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; ROUTE_STORAGE_KEY_BYTES];
        key[0..32].copy_from_slice(&route.space.0);
        key[32..64].copy_from_slice(&route.agent.0);
        key[64..96].copy_from_slice(route.genesis.as_bytes());
        key[96..128].copy_from_slice(route.admission.as_bytes());
        key[128..160].copy_from_slice(route.committee.as_bytes());
        key
    }

    fn entry_storage_key(route: AgentRouteKey, index: u64) -> [u8; ENTRY_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; ENTRY_STORAGE_KEY_BYTES];
        key[..ROUTE_STORAGE_KEY_BYTES].copy_from_slice(&route_storage_key(route));
        key[ROUTE_STORAGE_KEY_BYTES..].copy_from_slice(&index.to_be_bytes());
        key
    }

    fn share_storage_key(
        route: AgentRouteKey,
        index: u64,
        signer: NodeId,
    ) -> [u8; SHARE_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; SHARE_STORAGE_KEY_BYTES];
        key[..ENTRY_STORAGE_KEY_BYTES].copy_from_slice(&entry_storage_key(route, index));
        key[ENTRY_STORAGE_KEY_BYTES..].copy_from_slice(&signer.0);
        key
    }

    fn read_exact(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentRaftLedgerError> {
        let transaction = database.begin_read()?;
        let table = transaction.open_table(definition)?;
        Ok(table.get(key)?.map(|value| value.value().to_vec()))
    }

    fn rows_for_route_bounded(
        database: &Database,
        definition: TableDefinition<&[u8], &[u8]>,
        route: AgentRouteKey,
        maximum: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, AgentRaftLedgerError> {
        let prefix = route_storage_key(route);
        let transaction = database.begin_read()?;
        let table = transaction.open_table(definition)?;
        let mut rows = Vec::new();
        for row in table.range(prefix.as_slice()..)? {
            let (key, value) = row?;
            if !key.value().starts_with(prefix.as_slice()) {
                break;
            }
            if rows.len() == maximum {
                return Err(AgentRaftLedgerError::BacklogLimit);
            }
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    macro_rules! backend_from {
        ($error:ty) => {
            impl From<$error> for AgentRaftLedgerError {
                fn from(error: $error) -> Self {
                    Self::Backend(alloc::boxed::Box::new(error))
                }
            }
        };
    }

    backend_from!(redb::DatabaseError);
    backend_from!(redb::TableError);
    backend_from!(redb::StorageError);
    backend_from!(redb::TransactionError);
    backend_from!(redb::CommitError);
}

#[cfg(all(feature = "std", feature = "storage"))]
#[allow(unused_imports)]
pub(crate) use evidence_ledger::{
    AgentRaftEvidenceLedger, AgentRaftShareOutcome, AgentRaftSignError, ReplicaCommitSigner,
};

#[cfg(all(feature = "std", feature = "storage"))]
mod application_ledger_v2 {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

    use super::*;

    const APPLICATION_SCHEMA_VERSION: u32 = 2;
    const CONFIG_RECORD_MAX_BYTES: usize =
        MAX_AGENT_REPLICA_COMMITTEE_BYTES + MAX_COMMITTEE_AUTHORITY_BINDING_BYTES + 1024;
    const COMMAND_RESERVATION_RECORD_MAX_BYTES: usize = 1024;
    const MAX_SNAPSHOT_COMMITTEE_EVIDENCE: usize = 96;
    const SNAPSHOT_RECORD_MAX_BYTES: usize = MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES
        + MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES
        + MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES
        + MAX_SNAPSHOT_COMMITTEE_EVIDENCE
            * (MAX_AGENT_RAFT_APPLY_META_BYTES + MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES + 16)
        + 4096;
    // Adding a narrow authority must not silently enlarge legacy ASR4 bounds.
    const _: () = assert!(
        SNAPSHOT_RECORD_MAX_BYTES
            >= MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES
                + MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES
                + MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES
                + MAX_SHARED_RECOVERY_MANIFEST_BYTES
                + 4096
    );
    const RETIRED_AUDIT_ROOT_DOMAIN: &[u8] = b"vos/agent/shared/retired-audit-root/v1";
    const COMMITTEE_EVIDENCE_ROOT_DOMAIN: &[u8] =
        b"vos/agent/shared/snapshot-committee-evidence/v1";
    const PORTABLE_FOUNDATION_DOMAIN: &[u8] = b"vos/agent/shared/portable-recovery-foundation/v1";
    const PORTABLE_RETIRED_ROOT_DOMAIN: &[u8] =
        b"vos/agent/shared/portable-recovery-retired-root/v1";
    const GENERATION_STORAGE_KEY_BYTES: usize = 32 * 4;
    const AUDIT_STORAGE_KEY_BYTES: usize = GENERATION_STORAGE_KEY_BYTES + 8;

    #[cfg(test)]
    struct RecoveryPhaseTiming {
        started: std::time::Instant,
        previous: std::time::Instant,
        operation: &'static str,
        index: u64,
        node: NodeId,
    }

    #[cfg(test)]
    impl RecoveryPhaseTiming {
        fn start(enabled: bool, operation: &'static str, index: u64, node: NodeId) -> Option<Self> {
            if !enabled || std::env::var_os("VOS_SHARED_RECOVERY_TIMING").is_none() {
                return None;
            }
            let started = std::time::Instant::now();
            Some(Self {
                started,
                previous: started,
                operation,
                index,
                node,
            })
        }

        fn mark(timing: &mut Option<Self>, phase: &'static str) {
            if let Some(timing) = timing {
                let now = std::time::Instant::now();
                std::eprintln!(
                    "recovery_phase operation={} index={} node={:?} phase={} phase_us={} total_us={}",
                    timing.operation,
                    timing.index,
                    timing.node,
                    phase,
                    now.duration_since(timing.previous).as_micros(),
                    now.duration_since(timing.started).as_micros(),
                );
                timing.previous = now;
            }
        }
    }

    fn canonical_leader_noop_commitment() -> Result<Hash, AgentRaftApplicationErrorV2> {
        let raw = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data {
            payload: Vec::new(),
        })
        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        Ok(Hash::digest(
            AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN,
            &[&raw],
        ))
    }

    const CONFIG_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_application_config_v2");
    const APPLY_META_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_meta_v2");
    const APPLY_AUDIT_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_apply_audit_v2");
    const COMMITTEE_STATE_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_committee_state_v2");
    const COMMAND_RESERVATION_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_command_reservation_v2");
    const SNAPSHOT_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_snapshot_v2");
    const RECOVERY_MANIFEST_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_recovery_manifest_v2");
    const RECOVERY_OBSERVATION_TABLE_V2: TableDefinition<&[u8], &[u8]> =
        TableDefinition::new("agent_shared_raft_recovery_observation_v2");

    const V2_TABLE_NAMES: &[&str] = &[
        "raft_log",
        "raft_meta",
        "agent_shared_raft_application_config_v2",
        "agent_shared_raft_apply_meta_v2",
        "agent_shared_raft_apply_audit_v2",
        "agent_shared_raft_committee_state_v2",
        "agent_shared_raft_command_reservation_v2",
        "agent_shared_raft_snapshot_v2",
        "agent_shared_raft_recovery_manifest_v2",
        "agent_shared_raft_recovery_observation_v2",
    ];

    // Any table from the previous committee-keyed evidence generation makes
    // this database ineligible for V2 initialization. There is deliberately
    // no mixed-mode normalization or migration path.
    const LEGACY_V1_TABLE_NAMES: &[&str] = &[
        "agent_shared_raft_config",
        "agent_shared_raft_apply_meta",
        "agent_shared_raft_apply_reservation",
        "agent_shared_raft_claim_anchors",
        "agent_shared_raft_sign_pledges",
        "agent_shared_raft_commit_shares",
        "agent_shared_raft_quorum_certificates",
        "agent_shared_raft_fail_stop",
    ];

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ApplicationConfigV2 {
        version: u32,
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        initial_committee: AgentReplicaCommittee,
        authority: CommitteeChangeAuthorityBinding,
    }

    impl ApplicationConfigV2 {
        fn validate(&self) -> Result<(), AgentRaftWireError> {
            self.generation.validate()?;
            self.initial_committee
                .validate()
                .map_err(|_| AgentRaftWireError::InvalidCommitteeTransition)?;
            self.authority.validate()?;
            if self.version != APPLICATION_SCHEMA_VERSION
                || self.journal_store.as_bytes() == &[0; 32]
                || self.local_node == NodeId::ZERO
                || self.initial_committee.profile() != AgentProfile::Shared
                || self.initial_committee.space() != self.generation.space
                || self.initial_committee.agent() != self.generation.agent
            {
                // A joiner's local node is outside the initial committee.
                // Membership is enforced where a configuration row is first
                // written: only an initial member or an explicit joiner open.
                return Err(AgentRaftWireError::InvalidApplyMeta);
            }
            enforce_wire_bound(self, CONFIG_RECORD_MAX_BYTES)
        }
    }

    impl ServiceWire for ApplicationConfigV2 {
        const MAGIC: [u8; 4] = *b"AGC2";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.u32(self.version);
            encode_generation_route(&mut encoder, self.generation);
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
            encoder.bytes(&self.initial_committee.encode());
            encoder.bytes(&self.authority.encode());
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, CONFIG_RECORD_MAX_BYTES)?;
            let record = Self {
                version: decoder.u32()?,
                generation: decode_generation_route(decoder)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                local_node: NodeId(decoder.fixed()?),
                initial_committee: decode_nested::<AgentReplicaCommittee>(
                    decoder,
                    MAX_AGENT_REPLICA_COMMITTEE_BYTES,
                )?,
                authority: decode_nested::<CommitteeChangeAuthorityBinding>(
                    decoder,
                    MAX_COMMITTEE_AUTHORITY_BINDING_BYTES,
                )?,
            };
            record.validate().map_err(map_wire_decode_error)?;
            Ok(record)
        }
    }

    /// One exact ordinary command which may have crossed its external
    /// journal/artifact publication boundary but has not yet advanced the
    /// atomic Raft/application cursor. There is at most one such row for the
    /// generation because physical slots are applied strictly in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CommandReservationRecordV2 {
        generation: AgentGenerationRouteKey,
        route: AgentRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        index: u64,
        term: u64,
        raw_payload_commitment: Hash,
        command_commitment: Hash,
        artifact_batch: Option<ArtifactBatchId>,
    }

    impl CommandReservationRecordV2 {
        fn from_slot(
            generation: AgentGenerationRouteKey,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            slot: &CommittedSharedRaftCommand,
        ) -> Result<Self, AgentRaftApplicationErrorV2> {
            let artifact_batch = match slot.entry().command() {
                AgentRaftCommand::Ordered { artifact_batch, .. } => *artifact_batch,
                _ => None,
            };
            let record = Self {
                generation,
                route: slot.entry().route(),
                journal_store,
                local_node,
                index: slot.entry().index(),
                term: slot.entry().term(),
                raw_payload_commitment: slot.raw_payload_commitment(),
                command_commitment: slot.entry().payload_commitment(),
                artifact_batch,
            };
            record
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            Ok(record)
        }

        fn validate(&self) -> Result<(), AgentRaftWireError> {
            self.generation.validate()?;
            self.route.validate()?;
            if self.route.generation() != self.generation
                || self.journal_store.as_bytes() == &[0; 32]
                || self.local_node == NodeId::ZERO
                || self.index == 0
                || self.term == 0
                || self.raw_payload_commitment == Hash::ZERO
                || self.command_commitment == Hash::ZERO
                || self.artifact_batch == Some(ArtifactBatchId::ZERO)
            {
                return Err(AgentRaftWireError::InvalidApplyMeta);
            }
            enforce_wire_bound(self, COMMAND_RESERVATION_RECORD_MAX_BYTES)
        }

        fn matches_reserved(&self, reserved: &ReservedAgentRaftApplication) -> bool {
            self.route == reserved.route()
                && self.journal_store == reserved.journal_store()
                && self.local_node == reserved.local_node()
                && self.index == reserved.index()
                && self.term == reserved.term()
                && self.command_commitment == reserved.payload_commitment()
                && self.artifact_batch == reserved.artifact_batch()
        }
    }

    impl ServiceWire for CommandReservationRecordV2 {
        const MAGIC: [u8; 4] = *b"AGR2";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_generation_route(&mut encoder, self.generation);
            encode_route(&mut encoder, self.route);
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
            encoder.u64(self.index);
            encoder.u64(self.term);
            encoder.fixed(&self.raw_payload_commitment.0);
            encoder.fixed(&self.command_commitment.0);
            encoder.option(&self.artifact_batch, |encoder, batch| {
                encoder.fixed(batch.as_bytes())
            });
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, COMMAND_RESERVATION_RECORD_MAX_BYTES)?;
            let record = Self {
                generation: decode_generation_route(decoder)?,
                route: decode_route(decoder)?,
                journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                    .ok_or(DecodeError::NonCanonical)?,
                local_node: NodeId(decoder.fixed()?),
                index: decoder.u64()?,
                term: decoder.u64()?,
                raw_payload_commitment: Hash(decoder.fixed()?),
                command_commitment: Hash(decoder.fixed()?),
                artifact_batch: decoder
                    .option(|decoder| Ok(ArtifactBatchId::from_bytes(decoder.fixed()?)))?,
            };
            record.validate().map_err(map_wire_decode_error)?;
            Ok(record)
        }
    }

    /// Exact physical committee-transition evidence retained across audit-log
    /// retirement. Ordinary slots are represented by the cumulative retired
    /// audit root; committee changes retain their canonical bytes so restart
    /// can still derive the active committee from immutable genesis authority.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SnapshotCommitteeEvidenceV2 {
        record: AgentRaftApplyAuditRecordV2,
        physical: Vec<u8>,
    }

    impl SnapshotCommitteeEvidenceV2 {
        fn validate(&self) -> Result<(), AgentRaftApplicationErrorV2> {
            if !matches!(
                self.record.disposition,
                AgentRaftApplyDispositionV2::CommitteeChangePrepared { .. }
                    | AgentRaftApplyDispositionV2::CommitteeJointConfiguration { .. }
                    | AgentRaftApplyDispositionV2::CommitteeStableConfiguration { .. }
            ) || self.physical.is_empty()
                || self.physical.len() > MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES
                || Hash::digest(
                    AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN,
                    &[self.physical.as_slice()],
                ) != self.record.raw_payload_commitment
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let kind = decode_agent_raft_entry_kind(&self.physical)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if encode_agent_raft_entry_kind(&kind)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
                != self.physical
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(())
        }
    }

    impl ServiceWire for SnapshotCommitteeEvidenceV2 {
        const MAGIC: [u8; 4] = *b"ASE3";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encoder.bytes(&self.record.encode());
            encoder.bytes(&self.physical);
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(
                decoder,
                MAX_AGENT_RAFT_APPLY_META_BYTES + MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES + 128,
            )?;
            let evidence = Self {
                record: decode_nested::<AgentRaftApplyAuditRecordV2>(
                    decoder,
                    MAX_AGENT_RAFT_APPLY_META_BYTES,
                )?,
                physical: decoder.bytes_ref()?.to_vec(),
            };
            evidence.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(evidence)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum SnapshotAuthorityV2 {
        Physical(SharedAgentSnapshotCertificate),
        Portable(SharedAgentPortableSnapshotCertificate),
        Common {
            certificate: SharedAgentCommonSnapshotCertificate,
            binding: SharedAgentLocalSnapshotBinding,
            recovery: Option<(SharedRecoveryManifest, AgentRaftApplyDispositionV2)>,
        },
    }

    /// One durable, quorum-authenticated snapshot anchor. There is exactly
    /// one row per generation and replacements must advance its Raft index.
    /// A portable authority signs only logical state; `claim` is the exact
    /// destination-physical rebind retained for journal/Raft reconciliation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AgentRaftSnapshotRecordV2 {
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        claim: SharedAgentSnapshotClaim,
        authority: SnapshotAuthorityV2,
        committee_evidence: Vec<SnapshotCommitteeEvidenceV2>,
    }

    impl AgentRaftSnapshotRecordV2 {
        fn boundary_disposition(
            &self,
        ) -> Result<AgentRaftApplyDispositionV2, AgentRaftApplicationErrorV2> {
            if let SnapshotAuthorityV2::Common {
                recovery: Some((_, disposition)),
                ..
            } = &self.authority
            {
                return Ok(*disposition);
            }
            legacy_snapshot_boundary(&self.claim)
        }

        fn recovery_manifest(&self) -> Option<&SharedRecoveryManifest> {
            match &self.authority {
                SnapshotAuthorityV2::Common {
                    recovery: Some((manifest, _)),
                    ..
                } => Some(manifest),
                _ => None,
            }
        }

        fn authority_commitment(&self) -> Hash {
            match &self.authority {
                SnapshotAuthorityV2::Physical(certificate) => certificate.commitment(),
                SnapshotAuthorityV2::Portable(certificate) => certificate.commitment(),
                SnapshotAuthorityV2::Common { binding, .. } => binding.commitment(),
            }
        }

        fn verify_authority(&self) -> Result<(), AgentRaftApplicationErrorV2> {
            match &self.authority {
                SnapshotAuthorityV2::Common {
                    certificate,
                    binding,
                    recovery,
                } => {
                    binding
                        .verify(certificate, &self.claim)
                        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                    validate_common_recovery_manifest(
                        certificate,
                        recovery.as_ref().map(|(manifest, _)| manifest),
                    )?;
                    if let Some((manifest, disposition)) = recovery {
                        validate_snapshot_recovery_boundary(self, manifest, *disposition)?;
                    }
                    let foundation = common_restore_foundation(
                        self.generation,
                        self.journal_store,
                        self.local_node,
                        certificate.commitment(),
                    );
                    // Import mode is bound by the signed physical foundation,
                    // not an independently mutable flag in the ledger row.
                    if self.claim.boundary_payload_commitment()
                        == foundation.boundary_payload_commitment
                    {
                        if self.claim.retired_audit_root() != foundation.retired_audit_root
                            || self.claim.committee_evidence_root()
                                != foundation.committee_evidence_root
                            || self.claim.previous_snapshot().is_some()
                            || !self.committee_evidence.is_empty()
                        {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                    }
                    Ok(())
                }
                SnapshotAuthorityV2::Physical(certificate) => {
                    if certificate.claim() != &self.claim {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    certificate
                        .verify(self.claim.active_committee(), &self.claim)
                        .map(|_| ())
                        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)
                }
                SnapshotAuthorityV2::Portable(certificate) => {
                    let portable = certificate.claim();
                    if portable.ordered() != self.claim.ordered()
                        || portable.active_committee() != self.claim.active_committee()
                        || portable.authority_epoch() != self.claim.authority_epoch()
                        || portable.ordered_successor() != self.claim.ordered_successor()
                        || portable.checkpoint_predecessor() != self.claim.checkpoint_predecessor()
                        || portable.journal_heads() != self.claim.journal_heads()
                        || portable.checkpoint() != self.claim.checkpoint()
                        || portable.local_node() != self.claim.local_node()
                        || portable.control() != self.claim.control()
                        || portable.linear() != self.claim.linear()
                        || portable.merge() != self.claim.merge()
                        || portable.local() != self.claim.local()
                        || portable.ordered_invocations() != self.claim.ordered_invocations()
                        || portable.merge_invocations() != self.claim.merge_invocations()
                        || portable.local_invocations() != self.claim.local_invocations()
                        || portable.artifacts() != self.claim.artifacts()
                        || self.claim.boundary_payload_commitment()
                            != portable_foundation_commitment(
                                self.generation,
                                self.journal_store,
                                self.local_node,
                                certificate.commitment(),
                            )
                        || self.claim.retired_audit_root()
                            != portable_retired_audit_root(
                                self.generation,
                                self.journal_store,
                                self.local_node,
                                certificate.commitment(),
                            )
                        || self.claim.previous_snapshot().is_some()
                        || !self.committee_evidence.is_empty()
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    certificate
                        .verify(portable.active_committee(), portable)
                        .map(|_| ())
                        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)
                }
            }
        }

        fn validate(&self) -> Result<(), AgentRaftApplicationErrorV2> {
            let claim = &self.claim;
            if self.generation.validate().is_err()
                || self.journal_store.as_bytes() == &[0; 32]
                || self.local_node == NodeId::ZERO
                || claim.ordered().space() != self.generation.space
                || claim.ordered().agent() != self.generation.agent
                || claim.ordered().genesis() != self.generation.genesis
                || claim.ordered().admission() != self.generation.admission
                || claim.journal_store().0 != *self.journal_store.as_bytes()
                || claim.local_node() != self.local_node
                || self.committee_evidence.len() > MAX_SNAPSHOT_COMMITTEE_EVIDENCE
                || self
                    .committee_evidence
                    .windows(2)
                    .any(|pair| pair[0].record.index >= pair[1].record.index)
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            self.verify_authority()?;
            for evidence in &self.committee_evidence {
                evidence.validate()?;
                if evidence.record.generation != self.generation
                    || evidence.record.index > claim.raft_index()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
            }
            if snapshot_committee_evidence_root(self.generation, &self.committee_evidence)
                != claim.committee_evidence_root()
                || self.encode().len() > SNAPSHOT_RECORD_MAX_BYTES
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(())
        }
    }

    fn legacy_snapshot_boundary(
        claim: &SharedAgentSnapshotClaim,
    ) -> Result<AgentRaftApplyDispositionV2, AgentRaftApplicationErrorV2> {
        if claim.boundary_payload_commitment() == canonical_leader_noop_commitment()? {
            Ok(AgentRaftApplyDispositionV2::LeaderNoop)
        } else {
            Ok(AgentRaftApplyDispositionV2::Command(
                AgentRaftAuditDisposition::OrderedApplied {
                    entry: claim
                        .ordered()
                        .ordered()
                        .head
                        .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?,
                    claim: claim.ordered().commitment(),
                    successor: claim.ordered_successor(),
                },
            ))
        }
    }

    fn validate_common_recovery_manifest(
        certificate: &SharedAgentCommonSnapshotCertificate,
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        if let Some(manifest) = manifest {
            manifest
                .validate_at(certificate.claim().ordered().raft_index())
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            let ordered = certificate.claim().ordered();
            if manifest.generation()
                != AgentGenerationRouteKey::new(
                    ordered.space(),
                    ordered.agent(),
                    ordered.genesis(),
                    ordered.admission(),
                )
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?
                || manifest.committee() != certificate.claim().active_committee()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotCertificateInvalid);
            }
        }
        match (certificate.claim().recovery_manifest(), manifest) {
            (Some(expected), Some(manifest)) if manifest.commitment() == expected => Ok(()),
            (None, None) => Ok(()),
            (None, Some(manifest)) if manifest.is_empty() => Ok(()),
            _ => Err(AgentRaftApplicationErrorV2::SnapshotCertificateInvalid),
        }
    }

    fn validate_snapshot_recovery_boundary(
        record: &AgentRaftSnapshotRecordV2,
        manifest: &SharedRecoveryManifest,
        disposition: AgentRaftApplyDispositionV2,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        if let AgentRaftApplyDispositionV2::RecoveryRegistered {
            registration,
            manifest: root,
        } = disposition
        {
            if root != manifest.commitment() {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let registered = manifest
                .slots()
                .iter()
                .find(|slot| slot.registration().commitment() == registration)
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let route = AgentRouteKey::new(
                record.generation.space,
                record.generation.agent,
                record.generation.genesis,
                record.generation.admission,
                manifest.committee().id(),
            )
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let physical = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data {
                payload: AgentRaftCommand::RegisterRecovery {
                    route,
                    registration: registered.registration().clone(),
                }
                .encode(),
            })
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[&physical])
                != record.claim.boundary_payload_commitment()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
        } else if let AgentRaftApplyDispositionV2::RecoveryExpired {
            certificate,
            manifest: root,
        } = disposition
        {
            let terminal = manifest
                .slots()
                .iter()
                .filter_map(SharedRecoverySlot::expiry)
                .find(|terminal| terminal.certificate().commitment() == certificate)
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            if root != manifest.commitment()
                || terminal.raft_index() != record.claim.raft_index()
                || terminal.raft_term() != record.claim.raft_term()
                || terminal.certificate().claim().ordered() != record.claim.ordered().ordered()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let route = AgentRouteKey::new(
                record.generation.space,
                record.generation.agent,
                record.generation.genesis,
                record.generation.admission,
                manifest.committee().id(),
            )
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let physical = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data {
                payload: AgentRaftCommand::ExpireRecovery {
                    route,
                    certificate: terminal.certificate().clone(),
                }
                .encode(),
            })
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[&physical])
                != record.claim.boundary_payload_commitment()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
        } else if disposition != legacy_snapshot_boundary(&record.claim)? {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(())
    }

    impl ServiceWire for AgentRaftSnapshotRecordV2 {
        const MAGIC: [u8; 4] = *b"ASR4";

        fn encode_body(&self, output: &mut Vec<u8>) {
            let mut encoder = Encoder(output);
            encode_generation_route(&mut encoder, self.generation);
            encoder.fixed(self.journal_store.as_bytes());
            encoder.fixed(&self.local_node.0);
            encoder.bytes(&self.claim.encode());
            match &self.authority {
                SnapshotAuthorityV2::Physical(certificate) => {
                    encoder.u8(0);
                    encoder.bytes(&certificate.encode());
                }
                SnapshotAuthorityV2::Portable(certificate) => {
                    encoder.u8(1);
                    encoder.bytes(&certificate.encode());
                }
                SnapshotAuthorityV2::Common {
                    certificate,
                    binding,
                    recovery,
                } => {
                    encoder.u8(if recovery.is_some() { 3 } else { 2 });
                    encoder.bytes(&certificate.encode());
                    encoder.bytes(&binding.encode());
                    if let Some((manifest, disposition)) = recovery {
                        encoder.bytes(&manifest.encode());
                        encode_disposition_v2(&mut encoder, *disposition);
                    }
                }
            }
            encoder.u32(self.committee_evidence.len() as u32);
            for evidence in &self.committee_evidence {
                encoder.bytes(&evidence.encode());
            }
        }

        fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
            enforce_complete_bound(decoder, SNAPSHOT_RECORD_MAX_BYTES)?;
            let generation = decode_generation_route(decoder)?;
            let journal_store = JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                .ok_or(DecodeError::NonCanonical)?;
            let local_node = NodeId(decoder.fixed()?);
            let claim = decode_nested::<SharedAgentSnapshotClaim>(
                decoder,
                MAX_SHARED_AGENT_SNAPSHOT_CLAIM_BYTES,
            )?;
            let authority = match decoder.u8()? {
                0 => {
                    SnapshotAuthorityV2::Physical(decode_nested::<SharedAgentSnapshotCertificate>(
                        decoder,
                        MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES,
                    )?)
                }
                1 => SnapshotAuthorityV2::Portable(decode_nested::<
                    SharedAgentPortableSnapshotCertificate,
                >(
                    decoder,
                    MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES,
                )?),
                2 => SnapshotAuthorityV2::Common {
                    certificate: decode_nested::<SharedAgentCommonSnapshotCertificate>(
                        decoder,
                        MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
                    )?,
                    binding: decode_nested::<SharedAgentLocalSnapshotBinding>(
                        decoder,
                        MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
                    )?,
                    recovery: None,
                },
                3 => SnapshotAuthorityV2::Common {
                    certificate: decode_nested::<SharedAgentCommonSnapshotCertificate>(
                        decoder,
                        MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
                    )?,
                    binding: decode_nested::<SharedAgentLocalSnapshotBinding>(
                        decoder,
                        MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
                    )?,
                    recovery: Some((
                        decode_nested::<SharedRecoveryManifest>(
                            decoder,
                            MAX_SHARED_RECOVERY_MANIFEST_BYTES,
                        )?,
                        decode_disposition_v2(decoder)?,
                    )),
                },
                _ => return Err(DecodeError::InvalidTag),
            };
            let count = decoder.u32()? as usize;
            if count > MAX_SNAPSHOT_COMMITTEE_EVIDENCE {
                return Err(DecodeError::LimitExceeded);
            }
            let mut committee_evidence = Vec::new();
            committee_evidence
                .try_reserve_exact(count)
                .map_err(|_| DecodeError::LimitExceeded)?;
            for _ in 0..count {
                committee_evidence.push(decode_nested::<SnapshotCommitteeEvidenceV2>(
                    decoder,
                    MAX_AGENT_RAFT_APPLY_META_BYTES + MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES + 128,
                )?);
            }
            let record = Self {
                generation,
                journal_store,
                local_node,
                claim,
                authority,
                committee_evidence,
            };
            record.validate().map_err(|_| DecodeError::NonCanonical)?;
            Ok(record)
        }
    }

    /// Read-only ledger contribution to an exact journal checkpoint claim.
    pub(crate) type RecoveryReplayEvidence = Vec<(
        OrderedEntryId,
        crate::agent::journal::ReplayInputId,
        Option<crate::agent_sdk::RuntimeOutcome>,
    )>;

    #[derive(Clone, Debug)]
    pub(crate) struct AgentRaftSnapshotContextV2 {
        pub(crate) recovery_manifest: Option<SharedRecoveryManifest>,
        pub(crate) recovery_replay_evidence: RecoveryReplayEvidence,
        boundary_disposition: AgentRaftApplyDispositionV2,
        /// Exact logical Ordered projection rebound only for this snapshot to
        /// the latest authenticated physical foundation.
        pub(crate) ordered: OrderedCommitClaim,
        pub(crate) active_committee: AgentReplicaCommittee,
        pub(crate) authority_epoch: u64,
        pub(crate) boundary_payload_commitment: Hash,
        pub(crate) ordered_successor: JournalHeadsId,
        pub(crate) retired_audit_root: Hash,
        pub(crate) committee_evidence_root: Hash,
        pub(crate) previous_snapshot: Option<Hash>,
        committee_evidence: Vec<SnapshotCommitteeEvidenceV2>,
    }

    /// Call-local products of one complete audit in one database snapshot.
    /// Never retained across application calls or peer I/O.
    struct AuditedRecoveryView {
        meta: AgentRaftApplyMetaV2,
        committee: CommitteeApplicationStateV2,
        raft: crate::raft::RaftMeta,
        snapshot: Option<AgentRaftSnapshotRecordV2>,
        recovery: Option<SharedRecoveryManifest>,
        ordered: OrderedBase,
        reservation_pending: bool,
        // Collected only for reopen/snapshot proof, never retained across calls.
        recovery_replay_evidence: RecoveryReplayEvidence,
    }

    impl AuditedRecoveryView {
        fn capacity(&self) -> (u64, u64, bool) {
            (
                self.meta.applied_index,
                (MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64).saturating_sub(
                    self.meta
                        .applied_index
                        .saturating_sub(self.raft.snap_last_index),
                ),
                self.reservation_pending,
            )
        }
    }

    /// One call's exact predecessor, never retained across application calls.
    struct RecoveryUpdatePredecessor {
        manifest: Option<Vec<u8>>,
        meta: AgentRaftApplyMetaV2,
        snapshot: (u64, u64),
    }

    struct StagedRecoveryUpdate {
        predecessor: RecoveryUpdatePredecessor,
        manifest: Option<Vec<u8>>,
        observation: Option<Vec<u8>>,
    }

    impl StagedRecoveryUpdate {
        fn require_current(
            &self,
            transaction: &redb::WriteTransaction,
            key: &[u8],
            meta: &AgentRaftApplyMetaV2,
            raft: &crate::raft::RaftMeta,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
            let current = table.get(key)?;
            if current.as_ref().map(|value| value.value()) != self.predecessor.manifest.as_deref()
                || meta != &self.predecessor.meta
                || (raft.snap_last_index, raft.snap_last_term) != self.predecessor.snapshot
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    impl AgentRaftSnapshotContextV2 {
        pub(crate) fn committee_evidence_len(&self) -> usize {
            self.committee_evidence.len()
        }
    }

    /// Durable snapshot projection used by restart reconciliation and bounded
    /// cleanup. Construction remains inside the verified ledger path.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct InstalledAgentRaftSnapshotV2 {
        pub(crate) claim: SharedAgentSnapshotClaim,
        pub(crate) certificate_commitment: Hash,
    }

    /// Deterministic destination-only metadata for a typed common-state import.
    /// The complete resulting physical claim still requires its owner's binding
    /// signature and replay's authenticated source/destination closure checks.
    pub(crate) struct CommonSnapshotRestoreFoundation {
        pub(crate) journal_store: Hash,
        pub(crate) local_node: NodeId,
        pub(crate) boundary_payload_commitment: Hash,
        pub(crate) retired_audit_root: Hash,
        pub(crate) committee_evidence_root: Hash,
    }

    fn common_restore_foundation(
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        node: NodeId,
        certificate: Hash,
    ) -> CommonSnapshotRestoreFoundation {
        let encoded = generation_storage_key(generation);
        let parts: &[&[u8]] = &[&encoded, journal_store.as_bytes(), &node.0, &certificate.0];
        CommonSnapshotRestoreFoundation {
            journal_store: Hash(*journal_store.as_bytes()),
            local_node: node,
            boundary_payload_commitment: Hash::digest(
                b"vos/agent/shared/common-recovery-foundation/v1",
                parts,
            ),
            retired_audit_root: Hash::digest(b"vos/agent/shared/common-recovery-retired/v1", parts),
            committee_evidence_root: snapshot_committee_evidence_root(generation, &[]),
        }
    }

    /// Result of an atomic V2 foundation application.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum AgentRaftFoundationApplyOutcomeV2 {
        Applied(AgentRaftApplyMetaV2),
        Duplicate(AgentRaftApplyMetaV2),
    }

    /// Result of completing a replay/artifact operation under the exact
    /// durable command reservation.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum AgentRaftCommandApplyOutcomeV2 {
        Applied(AgentRaftApplyMetaV2),
        Duplicate(AgentRaftApplyMetaV2),
    }

    /// One Ordered audit row projected with the exact physical command.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct AgentRaftOrderedJournalAnchorV2 {
        pub(crate) route: AgentRouteKey,
        pub(crate) index: u64,
        pub(crate) term: u64,
        pub(crate) command_commitment: Hash,
        pub(crate) entry: OrderedEntryId,
        pub(crate) claim: Hash,
        pub(crate) successor: JournalHeadsId,
    }

    /// The sole reserved Ordered command which may be on either side of its
    /// journal CAS when a process restarts.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct AgentRaftPendingOrderedV2 {
        pub(crate) route: AgentRouteKey,
        pub(crate) index: u64,
        pub(crate) term: u64,
        pub(crate) command_commitment: Hash,
        pub(crate) entry: OrderedEntryId,
        // Taken from the authenticated physical command, not staged journal files.
        pub(crate) ordered_index: u64,
        pub(crate) ordered_parent: Option<OrderedEntryId>,
    }

    /// Cross-store restart projection and explicit bounded capacity.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct AgentRaftJournalAuditV2 {
        pub(crate) applied_slots: u64,
        pub(crate) remaining_slots: u64,
        pub(crate) reservation_pending: bool,
        pub(crate) snapshot: Option<InstalledAgentRaftSnapshotV2>,
        pub(crate) ordered: Vec<AgentRaftOrderedJournalAnchorV2>,
        pub(crate) pending_ordered: Option<AgentRaftPendingOrderedV2>,
    }

    /// Fail-closed V2 application error.
    #[derive(Debug)]
    pub(crate) enum AgentRaftApplicationErrorV2 {
        LegacyGeneration,
        ConfigurationMismatch,
        CorruptLedger,
        MissingCommittedSlot,
        ApplyGap { expected: u64, actual: u64 },
        TermRegression { previous: u64, actual: u64 },
        MissingAuditRecord(u64),
        ConflictingDuplicate(u64),
        SlotDatabaseMismatch(u64),
        RaftCursorMismatch { raft: u64, application: u64 },
        SnapshotBoundaryRequired,
        SnapshotCertificateInvalid,
        SnapshotStale,
        SnapshotReplay,
        SnapshotEvidenceLimit,
        CommandExecutionRequired,
        CommandReservationRequired,
        DivergentCommandReservation,
        WrongLocalReplica,
        WrongJournalStore,
        InvalidCommandDisposition,
        UnsolicitedConfiguration,
        WrongGeneration,
        StaleCommittee,
        OverlappingCommitteeChange,
        ReorderedConfiguration,
        WrongConfigurationNodes,
        TransitionBarrier,
        WrongAuthority,
        StaleAuthority,
        AuthorityEpochExhausted,
        BacklogLimit,
        Backend(alloc::boxed::Box<dyn std::error::Error + Send + Sync>),
    }

    impl fmt::Display for AgentRaftApplicationErrorV2 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Backend(error) => write!(formatter, "Shared Agent V2 apply backend: {error}"),
                _ => write!(formatter, "Shared Agent V2 apply failure: {self:?}"),
            }
        }
    }

    impl core::error::Error for AgentRaftApplicationErrorV2 {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Backend(error) => Some(&**error),
                _ => None,
            }
        }
    }

    /// Durable clean-generation application ledger for one Shared-Agent Raft
    /// database.
    ///
    /// Leader no-ops, ordinary-command reservations/completions, the exact
    /// authorized committee barrier, and authenticated snapshots share one
    /// contiguous physical cursor. Live-worker attachment remains an explicit
    /// refusal at this Agent-specific boundary.
    pub(crate) struct AgentRaftApplicationLedgerV2 {
        database: Arc<Database>,
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        initial_committee: AgentReplicaCommittee,
        authority: CommitteeChangeAuthorityBinding,
        writes: std::sync::Mutex<()>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct AgentNetworkCommitteeState {
        pub(crate) active: AgentReplicaCommittee,
        pub(crate) next: Option<AgentReplicaCommittee>,
        pub(crate) joint: bool,
    }

    impl AgentRaftApplicationLedgerV2 {
        pub(crate) fn database(&self) -> Arc<Database> {
            Arc::clone(&self.database)
        }

        pub(crate) fn open(
            database: Arc<Database>,
            generation: AgentGenerationRouteKey,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            initial_committee: AgentReplicaCommittee,
            authority: CommitteeChangeAuthorityBinding,
        ) -> Result<Self, AgentRaftApplicationErrorV2> {
            Self::open_with_role(
                database,
                generation,
                journal_store,
                local_node,
                initial_committee,
                authority,
                false,
            )
        }

        /// Explicitly create the ledger of a replica outside the initial
        /// committee. It applies the authenticated log as a passive replica
        /// until an authority-signed committee change admits it. Reopening an
        /// existing joiner ledger uses ordinary `open`: its exact durable
        /// configuration row is the only evidence a fresh open accepts.
        pub(crate) fn open_joiner(
            database: Arc<Database>,
            generation: AgentGenerationRouteKey,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            initial_committee: AgentReplicaCommittee,
            authority: CommitteeChangeAuthorityBinding,
        ) -> Result<Self, AgentRaftApplicationErrorV2> {
            Self::open_with_role(
                database,
                generation,
                journal_store,
                local_node,
                initial_committee,
                authority,
                true,
            )
        }

        fn open_with_role(
            database: Arc<Database>,
            generation: AgentGenerationRouteKey,
            journal_store: JournalStoreInstanceId,
            local_node: NodeId,
            initial_committee: AgentReplicaCommittee,
            authority: CommitteeChangeAuthorityBinding,
            joiner: bool,
        ) -> Result<Self, AgentRaftApplicationErrorV2> {
            generation
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)?;
            if journal_store.as_bytes() == &[0; 32] || local_node == NodeId::ZERO {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
            initial_committee
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)?;
            authority
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)?;
            if initial_committee.profile() != AgentProfile::Shared
                || initial_committee.space() != generation.space
                || initial_committee.agent() != generation.agent
                || (joiner && initial_committee.member_by_node(local_node).is_some())
            {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
            let initial_member = initial_committee.member_by_node(local_node).is_some();
            let expected = ApplicationConfigV2 {
                version: APPLICATION_SCHEMA_VERSION,
                generation,
                journal_store,
                local_node,
                initial_committee: initial_committee.clone(),
                authority,
            };
            let key = generation_storage_key(generation);
            let transaction = database.begin_write()?;

            validate_v2_table_namespace_write(&transaction, false)?;

            // Pin the complete V2 schema before inspecting any rows.
            {
                drop(transaction.open_table(crate::raft::RAFT_LOG)?);
                drop(transaction.open_table(crate::raft::RAFT_META)?);
                drop(transaction.open_table(CONFIG_TABLE_V2)?);
                drop(transaction.open_table(APPLY_META_TABLE_V2)?);
                drop(transaction.open_table(APPLY_AUDIT_TABLE_V2)?);
                drop(transaction.open_table(COMMITTEE_STATE_TABLE_V2)?);
                drop(transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?);
                drop(transaction.open_table(SNAPSHOT_TABLE_V2)?);
                drop(transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?);
                drop(transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?);
            }
            validate_v2_table_namespace_write(&transaction, true)?;
            ensure_single_generation_in_write(&transaction, &key, true)?;

            let existing_config = {
                let table = transaction.open_table(CONFIG_TABLE_V2)?;
                table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
            };
            match existing_config {
                Some(bytes) => {
                    let stored = ApplicationConfigV2::decode(&bytes)
                        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                    if stored != expected || stored.encode() != bytes {
                        return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
                    }
                    let meta = read_meta_in_write(&transaction, key.as_slice())?
                        .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                    validate_bound_meta(&meta, generation, journal_store)?;
                    let state = read_committee_state_in_write(&transaction, key.as_slice())?
                        .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                    validate_bound_committee_state(&state, generation, authority)?;
                }
                None => {
                    // Only an initial member, or an explicit joiner, may bind
                    // a fresh generation to this local node.
                    if !initial_member && !joiner {
                        return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
                    }
                    if read_meta_in_write(&transaction, key.as_slice())?.is_some()
                        || read_committee_state_in_write(&transaction, key.as_slice())?.is_some()
                        || read_command_reservation_in_write(&transaction, key.as_slice())?
                            .is_some()
                        || read_snapshot_in_write(&transaction, key.as_slice())?.is_some()
                        || audit_prefix_has_row_in_write(&transaction, &key)?
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    let raft_log_empty =
                        transaction.open_table(crate::raft::RAFT_LOG)?.is_empty()?;
                    let raft_meta_empty =
                        transaction.open_table(crate::raft::RAFT_META)?.is_empty()?;
                    let raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
                    if !raft_log_empty
                        || !raft_meta_empty
                        || raft != crate::raft::RaftMeta::default()
                    {
                        return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
                    }
                    // Materialize the zero host cursor in the same
                    // transaction as the generation binding; absence is not
                    // left as an ambient/default representation.
                    raft.write_host_fields_in_txn(&transaction)?;
                    {
                        let mut table = transaction.open_table(CONFIG_TABLE_V2)?;
                        table.insert(key.as_slice(), expected.encode().as_slice())?;
                    }
                    {
                        let meta = AgentRaftApplyMetaV2::post_genesis(generation, journal_store);
                        let mut table = transaction.open_table(APPLY_META_TABLE_V2)?;
                        table.insert(key.as_slice(), meta.encode().as_slice())?;
                    }
                    {
                        let state = CommitteeApplicationStateV2::initial(
                            generation,
                            initial_committee.clone(),
                            authority.initial_epoch,
                        );
                        let mut table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
                        table.insert(key.as_slice(), state.encode().as_slice())?;
                    }
                }
            }
            transaction.commit()?;

            let ledger = Self {
                database,
                generation,
                journal_store,
                local_node,
                initial_committee,
                authority,
                writes: std::sync::Mutex::new(()),
            };
            ledger.audit_recovery()?;
            Ok(ledger)
        }

        pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
            self.generation
        }

        /// An active member applies ordinary commands. So does a joiner (a
        /// node outside the initial committee) while it replays the
        /// authenticated log before the change that admits it; an initial
        /// member that was removed does not.
        fn applies_as_local_replica(&self, active: &AgentReplicaCommittee, local: NodeId) -> bool {
            active.member_by_node(local).is_some()
                || self.initial_committee.member_by_node(local).is_none()
        }

        /// Whether this local replica is outside the initial committee.
        pub(crate) fn is_joiner(&self) -> bool {
            self.initial_committee
                .member_by_node(self.local_node)
                .is_none()
        }

        pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
            self.journal_store
        }

        pub(crate) const fn local_node(&self) -> NodeId {
            self.local_node
        }

        pub(crate) fn recovery_manifest(
            &self,
        ) -> Result<SharedRecoveryManifest, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
            let key = generation_storage_key(self.generation);
            read_recovery_manifest(&table, &key, self.generation, &self.initial_committee)?
                .map(Ok)
                .unwrap_or_else(|| {
                    SharedRecoveryManifest::new(self.generation, self.initial_committee.clone())
                        .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)
                })
        }

        pub(crate) fn recovery_manifest_if_present(
            &self,
        ) -> Result<Option<SharedRecoveryManifest>, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            read_recovery_manifest(
                &transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?,
                &generation_storage_key(self.generation),
                self.generation,
                &self.initial_committee,
            )
        }

        pub(crate) fn recovery_input_registered(
            &self,
            input: &ReplayInput,
        ) -> Result<bool, AgentRaftApplicationErrorV2> {
            Ok(self
                .recovery_manifest_if_present()?
                .as_ref()
                .is_some_and(|manifest| recovery_input_matches(manifest, input)))
        }

        /// One fresh audited, quiescent physical prefix for an expiry vote.
        /// The driver additionally checks its exact materialized Ordered head,
        /// replay provenance, and current trusted time before allowing a signer.
        pub(crate) fn recovery_expiry_context(
            &self,
        ) -> Result<(u64, u64, OrderedBase, SharedRecoveryManifest), AgentRaftApplicationErrorV2>
        {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let transaction = self.database.begin_read()?;
            let audited = self.audit_recovery_in_read(&transaction)?;
            let last = transaction
                .open_table(crate::raft::RAFT_LOG)?
                .last()?
                .map(|(index, _)| index.value())
                .unwrap_or(audited.raft.snap_last_index);
            if audited.reservation_pending
                || audited.committee.pending.is_some()
                || audited.committee.active != self.initial_committee
                || audited.meta.applied_index != audited.raft.commit_index
                || last != audited.meta.applied_index
            {
                return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
            }
            Ok((
                audited.meta.applied_index,
                audited.meta.applied_term,
                audited.ordered,
                audited
                    .recovery
                    .ok_or(AgentRaftApplicationErrorV2::InvalidCommandDisposition)?,
            ))
        }

        /// Construction/recovery-only floor authentication. Live owners retain
        /// this audited scalar and advance it only through accepted expiry
        /// application/certified snapshot restoration, not mutable hot reads.
        pub(crate) fn authenticated_recovery_expiry_floor(
            &self,
        ) -> Result<u64, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let audited = self.audit_recovery_in_read(&transaction)?;
            Ok(audited
                .recovery
                .as_ref()
                .map_or(0, SharedRecoveryManifest::expiry_floor))
        }

        /// Exact physical proof for an unpruned terminal. Pruned callers must
        /// instead require full equality in their installed certified baseline.
        pub(crate) fn validate_recovery_expiry(
            &self,
            terminal: &SharedRecoveryExpiryTerminal,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let key = generation_storage_key(self.generation);
            let table = transaction.open_table(APPLY_META_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let meta = AgentRaftApplyMetaV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            if meta.encode() != bytes.value()
                || raft.last_applied != meta.applied_index
                || terminal.raft_index() > meta.applied_index
                || terminal.raft_index() <= raft.snap_last_index
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let key = audit_storage_key(self.generation, terminal.raft_index());
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let audit = AgentRaftApplyAuditRecordV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if audit.encode() != bytes.value()
                || audit.generation != self.generation
                || audit.index != terminal.raft_index()
                || audit.term != terminal.raft_term()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let physical = verify_audited_physical_row_in_read(&transaction, &raft, &audit)?;
            let (
                AgentRaftApplyDispositionV2::RecoveryExpired {
                    certificate: expected,
                    ..
                },
                Some(AgentRaftCommand::ExpireRecovery { route, certificate }),
            ) = (audit.disposition, physical.command)
            else {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            };
            if route.generation() != self.generation
                || route.committee() != self.initial_committee.id()
                || certificate != *terminal.certificate()
                || certificate.commitment() != expected
                || certificate.claim().prefix_index().checked_add(1) != Some(terminal.raft_index())
                || terminal.raft_term() < certificate.claim().prefix_term()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            certificate
                .verify(
                    self.generation,
                    &self.initial_committee,
                    certificate.claim(),
                )
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)
        }

        pub(crate) fn recovery_observations(
            &self,
        ) -> Result<Vec<SharedRecoveryObservation>, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let key = generation_storage_key(self.generation);
            let table = transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?;
            exact_audit_row_count(&table, &key)?;
            table
                .iter()?
                .map(|row| {
                    let (key, _) = row?;
                    read_recovery_observation(&table, key.value())?
                        .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)
                })
                .collect()
        }

        pub(crate) fn recovery_replay_evidence(
            &self,
        ) -> Result<RecoveryReplayEvidence, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            Ok(self
                .audit_recovery_in_read_with_evidence(&transaction, true)?
                .recovery_replay_evidence)
        }

        /// Exact bounded hot-read proof. This does not authenticate outcome
        /// bytes by itself: the driver also compares its fresh replay cache.
        pub(crate) fn validate_recovery_observation(
            &self,
            observation: &SharedRecoveryObservation,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let key = audit_storage_key(self.generation, observation.raft_index());
            let audit_table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let bytes = audit_table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let audit = AgentRaftApplyAuditRecordV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if audit.encode() != bytes.value()
                || audit.generation != self.generation
                || audit.index != observation.raft_index()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let physical = verify_audited_physical_row_in_read(&transaction, &raft, &audit)?;
            let (
                AgentRaftApplyDispositionV2::Command(AgentRaftAuditDisposition::OrderedApplied {
                    claim,
                    ..
                }),
                Some(AgentRaftCommand::Ordered { entry, .. }),
            ) = (audit.disposition, physical.command)
            else {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            };
            observation
                .validate_binding(audit.index, audit.term, claim, &entry.input)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if read_recovery_observation(
                &transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?,
                &key,
            )?
            .as_ref()
                != Some(observation)
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(())
        }

        pub(crate) fn validate_recovery_registration(
            &self,
            registration: &SharedRecoveryRegistration,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let state = self.network_committee_state()?;
            if state.next.is_some() || state.active != self.initial_committee {
                return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
            }
            let mut manifest = self.recovery_manifest()?;
            let cursor = self.cursor()?;
            manifest
                .apply_registration(
                    registration,
                    cursor.applied_index.saturating_add(1),
                    cursor.applied_term.max(1),
                )
                .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
            Ok(())
        }

        /// A custody signature is not proof of application. Check the exact
        /// registration metadata against its durable applied physical slot.
        pub(crate) fn validate_recovery_slot_registration(
            &self,
            slot: &SharedRecoverySlot,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let generation_key = generation_storage_key(self.generation);
            let meta_table = transaction.open_table(APPLY_META_TABLE_V2)?;
            let meta_bytes = meta_table
                .get(generation_key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let meta = AgentRaftApplyMetaV2::decode(meta_bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            if meta.encode() != meta_bytes.value()
                || raft.last_applied != meta.applied_index
                || slot.raft_index() > meta.applied_index
                || slot.raft_index() <= raft.snap_last_index
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let key = audit_storage_key(self.generation, slot.raft_index());
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let audit = AgentRaftApplyAuditRecordV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if audit.encode() != bytes.value()
                || audit.generation != self.generation
                || audit.index != slot.raft_index()
                || audit.term != slot.raft_term()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let physical = verify_audited_physical_row_in_read(&transaction, &raft, &audit)?;
            let (
                AgentRaftApplyDispositionV2::RecoveryRegistered {
                    registration: commitment,
                    ..
                },
                Some(AgentRaftCommand::RegisterRecovery {
                    route,
                    registration,
                }),
            ) = (audit.disposition, physical.command)
            else {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            };
            if route.generation() != self.generation
                || route.committee() != self.initial_committee.id()
                || commitment != slot.registration().commitment()
                || registration != *slot.registration()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(())
        }

        /// Test-only physical consensus harness. Production callers cannot
        /// manufacture commitment: they can only drain slots written by the
        /// Agent-specific transport into the ordinary Raft tables.
        #[cfg(test)]
        pub(crate) fn append_committed_for_test(
            &self,
            term: u64,
            kind: &vos_raft::EntryKind<AgentNodeId>,
        ) -> Result<u64, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let mut log = crate::raft::RaftLog::open(Arc::clone(&self.database))?;
            let transaction = self.database.begin_write()?;
            ensure_v2_config_in_write(
                &transaction,
                generation_storage_key(self.generation).as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let index = log.append_in_txn(
                &transaction,
                term,
                &encode_agent_raft_entry_kind(kind)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
            )?;
            let mut meta = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            meta.current_term = meta.current_term.max(term);
            meta.commit_index = index;
            meta.write_worker_fields_in_txn(&transaction)?;
            transaction.commit()?;
            Ok(index)
        }

        pub(crate) fn cursor(&self) -> Result<AgentRaftApplyMetaV2, AgentRaftApplicationErrorV2> {
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_read()?;
            let table = transaction.open_table(APPLY_META_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                .value()
                .to_vec();
            let meta = AgentRaftApplyMetaV2::decode(&bytes)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if meta.encode() != bytes {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            Ok(meta)
        }

        pub(crate) fn active_committee(
            &self,
        ) -> Result<AgentReplicaCommittee, AgentRaftApplicationErrorV2> {
            Ok(self.committee_state()?.active)
        }

        /// Exact committee view needed by the live transport. During a
        /// prepared or joint transition the next committee is already an
        /// authenticated route participant even though `active` remains the
        /// authority for journal application until the stable leg commits.
        pub(crate) fn network_committee_state(
            &self,
        ) -> Result<AgentNetworkCommitteeState, AgentRaftApplicationErrorV2> {
            let state = self.committee_state()?;
            let (next, joint) = state.pending.map_or((None, false), |pending| {
                (
                    Some(pending.change.next().clone()),
                    matches!(pending.phase, PendingCommitteePhaseV2::Joint { .. }),
                )
            });
            Ok(AgentNetworkCommitteeState {
                active: state.active,
                next,
                joint,
            })
        }

        pub(crate) fn pending_transition(
            &self,
        ) -> Result<Option<(CommitteeTransitionId, bool)>, AgentRaftApplicationErrorV2> {
            Ok(self.committee_state()?.pending.map(|pending| {
                (
                    pending.change.transition(),
                    matches!(pending.phase, PendingCommitteePhaseV2::Joint { .. }),
                )
            }))
        }

        pub(crate) fn authority_epoch(&self) -> Result<u64, AgentRaftApplicationErrorV2> {
            Ok(self.committee_state()?.authority_epoch)
        }

        /// Whether a fixed-roster recovery command can apply now: the initial
        /// committee is active and no transition is in flight.
        pub(crate) fn fixed_roster_recovery_admissible(
            &self,
        ) -> Result<bool, AgentRaftApplicationErrorV2> {
            let state = self.committee_state()?;
            Ok(state.pending.is_none() && state.active == self.initial_committee)
        }

        /// Non-mutating admission of a committee preparation against the
        /// current applied state. It repeats every check the committed
        /// `PrepareCommitteeChange` apply performs, so a leader never commits
        /// a preparation that every replica would then refuse to apply.
        pub(crate) fn preflight_committee_change(
            &self,
            change: &PrepareCommitteeChange,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let state = self.committee_state()?;
            if change.generation() != self.generation {
                return Err(AgentRaftApplicationErrorV2::WrongGeneration);
            }
            if state.pending.is_some() {
                return Err(AgentRaftApplicationErrorV2::OverlappingCommitteeChange);
            }
            if change.previous() != &state.active {
                return Err(AgentRaftApplicationErrorV2::StaleCommittee);
            }
            if state.authority_epoch == u64::MAX {
                return Err(AgentRaftApplicationErrorV2::AuthorityEpochExhausted);
            }
            if self.recovery_manifest_if_present()?.is_some() {
                return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
            }
            self.authority
                .verify(self.generation, state.authority_epoch, change)
        }

        /// Derive the exact ledger half of a snapshot claim without mutating
        /// either durable store. The logical boundary is the latest exact
        /// Ordered projection. A contiguous applied suffix after it may
        /// contain only leader no-ops; that suffix is authenticated as the
        /// snapshot's physical foundation without changing journal state.
        pub(crate) fn snapshot_context(
            &self,
            ordered: &OrderedCommitClaim,
        ) -> Result<AgentRaftSnapshotContextV2, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let transaction = self.database.begin_read()?;
            let audited = self.audit_recovery_in_read_with_evidence(&transaction, true)?;
            self.snapshot_context_from_audit(&transaction, ordered, audited)
        }

        /// Select the exact installed or journal-bound logical projection and
        /// derive its physical context from the same fresh audited read view.
        pub(crate) fn snapshot_candidate_context(
            &self,
            heads: &super::super::journal::JournalHeads,
            journal_ordered: Option<&OrderedCommitClaim>,
        ) -> Result<AgentRaftSnapshotContextV2, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let transaction = self.database.begin_read()?;
            let audited = self.audit_recovery_in_read_with_evidence(&transaction, true)?;
            let entry = heads
                .ordered_head
                .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
            let matches_heads = |claim: &&OrderedCommitClaim| {
                claim.ordered().head == Some(entry)
                    && claim.ordered().index == heads.ordered_index
                    && claim.genesis() == heads.genesis
                    && claim.admission() == heads.admission
                    && claim.runtime() == &heads.runtime
            };
            // Prefer the installed foundation after no-op-only progress; an
            // older retained journal binding must not skip that certified base.
            let ordered = audited
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.claim.ordered())
                .filter(matches_heads)
                .or_else(|| journal_ordered.filter(matches_heads))
                .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?
                .clone();
            self.snapshot_context_from_audit(&transaction, &ordered, audited)
        }

        fn snapshot_context_from_audit(
            &self,
            transaction: &redb::ReadTransaction,
            ordered: &OrderedCommitClaim,
            audited: AuditedRecoveryView,
        ) -> Result<AgentRaftSnapshotContextV2, AgentRaftApplicationErrorV2> {
            ordered
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
            let key = generation_storage_key(self.generation);
            let AuditedRecoveryView {
                meta,
                committee: state,
                raft,
                snapshot: previous,
                recovery,
                ordered: _,
                reservation_pending,
                recovery_replay_evidence,
            } = audited;
            if state.pending.is_some()
                || reservation_pending
                || meta.applied_index < ordered.raft_index()
                || ordered.space() != self.generation.space
                || ordered.agent() != self.generation.agent
                || ordered.genesis() != self.generation.genesis
                || ordered.admission() != self.generation.admission
                || ordered.committee() != state.active.id()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
            }

            if meta.applied_index <= raft.snap_last_index {
                return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
            }
            let boundary_from_previous = previous.as_ref().is_some_and(|previous| {
                ordered == previous.claim.ordered()
                    && ordered.raft_index() == raft.snap_last_index
                    && ordered.raft_term() == raft.snap_last_term
            });
            let (mut retired_audit_root, mut committee_evidence, previous_snapshot) =
                match previous.as_ref() {
                    Some(previous) => {
                        if raft.snap_last_index != previous.claim.raft_index()
                            || raft.snap_last_term != previous.claim.raft_term()
                        {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        (
                            previous.claim.retired_audit_root(),
                            previous.committee_evidence.clone(),
                            Some(previous.authority_commitment()),
                        )
                    }
                    None => {
                        if raft.snap_last_index != 0 || raft.snap_last_term != 0 {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        (
                            initial_retired_audit_root(
                                self.generation,
                                self.journal_store,
                                self.local_node,
                            ),
                            Vec::new(),
                            None,
                        )
                    }
                };
            let audit = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let physical = transaction.open_table(crate::raft::RAFT_LOG)?;
            let mut observed = raft.snap_last_index;
            let mut logical_boundary_seen = boundary_from_previous;
            let mut ordered_successor = previous
                .as_ref()
                .filter(|_| boundary_from_previous)
                .map(|previous| previous.claim.ordered_successor());
            for row in audit.range(key.as_slice()..)? {
                let (stored_key, value) = row?;
                if !stored_key.value().starts_with(key.as_slice()) {
                    break;
                }
                let record = AgentRaftApplyAuditRecordV2::decode(value.value())
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if record.index != observed.saturating_add(1)
                    || record.generation != self.generation
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let bytes = physical_bytes_for_record(&physical, &record)?;
                if record.index == ordered.raft_index() && !boundary_from_previous {
                    let AgentRaftApplyDispositionV2::Command(
                        AgentRaftAuditDisposition::OrderedApplied {
                            entry,
                            claim,
                            successor,
                        },
                    ) = record.disposition
                    else {
                        return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
                    };
                    if ordered.ordered().head != Some(entry) || ordered.commitment() != claim {
                        return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
                    }
                    logical_boundary_seen = true;
                    ordered_successor = Some(successor);
                } else if record.index > ordered.raft_index()
                    && !matches!(
                        record.disposition,
                        AgentRaftApplyDispositionV2::LeaderNoop
                            | AgentRaftApplyDispositionV2::RecoveryRegistered { .. }
                            | AgentRaftApplyDispositionV2::RecoveryExpired { .. }
                    )
                {
                    return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
                }
                retired_audit_root = fold_retired_audit_root(retired_audit_root, &record, &bytes);
                if matches!(
                    record.disposition,
                    AgentRaftApplyDispositionV2::CommitteeChangePrepared { .. }
                        | AgentRaftApplyDispositionV2::CommitteeJointConfiguration { .. }
                        | AgentRaftApplyDispositionV2::CommitteeStableConfiguration { .. }
                ) {
                    if committee_evidence.len() == MAX_SNAPSHOT_COMMITTEE_EVIDENCE {
                        return Err(AgentRaftApplicationErrorV2::SnapshotEvidenceLimit);
                    }
                    committee_evidence.push(SnapshotCommitteeEvidenceV2 {
                        record: record.clone(),
                        physical: bytes,
                    });
                }
                observed = record.index;
            }
            if observed != meta.applied_index {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            if !logical_boundary_seen {
                return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
            }
            let ordered = ordered
                .with_raft_foundation(meta.applied_index, meta.applied_term)
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
            Ok(AgentRaftSnapshotContextV2 {
                boundary_disposition: meta
                    .disposition
                    .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?,
                recovery_manifest: recovery,
                recovery_replay_evidence,
                ordered,
                active_committee: state.active,
                authority_epoch: state.authority_epoch,
                boundary_payload_commitment: meta.raw_payload_commitment,
                ordered_successor: ordered_successor
                    .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?,
                retired_audit_root,
                committee_evidence_root: snapshot_committee_evidence_root(
                    self.generation,
                    &committee_evidence,
                ),
                previous_snapshot,
                committee_evidence,
            })
        }

        /// Install one exact voter-majority certificate and retire its Raft
        /// log/audit prefix in the same redb transaction. Journal checkpoint
        /// publication is performed first by `SharedJournalAgentDriver`; a
        /// crash between the two boundaries leaves the full audit prefix and
        /// is therefore safely retryable.
        pub(crate) fn install_snapshot(
            &self,
            certificate: &SharedAgentSnapshotCertificate,
            logical_ordered: Option<&OrderedCommitClaim>,
        ) -> Result<InstalledAgentRaftSnapshotV2, AgentRaftApplicationErrorV2> {
            self.install_snapshot_authority(
                certificate.claim(),
                SnapshotAuthorityV2::Physical(certificate.clone()),
                logical_ordered,
            )
        }

        pub(crate) fn install_common_snapshot(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
            binding: &SharedAgentLocalSnapshotBinding,
            logical_ordered: Option<&OrderedCommitClaim>,
        ) -> Result<InstalledAgentRaftSnapshotV2, AgentRaftApplicationErrorV2> {
            self.validate_common_scope(certificate)?;
            binding
                .verify(certificate, binding.claim())
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            {
                let transaction = self.database.begin_read()?;
                if let Some(current) = read_snapshot_in_read(
                    &transaction,
                    generation_storage_key(self.generation).as_slice(),
                )? && let SnapshotAuthorityV2::Common {
                    certificate: installed,
                    binding: local,
                    ..
                } = &current.authority
                    && installed == certificate
                    && local == binding
                {
                    current.verify_authority()?;
                    return Ok(InstalledAgentRaftSnapshotV2 {
                        claim: current.claim.clone(),
                        certificate_commitment: current.authority_commitment(),
                    });
                }
            }
            let manifest = self.recovery_manifest()?;
            validate_common_recovery_manifest(certificate, Some(&manifest))?;
            let recovery = if certificate.claim().recovery_manifest().is_some() {
                Some((
                    manifest,
                    self.cursor()?
                        .disposition
                        .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?,
                ))
            } else {
                None
            };
            self.install_snapshot_authority(
                binding.claim(),
                SnapshotAuthorityV2::Common {
                    certificate: certificate.clone(),
                    binding: binding.clone(),
                    recovery,
                },
                logical_ordered,
            )
        }

        fn install_snapshot_authority(
            &self,
            claim: &SharedAgentSnapshotClaim,
            authority: SnapshotAuthorityV2,
            logical_ordered: Option<&OrderedCommitClaim>,
        ) -> Result<InstalledAgentRaftSnapshotV2, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let key = generation_storage_key(self.generation);
            let context = {
                let transaction = self.database.begin_read()?;
                let audited = self.audit_recovery_in_read(&transaction)?;
                if let Some(current) = &audited.snapshot {
                    let current_index = current.claim.raft_index();
                    if claim.raft_index() <= current_index {
                        if current.authority == authority && &current.claim == claim {
                            return Ok(InstalledAgentRaftSnapshotV2 {
                                claim: current.claim.clone(),
                                certificate_commitment: current.authority_commitment(),
                            });
                        }
                        return Err(AgentRaftApplicationErrorV2::SnapshotStale);
                    }
                }

                // The certificate may bind the same logical Ordered projection
                // to a later metadata foundation. Never feed that synthetic
                // foundation back into an Ordered commit-verification path.
                let logical_ordered =
                    logical_ordered.ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
                self.snapshot_context_from_audit(&transaction, logical_ordered, audited)?
            };
            match &authority {
                SnapshotAuthorityV2::Common {
                    certificate,
                    recovery,
                    ..
                } => {
                    validate_common_recovery_manifest(
                        certificate,
                        context.recovery_manifest.as_ref(),
                    )?;
                    if recovery.as_ref().is_some_and(|(manifest, disposition)| {
                        Some(manifest) != context.recovery_manifest.as_ref()
                            || *disposition != context.boundary_disposition
                    }) {
                        return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
                    }
                }
                _ if context
                    .recovery_manifest
                    .as_ref()
                    .is_some_and(|manifest| !manifest.is_empty()) =>
                {
                    return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
                }
                _ => {}
            }
            if claim.ordered() != &context.ordered
                || claim.active_committee() != &context.active_committee
                || claim.authority_epoch() != context.authority_epoch
                || claim.journal_store().0 != *self.journal_store.as_bytes()
                || claim.local_node() != self.local_node
                || claim.boundary_payload_commitment() != context.boundary_payload_commitment
                || claim.ordered_successor() != context.ordered_successor
                || claim.retired_audit_root() != context.retired_audit_root
                || claim.committee_evidence_root() != context.committee_evidence_root
                || claim.previous_snapshot() != context.previous_snapshot
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            let record = AgentRaftSnapshotRecordV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                local_node: self.local_node,
                claim: claim.clone(),
                authority,
                committee_evidence: context.committee_evidence,
            };
            record
                .verify_authority()
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            record.validate()?;

            let transaction = self.database.begin_write()?;
            ensure_v2_config_in_write(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            if read_command_reservation_in_write(&transaction, key.as_slice())?.is_some() {
                return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
            }
            let persisted_meta = read_meta_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            if persisted_meta.applied_index != claim.raft_index()
                || persisted_meta.applied_term != claim.raft_term()
                || persisted_meta.raw_payload_commitment != claim.boundary_payload_commitment()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            {
                let mut table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
                table.insert(key.as_slice(), record.encode().as_slice())?;
            }
            retire_recovery_observations(&transaction, &key, claim.raft_index())?;
            {
                let mut table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
                let mut retired = Vec::new();
                for row in table.range(key.as_slice()..)? {
                    let (stored_key, _) = row?;
                    if !stored_key.value().starts_with(key.as_slice()) {
                        break;
                    }
                    let bytes = stored_key.value();
                    let index = u64::from_be_bytes(
                        bytes[AUDIT_STORAGE_KEY_BYTES - 8..]
                            .try_into()
                            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
                    );
                    if index > claim.raft_index() {
                        break;
                    }
                    retired.push(bytes.to_vec());
                }
                for retired in retired {
                    table.remove(retired.as_slice())?;
                }
            }
            {
                let mut table = transaction.open_table(crate::raft::RAFT_LOG)?;
                let retired = table
                    .range(..=claim.raft_index())?
                    .map(|row| row.map(|(key, _)| key.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for index in retired {
                    table.remove(index)?;
                }
            }
            let mut raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            if raft.last_applied != claim.raft_index()
                || raft.commit_index < claim.raft_index()
                || raft.snap_last_index >= claim.raft_index()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            raft.snap_last_index = claim.raft_index();
            raft.snap_last_term = claim.raft_term();
            raft.write_worker_fields_in_txn(&transaction)?;
            transaction.commit()?;
            Ok(InstalledAgentRaftSnapshotV2 {
                claim: claim.clone(),
                certificate_commitment: record.authority_commitment(),
            })
        }

        fn validate_common_scope(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let claim = certificate.claim();
            certificate
                .verify(&self.initial_committee, claim)
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            if claim.active_committee() != &self.initial_committee
                || claim.authority_epoch() != self.authority.initial_epoch
                || claim.ordered().space() != self.generation.space
                || claim.ordered().agent() != self.generation.agent
                || claim.ordered().genesis() != self.generation.genesis
                || claim.ordered().admission() != self.generation.admission
                || self
                    .initial_committee
                    .member_by_node(self.local_node)
                    .is_none()
            {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
            Ok(())
        }

        pub(crate) fn common_restore_foundation(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
        ) -> Result<CommonSnapshotRestoreFoundation, AgentRaftApplicationErrorV2> {
            self.validate_common_scope(certificate)?;
            Ok(common_restore_foundation(
                self.generation,
                self.journal_store,
                self.local_node,
                certificate.commitment(),
            ))
        }

        /// Check before staging or publishing a destination journal. The host
        /// must retire its Raft worker throughout preflight/publication/install;
        /// the same checks run again in the final ledger transaction.
        pub(crate) fn validate_common_restore(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            self.validate_common_scope(certificate)?;
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery()?;
            // An aborted transaction makes this a non-mutating preflight while
            // sharing the exact install checks and table snapshot.
            let transaction = self.database.begin_write()?;
            self.common_restore_state(&transaction, certificate, None)
                .map(|_| ())
        }

        /// Recovery preflight for a separately authenticated physical binding.
        /// Unlike first admission, this permits only the exact already-installed
        /// anchor at equality, while retaining every later-suffix/reservation
        /// guard before a journal stage can be promoted.
        pub(crate) fn validate_bound_common_restore(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
            binding: &SharedAgentLocalSnapshotBinding,
        ) -> Result<(), AgentRaftApplicationErrorV2> {
            let foundation = self.common_restore_foundation(certificate)?;
            let claim = binding.claim();
            binding
                .verify(certificate, claim)
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            if claim.journal_store() != foundation.journal_store
                || claim.local_node() != foundation.local_node
                || claim.boundary_payload_commitment() != foundation.boundary_payload_commitment
                || claim.retired_audit_root() != foundation.retired_audit_root
                || claim.committee_evidence_root() != foundation.committee_evidence_root
                || claim.previous_snapshot().is_some()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery()?;
            let transaction = self.database.begin_write()?;
            self.common_restore_state(&transaction, certificate, Some(binding))
                .map(|_| ())
        }

        fn common_restore_state(
            &self,
            transaction: &redb::WriteTransaction,
            certificate: &SharedAgentCommonSnapshotCertificate,
            binding: Option<&SharedAgentLocalSnapshotBinding>,
        ) -> Result<crate::raft::RaftMeta, AgentRaftApplicationErrorV2> {
            let key = generation_storage_key(self.generation);
            ensure_v2_config_in_write(
                transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let meta = read_meta_in_write(transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let state = read_committee_state_in_write(transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let expected_state = CommitteeApplicationStateV2::initial(
                self.generation,
                self.initial_committee.clone(),
                self.authority.initial_epoch,
            );
            let raft = crate::raft::RaftMeta::load_from_write_transaction(transaction)?;
            {
                let table = transaction.open_table(crate::raft::RAFT_META)?;
                if raft.voted_for.is_some() || table.get(META_LEGACY_ACTIVE_CONFIG)?.is_some() {
                    return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
                }
                if let Some(cached) = table.get(META_AGENT_ACTIVE_CONFIG)? {
                    // The worker can persist speculative membership before
                    // application. Never retain an unevidenced configuration
                    // after pruning its log row. Only the canonical initial
                    // stable record is supported by this fixed-roster import.
                    let mut initial = ACTIVE_CONFIG_MAGIC.to_vec();
                    initial.extend_from_slice(&[0, 0]); // no log index, no joint set
                    initial.extend_from_slice(
                        &(self.initial_committee.members().len() as u16).to_le_bytes(),
                    );
                    for member in self.initial_committee.members() {
                        initial.extend_from_slice(&member.replica().node.0);
                    }
                    let mut genesis_indexed = ACTIVE_CONFIG_MAGIC.to_vec();
                    genesis_indexed.push(1);
                    genesis_indexed.extend_from_slice(&0_u64.to_le_bytes());
                    genesis_indexed.extend_from_slice(&initial[ACTIVE_CONFIG_MAGIC.len() + 1..]);
                    if cached.value() != initial.as_slice()
                        && cached.value() != genesis_indexed.as_slice()
                    {
                        return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
                    }
                }
            }
            if let Some(vote) = transaction
                .open_table(crate::raft::RAFT_META)?
                .get(META_AGENT_VOTED_FOR)?
            {
                let bytes: [u8; 32] = vote
                    .value()
                    .try_into()
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if bytes == [0; 32] || raft.current_term == 0 {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
            }
            let target = certificate.claim().ordered().raft_index();
            let exact_anchor = read_snapshot_in_write(transaction, key.as_slice())?
                .is_some_and(|current| matches!(current.authority,
                    SnapshotAuthorityV2::Common { certificate: ref existing, binding: ref existing_binding, .. }
                    if existing == certificate && binding == Some(existing_binding)
                        && &current.claim == existing_binding.claim()));
            if state != expected_state
                || read_command_reservation_in_write(transaction, key.as_slice())?.is_some()
                || meta.applied_index > target
                || raft.commit_index > target
                || raft.snap_last_index > target
                || (!exact_anchor
                    && (meta.applied_index == target
                        || raft.commit_index == target
                        || raft.snap_last_index == target))
                || (exact_anchor && (meta.applied_index != target || raft.last_applied != target))
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            // A locally uncommitted suffix may already be committed elsewhere.
            // This initial catch-up path refuses such destinations instead of
            // truncating entries without the Raft log-matching proof.
            if transaction
                .open_table(crate::raft::RAFT_LOG)?
                .range((
                    core::ops::Bound::Excluded(target),
                    core::ops::Bound::Unbounded,
                ))?
                .next()
                .transpose()?
                .is_some()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired);
            }
            Ok(raft)
        }

        /// Install only a locally signed rebind of a common fixed-committee
        /// checkpoint. Journal closure verification/publication and its crash
        /// marker belong to the driver; this transaction replaces only the
        /// already verified ledger foundation, never an unknown log suffix.
        pub(crate) fn restore_common_snapshot(
            &self,
            certificate: &SharedAgentCommonSnapshotCertificate,
            binding: &SharedAgentLocalSnapshotBinding,
            manifest: &SharedRecoveryManifest,
        ) -> Result<InstalledAgentRaftSnapshotV2, AgentRaftApplicationErrorV2> {
            let foundation = self.common_restore_foundation(certificate)?;
            validate_common_recovery_manifest(certificate, Some(manifest))?;
            let claim = binding.claim();
            binding
                .verify(certificate, claim)
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            if claim.journal_store() != foundation.journal_store
                || claim.local_node() != foundation.local_node
                || claim.boundary_payload_commitment() != foundation.boundary_payload_commitment
                || claim.retired_audit_root() != foundation.retired_audit_root
                || claim.committee_evidence_root() != foundation.committee_evidence_root
                || claim.previous_snapshot().is_some()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            let record = AgentRaftSnapshotRecordV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                local_node: self.local_node,
                claim: claim.clone(),
                authority: SnapshotAuthorityV2::Common {
                    certificate: certificate.clone(),
                    binding: binding.clone(),
                    recovery: if certificate.claim().recovery_manifest().is_some() {
                        Some((manifest.clone(), legacy_snapshot_boundary(claim)?))
                    } else {
                        None
                    },
                },
                committee_evidence: Vec::new(),
            };
            record.validate()?;
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery()?;
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_write()?;
            let mut raft = self.common_restore_state(&transaction, certificate, Some(binding))?;
            if let Some(current) = read_snapshot_in_write(&transaction, key.as_slice())? {
                if current == record {
                    return Ok(InstalledAgentRaftSnapshotV2 {
                        claim: claim.clone(),
                        certificate_commitment: binding.commitment(),
                    });
                }
                if current.claim.raft_index() >= claim.raft_index() {
                    return Err(AgentRaftApplicationErrorV2::SnapshotStale);
                }
            }
            let ordered_head = claim
                .ordered()
                .ordered()
                .head
                .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
            let restored_meta = AgentRaftApplyMetaV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                applied_index: claim.raft_index(),
                applied_term: claim.raft_term(),
                raw_payload_commitment: foundation.boundary_payload_commitment,
                disposition: Some(AgentRaftApplyDispositionV2::Command(
                    AgentRaftAuditDisposition::OrderedApplied {
                        entry: ordered_head,
                        claim: claim.ordered().commitment(),
                        successor: claim.ordered_successor(),
                    },
                )),
            };
            restored_meta
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            {
                let mut table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
                let retired = table
                    .range(key.as_slice()..)?
                    .take_while(|row| {
                        row.as_ref().map_or(true, |(stored, _)| {
                            stored.value().starts_with(key.as_slice())
                        })
                    })
                    .map(|row| row.map(|(stored, _)| stored.value().to_vec()))
                    .collect::<Result<Vec<_>, _>>()?;
                for retired in retired {
                    table.remove(retired.as_slice())?;
                }
            }
            {
                let mut table = transaction.open_table(crate::raft::RAFT_LOG)?;
                let retired = table
                    .range(..=claim.raft_index())?
                    .map(|row| row.map(|(index, _)| index.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for index in retired {
                    table.remove(index)?;
                }
            }
            transaction
                .open_table(APPLY_META_TABLE_V2)?
                .insert(key.as_slice(), restored_meta.encode().as_slice())?;
            transaction
                .open_table(SNAPSHOT_TABLE_V2)?
                .insert(key.as_slice(), record.encode().as_slice())?;
            write_recovery_manifest(&transaction, &key, Some(manifest))?;
            retire_recovery_observations(&transaction, &key, claim.raft_index())?;
            // Hard state is monotonic even when the destination had an election
            // while offline. Never clear a vote in an unchanged term.
            if raft.current_term < claim.raft_term() {
                raft.current_term = claim.raft_term();
                raft.voted_for = None;
                transaction
                    .open_table(crate::raft::RAFT_META)?
                    .remove(META_AGENT_VOTED_FOR)?;
            }
            raft.commit_index = claim.raft_index();
            raft.last_applied = claim.raft_index();
            raft.snap_last_index = claim.raft_index();
            raft.snap_last_term = claim.raft_term();
            raft.write_in_txn(&transaction)?;
            transaction.commit()?;
            self.audit_recovery()?;
            Ok(InstalledAgentRaftSnapshotV2 {
                claim: claim.clone(),
                certificate_commitment: binding.commitment(),
            })
        }

        pub(crate) fn common_snapshot_authority(
            &self,
        ) -> Result<
            Option<(
                SharedAgentCommonSnapshotCertificate,
                SharedAgentLocalSnapshotBinding,
            )>,
            AgentRaftApplicationErrorV2,
        > {
            Ok(self
                .common_snapshot_authority_with_recovery()?
                .map(|(certificate, binding, _, _)| (certificate, binding)))
        }

        /// One freshly audited database view supplies both the physical
        /// authority, certified recovery baseline, and current live manifest.
        /// The live manifest is still only provisional execution evidence:
        /// callers must check nonbaseline observations against fresh replay
        /// results. Never retain this view across application calls or peer I/O.
        pub(crate) fn common_snapshot_authority_with_recovery(
            &self,
        ) -> Result<
            Option<(
                SharedAgentCommonSnapshotCertificate,
                SharedAgentLocalSnapshotBinding,
                Option<SharedRecoveryManifest>,
                Option<SharedRecoveryManifest>,
            )>,
            AgentRaftApplicationErrorV2,
        > {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let transaction = self.database.begin_read()?;
            let audit = self.audit_recovery_in_read(&transaction)?;
            let Some(record) = audit.snapshot else {
                return Ok(None);
            };
            match record.authority {
                SnapshotAuthorityV2::Common {
                    certificate,
                    binding,
                    recovery,
                } => {
                    // Preserve the stronger baseline accessor's fixed-roster
                    // scope checks as well as the complete audit above.
                    self.validate_common_scope(&certificate)?;
                    if record.generation != self.generation
                        || record.journal_store != self.journal_store
                        || record.local_node != self.local_node
                        || record.claim.raft_index() != audit.raft.snap_last_index
                        || record.claim.raft_term() != audit.raft.snap_last_term
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    Ok(Some((
                        certificate,
                        binding,
                        recovery.map(|(manifest, _)| manifest),
                        audit.recovery,
                    )))
                }
                _ => Ok(None),
            }
        }

        /// The certified checkpoint baseline, never the manifest advanced by
        /// later application slots. Export and replay must not substitute the
        /// current live manifest for this preimage.
        pub(crate) fn common_snapshot_recovery_manifest(
            &self,
        ) -> Result<Option<SharedRecoveryManifest>, AgentRaftApplicationErrorV2> {
            self.common_snapshot_recovery_manifest_at(None)
        }

        pub(crate) fn common_snapshot_recovery_manifest_at(
            &self,
            checkpoint: Option<super::super::journal::CheckpointId>,
        ) -> Result<Option<SharedRecoveryManifest>, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let snapshot = read_snapshot_in_read(
                &transaction,
                generation_storage_key(self.generation).as_slice(),
            )?;
            match snapshot {
                Some(record) if matches!(record.authority, SnapshotAuthorityV2::Common { .. }) => {
                    if let SnapshotAuthorityV2::Common { certificate, .. } = &record.authority {
                        self.validate_common_scope(certificate)?;
                    }
                    let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
                    if record.generation != self.generation
                        || record.journal_store != self.journal_store
                        || record.local_node != self.local_node
                        || record.claim.raft_index() != raft.snap_last_index
                        || record.claim.raft_term() != raft.snap_last_term
                        || checkpoint.is_some_and(|expected| expected != record.claim.checkpoint())
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    record.verify_authority()?;
                    Ok(Some(match record.recovery_manifest() {
                        Some(manifest) => manifest.clone(),
                        None => SharedRecoveryManifest::new(
                            self.generation,
                            self.initial_committee.clone(),
                        )
                        .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?,
                    }))
                }
                _ => Ok(None),
            }
        }

        /// Establish one fresh physical Raft generation from a quorum-signed
        /// portable logical checkpoint. The source store identity and source
        /// audit root never enter this transaction; both physical roots are
        /// re-derived from the destination binding and retained certificate.
        pub(crate) fn restore_portable_snapshot(
            &self,
            certificate: &SharedAgentPortableSnapshotCertificate,
            verified: &VerifiedSharedAgentPortableSnapshot,
        ) -> Result<InstalledAgentRaftSnapshotV2, AgentRaftApplicationErrorV2> {
            if verified.claim() != certificate.claim()
                || verified.certificate_commitment() != certificate.commitment()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotCertificateInvalid);
            }
            let portable = certificate.claim();
            certificate
                .verify(&self.initial_committee, portable)
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            if portable.active_committee() != &self.initial_committee
                || portable.authority_epoch() != self.authority.initial_epoch
                || portable.local_node() != self.local_node
                || self.initial_committee.members().len() != 1
                || self.initial_committee.voter_count() != 1
                || portable.ordered().space() != self.generation.space
                || portable.ordered().agent() != self.generation.agent
                || portable.ordered().genesis() != self.generation.genesis
                || portable.ordered().admission() != self.generation.admission
            {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
            let certificate_commitment = certificate.commitment();
            let foundation = portable_foundation_commitment(
                self.generation,
                self.journal_store,
                self.local_node,
                certificate_commitment,
            );
            let retired_audit_root = portable_retired_audit_root(
                self.generation,
                self.journal_store,
                self.local_node,
                certificate_commitment,
            );
            let claim = SharedAgentSnapshotClaim::new(
                portable.ordered().clone(),
                portable.active_committee().clone(),
                portable.authority_epoch(),
                Hash(*self.journal_store.as_bytes()),
                foundation,
                portable.ordered_successor(),
                portable.checkpoint_predecessor(),
                portable.journal_heads(),
                portable.checkpoint(),
                portable.local_node(),
                portable.control(),
                portable.linear(),
                portable.merge(),
                portable.local(),
                portable.ordered_invocations(),
                portable.merge_invocations(),
                portable.local_invocations(),
                portable.artifacts(),
                retired_audit_root,
                snapshot_committee_evidence_root(self.generation, &[]),
                None,
            )
            .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            let record = AgentRaftSnapshotRecordV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                local_node: self.local_node,
                claim: claim.clone(),
                authority: SnapshotAuthorityV2::Portable(certificate.clone()),
                committee_evidence: Vec::new(),
            };
            record.validate()?;

            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_write()?;
            ensure_v2_config_in_write(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            if let Some(current) = read_snapshot_in_write(&transaction, key.as_slice())? {
                if current.authority_commitment() == certificate_commitment
                    && current.claim == claim
                {
                    return Ok(InstalledAgentRaftSnapshotV2 {
                        claim,
                        certificate_commitment,
                    });
                }
                return Err(AgentRaftApplicationErrorV2::SnapshotStale);
            }
            let meta = read_meta_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let expected_meta =
                AgentRaftApplyMetaV2::post_genesis(self.generation, self.journal_store);
            let state = read_committee_state_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let expected_state = CommitteeApplicationStateV2::initial(
                self.generation,
                self.initial_committee.clone(),
                self.authority.initial_epoch,
            );
            let raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            if meta != expected_meta
                || state != expected_state
                || read_command_reservation_in_write(&transaction, key.as_slice())?.is_some()
                || audit_prefix_has_row_in_write(&transaction, &key)?
                || !transaction.open_table(crate::raft::RAFT_LOG)?.is_empty()?
                || raft != crate::raft::RaftMeta::default()
            {
                return Err(AgentRaftApplicationErrorV2::SnapshotReplay);
            }
            let ordered_head = portable
                .ordered()
                .ordered()
                .head
                .ok_or(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)?;
            let disposition =
                AgentRaftApplyDispositionV2::Command(AgentRaftAuditDisposition::OrderedApplied {
                    entry: ordered_head,
                    claim: portable.ordered().commitment(),
                    successor: portable.ordered_successor(),
                });
            let restored_meta = AgentRaftApplyMetaV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                applied_index: portable.raft_index(),
                applied_term: portable.raft_term(),
                raw_payload_commitment: foundation,
                disposition: Some(disposition),
            };
            restored_meta
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)?;
            {
                let mut table = transaction.open_table(APPLY_META_TABLE_V2)?;
                table.insert(key.as_slice(), restored_meta.encode().as_slice())?;
            }
            {
                let mut table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
                table.insert(key.as_slice(), record.encode().as_slice())?;
            }
            let restored_raft = crate::raft::RaftMeta {
                current_term: portable.raft_term(),
                voted_for: None,
                commit_index: portable.raft_index(),
                last_applied: portable.raft_index(),
                snap_last_index: portable.raft_index(),
                snap_last_term: portable.raft_term(),
            };
            restored_raft.write_in_txn(&transaction)?;
            transaction.commit()?;
            self.audit_recovery()?;
            Ok(InstalledAgentRaftSnapshotV2 {
                claim,
                certificate_commitment,
            })
        }

        pub(crate) fn current_snapshot(
            &self,
        ) -> Result<Option<InstalledAgentRaftSnapshotV2>, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery()?;
            let transaction = self.database.begin_read()?;
            Ok(read_snapshot_in_read(
                &transaction,
                generation_storage_key(self.generation).as_slice(),
            )?
            .map(|record| InstalledAgentRaftSnapshotV2 {
                claim: record.claim.clone(),
                certificate_commitment: record.authority_commitment(),
            }))
        }

        /// Every authority-certified committee ever activated or prepared in
        /// this generation. Shared Merge replay uses this bounded history to
        /// verify already-durable events, while live import separately
        /// requires the currently active committee ID.
        pub(crate) fn committee_history(
            &self,
        ) -> Result<Vec<AgentReplicaCommittee>, AgentRaftApplicationErrorV2> {
            self.audit_recovery()?;
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let mut committees = BTreeMap::new();
            committees.insert(self.initial_committee.id(), self.initial_committee.clone());
            if let Some(snapshot) = read_snapshot_in_read(&transaction, key.as_slice())? {
                for evidence in &snapshot.committee_evidence {
                    if !matches!(
                        evidence.record.disposition,
                        AgentRaftApplyDispositionV2::CommitteeChangePrepared { .. }
                    ) {
                        continue;
                    }
                    let vos_raft::EntryKind::Data { payload } =
                        decode_agent_raft_entry_kind(&evidence.physical)
                            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
                    else {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    };
                    let AgentRaftCommand::PrepareCommitteeChange(change) =
                        AgentRaftCommand::decode(&payload)
                            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
                    else {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    };
                    if let Some(existing) =
                        committees.insert(change.next().id(), change.next().clone())
                        && existing != *change.next()
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                }
            }
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            for row in table.range(key.as_slice()..)? {
                let (stored_key, value) = row?;
                if !stored_key.value().starts_with(key.as_slice()) {
                    break;
                }
                let record = AgentRaftApplyAuditRecordV2::decode(value.value())
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if !matches!(
                    record.disposition,
                    AgentRaftApplyDispositionV2::CommitteeChangePrepared { .. }
                ) {
                    continue;
                }
                let physical = verify_audited_physical_row_in_read(&transaction, &raft, &record)?;
                let Some(AgentRaftCommand::PrepareCommitteeChange(change)) = physical.command
                else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if let Some(existing) = committees.insert(change.next().id(), change.next().clone())
                    && existing != *change.next()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                if committees.len() > MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                    return Err(AgentRaftApplicationErrorV2::BacklogLimit);
                }
            }
            Ok(committees.into_values().collect())
        }

        fn committee_state(
            &self,
        ) -> Result<CommitteeApplicationStateV2, AgentRaftApplicationErrorV2> {
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_read()?;
            let table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                .value()
                .to_vec();
            let state = CommitteeApplicationStateV2::decode(&bytes)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if state.encode() != bytes {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            validate_bound_committee_state(&state, self.generation, self.authority)?;
            Ok(state)
        }

        /// Return the exact next committed physical slot, or `None` when the
        /// Raft commit cursor has not reached it. Callers cannot skip ahead
        /// through this API.
        pub(crate) fn next_committed_slot(
            &self,
        ) -> Result<Option<CommittedSharedRaftSlot>, AgentRaftApplicationErrorV2> {
            let next = self.cursor()?.applied_index.saturating_add(1);
            let witness = RedbSharedRaftLogWitness::new(Arc::clone(&self.database));
            match CommittedSharedRaftSlot::from_durable_log(&witness, next) {
                Ok(slot) => Ok(Some(slot)),
                Err(CommittedSharedRaftSlotError::Missing) => Ok(None),
                Err(CommittedSharedRaftSlotError::Invalid(_)) => {
                    Err(AgentRaftApplicationErrorV2::CorruptLedger)
                }
                Err(CommittedSharedRaftSlotError::Witness(error)) => Err(error.into()),
            }
        }

        /// Reserve the exact next ordinary command before any external
        /// journal or artifact publication is attempted. An exact retry by
        /// the same local replica returns equivalent opaque authority; any
        /// different command, replica, generation, committee, or store is a
        /// fail-closed divergence.
        pub(crate) fn reserve_command_application(
            &self,
            slot: &CommittedSharedRaftCommand,
        ) -> Result<ReservedAgentRaftApplication, AgentRaftApplicationErrorV2> {
            if matches!(
                slot.entry().command(),
                AgentRaftCommand::PrepareCommitteeChange(_)
                    | AgentRaftCommand::RegisterRecovery { .. }
                    | AgentRaftCommand::ExpireRecovery { .. }
            ) {
                return Err(AgentRaftApplicationErrorV2::CommandExecutionRequired);
            }
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let key = generation_storage_key(self.generation);
            let expiry_guard = match slot.entry().command() {
                AgentRaftCommand::Ordered { entry, .. } => {
                    self.stage_expiry_execution_guard(slot.entry().index(), &entry.input)?
                }
                _ => None,
            };
            let transaction = self.database.begin_write()?;
            ensure_v2_config_in_write(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let current = read_meta_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&current, self.generation, self.journal_store)?;
            let state = read_committee_state_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_committee_state(&state, self.generation, self.authority)?;
            if state.pending.is_some() {
                return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
            }
            let route = slot.entry().route();
            if route.generation() != self.generation {
                return Err(AgentRaftApplicationErrorV2::WrongGeneration);
            }
            if route.committee() != state.active.id() {
                return Err(AgentRaftApplicationErrorV2::StaleCommittee);
            }
            if !self.applies_as_local_replica(&state.active, self.local_node) {
                return Err(AgentRaftApplicationErrorV2::WrongLocalReplica);
            }

            let raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            if let Some(guard) = &expiry_guard {
                guard.require_current(&transaction, &key, &current, &raft)?;
            }
            if raft.last_applied != current.applied_index {
                return Err(AgentRaftApplicationErrorV2::RaftCursorMismatch {
                    raft: raft.last_applied,
                    application: current.applied_index,
                });
            }
            if slot.entry().index() <= current.applied_index {
                return Err(AgentRaftApplicationErrorV2::ConflictingDuplicate(
                    slot.entry().index(),
                ));
            }
            let next = current.applied_index.saturating_add(1);
            if slot.entry().index() != next {
                return Err(AgentRaftApplicationErrorV2::ApplyGap {
                    expected: next,
                    actual: slot.entry().index(),
                });
            }
            if current.applied_index != 0 && slot.entry().term() < current.applied_term {
                return Err(AgentRaftApplicationErrorV2::TermRegression {
                    previous: current.applied_term,
                    actual: slot.entry().term(),
                });
            }
            if current.applied_index.saturating_sub(raft.snap_last_index)
                >= MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64
            {
                return Err(AgentRaftApplicationErrorV2::BacklogLimit);
            }
            verify_committed_command_physical_row_in_write(&transaction, &raft, slot)?;

            let expected = CommandReservationRecordV2::from_slot(
                self.generation,
                self.journal_store,
                self.local_node,
                slot,
            )?;
            let existing = read_command_reservation_in_write(&transaction, key.as_slice())?;
            if let Some(existing) = existing {
                if existing != expected {
                    return Err(AgentRaftApplicationErrorV2::DivergentCommandReservation);
                }
            } else {
                let audit_key = audit_storage_key(self.generation, slot.entry().index());
                if read_audit_in_write(&transaction, audit_key.as_slice())?.is_some() {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let mut table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
                table.insert(key.as_slice(), expected.encode().as_slice())?;
                drop(table);
                transaction.commit()?;
            }
            Ok(ReservedAgentRaftApplication {
                committed: slot.entry().clone(),
                local_node: self.local_node,
                journal_store: self.journal_store,
                artifact_batch: expected.artifact_batch,
            })
        }

        /// Complete a successfully persisted artifact operation. Ordered
        /// publication cannot use this method; it must cross the opaque replay
        /// receipt boundary below.
        pub(crate) fn complete_artifact_command(
            &self,
            reserved: &ReservedAgentRaftApplication,
            disposition: AgentRaftAuditDisposition,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            if matches!(
                disposition,
                AgentRaftAuditDisposition::OrderedApplied { .. }
            ) {
                return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
            }
            self.complete_reserved_command(reserved, disposition, None)
        }

        #[cfg(test)]
        pub(crate) fn anchor_ordered_for_test(
            &self,
            slot: &CommittedSharedRaftCommand,
            claim: &OrderedCommitClaim,
            successor: JournalHeadsId,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            let reserved = self.reserve_command_application(slot)?;
            super::evidence_ledger::validate_claim_link_with_artifact_batch(
                reserved.route(),
                reserved.committed(),
                claim,
            )
            .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
            let AgentRaftCommand::Ordered { entry, .. } = reserved.committed().command() else {
                return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
            };
            self.complete_reserved_command(
                &reserved,
                AgentRaftAuditDisposition::OrderedApplied {
                    entry: entry.id(),
                    claim: claim.commitment(),
                    successor,
                },
                None,
            )
        }

        /// Advance the physical Raft cursor only for replay's exact successful
        /// Shared Ordered publication receipt.
        pub(crate) fn anchor_applied_ordered(
            &self,
            published: PublishedSharedOrdered,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            self.anchor_applied_ordered_with_recovery(published, None)
        }

        pub(crate) fn anchor_applied_ordered_with_recovery(
            &self,
            published: PublishedSharedOrdered,
            observation: Option<&VerifiedSharedRecoveryObservation>,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            let reserved = published.reservation();
            if published.journal_store() != self.journal_store
                || reserved.journal_store() != self.journal_store
                || published.journal_store() != reserved.journal_store()
            {
                return Err(AgentRaftApplicationErrorV2::WrongJournalStore);
            }
            let committed = reserved.committed();
            let claim = published.claim();
            super::evidence_ledger::validate_claim_link_with_artifact_batch(
                committed.route(),
                committed,
                claim,
            )
            .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
            let entry = match committed.command() {
                AgentRaftCommand::Ordered { entry, .. } => entry,
                _ => return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition),
            };
            if published.entry() != entry.id()
                || published.raft_index() != committed.index()
                || published.raft_term() != committed.term()
                || published.raft_payload_commitment() != committed.payload_commitment()
            {
                return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
            }
            self.complete_reserved_command(
                reserved,
                AgentRaftAuditDisposition::OrderedApplied {
                    entry: entry.id(),
                    claim: claim.commitment(),
                    successor: published.successor(),
                },
                observation,
            )
        }

        fn stage_expiry_execution_guard(
            &self,
            index: u64,
            input: &ReplayInput,
        ) -> Result<Option<StagedRecoveryUpdate>, AgentRaftApplicationErrorV2> {
            // Preserve the legacy hot path: only expiry-enabled manifests need
            // decoding, and never while holding the Raft database writer.
            let transaction = self.database.begin_read()?;
            let key = generation_storage_key(self.generation);
            let table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
            let expiry = table
                .get(key.as_slice())?
                .is_some_and(|value| value.value().starts_with(b"RMF2"));
            drop(table);
            drop(transaction);
            if !expiry {
                return Ok(None);
            }
            let predecessor = self
                .recovery_update_predecessor(index)?
                .ok_or(AgentRaftApplicationErrorV2::ConflictingDuplicate(index))?;
            let manifest = self
                .decode_recovery_predecessor(&predecessor)?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            if recovery_input_expired(&manifest, input) {
                return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
            }
            Ok(Some(StagedRecoveryUpdate {
                predecessor,
                manifest: None,
                observation: None,
            }))
        }

        /// Capture only a fresh application's predecessor. Historical retry
        /// classification remains inside the write transaction and must not
        /// refold a request whose live owner slot has since been replaced.
        fn recovery_update_predecessor(
            &self,
            index: u64,
        ) -> Result<Option<RecoveryUpdatePredecessor>, AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            let key = generation_storage_key(self.generation);
            let table = transaction.open_table(APPLY_META_TABLE_V2)?;
            let bytes = table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let meta = AgentRaftApplyMetaV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            if meta.encode() != bytes.value() {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            if index <= meta.applied_index {
                return Ok(None);
            }
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
            let manifest = table
                .get(key.as_slice())?
                .map(|value| {
                    if value.value().len() > MAX_SHARED_RECOVERY_MANIFEST_BYTES {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    Ok(value.value().to_vec())
                })
                .transpose()?;
            Ok(Some(RecoveryUpdatePredecessor {
                manifest,
                meta,
                snapshot: (raft.snap_last_index, raft.snap_last_term),
            }))
        }

        fn decode_recovery_predecessor(
            &self,
            predecessor: &RecoveryUpdatePredecessor,
        ) -> Result<Option<SharedRecoveryManifest>, AgentRaftApplicationErrorV2> {
            predecessor
                .manifest
                .as_deref()
                .map(|bytes| {
                    decode_recovery_manifest(bytes, self.generation, &self.initial_committee)
                })
                .transpose()
        }

        fn stage_recovery_observation(
            &self,
            reserved: &ReservedAgentRaftApplication,
            observation: Option<&VerifiedSharedRecoveryObservation>,
        ) -> Result<Option<StagedRecoveryUpdate>, AgentRaftApplicationErrorV2> {
            let Some(predecessor) = self.recovery_update_predecessor(reserved.index())? else {
                return Ok(None);
            };
            let mut manifest = self.decode_recovery_predecessor(&predecessor)?;
            let matches_recovery = match (manifest.as_ref(), reserved.committed().command()) {
                (Some(manifest), AgentRaftCommand::Ordered { entry, .. }) => {
                    if recovery_input_expired(manifest, &entry.input) {
                        return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
                    }
                    recovery_input_matches(manifest, &entry.input)
                }
                _ => false,
            };
            let is_acknowledgement = matches!(reserved.committed().command(),
                AgentRaftCommand::Ordered { entry, .. }
                    if matches!(entry.input.operation, ReplayOperation::CleanAcknowledge { .. }));
            if (!matches_recovery && observation.is_some())
                || (matches_recovery && observation.is_none() && !is_acknowledgement)
            {
                return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
            }
            let (manifest, observation) = if let Some(observation) = observation {
                let manifest = manifest
                    .as_mut()
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                manifest
                    .observe(observation)
                    .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
                (
                    Some(manifest.encode()),
                    Some(observation.observation().encode()),
                )
            } else {
                (None, None)
            };
            Ok(Some(StagedRecoveryUpdate {
                predecessor,
                manifest,
                observation,
            }))
        }

        fn stage_recovery_registration(
            &self,
            slot: &CommittedSharedRaftSlot,
        ) -> Result<
            Option<(StagedRecoveryUpdate, AgentRaftApplyDispositionV2)>,
            AgentRaftApplicationErrorV2,
        > {
            let CommittedSharedRaftSlot::Command(command) = slot else {
                return Ok(None);
            };
            if !matches!(
                command.entry().command(),
                AgentRaftCommand::RegisterRecovery { .. } | AgentRaftCommand::ExpireRecovery { .. }
            ) {
                return Ok(None);
            }
            let Some(predecessor) = self.recovery_update_predecessor(slot.index())? else {
                return Ok(None);
            };
            let mut manifest = self
                .decode_recovery_predecessor(&predecessor)?
                .map(Ok)
                .unwrap_or_else(|| {
                    SharedRecoveryManifest::new(self.generation, self.initial_committee.clone())
                        .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)
                })?;
            let disposition = match command.entry().command() {
                AgentRaftCommand::RegisterRecovery { registration, .. } => {
                    manifest
                        .apply_registration(registration, slot.index(), slot.term())
                        .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
                    AgentRaftApplyDispositionV2::RecoveryRegistered {
                        registration: registration.commitment(),
                        manifest: manifest.commitment(),
                    }
                }
                AgentRaftCommand::ExpireRecovery { certificate, .. } => {
                    // A complete fresh audit is prepared before the database
                    // writer. Exact meta/manifest/snapshot CAS below keeps this
                    // proof valid across the transaction boundary.
                    let transaction = self.database.begin_read()?;
                    let audited = self.audit_recovery_in_read(&transaction)?;
                    let claim = certificate.claim();
                    if audited.meta != predecessor.meta
                        || audited.recovery.as_ref() != Some(&manifest)
                        || (audited.raft.snap_last_index, audited.raft.snap_last_term)
                            != predecessor.snapshot
                        || audited.reservation_pending
                        || audited.ordered != claim.ordered()
                        || audited.meta.applied() != (claim.prefix_index(), claim.prefix_term())
                    {
                        return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
                    }
                    manifest
                        .apply_expiry(certificate, slot.index(), slot.term())
                        .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
                    AgentRaftApplyDispositionV2::RecoveryExpired {
                        certificate: certificate.commitment(),
                        manifest: manifest.commitment(),
                    }
                }
                _ => unreachable!("metadata shape checked above"),
            };
            Ok(Some((
                StagedRecoveryUpdate {
                    predecessor,
                    manifest: Some(manifest.encode()),
                    observation: None,
                },
                disposition,
            )))
        }

        fn complete_reserved_command(
            &self,
            reserved: &ReservedAgentRaftApplication,
            disposition: AgentRaftAuditDisposition,
            observation: Option<&VerifiedSharedRecoveryObservation>,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            #[cfg(test)]
            let mut recovery_timing = RecoveryPhaseTiming::start(
                observation.is_some(),
                "observation",
                reserved.index(),
                self.local_node,
            );
            disposition
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
            validate_command_disposition(reserved.committed().command(), disposition)?;
            if let Some(observation) = observation {
                let (
                    AgentRaftCommand::Ordered { entry, .. },
                    AgentRaftAuditDisposition::OrderedApplied { claim, .. },
                ) = (reserved.committed().command(), disposition)
                else {
                    return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
                };
                observation
                    .observation()
                    .validate_binding(reserved.index(), reserved.term(), claim, &entry.input)
                    .map_err(|_| AgentRaftApplicationErrorV2::InvalidCommandDisposition)?;
            }
            if reserved.journal_store() != self.journal_store {
                return Err(AgentRaftApplicationErrorV2::WrongJournalStore);
            }
            if reserved.route().generation() != self.generation {
                return Err(AgentRaftApplicationErrorV2::WrongGeneration);
            }
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "binding_validated");

            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "application_lock_acquired");
            let staged = self.stage_recovery_observation(reserved, observation)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "recovery_staged_before_writer");
            self.complete_staged_reserved_command(
                reserved,
                disposition,
                observation,
                staged,
                #[cfg(test)]
                recovery_timing,
            )
        }

        fn complete_staged_reserved_command(
            &self,
            reserved: &ReservedAgentRaftApplication,
            disposition: AgentRaftAuditDisposition,
            observation: Option<&VerifiedSharedRecoveryObservation>,
            staged: Option<StagedRecoveryUpdate>,
            #[cfg(test)] mut recovery_timing: Option<RecoveryPhaseTiming>,
        ) -> Result<AgentRaftCommandApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_write()?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "write_lock_acquired");
            ensure_v2_config_in_write(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let current = read_meta_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&current, self.generation, self.journal_store)?;
            let state = read_committee_state_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_committee_state(&state, self.generation, self.authority)?;
            let mut raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            if raft.last_applied != current.applied_index {
                return Err(AgentRaftApplicationErrorV2::RaftCursorMismatch {
                    raft: raft.last_applied,
                    application: current.applied_index,
                });
            }

            if reserved.index() <= current.applied_index {
                if read_command_reservation_in_write(&transaction, key.as_slice())?.is_some() {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let audit_key = audit_storage_key(self.generation, reserved.index());
                let stored = read_audit_in_write(&transaction, audit_key.as_slice())?.ok_or(
                    AgentRaftApplicationErrorV2::MissingAuditRecord(reserved.index()),
                )?;
                let expected = AgentRaftApplyDispositionV2::Command(disposition);
                if stored.generation != self.generation
                    || stored.index != reserved.index()
                    || stored.term != reserved.term()
                    || stored.disposition != expected
                {
                    return Err(AgentRaftApplicationErrorV2::ConflictingDuplicate(
                        reserved.index(),
                    ));
                }
                verify_reserved_command_physical_row_in_write(
                    &transaction,
                    &raft,
                    reserved,
                    stored.raw_payload_commitment,
                )?;
                let stored_observation = read_recovery_observation(
                    &transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?,
                    &audit_key,
                )?;
                if stored_observation.as_ref() != observation.map(|value| value.observation()) {
                    return Err(AgentRaftApplicationErrorV2::ConflictingDuplicate(
                        reserved.index(),
                    ));
                }
                return Ok(AgentRaftCommandApplyOutcomeV2::Duplicate(current));
            }

            let next = current.applied_index.saturating_add(1);
            if reserved.index() != next {
                return Err(AgentRaftApplicationErrorV2::ApplyGap {
                    expected: next,
                    actual: reserved.index(),
                });
            }
            if current.applied_index != 0 && reserved.term() < current.applied_term {
                return Err(AgentRaftApplicationErrorV2::TermRegression {
                    previous: current.applied_term,
                    actual: reserved.term(),
                });
            }
            if state.pending.is_some() {
                return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
            }
            if reserved.route().committee() != state.active.id() {
                return Err(AgentRaftApplicationErrorV2::StaleCommittee);
            }
            if !self.applies_as_local_replica(&state.active, reserved.local_node()) {
                return Err(AgentRaftApplicationErrorV2::WrongLocalReplica);
            }
            let stored = read_command_reservation_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CommandReservationRequired)?;
            if stored.generation != self.generation || !stored.matches_reserved(reserved) {
                return Err(AgentRaftApplicationErrorV2::DivergentCommandReservation);
            }
            verify_reserved_command_physical_row_in_write(
                &transaction,
                &raft,
                reserved,
                stored.raw_payload_commitment,
            )?;

            let wrapped = AgentRaftApplyDispositionV2::Command(disposition);
            let audit = AgentRaftApplyAuditRecordV2 {
                generation: self.generation,
                index: reserved.index(),
                term: reserved.term(),
                raw_payload_commitment: stored.raw_payload_commitment,
                disposition: wrapped,
            };
            audit
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let audit_key = audit_storage_key(self.generation, reserved.index());
            if read_audit_in_write(&transaction, audit_key.as_slice())?.is_some() {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "physical_binding_validated");
            let staged = staged.ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            staged.require_current(&transaction, &key, &current, &raft)?;
            if let Some(manifest) = &staged.manifest {
                transaction
                    .open_table(RECOVERY_MANIFEST_TABLE_V2)?
                    .insert(key.as_slice(), manifest.as_slice())?;
            }
            if let Some(observation) = &staged.observation {
                transaction
                    .open_table(RECOVERY_OBSERVATION_TABLE_V2)?
                    .insert(audit_key.as_slice(), observation.as_slice())?;
            }
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "recovery_cas_rows_written");
            let next_meta = AgentRaftApplyMetaV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                applied_index: reserved.index(),
                applied_term: reserved.term(),
                raw_payload_commitment: stored.raw_payload_commitment,
                disposition: Some(wrapped),
            };
            next_meta
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            {
                let mut table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
                table.insert(audit_key.as_slice(), audit.encode().as_slice())?;
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE_V2)?;
                table.insert(key.as_slice(), next_meta.encode().as_slice())?;
            }
            {
                let mut table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
                if table.remove(key.as_slice())?.is_none() {
                    return Err(AgentRaftApplicationErrorV2::CommandReservationRequired);
                }
            }
            raft.last_applied = reserved.index();
            raft.write_host_fields_in_txn(&transaction)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "application_rows_written");
            transaction.commit()?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "committed");
            Ok(AgentRaftCommandApplyOutcomeV2::Applied(next_meta))
        }

        /// Apply one exact physical slot. While a committee transition is
        /// pending, the next slot must be its exact joint/stable barrier leg;
        /// even leader no-ops are refused without cursor advancement.
        pub(crate) fn apply_foundation_slot(
            &self,
            slot: &CommittedSharedRaftSlot,
        ) -> Result<AgentRaftFoundationApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            #[cfg(test)]
            let mut recovery_timing = RecoveryPhaseTiming::start(
                matches!(slot, CommittedSharedRaftSlot::Command(command) if matches!(command.entry().command(), AgentRaftCommand::RegisterRecovery { .. })),
                "registration",
                slot.index(),
                self.local_node,
            );
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "application_lock_acquired");
            let staged = self.stage_recovery_registration(slot)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "recovery_staged_before_writer");
            self.apply_staged_foundation_slot(
                slot,
                staged,
                #[cfg(test)]
                recovery_timing,
            )
        }

        fn apply_staged_foundation_slot(
            &self,
            slot: &CommittedSharedRaftSlot,
            staged: Option<(StagedRecoveryUpdate, AgentRaftApplyDispositionV2)>,
            #[cfg(test)] mut recovery_timing: Option<RecoveryPhaseTiming>,
        ) -> Result<AgentRaftFoundationApplyOutcomeV2, AgentRaftApplicationErrorV2> {
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_write()?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "write_lock_acquired");
            ensure_v2_config_in_write(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let current = read_meta_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&current, self.generation, self.journal_store)?;
            let state = read_committee_state_in_write(&transaction, key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_committee_state(&state, self.generation, self.authority)?;
            let mut raft = crate::raft::RaftMeta::load_from_write_transaction(&transaction)?;
            if raft.last_applied != current.applied_index {
                return Err(AgentRaftApplicationErrorV2::RaftCursorMismatch {
                    raft: raft.last_applied,
                    application: current.applied_index,
                });
            }

            if slot.index() <= current.applied_index {
                let audit_key = audit_storage_key(self.generation, slot.index());
                let stored = read_audit_in_write(&transaction, audit_key.as_slice())?.ok_or(
                    AgentRaftApplicationErrorV2::MissingAuditRecord(slot.index()),
                )?;
                if stored.generation != self.generation
                    || stored.index != slot.index()
                    || stored.term != slot.term()
                    || stored.raw_payload_commitment != slot.raw_payload_commitment()
                {
                    return Err(AgentRaftApplicationErrorV2::ConflictingDuplicate(
                        slot.index(),
                    ));
                }
                verify_physical_row_in_write(&transaction, &raft, slot, stored.disposition)?;
                return Ok(AgentRaftFoundationApplyOutcomeV2::Duplicate(current));
            }

            let next = current.applied_index.saturating_add(1);
            if slot.index() != next {
                return Err(AgentRaftApplicationErrorV2::ApplyGap {
                    expected: next,
                    actual: slot.index(),
                });
            }
            if current.applied_index != 0 && slot.term() < current.applied_term {
                return Err(AgentRaftApplicationErrorV2::TermRegression {
                    previous: current.applied_term,
                    actual: slot.term(),
                });
            }
            if current.applied_index.saturating_sub(raft.snap_last_index)
                >= MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64
            {
                return Err(AgentRaftApplicationErrorV2::BacklogLimit);
            }

            let (disposition, next_state, recovery_update) = if let CommittedSharedRaftSlot::Command(
                command,
            ) = slot
                && let AgentRaftCommand::RegisterRecovery { route, .. }
                | AgentRaftCommand::ExpireRecovery { route, .. } = command.entry().command()
            {
                if state.pending.is_some()
                    || state.active != self.initial_committee
                    || route.generation() != self.generation
                    || route.committee() != state.active.id()
                {
                    return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
                }
                #[cfg(test)]
                RecoveryPhaseTiming::mark(&mut recovery_timing, "application_state_validated");
                let (staged, disposition) =
                    staged.ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                staged.require_current(&transaction, &key, &current, &raft)?;
                if read_command_reservation_in_write(&transaction, key.as_slice())?.is_some() {
                    return Err(AgentRaftApplicationErrorV2::CommandReservationRequired);
                }
                (disposition, state.clone(), staged.manifest)
            } else {
                if matches!(slot, CommittedSharedRaftSlot::Command(command) if matches!(command.entry().command(), AgentRaftCommand::PrepareCommitteeChange(_)))
                    && read_recovery_manifest(
                        &transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?,
                        &key,
                        self.generation,
                        &self.initial_committee,
                    )?
                    .is_some()
                {
                    return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
                }
                let (disposition, next_state) = self.transition_state(&state, slot)?;
                (disposition, next_state, None)
            };
            verify_physical_row_in_write(&transaction, &raft, slot, disposition)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "physical_binding_validated");

            let expected_record = AgentRaftApplyAuditRecordV2 {
                generation: self.generation,
                index: slot.index(),
                term: slot.term(),
                raw_payload_commitment: slot.raw_payload_commitment(),
                disposition,
            };
            expected_record
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            next_state
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;

            let audit_key = audit_storage_key(self.generation, slot.index());
            if read_audit_in_write(&transaction, audit_key.as_slice())?.is_some() {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let next_meta = AgentRaftApplyMetaV2 {
                generation: self.generation,
                journal_store: self.journal_store,
                applied_index: slot.index(),
                applied_term: slot.term(),
                raw_payload_commitment: slot.raw_payload_commitment(),
                disposition: Some(disposition),
            };
            next_meta
                .validate()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            {
                let mut table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
                table.insert(audit_key.as_slice(), expected_record.encode().as_slice())?;
            }
            {
                let mut table = transaction.open_table(APPLY_META_TABLE_V2)?;
                table.insert(key.as_slice(), next_meta.encode().as_slice())?;
            }
            {
                let mut table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
                table.insert(key.as_slice(), next_state.encode().as_slice())?;
            }
            if let Some(manifest) = recovery_update {
                let mut table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
                table.insert(key.as_slice(), manifest.as_slice())?;
            }
            raft.last_applied = slot.index();
            raft.write_host_fields_in_txn(&transaction)?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "application_rows_encoded_written");
            transaction.commit()?;
            #[cfg(test)]
            RecoveryPhaseTiming::mark(&mut recovery_timing, "committed");
            Ok(AgentRaftFoundationApplyOutcomeV2::Applied(next_meta))
        }

        fn transition_state(
            &self,
            state: &CommitteeApplicationStateV2,
            slot: &CommittedSharedRaftSlot,
        ) -> Result<
            (AgentRaftApplyDispositionV2, CommitteeApplicationStateV2),
            AgentRaftApplicationErrorV2,
        > {
            match slot {
                CommittedSharedRaftSlot::LeaderNoop(_) => {
                    if state.pending.is_some() {
                        return Err(AgentRaftApplicationErrorV2::TransitionBarrier);
                    }
                    Ok((AgentRaftApplyDispositionV2::LeaderNoop, state.clone()))
                }
                CommittedSharedRaftSlot::Command(command) => match command.entry().command() {
                    AgentRaftCommand::PrepareCommitteeChange(change) => {
                        if change.generation() != self.generation {
                            return Err(AgentRaftApplicationErrorV2::WrongGeneration);
                        }
                        if state.pending.is_some() {
                            return Err(AgentRaftApplicationErrorV2::OverlappingCommitteeChange);
                        }
                        if change.previous() != &state.active {
                            return Err(AgentRaftApplicationErrorV2::StaleCommittee);
                        }
                        if state.authority_epoch == u64::MAX {
                            return Err(AgentRaftApplicationErrorV2::AuthorityEpochExhausted);
                        }
                        self.authority
                            .verify(self.generation, state.authority_epoch, change)?;
                        let mut next_state = state.clone();
                        next_state.pending = Some(PendingCommitteeChangeV2 {
                            change: change.clone(),
                            prepare_index: slot.index(),
                            prepare_term: slot.term(),
                            prepare_payload_commitment: slot.raw_payload_commitment(),
                            phase: PendingCommitteePhaseV2::Prepared,
                        });
                        Ok((
                            AgentRaftApplyDispositionV2::CommitteeChangePrepared {
                                transition: change.transition(),
                                previous: change.previous().id(),
                                next: change.next().id(),
                                authority: change.authority_commitment(),
                            },
                            next_state,
                        ))
                    }
                    _ if state.pending.is_some() => {
                        Err(AgentRaftApplicationErrorV2::TransitionBarrier)
                    }
                    _ => Err(AgentRaftApplicationErrorV2::CommandExecutionRequired),
                },
                CommittedSharedRaftSlot::Configuration(configuration) => {
                    let Some(pending) = state.pending.as_ref() else {
                        return Err(AgentRaftApplicationErrorV2::UnsolicitedConfiguration);
                    };
                    let change = &pending.change;
                    match pending.phase {
                        PendingCommitteePhaseV2::Prepared => {
                            let Some(previous) = configuration.joint_old() else {
                                return Err(AgentRaftApplicationErrorV2::ReorderedConfiguration);
                            };
                            if previous != change.previous_voters()
                                || configuration.members() != change.next_voters()
                            {
                                return Err(AgentRaftApplicationErrorV2::WrongConfigurationNodes);
                            }
                            let mut next_state = state.clone();
                            let Some(next_pending) = next_state.pending.as_mut() else {
                                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                            };
                            next_pending.phase = PendingCommitteePhaseV2::Joint {
                                index: slot.index(),
                                term: slot.term(),
                                raw_payload_commitment: slot.raw_payload_commitment(),
                            };
                            Ok((
                                AgentRaftApplyDispositionV2::CommitteeJointConfiguration {
                                    transition: change.transition(),
                                    previous: change.previous().id(),
                                    next: change.next().id(),
                                },
                                next_state,
                            ))
                        }
                        PendingCommitteePhaseV2::Joint { .. } => {
                            if configuration.joint_old().is_some() {
                                return Err(AgentRaftApplicationErrorV2::ReorderedConfiguration);
                            }
                            if configuration.members() != change.next_voters() {
                                return Err(AgentRaftApplicationErrorV2::WrongConfigurationNodes);
                            }
                            let mut next_state = state.clone();
                            next_state.active = change.next().clone();
                            next_state.authority_epoch = next_state
                                .authority_epoch
                                .checked_add(1)
                                .ok_or(AgentRaftApplicationErrorV2::AuthorityEpochExhausted)?;
                            next_state.pending = None;
                            Ok((
                                AgentRaftApplyDispositionV2::CommitteeStableConfiguration {
                                    transition: change.transition(),
                                    committee: change.next().id(),
                                },
                                next_state,
                            ))
                        }
                    }
                }
            }
        }

        /// Strict restart audit. A retained suffix is checked against its
        /// still-present physical Raft rows; a compacted prefix is accepted
        /// only through the exact snapshot certificate and the complete
        /// authority-verified committee-transition evidence it carries.
        pub(crate) fn audit_recovery(&self) -> Result<(), AgentRaftApplicationErrorV2> {
            self.audit_recovery_capacity().map(|_| ())
        }

        /// Capacity facts from the same fully authenticated recovery pass.
        /// No projection of the already validated command suffix is needed.
        pub(crate) fn capacity(&self) -> Result<(u64, u64, bool), AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery_capacity()
        }

        fn audit_recovery_capacity(&self) -> Result<(u64, u64, bool), AgentRaftApplicationErrorV2> {
            let transaction = self.database.begin_read()?;
            self.audit_recovery_in_read(&transaction)
                .map(|view| view.capacity())
        }

        fn audit_recovery_in_read(
            &self,
            transaction: &redb::ReadTransaction,
        ) -> Result<AuditedRecoveryView, AgentRaftApplicationErrorV2> {
            self.audit_recovery_in_read_with_evidence(transaction, false)
        }

        fn audit_recovery_in_read_with_evidence(
            &self,
            transaction: &redb::ReadTransaction,
            collect_replay_evidence: bool,
        ) -> Result<AuditedRecoveryView, AgentRaftApplicationErrorV2> {
            let started = std::time::Instant::now();
            let key = generation_storage_key(self.generation);
            ensure_v2_config_in_read(
                &transaction,
                key.as_slice(),
                self.generation,
                self.journal_store,
                self.local_node,
                &self.initial_committee,
                self.authority,
            )?;
            let meta = {
                let table = transaction.open_table(APPLY_META_TABLE_V2)?;
                let bytes = table
                    .get(key.as_slice())?
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                    .value()
                    .to_vec();
                let meta = AgentRaftApplyMetaV2::decode(&bytes)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if meta.encode() != bytes {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                meta
            };
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            let stored_committee_state = {
                let table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
                let bytes = table
                    .get(key.as_slice())?
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                    .value()
                    .to_vec();
                let state = CommitteeApplicationStateV2::decode(&bytes)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if state.encode() != bytes {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                validate_bound_committee_state(&state, self.generation, self.authority)?;
                state
            };
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let snapshot = read_snapshot_in_read(&transaction, key.as_slice())?;
            let (mut replayed_committee_state, snapshot_claim) = match snapshot.as_ref() {
                Some(snapshot) => {
                    snapshot.validate()?;
                    let state = replay_snapshot_committee_evidence(
                        self.generation,
                        self.initial_committee.clone(),
                        self.authority,
                        &snapshot.committee_evidence,
                    )?;
                    let claim = &snapshot.claim;
                    if state.active != *claim.active_committee()
                        || state.authority_epoch != claim.authority_epoch()
                        || claim.journal_store().0 != *self.journal_store.as_bytes()
                        || claim.local_node() != self.local_node
                        || raft.snap_last_index != claim.raft_index()
                        || raft.snap_last_term != claim.raft_term()
                    {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    snapshot.verify_authority()?;
                    (state, Some(claim))
                }
                None => {
                    if raft.snap_last_index != 0 || raft.snap_last_term != 0 {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    (
                        CommitteeApplicationStateV2::initial(
                            self.generation,
                            self.initial_committee.clone(),
                            self.authority.initial_epoch,
                        ),
                        None,
                    )
                }
            };
            if raft.last_applied != meta.applied_index {
                return Err(AgentRaftApplicationErrorV2::RaftCursorMismatch {
                    raft: raft.last_applied,
                    application: meta.applied_index,
                });
            }
            if raft.commit_index < meta.applied_index {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }

            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let observation_table = transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?;
            let mut replayed_recovery = snapshot
                .as_ref()
                .and_then(|record| record.recovery_manifest())
                .cloned();
            let mut ordered = snapshot
                .as_ref()
                .map(|record| record.claim.ordered().ordered())
                .unwrap_or_else(OrderedBase::post_genesis);
            let mut observed_recovery_rows = 0_usize;
            let mut recovery_replay_evidence = Vec::new();
            let mut expected_index = raft.snap_last_index.saturating_add(1);
            let mut previous_term = raft.snap_last_term;
            let mut last_record = None;
            let mut retained = 0_usize;
            for row in table.range(key.as_slice()..)? {
                let (stored_key, value) = row?;
                if !stored_key.value().starts_with(key.as_slice()) {
                    break;
                }
                retained = retained.saturating_add(1);
                if retained > MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES
                    || stored_key.value().len() != AUDIT_STORAGE_KEY_BYTES
                {
                    return Err(AgentRaftApplicationErrorV2::BacklogLimit);
                }
                let record = AgentRaftApplyAuditRecordV2::decode(value.value())
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if record.encode() != value.value()
                    || record.generation != self.generation
                    || record.index != expected_index
                    || record.term < previous_term
                    || audit_storage_key(self.generation, record.index).as_slice()
                        != stored_key.value()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let physical = verify_audited_physical_row_in_read(&transaction, &raft, &record)?;
                let observation =
                    read_recovery_observation(&observation_table, stored_key.value())?;
                match (&record.disposition, physical.command.as_ref()) {
                    (
                        AgentRaftApplyDispositionV2::RecoveryRegistered {
                            registration: expected,
                            manifest: root,
                        },
                        Some(AgentRaftCommand::RegisterRecovery { registration, .. }),
                    ) => {
                        if observation.is_some() || registration.commitment() != *expected {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        let manifest = match &mut replayed_recovery {
                            Some(manifest) => manifest,
                            empty @ None => empty.insert(
                                SharedRecoveryManifest::new(
                                    self.generation,
                                    self.initial_committee.clone(),
                                )
                                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
                            ),
                        };
                        manifest
                            .apply_registration(registration, record.index, record.term)
                            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                        if manifest.commitment() != *root {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                    }
                    (
                        AgentRaftApplyDispositionV2::RecoveryExpired {
                            certificate: expected,
                            manifest: root,
                        },
                        Some(AgentRaftCommand::ExpireRecovery { certificate, .. }),
                    ) => {
                        let claim = certificate.claim();
                        if observation.is_some()
                            || certificate.commitment() != *expected
                            || claim.prefix_index().checked_add(1) != Some(record.index)
                            || claim.prefix_term() != previous_term
                            || claim.ordered() != ordered
                        {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        let manifest = replayed_recovery
                            .as_mut()
                            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                        manifest
                            .apply_expiry(certificate, record.index, record.term)
                            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                        if manifest.commitment() != *root {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                    }
                    (
                        AgentRaftApplyDispositionV2::Command(
                            AgentRaftAuditDisposition::OrderedApplied { claim, .. },
                        ),
                        Some(AgentRaftCommand::Ordered { entry, .. }),
                    ) => {
                        ordered = OrderedBase {
                            index: entry.index,
                            head: Some(entry.id()),
                        };
                        if replayed_recovery
                            .as_ref()
                            .is_some_and(|manifest| recovery_input_expired(manifest, &entry.input))
                        {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        let matches = replayed_recovery
                            .as_ref()
                            .is_some_and(|manifest| recovery_input_matches(manifest, &entry.input));
                        let is_acknowledgement = matches!(
                            entry.input.operation,
                            ReplayOperation::CleanAcknowledge { .. }
                        );
                        if (!matches && observation.is_some())
                            || (matches && observation.is_none() && !is_acknowledgement)
                        {
                            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                        }
                        if matches && collect_replay_evidence {
                            // Only the driver can turn this structural audit
                            // into execution evidence. None requires exactly
                            // Acknowledged(Err) at this physical occurrence.
                            recovery_replay_evidence.push((
                                entry.id(), entry.input.id(),
                                observation.as_ref().map(|value| value.outcome().clone()),
                            ));
                        }
                        if let Some(observation) = observation {
                            observation
                                .validate_binding(record.index, record.term, *claim, &entry.input)
                                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                            // This is a provisional ledger fold, not execution
                            // authority. Driver reopen independently compares all
                            // retained outcomes with authenticated physical replay.
                            let verified =
                                VerifiedSharedRecoveryObservation::from_audited_record(observation)
                                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                            replayed_recovery
                                .as_mut()
                                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                                .observe(&verified)
                                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                            observed_recovery_rows += 1;
                        }
                    }
                    _ if observation.is_some() => {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    _ => {}
                }
                replay_committee_disposition(
                    &mut replayed_committee_state,
                    self.authority,
                    &record,
                    physical,
                )?;
                previous_term = record.term;
                expected_index = expected_index.saturating_add(1);
                last_record = Some(record);
            }
            let live_recovery = read_recovery_manifest(
                &transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?,
                &key,
                self.generation,
                &self.initial_committee,
            )?;
            if replayed_recovery.as_ref().filter(|value| !value.is_empty())
                != live_recovery.as_ref()
                || observed_recovery_rows != exact_audit_row_count(&observation_table, &key)?
                || live_recovery
                    .as_ref()
                    .is_some_and(|value| value.validate_at_raft_index(meta.applied_index).is_err())
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let observed = expected_index.saturating_sub(1);
            if observed != meta.applied_index {
                return Err(AgentRaftApplicationErrorV2::MissingAuditRecord(
                    expected_index.min(meta.applied_index),
                ));
            }
            match last_record {
                Some(record)
                    if record.term == meta.applied_term
                        && record.raw_payload_commitment == meta.raw_payload_commitment
                        && Some(record.disposition) == meta.disposition => {}
                None if meta.applied_index == 0 && snapshot_claim.is_none() => {}
                None if snapshot_claim.is_some_and(|claim| {
                    let expected = snapshot
                        .as_ref()
                        .expect("snapshot claim has record")
                        .boundary_disposition();
                    meta.applied_index == claim.raft_index()
                        && meta.applied_term == claim.raft_term()
                        && meta.raw_payload_commitment == claim.boundary_payload_commitment()
                        && expected.is_ok_and(|expected| meta.disposition == Some(expected))
                }) => {}
                _ => return Err(AgentRaftApplicationErrorV2::CorruptLedger),
            }
            if replayed_committee_state != stored_committee_state {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let reservation = {
                let table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
                table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec())
            }
            .map(|bytes| {
                let record = CommandReservationRecordV2::decode(&bytes)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if record.encode() != bytes {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                Ok(record)
            })
            .transpose()?;
            let reservation_pending = reservation.is_some();
            if let Some(reservation) = reservation {
                if reservation.generation != self.generation
                    || reservation.journal_store != self.journal_store
                    || reservation.local_node != self.local_node
                    || reservation.index != meta.applied_index.saturating_add(1)
                    || (meta.applied_index != 0 && reservation.term < meta.applied_term)
                    || stored_committee_state.pending.is_some()
                    || reservation.route.committee() != stored_committee_state.active.id()
                    || stored_committee_state
                        .active
                        .member_by_node(reservation.local_node)
                        .is_none()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                verify_reservation_physical_row_in_read(&transaction, &raft, &reservation)?;
            }
            tracing::debug!(
                elapsed_us = started.elapsed().as_micros() as u64,
                rows = retained,
                "Shared recovery audit complete"
            );
            Ok(AuditedRecoveryView {
                meta,
                committee: stored_committee_state,
                raft,
                snapshot,
                recovery: live_recovery,
                ordered,
                reservation_pending,
                recovery_replay_evidence,
            })
        }

        /// Read one retained applied Ordered slot without rerunning a full
        /// recovery audit. Open/recovery validates the complete contiguous
        /// ledger; normal availability checks validate only their exact row
        /// and its committed physical preimage in one database snapshot.
        pub(crate) fn ordered_anchor(
            &self,
            index: u64,
        ) -> Result<Option<AgentRaftOrderedJournalAnchorV2>, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let key = generation_storage_key(self.generation);
            let meta_table = transaction.open_table(APPLY_META_TABLE_V2)?;
            let meta_bytes = meta_table
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let meta = AgentRaftApplyMetaV2::decode(meta_bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            validate_bound_meta(&meta, self.generation, self.journal_store)?;
            if meta.encode() != meta_bytes.value() || raft.last_applied != meta.applied_index {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            if index == 0 || index <= raft.snap_last_index || index > meta.applied_index {
                return Ok(None);
            }
            let audit_key = audit_storage_key(self.generation, index);
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            let bytes = table
                .get(audit_key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::MissingAuditRecord(index))?;
            let record = AgentRaftApplyAuditRecordV2::decode(bytes.value())
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if record.generation != self.generation
                || record.index != index
                || record.encode() != bytes.value()
            {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let AgentRaftApplyDispositionV2::Command(AgentRaftAuditDisposition::OrderedApplied {
                entry,
                claim,
                successor,
            }) = record.disposition
            else {
                return Ok(None);
            };
            let physical = verify_audited_physical_row_in_read(&transaction, &raft, &record)?;
            let command = physical
                .command
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
            let AgentRaftCommand::Ordered {
                route,
                entry: physical_entry,
                ..
            } = &command
            else {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            };
            if route.generation() != self.generation || physical_entry.id() != entry {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            Ok(Some(AgentRaftOrderedJournalAnchorV2 {
                route: *route,
                index,
                term: record.term,
                command_commitment: command.commitment(),
                entry,
                claim,
                successor,
            }))
        }

        /// Project the exact retained Ordered suffix so the host can reconcile
        /// it with the independently durable journal binding namespace. The
        /// remaining count is the hard capacity relative to the latest
        /// authenticated snapshot cursor.
        pub(crate) fn journal_audit(
            &self,
        ) -> Result<AgentRaftJournalAuditV2, AgentRaftApplicationErrorV2> {
            let _guard = self
                .writes
                .lock()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            self.audit_recovery()?;
            let key = generation_storage_key(self.generation);
            let transaction = self.database.begin_read()?;
            let raft = crate::raft::RaftMeta::load_from_read_transaction(&transaction)?;
            let meta_bytes = transaction
                .open_table(APPLY_META_TABLE_V2)?
                .get(key.as_slice())?
                .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
                .value()
                .to_vec();
            let meta = AgentRaftApplyMetaV2::decode(&meta_bytes)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            if meta.encode() != meta_bytes {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            validate_bound_meta(&meta, self.generation, self.journal_store)?;

            let mut ordered = Vec::new();
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            for row in table.range(key.as_slice()..)? {
                let (stored_key, value) = row?;
                if !stored_key.value().starts_with(key.as_slice()) {
                    break;
                }
                let record = AgentRaftApplyAuditRecordV2::decode(value.value())
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                let AgentRaftApplyDispositionV2::Command(
                    AgentRaftAuditDisposition::OrderedApplied {
                        entry,
                        claim,
                        successor,
                    },
                ) = record.disposition
                else {
                    continue;
                };
                if ordered.len() == MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
                    return Err(AgentRaftApplicationErrorV2::BacklogLimit);
                }
                let physical = verify_audited_physical_row_in_read(&transaction, &raft, &record)?;
                let command = physical
                    .command
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                let AgentRaftCommand::Ordered {
                    route,
                    entry: physical_entry,
                    ..
                } = &command
                else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if physical_entry.id() != entry {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                ordered.push(AgentRaftOrderedJournalAnchorV2 {
                    route: *route,
                    index: record.index,
                    term: record.term,
                    command_commitment: command.commitment(),
                    entry,
                    claim,
                    successor,
                });
            }

            let reservation = transaction
                .open_table(COMMAND_RESERVATION_TABLE_V2)?
                .get(key.as_slice())?
                .map(|value| value.value().to_vec())
                .map(|bytes| {
                    let record = CommandReservationRecordV2::decode(&bytes)
                        .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                    if record.encode() != bytes {
                        return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                    }
                    Ok(record)
                })
                .transpose()?;
            let pending_ordered = if let Some(reservation) = &reservation {
                let (_, _, _, raw) =
                    crate::raft::RaftLog::committed_payload_at(&self.database, reservation.index)?
                        .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                let physical = decode_agent_raft_entry_kind(&raw)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                let vos_raft::EntryKind::Data { payload } = physical else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                let command = AgentRaftCommand::decode(&payload)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                match &command {
                    AgentRaftCommand::Ordered { route, entry, .. } => {
                        Some(AgentRaftPendingOrderedV2 {
                            route: *route,
                            index: reservation.index,
                            term: reservation.term,
                            command_commitment: command.commitment(),
                            entry: entry.id(),
                            ordered_index: entry.index,
                            ordered_parent: entry.parent,
                        })
                    }
                    _ => None,
                }
            } else {
                None
            };
            Ok(AgentRaftJournalAuditV2 {
                applied_slots: meta.applied_index,
                remaining_slots: (MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64)
                    .saturating_sub(meta.applied_index.saturating_sub(raft.snap_last_index)),
                reservation_pending: reservation.is_some(),
                snapshot: read_snapshot_in_read(&transaction, key.as_slice())?.map(|record| {
                    InstalledAgentRaftSnapshotV2 {
                        claim: record.claim.clone(),
                        certificate_commitment: record.authority_commitment(),
                    }
                }),
                ordered,
                pending_ordered,
            })
        }
    }

    fn initial_retired_audit_root(
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
    ) -> Hash {
        Hash::digest(
            RETIRED_AUDIT_ROOT_DOMAIN,
            &[
                &generation.encode(),
                journal_store.as_bytes(),
                &local_node.0,
            ],
        )
    }

    fn portable_foundation_commitment(
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        certificate: Hash,
    ) -> Hash {
        Hash::digest(
            PORTABLE_FOUNDATION_DOMAIN,
            &[
                &generation.encode(),
                journal_store.as_bytes(),
                &local_node.0,
                &certificate.0,
            ],
        )
    }

    fn portable_retired_audit_root(
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        certificate: Hash,
    ) -> Hash {
        Hash::digest(
            PORTABLE_RETIRED_ROOT_DOMAIN,
            &[
                &generation.encode(),
                journal_store.as_bytes(),
                &local_node.0,
                &certificate.0,
            ],
        )
    }

    fn fold_retired_audit_root(
        previous: Hash,
        record: &AgentRaftApplyAuditRecordV2,
        physical: &[u8],
    ) -> Hash {
        Hash::digest(
            RETIRED_AUDIT_ROOT_DOMAIN,
            &[&previous.0, &record.encode(), physical],
        )
    }

    fn snapshot_committee_evidence_root(
        generation: AgentGenerationRouteKey,
        evidence: &[SnapshotCommitteeEvidenceV2],
    ) -> Hash {
        let mut root = Hash::digest(
            COMMITTEE_EVIDENCE_ROOT_DOMAIN,
            &[&generation.encode(), &(evidence.len() as u64).to_le_bytes()],
        );
        for item in evidence {
            root = Hash::digest(
                COMMITTEE_EVIDENCE_ROOT_DOMAIN,
                &[&root.0, &item.record.encode(), &item.physical],
            );
        }
        root
    }

    fn physical_bytes_for_record<T>(
        table: &T,
        record: &AgentRaftApplyAuditRecordV2,
    ) -> Result<Vec<u8>, AgentRaftApplicationErrorV2>
    where
        T: ReadableTable<u64, &'static [u8]>,
    {
        let stored = table
            .get(record.index)?
            .ok_or(AgentRaftApplicationErrorV2::MissingCommittedSlot)?;
        let (term, physical) = stored
            .value()
            .split_at_checked(8)
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
        let term = u64::from_le_bytes(
            term.try_into()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
        );
        if term != record.term {
            return Err(AgentRaftApplicationErrorV2::SlotDatabaseMismatch(
                record.index,
            ));
        }
        verify_physical_bytes(
            record.index,
            record.term,
            record.raw_payload_commitment,
            record.disposition,
            stored.value(),
        )?;
        Ok(physical.to_vec())
    }

    fn replay_snapshot_committee_evidence(
        generation: AgentGenerationRouteKey,
        initial_committee: AgentReplicaCommittee,
        authority: CommitteeChangeAuthorityBinding,
        evidence: &[SnapshotCommitteeEvidenceV2],
    ) -> Result<CommitteeApplicationStateV2, AgentRaftApplicationErrorV2> {
        let mut state = CommitteeApplicationStateV2::initial(
            generation,
            initial_committee,
            authority.initial_epoch,
        );
        for item in evidence {
            item.validate()?;
            let physical = decode_agent_raft_entry_kind(&item.physical)
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            let physical = validate_physical_kind(physical, item.record.disposition)?;
            replay_committee_disposition(&mut state, authority, &item.record, physical)?;
        }
        if state.pending.is_some() {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(state)
    }

    fn replay_committee_disposition(
        state: &mut CommitteeApplicationStateV2,
        authority: CommitteeChangeAuthorityBinding,
        record: &AgentRaftApplyAuditRecordV2,
        physical: ValidatedPhysicalEntry,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let ValidatedPhysicalEntry { kind, command } = physical;
        match (record.disposition, kind) {
            (
                AgentRaftApplyDispositionV2::RecoveryExpired { certificate, .. },
                vos_raft::EntryKind::Data { .. },
            ) if state.pending.is_none() => {
                let Some(AgentRaftCommand::ExpireRecovery {
                    route,
                    certificate: proof,
                }) = command
                else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if route.generation() != state.generation
                    || route.committee() != state.active.id()
                    || proof.claim().committee() != &state.active
                    || proof.commitment() != certificate
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
            }
            (
                AgentRaftApplyDispositionV2::RecoveryRegistered { registration, .. },
                vos_raft::EntryKind::Data { .. },
            ) if state.pending.is_none() => {
                let Some(AgentRaftCommand::RegisterRecovery {
                    route,
                    registration: request,
                }) = command
                else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if route.generation() != state.generation
                    || route.committee() != state.active.id()
                    || request.commitment() != registration
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
            }
            (AgentRaftApplyDispositionV2::LeaderNoop, vos_raft::EntryKind::Data { payload })
                if payload.is_empty() && state.pending.is_none() => {}
            (
                AgentRaftApplyDispositionV2::Command(disposition),
                vos_raft::EntryKind::Data { .. },
            ) if state.pending.is_none() => {
                let command = command.ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                // validate_physical_kind already compared this owned command's
                // complete encoding with the physical payload. It has not been
                // mutated since that check; repeat only the replay-specific
                // generation, committee and disposition validation here.
                if command.route().generation() != state.generation
                    || command.route().committee() != state.active.id()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                validate_command_disposition(&command, disposition)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
            }
            (
                AgentRaftApplyDispositionV2::CommitteeChangePrepared {
                    transition,
                    previous,
                    next,
                    authority: authority_commitment,
                },
                vos_raft::EntryKind::Data { .. },
            ) => {
                if state.pending.is_some() {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let Some(AgentRaftCommand::PrepareCommitteeChange(change)) = command else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if change.generation() != state.generation
                    || change.previous() != &state.active
                    || change.transition() != transition
                    || change.previous().id() != previous
                    || change.next().id() != next
                    || change.authority_commitment() != authority_commitment
                    || state.authority_epoch == u64::MAX
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                authority
                    .verify(state.generation, state.authority_epoch, &change)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                state.pending = Some(PendingCommitteeChangeV2 {
                    change,
                    prepare_index: record.index,
                    prepare_term: record.term,
                    prepare_payload_commitment: record.raw_payload_commitment,
                    phase: PendingCommitteePhaseV2::Prepared,
                });
            }
            (
                AgentRaftApplyDispositionV2::CommitteeJointConfiguration {
                    transition,
                    previous,
                    next,
                },
                vos_raft::EntryKind::ConfigChange { joint_old, members },
            ) => {
                let pending = state
                    .pending
                    .as_mut()
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                if !matches!(pending.phase, PendingCommitteePhaseV2::Prepared)
                    || record.index != pending.prepare_index.saturating_add(1)
                    || record.term < pending.prepare_term
                    || joint_old.as_deref() != Some(pending.change.previous_voters())
                    || members != pending.change.next_voters()
                    || transition != pending.change.transition()
                    || previous != pending.change.previous().id()
                    || next != pending.change.next().id()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                pending.phase = PendingCommitteePhaseV2::Joint {
                    index: record.index,
                    term: record.term,
                    raw_payload_commitment: record.raw_payload_commitment,
                };
            }
            (
                AgentRaftApplyDispositionV2::CommitteeStableConfiguration {
                    transition,
                    committee,
                },
                vos_raft::EntryKind::ConfigChange { joint_old, members },
            ) => {
                let pending = state
                    .pending
                    .as_ref()
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                let PendingCommitteePhaseV2::Joint { index, term, .. } = pending.phase else {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                };
                if record.index != index.saturating_add(1)
                    || record.term < term
                    || joint_old.is_some()
                    || members != pending.change.next_voters()
                    || transition != pending.change.transition()
                    || committee != pending.change.next().id()
                {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                state.active = pending.change.next().clone();
                state.authority_epoch = state
                    .authority_epoch
                    .checked_add(1)
                    .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
                state.pending = None;
            }
            _ => return Err(AgentRaftApplicationErrorV2::CorruptLedger),
        }
        state
            .validate()
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)
    }

    fn validate_bound_meta(
        meta: &AgentRaftApplyMetaV2,
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        meta.validate()
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if meta.generation != generation || meta.journal_store != journal_store {
            return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
        }
        Ok(())
    }

    fn validate_command_disposition(
        command: &AgentRaftCommand,
        disposition: AgentRaftAuditDisposition,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let matches = match (command, disposition) {
            (
                AgentRaftCommand::ArtifactChunk(chunk),
                AgentRaftAuditDisposition::ArtifactChunkStored {
                    batch,
                    artifact,
                    offset,
                    chunk: chunk_commitment,
                },
            ) => {
                batch == chunk.batch()
                    && artifact == chunk.artifact().hash
                    && offset == chunk.offset()
                    && chunk_commitment == chunk.commitment()
            }
            (
                AgentRaftCommand::ArtifactAbort { batch, .. },
                AgentRaftAuditDisposition::ArtifactBatchAborted {
                    batch: applied_batch,
                },
            ) => *batch == applied_batch,
            (
                AgentRaftCommand::Ordered { entry, .. },
                AgentRaftAuditDisposition::OrderedApplied {
                    entry: applied_entry,
                    ..
                },
            ) => entry.id() == applied_entry,
            _ => false,
        };
        if !matches {
            return Err(AgentRaftApplicationErrorV2::InvalidCommandDisposition);
        }
        Ok(())
    }

    fn validate_bound_committee_state(
        state: &CommitteeApplicationStateV2,
        generation: AgentGenerationRouteKey,
        authority: CommitteeChangeAuthorityBinding,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        state
            .validate()
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        authority
            .validate()
            .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)?;
        if state.generation != generation || state.authority_epoch < authority.initial_epoch {
            return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
        }
        Ok(())
    }

    fn ensure_v2_config_in_read(
        transaction: &redb::ReadTransaction,
        key: &[u8],
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        initial_committee: &AgentReplicaCommittee,
        authority: CommitteeChangeAuthorityBinding,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        validate_v2_table_namespace_read(transaction)?;
        ensure_single_generation_in_read(transaction, key, false)?;
        let table = transaction.open_table(CONFIG_TABLE_V2)?;
        let bytes = table
            .get(key)?
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
            .value()
            .to_vec();
        let stored = ApplicationConfigV2::decode(&bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if stored.encode() != bytes
            || stored
                != (ApplicationConfigV2 {
                    version: APPLICATION_SCHEMA_VERSION,
                    generation,
                    journal_store,
                    local_node,
                    initial_committee: initial_committee.clone(),
                    authority,
                })
        {
            return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
        }
        Ok(())
    }

    fn ensure_v2_config_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
        generation: AgentGenerationRouteKey,
        journal_store: JournalStoreInstanceId,
        local_node: NodeId,
        initial_committee: &AgentReplicaCommittee,
        authority: CommitteeChangeAuthorityBinding,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        validate_v2_table_namespace_write(transaction, true)?;
        let key: &[u8; GENERATION_STORAGE_KEY_BYTES] = key
            .try_into()
            .map_err(|_| AgentRaftApplicationErrorV2::ConfigurationMismatch)?;
        ensure_single_generation_in_write(transaction, key, false)?;
        let table = transaction.open_table(CONFIG_TABLE_V2)?;
        let bytes = table
            .get(key.as_slice())?
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?
            .value()
            .to_vec();
        let stored = ApplicationConfigV2::decode(&bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if stored.encode() != bytes
            || stored
                != (ApplicationConfigV2 {
                    version: APPLICATION_SCHEMA_VERSION,
                    generation,
                    journal_store,
                    local_node,
                    initial_committee: initial_committee.clone(),
                    authority,
                })
        {
            return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
        }
        Ok(())
    }

    fn validate_v2_table_namespace_read(
        transaction: &redb::ReadTransaction,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let mut count = 0_usize;
        for table in transaction.list_tables()? {
            let name = table.name();
            if LEGACY_V1_TABLE_NAMES.contains(&name) {
                return Err(AgentRaftApplicationErrorV2::LegacyGeneration);
            }
            if !V2_TABLE_NAMES.contains(&name) {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            count = count.saturating_add(1);
        }
        if count != V2_TABLE_NAMES.len() || transaction.list_multimap_tables()?.next().is_some() {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(())
    }

    fn validate_v2_table_namespace_write(
        transaction: &redb::WriteTransaction,
        require_complete: bool,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let mut count = 0_usize;
        for table in transaction.list_tables()? {
            let name = table.name();
            if LEGACY_V1_TABLE_NAMES.contains(&name) {
                return Err(AgentRaftApplicationErrorV2::LegacyGeneration);
            }
            if !V2_TABLE_NAMES.contains(&name) {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            count = count.saturating_add(1);
        }
        if (require_complete && count != V2_TABLE_NAMES.len())
            || transaction.list_multimap_tables()?.next().is_some()
        {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(())
    }

    fn ensure_single_generation_in_read(
        transaction: &redb::ReadTransaction,
        expected_key: &[u8],
        allow_empty: bool,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let config_rows = {
            let table = transaction.open_table(CONFIG_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key)?
        };
        let meta_rows = {
            let table = transaction.open_table(APPLY_META_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key)?
        };
        let audit_rows = {
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            exact_audit_row_count(&table, expected_key)?
        };
        let committee_rows = {
            let table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key)?
        };
        let reservation_rows = {
            let table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key)?
        };
        let snapshot_rows = {
            let table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key)?
        };
        let recovery_rows = exact_generation_row_count(
            &transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?,
            expected_key,
        )?;
        let observation_rows = exact_audit_row_count(
            &transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?,
            expected_key,
        )?;
        if config_rows == 0 && (recovery_rows != 0 || observation_rows != 0) {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        validate_single_generation_counts(
            config_rows,
            meta_rows,
            committee_rows,
            audit_rows,
            reservation_rows,
            snapshot_rows,
            allow_empty,
        )
    }

    fn ensure_single_generation_in_write(
        transaction: &redb::WriteTransaction,
        expected_key: &[u8; GENERATION_STORAGE_KEY_BYTES],
        allow_empty: bool,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let config_rows = {
            let table = transaction.open_table(CONFIG_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key.as_slice())?
        };
        let meta_rows = {
            let table = transaction.open_table(APPLY_META_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key.as_slice())?
        };
        let audit_rows = {
            let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
            exact_audit_row_count(&table, expected_key.as_slice())?
        };
        let committee_rows = {
            let table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key.as_slice())?
        };
        let reservation_rows = {
            let table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key.as_slice())?
        };
        let snapshot_rows = {
            let table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
            exact_generation_row_count(&table, expected_key.as_slice())?
        };
        let recovery_rows = exact_generation_row_count(
            &transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?,
            expected_key.as_slice(),
        )?;
        let observation_rows = exact_audit_row_count(
            &transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?,
            expected_key.as_slice(),
        )?;
        if config_rows == 0 && (recovery_rows != 0 || observation_rows != 0) {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        validate_single_generation_counts(
            config_rows,
            meta_rows,
            committee_rows,
            audit_rows,
            reservation_rows,
            snapshot_rows,
            allow_empty,
        )
    }

    fn read_recovery_manifest<T>(
        table: &T,
        key: &[u8],
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<Option<SharedRecoveryManifest>, AgentRaftApplicationErrorV2>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let Some(stored) = table.get(key)? else {
            return Ok(None);
        };
        decode_recovery_manifest(stored.value(), generation, committee).map(Some)
    }

    fn decode_recovery_manifest(
        stored: &[u8],
        generation: AgentGenerationRouteKey,
        committee: &AgentReplicaCommittee,
    ) -> Result<SharedRecoveryManifest, AgentRaftApplicationErrorV2> {
        let manifest = SharedRecoveryManifest::decode(stored)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if manifest.encode() != stored
            || manifest.generation() != generation
            || manifest.committee() != committee
        {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(manifest)
    }

    fn recovery_input_matches(manifest: &SharedRecoveryManifest, input: &ReplayInput) -> bool {
        manifest
            .slots()
            .iter()
            .any(|slot| recovery_slot_input_matches(slot, input))
    }
    fn recovery_input_expired(manifest: &SharedRecoveryManifest, input: &ReplayInput) -> bool {
        manifest
            .slots()
            .iter()
            .any(|slot| slot.expiry().is_some() && recovery_slot_input_matches(slot, input))
    }
    fn recovery_slot_input_matches(slot: &SharedRecoverySlot, input: &ReplayInput) -> bool {
        match &input.operation {
            ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
                ..
            } => {
                work == slot.registration().work()
                    && authorization == slot.registration().authorization()
            }
            ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
                ..
            } => {
                *work
                    == crate::agent_sdk::InvocationRetirement::from_work(slot.registration().work())
                    && authorization == slot.registration().authorization()
            }
            _ => false,
        }
    }

    fn write_recovery_manifest(
        transaction: &redb::WriteTransaction,
        key: &[u8],
        manifest: Option<&SharedRecoveryManifest>,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let mut table = transaction.open_table(RECOVERY_MANIFEST_TABLE_V2)?;
        if let Some(manifest) = manifest.filter(|value| !value.is_empty()) {
            table.insert(key, manifest.encode().as_slice())?;
        } else {
            table.remove(key)?;
        }
        Ok(())
    }

    fn retire_recovery_observations(
        transaction: &redb::WriteTransaction,
        key: &[u8],
        boundary: u64,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let mut table = transaction.open_table(RECOVERY_OBSERVATION_TABLE_V2)?;
        let retired = table
            .range(key..)?
            .take_while(|row| {
                row.as_ref()
                    .map_or(true, |(stored, _)| stored.value().starts_with(key))
            })
            .map(|row| row.map(|(stored, _)| stored.value().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        for stored in retired {
            if stored.len() != AUDIT_STORAGE_KEY_BYTES {
                return Err(AgentRaftApplicationErrorV2::CorruptLedger);
            }
            let index = u64::from_be_bytes(
                stored[stored.len() - 8..]
                    .try_into()
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
            );
            if index <= boundary {
                table.remove(stored.as_slice())?;
            }
        }
        Ok(())
    }

    fn read_recovery_observation<T>(
        table: &T,
        key: &[u8],
    ) -> Result<Option<SharedRecoveryObservation>, AgentRaftApplicationErrorV2>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let Some(stored) = table.get(key)? else {
            return Ok(None);
        };
        let observation = SharedRecoveryObservation::decode(stored.value())
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if observation.encode() != stored.value() {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(observation))
    }

    fn exact_generation_row_count<T>(
        table: &T,
        expected_key: &[u8],
    ) -> Result<usize, AgentRaftApplicationErrorV2>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let mut count = 0_usize;
        for row in table.iter()? {
            let (key, _) = row?;
            count = count.saturating_add(1);
            if count > 1 || key.value() != expected_key {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
        }
        Ok(count)
    }

    fn exact_audit_row_count<T>(
        table: &T,
        expected_prefix: &[u8],
    ) -> Result<usize, AgentRaftApplicationErrorV2>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let mut count = 0_usize;
        for row in table.iter()? {
            let (key, _) = row?;
            count = count.saturating_add(1);
            if count > MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES
                || key.value().len() != AUDIT_STORAGE_KEY_BYTES
                || !key.value().starts_with(expected_prefix)
            {
                return Err(AgentRaftApplicationErrorV2::ConfigurationMismatch);
            }
        }
        Ok(count)
    }

    fn validate_single_generation_counts(
        config_rows: usize,
        meta_rows: usize,
        committee_rows: usize,
        audit_rows: usize,
        reservation_rows: usize,
        snapshot_rows: usize,
        allow_empty: bool,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        match (
            config_rows,
            meta_rows,
            committee_rows,
            audit_rows,
            reservation_rows,
            snapshot_rows,
        ) {
            (0, 0, 0, 0, 0, 0) if allow_empty => Ok(()),
            (1, 1, 1, _, 0 | 1, 0 | 1) => Ok(()),
            _ => Err(AgentRaftApplicationErrorV2::CorruptLedger),
        }
    }

    fn read_meta_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
    ) -> Result<Option<AgentRaftApplyMetaV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(APPLY_META_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let meta = AgentRaftApplyMetaV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if meta.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(meta))
    }

    fn read_committee_state_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
    ) -> Result<Option<CommitteeApplicationStateV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(COMMITTEE_STATE_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let state = CommitteeApplicationStateV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if state.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(state))
    }

    fn read_audit_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
    ) -> Result<Option<AgentRaftApplyAuditRecordV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let record = AgentRaftApplyAuditRecordV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if record.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(record))
    }

    fn read_command_reservation_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
    ) -> Result<Option<CommandReservationRecordV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(COMMAND_RESERVATION_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let record = CommandReservationRecordV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if record.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(record))
    }

    fn read_snapshot_in_write(
        transaction: &redb::WriteTransaction,
        key: &[u8],
    ) -> Result<Option<AgentRaftSnapshotRecordV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let record = AgentRaftSnapshotRecordV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if record.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(record))
    }

    fn read_snapshot_in_read(
        transaction: &redb::ReadTransaction,
        key: &[u8],
    ) -> Result<Option<AgentRaftSnapshotRecordV2>, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(SNAPSHOT_TABLE_V2)?;
        let Some(value) = table.get(key)? else {
            return Ok(None);
        };
        let bytes = value.value();
        let record = AgentRaftSnapshotRecordV2::decode(bytes)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if record.encode() != bytes {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(Some(record))
    }

    fn audit_prefix_has_row_in_write(
        transaction: &redb::WriteTransaction,
        prefix: &[u8; GENERATION_STORAGE_KEY_BYTES],
    ) -> Result<bool, AgentRaftApplicationErrorV2> {
        let table = transaction.open_table(APPLY_AUDIT_TABLE_V2)?;
        let mut rows = table.range(prefix.as_slice()..)?;
        Ok(rows
            .next()
            .transpose()?
            .is_some_and(|(key, _)| key.value().starts_with(prefix.as_slice())))
    }

    fn verify_physical_row_in_write(
        transaction: &redb::WriteTransaction,
        raft: &crate::raft::RaftMeta,
        slot: &CommittedSharedRaftSlot,
        disposition: AgentRaftApplyDispositionV2,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        if raft.commit_index < slot.index() {
            return Err(AgentRaftApplicationErrorV2::MissingCommittedSlot);
        }
        let table = transaction.open_table(crate::raft::RAFT_LOG)?;
        let bytes = table
            .get(slot.index())?
            .ok_or(AgentRaftApplicationErrorV2::MissingCommittedSlot)?;
        verify_physical_bytes(
            slot.index(),
            slot.term(),
            slot.raw_payload_commitment(),
            disposition,
            bytes.value(),
        )
        .map(|_| ())
    }

    fn verify_committed_command_physical_row_in_write(
        transaction: &redb::WriteTransaction,
        raft: &crate::raft::RaftMeta,
        slot: &CommittedSharedRaftCommand,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        verify_command_physical_row_in_write(
            transaction,
            raft,
            slot.entry().index(),
            slot.entry().term(),
            slot.raw_payload_commitment(),
            slot.entry().route(),
            slot.entry().payload_commitment(),
            Some(slot.entry().command()),
        )
    }

    fn verify_reserved_command_physical_row_in_write(
        transaction: &redb::WriteTransaction,
        raft: &crate::raft::RaftMeta,
        reserved: &ReservedAgentRaftApplication,
        raw_payload_commitment: Hash,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        verify_command_physical_row_in_write(
            transaction,
            raft,
            reserved.index(),
            reserved.term(),
            raw_payload_commitment,
            reserved.route(),
            reserved.payload_commitment(),
            Some(reserved.committed().command()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_command_physical_row_in_write(
        transaction: &redb::WriteTransaction,
        raft: &crate::raft::RaftMeta,
        index: u64,
        expected_term: u64,
        expected_raw_commitment: Hash,
        expected_route: AgentRouteKey,
        expected_command_commitment: Hash,
        expected_command: Option<&AgentRaftCommand>,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        if raft.commit_index < index {
            return Err(AgentRaftApplicationErrorV2::MissingCommittedSlot);
        }
        let table = transaction.open_table(crate::raft::RAFT_LOG)?;
        let bytes = table
            .get(index)?
            .ok_or(AgentRaftApplicationErrorV2::MissingCommittedSlot)?;
        verify_command_physical_bytes(
            index,
            expected_term,
            expected_raw_commitment,
            expected_route,
            expected_command_commitment,
            expected_command,
            bytes.value(),
        )
    }

    fn verify_reservation_physical_row_in_read(
        transaction: &redb::ReadTransaction,
        raft: &crate::raft::RaftMeta,
        reservation: &CommandReservationRecordV2,
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        if raft.commit_index < reservation.index {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        let table = transaction.open_table(crate::raft::RAFT_LOG)?;
        let bytes = table
            .get(reservation.index)?
            .ok_or(AgentRaftApplicationErrorV2::MissingCommittedSlot)?;
        verify_command_physical_bytes(
            reservation.index,
            reservation.term,
            reservation.raw_payload_commitment,
            reservation.route,
            reservation.command_commitment,
            None,
            bytes.value(),
        )?;
        let raw = bytes
            .value()
            .get(8..)
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
        let vos_raft::EntryKind::Data { payload } = decode_agent_raft_entry_kind(raw)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
        else {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        };
        let command = AgentRaftCommand::decode(&payload)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        let artifact_batch = match command {
            AgentRaftCommand::Ordered { artifact_batch, .. } => artifact_batch,
            _ => None,
        };
        if artifact_batch != reservation.artifact_batch {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_command_physical_bytes(
        index: u64,
        expected_term: u64,
        expected_raw_commitment: Hash,
        expected_route: AgentRouteKey,
        expected_command_commitment: Hash,
        expected_command: Option<&AgentRaftCommand>,
        stored: &[u8],
    ) -> Result<(), AgentRaftApplicationErrorV2> {
        let (term, raw) = stored
            .split_at_checked(8)
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
        let term = u64::from_le_bytes(
            term.try_into()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
        );
        let raw_commitment = Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[raw]);
        if term != expected_term || raw_commitment != expected_raw_commitment {
            return Err(AgentRaftApplicationErrorV2::SlotDatabaseMismatch(index));
        }
        let kind = decode_agent_raft_entry_kind(raw)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if encode_agent_raft_entry_kind(&kind)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
            != raw
        {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        let vos_raft::EntryKind::Data { payload } = kind else {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        };
        let command = AgentRaftCommand::decode(&payload)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if command.encode() != payload
            || matches!(
                command,
                AgentRaftCommand::PrepareCommitteeChange(_)
                    | AgentRaftCommand::RegisterRecovery { .. }
                    | AgentRaftCommand::ExpireRecovery { .. }
            )
            || command.route() != expected_route
            || command.commitment() != expected_command_commitment
            || expected_command.is_some_and(|expected| expected != &command)
        {
            return Err(AgentRaftApplicationErrorV2::SlotDatabaseMismatch(index));
        }
        Ok(())
    }

    /// Carries the canonical command decoded while checking physical shape.
    /// Consumers still check their own route, disposition and authority.
    /// This is per-read evidence, never a cache across storage observations.
    /// Construct only in validate_physical_kind, which proves exact payload
    /// equality. Pass the owned value directly to its consumer without mutation.
    struct ValidatedPhysicalEntry {
        kind: vos_raft::EntryKind<AgentNodeId>,
        command: Option<AgentRaftCommand>,
    }

    fn verify_audited_physical_row_in_read(
        transaction: &redb::ReadTransaction,
        raft: &crate::raft::RaftMeta,
        record: &AgentRaftApplyAuditRecordV2,
    ) -> Result<ValidatedPhysicalEntry, AgentRaftApplicationErrorV2> {
        if raft.commit_index < record.index {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        let table = transaction.open_table(crate::raft::RAFT_LOG)?;
        let bytes = table
            .get(record.index)?
            .ok_or(AgentRaftApplicationErrorV2::MissingCommittedSlot)?;
        verify_physical_bytes(
            record.index,
            record.term,
            record.raw_payload_commitment,
            record.disposition,
            bytes.value(),
        )
    }

    fn verify_physical_bytes(
        index: u64,
        expected_term: u64,
        expected_commitment: Hash,
        disposition: AgentRaftApplyDispositionV2,
        stored: &[u8],
    ) -> Result<ValidatedPhysicalEntry, AgentRaftApplicationErrorV2> {
        let (term, raw) = stored
            .split_at_checked(8)
            .ok_or(AgentRaftApplicationErrorV2::CorruptLedger)?;
        let term = u64::from_le_bytes(
            term.try_into()
                .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?,
        );
        let commitment = Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[raw]);
        if term != expected_term || commitment != expected_commitment {
            return Err(AgentRaftApplicationErrorV2::SlotDatabaseMismatch(index));
        }
        let kind = decode_agent_raft_entry_kind(raw)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
        if encode_agent_raft_entry_kind(&kind)
            .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?
            != raw
        {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        validate_physical_kind(kind, disposition)
    }

    fn validate_physical_kind(
        kind: vos_raft::EntryKind<AgentNodeId>,
        disposition: AgentRaftApplyDispositionV2,
    ) -> Result<ValidatedPhysicalEntry, AgentRaftApplicationErrorV2> {
        let command = match &kind {
            vos_raft::EntryKind::Data { payload } if !payload.is_empty() => {
                if payload.len() > MAX_AGENT_RAFT_COMMAND_BYTES {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                let command = AgentRaftCommand::decode(payload)
                    .map_err(|_| AgentRaftApplicationErrorV2::CorruptLedger)?;
                if command.encode() != *payload {
                    return Err(AgentRaftApplicationErrorV2::CorruptLedger);
                }
                Some(command)
            }
            _ => None,
        };
        let compatible = match (&kind, disposition) {
            (vos_raft::EntryKind::Data { payload }, AgentRaftApplyDispositionV2::LeaderNoop) => {
                payload.is_empty()
            }
            (vos_raft::EntryKind::Data { .. }, AgentRaftApplyDispositionV2::Command(_)) => {
                command.as_ref().is_some_and(|command| {
                    !matches!(
                        command,
                        AgentRaftCommand::PrepareCommitteeChange(_)
                            | AgentRaftCommand::RegisterRecovery { .. }
                            | AgentRaftCommand::ExpireRecovery { .. }
                    )
                })
            }
            (
                vos_raft::EntryKind::Data { .. },
                AgentRaftApplyDispositionV2::RecoveryRegistered { registration, .. },
            ) => {
                matches!(command.as_ref(), Some(AgentRaftCommand::RegisterRecovery { registration: request, .. }) if request.commitment() == registration)
            }
            (
                vos_raft::EntryKind::Data { .. },
                AgentRaftApplyDispositionV2::RecoveryExpired { certificate, .. },
            ) => {
                matches!(command.as_ref(), Some(AgentRaftCommand::ExpireRecovery { certificate: proof, .. }) if proof.commitment() == certificate)
            }
            (
                vos_raft::EntryKind::Data { .. },
                AgentRaftApplyDispositionV2::CommitteeChangePrepared {
                    transition,
                    previous,
                    next,
                    authority,
                },
            ) => command.as_ref().is_some_and(|command| {
                matches!(
                    command,
                    AgentRaftCommand::PrepareCommitteeChange(change)
                        if change.transition() == transition
                            && change.previous().id() == previous
                            && change.next().id() == next
                            && change.authority_commitment() == authority
                )
            }),
            (
                vos_raft::EntryKind::ConfigChange { joint_old, members },
                AgentRaftApplyDispositionV2::CommitteeJointConfiguration { .. },
            ) => {
                joint_old.is_some()
                    && validate_raft_configuration(joint_old.as_deref(), members).is_ok()
            }
            (
                vos_raft::EntryKind::ConfigChange { joint_old, members },
                AgentRaftApplyDispositionV2::CommitteeStableConfiguration { .. },
            ) => {
                joint_old.is_none()
                    && validate_raft_configuration(joint_old.as_deref(), members).is_ok()
            }
            _ => false,
        };
        if !compatible {
            return Err(AgentRaftApplicationErrorV2::CorruptLedger);
        }
        Ok(ValidatedPhysicalEntry { kind, command })
    }

    #[test]
    fn physical_command_reuse_preserves_fresh_byte_and_shape_validation() {
        let route = AgentRouteKey::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            AgentJournalGenesisId([3; 32]),
            AgentGenesisAdmissionId::from_bytes([4; 32]),
            AgentReplicaCommitteeId::from_bytes([5; 32]),
        )
        .unwrap();
        let batch = ArtifactBatchId::from_bytes([6; 32]);
        let command = AgentRaftCommand::ArtifactAbort { route, batch };
        let disposition =
            AgentRaftApplyDispositionV2::Command(AgentRaftAuditDisposition::ArtifactBatchAborted {
                batch,
            });
        let raw = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data {
            payload: command.encode(),
        })
        .unwrap();
        let commitment = Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[&raw]);
        let mut stored = 7u64.to_le_bytes().to_vec();
        stored.extend_from_slice(&raw);
        let verified = verify_physical_bytes(1, 7, commitment, disposition, &stored).unwrap();
        assert_eq!(verified.command.unwrap().encode(), command.encode());
        assert!(verify_physical_bytes(1, 8, commitment, disposition, &stored).is_err());
        assert!(
            verify_physical_bytes(
                1,
                7,
                commitment,
                AgentRaftApplyDispositionV2::LeaderNoop,
                &stored
            )
            .is_err()
        );
        *stored.last_mut().unwrap() ^= 1;
        assert!(verify_physical_bytes(1, 7, commitment, disposition, &stored).is_err());
        // A newly committed hash must not make malformed command bytes valid.
        let malformed = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data {
            payload: vec![0xff],
        })
        .unwrap();
        let malformed_commitment =
            Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[&malformed]);
        let mut malformed_stored = 7u64.to_le_bytes().to_vec();
        malformed_stored.extend_from_slice(&malformed);
        assert!(
            verify_physical_bytes(1, 7, malformed_commitment, disposition, &malformed_stored)
                .is_err()
        );
        // Recomputed outer commitments must not admit a noncanonical inner
        // command. Each read still performs the complete strict decode/check.
        let canonical = command.encode();
        let mut trailing = canonical.clone();
        trailing.push(0);
        for payload in [trailing, canonical[..canonical.len() - 1].to_vec()] {
            let raw = encode_agent_raft_entry_kind(&vos_raft::EntryKind::Data { payload }).unwrap();
            let commitment = Hash::digest(AGENT_RAFT_PHYSICAL_SLOT_COMMITMENT_DOMAIN, &[&raw]);
            let mut stored = 7u64.to_le_bytes().to_vec();
            stored.extend_from_slice(&raw);
            assert!(verify_physical_bytes(1, 7, commitment, disposition, &stored).is_err());
        }
    }

    #[cfg(test)]
    mod recovery_staging_tests {
        use super::super::tests::{TempDirectory, committee_authority_binding};
        use super::*;
        use crate::agent::shared_recovery::{
            SharedRecoveryRegistrationRequest, recovery_observation_for_test,
            recovery_registration_for_test,
        };
        use ed25519_dalek::{Signer as _, SigningKey};

        fn fixture(
            label: &str,
        ) -> (
            TempDirectory,
            AgentRaftApplicationLedgerV2,
            SharedRecoveryRegistration,
        ) {
            let directory = TempDirectory::new(label);
            let registration = recovery_registration_for_test(1, 7);
            let committee = crate::agent::shared_commit::common_snapshot_claim_for_test()
                .active_committee()
                .clone();
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::new(Database::create(directory.database()).unwrap()),
                registration.generation(),
                JournalStoreInstanceId::from_bytes([0xe9; 32]).unwrap(),
                registration.owner(),
                committee,
                committee_authority_binding(),
            )
            .unwrap();
            (directory, ledger, registration)
        }

        fn route(registration: &SharedRecoveryRegistration) -> AgentRouteKey {
            let scope = registration.generation();
            AgentRouteKey::new(
                scope.space(),
                scope.agent(),
                scope.genesis(),
                scope.admission(),
                registration.committee(),
            )
            .unwrap()
        }

        fn append_registration(
            ledger: &AgentRaftApplicationLedgerV2,
            registration: &SharedRecoveryRegistration,
        ) -> CommittedSharedRaftSlot {
            ledger
                .append_committed_for_test(
                    3,
                    &vos_raft::EntryKind::Data {
                        payload: AgentRaftCommand::RegisterRecovery {
                            route: route(registration),
                            registration: registration.clone(),
                        }
                        .encode(),
                    },
                )
                .unwrap();
            ledger.next_committed_slot().unwrap().unwrap()
        }

        fn reserve_observation(
            ledger: &AgentRaftApplicationLedgerV2,
            registration: &SharedRecoveryRegistration,
            acknowledge: bool,
        ) -> (
            ReservedAgentRaftApplication,
            AgentRaftAuditDisposition,
            VerifiedSharedRecoveryObservation,
        ) {
            let index = ledger.cursor().unwrap().applied_index + 1;
            let prototype = recovery_observation_for_test(registration, index, acknowledge);
            let prior_ordered = ledger.journal_audit().unwrap().ordered;
            let entry = OrderedEntry {
                genesis: registration.generation().genesis(),
                index: prior_ordered.len() as u64 + 1,
                parent: prior_ordered.last().map(|anchor| anchor.entry),
                merge_frontier: prototype.observation().claim().merge_frontier(),
                merge_seal: None,
                input: prototype.observation().input().clone(),
            };
            entry
                .validate()
                .expect("ordinary Invoke/ACK has no lifecycle seal");
            ledger
                .append_committed_for_test(
                    3,
                    &vos_raft::EntryKind::Data {
                        payload: AgentRaftCommand::Ordered {
                            route: route(registration),
                            artifact_batch: None,
                            entry: entry.clone(),
                        }
                        .encode(),
                    },
                )
                .unwrap();
            let CommittedSharedRaftSlot::Command(command) =
                ledger.next_committed_slot().unwrap().unwrap()
            else {
                panic!("expected Ordered")
            };
            let reserved = ledger.reserve_command_application(&command).unwrap();
            let previous = prototype.observation().claim();
            let claim = OrderedCommitClaim::new(
                previous.genesis(),
                previous.admission(),
                previous.committee(),
                index,
                3,
                OrderedBase {
                    index: entry.index,
                    head: Some(entry.id()),
                },
                entry.merge_frontier,
                previous.merge().clone(),
                previous.merge_invocations(),
                previous.runtime().clone(),
                previous.control().clone(),
                previous.linear().clone(),
                previous.ordered_invocations(),
                previous.artifacts(),
                OrderedBase::post_genesis(),
                None,
                previous.fence_ancestry(),
            )
            .unwrap();
            let observation = VerifiedSharedRecoveryObservation::from_validated_replay(
                index,
                3,
                &claim,
                &entry.input,
                prototype.observation().outcome(),
            )
            .unwrap();
            let disposition = AgentRaftAuditDisposition::OrderedApplied {
                entry: entry.id(),
                claim: claim.commitment(),
                successor: JournalHeadsId([0xea; 32]),
            };
            (reserved, disposition, observation)
        }

        #[derive(Debug, PartialEq, Eq)]
        struct DurableRows {
            tables: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
            log: Vec<(u64, Vec<u8>)>,
            raft: crate::raft::RaftMeta,
            vote: Option<Vec<u8>>,
        }

        fn durable_rows(ledger: &AgentRaftApplicationLedgerV2) -> DurableRows {
            let transaction = ledger.database.begin_read().unwrap();
            let tables = [
                CONFIG_TABLE_V2,
                APPLY_META_TABLE_V2,
                APPLY_AUDIT_TABLE_V2,
                COMMITTEE_STATE_TABLE_V2,
                COMMAND_RESERVATION_TABLE_V2,
                SNAPSHOT_TABLE_V2,
                RECOVERY_MANIFEST_TABLE_V2,
                RECOVERY_OBSERVATION_TABLE_V2,
            ]
            .into_iter()
            .map(|definition| {
                transaction
                    .open_table(definition)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|row| {
                        let (key, value) = row.unwrap();
                        (key.value().to_vec(), value.value().to_vec())
                    })
                    .collect()
            })
            .collect();
            let log = transaction
                .open_table(crate::raft::RAFT_LOG)
                .unwrap()
                .iter()
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.value(), value.value().to_vec())
                })
                .collect();
            let vote = transaction
                .open_table(crate::raft::RAFT_META)
                .unwrap()
                .get(META_AGENT_VOTED_FOR)
                .unwrap()
                .map(|value| value.value().to_vec());
            DurableRows {
                tables,
                log,
                raft: crate::raft::RaftMeta::load_from_read_transaction(&transaction).unwrap(),
                vote,
            }
        }

        // A staged computation carries no authority to overwrite a changed
        // predecessor, even if that change has not advanced the applied index.
        #[test]
        fn staged_recovery_rejects_changed_raw_meta_and_snapshot_atomically() {
            for observation_path in [false, true] {
                for mutation in 0..3 {
                    let (_directory, ledger, registration) = fixture("staged_recovery_cas");
                    let initial = append_registration(&ledger, &registration);
                    ledger.apply_foundation_slot(&initial).unwrap();
                    let next_registration = recovery_registration_for_test(2, 7);
                    let next = (!observation_path)
                        .then(|| append_registration(&ledger, &next_registration));
                    let observation = observation_path
                        .then(|| reserve_observation(&ledger, &registration, false));
                    let staged_registration = next
                        .as_ref()
                        .and_then(|slot| ledger.stage_recovery_registration(slot).unwrap());
                    let staged_observation =
                        observation.as_ref().and_then(|(reserved, _, observed)| {
                            ledger
                                .stage_recovery_observation(reserved, Some(observed))
                                .unwrap()
                        });
                    let key = generation_storage_key(ledger.generation);
                    let mut altered = ledger.recovery_manifest().unwrap();
                    altered
                        .apply_registration(&next_registration, 2, 3)
                        .unwrap();
                    let transaction = ledger.database.begin_write().unwrap();
                    match mutation {
                        0 => {
                            transaction
                                .open_table(RECOVERY_MANIFEST_TABLE_V2)
                                .unwrap()
                                .insert(key.as_slice(), altered.encode().as_slice())
                                .unwrap();
                        }
                        1 => {
                            let mut meta = read_meta_in_write(&transaction, &key).unwrap().unwrap();
                            meta.raw_payload_commitment = Hash([0xeb; 32]);
                            transaction
                                .open_table(APPLY_META_TABLE_V2)
                                .unwrap()
                                .insert(key.as_slice(), meta.encode().as_slice())
                                .unwrap();
                        }
                        _ => {
                            let mut raft =
                                crate::raft::RaftMeta::load_from_write_transaction(&transaction)
                                    .unwrap();
                            raft.snap_last_index = 1;
                            raft.snap_last_term = 3;
                            raft.write_in_txn(&transaction).unwrap();
                        }
                    }
                    transaction.commit().unwrap();
                    let before = durable_rows(&ledger);
                    if let Some(slot) = &next {
                        assert!(
                            ledger
                                .apply_staged_foundation_slot(slot, staged_registration, None)
                                .is_err()
                        );
                    } else {
                        let (reserved, disposition, observed) = observation.as_ref().unwrap();
                        assert!(
                            ledger
                                .complete_staged_reserved_command(
                                    reserved,
                                    *disposition,
                                    Some(observed),
                                    staged_observation,
                                    None
                                )
                                .is_err()
                        );
                    }
                    assert_eq!(
                        durable_rows(&ledger),
                        before,
                        "path={observation_path} mutation={mutation}"
                    );
                }
            }
        }

        #[test]
        fn staged_recovery_preserves_concurrent_worker_hard_state() {
            for observation_path in [false, true] {
                let (_directory, ledger, registration) = fixture("staged_recovery_worker");
                let initial = append_registration(&ledger, &registration);
                ledger.apply_foundation_slot(&initial).unwrap();
                let next = (!observation_path)
                    .then(|| append_registration(&ledger, &recovery_registration_for_test(2, 7)));
                let observation =
                    observation_path.then(|| reserve_observation(&ledger, &registration, false));
                let staged_registration = next
                    .as_ref()
                    .and_then(|slot| ledger.stage_recovery_registration(slot).unwrap());
                let staged_observation =
                    observation.as_ref().and_then(|(reserved, _, observed)| {
                        ledger
                            .stage_recovery_observation(reserved, Some(observed))
                            .unwrap()
                    });
                ledger
                    .append_committed_for_test(
                        9,
                        &vos_raft::EntryKind::Data {
                            payload: Vec::new(),
                        },
                    )
                    .unwrap();
                let transaction = ledger.database.begin_write().unwrap();
                let mut expected =
                    crate::raft::RaftMeta::load_from_write_transaction(&transaction).unwrap();
                expected.current_term = 9;
                expected.voted_for = Some(0xabcd);
                expected.write_in_txn(&transaction).unwrap();
                let vote = [0xec; 32];
                transaction
                    .open_table(crate::raft::RAFT_META)
                    .unwrap()
                    .insert(META_AGENT_VOTED_FOR, vote.as_slice())
                    .unwrap();
                transaction.commit().unwrap();
                if let Some(slot) = &next {
                    assert!(matches!(
                        ledger
                            .apply_staged_foundation_slot(slot, staged_registration, None)
                            .unwrap(),
                        AgentRaftFoundationApplyOutcomeV2::Applied(_)
                    ));
                } else {
                    let (reserved, disposition, observed) = observation.as_ref().unwrap();
                    assert!(matches!(
                        ledger
                            .complete_staged_reserved_command(
                                reserved,
                                *disposition,
                                Some(observed),
                                staged_observation,
                                None
                            )
                            .unwrap(),
                        AgentRaftCommandApplyOutcomeV2::Applied(_)
                    ));
                }
                expected.last_applied = 2;
                let after = durable_rows(&ledger);
                assert_eq!(after.raft, expected);
                assert_eq!(after.vote.as_deref(), Some(vote.as_slice()));
                ledger.audit_recovery().unwrap();
            }
        }

        #[test]
        fn staged_recovery_rejects_malformed_or_oversized_predecessor_without_writes() {
            for observation_path in [false, true] {
                for oversized in [false, true] {
                    let (_directory, ledger, registration) = fixture("staged_recovery_invalid");
                    let initial = append_registration(&ledger, &registration);
                    ledger.apply_foundation_slot(&initial).unwrap();
                    let next = (!observation_path).then(|| {
                        append_registration(&ledger, &recovery_registration_for_test(2, 7))
                    });
                    let observation = observation_path
                        .then(|| reserve_observation(&ledger, &registration, false));
                    let bytes = if oversized {
                        vec![0; MAX_SHARED_RECOVERY_MANIFEST_BYTES + 1]
                    } else {
                        b"malformed-recovery".to_vec()
                    };
                    let transaction = ledger.database.begin_write().unwrap();
                    transaction
                        .open_table(RECOVERY_MANIFEST_TABLE_V2)
                        .unwrap()
                        .insert(
                            generation_storage_key(ledger.generation).as_slice(),
                            bytes.as_slice(),
                        )
                        .unwrap();
                    transaction.commit().unwrap();
                    let before = durable_rows(&ledger);
                    if let Some(slot) = &next {
                        assert!(ledger.apply_foundation_slot(slot).is_err());
                    } else {
                        let (reserved, disposition, observed) = observation.as_ref().unwrap();
                        assert!(
                            ledger
                                .complete_reserved_command(reserved, *disposition, Some(observed))
                                .is_err()
                        );
                    }
                    assert_eq!(durable_rows(&ledger), before);
                }
            }
        }

        #[test]
        fn repeated_recovery_invokes_and_acknowledgements_keep_canonical_capsule_on_reopen() {
            let (_directory, ledger, registration) = fixture("repeated_recovery_evidence");
            let initial = append_registration(&ledger, &registration);
            ledger.apply_foundation_slot(&initial).unwrap();
            let first_invoke = reserve_observation(&ledger, &registration, false);
            ledger
                .complete_reserved_command(&first_invoke.0, first_invoke.1, Some(&first_invoke.2))
                .unwrap();
            // A negative ACK is an ordinary committed row, not custody
            // evidence. The driver must later authenticate its exact outcome.
            let negative_before = reserve_observation(&ledger, &registration, true);
            ledger
                .complete_reserved_command(&negative_before.0, negative_before.1, None)
                .unwrap();
            assert!(
                !ledger
                    .recovery_manifest()
                    .unwrap()
                    .slot(registration.owner())
                    .unwrap()
                    .is_acknowledged()
            );
            let first_ack = reserve_observation(&ledger, &registration, true);
            ledger
                .complete_reserved_command(&first_ack.0, first_ack.1, Some(&first_ack.2))
                .unwrap();
            let canonical = ledger.recovery_manifest().unwrap();

            let repeated_invoke = reserve_observation(&ledger, &registration, false);
            let original = repeated_invoke.2.observation();
            let different = VerifiedSharedRecoveryObservation::from_validated_replay(
                original.raft_index(),
                original.raft_term(),
                original.claim(),
                original.input(),
                &crate::agent_sdk::RuntimeOutcome::Completed(Err(
                    crate::agent_sdk::InvocationError::NotFound,
                )),
            )
            .unwrap();
            ledger
                .complete_reserved_command(&repeated_invoke.0, repeated_invoke.1, Some(&different))
                .unwrap();
            let repeated_ack = reserve_observation(&ledger, &registration, true);
            ledger
                .complete_reserved_command(&repeated_ack.0, repeated_ack.1, Some(&repeated_ack.2))
                .unwrap();
            let negative_after = reserve_observation(&ledger, &registration, true);
            ledger
                .complete_reserved_command(&negative_after.0, negative_after.1, None)
                .unwrap();
            assert_eq!(ledger.recovery_manifest().unwrap(), canonical);
            let evidence = ledger.recovery_replay_evidence().unwrap();
            let observations = ledger.recovery_observations().unwrap();
            let absent: Vec<_> = evidence
                .iter()
                .filter_map(|(entry, input, outcome)| outcome.is_none().then_some((*entry, *input)))
                .collect();
            assert_eq!(observations.len(), 4);
            assert!(observations.contains(first_invoke.2.observation()));
            assert!(observations.contains(first_ack.2.observation()));
            assert!(observations.contains(different.observation()));
            assert!(observations.contains(repeated_ack.2.observation()));
            assert_eq!(
                absent,
                vec![
                    (
                        negative_before
                            .2
                            .observation()
                            .claim()
                            .ordered()
                            .head
                            .unwrap(),
                        negative_before.2.observation().input_id()
                    ),
                    (
                        negative_after
                            .2
                            .observation()
                            .claim()
                            .ordered()
                            .head
                            .unwrap(),
                        negative_after.2.observation().input_id()
                    ),
                ]
            );
            assert_ne!(
                first_invoke.2.observation().claim().ordered().head,
                different.observation().claim().ordered().head
            );
            let reopened = AgentRaftApplicationLedgerV2::open(
                ledger.database.clone(),
                ledger.generation,
                ledger.journal_store,
                ledger.local_node,
                ledger.initial_committee.clone(),
                ledger.authority,
            )
            .unwrap();
            assert_eq!(reopened.recovery_manifest().unwrap(), canonical);
            assert_eq!(reopened.recovery_replay_evidence().unwrap(), evidence);
            let context = reopened
                .snapshot_context(negative_after.2.observation().claim())
                .unwrap();
            assert_eq!(context.recovery_replay_evidence, evidence);
        }

        #[test]
        fn staged_recovery_historical_duplicates_do_not_refold_replaced_owner() {
            let (_directory, ledger, registration) = fixture("staged_recovery_duplicates");
            let initial = append_registration(&ledger, &registration);
            ledger.apply_foundation_slot(&initial).unwrap();
            let invoke = reserve_observation(&ledger, &registration, false);
            ledger
                .complete_reserved_command(&invoke.0, invoke.1, Some(&invoke.2))
                .unwrap();
            let acknowledge = reserve_observation(&ledger, &registration, true);
            ledger
                .complete_reserved_command(&acknowledge.0, acknowledge.1, Some(&acknowledge.2))
                .unwrap();
            let manifest = ledger.recovery_manifest().unwrap();
            let previous = manifest.slot(registration.owner()).unwrap();
            let new = recovery_registration_for_test(1, 8);
            let request = SharedRecoveryRegistrationRequest::new(
                new.generation(),
                new.committee(),
                new.owner(),
                previous.sequence() + 1,
                Some(previous.commitment()),
                new.query().clone(),
                new.work().clone(),
                new.authorization().clone(),
            )
            .unwrap();
            let signature = SigningKey::from_bytes(&[1; 32])
                .sign(&request.signing_message().0)
                .to_bytes();
            let replacement = SharedRecoveryRegistration::new(
                request,
                ReplicaCommitSignature::new(new.owner(), signature).unwrap(),
            )
            .unwrap();
            let slot = append_registration(&ledger, &replacement);
            ledger.apply_foundation_slot(&slot).unwrap();
            assert_ne!(
                ledger
                    .recovery_manifest()
                    .unwrap()
                    .slot(registration.owner())
                    .unwrap()
                    .registration(),
                &registration
            );
            let before = durable_rows(&ledger);
            assert!(matches!(
                ledger.apply_foundation_slot(&initial).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
            ));
            for (reserved, disposition, observation) in [&invoke, &acknowledge] {
                assert!(matches!(
                    ledger
                        .complete_reserved_command(reserved, *disposition, Some(observation))
                        .unwrap(),
                    AgentRaftCommandApplyOutcomeV2::Duplicate(_)
                ));
            }
            assert_eq!(durable_rows(&ledger), before);
            ledger.audit_recovery().unwrap();
        }
    }

    /// Diagnostic only: provide a disk-backed COPY of a stopped space's Raft
    /// database. Opening redb may update its metadata even without a write txn.
    #[test]
    #[ignore = "requires VOS_AGENT_RAFT_BENCH_COPIED_DB; reports timing, not a release gate"]
    fn fixed_history_physical_decode_probe() {
        let path = std::env::var_os("VOS_AGENT_RAFT_BENCH_COPIED_DB")
            .expect("provide a copied, stopped Raft database");
        let database = Database::open(path).unwrap();
        let transaction = database.begin_read().unwrap();
        let audit = transaction.open_table(APPLY_AUDIT_TABLE_V2).unwrap();
        let log = transaction.open_table(crate::raft::RAFT_LOG).unwrap();
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        for row in audit.iter().unwrap() {
            let (_, value) = row.unwrap();
            let record = AgentRaftApplyAuditRecordV2::decode(value.value()).unwrap();
            assert_eq!(record.encode(), value.value());
            let physical = log.get(record.index).unwrap().unwrap().value().to_vec();
            bytes = bytes.checked_add(physical.len()).unwrap();
            assert!(rows.len() < MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES);
            assert!(bytes <= 256 * 1024 * 1024);
            rows.push((record, physical));
        }
        assert!(!rows.is_empty());
        // Alternate order to reduce warm-cache/order bias. Neither path
        // changes history; the additional decode models the former consumer.
        for round in 0..4 {
            for duplicate in if round % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let started = std::time::Instant::now();
                let mut commands = 0usize;
                for (record, stored) in &rows {
                    let verified = verify_physical_bytes(
                        record.index,
                        record.term,
                        record.raw_payload_commitment,
                        record.disposition,
                        stored,
                    )
                    .unwrap();
                    if let Some(command) = verified.command {
                        commands += 1;
                        let vos_raft::EntryKind::Data { payload } = verified.kind else {
                            panic!("validated command without data entry");
                        };
                        let consumed = if duplicate {
                            AgentRaftCommand::decode(&payload).unwrap()
                        } else {
                            command
                        };
                        assert_eq!(consumed.encode(), payload);
                        std::hint::black_box(consumed);
                    }
                }
                eprintln!(
                    "physical-decode round={round} duplicate={duplicate} rows={} commands={commands} bytes={bytes} elapsed_us={}",
                    rows.len(),
                    started.elapsed().as_micros()
                );
            }
        }
    }

    pub(super) fn generation_storage_key(
        generation: AgentGenerationRouteKey,
    ) -> [u8; GENERATION_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; GENERATION_STORAGE_KEY_BYTES];
        key[0..32].copy_from_slice(&generation.space.0);
        key[32..64].copy_from_slice(&generation.agent.0);
        key[64..96].copy_from_slice(generation.genesis.as_bytes());
        key[96..128].copy_from_slice(generation.admission.as_bytes());
        key
    }

    pub(super) fn audit_storage_key(
        generation: AgentGenerationRouteKey,
        index: u64,
    ) -> [u8; AUDIT_STORAGE_KEY_BYTES] {
        let mut key = [0_u8; AUDIT_STORAGE_KEY_BYTES];
        key[..GENERATION_STORAGE_KEY_BYTES].copy_from_slice(&generation_storage_key(generation));
        key[GENERATION_STORAGE_KEY_BYTES..].copy_from_slice(&index.to_be_bytes());
        key
    }

    macro_rules! backend_from_v2 {
        ($error:ty) => {
            impl From<$error> for AgentRaftApplicationErrorV2 {
                fn from(error: $error) -> Self {
                    Self::Backend(alloc::boxed::Box::new(error))
                }
            }
        };
    }

    backend_from_v2!(crate::commit::CommitError);
    backend_from_v2!(redb::DatabaseError);
    backend_from_v2!(redb::TableError);
    backend_from_v2!(redb::StorageError);
    backend_from_v2!(redb::TransactionError);
    backend_from_v2!(redb::CommitError);
}

#[cfg(all(feature = "std", feature = "storage"))]
#[allow(unused_imports)]
pub(crate) use application_ledger_v2::{
    AgentNetworkCommitteeState, AgentRaftApplicationErrorV2, AgentRaftApplicationLedgerV2,
    AgentRaftCommandApplyOutcomeV2, AgentRaftFoundationApplyOutcomeV2, AgentRaftJournalAuditV2,
    AgentRaftOrderedJournalAnchorV2, AgentRaftPendingOrderedV2, AgentRaftSnapshotContextV2,
    CommonSnapshotRestoreFoundation, InstalledAgentRaftSnapshotV2,
};

#[cfg(test)]
mod tests {
    #[cfg(feature = "storage")]
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    #[cfg(feature = "storage")]
    use core::cell::Cell;

    #[cfg(feature = "storage")]
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey;
    #[cfg(feature = "storage")]
    use redb::{Database, ReadableTable, TableDefinition};
    #[cfg(feature = "storage")]
    use vos_raft::EntryKind;

    use super::*;
    use crate::agent::authority::{
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding,
        ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth};
    use crate::agent::genesis::{AgentReplicaMember, derive_replica_raft_slot};
    use crate::agent::journal::{
        ArtifactClosureId, CheckpointId, InvocationIndexId, LaneStateId, MergeFrontierId,
        MergeSealId, ReplayInput, ReplayOperation, RuntimeBinding,
    };
    use crate::agent::shared_commit::{
        MAX_REPLICA_QUORUM_CERTIFICATE_BYTES, SharedLaneProjection, SharedSealedMergeProjection,
    };
    use crate::agent::{AgentReplica, EXECUTION_SEMANTICS_ID, MethodMode, RUNTIME_ABI_ID};
    use crate::service::{ActorId, DeploymentId, InvocationId, PrincipalId, ProducerId, ProgramId};

    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let mut peer = PEER_ID_PREFIX.to_vec();
        peer.extend_from_slice(&key.verifying_key().to_bytes());
        peer
    }

    #[cfg(feature = "storage")]
    fn raft_node(byte: u8) -> AgentNodeId {
        AgentNodeId([byte; 32])
    }

    fn member(key: &SigningKey, role: ReplicaRole) -> AgentReplicaMember {
        let peer = peer_id(key);
        let public_key = key.verifying_key().to_bytes();
        AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer),
                principal: PrincipalId::of_public_key(&public_key),
                role,
            },
            peer.clone(),
            public_key,
            (role == ReplicaRole::Voter).then(|| derive_replica_raft_slot(&peer)),
        )
        .unwrap()
    }

    fn committee(voters: &[SigningKey], observers: &[SigningKey]) -> AgentReplicaCommittee {
        let mut members = voters
            .iter()
            .map(|key| member(key, ReplicaRole::Voter))
            .chain(
                observers
                    .iter()
                    .map(|key| member(key, ReplicaRole::Observer)),
            )
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        AgentReplicaCommittee::new(
            SpaceId([0x11; 32]),
            AgentId([0x22; 32]),
            AgentProfile::Shared,
            members,
        )
        .unwrap()
    }

    fn route(committee: &AgentReplicaCommittee) -> AgentRouteKey {
        AgentRouteKey::new(
            committee.space(),
            committee.agent(),
            AgentJournalGenesisId([0x33; 32]),
            AgentGenesisAdmissionId::from_bytes([0x34; 32]),
            committee.id(),
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn runtime() -> RuntimeBinding {
        RuntimeBinding {
            space: SpaceId([0x11; 32]),
            agent: AgentId([0x22; 32]),
            deployment: DeploymentId([0x23; 32]),
            program: ProgramId([0x24; 32]),
            producer: ProducerId([0x25; 32]),
            package: BlobRef::of_bytes(b"shared runtime package"),
            runtime_abi: RUNTIME_ABI_ID,
            execution_semantics: EXECUTION_SEMANTICS_ID,
        }
    }

    #[cfg(feature = "storage")]
    fn ordered_entry(route: AgentRouteKey) -> OrderedEntry {
        OrderedEntry {
            genesis: route.genesis(),
            index: 1,
            parent: None,
            merge_frontier: MergeFrontierId([0x36; 32]),
            merge_seal: Some(MergeSealId([0x3d; 32])),
            input: ReplayInput {
                runtime: runtime(),
                operation: ReplayOperation::SealMerge,
            },
        }
    }

    #[cfg(feature = "storage")]
    fn ordinary_ordered_entry(route: AgentRouteKey, parent: OrderedEntryId) -> OrderedEntry {
        let invocation = ActorInvocation {
            invocation: InvocationId([0x61; 32]),
            actor: ActorId([0x62; 32]),
            incarnation: Hash([0x63; 32]),
            deployment: DeploymentId([0x64; 32]),
            program: ProgramId([0x65; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![0x66],
            availability: Vec::new(),
            gas: 1,
        };
        let public_key = ed25519_public_key_wire([0x67; 32]);
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: AgentAuthorityBinding {
                    agent: route.agent(),
                    actor: ActorId([0x68; 32]),
                    deployment: DeploymentId([0x69; 32]),
                    program: ProgramId([0x6a; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                    public_key,
                },
                space: route.space(),
                agent: route.agent(),
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 2,
            },
            signature: vec![0x6b; ED25519_SIGNATURE_BYTES],
        };
        OrderedEntry {
            genesis: route.genesis(),
            index: 2,
            parent: Some(parent),
            merge_frontier: MergeFrontierId([0x6c; 32]),
            merge_seal: None,
            input: ReplayInput {
                runtime: runtime(),
                operation: ReplayOperation::Invoke {
                    invocation,
                    authority,
                    observed_slot: 1,
                },
            },
        }
    }

    #[cfg(feature = "storage")]
    fn lane(byte: u8, state: &[u8]) -> SharedLaneProjection {
        SharedLaneProjection::new(LaneStateId([byte; 32]), BlobRef::of_bytes(state)).unwrap()
    }

    #[cfg(feature = "storage")]
    fn successor(byte: u8) -> JournalHeadsId {
        JournalHeadsId([byte; 32])
    }

    #[cfg(feature = "storage")]
    fn journal_store(byte: u8) -> JournalStoreInstanceId {
        JournalStoreInstanceId::from_bytes([byte; 32]).unwrap()
    }

    #[cfg(feature = "storage")]
    const COMMITTEE_AUTHORITY_EPOCH: u64 = 41;
    /// Descriptor replica generation carried by test committee requests.
    #[cfg(feature = "storage")]
    const COMMITTEE_EXPECTED_GENERATION: crate::agent_sdk::Hash =
        crate::agent_sdk::Hash([0x5e; 32]);
    /// Leader-observed logical slot of test committee preparations.
    #[cfg(feature = "storage")]
    const COMMITTEE_OBSERVED_SLOT: u64 = 1;

    #[cfg(feature = "storage")]
    pub(super) fn committee_authority_binding() -> CommitteeChangeAuthorityBinding {
        let key = key(0xe1);
        let public_key = key.verifying_key().to_bytes();
        CommitteeChangeAuthorityBinding::new(
            crate::agent_sdk::Hash([0xe2; 32]),
            crate::agent_sdk::authority::AuthorityIssuer {
                principal: crate::agent_sdk::PrincipalId([0xe3; 32]),
                actor: crate::agent_sdk::ActorId([0xe4; 32]),
                deployment: crate::agent_sdk::DeploymentId([0xe5; 32]),
                program: crate::agent_sdk::ProgramId([0xe6; 32]),
                producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
            },
            crate::agent_sdk::DeploymentId([0xe7; 32]),
            public_key,
            COMMITTEE_AUTHORITY_EPOCH,
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn open_foundation_ledger(
        database: Arc<Database>,
        generation: AgentGenerationRouteKey,
        store: JournalStoreInstanceId,
    ) -> Result<AgentRaftApplicationLedgerV2, AgentRaftApplicationErrorV2> {
        let initial = committee(&[key(1)], &[]);
        let local_node = initial.members()[0].replica().node;
        AgentRaftApplicationLedgerV2::open(
            database,
            generation,
            store,
            local_node,
            initial,
            committee_authority_binding(),
        )
    }

    #[cfg(feature = "storage")]
    fn committee_change_with(
        generation: AgentGenerationRouteKey,
        previous: &AgentReplicaCommittee,
        next: &AgentReplicaCommittee,
        signing_key: &SigningKey,
        policy: crate::agent_sdk::Hash,
        issuer_label: u8,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> PrepareCommitteeChange {
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
            AuthorityReceipt, AuthorityReceiptSelector,
        };

        let public_key = signing_key.verifying_key().to_bytes();
        let request = PrepareCommitteeChange::authority_request(
            generation,
            previous,
            next,
            COMMITTEE_EXPECTED_GENERATION,
        )
        .unwrap()
        .commitment();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy,
                issuer: AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([issuer_label; 32]),
                    actor: crate::agent_sdk::ActorId([issuer_label.wrapping_add(1); 32]),
                    deployment: crate::agent_sdk::DeploymentId([issuer_label.wrapping_add(2); 32]),
                    program: crate::agent_sdk::ProgramId([issuer_label.wrapping_add(3); 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                space: crate::agent_sdk::SpaceId(generation.space().0),
                agent: crate::agent_sdk::AgentId(generation.agent().0),
                operation: AuthorityOperationKind::ChangeReplicaSet,
                runtime_deployment,
                actor: None,
                actor_deployment: None,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0xec; 32]),
                },
                lane_roots: AuthorityLaneRoots {
                    control: Some(crate::agent_sdk::Hash([0xed; 32])),
                    ..AuthorityLaneRoots::default()
                },
                epoch,
                decision_sequence: valid_from.max(1),
                acknowledged_through: 0,
                valid_from,
                expires_at,
                request,
            },
            public_key,
            signature: [1; 64],
        };
        receipt.signature = signing_key.sign(&receipt.signing_bytes()).to_bytes();
        PrepareCommitteeChange::new(
            generation,
            previous.clone(),
            next.clone(),
            COMMITTEE_EXPECTED_GENERATION,
            COMMITTEE_OBSERVED_SLOT,
            receipt,
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn committee_change(
        generation: AgentGenerationRouteKey,
        previous: &AgentReplicaCommittee,
        next: &AgentReplicaCommittee,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> PrepareCommitteeChange {
        let binding = committee_authority_binding();
        committee_change_with(
            generation,
            previous,
            next,
            &key(0xe1),
            binding.policy,
            0xe3,
            binding.runtime_deployment,
            epoch,
            valid_from,
            expires_at,
        )
    }

    #[cfg(feature = "storage")]
    fn open_transition_ledger(
        database: Arc<Database>,
        initial: AgentReplicaCommittee,
        store: JournalStoreInstanceId,
    ) -> Result<AgentRaftApplicationLedgerV2, AgentRaftApplicationErrorV2> {
        let local_node = initial.members()[0].replica().node;
        AgentRaftApplicationLedgerV2::open(
            database,
            route(&initial).generation(),
            store,
            local_node,
            initial,
            committee_authority_binding(),
        )
    }

    #[cfg(feature = "storage")]
    fn assert_prepare_rejected_without_advance(
        label: &str,
        initial: AgentReplicaCommittee,
        change: PrepareCommitteeChange,
        store: JournalStoreInstanceId,
        expected: impl FnOnce(&AgentRaftApplicationErrorV2) -> bool,
    ) {
        let directory = TempDirectory::new(label);
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let ledger = open_transition_ledger(Arc::clone(&database), initial, store).unwrap();
        ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(change).encode(),
                },
            )
            .unwrap();
        let slot = ledger.next_committed_slot().unwrap().unwrap();
        let error = ledger.apply_foundation_slot(&slot).unwrap_err();
        assert!(expected(&error), "unexpected prepare error: {error:?}");
        assert_eq!(ledger.cursor().unwrap().applied(), (0, 0));
        assert_eq!(ledger.pending_transition().unwrap(), None);
        assert_eq!(
            crate::raft::RaftMeta::load(&database).unwrap().last_applied,
            0
        );
    }

    #[cfg(feature = "storage")]
    fn claim(
        route: AgentRouteKey,
        entry: &OrderedEntry,
        raft_index: u64,
        raft_term: u64,
        linear_state: &[u8],
    ) -> OrderedCommitClaim {
        let ordered = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        let merge = lane(0x37, b"observed merge state");
        OrderedCommitClaim::new(
            route.genesis(),
            route.admission(),
            route.committee(),
            raft_index,
            raft_term,
            ordered,
            entry.merge_frontier,
            merge.clone(),
            InvocationIndexId([0x42; 32]),
            runtime(),
            lane(0x38, b"control state"),
            lane(0x39, linear_state),
            InvocationIndexId([0x3a; 32]),
            ArtifactClosureId([0x3b; 32]),
            ordered,
            Some(
                SharedSealedMergeProjection::new(
                    entry.merge_seal.unwrap(),
                    entry.merge_frontier,
                    merge,
                    InvocationIndexId([0x40; 32]),
                )
                .unwrap(),
            ),
            Hash([0x41; 32]),
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn retained_seal_claim(
        route: AgentRouteKey,
        fence: &OrderedEntry,
        entry: &OrderedEntry,
        raft_index: u64,
        raft_term: u64,
    ) -> OrderedCommitClaim {
        let ordered = OrderedBase {
            index: entry.index,
            head: Some(entry.id()),
        };
        let sealed_lane = lane(0x70, b"sealed merge state");
        OrderedCommitClaim::new(
            route.genesis(),
            route.admission(),
            route.committee(),
            raft_index,
            raft_term,
            ordered,
            entry.merge_frontier,
            lane(0x71, b"newer observed merge state"),
            InvocationIndexId([0x72; 32]),
            runtime(),
            lane(0x73, b"control state after ordinary entry"),
            lane(0x74, b"linear state after ordinary entry"),
            InvocationIndexId([0x75; 32]),
            ArtifactClosureId([0x76; 32]),
            OrderedBase {
                index: fence.index,
                head: Some(fence.id()),
            },
            Some(
                SharedSealedMergeProjection::new(
                    fence.merge_seal.unwrap(),
                    fence.merge_frontier,
                    sealed_lane,
                    InvocationIndexId([0x77; 32]),
                )
                .unwrap(),
            ),
            Hash([0x78; 32]),
        )
        .unwrap()
    }

    struct TestWitness {
        row: Option<(u64, u64, u64, Vec<u8>)>,
    }

    impl DurableAgentRaftLogWitness for TestWitness {
        type Error = ();

        fn read_committed_payload(
            &self,
            _index: u64,
        ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error> {
            Ok(self.row.clone())
        }
    }

    #[cfg(feature = "storage")]
    struct PhysicalTestWitness {
        row: Option<(u64, u64, u64, Vec<u8>)>,
    }

    #[cfg(feature = "storage")]
    impl DurableSharedRaftLogWitness for PhysicalTestWitness {
        type Error = ();

        fn read_committed_physical_slot(
            &self,
            _index: u64,
        ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error> {
            Ok(self.row.clone())
        }
    }

    #[cfg(feature = "storage")]
    fn physical_slot(
        kind: EntryKind<AgentNodeId>,
        index: u64,
        term: u64,
    ) -> CommittedSharedRaftSlot {
        CommittedSharedRaftSlot::from_durable_log(
            &PhysicalTestWitness {
                row: Some((
                    index,
                    term,
                    index,
                    encode_agent_raft_entry_kind(&kind).unwrap(),
                )),
            },
            index,
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn append_committed_kind(
        database: &Arc<Database>,
        term: u64,
        kind: &EntryKind<AgentNodeId>,
    ) -> u64 {
        let mut log = crate::raft::RaftLog::open(Arc::clone(database)).unwrap();
        let transaction = database.begin_write().unwrap();
        let index = log
            .append_in_txn(
                &transaction,
                term,
                &encode_agent_raft_entry_kind(kind).unwrap(),
            )
            .unwrap();
        let mut meta = crate::raft::RaftMeta::load_from_write_transaction(&transaction).unwrap();
        meta.current_term = meta.current_term.max(term);
        meta.commit_index = index;
        meta.write_worker_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();
        index
    }

    #[cfg(feature = "storage")]
    fn committed(command: AgentRaftCommand, index: u64, term: u64) -> CommittedAgentRaftEntry {
        CommittedAgentRaftEntry::from_durable_log(
            &TestWitness {
                row: Some((index, term, index, command.encode())),
            },
            index,
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    fn ordered_fixture(
        committee: &AgentReplicaCommittee,
    ) -> (CommittedAgentRaftEntry, OrderedCommitClaim) {
        let route = route(committee);
        let entry = ordered_entry(route);
        let claim = claim(route, &entry, 1, 7, b"linear state");
        let committed = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry,
            },
            1,
            7,
        );
        (committed, claim)
    }

    #[test]
    fn route_manifest_chunk_and_commands_round_trip_with_hard_bounds() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        assert_eq!(AgentRouteKey::decode(&route.encode()).unwrap(), route);

        let bytes = vec![0xa5; ARTIFACT_CHUNK_DATA_BYTES + 17];
        let mut artifacts = vec![BlobRef::of_bytes(&bytes), BlobRef::of_bytes(b"second")];
        artifacts.sort_by_key(|artifact| artifact.hash);
        let target = artifacts
            .iter()
            .position(|artifact| artifact.len == bytes.len() as u64)
            .unwrap() as u32;
        let manifest = ArtifactBatchManifest::new(route, artifacts).unwrap();
        assert_eq!(
            ArtifactBatchManifest::decode(&manifest.encode()).unwrap(),
            manifest
        );
        assert_ne!(manifest.id(), ArtifactBatchId::ZERO);

        let chunk = ArtifactChunk::new(
            manifest.clone(),
            target,
            0,
            bytes[..ARTIFACT_CHUNK_DATA_BYTES].to_vec(),
        )
        .unwrap();
        assert_eq!(ArtifactChunk::decode(&chunk.encode()).unwrap(), chunk);
        let chunk_command = AgentRaftCommand::ArtifactChunk(chunk.clone());
        assert_eq!(
            AgentRaftCommand::decode(&chunk_command.encode()).unwrap(),
            chunk_command
        );
        let abort = AgentRaftCommand::ArtifactAbort {
            route,
            batch: manifest.id(),
        };
        assert_eq!(AgentRaftCommand::decode(&abort.encode()).unwrap(), abort);

        let mut too_many = Vec::new();
        for index in 1..=MAX_CATALOG_ARTIFACT_REFERENCES + 1 {
            let mut hash = [0_u8; 32];
            hash[..4].copy_from_slice(&index.to_be_bytes());
            too_many.push(BlobRef {
                hash: Hash(hash),
                len: 0,
            });
        }
        assert!(matches!(
            ArtifactBatchManifest::new(route, too_many),
            Err(AgentRaftWireError::LimitExceeded)
        ));
        assert!(manifest.encode().len() <= MAX_ARTIFACT_BATCH_MANIFEST_BYTES);
        assert!(chunk.encode().len() <= MAX_ARTIFACT_CHUNK_WIRE_BYTES);
        assert!(chunk_command.encode().len() <= MAX_AGENT_RAFT_COMMAND_BYTES);
    }

    #[test]
    fn stable_generation_route_excludes_committee_epoch() {
        let voters = [key(1)];
        let route = route(&committee(&voters, &[]));
        let next_epoch = AgentRouteKey::new(
            route.space(),
            route.agent(),
            route.genesis(),
            route.admission(),
            AgentReplicaCommitteeId::from_bytes([0x91; 32]),
        )
        .unwrap();

        assert_ne!(route, next_epoch);
        assert_eq!(route.generation(), next_epoch.generation());
        assert_eq!(
            AgentGenerationRouteKey::decode(&route.generation().encode()).unwrap(),
            route.generation()
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn decoded_ordered_command_preserves_child_and_enclosing_validation() {
        let route = route(&committee(&[key(1)], &[]));
        let original = AgentRaftCommand::Ordered {
            route,
            artifact_batch: None,
            entry: ordered_entry(route),
        };
        original.validate().unwrap();
        assert_eq!(
            AgentRaftCommand::decode(&original.encode()).unwrap(),
            original
        );
        for case in 0..7 {
            let mut changed = AgentRaftCommand::decode(&original.encode()).unwrap();
            let AgentRaftCommand::Ordered {
                artifact_batch,
                entry,
                ..
            } = &mut changed
            else {
                unreachable!()
            };
            match case {
                0 => entry.index = 0,
                1 => entry.parent = Some(OrderedEntryId::ZERO),
                2 => entry.merge_seal = None,
                3 => entry.input.runtime.agent = AgentId([0x77; 32]),
                4 => entry.genesis = AgentJournalGenesisId([0x78; 32]),
                5 => *artifact_batch = Some(ArtifactBatchId::ZERO),
                6 => entry.input.runtime.agent = AgentId::ZERO,
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err(), "constructed case {case}");
            assert!(
                AgentRaftCommand::decode(&changed.encode()).is_err(),
                "decoded case {case}"
            );
        }
        let canonical = original.encode();
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(AgentRaftCommand::decode(&trailing).is_err());
        assert!(AgentRaftCommand::decode(&canonical[..canonical.len() - 1]).is_err());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn committee_prepare_wire_binds_complete_committees_nodes_and_signed_evidence() {
        use crate::agent_sdk::authority::AuthorityOperationKind;

        let initial = committee(&[key(1), key(2)], &[key(9)]);
        let next = committee(&[key(2), key(3)], &[key(8)]);
        let generation = route(&initial).generation();
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );

        assert_eq!(
            PrepareCommitteeChange::decode(&change.encode()).unwrap(),
            change
        );
        let command = AgentRaftCommand::PrepareCommitteeChange(change.clone());
        assert_eq!(
            AgentRaftCommand::decode(&command.encode()).unwrap(),
            command
        );
        assert_eq!(command.route().committee(), initial.id());
        assert_eq!(
            change.previous_voters(),
            committee_voter_nodes(&initial).unwrap()
        );
        assert_eq!(change.next_voters(), committee_voter_nodes(&next).unwrap());

        let mut different_evidence = change.authority().clone();
        different_evidence.selector.evidence.commitment = crate::agent_sdk::Hash([0xee; 32]);
        different_evidence.signature = key(0xe1)
            .sign(&different_evidence.signing_bytes())
            .to_bytes();
        let different_evidence = PrepareCommitteeChange::new(
            generation,
            initial.clone(),
            next.clone(),
            COMMITTEE_EXPECTED_GENERATION,
            COMMITTEE_OBSERVED_SLOT,
            different_evidence,
        )
        .unwrap();
        assert_ne!(different_evidence.transition(), change.transition());

        let mut wrong_nodes = change.clone();
        wrong_nodes.previous_voters = wrong_nodes.next_voters.clone();
        assert_eq!(
            wrong_nodes.validate(),
            Err(AgentRaftWireError::InvalidCommitteeTransition)
        );
        assert_eq!(
            PrepareCommitteeChange::decode(&wrong_nodes.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut wrong_operation = change.authority().clone();
        wrong_operation.selector.operation = AuthorityOperationKind::CreateAgent;
        wrong_operation.signature = key(0xe1).sign(&wrong_operation.signing_bytes()).to_bytes();
        assert_eq!(
            PrepareCommitteeChange::new(
                generation,
                initial.clone(),
                next.clone(),
                COMMITTEE_EXPECTED_GENERATION,
                COMMITTEE_OBSERVED_SLOT,
                wrong_operation,
            ),
            Err(AgentRaftWireError::InvalidAuthorityEvidence)
        );

        let mut wrong_request = change.authority().clone();
        wrong_request.selector.request = crate::agent_sdk::Hash([0xef; 32]);
        wrong_request.signature = key(0xe1).sign(&wrong_request.signing_bytes()).to_bytes();
        assert_eq!(
            PrepareCommitteeChange::new(
                generation,
                initial.clone(),
                next.clone(),
                COMMITTEE_EXPECTED_GENERATION,
                COMMITTEE_OBSERVED_SLOT,
                wrong_request,
            ),
            Err(AgentRaftWireError::InvalidAuthorityEvidence)
        );

        // The signed request is exactly the SDK ChangeReplicas request a real
        // Authority approves: the canonical next roster and the replaced
        // descriptor replica generation. Neither may be substituted.
        let sdk_request = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: COMMITTEE_EXPECTED_GENERATION,
            replicas: committee_sdk_replicas(&next),
        };
        assert!(sdk_request.is_valid());
        assert_eq!(
            change.authority().selector.request,
            sdk_request.commitment()
        );
        assert_eq!(
            PrepareCommitteeChange::authority_request(
                generation,
                &initial,
                &next,
                COMMITTEE_EXPECTED_GENERATION,
            )
            .unwrap(),
            sdk_request
        );
        assert_eq!(change.expected_generation(), COMMITTEE_EXPECTED_GENERATION);
        assert_eq!(change.observed_slot(), COMMITTEE_OBSERVED_SLOT);
        assert_eq!(
            PrepareCommitteeChange::new(
                generation,
                initial.clone(),
                next.clone(),
                crate::agent_sdk::Hash([0x5f; 32]),
                COMMITTEE_OBSERVED_SLOT,
                change.authority().clone(),
            ),
            Err(AgentRaftWireError::InvalidAuthorityEvidence),
            "a different replaced generation is a different signed request"
        );
        assert_eq!(
            PrepareCommitteeChange::new(
                generation,
                initial.clone(),
                committee(&[key(2), key(4)], &[key(8)]),
                COMMITTEE_EXPECTED_GENERATION,
                COMMITTEE_OBSERVED_SLOT,
                change.authority().clone(),
            ),
            Err(AgentRaftWireError::InvalidAuthorityEvidence),
            "a different next roster is a different signed request"
        );
        assert_eq!(
            PrepareCommitteeChange::new(
                generation,
                initial.clone(),
                next.clone(),
                crate::agent_sdk::Hash::ZERO,
                COMMITTEE_OBSERVED_SLOT,
                change.authority().clone(),
            ),
            Err(AgentRaftWireError::InvalidCommitteeTransition),
            "a zero replaced generation is not a canonical SDK request"
        );
        // The observed slot is covered by the exact wire bytes.
        let mut moved = change.clone();
        moved.observed_slot += 1;
        assert_ne!(moved.encode(), change.encode());
        assert_eq!(
            PrepareCommitteeChange::decode(&moved.encode()).unwrap(),
            moved
        );

        for (wrong_space, wrong_agent) in [
            (
                crate::agent_sdk::SpaceId([0xfa; 32]),
                crate::agent_sdk::AgentId(generation.agent().0),
            ),
            (
                crate::agent_sdk::SpaceId(generation.space().0),
                crate::agent_sdk::AgentId([0xfb; 32]),
            ),
        ] {
            let mut wrong_scope = change.authority().clone();
            wrong_scope.selector.space = wrong_space;
            wrong_scope.selector.agent = wrong_agent;
            wrong_scope.signature = key(0xe1).sign(&wrong_scope.signing_bytes()).to_bytes();
            assert_eq!(
                PrepareCommitteeChange::new(
                    generation,
                    change.previous().clone(),
                    change.next().clone(),
                    COMMITTEE_EXPECTED_GENERATION,
                    COMMITTEE_OBSERVED_SLOT,
                    wrong_scope,
                ),
                Err(AgentRaftWireError::InvalidAuthorityEvidence)
            );
        }
    }

    #[cfg(feature = "storage")]
    #[test]
    fn physical_slot_decoder_covers_noop_and_exact_command_and_rejects_bad_data() {
        let noop = physical_slot(
            EntryKind::Data {
                payload: Vec::new(),
            },
            1,
            4,
        );
        assert!(matches!(noop, CommittedSharedRaftSlot::LeaderNoop(_)));
        assert_eq!(
            (noop.index(), noop.term(), noop.committed_index()),
            (1, 4, 1)
        );
        assert_ne!(noop.raw_payload_commitment(), Hash::ZERO);

        let route = route(&committee(&[key(1)], &[]));
        let command = AgentRaftCommand::ArtifactAbort {
            route,
            batch: ArtifactBatchId::from_bytes([0x51; 32]),
        };
        let slot = physical_slot(
            EntryKind::Data {
                payload: command.encode(),
            },
            2,
            4,
        );
        match slot {
            CommittedSharedRaftSlot::Command(committed) => {
                assert_eq!(committed.entry().command(), &command);
                assert_eq!(committed.entry().index(), 2);
            }
            _ => panic!("canonical nonempty Data was not decoded as a command"),
        }

        for payload in [vec![0xff], {
            let mut bytes = command.encode();
            bytes.push(0);
            bytes
        }] {
            assert!(matches!(
                CommittedSharedRaftSlot::from_durable_log(
                    &PhysicalTestWitness {
                        row: Some((
                            3,
                            4,
                            3,
                            encode_agent_raft_entry_kind(&EntryKind::Data { payload }).unwrap(),
                        )),
                    },
                    3,
                ),
                Err(CommittedSharedRaftSlotError::Invalid(_))
            ));
        }
        assert!(matches!(
            CommittedSharedRaftSlot::from_durable_log(
                &PhysicalTestWitness {
                    row: Some((3, 4, 3, vec![0xff])),
                },
                3,
            ),
            Err(CommittedSharedRaftSlotError::Invalid(
                AgentRaftWireError::InvalidPhysicalSlot
            ))
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn physical_configuration_is_bounded_sorted_unique_and_unsolicited_is_refused() {
        let config = physical_slot(
            EntryKind::ConfigChange {
                joint_old: Some(vec![raft_node(1), raft_node(3)]),
                members: vec![raft_node(2), raft_node(4)],
            },
            1,
            9,
        );
        match &config {
            CommittedSharedRaftSlot::Configuration(config) => {
                assert_eq!(
                    config.joint_old(),
                    Some([raft_node(1), raft_node(3)].as_slice())
                );
                assert_eq!(config.members(), &[raft_node(2), raft_node(4)]);
            }
            _ => panic!("configuration slot decoded as the wrong physical kind"),
        }

        let invalid = [
            EntryKind::ConfigChange {
                joint_old: None,
                members: Vec::new(),
            },
            EntryKind::ConfigChange {
                joint_old: None,
                members: vec![raft_node(2), raft_node(1)],
            },
            EntryKind::ConfigChange {
                joint_old: Some(vec![raft_node(1), raft_node(1)]),
                members: vec![raft_node(1), raft_node(2)],
            },
            EntryKind::ConfigChange {
                joint_old: None,
                members: (1..=MAX_AGENT_REPLICAS + 1)
                    .map(|index| raft_node(index as u8))
                    .collect(),
            },
        ];
        for kind in invalid {
            assert_eq!(
                encode_agent_raft_entry_kind(&kind),
                Err(AgentRaftWireError::InvalidConfiguration)
            );
        }

        let directory = TempDirectory::new("v2_config_refusal");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let ledger = open_foundation_ledger(
            Arc::clone(&database),
            route(&committee(&[key(1)], &[])).generation(),
            journal_store(0xa1),
        )
        .unwrap();
        ledger
            .append_committed_for_test(
                9,
                &EntryKind::ConfigChange {
                    joint_old: Some(vec![raft_node(1), raft_node(3)]),
                    members: vec![raft_node(2), raft_node(4)],
                },
            )
            .unwrap();
        let config = ledger.next_committed_slot().unwrap().unwrap();
        assert!(matches!(
            ledger.apply_foundation_slot(&config),
            Err(AgentRaftApplicationErrorV2::UnsolicitedConfiguration)
        ));
        assert_eq!(ledger.cursor().unwrap().applied(), (0, 0));
        assert_eq!(
            crate::raft::RaftMeta::load(&database).unwrap().last_applied,
            0
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn full_node_configuration_preserves_low_byte_collisions_and_rejects_legacy_rows() {
        let mut first = [0x11; 32];
        first[30..].copy_from_slice(&[0xa5, 0x5a]);
        let mut second = [0x22; 32];
        second[30..].copy_from_slice(&[0xa5, 0x5a]);
        let first = AgentNodeId(first);
        let second = AgentNodeId(second);
        assert_ne!(first, second);
        assert_eq!(&first.as_bytes()[30..], &second.as_bytes()[30..]);

        let mut members = vec![second, first];
        members.sort_unstable();
        let kind = EntryKind::ConfigChange {
            joint_old: Some(members.clone()),
            members: members.clone(),
        };
        let raw = encode_agent_raft_entry_kind(&kind).unwrap();
        assert_eq!(decode_agent_raft_entry_kind(&raw).unwrap(), kind);
        let slot = CommittedSharedRaftSlot::from_durable_log(
            &PhysicalTestWitness {
                row: Some((1, 9, 1, raw.clone())),
            },
            1,
        )
        .unwrap();
        let CommittedSharedRaftSlot::Configuration(configuration) = slot else {
            panic!("full-Node configuration decoded as a different physical kind")
        };
        assert_eq!(configuration.joint_old(), Some(members.as_slice()));
        assert_eq!(configuration.members(), members);

        let legacy = crate::raft::redb_storage::encode_entry_kind(
            &vos_raft::EntryKind::<u16>::ConfigChange {
                joint_old: Some(vec![0x5aa5]),
                members: vec![0x5aa5],
            },
        );
        assert_eq!(
            decode_agent_raft_entry_kind(&legacy),
            Err(AgentRaftWireError::InvalidPhysicalSlot)
        );

        let mut zero = AGENT_RAFT_PHYSICAL_MAGIC.to_vec();
        {
            let mut encoder = Encoder(&mut zero);
            encoder.u8(AGENT_RAFT_PHYSICAL_CONFIGURATION);
            encoder.bool(false);
            encode_raft_nodes(&mut encoder, &[AgentNodeId::ZERO]);
        }
        assert_eq!(
            decode_agent_raft_entry_kind(&zero),
            Err(AgentRaftWireError::InvalidConfiguration)
        );

        let mut trailing = raw;
        trailing.push(0);
        assert_eq!(
            decode_agent_raft_entry_kind(&trailing),
            Err(AgentRaftWireError::InvalidConfiguration)
        );

        let mut oversized_count = AGENT_RAFT_PHYSICAL_MAGIC.to_vec();
        {
            let mut encoder = Encoder(&mut oversized_count);
            encoder.u8(AGENT_RAFT_PHYSICAL_CONFIGURATION);
            encoder.bool(false);
            encoder.u16((MAX_AGENT_REPLICAS as u16) + 1);
        }
        assert_eq!(
            decode_agent_raft_entry_kind(&oversized_count),
            Err(AgentRaftWireError::InvalidConfiguration)
        );

        let mut oversized_slot = vec![0; MAX_AGENT_RAFT_PHYSICAL_SLOT_BYTES + 1];
        oversized_slot[..AGENT_RAFT_PHYSICAL_MAGIC.len()]
            .copy_from_slice(&AGENT_RAFT_PHYSICAL_MAGIC);
        assert_eq!(
            decode_agent_raft_entry_kind(&oversized_slot),
            Err(AgentRaftWireError::InvalidPhysicalSlot)
        );
    }

    #[test]
    fn chunk_commitment_and_durable_log_promotion_reject_tampering() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let artifact_bytes = b"canonical artifact".to_vec();
        let manifest =
            ArtifactBatchManifest::new(route, vec![BlobRef::of_bytes(&artifact_bytes)]).unwrap();
        let chunk = ArtifactChunk::new(manifest, 0, 0, artifact_bytes).unwrap();
        let mut tampered = chunk.encode();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            ArtifactChunk::decode(&tampered),
            Err(DecodeError::NonCanonical)
        );

        let command = AgentRaftCommand::ArtifactChunk(chunk);
        let encoded = command.encode();
        assert!(matches!(
            CommittedAgentRaftEntry::from_durable_log(
                &TestWitness {
                    row: Some((2, 3, 1, encoded.clone())),
                },
                2,
            ),
            Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry
            ))
        ));
        assert!(matches!(
            CommittedAgentRaftEntry::from_durable_log(
                &TestWitness {
                    row: Some((3, 3, 3, encoded)),
                },
                2,
            ),
            Err(CommittedAgentRaftEntryError::Invalid(
                AgentRaftWireError::InvalidCommittedEntry
            ))
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_application_rejects_gap_term_regression_and_command_without_advancing() {
        let generation = route(&committee(&[key(1)], &[])).generation();

        let gap_directory = TempDirectory::new("v2_gap");
        let gap_database = Arc::new(Database::create(gap_directory.database()).unwrap());
        let gap_ledger =
            open_foundation_ledger(Arc::clone(&gap_database), generation, journal_store(0xa2))
                .unwrap();
        gap_ledger
            .append_committed_for_test(
                4,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        gap_ledger
            .append_committed_for_test(
                4,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let gap_slot = CommittedSharedRaftSlot::from_durable_log(
            &RedbSharedRaftLogWitness::new(Arc::clone(&gap_database)),
            2,
        )
        .unwrap();
        assert!(matches!(
            gap_ledger.apply_foundation_slot(&gap_slot),
            Err(AgentRaftApplicationErrorV2::ApplyGap {
                expected: 1,
                actual: 2
            })
        ));
        assert_eq!(gap_ledger.cursor().unwrap().applied(), (0, 0));

        let term_directory = TempDirectory::new("v2_term_regression");
        let term_database = Arc::new(Database::create(term_directory.database()).unwrap());
        let term_ledger =
            open_foundation_ledger(Arc::clone(&term_database), generation, journal_store(0xa3))
                .unwrap();
        term_ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let first = term_ledger.next_committed_slot().unwrap().unwrap();
        term_ledger.apply_foundation_slot(&first).unwrap();
        term_ledger
            .append_committed_for_test(
                6,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let second = term_ledger.next_committed_slot().unwrap().unwrap();
        assert!(matches!(
            term_ledger.apply_foundation_slot(&second),
            Err(AgentRaftApplicationErrorV2::TermRegression {
                previous: 7,
                actual: 6
            })
        ));
        assert_eq!(term_ledger.cursor().unwrap().applied(), (1, 7));
        assert_eq!(
            crate::raft::RaftMeta::load(&term_database)
                .unwrap()
                .last_applied,
            1
        );

        let command = AgentRaftCommand::ArtifactAbort {
            route: route(&committee(&[key(1)], &[])),
            batch: ArtifactBatchId::from_bytes([0x54; 32]),
        };
        let command_directory = TempDirectory::new("v2_command_refusal");
        let command_database = Arc::new(Database::create(command_directory.database()).unwrap());
        let command_ledger = open_foundation_ledger(
            Arc::clone(&command_database),
            generation,
            journal_store(0xa4),
        )
        .unwrap();
        command_ledger
            .append_committed_for_test(
                8,
                &EntryKind::Data {
                    payload: command.encode(),
                },
            )
            .unwrap();
        let command_slot = command_ledger.next_committed_slot().unwrap().unwrap();
        assert!(matches!(
            command_ledger.apply_foundation_slot(&command_slot),
            Err(AgentRaftApplicationErrorV2::CommandExecutionRequired)
        ));
        assert_eq!(command_ledger.cursor().unwrap().applied(), (0, 0));
    }

    #[cfg(feature = "storage")]
    fn assert_capacity_matches_full_audit(ledger: &AgentRaftApplicationLedgerV2) {
        let audit = ledger.journal_audit().unwrap();
        assert_eq!(
            ledger.capacity().unwrap(),
            (
                audit.applied_slots,
                audit.remaining_slots,
                audit.reservation_pending
            )
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_ordered_anchor_lookup_requires_exact_applied_physical_row() {
        let directory = TempDirectory::new("v2_targeted_ordered_anchor");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let committee = committee(&[key(1)], &[]);
        let route = route(&committee);
        let store = journal_store(0xad);
        let ledger =
            open_foundation_ledger(Arc::clone(&database), route.generation(), store).unwrap();
        ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let noop = ledger.next_committed_slot().unwrap().unwrap();
        ledger.apply_foundation_slot(&noop).unwrap();
        assert!(ledger.ordered_anchor(0).unwrap().is_none());
        assert!(ledger.ordered_anchor(1).unwrap().is_none());
        assert!(ledger.ordered_anchor(2).unwrap().is_none());
        let entry = ordered_entry(route);
        let command = AgentRaftCommand::Ordered {
            route,
            artifact_batch: None,
            entry: entry.clone(),
        };
        ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: command.encode(),
                },
            )
            .unwrap();
        assert!(
            ledger.ordered_anchor(2).unwrap().is_none(),
            "Raft commit is not application"
        );
        let CommittedSharedRaftSlot::Command(slot) = ledger.next_committed_slot().unwrap().unwrap()
        else {
            panic!("expected Ordered command");
        };
        ledger.reserve_command_application(&slot).unwrap();
        assert!(
            ledger.ordered_anchor(2).unwrap().is_none(),
            "reservation is not publication"
        );
        let claim = claim(route, &entry, 2, 7, b"targeted-anchor-state");
        ledger
            .anchor_ordered_for_test(&slot, &claim, successor(0xae))
            .unwrap();
        let expected = ledger.journal_audit().unwrap().ordered.pop().unwrap();
        assert_eq!(ledger.ordered_anchor(2).unwrap(), Some(expected.clone()));
        assert!(ledger.ordered_anchor(3).unwrap().is_none());
        drop(ledger);
        let reopened =
            open_foundation_ledger(Arc::clone(&database), route.generation(), store).unwrap();
        assert_eq!(reopened.ordered_anchor(2).unwrap(), Some(expected));

        // A retained application row alone must never certify a changed or
        // missing physical preimage, even after a successful startup audit.
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(crate::raft::RAFT_LOG).unwrap();
            let mut bytes = table.get(2).unwrap().unwrap().value().to_vec();
            bytes[..8].copy_from_slice(&8_u64.to_le_bytes());
            table.insert(2, bytes.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        assert!(matches!(
            reopened.ordered_anchor(2),
            Err(AgentRaftApplicationErrorV2::SlotDatabaseMismatch(2))
        ));
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(crate::raft::RAFT_LOG)
            .unwrap()
            .remove(2)
            .unwrap();
        transaction.commit().unwrap();
        assert!(matches!(
            reopened.ordered_anchor(2),
            Err(AgentRaftApplicationErrorV2::MissingCommittedSlot)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_noop_apply_is_atomic_restartable_and_duplicate_exact() {
        let directory = TempDirectory::new("v2_restart_duplicate");
        let path = directory.database();
        let generation = route(&committee(&[key(1)], &[])).generation();
        let store = journal_store(0xa5);
        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = open_foundation_ledger(Arc::clone(&database), generation, store).unwrap();
            ledger
                .append_committed_for_test(
                    11,
                    &EntryKind::Data {
                        payload: Vec::new(),
                    },
                )
                .unwrap();
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let commitment = slot.raw_payload_commitment();
            match ledger.apply_foundation_slot(&slot).unwrap() {
                AgentRaftFoundationApplyOutcomeV2::Applied(meta) => {
                    assert_eq!(meta.applied(), (1, 11));
                    assert_eq!(meta.raw_payload_commitment(), commitment);
                    assert_eq!(
                        meta.disposition(),
                        Some(AgentRaftApplyDispositionV2::LeaderNoop)
                    );
                }
                _ => panic!("first no-op was not newly applied"),
            }
            match ledger.apply_foundation_slot(&slot).unwrap() {
                AgentRaftFoundationApplyOutcomeV2::Duplicate(meta) => {
                    assert_eq!(meta.applied(), (1, 11));
                }
                _ => panic!("exact retry was not classified as a duplicate"),
            }
            assert_eq!(
                crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                1
            );
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = open_foundation_ledger(Arc::clone(&database), generation, store).unwrap();
        assert_eq!(ledger.generation(), generation);
        assert_eq!(ledger.cursor().unwrap().applied(), (1, 11));
        ledger.audit_recovery().unwrap();
        assert_capacity_matches_full_audit(&ledger);
        assert!(ledger.next_committed_slot().unwrap().is_none());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_command_reservation_is_replica_bound_restartable_and_atomically_completed() {
        let directory = TempDirectory::new("v2_command_reservation_restart");
        let path = directory.database();
        let initial = committee(&[key(1)], &[key(2)]);
        let generation = route(&initial).generation();
        let store = journal_store(0xb1);
        let local_node = member(&key(1), ReplicaRole::Voter).replica().node;
        let batch = ArtifactBatchId::from_bytes([0xb2; 32]);
        let disposition = AgentRaftAuditDisposition::ArtifactBatchAborted { batch };

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            ledger
                .append_committed_for_test(
                    12,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::ArtifactAbort {
                            route: route(&initial),
                            batch,
                        }
                        .encode(),
                    },
                )
                .unwrap();
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let CommittedSharedRaftSlot::Command(command) = &slot else {
                panic!("ordinary command decoded as the wrong physical kind");
            };
            assert_eq!(ledger.local_node(), local_node);
            let first = ledger.reserve_command_application(command).unwrap();
            let retry = ledger.reserve_command_application(command).unwrap();
            assert_eq!(first.index(), 1);
            assert_eq!(retry.payload_commitment(), first.payload_commitment());
            assert_eq!(ledger.cursor().unwrap().applied(), (0, 0));
            assert_eq!(
                crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                0
            );
            ledger.audit_recovery().unwrap();
            assert_capacity_matches_full_audit(&ledger);
            assert!(ledger.capacity().unwrap().2);
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let CommittedSharedRaftSlot::Command(command) = &slot else {
                panic!("ordinary command decoded as the wrong physical kind");
            };
            let recovered = ledger.reserve_command_application(command).unwrap();
            assert_capacity_matches_full_audit(&ledger);
            match ledger
                .complete_artifact_command(&recovered, disposition)
                .unwrap()
            {
                AgentRaftCommandApplyOutcomeV2::Applied(meta) => {
                    assert_eq!(meta.applied(), (1, 12));
                    assert_eq!(
                        meta.disposition(),
                        Some(AgentRaftApplyDispositionV2::Command(disposition))
                    );
                }
                _ => panic!("recovered command was not newly applied"),
            }
            assert_capacity_matches_full_audit(&ledger);
            assert!(!ledger.capacity().unwrap().2);
            assert!(matches!(
                ledger
                    .complete_artifact_command(&recovered, disposition)
                    .unwrap(),
                AgentRaftCommandApplyOutcomeV2::Duplicate(_)
            ));
            assert_eq!(
                crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                1
            );
            ledger.audit_recovery().unwrap();
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            local_node,
            initial,
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(ledger.cursor().unwrap().applied(), (1, 12));
        assert!(ledger.next_committed_slot().unwrap().is_none());
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                database,
                generation,
                journal_store(0xb3),
                local_node,
                committee(&[key(1)], &[key(2)]),
                committee_authority_binding(),
            ),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_restart_rejects_corrupt_or_ambiguous_command_residue() {
        const RESERVATION_TABLE: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("agent_shared_raft_command_reservation_v2");

        let directory = TempDirectory::new("v2_corrupt_command_residue");
        let path = directory.database();
        let initial = committee(&[key(1)], &[]);
        let generation = route(&initial).generation();
        let store = journal_store(0xb4);
        let local_node = member(&key(1), ReplicaRole::Voter).replica().node;
        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            ledger
                .append_committed_for_test(
                    13,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::ArtifactAbort {
                            route: route(&initial),
                            batch: ArtifactBatchId::from_bytes([0xb5; 32]),
                        }
                        .encode(),
                    },
                )
                .unwrap();
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let CommittedSharedRaftSlot::Command(command) = &slot else {
                panic!("ordinary command decoded as the wrong physical kind");
            };
            ledger.reserve_command_application(command).unwrap();
        }
        {
            let database = Database::create(&path).unwrap();
            let transaction = database.begin_write().unwrap();
            {
                let mut table = transaction.open_table(RESERVATION_TABLE).unwrap();
                table
                    .insert(
                        application_ledger_v2::generation_storage_key(generation).as_slice(),
                        b"non-canonical-residue".as_slice(),
                    )
                    .unwrap();
            }
            transaction.commit().unwrap();
        }
        let database = Arc::new(Database::create(&path).unwrap());
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                database,
                generation,
                store,
                local_node,
                initial,
                committee_authority_binding(),
            ),
            Err(AgentRaftApplicationErrorV2::CorruptLedger)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_committee_change_is_authorized_joint_stable_atomic_and_restartable() {
        let directory = TempDirectory::new("v2_committee_restart");
        let path = directory.database();
        let initial = committee(&[key(1), key(2)], &[key(9)]);
        let next = committee(&[key(2), key(3)], &[key(8)]);
        let generation = route(&initial).generation();
        let store = journal_store(0xc1);
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let transition = change.transition();
        let previous_voters = change.previous_voters().to_vec();
        let next_voters = change.next_voters().to_vec();

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            ledger
                .append_committed_for_test(
                    7,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::PrepareCommitteeChange(change.clone()).encode(),
                    },
                )
                .unwrap();
            let prepare = ledger.next_committed_slot().unwrap().unwrap();
            match ledger.apply_foundation_slot(&prepare).unwrap() {
                AgentRaftFoundationApplyOutcomeV2::Applied(meta) => assert_eq!(
                    meta.disposition(),
                    Some(AgentRaftApplyDispositionV2::CommitteeChangePrepared {
                        transition,
                        previous: initial.id(),
                        next: next.id(),
                        authority: change.authority_commitment(),
                    })
                ),
                _ => panic!("prepare was not newly applied"),
            }
            assert_eq!(ledger.active_committee().unwrap(), initial);
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, false))
            );
            assert!(matches!(
                ledger.apply_foundation_slot(&prepare).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
            ));
            assert_eq!(
                crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                1
            );
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, false))
            );
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: Some(previous_voters.clone()),
                    members: next_voters.clone(),
                },
            );
            let joint = ledger.next_committed_slot().unwrap().unwrap();
            match ledger.apply_foundation_slot(&joint).unwrap() {
                AgentRaftFoundationApplyOutcomeV2::Applied(meta) => assert_eq!(
                    meta.disposition(),
                    Some(AgentRaftApplyDispositionV2::CommitteeJointConfiguration {
                        transition,
                        previous: initial.id(),
                        next: next.id(),
                    })
                ),
                _ => panic!("joint configuration was not newly applied"),
            }
            assert_eq!(ledger.active_committee().unwrap(), initial);
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, true))
            );
            assert!(matches!(
                ledger.apply_foundation_slot(&joint).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
            ));
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, true))
            );
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters,
                },
            );
            let stable = ledger.next_committed_slot().unwrap().unwrap();
            match ledger.apply_foundation_slot(&stable).unwrap() {
                AgentRaftFoundationApplyOutcomeV2::Applied(meta) => assert_eq!(
                    meta.disposition(),
                    Some(AgentRaftApplyDispositionV2::CommitteeStableConfiguration {
                        transition,
                        committee: next.id(),
                    })
                ),
                _ => panic!("stable configuration was not newly applied"),
            }
            assert_eq!(ledger.active_committee().unwrap(), next);
            assert_eq!(ledger.pending_transition().unwrap(), None);
            assert_eq!(
                ledger.authority_epoch().unwrap(),
                COMMITTEE_AUTHORITY_EPOCH + 1
            );
            assert_eq!(
                crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                3
            );
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = open_transition_ledger(Arc::clone(&database), initial, store).unwrap();
        assert_eq!(ledger.active_committee().unwrap(), next);
        ledger.audit_recovery().unwrap();
        let stable =
            CommittedSharedRaftSlot::from_durable_log(&RedbSharedRaftLogWitness::new(database), 3)
                .unwrap();
        assert!(matches!(
            ledger.apply_foundation_slot(&stable).unwrap(),
            AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
        ));
    }

    /// A node outside the initial committee binds a fresh ledger only through
    /// the explicit joiner open, applies the authenticated transition that
    /// admits it, and is then reopened by the ordinary open from its exact
    /// durable configuration row.
    #[cfg(feature = "storage")]
    #[test]
    fn v2_joiner_ledger_opens_only_explicitly_and_applies_its_admission() {
        let directory = TempDirectory::new("v2_joiner_ledger");
        let path = directory.database();
        let initial = committee(&[key(1)], &[]);
        let next = committee(&[key(1), key(2), key(3)], &[]);
        let generation = route(&initial).generation();
        let store = journal_store(0xc9);
        let joiner = member(&key(2), ReplicaRole::Voter).replica().node;
        assert!(initial.member_by_node(joiner).is_none());

        {
            let database = Arc::new(Database::create(&path).unwrap());
            assert!(matches!(
                AgentRaftApplicationLedgerV2::open(
                    Arc::clone(&database),
                    generation,
                    store,
                    joiner,
                    initial.clone(),
                    committee_authority_binding(),
                ),
                Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
            ));
            assert!(matches!(
                AgentRaftApplicationLedgerV2::open_joiner(
                    Arc::clone(&database),
                    generation,
                    store,
                    initial.members()[0].replica().node,
                    initial.clone(),
                    committee_authority_binding(),
                ),
                Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
            ));
            let ledger = AgentRaftApplicationLedgerV2::open_joiner(
                Arc::clone(&database),
                generation,
                store,
                joiner,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            assert!(ledger.is_joiner());
            let change = committee_change(
                generation,
                &initial,
                &next,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            );
            let previous_voters = change.previous_voters().to_vec();
            let next_voters = change.next_voters().to_vec();
            for kind in [
                EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(change).encode(),
                },
                EntryKind::ConfigChange {
                    joint_old: Some(previous_voters),
                    members: next_voters.clone(),
                },
                EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters,
                },
            ] {
                ledger.append_committed_for_test(7, &kind).unwrap();
                let slot = ledger.next_committed_slot().unwrap().unwrap();
                assert!(matches!(
                    ledger.apply_foundation_slot(&slot).unwrap(),
                    AgentRaftFoundationApplyOutcomeV2::Applied(_)
                ));
            }
            assert_eq!(ledger.active_committee().unwrap(), next);
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftApplicationLedgerV2::open(
            database,
            generation,
            store,
            joiner,
            initial,
            committee_authority_binding(),
        )
        .unwrap();
        ledger.audit_recovery().unwrap();
        assert!(ledger.is_joiner());
        assert_eq!(ledger.active_committee().unwrap(), next);
        assert_eq!(
            ledger.authority_epoch().unwrap(),
            COMMITTEE_AUTHORITY_EPOCH + 1
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_one_voter_to_three_voters_commits_signed_transition_and_reopens() {
        // This is the exact committee shape proposed for the fixed three-node
        // system rollout. It qualifies the Raft primitive, not joiner
        // enrollment, Authority finality, or a released operator workflow.
        let directory = TempDirectory::new("v2_system_one_to_three");
        let path = directory.database();
        let initial = committee(&[key(1)], &[]);
        let next = committee(&[key(1), key(2), key(3)], &[]);
        let generation = route(&initial).generation();
        let store = journal_store(0xc3);
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let previous_voters = change.previous_voters().to_vec();
        let next_voters = change.next_voters().to_vec();
        let transition = change.transition();

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            ledger
                .append_committed_for_test(
                    7,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::PrepareCommitteeChange(change).encode(),
                    },
                )
                .unwrap();
            let prepared = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&prepared).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            assert_eq!(ledger.active_committee().unwrap(), initial);
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, false))
            );
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, false))
            );
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: Some(previous_voters),
                    members: next_voters.clone(),
                },
            );
            let joint = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&joint).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, true))
            );
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger =
                open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
            assert_eq!(
                ledger.pending_transition().unwrap(),
                Some((transition, true))
            );
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters,
                },
            );
            let stable = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&stable).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            assert_eq!(ledger.active_committee().unwrap(), next);
            assert_eq!(ledger.pending_transition().unwrap(), None);
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = open_transition_ledger(database, initial, store).unwrap();
        ledger.audit_recovery().unwrap();
        assert_eq!(ledger.active_committee().unwrap(), next);
        assert_eq!(ledger.pending_transition().unwrap(), None);
        assert_eq!(
            ledger.authority_epoch().unwrap(),
            COMMITTEE_AUTHORITY_EPOCH + 1
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_snapshot_retains_rotation_evidence_after_audit_prefix_retirement() {
        let directory = TempDirectory::new("v2_snapshot_rotation_evidence");
        let path = directory.database();
        let voter_keys = [key(1), key(2), key(3)];
        let initial = committee(&voter_keys[..2], &[key(9)]);
        let next = committee(&voter_keys, &[key(8)]);
        let generation = route(&initial).generation();
        let store = journal_store(0xc2);
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let previous_voters = change.previous_voters().to_vec();
        let next_voters = change.next_voters().to_vec();
        let local_node = initial.members()[0].replica().node;
        assert!(next.member_by_node(local_node).is_some());
        let certificate;

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            append_committed_kind(
                &database,
                7,
                &EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(change).encode(),
                },
            );
            let prepare = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&prepare).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: Some(previous_voters),
                    members: next_voters.clone(),
                },
            );
            let joint = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&joint).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            append_committed_kind(
                &database,
                8,
                &EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters,
                },
            );
            let stable = ledger.next_committed_slot().unwrap().unwrap();
            assert!(matches!(
                ledger.apply_foundation_slot(&stable).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Applied(_)
            ));
            assert_eq!(ledger.active_committee().unwrap(), next);

            let active_route = route(&next);
            let entry = ordered_entry(active_route);
            append_committed_kind(
                &database,
                9,
                &EntryKind::Data {
                    payload: AgentRaftCommand::Ordered {
                        route: active_route,
                        artifact_batch: None,
                        entry: entry.clone(),
                    }
                    .encode(),
                },
            );
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let CommittedSharedRaftSlot::Command(command) = slot else {
                panic!("expected Ordered command slot")
            };
            let ordered = claim(active_route, &entry, 4, 9, b"post-rotation-linear");
            let ordered_successor = successor(0xd1);
            ledger
                .anchor_ordered_for_test(&command, &ordered, ordered_successor)
                .unwrap();
            let context = ledger.snapshot_context(&ordered).unwrap();
            assert_eq!(context.active_committee, next);
            assert_eq!(context.committee_evidence_len(), 3);
            let claim = SharedAgentSnapshotClaim::new(
                ordered,
                context.active_committee.clone(),
                context.authority_epoch,
                Hash(*store.as_bytes()),
                context.boundary_payload_commitment,
                context.ordered_successor,
                context.ordered_successor,
                successor(0xd2),
                CheckpointId([0xd3; 32]),
                local_node,
                LaneStateId([0xd4; 32]),
                LaneStateId([0xd5; 32]),
                LaneStateId([0xd6; 32]),
                LaneStateId([0xd7; 32]),
                InvocationIndexId([0xd8; 32]),
                InvocationIndexId([0xd9; 32]),
                InvocationIndexId([0xda; 32]),
                ArtifactClosureId([0xdb; 32]),
                context.retired_audit_root,
                context.committee_evidence_root,
                context.previous_snapshot,
            )
            .unwrap();
            let message = SharedAgentSnapshotCertificate::signing_message(
                claim.active_committee().id(),
                claim.commitment(),
            );
            let mut signatures = voter_keys
                .iter()
                .map(|key| {
                    ReplicaCommitSignature::new(
                        NodeId::of_authenticated_peer(&peer_id(key)),
                        key.sign(&message.0).to_bytes(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            signatures.sort_by_key(ReplicaCommitSignature::signer);
            certificate = SharedAgentSnapshotCertificate::new(claim, signatures).unwrap();
            ledger
                .install_snapshot(&certificate, Some(certificate.claim().ordered()))
                .unwrap();
            let audit = ledger.journal_audit().unwrap();
            assert_capacity_matches_full_audit(&ledger);
            assert!(audit.ordered.is_empty());
            assert!(
                ledger.ordered_anchor(4).unwrap().is_none(),
                "pruned rows need snapshot authority, not a raw applied index"
            );
            assert_eq!(
                audit
                    .snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.certificate_commitment),
                Some(certificate.commitment())
            );
            assert_eq!(
                crate::raft::RaftMeta::load(&database)
                    .unwrap()
                    .snap_last_index,
                4
            );
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let reopened = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            local_node,
            initial.clone(),
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(reopened.active_committee().unwrap(), next);
        assert_eq!(
            reopened
                .current_snapshot()
                .unwrap()
                .unwrap()
                .certificate_commitment,
            certificate.commitment()
        );
        let history = reopened.committee_history().unwrap();
        assert!(history.contains(&initial));
        assert!(history.contains(&next));
        reopened.audit_recovery().unwrap();

        // Candidate boundary selection reuses one freshly audited view. A
        // metadata-only successor keeps the exact installed logical boundary,
        // including when the original journal binding has been retired.
        let previous = certificate.claim().ordered();
        let mut heads = super::super::journal::JournalHeads::initial(
            generation.genesis(),
            generation.admission(),
            local_node,
            previous.merge_frontier(),
            previous.runtime().clone(),
        );
        heads.ordered_head = previous.ordered().head;
        heads.ordered_index = previous.ordered().index;
        reopened
            .append_committed_for_test(
                10,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let noop = reopened.next_committed_slot().unwrap().unwrap();
        reopened.apply_foundation_slot(&noop).unwrap();
        let context = reopened.snapshot_candidate_context(&heads, None).unwrap();
        let repeated = reopened
            .snapshot_candidate_context(&heads, Some(previous))
            .unwrap();
        assert_eq!(context.ordered, repeated.ordered);
        assert_eq!(context.retired_audit_root, repeated.retired_audit_root);
        assert_eq!(context.previous_snapshot, Some(certificate.commitment()));
        assert_eq!(context.ordered.ordered(), previous.ordered());
        assert_eq!(context.ordered.raft_index(), 5);

        // A new Ordered transition selects only its matching journal-bound
        // claim; neither an old installed projection nor changed heads suffice.
        let mut entry = ordered_entry(route(&next));
        entry.index = previous.ordered().index + 1;
        entry.parent = previous.ordered().head;
        reopened
            .append_committed_for_test(
                10,
                &EntryKind::Data {
                    payload: AgentRaftCommand::Ordered {
                        route: route(&next),
                        artifact_batch: None,
                        entry: entry.clone(),
                    }
                    .encode(),
                },
            )
            .unwrap();
        let CommittedSharedRaftSlot::Command(command) =
            reopened.next_committed_slot().unwrap().unwrap()
        else {
            panic!("expected changed Ordered boundary")
        };
        let changed = claim(route(&next), &entry, 6, 10, b"changed-boundary");
        reopened
            .anchor_ordered_for_test(&command, &changed, successor(0xdc))
            .unwrap();
        assert!(
            reopened
                .snapshot_candidate_context(&heads, Some(previous))
                .is_err()
        );
        heads.ordered_head = Some(entry.id());
        heads.ordered_index = entry.index;
        assert!(
            reopened
                .snapshot_candidate_context(&heads, Some(previous))
                .is_err()
        );
        assert_eq!(
            reopened
                .snapshot_candidate_context(&heads, Some(&changed))
                .unwrap()
                .ordered,
            changed,
        );
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(crate::raft::RAFT_LOG)
            .unwrap()
            .remove(5)
            .unwrap();
        transaction.commit().unwrap();
        assert!(
            reopened
                .snapshot_candidate_context(&heads, Some(&changed))
                .is_err(),
            "each candidate must freshly authenticate even an earlier metadata row",
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_recovery_expiry_is_quorum_bound_metadata_and_fences_execution() {
        use crate::agent::shared_recovery::{
            recovery_expiry_certificate_for_test, recovery_observation_for_test,
            recovery_registration_for_test,
        };
        let registration = recovery_registration_for_test(1, 7);
        let committee = crate::agent::shared_commit::common_snapshot_claim_for_test()
            .active_committee()
            .clone();
        let generation = registration.generation();
        let node = registration.owner();
        let directory = TempDirectory::new("v2_recovery_expiry");
        let path = directory.database();
        let store = journal_store(0xe2);
        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            node,
            committee.clone(),
            committee_authority_binding(),
        )
        .unwrap();
        let route = AgentRouteKey::new(
            generation.space(),
            generation.agent(),
            generation.genesis(),
            generation.admission(),
            committee.id(),
        )
        .unwrap();
        ledger
            .append_committed_for_test(
                3,
                &EntryKind::Data {
                    payload: AgentRaftCommand::RegisterRecovery {
                        route,
                        registration: registration.clone(),
                    }
                    .encode(),
                },
            )
            .unwrap();
        ledger
            .apply_foundation_slot(&ledger.next_committed_slot().unwrap().unwrap())
            .unwrap();
        let (index, term, ordered, manifest) = ledger.recovery_expiry_context().unwrap();
        assert_eq!((index, term, ordered), (1, 3, OrderedBase::post_genesis()));
        let certificate = recovery_expiry_certificate_for_test(
            &manifest,
            registration.request(),
            index,
            term,
            ordered,
            20,
        );
        let command = AgentRaftCommand::ExpireRecovery {
            route,
            certificate: certificate.clone(),
        };
        assert_eq!(
            AgentRaftCommand::decode(&command.encode()).unwrap(),
            command
        );
        ledger
            .append_committed_for_test(
                3,
                &EntryKind::Data {
                    payload: command.encode(),
                },
            )
            .unwrap();
        assert!(
            ledger.recovery_expiry_context().is_err(),
            "unapplied command is not a signing prefix"
        );
        let slot = ledger.next_committed_slot().unwrap().unwrap();
        let CommittedSharedRaftSlot::Command(ordinary) = &slot else {
            panic!("expiry is typed metadata")
        };
        assert!(ledger.reserve_command_application(ordinary).is_err());
        ledger.apply_foundation_slot(&slot).unwrap();
        assert!(matches!(
            ledger.apply_foundation_slot(&slot).unwrap(),
            AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
        ));
        let retained = ledger.recovery_manifest().unwrap();
        let terminal = retained.slot(node).unwrap().expiry().unwrap().clone();
        assert_eq!(retained.expiry_floor(), 20);
        assert!(!retained.slot(node).unwrap().is_acknowledged());
        let disposition = AgentRaftApplyDispositionV2::RecoveryExpired {
            certificate: certificate.commitment(),
            manifest: retained.commitment(),
        };
        assert_eq!(ledger.cursor().unwrap().disposition(), Some(disposition));
        assert_eq!(
            AgentRaftApplyDispositionV2::decode(&disposition.encode()).unwrap(),
            disposition
        );
        ledger.validate_recovery_expiry(&terminal).unwrap();
        assert!(ledger.journal_audit().unwrap().ordered.is_empty());
        assert!(ledger.recovery_replay_evidence().unwrap().is_empty());
        drop(ledger);
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            node,
            committee,
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(ledger.recovery_manifest().unwrap(), retained);
        ledger.validate_recovery_expiry(&terminal).unwrap();
        let proof = recovery_observation_for_test(&registration, 3, false);
        let entry = OrderedEntry {
            genesis: generation.genesis(),
            index: 1,
            parent: None,
            merge_frontier: proof.observation().claim().merge_frontier(),
            merge_seal: None,
            input: proof.observation().input().clone(),
        };
        entry.validate().unwrap();
        ledger
            .append_committed_for_test(
                3,
                &EntryKind::Data {
                    payload: AgentRaftCommand::Ordered {
                        route,
                        artifact_batch: None,
                        entry,
                    }
                    .encode(),
                },
            )
            .unwrap();
        let CommittedSharedRaftSlot::Command(replayed) =
            ledger.next_committed_slot().unwrap().unwrap()
        else {
            panic!("ordered")
        };
        assert!(
            ledger.reserve_command_application(&replayed).is_err(),
            "refuse before journal publication, not merely at observation"
        );
        assert_eq!(ledger.cursor().unwrap().applied(), (2, 3));
        assert_eq!(ledger.recovery_manifest().unwrap(), retained);
        assert!(!ledger.journal_audit().unwrap().reservation_pending);
        ledger.audit_recovery().unwrap();
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_recovery_expiry_rejects_wrong_or_stale_certified_prefix_atomically() {
        use crate::agent::shared_recovery::{
            recovery_expiry_certificate_for_test, recovery_registration_for_test,
        };
        for stale in [false, true] {
            let registration = recovery_registration_for_test(1, 7);
            let committee = crate::agent::shared_commit::common_snapshot_claim_for_test()
                .active_committee()
                .clone();
            let generation = registration.generation();
            let directory = TempDirectory::new("v2_expiry_wrong_prefix");
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                journal_store(0xe4),
                registration.owner(),
                committee.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            let route = AgentRouteKey::new(
                generation.space(),
                generation.agent(),
                generation.genesis(),
                generation.admission(),
                committee.id(),
            )
            .unwrap();
            ledger
                .append_committed_for_test(
                    3,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::RegisterRecovery {
                            route,
                            registration: registration.clone(),
                        }
                        .encode(),
                    },
                )
                .unwrap();
            ledger
                .apply_foundation_slot(&ledger.next_committed_slot().unwrap().unwrap())
                .unwrap();
            let manifest = ledger.recovery_manifest().unwrap();
            let ordered = if stale {
                OrderedBase::post_genesis()
            } else {
                OrderedBase {
                    index: 1,
                    head: Some(OrderedEntryId::new([0xe5; 32])),
                }
            };
            let certificate = recovery_expiry_certificate_for_test(
                &manifest,
                registration.request(),
                1,
                3,
                ordered,
                20,
            );
            if stale {
                ledger
                    .append_committed_for_test(
                        3,
                        &EntryKind::Data {
                            payload: Vec::new(),
                        },
                    )
                    .unwrap();
                ledger
                    .apply_foundation_slot(&ledger.next_committed_slot().unwrap().unwrap())
                    .unwrap();
            }
            let before = ledger.cursor().unwrap();
            ledger
                .append_committed_for_test(
                    3,
                    &EntryKind::Data {
                        payload: AgentRaftCommand::ExpireRecovery { route, certificate }.encode(),
                    },
                )
                .unwrap();
            assert!(
                ledger
                    .apply_foundation_slot(&ledger.next_committed_slot().unwrap().unwrap())
                    .is_err()
            );
            assert_eq!(ledger.cursor().unwrap(), before);
            assert_eq!(ledger.recovery_manifest().unwrap(), manifest);
            assert_eq!(ledger.authenticated_recovery_expiry_floor().unwrap(), 0);
            assert!(!ledger.journal_audit().unwrap().reservation_pending);
        }
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_recovery_expiry_floor_is_replayed_after_last_terminal_replacement() {
        use crate::agent::shared_recovery::{
            recovery_expiry_certificate_for_test, recovery_registration_for_test,
            recovery_replacement_expiring_for_test,
        };
        let registration = recovery_registration_for_test(1, 7);
        let committee = crate::agent::shared_commit::common_snapshot_claim_for_test()
            .active_committee()
            .clone();
        let generation = registration.generation();
        let directory = TempDirectory::new("v2_expiry_floor");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let store = journal_store(0xe3);
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            registration.owner(),
            committee.clone(),
            committee_authority_binding(),
        )
        .unwrap();
        let route = AgentRouteKey::new(
            generation.space(),
            generation.agent(),
            generation.genesis(),
            generation.admission(),
            committee.id(),
        )
        .unwrap();
        let apply = |command: AgentRaftCommand| {
            ledger
                .append_committed_for_test(
                    3,
                    &EntryKind::Data {
                        payload: command.encode(),
                    },
                )
                .unwrap();
            ledger
                .apply_foundation_slot(&ledger.next_committed_slot().unwrap().unwrap())
                .unwrap();
        };
        apply(AgentRaftCommand::RegisterRecovery {
            route,
            registration: registration.clone(),
        });
        let (_, _, ordered, manifest) = ledger.recovery_expiry_context().unwrap();
        let certificate = recovery_expiry_certificate_for_test(
            &manifest,
            registration.request(),
            1,
            3,
            ordered,
            22,
        );
        apply(AgentRaftCommand::ExpireRecovery { route, certificate });
        let next =
            recovery_replacement_expiring_for_test(&ledger.recovery_manifest().unwrap(), 1, 8, 30);
        apply(AgentRaftCommand::RegisterRecovery {
            route,
            registration: next,
        });
        let retained = ledger.recovery_manifest().unwrap();
        assert!(retained.slots().iter().all(|slot| slot.expiry().is_none()));
        assert_eq!(ledger.authenticated_recovery_expiry_floor().unwrap(), 22);
        const MANIFEST: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("agent_shared_raft_recovery_manifest_v2");
        let key = application_ledger_v2::generation_storage_key(generation);
        let original = retained.encode();
        for replacement in [Some(21_u64), Some(23_u64), None] {
            let mut bytes = original.clone();
            if let Some(floor) = replacement {
                let start = bytes.len() - 8;
                bytes[start..].copy_from_slice(&floor.to_le_bytes());
            } else {
                bytes.truncate(bytes.len() - 8);
                bytes[..4].copy_from_slice(b"RMF1");
            }
            SharedRecoveryManifest::decode(&bytes).unwrap();
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(MANIFEST)
                .unwrap()
                .insert(key.as_slice(), bytes.as_slice())
                .unwrap();
            transaction.commit().unwrap();
            assert!(ledger.authenticated_recovery_expiry_floor().is_err());
            assert!(
                AgentRaftApplicationLedgerV2::open(
                    Arc::clone(&database),
                    generation,
                    store,
                    registration.owner(),
                    committee.clone(),
                    committee_authority_binding()
                )
                .is_err()
            );
        }
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(MANIFEST)
            .unwrap()
            .insert(key.as_slice(), original.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        let reopened = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            registration.owner(),
            committee,
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(reopened.authenticated_recovery_expiry_floor().unwrap(), 22);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_recovery_registration_is_typed_bounded_durable_metadata() {
        use crate::agent::shared_recovery::recovery_registration_for_test;
        let registration = recovery_registration_for_test(1, 7);
        let committee = crate::agent::shared_commit::common_snapshot_claim_for_test()
            .active_committee()
            .clone();
        let generation = registration.generation();
        let local_node = registration.owner();
        let directory = TempDirectory::new("v2_recovery_registration");
        let path = directory.database();
        let store = journal_store(0xe1);
        let expected;
        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                committee.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            assert!(ledger.recovery_manifest().unwrap().is_empty());
            ledger
                .validate_recovery_registration(&registration)
                .unwrap();
            let command = AgentRaftCommand::RegisterRecovery {
                route: AgentRouteKey::new(
                    generation.space(),
                    generation.agent(),
                    generation.genesis(),
                    generation.admission(),
                    committee.id(),
                )
                .unwrap(),
                registration: registration.clone(),
            };
            assert_eq!(
                AgentRaftCommand::decode(&command.encode()).unwrap(),
                command
            );
            ledger
                .append_committed_for_test(
                    3,
                    &EntryKind::Data {
                        payload: command.encode(),
                    },
                )
                .unwrap();
            let slot = ledger.next_committed_slot().unwrap().unwrap();
            let CommittedSharedRaftSlot::Command(ordinary) = &slot else {
                panic!("registration is data metadata")
            };
            assert!(ledger.reserve_command_application(ordinary).is_err());
            ledger.apply_foundation_slot(&slot).unwrap();
            expected = ledger.recovery_manifest().unwrap();
            assert_eq!(ledger.active_committee().unwrap(), committee);
            assert_eq!(expected.slots().len(), 1);
            assert_eq!(
                expected.slot(local_node).unwrap().registration(),
                &registration
            );
            assert_eq!(
                ledger.cursor().unwrap().disposition(),
                Some(AgentRaftApplyDispositionV2::RecoveryRegistered {
                    registration: registration.commitment(),
                    manifest: expected.commitment(),
                })
            );
            assert!(matches!(
                ledger.apply_foundation_slot(&slot).unwrap(),
                AgentRaftFoundationApplyOutcomeV2::Duplicate(_)
            ));
            assert!(ledger.journal_audit().unwrap().ordered.is_empty());
            assert!(ledger.recovery_observations().unwrap().is_empty());
            // An unacknowledged owner cannot acquire an unrelated obligation.
            let divergent = recovery_registration_for_test(1, 8);
            assert!(ledger.validate_recovery_registration(&divergent).is_err());
            assert_eq!(ledger.recovery_manifest().unwrap(), expected);
            ledger.audit_recovery().unwrap();
        }
        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation,
            store,
            local_node,
            committee,
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(ledger.recovery_manifest().unwrap(), expected);
        ledger
            .validate_recovery_slot_registration(expected.slot(local_node).unwrap())
            .unwrap();
        assert_eq!(ledger.cursor().unwrap().applied(), (1, 3));
        // A valid-looking replacement live manifest cannot override its exact
        // signed physical registration history on reopen/audit.
        const MANIFEST: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("agent_shared_raft_recovery_manifest_v2");
        let transaction = database.begin_write().unwrap();
        let mut table = transaction.open_table(MANIFEST).unwrap();
        let key = table
            .iter()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .0
            .value()
            .to_vec();
        let original = table.get(key.as_slice()).unwrap().unwrap().value().to_vec();
        let mut altered = expected.clone();
        altered
            .apply_registration(&recovery_registration_for_test(2, 7), 2, 3)
            .unwrap();
        let unadmitted = altered
            .slot(recovery_registration_for_test(2, 7).owner())
            .unwrap();
        assert!(
            ledger
                .validate_recovery_slot_registration(unadmitted)
                .is_err()
        );
        let mut forged_position =
            SharedRecoveryManifest::new(generation, expected.committee().clone()).unwrap();
        forged_position
            .apply_registration(&recovery_registration_for_test(2, 7), 1, 3)
            .unwrap();
        assert!(
            ledger
                .validate_recovery_slot_registration(forged_position.slots().first().unwrap())
                .is_err()
        );
        table
            .insert(key.as_slice(), altered.encode().as_slice())
            .unwrap();
        drop(table);
        transaction.commit().unwrap();
        assert!(
            ledger
                .validate_recovery_slot_registration(unadmitted)
                .is_err()
        );
        assert!(ledger.audit_recovery().is_err());
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(MANIFEST)
            .unwrap()
            .insert(key.as_slice(), original.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        ledger.audit_recovery().unwrap();
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_common_snapshot_restore_preserves_hard_state_and_refuses_unknown_suffix() {
        assert_common_snapshot_restore(false);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_common_recovery_view_reaudits_fresh_corruption_and_preserves_exact_baseline() {
        assert_common_snapshot_restore(true);
    }

    #[cfg(feature = "storage")]
    fn assert_common_snapshot_restore(with_recovery: bool) {
        use crate::agent::shared_commit::{
            SharedAgentCommonSnapshotClaim, common_snapshot_claim_for_test,
        };
        let fixture = common_snapshot_claim_for_test();
        let initial = fixture.active_committee().clone();
        let recovery = if with_recovery {
            crate::agent::shared_recovery::completed_recovery_manifest_for_test()
        } else {
            SharedRecoveryManifest::new(route(&initial).generation(), initial.clone()).unwrap()
        };
        let mut common = SharedAgentCommonSnapshotClaim::new(
            fixture.ordered().clone(),
            initial.clone(),
            committee_authority_binding().initial_epoch,
            fixture.ancestry().clone(),
        )
        .unwrap();
        if with_recovery {
            common = common
                .with_recovery_manifest(recovery.commitment())
                .unwrap();
        }
        let message = SharedAgentCommonSnapshotCertificate::signing_message(
            initial.id(),
            common.commitment(),
        );
        let mut signatures = [key(1), key(2)]
            .iter()
            .map(|signer| {
                ReplicaCommitSignature::new(
                    NodeId::of_authenticated_peer(&peer_id(signer)),
                    signer.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        let certificate = SharedAgentCommonSnapshotCertificate::new(common, signatures).unwrap();
        let local_key = key(3);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&local_key));
        for (has_suffix, previous_term) in [(false, 12), (false, 3), (false, 2), (true, 12)] {
            let directory = TempDirectory::new(if has_suffix {
                "common_restore_suffix"
            } else {
                "common_restore_hard_state"
            });
            let database = Arc::new(Database::create(directory.database()).unwrap());
            let generation = route(&initial).generation();
            let store = journal_store(0xc1);
            let ledger = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            {
                let mut log = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap();
                let transaction = database.begin_write().unwrap();
                if has_suffix {
                    for _ in 0..=certificate.claim().ordered().raft_index() {
                        log.append_in_txn(
                            &transaction,
                            3,
                            &encode_agent_raft_entry_kind(&EntryKind::Data {
                                payload: Vec::new(),
                            })
                            .unwrap(),
                        )
                        .unwrap();
                    }
                }
                let mut meta =
                    crate::raft::RaftMeta::load_from_write_transaction(&transaction).unwrap();
                meta.current_term = previous_term;
                meta.voted_for = None;
                meta.write_in_txn(&transaction).unwrap();
                transaction
                    .open_table(crate::raft::RAFT_META)
                    .unwrap()
                    .insert(META_AGENT_VOTED_FOR, local_node.0.as_slice())
                    .unwrap();
                transaction.commit().unwrap();
            }
            let foundation = ledger.common_restore_foundation(&certificate).unwrap();
            let bind = |head: u8| {
                let ordered = certificate.claim().ordered();
                let physical = SharedAgentSnapshotClaim::new(
                    ordered.clone(),
                    initial.clone(),
                    certificate.claim().authority_epoch(),
                    foundation.journal_store,
                    foundation.boundary_payload_commitment,
                    successor(head),
                    successor(0xd2),
                    successor(head),
                    CheckpointId([head; 32]),
                    local_node,
                    LaneStateId([0xd4; 32]),
                    LaneStateId([0xd5; 32]),
                    LaneStateId([0xd6; 32]),
                    LaneStateId([0xd7; 32]),
                    ordered.ordered_invocations(),
                    ordered.merge_invocations(),
                    InvocationIndexId([0xda; 32]),
                    ordered.artifacts(),
                    foundation.retired_audit_root,
                    foundation.committee_evidence_root,
                    None,
                )
                .unwrap();
                let message = SharedAgentLocalSnapshotBinding::signing_message(
                    certificate.commitment(),
                    physical.commitment(),
                    local_node,
                );
                SharedAgentLocalSnapshotBinding::new(
                    certificate.commitment(),
                    physical,
                    ReplicaCommitSignature::new(local_node, local_key.sign(&message.0).to_bytes())
                        .unwrap(),
                )
                .unwrap()
            };
            let binding = bind(0xd1);
            let before = crate::raft::RaftMeta::load(&database).unwrap();
            let mut unsigned_pending = recovery.clone();
            unsigned_pending
                .apply_registration(
                    &crate::agent::shared_recovery::recovery_registration_for_test(2, 7),
                    4,
                    3,
                )
                .unwrap();
            assert!(matches!(
                ledger.restore_common_snapshot(&certificate, &binding, &unsigned_pending),
                Err(AgentRaftApplicationErrorV2::SnapshotCertificateInvalid)
            ));
            assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), before);
            assert!(ledger.current_snapshot().unwrap().is_none());
            let read_node_vote = || {
                database
                    .begin_read()
                    .unwrap()
                    .open_table(crate::raft::RAFT_META)
                    .unwrap()
                    .get(META_AGENT_VOTED_FOR)
                    .unwrap()
                    .map(|value| value.value().to_vec())
            };
            if !has_suffix {
                let node_config = |index: Option<u64>, joint: bool, changed: bool| {
                    let mut bytes = ACTIVE_CONFIG_MAGIC.to_vec();
                    bytes.push(u8::from(index.is_some()));
                    if let Some(index) = index {
                        bytes.extend_from_slice(&index.to_le_bytes());
                    }
                    bytes.push(u8::from(joint));
                    let mut members = (3_u16).to_le_bytes().to_vec();
                    for member in initial.members() {
                        members.extend_from_slice(&member.replica().node.0);
                    }
                    if changed {
                        *members.last_mut().unwrap() ^= 1;
                    }
                    if joint {
                        bytes.extend_from_slice(&members);
                    }
                    bytes.extend_from_slice(&members);
                    bytes
                };
                for (key, value) in [
                    (META_AGENT_ACTIVE_CONFIG, node_config(Some(1), false, false)),
                    (META_AGENT_ACTIVE_CONFIG, node_config(None, true, false)),
                    (META_AGENT_ACTIVE_CONFIG, node_config(None, false, true)),
                    (META_AGENT_ACTIVE_CONFIG, vec![0]),
                    (META_LEGACY_ACTIVE_CONFIG, vec![1]),
                    ("voted_for", 42_u16.to_le_bytes().to_vec()),
                ] {
                    let transaction = database.begin_write().unwrap();
                    transaction
                        .open_table(crate::raft::RAFT_META)
                        .unwrap()
                        .insert(key, value.as_slice())
                        .unwrap();
                    transaction.commit().unwrap();
                    assert!(matches!(
                        ledger.validate_common_restore(&certificate),
                        Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
                    ));
                    assert!(
                        ledger
                            .restore_common_snapshot(&certificate, &binding, &recovery)
                            .is_err()
                    );
                    assert!(ledger.current_snapshot().unwrap().is_none());
                    assert_eq!(read_node_vote(), Some(local_node.0.to_vec()));
                    let transaction = database.begin_write().unwrap();
                    assert_eq!(
                        transaction
                            .open_table(crate::raft::RAFT_META)
                            .unwrap()
                            .get(key)
                            .unwrap()
                            .unwrap()
                            .value(),
                        value.as_slice()
                    );
                    transaction
                        .open_table(crate::raft::RAFT_META)
                        .unwrap()
                        .remove(key)
                        .unwrap();
                    transaction.commit().unwrap();
                    assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), before);
                }
                // Both canonical initial representations are harmless: neither
                // asserts a speculative or pruned membership transition.
                for index in [None, Some(0)] {
                    let transaction = database.begin_write().unwrap();
                    transaction
                        .open_table(crate::raft::RAFT_META)
                        .unwrap()
                        .insert(
                            META_AGENT_ACTIVE_CONFIG,
                            node_config(index, false, false).as_slice(),
                        )
                        .unwrap();
                    transaction.commit().unwrap();
                    ledger.validate_common_restore(&certificate).unwrap();
                }
            }
            if has_suffix {
                let before_rows = database
                    .begin_read()
                    .unwrap()
                    .open_table(crate::raft::RAFT_LOG)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|row| {
                        let (index, bytes) = row.unwrap();
                        (index.value(), bytes.value().to_vec())
                    })
                    .collect::<Vec<_>>();
                assert!(matches!(
                    ledger.validate_common_restore(&certificate),
                    Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)
                ));
                assert!(
                    ledger
                        .restore_common_snapshot(&certificate, &binding, &recovery)
                        .is_err()
                );
                assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), before);
                assert_eq!(read_node_vote(), Some(local_node.0.to_vec()));
                assert!(ledger.current_snapshot().unwrap().is_none());
                let after_rows = database
                    .begin_read()
                    .unwrap()
                    .open_table(crate::raft::RAFT_LOG)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .map(|row| {
                        let (index, bytes) = row.unwrap();
                        (index.value(), bytes.value().to_vec())
                    })
                    .collect::<Vec<_>>();
                assert_eq!(before_rows, after_rows);
                continue;
            }
            ledger.validate_common_restore(&certificate).unwrap();
            let installed = ledger
                .restore_common_snapshot(&certificate, &binding, &recovery)
                .unwrap();
            let after = crate::raft::RaftMeta::load(&database).unwrap();
            assert_eq!(
                (after.current_term, after.voted_for),
                (previous_term.max(3), None)
            );
            assert_eq!(
                read_node_vote(),
                (previous_term >= 3).then(|| local_node.0.to_vec())
            );
            assert_eq!(
                after.last_applied,
                certificate.claim().ordered().raft_index()
            );
            assert_eq!(
                ledger
                    .restore_common_snapshot(&certificate, &binding, &recovery)
                    .unwrap(),
                installed
            );
            // Same common QC is not authority for a second physical jump.
            assert!(ledger.validate_common_restore(&certificate).is_err());
            ledger
                .validate_bound_common_restore(&certificate, &binding)
                .unwrap();
            assert!(
                ledger
                    .validate_bound_common_restore(&certificate, &bind(0xd9))
                    .is_err()
            );
            // Equality with an installed certificate is not permission to
            // discard even a locally uncommitted later log entry.
            let mut log = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap();
            let transaction = database.begin_write().unwrap();
            let uncommitted = log
                .append_in_txn(
                    &transaction,
                    after.current_term,
                    &encode_agent_raft_entry_kind(&EntryKind::Data {
                        payload: Vec::new(),
                    })
                    .unwrap(),
                )
                .unwrap();
            transaction.commit().unwrap();
            assert!(matches!(
                ledger.validate_bound_common_restore(&certificate, &binding),
                Err(AgentRaftApplicationErrorV2::SnapshotBoundaryRequired)
            ));
            assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), after);
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(crate::raft::RAFT_LOG)
                .unwrap()
                .remove(uncommitted)
                .unwrap();
            transaction.commit().unwrap();
            ledger
                .validate_bound_common_restore(&certificate, &binding)
                .unwrap();
            assert!(
                ledger
                    .restore_common_snapshot(&certificate, &bind(0xd9), &recovery)
                    .is_err()
            );
            assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), after);
            assert_eq!(
                ledger.common_snapshot_authority().unwrap(),
                Some((certificate.clone(), binding.clone()))
            );
            let expected_view = Some((
                certificate.clone(),
                binding.clone(),
                with_recovery.then(|| recovery.clone()),
                with_recovery.then(|| recovery.clone()),
            ));
            assert_eq!(
                ledger.common_snapshot_authority_with_recovery().unwrap(),
                expected_view
            );
            if with_recovery && previous_term == 12 {
                // Successful earlier reads are never durable authority for a
                // later call. A valid owner-signed but unapplied live slot and
                // fresh snapshot corruption must each invalidate the view.
                const MANIFEST: TableDefinition<&[u8], &[u8]> =
                    TableDefinition::new("agent_shared_raft_recovery_manifest_v2");
                const SNAPSHOT: TableDefinition<&[u8], &[u8]> =
                    TableDefinition::new("agent_shared_raft_snapshot_v2");
                for (table, is_manifest) in [(MANIFEST, true), (SNAPSHOT, false)] {
                    let (row_key, original) = {
                        let transaction = database.begin_read().unwrap();
                        let table = transaction.open_table(table).unwrap();
                        let row = table.iter().unwrap().next().unwrap().unwrap();
                        (row.0.value().to_vec(), row.1.value().to_vec())
                    };
                    let mut corrupt = if is_manifest {
                        unsigned_pending.encode()
                    } else {
                        original.clone()
                    };
                    if !is_manifest {
                        *corrupt.last_mut().unwrap() ^= 1;
                    }
                    let write_row = |bytes: &[u8]| {
                        let transaction = database.begin_write().unwrap();
                        transaction
                            .open_table(table)
                            .unwrap()
                            .insert(row_key.as_slice(), bytes)
                            .unwrap();
                        transaction.commit().unwrap();
                    };
                    write_row(&corrupt);
                    assert!(ledger.common_snapshot_authority_with_recovery().is_err());
                    assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), after);
                    write_row(&original);
                    assert_eq!(
                        ledger.common_snapshot_authority_with_recovery().unwrap(),
                        expected_view
                    );
                }
                let transaction = database.begin_write().unwrap();
                let mut changed = after.clone();
                changed.snap_last_term += 1;
                changed.write_in_txn(&transaction).unwrap();
                transaction.commit().unwrap();
                assert!(ledger.common_snapshot_authority_with_recovery().is_err());
                let transaction = database.begin_write().unwrap();
                after.write_in_txn(&transaction).unwrap();
                transaction.commit().unwrap();
                assert_eq!(
                    ledger.common_snapshot_authority_with_recovery().unwrap(),
                    expected_view
                );
            }
            drop(ledger);
            let reopened = AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation,
                store,
                local_node,
                initial.clone(),
                committee_authority_binding(),
            )
            .unwrap();
            reopened.audit_recovery().unwrap();
            assert_eq!(
                reopened.common_snapshot_authority_with_recovery().unwrap(),
                expected_view
            );
            let next = append_committed_kind(
                &database,
                after.current_term,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            );
            assert_eq!(next, after.last_applied + 1);
            assert!(
                reopened
                    .validate_bound_common_restore(&certificate, &binding)
                    .is_err()
            );
            let slot = reopened.next_committed_slot().unwrap().unwrap();
            reopened.apply_foundation_slot(&slot).unwrap();
            assert_eq!(
                reopened.cursor().unwrap().applied(),
                (next, after.current_term)
            );
            let registration = crate::agent::shared_recovery::recovery_registration_for_test(2, 7);
            let registration_index = append_committed_kind(
                &database,
                after.current_term,
                &EntryKind::Data {
                    payload: AgentRaftCommand::RegisterRecovery {
                        route: route(&initial),
                        registration: registration.clone(),
                    }
                    .encode(),
                },
            );
            let slot = reopened.next_committed_slot().unwrap().unwrap();
            reopened.apply_foundation_slot(&slot).unwrap();
            let mut live = recovery.clone();
            live.apply_registration(&registration, registration_index, after.current_term)
                .unwrap();
            assert_eq!(
                reopened.common_snapshot_authority_with_recovery().unwrap(),
                Some((
                    certificate.clone(),
                    binding.clone(),
                    with_recovery.then(|| recovery.clone()),
                    Some(live),
                )),
                "later applied custody changes the audited live manifest, never its certified baseline",
            );
            assert!(
                reopened
                    .restore_common_snapshot(&certificate, &binding, &recovery)
                    .is_err()
            );
        }
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_prepare_rejects_wrong_generation_committee_and_authority_without_advance() {
        let initial = committee(&[key(1), key(2)], &[key(9)]);
        let next = committee(&[key(2), key(3)], &[key(8)]);
        let generation = route(&initial).generation();

        let wrong_generation = AgentGenerationRouteKey::new(
            generation.space(),
            generation.agent(),
            generation.genesis(),
            AgentGenesisAdmissionId::from_bytes([0xb1; 32]),
        )
        .unwrap();
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_generation",
            initial.clone(),
            committee_change(
                wrong_generation,
                &initial,
                &next,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xc2),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongGeneration),
        );

        let stale = committee(&[key(1), key(3)], &[key(9)]);
        let stale_next = committee(&[key(3), key(4)], &[key(8)]);
        assert_prepare_rejected_without_advance(
            "v2_prepare_stale_committee",
            initial.clone(),
            committee_change(
                generation,
                &stale,
                &stale_next,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xc3),
            |error| matches!(error, AgentRaftApplicationErrorV2::StaleCommittee),
        );

        let binding = committee_authority_binding();
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_signer",
            initial.clone(),
            committee_change_with(
                generation,
                &initial,
                &next,
                &key(0xf1),
                binding.policy,
                0xe3,
                binding.runtime_deployment,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xc4),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_policy",
            initial.clone(),
            committee_change_with(
                generation,
                &initial,
                &next,
                &key(0xe1),
                crate::agent_sdk::Hash([0xf2; 32]),
                0xe3,
                binding.runtime_deployment,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xc5),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_issuer",
            initial.clone(),
            committee_change_with(
                generation,
                &initial,
                &next,
                &key(0xe1),
                binding.policy,
                0xd3,
                binding.runtime_deployment,
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xcc),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_runtime_deployment",
            initial.clone(),
            committee_change_with(
                generation,
                &initial,
                &next,
                &key(0xe1),
                binding.policy,
                0xe3,
                crate::agent_sdk::DeploymentId([0xcd; 32]),
                COMMITTEE_AUTHORITY_EPOCH,
                1,
                10,
            ),
            journal_store(0xcd),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
        assert_prepare_rejected_without_advance(
            "v2_prepare_wrong_epoch",
            initial.clone(),
            committee_change(
                generation,
                &initial,
                &next,
                COMMITTEE_AUTHORITY_EPOCH + 1,
                1,
                10,
            ),
            journal_store(0xc6),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
        assert_prepare_rejected_without_advance(
            "v2_prepare_not_live",
            initial.clone(),
            committee_change(
                generation,
                &initial,
                &next,
                COMMITTEE_AUTHORITY_EPOCH,
                2,
                10,
            ),
            journal_store(0xc7),
            |error| matches!(error, AgentRaftApplicationErrorV2::StaleAuthority),
        );

        let valid = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let mut bad_signature = valid.authority().clone();
        bad_signature.signature[0] ^= 1;
        let bad_signature = PrepareCommitteeChange::new(
            generation,
            initial.clone(),
            next,
            COMMITTEE_EXPECTED_GENERATION,
            COMMITTEE_OBSERVED_SLOT,
            bad_signature,
        )
        .unwrap();
        assert_prepare_rejected_without_advance(
            "v2_prepare_bad_signature",
            initial,
            bad_signature,
            journal_store(0xc8),
            |error| matches!(error, AgentRaftApplicationErrorV2::WrongAuthority),
        );
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_pending_barrier_rejects_overlap_reorder_wrong_role_and_partial_nodes() {
        let directory = TempDirectory::new("v2_committee_hostile_barrier");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let initial = committee(&[key(1), key(2)], &[key(9)]);
        let next = committee(&[key(2), key(3)], &[key(8)]);
        let generation = route(&initial).generation();
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let previous_voters = change.previous_voters().to_vec();
        let next_voters = change.next_voters().to_vec();
        let ledger =
            open_transition_ledger(Arc::clone(&database), initial.clone(), journal_store(0xc9))
                .unwrap();
        ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(change.clone()).encode(),
                },
            )
            .unwrap();
        let prepare = ledger.next_committed_slot().unwrap().unwrap();
        ledger.apply_foundation_slot(&prepare).unwrap();

        macro_rules! rejects_at_prepare_barrier {
            ($slot:expr, $pattern:pat) => {{
                let error = ledger.apply_foundation_slot(&$slot).unwrap_err();
                assert!(
                    matches!(error, $pattern),
                    "unexpected barrier error: {error:?}"
                );
                assert_eq!(ledger.cursor().unwrap().applied(), (1, 7));
                assert_eq!(
                    ledger.pending_transition().unwrap(),
                    Some((change.transition(), false))
                );
                assert_eq!(
                    crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                    1
                );
            }};
        }

        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters.clone(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::ReorderedConfiguration
        );
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: Some(previous_voters[..1].to_vec()),
                    members: next_voters.clone(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::WrongConfigurationNodes
        );
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: Some(previous_voters.clone()),
                    members: next_voters[..1].to_vec(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::WrongConfigurationNodes
        );

        let observer_node = AgentNodeId(member(&key(8), ReplicaRole::Observer).replica().node.0);
        assert!(!next_voters.contains(&observer_node));
        let mut role_confused_nodes = next_voters.clone();
        role_confused_nodes.push(observer_node);
        role_confused_nodes.sort_unstable();
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: Some(previous_voters.clone()),
                    members: role_confused_nodes.clone(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::WrongConfigurationNodes
        );
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::Data {
                    payload: Vec::new()
                },
                2,
                8
            ),
            AgentRaftApplicationErrorV2::TransitionBarrier
        );
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::Data {
                    payload: AgentRaftCommand::ArtifactAbort {
                        route: route(&initial),
                        batch: ArtifactBatchId::from_bytes([0xca; 32]),
                    }
                    .encode(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::TransitionBarrier
        );
        let overlapping_next = committee(&[key(1), key(4)], &[key(7)]);
        let overlapping = committee_change(
            generation,
            &initial,
            &overlapping_next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        rejects_at_prepare_barrier!(
            physical_slot(
                EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(overlapping).encode(),
                },
                2,
                8,
            ),
            AgentRaftApplicationErrorV2::OverlappingCommitteeChange
        );

        append_committed_kind(
            &database,
            8,
            &EntryKind::ConfigChange {
                joint_old: Some(previous_voters),
                members: next_voters.clone(),
            },
        );
        let joint = ledger.next_committed_slot().unwrap().unwrap();
        ledger.apply_foundation_slot(&joint).unwrap();
        assert_eq!(
            ledger.pending_transition().unwrap(),
            Some((change.transition(), true))
        );

        macro_rules! rejects_at_joint_barrier {
            ($slot:expr, $pattern:pat) => {{
                let error = ledger.apply_foundation_slot(&$slot).unwrap_err();
                assert!(
                    matches!(error, $pattern),
                    "unexpected barrier error: {error:?}"
                );
                assert_eq!(ledger.cursor().unwrap().applied(), (2, 8));
                assert_eq!(
                    ledger.pending_transition().unwrap(),
                    Some((change.transition(), true))
                );
                assert_eq!(
                    crate::raft::RaftMeta::load(&database).unwrap().last_applied,
                    2
                );
            }};
        }

        rejects_at_joint_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: Some(change.previous_voters().to_vec()),
                    members: next_voters.clone(),
                },
                3,
                8,
            ),
            AgentRaftApplicationErrorV2::ReorderedConfiguration
        );
        rejects_at_joint_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: None,
                    members: next_voters[..1].to_vec(),
                },
                3,
                8,
            ),
            AgentRaftApplicationErrorV2::WrongConfigurationNodes
        );
        rejects_at_joint_barrier!(
            physical_slot(
                EntryKind::ConfigChange {
                    joint_old: None,
                    members: role_confused_nodes,
                },
                3,
                8,
            ),
            AgentRaftApplicationErrorV2::WrongConfigurationNodes
        );

        append_committed_kind(
            &database,
            8,
            &EntryKind::ConfigChange {
                joint_old: None,
                members: next_voters,
            },
        );
        let stable = ledger.next_committed_slot().unwrap().unwrap();
        ledger.apply_foundation_slot(&stable).unwrap();
        assert_eq!(ledger.active_committee().unwrap(), next);
        assert_eq!(ledger.pending_transition().unwrap(), None);
        assert_eq!(ledger.cursor().unwrap().applied(), (3, 8));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_restart_replays_transition_and_rejects_valid_looking_state_tampering() {
        const COMMITTEE_STATE_TABLE: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("agent_shared_raft_committee_state_v2");

        let directory = TempDirectory::new("v2_committee_state_tamper");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let initial = committee(&[key(1), key(2)], &[key(9)]);
        let next = committee(&[key(2), key(3)], &[key(8)]);
        let generation = route(&initial).generation();
        let store = journal_store(0xcb);
        let change = committee_change(
            generation,
            &initial,
            &next,
            COMMITTEE_AUTHORITY_EPOCH,
            1,
            10,
        );
        let ledger = open_transition_ledger(Arc::clone(&database), initial.clone(), store).unwrap();
        ledger
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: AgentRaftCommand::PrepareCommitteeChange(change).encode(),
                },
            )
            .unwrap();
        let prepare = ledger.next_committed_slot().unwrap().unwrap();
        ledger.apply_foundation_slot(&prepare).unwrap();
        drop(ledger);

        let storage_key = application_ledger_v2::generation_storage_key(generation);
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(COMMITTEE_STATE_TABLE).unwrap();
            let bytes = table
                .get(storage_key.as_slice())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let mut state = CommitteeApplicationStateV2::decode(&bytes).unwrap();
            state.pending = None;
            state.validate().unwrap();
            table
                .insert(storage_key.as_slice(), state.encode().as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();

        assert!(matches!(
            open_transition_ledger(database, initial, store),
            Err(AgentRaftApplicationErrorV2::CorruptLedger)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_duplicate_conflict_and_missing_or_corrupt_rows_fail_closed() {
        let generation = route(&committee(&[key(1)], &[])).generation();

        let conflict_directory = TempDirectory::new("v2_duplicate_conflict");
        let conflict_database = Arc::new(Database::create(conflict_directory.database()).unwrap());
        let conflict_ledger = open_foundation_ledger(
            Arc::clone(&conflict_database),
            generation,
            journal_store(0xa6),
        )
        .unwrap();
        conflict_ledger
            .append_committed_for_test(
                12,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let exact = conflict_ledger.next_committed_slot().unwrap().unwrap();
        conflict_ledger.apply_foundation_slot(&exact).unwrap();
        let conflicting = physical_slot(
            EntryKind::Data {
                payload: Vec::new(),
            },
            1,
            13,
        );
        assert!(matches!(
            conflict_ledger.apply_foundation_slot(&conflicting),
            Err(AgentRaftApplicationErrorV2::ConflictingDuplicate(1))
        ));

        let missing_directory = TempDirectory::new("v2_missing_log");
        let missing_database = Arc::new(Database::create(missing_directory.database()).unwrap());
        let missing_ledger = open_foundation_ledger(
            Arc::clone(&missing_database),
            generation,
            journal_store(0xa7),
        )
        .unwrap();
        missing_ledger
            .append_committed_for_test(
                14,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let slot = missing_ledger.next_committed_slot().unwrap().unwrap();
        missing_ledger.apply_foundation_slot(&slot).unwrap();
        {
            let transaction = missing_database.begin_write().unwrap();
            transaction
                .open_table(crate::raft::RAFT_LOG)
                .unwrap()
                .remove(1)
                .unwrap();
            transaction.commit().unwrap();
        }
        assert!(matches!(
            missing_ledger.audit_recovery(),
            Err(AgentRaftApplicationErrorV2::MissingCommittedSlot)
        ));
        assert!(matches!(
            missing_ledger.capacity(),
            Err(AgentRaftApplicationErrorV2::MissingCommittedSlot)
        ));

        let corrupt_directory = TempDirectory::new("v2_corrupt_audit");
        let corrupt_database = Arc::new(Database::create(corrupt_directory.database()).unwrap());
        let corrupt_ledger = open_foundation_ledger(
            Arc::clone(&corrupt_database),
            generation,
            journal_store(0xa8),
        )
        .unwrap();
        corrupt_ledger
            .append_committed_for_test(
                15,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        let slot = corrupt_ledger.next_committed_slot().unwrap().unwrap();
        corrupt_ledger.apply_foundation_slot(&slot).unwrap();
        {
            const AUDIT_TABLE: TableDefinition<&[u8], &[u8]> =
                TableDefinition::new("agent_shared_raft_apply_audit_v2");
            let key = application_ledger_v2::audit_storage_key(generation, 1);
            let transaction = corrupt_database.begin_write().unwrap();
            transaction
                .open_table(AUDIT_TABLE)
                .unwrap()
                .insert(key.as_slice(), b"corrupt".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        assert!(matches!(
            corrupt_ledger.audit_recovery(),
            Err(AgentRaftApplicationErrorV2::CorruptLedger)
        ));
        assert!(matches!(
            corrupt_ledger.capacity(),
            Err(AgentRaftApplicationErrorV2::CorruptLedger)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_wire_and_disk_reject_v1_generation() {
        let v1 = AgentRaftAuditDisposition::ArtifactBatchAborted {
            batch: ArtifactBatchId::from_bytes([0x58; 32]),
        };
        assert_eq!(
            AgentRaftApplyDispositionV2::decode(&v1.encode()),
            Err(DecodeError::InvalidTag)
        );
        let v1_meta = AgentRaftApplyMeta::post_genesis(route(&committee(&[key(1)], &[])));
        assert_eq!(
            AgentRaftApplyMetaV2::decode(&v1_meta.encode()),
            Err(DecodeError::InvalidTag)
        );

        const LEGACY_CONFIG: TableDefinition<&[u8], &[u8]> =
            TableDefinition::new("agent_shared_raft_config");
        let directory = TempDirectory::new("v2_reject_v1");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        {
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(LEGACY_CONFIG)
                .unwrap()
                .insert(b"legacy".as_slice(), b"v1".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        assert!(matches!(
            open_foundation_ledger(
                database,
                route(&committee(&[key(1)], &[])).generation(),
                journal_store(0xa9),
            ),
            Err(AgentRaftApplicationErrorV2::LegacyGeneration)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_database_cannot_rebind_generation_store_initial_committee_or_authority() {
        let directory = TempDirectory::new("v2_generation_binding");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let initial = committee(&[key(1)], &[]);
        let generation_a = route(&initial).generation();
        let generation_b = AgentGenerationRouteKey::new(
            generation_a.space(),
            generation_a.agent(),
            generation_a.genesis(),
            AgentGenesisAdmissionId::from_bytes([0xba; 32]),
        )
        .unwrap();
        let store_a = journal_store(0xaa);
        let store_b = journal_store(0xbb);
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::clone(&database),
            generation_a,
            store_a,
            initial.members()[0].replica().node,
            initial.clone(),
            committee_authority_binding(),
        )
        .unwrap();
        assert_eq!(ledger.cursor().unwrap().applied(), (0, 0));

        assert!(matches!(
            open_foundation_ledger(Arc::clone(&database), generation_b, store_b,),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));
        assert!(matches!(
            open_foundation_ledger(Arc::clone(&database), generation_a, store_b),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));

        let different_initial = committee(&[key(2)], &[]);
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                Arc::clone(&database),
                generation_a,
                store_a,
                different_initial.members()[0].replica().node,
                different_initial,
                committee_authority_binding(),
            ),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));

        let alternate_key = key(0xf3);
        let alternate_public_key = alternate_key.verifying_key().to_bytes();
        let alternate_authority = CommitteeChangeAuthorityBinding::new(
            crate::agent_sdk::Hash([0xf4; 32]),
            crate::agent_sdk::authority::AuthorityIssuer {
                principal: crate::agent_sdk::PrincipalId([0xf5; 32]),
                actor: crate::agent_sdk::ActorId([0xf6; 32]),
                deployment: crate::agent_sdk::DeploymentId([0xf7; 32]),
                program: crate::agent_sdk::ProgramId([0xf8; 32]),
                producer: crate::agent_sdk::ProducerId::of_public_key(&alternate_public_key),
            },
            crate::agent_sdk::DeploymentId([0xf9; 32]),
            alternate_public_key,
            COMMITTEE_AUTHORITY_EPOCH,
        )
        .unwrap();
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                database,
                generation_a,
                store_a,
                initial.members()[0].replica().node,
                initial,
                alternate_authority,
            ),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_fresh_binding_rejects_all_preexisting_raft_state() {
        let initial = committee(&[key(1)], &[]);
        let generation = route(&initial).generation();
        let store = journal_store(0xad);

        // A generationless committed no-op must not be adopted merely because
        // the Agent application cursor has not advanced yet.
        let log_directory = TempDirectory::new("v2_stale_raft_log_before_binding");
        let log_database = Arc::new(Database::create(log_directory.database()).unwrap());
        assert_eq!(
            append_committed_kind(
                &log_database,
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            ),
            1
        );
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                Arc::clone(&log_database),
                generation,
                store,
                initial.members()[0].replica().node,
                initial.clone(),
                committee_authority_binding(),
            ),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));
        let stale_meta = crate::raft::RaftMeta::load(&log_database).unwrap();
        assert_eq!(stale_meta.current_term, 7);
        assert_eq!(stale_meta.commit_index, 1);
        assert_eq!(stale_meta.last_applied, 0);
        assert_eq!(
            crate::raft::RaftLog::open(Arc::clone(&log_database))
                .unwrap()
                .len()
                .unwrap(),
            1
        );

        // Even rows encoding the scalar defaults are residue. A pristine
        // first bind has an empty metadata table, not merely decoded zeros.
        let meta_directory = TempDirectory::new("v2_stale_raft_meta_before_binding");
        let meta_database = Arc::new(Database::create(meta_directory.database()).unwrap());
        {
            let transaction = meta_database.begin_write().unwrap();
            crate::raft::RaftMeta::default()
                .write_in_txn(&transaction)
                .unwrap();
            transaction.commit().unwrap();
        }
        assert!(matches!(
            AgentRaftApplicationLedgerV2::open(
                meta_database,
                generation,
                store,
                initial.members()[0].replica().node,
                initial,
                committee_authority_binding(),
            ),
            Err(AgentRaftApplicationErrorV2::ConfigurationMismatch)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn v2_open_and_physical_witness_reject_malformed_raft_meta() {
        const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");
        let directory = TempDirectory::new("v2_malformed_raft_meta");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        {
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(META_TABLE)
                .unwrap()
                .insert("commit_index", &[1_u8; 7][..])
                .unwrap();
            transaction.commit().unwrap();
        }

        assert!(matches!(
            open_foundation_ledger(
                Arc::clone(&database),
                route(&committee(&[key(1)], &[])).generation(),
                journal_store(0xac),
            ),
            Err(AgentRaftApplicationErrorV2::Backend(_))
        ));
        assert!(matches!(
            CommittedSharedRaftSlot::from_durable_log(&RedbSharedRaftLogWitness::new(database), 1,),
            Err(CommittedSharedRaftSlotError::Witness(_))
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn ordinary_ordered_successor_accepts_the_prior_retained_merge_seal() {
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let fence = ordered_entry(route);
        let entry = ordinary_ordered_entry(route, fence.id());
        let claim = retained_seal_claim(route, &fence, &entry, 2, 7);
        assert!(entry.merge_seal.is_none());
        assert_eq!(
            claim.merge_seal(),
            fence.merge_seal,
            "the claim retains the prior fence seal"
        );
        assert_ne!(claim.merge_fence(), claim.ordered());

        let committed = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry,
            },
            2,
            7,
        );
        evidence_ledger::validate_claim_link(route, &committed, &claim).unwrap();
    }

    #[cfg(feature = "storage")]
    pub(super) struct TempDirectory(std::path::PathBuf);

    #[cfg(feature = "storage")]
    impl TempDirectory {
        pub(super) fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(alloc::format!(
                "vos_shared_raft_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(super) fn database(&self) -> std::path::PathBuf {
            self.0.join("evidence.redb")
        }
    }

    #[cfg(feature = "storage")]
    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(feature = "storage")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestSignFailure;

    #[cfg(feature = "storage")]
    impl fmt::Display for TestSignFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected signer failure")
        }
    }

    #[cfg(feature = "storage")]
    impl core::error::Error for TestSignFailure {}

    #[cfg(feature = "storage")]
    struct CheckingSigner<'a> {
        ledger: &'a AgentRaftEvidenceLedger,
        key: &'a SigningKey,
        expected_index: u64,
        expected_claim: Hash,
        calls: &'a Cell<usize>,
        fail: bool,
    }

    #[cfg(feature = "storage")]
    impl ReplicaCommitSigner for CheckingSigner<'_> {
        type Error = TestSignFailure;

        fn node(&self) -> NodeId {
            NodeId::of_authenticated_peer(&peer_id(self.key))
        }

        fn sign_commit_message(&self, message: Hash) -> Result<[u8; 64], Self::Error> {
            // This read opens a new redb transaction from inside the callback;
            // it proves the pledge commit completed before signing began.
            assert_eq!(
                self.ledger.pledged_claim(self.expected_index).unwrap(),
                Some(self.expected_claim)
            );
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err(TestSignFailure)
            } else {
                Ok(self.key.sign(&message.0).to_bytes())
            }
        }
    }

    #[cfg(feature = "storage")]
    struct PanicSigner {
        node: NodeId,
    }

    #[cfg(feature = "storage")]
    impl ReplicaCommitSigner for PanicSigner {
        type Error = TestSignFailure;

        fn node(&self) -> NodeId {
            self.node
        }

        fn sign_commit_message(&self, _message: Hash) -> Result<[u8; 64], Self::Error> {
            panic!("an exact signed retry must not invoke the signer")
        }
    }

    #[cfg(feature = "storage")]
    #[test]
    fn pledge_survives_crash_window_and_exact_retry_never_resigns() {
        let directory = TempDirectory::new("pledge_reopen");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);

        // Crash after the pre-CAS capacity reservation but before publication.
        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            assert_eq!(
                reserved.payload_commitment(),
                committed.payload_commitment()
            );
            assert_eq!(reserved.journal_store(), journal_store(0x80));
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            assert!(matches!(
                AgentRaftEvidenceLedger::open(
                    database,
                    route,
                    committee.clone(),
                    local_node,
                    journal_store(0x81),
                ),
                Err(AgentRaftLedgerError::ConfigurationMismatch)
            ));
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            let duplicate = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &claim, successor(0x79))
                .unwrap();
            assert!(matches!(
                ledger.anchor_applied_ordered_for_test(duplicate, &claim, successor(0x79),),
                Err(AgentRaftLedgerError::AppliedConflict)
            ));
            let calls = Cell::new(0);
            let failed = ledger.sign_local(
                &claim,
                &CheckingSigner {
                    ledger: &ledger,
                    key: &voters[0],
                    expected_index: claim.raft_index(),
                    expected_claim: claim.commitment(),
                    calls: &calls,
                    fail: true,
                },
            );
            assert!(matches!(failed, Err(AgentRaftSignError::Signer(_))));
            assert_eq!(calls.get(), 1);
            assert_eq!(
                ledger.pledged_claim(claim.raft_index()).unwrap(),
                Some(claim.commitment())
            );
            assert!(ledger.certificate(claim.raft_index()).unwrap().is_none());
        }

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let recovered_application =
                ledger.recover_applied_ordered(&committed).unwrap().unwrap();
            assert_eq!(recovered_application.claim(), &claim);
            assert_eq!(recovered_application.successor(), successor(0x79));
            assert!(matches!(
                ledger.reserve_ordered_application(&committed),
                Err(AgentRaftLedgerError::AppliedConflict)
            ));
            let calls = Cell::new(0);
            let outcome = ledger
                .sign_local(
                    &claim,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: claim.raft_index(),
                        expected_claim: claim.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap();
            assert_eq!(calls.get(), 1);
            assert!(outcome.certificate().is_some());
            outcome
                .certificate()
                .unwrap()
                .verify(&committee, &claim)
                .unwrap();

            let retried = ledger
                .sign_local(&claim, &PanicSigner { node: local_node })
                .unwrap();
            assert_eq!(retried.share(), outcome.share());
            assert_eq!(
                ledger.apply_meta().unwrap().compact_safe(),
                (claim.raft_index(), claim.raft_term())
            );
        }
    }

    #[cfg(feature = "storage")]
    #[test]
    fn reservation_from_another_journal_instance_cannot_anchor() {
        let first_directory = TempDirectory::new("journal_binding_a");
        let second_directory = TempDirectory::new("journal_binding_b");
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);
        let first = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(first_directory.database()).unwrap()),
            route,
            committee.clone(),
            local_node,
            journal_store(0x84),
        )
        .unwrap();
        let second = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(second_directory.database()).unwrap()),
            route,
            committee,
            local_node,
            journal_store(0x85),
        )
        .unwrap();
        let foreign = first.reserve_ordered_application(&committed).unwrap();
        let local = second.reserve_ordered_application(&committed).unwrap();
        assert!(matches!(
            second.anchor_applied_ordered_for_test(foreign, &claim, successor(0x86)),
            Err(AgentRaftLedgerError::WrongJournalStore)
        ));
        second
            .anchor_applied_ordered_for_test(local, &claim, successor(0x86))
            .unwrap();
    }

    #[cfg(feature = "storage")]
    #[test]
    fn ordered_artifact_batch_is_rejected_before_phase_one_reservation() {
        let directory = TempDirectory::new("ordered_artifact_batch");
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (unbatched, claim) = ordered_fixture(&committee);
        let entry = match unbatched.command() {
            AgentRaftCommand::Ordered { entry, .. } => entry.clone(),
            _ => unreachable!(),
        };
        let batched = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: Some(ArtifactBatchId::from_bytes([0x88; 32])),
                entry,
            },
            1,
            7,
        );
        let ledger = AgentRaftEvidenceLedger::open(
            Arc::new(Database::create(directory.database()).unwrap()),
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let before = ledger.apply_meta().unwrap();
        assert!(matches!(
            ledger.reserve_ordered_application(&batched),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert!(matches!(
            ledger.recover_applied_ordered(&batched),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert!(matches!(
            evidence_ledger::validate_claim_link(route, &batched, &claim),
            Err(AgentRaftLedgerError::ArtifactBatchReceiptRequired)
        ));
        assert_eq!(ledger.apply_meta().unwrap(), before);

        // A valid unbatched command can still take the same slot, proving the
        // rejected call wrote neither a reservation nor fail-stop evidence.
        let reserved = ledger.reserve_ordered_application(&unbatched).unwrap();
        ledger
            .anchor_applied_ordered_for_test(reserved, &claim, successor(0x89))
            .unwrap();
    }

    #[cfg(feature = "storage")]
    #[test]
    fn divergent_anchored_claim_persists_fail_stop_across_reopen() {
        let directory = TempDirectory::new("equivocation");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, anchored_claim) = ordered_fixture(&committee);
        let entry = match committed.command() {
            AgentRaftCommand::Ordered { entry, .. } => entry,
            _ => unreachable!(),
        };
        let divergent = claim(route, entry, 1, 7, b"divergent linear state");

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &anchored_claim, successor(0x7a))
                .unwrap();
            let calls = Cell::new(0);
            let error = ledger
                .sign_local(
                    &divergent,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: divergent.raft_index(),
                        expected_claim: divergent.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap_err();
            assert!(matches!(
                error,
                AgentRaftSignError::Ledger(AgentRaftLedgerError::DivergentClaim)
            ));
            assert_eq!(calls.get(), 0);
            assert!(ledger.is_fail_stopped().unwrap());
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.sign_local(&anchored_claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::FailStopped
            ))
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn conflicting_reservation_fail_stops_but_the_admitted_exact_slot_can_drain() {
        let directory = TempDirectory::new("reservation_equivocation");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let first_entry = ordered_entry(route);
        let first_claim = claim(route, &first_entry, 1, 7, b"admitted linear state");
        let mut conflicting_entry = first_entry.clone();
        conflicting_entry.merge_frontier = MergeFrontierId([0x7d; 32]);
        let first = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: first_entry,
            },
            1,
            7,
        );
        let conflicting = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: conflicting_entry,
            },
            1,
            7,
        );

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let _lost_after_crash = ledger.reserve_ordered_application(&first).unwrap();
            assert!(matches!(
                ledger.reserve_ordered_application(&conflicting),
                Err(AgentRaftLedgerError::DivergentReservation)
            ));
            assert!(ledger.is_fail_stopped().unwrap());
            // Simulate a crash after the reservation may have crossed the
            // journal CAS but before its in-memory authority reaches anchor.
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee,
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.reserve_ordered_application(&conflicting),
            Err(AgentRaftLedgerError::FailStopped)
        ));
        // The exact authority may already have crossed the journal CAS.
        // Reissuing and draining its durable reservation is therefore
        // mandatory even though every new authority and all signing stop.
        let recovered_reservation = ledger.reserve_ordered_application(&first).unwrap();
        ledger
            .anchor_applied_ordered_for_test(recovered_reservation, &first_claim, successor(0x87))
            .unwrap();
        assert!(ledger.is_fail_stopped().unwrap());
        assert!(matches!(
            ledger.sign_local(&first_claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::FailStopped
            ))
        ));
        let recovered = ledger.recover_applied_ordered(&first).unwrap().unwrap();
        assert_eq!(recovered.claim(), &first_claim);
        assert_eq!(recovered.successor(), successor(0x87));
        assert!(matches!(
            ledger.reserve_ordered_application(&first),
            Err(AgentRaftLedgerError::FailStopped)
        ));
    }

    #[cfg(feature = "storage")]
    #[test]
    fn reopen_rejects_a_gap_in_the_permanent_contiguous_anchor_history() {
        let directory = TempDirectory::new("anchor_gap");
        let path = directory.database();
        let voters = [key(1)];
        let committee = committee(&voters, &[]);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let fence = ordered_entry(route);
        let first_claim = claim(route, &fence, 1, 7, b"first linear state");
        let first = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: fence.clone(),
            },
            1,
            7,
        );
        let ordinary = ordinary_ordered_entry(route, fence.id());
        let second_claim = retained_seal_claim(route, &fence, &ordinary, 2, 7);
        let second = committed(
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry: ordinary,
            },
            2,
            7,
        );

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            let reserved = ledger.reserve_ordered_application(&first).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &first_claim, successor(0x82))
                .unwrap();
            let reserved = ledger.reserve_ordered_application(&second).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &second_claim, successor(0x83))
                .unwrap();
            ledger.delete_anchor_for_test(1).unwrap();
        }

        let database = Arc::new(Database::create(&path).unwrap());
        assert!(matches!(
            AgentRaftEvidenceLedger::open(
                database,
                route,
                committee,
                local_node,
                journal_store(0x80),
            ),
            Err(AgentRaftLedgerError::CorruptLedger)
        ));
    }

    #[cfg(feature = "storage")]
    fn share(claim: &OrderedCommitClaim, key: &SigningKey) -> ReplicaCommitSignature {
        let message =
            ReplicaQuorumCertificate::signing_message(claim.committee(), claim.commitment());
        ReplicaCommitSignature::new(
            NodeId::of_authenticated_peer(&peer_id(key)),
            key.sign(&message.0).to_bytes(),
        )
        .unwrap()
    }

    #[cfg(feature = "storage")]
    #[test]
    fn remote_voter_shares_form_and_recover_exact_quorum_certificate() {
        let directory = TempDirectory::new("remote_shares");
        let path = directory.database();
        let voters = [key(1), key(2), key(3)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&voters[0]));
        let (committed, claim) = ordered_fixture(&committee);

        {
            let database = Arc::new(Database::create(&path).unwrap());
            let ledger = AgentRaftEvidenceLedger::open(
                database,
                route,
                committee.clone(),
                local_node,
                journal_store(0x80),
            )
            .unwrap();
            assert!(matches!(
                ledger.record_remote_share(&claim, share(&claim, &voters[1])),
                Err(AgentRaftLedgerError::ClaimNotAnchored)
            ));
            let reserved = ledger.reserve_ordered_application(&committed).unwrap();
            ledger
                .anchor_applied_ordered_for_test(reserved, &claim, successor(0x7b))
                .unwrap();
            let calls = Cell::new(0);
            let local = ledger
                .sign_local(
                    &claim,
                    &CheckingSigner {
                        ledger: &ledger,
                        key: &voters[0],
                        expected_index: claim.raft_index(),
                        expected_claim: claim.commitment(),
                        calls: &calls,
                        fail: false,
                    },
                )
                .unwrap();
            assert!(local.certificate().is_none());

            let observer_error = ledger
                .record_remote_share(&claim, share(&claim, &observers[0]))
                .unwrap_err();
            assert!(matches!(
                observer_error,
                AgentRaftLedgerError::ObserverSigner
            ));
            let quorum = ledger
                .record_remote_share(&claim, share(&claim, &voters[1]))
                .unwrap();
            let certificate = quorum.certificate().unwrap();
            assert_eq!(certificate.signatures().len(), 2);
            certificate.verify(&committee, &claim).unwrap();
            let first_certificate = certificate.clone();
            let late = ledger
                .record_remote_share(&claim, share(&claim, &voters[2]))
                .unwrap();
            assert_eq!(late.certificate(), Some(&first_certificate));
            assert_eq!(
                late.share().signer(),
                member(&voters[2], ReplicaRole::Voter).replica().node
            );
            assert_eq!(
                ledger.apply_meta().unwrap().compact_safe_qc(),
                Some(certificate.commitment())
            );
        }

        let database = Arc::new(Database::create(&path).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee.clone(),
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let recovered = ledger.certificate(claim.raft_index()).unwrap().unwrap();
        recovered.verify(&committee, &claim).unwrap();
        assert_eq!(recovered.signatures().len(), committee.quorum_threshold());
        assert!(recovered.encode().len() <= MAX_REPLICA_QUORUM_CERTIFICATE_BYTES);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn observer_applies_and_verifies_quorum_but_never_pledges_or_signs() {
        let voters = [key(1)];
        let observers = [key(9)];
        let committee = committee(&voters, &observers);
        let route = route(&committee);
        let local_node = NodeId::of_authenticated_peer(&peer_id(&observers[0]));
        let (committed, claim) = ordered_fixture(&committee);
        let directory = TempDirectory::new("observer_apply");
        let database = Arc::new(Database::create(directory.database()).unwrap());
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee.clone(),
            local_node,
            journal_store(0x80),
        )
        .unwrap();
        let reserved = ledger.reserve_ordered_application(&committed).unwrap();
        assert_eq!(reserved.local_node(), local_node);
        ledger
            .anchor_applied_ordered_for_test(reserved, &claim, successor(0x7c))
            .unwrap();

        assert!(matches!(
            ledger.sign_local(&claim, &PanicSigner { node: local_node }),
            Err(AgentRaftSignError::Ledger(
                AgentRaftLedgerError::LocalReplicaNotVoter
            ))
        ));
        assert_eq!(ledger.pledged_claim(claim.raft_index()).unwrap(), None);

        let outcome = ledger
            .record_remote_share(&claim, share(&claim, &voters[0]))
            .unwrap();
        let certificate = outcome.certificate().unwrap();
        certificate.verify(&committee, &claim).unwrap();
        assert_eq!(
            ledger.apply_meta().unwrap().compact_safe_qc(),
            Some(certificate.commitment())
        );
    }
}
