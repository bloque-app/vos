//! Bounded production host boundary for ordinary Shared Agents.
//!
//! Every hosted Agent owns one full-identity journal directory, one
//! generation-bound Raft database, and one generation-bound artifact staging
//! directory.  Opening the host rechecks system-Agent finality, package trust,
//! every durable namespace, and the journal/Raft cross-store binding before an
//! Agent becomes discoverable.
//!
//! This module deliberately does not attach the service-oriented Raft worker
//! or singleton service CRDT router. The clean network owner attaches the
//! Agent-specific full-identity worker explicitly and reconstructs that
//! process-only state after restart. Agent checkpoint candidates,
//! authenticated installation, and bounded journal retirement remain driven
//! through this host boundary.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use redb::Database;

use super::bootstrap::{
    SystemAgentGenesisProvision, seal_prepared_system_agent_genesis,
    validate_system_agent_genesis_catalog,
};
use super::committee::{MAX_ROOT_ANCHOR_PINS_BYTES, RootAnchorPins};
use super::driver::AgentTrustProvider;
use super::driver::SdkManagementArtifacts;
use super::execution::RuntimeBlob;
use super::genesis::{
    AgentGenesisFinalityError, AgentGenesisFinalityVerifier, AgentGenesisProvision,
    AgentGenesisProvisionVerificationError, AgentReplicaCommittee, VerifiedAgentGenesisProvision,
    validate_agent_genesis_catalog,
};
use super::host::{AgentHostError, AgentHostRootLease, AgentHostScope, LocalMergeAuthenticator};
use super::journal::{
    AgentJournalGenesisId, CanonicalJournalRecord, MAX_JOURNAL_RECORD_BYTES, MergeEvent,
    MergeEventId, MergeFrontierId, OrderedEntryId, RuntimeBinding,
};
#[cfg(feature = "experimental-state-blocks")]
use super::journal_store::CatalogBlobResolverFactory;
use super::journal_store::{
    AgentJournalStore, FileAgentJournalStore, FileLocalAgentJournalSlot,
    MAX_PORTABLE_JOURNAL_BLOBS, MAX_PORTABLE_JOURNAL_IMAGE_BYTES, MAX_PORTABLE_JOURNAL_OBJECTS,
    PortableJournalCheckpoint, PortableJournalLimits,
};
use super::local_journal_driver::LocalJournalAgentDriver;
use super::replay::ReplaySealedOrdinaryGenesis;
use super::shared_commit::{
    MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES, ReplicaCommitSignature,
    SharedAgentCommonSnapshotCertificate, SharedAgentCommonSnapshotClaim,
    SharedAgentLocalSnapshotBinding, SharedAgentPortableSnapshotCertificate,
    SharedAgentPortableSnapshotClaim, SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim,
    VerifiedSharedAgentPortableSnapshot,
};
use super::shared_journal_driver::{
    FileSharedArtifactStager, SharedArtifactStagerError, SharedJournalAgentDriver,
    SharedJournalDriverError, SharedMergeObject, SharedPhysicalApplyOutcome,
    install_immutable_file, preflight_common_rebind, preflight_common_source,
    preflight_portable_checkpoint, read_regular_bounded,
};
use super::shared_raft::{
    AgentGenerationRouteKey, AgentRaftApplicationErrorV2, AgentRaftApplicationLedgerV2,
    AgentRouteKey, CommitteeChangeAuthorityBinding,
};
use super::{AgentIdentity, AgentProfile, ReplicaRole, StateLane};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId};

const JOURNAL_SUFFIX: &str = ".agent";
const JOURNAL_LOCK_SUFFIX: &str = ".agent-lock";
const INTENT_SUFFIX: &str = ".shared-genesis.intent";
const INTENT_STAGE_SUFFIX: &str = ".shared-genesis.intent.next";
const EXPOSURE_SUFFIX: &str = ".shared-genesis.exposed";
const EXPOSURE_STAGE_SUFFIX: &str = ".shared-genesis.exposed.next";
const RAFT_SUFFIX: &str = ".shared-raft.redb";
const ARTIFACT_SUFFIX: &str = ".shared-artifacts";
const PORTABLE_RESTORE_SUFFIX: &str = ".shared-portable-restore";
const PORTABLE_RESTORE_STAGE_SUFFIX: &str = ".shared-portable-restore.next";
const SHARED_GENESIS_INTENT_DOMAIN: &[u8] = b"vos/agent-host/shared-genesis-intent/v1";
const SHARED_PORTABLE_ROOT_PINS_DOMAIN: &[u8] = b"vos/agent-host/shared-portable-root-pins/v1";
const MAX_COMMON_CHECKPOINT_BUNDLE_BYTES: usize = MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES
    + super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES
    + super::shared_commit::MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES
    + super::shared_recovery::MAX_SHARED_RECOVERY_MANIFEST_BYTES
    + 4;
const MAX_COMMON_RESTORE_BYTES: usize = MAX_COMMON_CHECKPOINT_BUNDLE_BYTES
    + super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES
    + MAX_JOURNAL_RECORD_BYTES;

/// Hard discovery bound for one Shared host root.
pub const MAX_SHARED_HOST_AGENTS: usize = 4096;
/// The intent retains one complete finalized provision and its exact genesis
/// catalog preimages. Ordinary genesis currently has exactly one catalog
/// reference, but the aggregate bound remains explicit.
pub const MAX_SHARED_GENESIS_INTENT_BYTES: usize = super::genesis::MAX_AGENT_GENESIS_PROVISION_BYTES
    + super::bootstrap::MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES
    + super::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES
    + super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES as usize
    + 4096;
/// Absolute complete-wire ceiling for one singleton Shared system-Agent
/// portable recovery bundle.
pub const MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES: usize = MAX_PORTABLE_JOURNAL_IMAGE_BYTES
    + MAX_SHARED_GENESIS_INTENT_BYTES
    + MAX_ROOT_ANCHOR_PINS_BYTES
    + MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES
    + 4096;

type FileSharedDriver = SharedJournalAgentDriver<FileAgentJournalStore, FileSharedArtifactStager>;

/// Stable public projection of the bounded Shared-host failure boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentHostError {
    Unavailable,
    ProjectionExpired,
    DirectoryInUse,
    InvalidScope,
    ScopeMismatch,
    InvalidProvision,
    Finality(AgentGenesisFinalityError),
    InvalidCatalog,
    Conflict,
    CorruptResidue,
    AgentNotFound,
    CapacityExhausted,
    TransportNotAttached,
    SnapshotBoundaryRequired,
    SnapshotCertificateInvalid,
    SnapshotStale,
    SnapshotReplay,
    SnapshotEvidenceLimit,
    PortableBackupUnsupported,
    PortableBackupInvalid,
    /// A Shared replica change was refused before any Raft slot was used.
    CommitteeChangeRefused,
}

pub(crate) enum SharedAuthorityProjectionAudit {
    Ready(Vec<super::supervisor::AgentRouteIdentity>),
    Lag,
}

impl core::fmt::Display for SharedAgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Shared Agent host: {self:?}")
    }
}

impl core::error::Error for SharedAgentHostError {}

/// Transport remains an explicit attachment state rather than an inferred
/// consequence of a durable Raft file existing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentTransportState {
    NotAttached,
    /// The exact active generation/committee is owned by the clean
    /// `/vos/agent/1.0.0` route directory. This is process state only and is
    /// intentionally reconstructed after every restart.
    Attached,
}

/// Durable Agent-specific snapshot state. This never describes the generic
/// service snapshot format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedAgentSnapshotState {
    None,
    Installed {
        raft_index: u64,
        raft_term: u64,
        certificate: Hash,
    },
}

/// Successful exact snapshot installation. Journal cleanup is intentionally
/// reported separately by the bounded compaction API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentSnapshotInstall {
    pub raft_index: u64,
    pub raft_term: u64,
    pub certificate: Hash,
    pub journal_heads: super::journal::JournalHeadsId,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonCheckpointCrashStage {
    Marker,
    Journal,
    Ledger,
}

/// Opaque result of exact physical snapshot-candidate reconstruction.
///
/// Only [`SharedAgentHost::request_snapshot_compaction`] can construct this
/// token. It proves that this host compared the complete claim with its bound
/// journal and Raft generation. A remote voter must still reconstruct and
/// validate the authenticated evidence independently before signing; the
/// composite-network evidence exchange is not attached by this host.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentSnapshotCandidate {
    claim: SharedAgentSnapshotClaim,
    message: Hash,
}

impl VerifiedSharedAgentSnapshotCandidate {
    fn from_reconstructed(claim: SharedAgentSnapshotClaim) -> Self {
        let message = SharedAgentSnapshotCertificate::signing_message(
            claim.active_committee().id(),
            claim.commitment(),
        );
        Self { claim, message }
    }

    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }

    /// Domain-separated bytes an independently validating voter may sign.
    pub const fn signing_message(&self) -> Hash {
        self.message
    }
}

/// A common boundary independently reconstructed from this replica's own
/// journal and applied Raft history. Foreign physical heads are never votes.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentCommonSnapshotCandidate {
    claim: SharedAgentCommonSnapshotClaim,
    message: Hash,
}

/// Signing capability minted only from a fresh audited applied prefix and
/// the host's trusted clock. A decoded expiry claim is not this capability.
#[derive(Clone, Debug)]
pub struct VerifiedSharedRecoveryExpiryCandidate {
    claim: super::shared_recovery::SharedRecoveryExpiryClaim,
}

impl VerifiedSharedRecoveryExpiryCandidate {
    pub const fn claim(&self) -> &super::shared_recovery::SharedRecoveryExpiryClaim {
        &self.claim
    }
    pub fn signing_message(&self) -> Hash {
        self.claim.signing_message()
    }
}

impl VerifiedSharedAgentCommonSnapshotCandidate {
    fn from_reconstructed(claim: SharedAgentCommonSnapshotClaim) -> Self {
        let message = SharedAgentCommonSnapshotCertificate::signing_message(
            claim.active_committee().id(),
            claim.commitment(),
        );
        Self { claim, message }
    }

    pub const fn claim(&self) -> &SharedAgentCommonSnapshotClaim {
        &self.claim
    }
    pub const fn signing_message(&self) -> Hash {
        self.message
    }
}

/// Exact local physical binding of a verified common certificate. Only a
/// reconstructed local checkpoint (or validated destination rebind) mints it.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentLocalSnapshotCandidate {
    common_certificate: Hash,
    claim: SharedAgentSnapshotClaim,
    message: Hash,
}

impl VerifiedSharedAgentLocalSnapshotCandidate {
    #[cfg(test)]
    pub(crate) fn from_reconstructed_for_test(
        common_certificate: Hash,
        claim: SharedAgentSnapshotClaim,
    ) -> Self {
        Self::from_reconstructed(common_certificate, claim)
    }

    fn from_reconstructed(common_certificate: Hash, claim: SharedAgentSnapshotClaim) -> Self {
        let message = SharedAgentLocalSnapshotBinding::signing_message(
            common_certificate,
            claim.commitment(),
            claim.local_node(),
        );
        Self {
            common_certificate,
            claim,
            message,
        }
    }

    pub const fn common_certificate(&self) -> Hash {
        self.common_certificate
    }
    pub const fn claim(&self) -> &SharedAgentSnapshotClaim {
        &self.claim
    }
    pub const fn signing_message(&self) -> Hash {
        self.message
    }
}

/// Opaque result of reconstructing one exact source-store-independent
/// recovery claim. The returned message is the only byte string replicas
/// should sign for the subsequent aggregate export.
#[derive(Clone, Debug)]
pub struct VerifiedSharedAgentPortableBackupCandidate {
    claim: SharedAgentPortableSnapshotClaim,
    message: Hash,
}

impl VerifiedSharedAgentPortableBackupCandidate {
    fn from_reconstructed(claim: SharedAgentPortableSnapshotClaim) -> Self {
        let message = SharedAgentPortableSnapshotCertificate::signing_message(
            claim.active_committee().id(),
            claim.commitment(),
        );
        Self { claim, message }
    }

    pub const fn claim(&self) -> &SharedAgentPortableSnapshotClaim {
        &self.claim
    }

    pub const fn signing_message(&self) -> Hash {
        self.message
    }
}

/// Caller-selected work and allocation ceilings for one portable checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentPortableBackupLimits {
    pub max_objects: usize,
    pub max_blobs: usize,
    pub max_index_nodes: usize,
    pub max_bytes: u64,
}

impl SharedAgentPortableBackupLimits {
    fn journal(self) -> Result<PortableJournalLimits, SharedAgentHostError> {
        if self.max_objects == 0
            || self.max_objects > MAX_PORTABLE_JOURNAL_OBJECTS
            || self.max_blobs == 0
            || self.max_blobs > MAX_PORTABLE_JOURNAL_BLOBS
            || self.max_index_nodes == 0
            || self.max_bytes == 0
            || self.max_bytes > MAX_PORTABLE_JOURNAL_IMAGE_BYTES as u64
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        Ok(PortableJournalLimits {
            max_objects: self.max_objects,
            max_blobs: self.max_blobs,
            max_index_nodes: self.max_index_nodes,
            max_bytes: self.max_bytes,
        })
    }
}

/// Explicit bounds for one resumable post-snapshot journal cleanup pass.
/// Shared-binding validation additionally scans at most the fixed,
/// fail-closed Shared-binding namespace capacity; `max_binding_unlinks` caps
/// mutations, while the remaining fields cap generic journal traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentCompactionLimits {
    /// Maximum authenticated Shared-binding files physically removed.
    pub max_binding_unlinks: usize,
    pub max_index_nodes: usize,
    pub max_marked_objects: usize,
    pub max_marked_blobs: usize,
    pub max_scanned_files: usize,
    pub max_scanned_bytes: u64,
    pub max_unlinks: usize,
}

/// Exact physical work completed in one bounded pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentCompaction {
    pub bindings_removed: usize,
    pub bindings_remaining: usize,
    pub objects_removed: usize,
    pub blobs_removed: usize,
    pub aliases_removed: usize,
    pub resumed: bool,
    pub complete: bool,
}

/// Engines required by the currently admitted actor directory. Control is
/// always ordered for a Shared Agent; the actor-selected data lanes are
/// reported independently so a future transport coordinator creates no
/// unused Merge engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedAgentEnginePlan {
    pub control_raft: bool,
    pub linear_raft: bool,
    pub merge: bool,
    pub local: bool,
}

/// Exact authority-certified transport identity of one active replica.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedReplicaRoute {
    pub node: NodeId,
    pub role: ReplicaRole,
    pub peer_id: Vec<u8>,
    pub ed25519_public_key: [u8; 32],
    pub raft_slot: Option<u16>,
}

/// Authenticated next-committee route visible while the durable committee
/// transition is prepared or joint. These replicas may be transport/Merge
/// members before the stable leg makes them the active journal authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedCommitteeTransitionRoute {
    pub next_committee: super::genesis::AgentReplicaCommitteeId,
    pub next_replicas: Vec<SharedReplicaRoute>,
    pub joint: bool,
}

/// Public status for one physical generation. `remaining_slots` is a hard
/// bound, not an uptime estimate: reaching zero rejects the next application
/// before artifact, journal, reservation, or Raft-apply mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentStatus {
    pub identity: AgentIdentity,
    pub generation: AgentGenerationRouteKey,
    pub route: AgentRouteKey,
    pub replication_id: [u8; 32],
    pub local_role: Option<ReplicaRole>,
    pub replicas: Vec<SharedReplicaRoute>,
    pub committee_transition: Option<SharedCommitteeTransitionRoute>,
    pub engines: SharedAgentEnginePlan,
    pub applied_slots: u64,
    pub remaining_slots: u64,
    pub reservation_pending: bool,
    pub transport: SharedAgentTransportState,
    pub snapshots: SharedAgentSnapshotState,
}

/// Attachment facts which do not require executing a full actor-directory
/// projection. Invocation dispatch uses this view while holding the network
/// generation lease, then performs one keyed actor/material lookup. The full
/// [`SharedAgentStatus`] remains the administrative surface and may derive
/// aggregate engine lanes from the complete bounded directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedAgentAttachmentStatus {
    pub(crate) identity: AgentIdentity,
    pub(crate) generation: AgentGenerationRouteKey,
    pub(crate) route: AgentRouteKey,
    pub(crate) replication_id: [u8; 32],
    pub(crate) local_role: Option<ReplicaRole>,
    pub(crate) replicas: Vec<SharedReplicaRoute>,
    pub(crate) committee_transition: Option<SharedCommitteeTransitionRoute>,
    pub(crate) transport: SharedAgentTransportState,
    /// The local node is an explicit joiner not yet named by any committee.
    pub(crate) joining: bool,
}

/// Exact SDK identity projection reconstructed from one authenticated Shared
/// journal image while the host boundary is locked. This is deliberately
/// narrower than a host handle: it carries no storage, consensus, or legacy
/// Service identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedAgentRuntimeProjection {
    pub(crate) descriptor: crate::agent_sdk::AgentDescriptor,
    pub(crate) actors: Vec<crate::agent_sdk::ActorDirectoryRecord>,
}

/// Exact journal position needed to construct the next candidate outside the
/// physical apply boundary. It is observational and grants no commit power.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentJournalPosition {
    pub genesis: AgentJournalGenesisId,
    pub admission: super::genesis::AgentGenesisAdmissionId,
    pub ordered_index: u64,
    pub ordered_head: Option<OrderedEntryId>,
    pub merge_frontier: MergeFrontierId,
    pub runtime: RuntimeBinding,
}

/// Filesystem route handed to an Agent-specific consensus coordinator. The
/// path alone is not evidence that a transport is attached or a slot is
/// committed; application still reads the database's durable commit cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedAgentPhysicalRoute {
    pub generation: AgentGenerationRouteKey,
    pub replication_id: [u8; 32],
    pub raft_database: PathBuf,
}

/// Result of applying one already committed physical slot or importing one
/// authenticated Merge event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedAgentApplyOutcome {
    Applied { index: u64 },
    Duplicate { index: u64 },
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SharedGenesisAuthority {
    AuthorityFinalized(AgentGenesisProvision),
    SystemBootstrap {
        provision: SystemAgentGenesisProvision,
        committee: AgentReplicaCommittee,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedGenesisIntent {
    authority: SharedGenesisAuthority,
    catalog: Vec<RuntimeBlob>,
    committee_authority: CommitteeChangeAuthorityBinding,
}

impl SharedGenesisIntent {
    /// Common catch-up keeps each member's independently admitted physical
    /// genesis. Only the replica/locator node may differ; all certified
    /// common Create and authority material must be identical.
    fn same_common_system_generation(&self, other: &Self) -> bool {
        let mut rebound = self.clone();
        let (
            SharedGenesisAuthority::SystemBootstrap { provision, .. },
            SharedGenesisAuthority::SystemBootstrap {
                provision: target, ..
            },
        ) = (&mut rebound.authority, &other.authority)
        else {
            return false;
        };
        let Ok(rebound_provision) = provision.rebind_replica(target.proposal().replica()) else {
            return false;
        };
        *provision = rebound_provision;
        rebound == *other
    }

    fn new(
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<Self, SharedAgentHostError> {
        let intent = Self {
            authority: SharedGenesisAuthority::AuthorityFinalized(provision),
            catalog,
            committee_authority,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn new_system_bootstrap(
        provision: SystemAgentGenesisProvision,
        committee: AgentReplicaCommittee,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<Self, SharedAgentHostError> {
        let intent = Self {
            authority: SharedGenesisAuthority::SystemBootstrap {
                provision,
                committee,
            },
            catalog,
            committee_authority,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), SharedAgentHostError> {
        let is_shared = match &self.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => {
                provision
                    .validate()
                    .map_err(|_| SharedAgentHostError::InvalidProvision)?;
                validate_agent_genesis_catalog(provision.proposal(), &self.catalog)
                    .map_err(|_| SharedAgentHostError::InvalidCatalog)?;
                provision
                    .proposal()
                    .clean_descriptor()
                    .map(|descriptor| {
                        descriptor.identity.profile == crate::agent_sdk::AgentProfile::Shared
                    })
                    .map_err(|_| SharedAgentHostError::InvalidProvision)?
            }
            SharedGenesisAuthority::SystemBootstrap {
                provision,
                committee,
            } => {
                provision
                    .validate()
                    .map_err(|_| SharedAgentHostError::InvalidProvision)?;
                validate_system_agent_genesis_catalog(provision.proposal(), &self.catalog)
                    .map_err(|_| SharedAgentHostError::InvalidCatalog)?;
                let descriptor = clean_system_bootstrap_descriptor(provision)?;
                if committee.validate().is_err()
                    || committee.profile() != AgentProfile::Shared
                    || committee.space().0 != descriptor.identity.space.0
                    || committee.agent().0 != descriptor.identity.agent.0
                    || !matches!(committee.members().len(), 1 | 3)
                    || committee.members().len() != descriptor.replicas.len()
                    || !committee.members().iter().all(|member| {
                        super::bootstrap::descriptor_matches_root_replica(
                            descriptor,
                            member.replica(),
                        )
                    })
                    || committee
                        .member_by_node(provision.proposal().replica().node)
                        .map(|member| member.replica())
                        != Some(provision.proposal().replica())
                {
                    return Err(SharedAgentHostError::InvalidProvision);
                }
                true
            }
        };
        if !is_shared
            || CommitteeChangeAuthorityBinding::decode(&self.committee_authority.encode())
                .ok()
                .as_ref()
                != Some(&self.committee_authority)
            || self.catalog.iter().any(|blob| {
                blob.bytes.len() > super::MAX_CATALOG_ARTIFACT_BYTES as usize
                    || !blob.reference.matches(&blob.bytes)
            })
        {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        let encoded = self.encode();
        if encoded.len() > MAX_SHARED_GENESIS_INTENT_BYTES {
            return Err(SharedAgentHostError::InvalidCatalog);
        }
        Ok(())
    }

    fn agent(&self) -> Result<AgentId, SharedAgentHostError> {
        match &self.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => provision
                .proposal()
                .clean_descriptor()
                .map(|descriptor| AgentId(descriptor.identity.agent.0))
                .map_err(|_| SharedAgentHostError::InvalidProvision),
            SharedGenesisAuthority::SystemBootstrap { provision, .. } => {
                Ok(provision.proposal().locator().agent)
            }
        }
    }

    fn space(&self) -> crate::service::SpaceId {
        match &self.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => {
                provision.proposal().locator().space
            }
            SharedGenesisAuthority::SystemBootstrap { provision, .. } => {
                provision.proposal().locator().space
            }
        }
    }

    fn committee(&self) -> &AgentReplicaCommittee {
        match &self.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => provision.replicas(),
            SharedGenesisAuthority::SystemBootstrap { committee, .. } => committee,
        }
    }

    fn id(&self) -> Hash {
        Hash::digest(SHARED_GENESIS_INTENT_DOMAIN, &[&self.encode()])
    }
}

fn clean_system_bootstrap_descriptor(
    provision: &SystemAgentGenesisProvision,
) -> Result<&crate::agent_sdk::AgentDescriptor, SharedAgentHostError> {
    let super::journal::ReplayOperation::CleanManage {
        request: crate::agent_sdk::ManagementRequest::Create(descriptor),
        ..
    } = &provision.proposal().create().operation
    else {
        return Err(SharedAgentHostError::InvalidProvision);
    };
    Ok(descriptor)
}

impl ServiceWire for SharedGenesisIntent {
    const MAGIC: [u8; 4] = *b"AGSI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        match &self.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => {
                encoder.u8(0);
                encoder.bytes(&provision.encode());
            }
            SharedGenesisAuthority::SystemBootstrap {
                provision,
                committee,
            } => {
                encoder.u8(1);
                encoder.bytes(&provision.encode());
                encoder.bytes(&committee.encode());
            }
        }
        encoder.u32(self.catalog.len() as u32);
        for blob in &self.catalog {
            encoder.fixed(&blob.reference.hash.0);
            encoder.u64(blob.reference.len);
            encoder.bytes(&blob.bytes);
        }
        encoder.bytes(&self.committee_authority.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_SHARED_GENESIS_INTENT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let authority = match decoder.u8()? {
            0 => SharedGenesisAuthority::AuthorityFinalized(AgentGenesisProvision::decode(
                &decoder.bytes()?,
            )?),
            1 => SharedGenesisAuthority::SystemBootstrap {
                provision: SystemAgentGenesisProvision::decode(&decoder.bytes()?)?,
                committee: AgentReplicaCommittee::decode(&decoder.bytes()?)?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        let count = decoder.u32()? as usize;
        if count > super::MAX_CATALOG_ARTIFACT_REFERENCES as usize {
            return Err(DecodeError::LimitExceeded);
        }
        let mut catalog = Vec::new();
        catalog
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..count {
            let reference = BlobRef {
                hash: Hash(decoder.fixed()?),
                len: decoder.u64()?,
            };
            let bytes = decoder.bytes()?;
            catalog.push(RuntimeBlob { reference, bytes });
        }
        let committee_authority = CommitteeChangeAuthorityBinding::decode(&decoder.bytes()?)?;
        let intent = Self {
            authority,
            catalog,
            committee_authority,
        };
        intent.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(intent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedAgentPortableBackupBundle {
    intent: SharedGenesisIntent,
    root_pins: RootAnchorPins,
    certificate: SharedAgentPortableSnapshotCertificate,
    journal: PortableJournalCheckpoint,
}

#[derive(Clone, Debug)]
struct PreparedPortableRestore {
    bundle: SharedAgentPortableBackupBundle,
    verified: VerifiedSharedAgentPortableSnapshot,
    maximum_index_nodes: usize,
    stage_heads_only_for_test: bool,
}

/// Source bytes are kept intact. Destination metadata is separately derived
/// and authenticated; neither AGS3 nor AGP1 silently changes meaning here.
#[derive(Clone, Debug)]
struct CommonCheckpointBundle {
    intent: SharedGenesisIntent,
    root_pins: RootAnchorPins,
    certificate: SharedAgentCommonSnapshotCertificate,
    binding: SharedAgentLocalSnapshotBinding,
    journal: PortableJournalCheckpoint,
    recovery: Option<super::shared_recovery::SharedRecoveryManifest>,
}

impl CommonCheckpointBundle {
    fn recovery_manifest_for_restore(
        &self,
    ) -> Result<super::shared_recovery::SharedRecoveryManifest, SharedAgentHostError> {
        self.validate()?;
        if let Some(manifest) = &self.recovery {
            return Ok(manifest.clone());
        }
        let ordered = self.certificate.claim().ordered();
        let generation = AgentGenerationRouteKey::new(
            ordered.space(),
            ordered.agent(),
            ordered.genesis(),
            ordered.admission(),
        )
        .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        super::shared_recovery::SharedRecoveryManifest::new(
            generation,
            self.certificate.claim().active_committee().clone(),
        )
        .map_err(|_| SharedAgentHostError::PortableBackupInvalid)
    }

    fn validate(&self) -> Result<(), SharedAgentHostError> {
        self.intent.validate()?;
        self.root_pins
            .validate()
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        self.journal
            .validate_shape()
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        let SharedGenesisAuthority::SystemBootstrap {
            provision,
            committee,
        } = &self.intent.authority
        else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        let claim = self.binding.claim();
        match (&self.recovery, self.certificate.claim().recovery_manifest()) {
            (None, None) => {}
            (Some(recovery), Some(commitment)) => {
                let generation = AgentGenerationRouteKey::new(
                    claim.ordered().space(),
                    claim.ordered().agent(),
                    claim.ordered().genesis(),
                    claim.ordered().admission(),
                )
                .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
                recovery
                    .validate_at_raft_index(claim.raft_index())
                    .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
                if recovery.generation() != generation
                    || recovery.committee() != committee
                    || recovery.commitment() != commitment
                {
                    return Err(SharedAgentHostError::PortableBackupInvalid);
                }
            }
            _ => return Err(SharedAgentHostError::PortableBackupInvalid),
        }
        if provision.root() != &self.root_pins
            || self.certificate.claim().active_committee() != committee
            || provision.proposal().replica().node != claim.local_node()
            || claim.authority_epoch() != self.intent.committee_authority.initial_epoch()
            || claim.ordered().space() != self.intent.space()
            || claim.ordered().agent() != self.intent.agent()?
            || claim.journal_heads() != self.journal.heads().id()
            || claim.local_node() != self.journal.heads().node
            || self.journal.heads().genesis != claim.ordered().genesis()
            || self.journal.heads().admission != claim.ordered().admission()
            || self.encode().len() > MAX_COMMON_CHECKPOINT_BUNDLE_BYTES
        {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        self.binding
            .verify(&self.certificate, claim)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        Ok(())
    }
}

fn decode_common_field<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    let value = T::decode(bytes)?;
    if value.encode() != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

impl ServiceWire for CommonCheckpointBundle {
    const MAGIC: [u8; 4] = *b"ACB1";
    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(if self.recovery.is_some() {
            b"ACB2"
        } else {
            &Self::MAGIC
        });
        output.extend_from_slice(&crate::service::PLATFORM_ID.0);
        self.encode_body(&mut output);
        output
    }
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let recovery = match decoder.take(4)? {
            b"ACB1" => false,
            b"ACB2" => true,
            _ => return Err(DecodeError::InvalidTag),
        };
        if Hash(decoder.fixed()?) != crate::service::PLATFORM_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self::decode_body(&mut decoder)?;
        if !decoder.exhausted() || value.recovery.is_some() != recovery {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.intent.encode());
        encoder.bytes(&self.root_pins.encode());
        encoder.bytes(&self.certificate.encode());
        encoder.bytes(&self.binding.encode());
        encoder.bytes(&self.journal.encode());
        if let Some(recovery) = &self.recovery {
            encoder.bytes(&recovery.encode());
        }
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_COMMON_CHECKPOINT_BUNDLE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let bundle = Self {
            intent: decode_common_field(decoder, MAX_SHARED_GENESIS_INTENT_BYTES)?,
            root_pins: decode_common_field(decoder, MAX_ROOT_ANCHOR_PINS_BYTES)?,
            certificate: decode_common_field(
                decoder,
                super::shared_commit::MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
            )?,
            binding: decode_common_field(
                decoder,
                super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
            )?,
            journal: decode_common_field(decoder, MAX_PORTABLE_JOURNAL_IMAGE_BYTES)?,
            recovery: if decoder.exhausted() {
                None
            } else {
                Some(decode_common_field(
                    decoder,
                    super::shared_recovery::MAX_SHARED_RECOVERY_MANIFEST_BYTES,
                )?)
            },
        };
        bundle.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(bundle)
    }
}

#[derive(Clone, Debug)]
struct CommonRestoreRecord {
    bundle: CommonCheckpointBundle,
    predecessor: super::journal::JournalHeads,
    binding: SharedAgentLocalSnapshotBinding,
}

#[derive(Clone, Debug)]
struct CommonInstallRecord {
    intent: Hash,
    certificate: SharedAgentCommonSnapshotCertificate,
    binding: SharedAgentLocalSnapshotBinding,
    predecessor: super::journal::JournalHeads,
    target: super::journal::JournalHeads,
    logical: super::shared_commit::OrderedCommitClaim,
}

impl CommonInstallRecord {
    fn validate(&self) -> Result<(), SharedAgentHostError> {
        self.predecessor
            .validate_successor(&self.target)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let physical = self.binding.claim();
        if self.intent == Hash::ZERO
            || physical.journal_heads() != self.target.id()
            || physical.checkpoint_predecessor() != self.predecessor.id()
            || self.target.checkpoint != Some(physical.checkpoint())
            || self.target.node != physical.local_node()
            || self.predecessor.ordered_head != self.target.ordered_head
            || self.predecessor.ordered_index != self.target.ordered_index
            || self.logical.ordered() != self.certificate.claim().ordered().ordered()
            || self.logical.genesis() != self.target.genesis
            || self.logical.admission() != self.target.admission
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        self.binding
            .verify(&self.certificate, physical)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        Ok(())
    }
}

impl ServiceWire for CommonInstallRecord {
    const MAGIC: [u8; 4] = *b"ACL1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.intent.0);
        encoder.bytes(&self.certificate.encode());
        encoder.bytes(&self.binding.encode());
        encoder.bytes(&self.predecessor.encode());
        encoder.bytes(&self.target.encode());
        encoder.bytes(&self.logical.encode());
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_COMMON_RESTORE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let record = Self {
            intent: Hash(decoder.fixed()?),
            certificate: decode_common_field(
                decoder,
                super::shared_commit::MAX_SHARED_AGENT_COMMON_SNAPSHOT_CERTIFICATE_BYTES,
            )?,
            binding: decode_common_field(
                decoder,
                super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
            )?,
            predecessor: decode_common_field(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            target: decode_common_field(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            logical: decode_common_field(
                decoder,
                super::shared_commit::MAX_ORDERED_COMMIT_CLAIM_BYTES,
            )?,
        };
        record.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(record)
    }
}

impl ServiceWire for CommonRestoreRecord {
    const MAGIC: [u8; 4] = *b"ACR1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.bundle.encode());
        encoder.bytes(&self.predecessor.encode());
        encoder.bytes(&self.binding.encode());
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_COMMON_RESTORE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let record = Self {
            bundle: decode_common_field(decoder, MAX_COMMON_CHECKPOINT_BUNDLE_BYTES)?,
            predecessor: decode_common_field(decoder, MAX_JOURNAL_RECORD_BYTES)?,
            binding: decode_common_field(
                decoder,
                super::shared_commit::MAX_SHARED_AGENT_LOCAL_SNAPSHOT_BINDING_BYTES,
            )?,
        };
        let claim = record.binding.claim();
        if record.predecessor.id() != claim.checkpoint_predecessor()
            || record.predecessor.node != claim.local_node()
            || record.predecessor.genesis != claim.ordered().genesis()
            || record.predecessor.admission != claim.ordered().admission()
            || record.predecessor.ordered_index > claim.ordered().ordered().index
        {
            return Err(DecodeError::NonCanonical);
        }
        record
            .binding
            .verify(&record.bundle.certificate, claim)
            .map_err(|_| DecodeError::NonCanonical)?;
        Ok(record)
    }
}

/// Source identity is used only for independent read-only reconstruction.
/// This object cannot sign any event or claim on the source node's behalf.
struct CommonSnapshotReadOnlyNode(NodeId);
impl LocalMergeAuthenticator for CommonSnapshotReadOnlyNode {
    fn node(&self) -> NodeId {
        self.0
    }
    fn sign_event(&self, _: &mut MergeEvent) -> bool {
        false
    }
    fn verify_event(&self, _: &MergeEvent) -> bool {
        false
    }
}

fn absolute_portable_journal_limits() -> PortableJournalLimits {
    PortableJournalLimits {
        max_objects: MAX_PORTABLE_JOURNAL_OBJECTS,
        max_blobs: MAX_PORTABLE_JOURNAL_BLOBS,
        max_index_nodes: MAX_PORTABLE_JOURNAL_OBJECTS,
        max_bytes: MAX_PORTABLE_JOURNAL_IMAGE_BYTES as u64,
    }
}

impl SharedAgentPortableBackupBundle {
    fn validate(&self) -> Result<VerifiedSharedAgentPortableSnapshot, SharedAgentHostError> {
        self.intent.validate()?;
        self.root_pins
            .validate()
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        self.journal
            .validate_shape()
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        let SharedGenesisAuthority::SystemBootstrap {
            provision,
            committee,
        } = &self.intent.authority
        else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        let claim = self.certificate.claim();
        if provision.root() != &self.root_pins
            || claim.genesis_intent() != self.intent.id()
            || claim.root_pins() != portable_root_pins_commitment(&self.root_pins)
            || claim.active_committee() != committee
            || claim.ordered().space() != self.intent.space()
            || claim.ordered().agent() != self.intent.agent()?
            || claim.local_node() != self.journal.heads().node
            || claim.ordered().genesis() != self.journal.heads().genesis
            || claim.ordered().admission() != self.journal.heads().admission
            || claim.journal_heads() != self.journal.heads().id()
            || claim.checkpoint()
                != self
                    .journal
                    .heads()
                    .checkpoint
                    .ok_or(SharedAgentHostError::PortableBackupInvalid)?
            || claim.journal_image() != self.journal.commitment()
        {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        let verified = self
            .certificate
            .verify(committee, claim)
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        if self.encode().len() > MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        Ok(verified)
    }
}

impl ServiceWire for SharedAgentPortableBackupBundle {
    const MAGIC: [u8; 4] = *b"ASB1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.intent.encode());
        encoder.bytes(&self.root_pins.encode());
        encoder.bytes(&self.certificate.encode());
        encoder.bytes(&self.journal.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining()
            > MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES
                .checked_sub(4 + 32)
                .ok_or(DecodeError::LimitExceeded)?
        {
            return Err(DecodeError::LimitExceeded);
        }
        let intent_bytes = decoder.bytes()?;
        if intent_bytes.len() > MAX_SHARED_GENESIS_INTENT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let root_bytes = decoder.bytes()?;
        if root_bytes.len() > MAX_ROOT_ANCHOR_PINS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let certificate_bytes = decoder.bytes()?;
        if certificate_bytes.len() > MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let journal_bytes = decoder.bytes()?;
        if journal_bytes.len() > MAX_PORTABLE_JOURNAL_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let bundle = Self {
            intent: SharedGenesisIntent::decode(&intent_bytes)?,
            root_pins: RootAnchorPins::decode(&root_bytes)?,
            certificate: SharedAgentPortableSnapshotCertificate::decode(&certificate_bytes)?,
            journal: PortableJournalCheckpoint::decode(&journal_bytes)?,
        };
        bundle.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(bundle)
    }
}

fn portable_root_pins_commitment(root_pins: &RootAnchorPins) -> Hash {
    Hash::digest(SHARED_PORTABLE_ROOT_PINS_DOMAIN, &[&root_pins.encode()])
}

enum PreparedSharedGenesis {
    AuthorityFinalized(super::replay::ReplaySealedSharedGenesis),
    SystemBootstrap(super::replay::ReplaySealedGenesis),
    #[cfg(feature = "experimental-state-blocks")]
    ExternalAuthorityFinalized(Arc<super::replay::ReplaySealedExternalGenesis>),
}

impl PreparedSharedGenesis {
    fn genesis(&self) -> &super::journal::AgentJournalGenesis {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.genesis(),
            Self::SystemBootstrap(sealed) => sealed.genesis(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.genesis(),
        }
    }

    fn admission_record(&self) -> &super::genesis::AgentGenesisAdmissionRecord {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.admission_record(),
            Self::SystemBootstrap(sealed) => sealed.admission_record(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => {
                ReplaySealedOrdinaryGenesis::admission_record(sealed.as_ref())
                    .expect("Shared external genesis has finalized admission")
            }
        }
    }
}

impl super::replay::ReplaySealedOrdinaryGenesis for PreparedSharedGenesis {
    fn genesis(&self) -> &super::journal::AgentJournalGenesis {
        self.genesis()
    }

    fn post_create(&self) -> &super::wire::RuntimeState {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.post_create(),
            Self::SystemBootstrap(sealed) => sealed.post_create(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.post_create(),
        }
    }

    fn empty_frontier(&self) -> &super::journal::MergeFrontier {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.empty_frontier(),
            Self::SystemBootstrap(sealed) => sealed.empty_frontier(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.empty_frontier(),
        }
    }

    fn ordered_invocations(&self) -> &super::journal::InvocationIndexManifest {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.ordered_invocations(),
            Self::SystemBootstrap(sealed) => sealed.ordered_invocations(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.ordered_invocations(),
        }
    }

    fn merge_invocations(&self) -> &super::journal::InvocationIndexManifest {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.merge_invocations(),
            Self::SystemBootstrap(sealed) => sealed.merge_invocations(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.merge_invocations(),
        }
    }

    fn local_invocations(&self) -> &super::journal::InvocationIndexManifest {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.local_invocations(),
            Self::SystemBootstrap(sealed) => sealed.local_invocations(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.local_invocations(),
        }
    }

    fn artifacts(&self) -> &super::journal::ArtifactClosure {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.artifacts(),
            Self::SystemBootstrap(sealed) => sealed.artifacts(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.artifacts(),
        }
    }

    fn replica(&self) -> super::AgentReplica {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.replica(),
            Self::SystemBootstrap(sealed) => sealed.replica(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.replica(),
        }
    }

    fn admission_commitment(&self) -> Hash {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.admission_commitment(),
            Self::SystemBootstrap(sealed) => sealed.admission_commitment(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.admission_commitment(),
        }
    }

    fn lane_manifest(
        &self,
        lane: super::journal::PersistedLane,
    ) -> super::journal::LaneStateManifest {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.lane_manifest(lane),
            Self::SystemBootstrap(sealed) => sealed.lane_manifest(lane),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.lane_manifest(lane),
        }
    }

    fn initial_heads(&self) -> super::journal::JournalHeads {
        match self {
            Self::AuthorityFinalized(sealed) => sealed.initial_heads(),
            Self::SystemBootstrap(sealed) => sealed.initial_heads(),
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => {
                ReplaySealedOrdinaryGenesis::initial_heads(sealed.as_ref())
            }
        }
    }

    fn validates_post_create_state(&self) -> bool {
        match self {
            Self::AuthorityFinalized(sealed) => {
                super::replay::ReplaySealedOrdinaryGenesis::validates_post_create_state(sealed)
            }
            Self::SystemBootstrap(sealed) => {
                super::replay::ReplaySealedOrdinaryGenesis::validates_post_create_state(sealed)
            }
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => {
                ReplaySealedOrdinaryGenesis::validates_post_create_state(sealed.as_ref())
            }
        }
    }

    fn admission_record(&self) -> Option<&super::genesis::AgentGenesisAdmissionRecord> {
        Some(self.admission_record())
    }

    fn validate_seal(&self) -> Result<(), super::replay::ReplayValidationError> {
        match self {
            Self::AuthorityFinalized(sealed) => {
                super::replay::ReplaySealedOrdinaryGenesis::validate_seal(sealed)
            }
            Self::SystemBootstrap(sealed) => {
                super::replay::ReplaySealedOrdinaryGenesis::validate_seal(sealed)
            }
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.validate_seal(),
        }
    }

    fn genesis_checkpoint(&self) -> Option<super::journal::CheckpointManifest> {
        match self {
            #[cfg(feature = "experimental-state-blocks")]
            Self::ExternalAuthorityFinalized(sealed) => sealed.genesis_checkpoint(),
            _ => None,
        }
    }
}

/// Process-selected admission mode, never inferred from files on disk. The
/// candidate mode still requires the signed Linear-only external contract.
#[derive(Clone, Copy)]
enum SharedExecutionSelection {
    ImageOnly,
    #[cfg(feature = "experimental-state-blocks")]
    ExternalLinearCandidates,
}

struct HostedSharedAgent {
    intent: SharedGenesisIntent,
    raft_path: PathBuf,
    driver: FileSharedDriver,
}

/// Process-only ownership of the live network/storage boundary. Every
/// non-detached state blocks snapshot database replacement and journal GC:
/// both operations would invalidate a worker cache or anti-entropy walk even
/// while route setup or ordered shutdown is still in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportLeaseState {
    Attaching,
    Attached,
    Stopping,
}

/// Serialized owner of a directory containing independently durable Shared
/// Agent replicas. Callers may place this behind their own command queue; the
/// type itself intentionally requires `&mut self` for every mutation.
pub struct SharedAgentHost {
    lease: AgentHostRootLease,
    agents: BTreeMap<AgentId, HostedSharedAgent>,
    transport_leases: BTreeMap<AgentId, TransportLeaseState>,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    finality: Arc<dyn AgentGenesisFinalityVerifier>,
    root_pins: Option<RootAnchorPins>,
    execution_selection: SharedExecutionSelection,
    // Unserved generations: the complete startup set when deferred_open is
    // true, or individually staged live Creates while existing Agents serve.
    deferred_generations: BTreeMap<AgentId, GenerationFiles>,
    deferred_open: bool,
    #[cfg(test)]
    common_checkpoint_crash: Option<CommonCheckpointCrashStage>,
}

impl SharedAgentHost {
    #[cfg(test)]
    pub(crate) fn set_common_checkpoint_crash_for_test(
        &mut self,
        stage: CommonCheckpointCrashStage,
    ) {
        self.common_checkpoint_crash = Some(stage);
    }

    #[cfg(test)]
    pub(crate) fn common_checkpoint_crash_pending_for_test(&self) -> bool {
        self.common_checkpoint_crash.is_some()
    }

    #[cfg(test)]
    pub(crate) fn common_checkpoint_install_endpoints_for_test(
        &mut self,
        agent: AgentId,
    ) -> Result<
        Option<(super::journal::JournalHeads, super::journal::JournalHeads)>,
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let Some(bytes) =
            read_host_record_pair(&self.portable_restore_path(agent), MAX_COMMON_RESTORE_BYTES)?
        else {
            return Ok(None);
        };
        let record = CommonInstallRecord::decode(&bytes)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if record.encode() != bytes
            || record.target.runtime.agent != agent
            || record.target.node != self.scope().node
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(Some((record.predecessor, record.target)))
    }

    #[cfg(test)]
    fn common_checkpoint_crash_at(
        &mut self,
        stage: CommonCheckpointCrashStage,
    ) -> Result<(), SharedAgentHostError> {
        if self.common_checkpoint_crash == Some(stage) {
            self.common_checkpoint_crash = None;
            return Err(SharedAgentHostError::Unavailable);
        }
        Ok(())
    }
    /// Acquire a stable outer lease and reopen every discoverable Shared
    /// generation. No generation is returned until live finality and complete
    /// physical recovery succeed.
    pub fn open(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::open_with_optional_root(root, stable_lock_path, scope, trust, merge, finality, None)
    }

    /// Open a host which may additionally contain the exact root/QC-admitted
    /// clean system Agent. The pins are an independent daemon input and are
    /// never recovered from the host's own genesis intent.
    pub(crate) fn open_with_root(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, SharedAgentHostError> {
        root_pins
            .validate()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        Self::open_with_optional_root(
            root,
            stable_lock_path,
            scope,
            trust,
            merge,
            finality,
            Some(root_pins),
        )
    }

    fn open_with_optional_root(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: Option<RootAnchorPins>,
    ) -> Result<Self, SharedAgentHostError> {
        let lease = AgentHostRootLease::acquire(root, stable_lock_path, scope)
            .map_err(map_outer_lease_error)?;
        Self::open_with_lease_and_root(lease, trust, merge, finality, root_pins)
    }

    /// Reopen is intentionally an alias with no weaker recovery mode.
    pub fn reopen(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::open(root, stable_lock_path, scope, trust, merge, finality)
    }

    pub fn open_with_lease(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::open_with_lease_and_root(lease, trust, merge, finality, None)
    }

    fn open_with_lease_and_root(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: Option<RootAnchorPins>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::open_with_lease_and_root_mode(
            lease,
            trust,
            merge,
            finality,
            root_pins,
            None,
            SharedExecutionSelection::ImageOnly,
        )
    }

    /// Internal, unpromoted fixed-three candidate owner. The caller must select
    /// this mode again on reopen; persisted external files cannot opt a public
    /// image-only owner into a different executor. System bootstrap remains
    /// image-backed and ordinary external admissions retain their signed ABI,
    /// Linear-only capability checks and real Authority finality.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn open_external_candidates(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: Option<RootAnchorPins>,
    ) -> Result<Self, SharedAgentHostError> {
        if let Some(pins) = &root_pins {
            pins.validate()
                .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        }
        let lease = AgentHostRootLease::acquire(root, stable_lock_path, scope)
            .map_err(map_outer_lease_error)?;
        Self::open_with_lease_and_root_mode(
            lease,
            trust,
            merge,
            finality,
            root_pins,
            None,
            SharedExecutionSelection::ExternalLinearCandidates,
        )
    }

    /// Internal startup phase: retain the outer lease while opening only the
    /// independently selected system Agent. Ordinary generations remain hidden
    /// until `reopen_deferred_generations` verifies all their finality.
    pub(crate) fn open_system_first(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: RootAnchorPins,
        system_agent: AgentId,
    ) -> Result<Self, SharedAgentHostError> {
        root_pins
            .validate()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        if system_agent == AgentId::ZERO {
            return Err(SharedAgentHostError::InvalidScope);
        }
        let lease = AgentHostRootLease::acquire(root, stable_lock_path, scope)
            .map_err(map_outer_lease_error)?;
        Self::open_with_lease_and_root_mode(
            lease,
            trust,
            merge,
            finality,
            Some(root_pins),
            Some(system_agent),
            SharedExecutionSelection::ImageOnly,
        )
    }

    fn open_with_lease_and_root_mode(
        mut lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
        root_pins: Option<RootAnchorPins>,
        only_system: Option<AgentId>,
        execution_selection: SharedExecutionSelection,
    ) -> Result<Self, SharedAgentHostError> {
        if lease.scope().validate().is_err() || merge.node() != lease.scope().node {
            return Err(SharedAgentHostError::InvalidScope);
        }
        lease.validate_live().map_err(map_outer_lease_error)?;
        let files = scan_generation_namespaces(&lease)?;
        let mut host = Self {
            lease,
            agents: BTreeMap::new(),
            transport_leases: BTreeMap::new(),
            trust,
            merge,
            finality,
            root_pins,
            execution_selection,
            deferred_generations: BTreeMap::new(),
            deferred_open: only_system.is_some(),
            #[cfg(test)]
            common_checkpoint_crash: None,
        };
        for (agent, mut files) in files {
            if only_system.is_some_and(|system| agent != system) {
                host.deferred_generations.insert(agent, files);
                continue;
            }
            #[cfg(test)]
            if let Some(record) = host.read_common_install(agent, files)? {
                let hosted = host.resume_common_install(agent, files, &record)?;
                retire_host_record(&host.portable_restore_path(agent))?;
                if host.agents.insert(agent, hosted).is_some() {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
                continue;
            }
            if let Some(record) = host.read_common_restore(agent, files)? {
                let hosted = host.resume_common_restore(agent, files, &record)?;
                retire_host_record(&host.portable_restore_path(agent))?;
                if host.agents.insert(agent, hosted).is_some() {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
                continue;
            }
            let recovery = host.read_portable_restore(agent, files)?;
            let (intent, encoded) = if let Some(recovery) = &recovery {
                if files.intent || files.intent_stage {
                    let (intent, encoded) = host.read_intent(agent, files)?;
                    if intent != recovery.bundle.intent {
                        return Err(SharedAgentHostError::CorruptResidue);
                    }
                    (intent, encoded)
                } else {
                    (
                        recovery.bundle.intent.clone(),
                        recovery.bundle.intent.encode(),
                    )
                }
            } else {
                host.read_intent(agent, files)?
            };
            if only_system.is_some()
                && !matches!(
                    intent.authority,
                    SharedGenesisAuthority::SystemBootstrap { .. }
                )
            {
                return Err(SharedAgentHostError::InvalidProvision);
            }
            // A retained non-member intent was written only by explicit
            // joiner provisioning; reopen it as that joiner.
            let sealed =
                host.verify_and_prepare_with_role(&intent, host.finality.as_ref(), true)?;
            install_host_record(&host.intent_path(agent), &encoded)?;
            files.intent = true;
            let exposed = host.read_exposure(agent, intent.id(), files)?;
            let hosted =
                host.open_generation(intent, &sealed, exposed, files, recovery.as_ref())?;
            if recovery.is_some() {
                retire_host_record(&host.portable_restore_path(agent))?;
            }
            if host.agents.insert(agent, hosted).is_some() {
                return Err(SharedAgentHostError::CorruptResidue);
            }
        }
        host.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(host)
    }

    /// Complete startup without releasing the outer host lease. Do not expose
    /// a partially verified ordinary set if any generation fails recovery.
    pub(crate) fn deferred_agent_ids(&self) -> Vec<AgentId> {
        self.deferred_generations.keys().copied().collect()
    }

    pub(crate) fn has_deferred_open(&self) -> bool {
        self.deferred_open
    }

    /// Complete startup under the original outer lease after obtaining finality.
    pub(crate) fn reopen_deferred_generations(
        &mut self,
        finality: Arc<dyn AgentGenesisFinalityVerifier>,
    ) -> Result<(), SharedAgentHostError> {
        if !self.deferred_open {
            return Err(SharedAgentHostError::Conflict);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let mut reopened = BTreeMap::new();
        let current_files = scan_generation_namespaces(&self.lease)?;
        if current_files.keys().any(|agent| {
            !self.agents.contains_key(agent) && !self.deferred_generations.contains_key(agent)
        }) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let deferred: Vec<_> = self.deferred_generations.keys().copied().collect();
        for agent in deferred {
            let files = *current_files
                .get(&agent)
                .ok_or(SharedAgentHostError::CorruptResidue)?;
            let hosted = self.open_deferred_generation(agent, files, finality.as_ref())?;
            reopened.insert(agent, hosted);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents.extend(reopened);
        self.deferred_generations.clear();
        self.deferred_open = false;
        self.finality = finality;
        Ok(())
    }

    /// Recovery-only opening: the returned generation is not inserted into the
    /// serving set. Dropping it releases its driver before another phase opens it.
    fn open_deferred_generation(
        &mut self,
        agent: AgentId,
        mut files: GenerationFiles,
        finality: &dyn AgentGenesisFinalityVerifier,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        if !self.deferred_generations.contains_key(&agent) || self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let recovery = self.read_portable_restore(agent, files)?;
        let (intent, encoded) = if let Some(recovery) = &recovery {
            if files.intent || files.intent_stage {
                let pair = self.read_intent(agent, files)?;
                if pair.0 != recovery.bundle.intent {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
                pair
            } else {
                (
                    recovery.bundle.intent.clone(),
                    recovery.bundle.intent.encode(),
                )
            }
        } else {
            self.read_intent(agent, files)?
        };
        if !matches!(
            intent.authority,
            SharedGenesisAuthority::AuthorityFinalized(_)
        ) {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        let sealed = self.verify_and_prepare_with_role(&intent, finality, true)?;
        install_host_record(&self.intent_path(agent), &encoded)?;
        files.intent = true;
        let exposed = self.read_exposure(agent, intent.id(), files)?;
        let hosted = self.open_generation(intent, &sealed, exposed, files, recovery.as_ref())?;
        if recovery.is_some() {
            retire_host_record(&self.portable_restore_path(agent))?;
        }
        Ok(hosted)
    }

    /// Validate an unfinished, unserved Create (startup or live admission).
    /// Its finality must already have been independently proved;
    /// this method neither publishes routes nor relaxes management admission.
    pub(crate) fn observe_deferred_clean_genesis_application(
        &mut self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        finality: &dyn AgentGenesisFinalityVerifier,
    ) -> Result<
        (
            crate::agent_sdk::ManagementReply,
            crate::agent_sdk::Hash,
            u64,
        ),
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let current_files = scan_generation_namespaces(&self.lease)?;
        if current_files.keys().any(|agent| {
            !self.agents.contains_key(agent) && !self.deferred_generations.contains_key(agent)
        }) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let files = *current_files
            .get(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let hosted = self.open_deferred_generation(agent, files, finality)?;
        let observed = Self::observe_hosted_clean_genesis_application(&hosted, request, receipt)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(observed)
    }

    pub fn scope(&self) -> AgentHostScope {
        self.lease.scope()
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Derive an ordinary Shared genesis proposal by executing Create with
    /// this host's trust and local replica identity. This is a read-only
    /// preparation boundary for issuance coordinators: it writes no intent,
    /// signs nothing, and grants neither finality nor a journal seal.
    /// The committee must still be independently authorized by the issuer.
    pub fn prepare_genesis_proposal(
        &mut self,
        create: super::journal::ReplayInput,
        committee: &AgentReplicaCommittee,
        catalog: &[RuntimeBlob],
    ) -> Result<super::genesis::AgentGenesisProposal, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if committee.space() != self.scope().space {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replica = committee
            .member_by_node(self.scope().node)
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .replica();
        let prepared =
            LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_shared_genesis_candidate(
                create,
                replica,
                committee,
                catalog,
                Arc::clone(&self.trust),
                Arc::clone(&self.merge),
            )
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let proposal = prepared
            .ordinary_proposal()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(proposal)
    }

    /// Prepare clean Shared Create from the signed management receipt and an
    /// admitted runtime. Coordinators must durably retain `observed_slot` for
    /// exact retry; selecting a new slot changes the proposal identity.
    /// This performs execution only, not issuance, publication or finality.
    pub fn prepare_clean_genesis_proposal(
        &mut self,
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime: &super::package_admission::AdmittedRuntimePackage,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
        committee: &AgentReplicaCommittee,
    ) -> Result<(super::genesis::AgentGenesisProposal, Vec<RuntimeBlob>), SharedAgentHostError>
    {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if descriptor.identity.space.0 != self.scope().space.0 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (create, catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_genesis_input(
                descriptor,
                runtime,
                authority,
                observed_slot,
                &self.trust,
                &self.merge,
            )
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let proposal = self.prepare_genesis_proposal(create, committee, &catalog)?;
        Ok((proposal, catalog))
    }

    /// Internal proposal-only path for the signed Linear-only external Shared
    /// contract. It does not publish a store, establish finality, or enable
    /// production startup. The ordinary Authority admission remains required.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn prepare_clean_external_genesis_proposal(
        &mut self,
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime: &super::package_admission::AdmittedStateRuntimePackage,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
        committee: &AgentReplicaCommittee,
    ) -> Result<(super::genesis::AgentGenesisProposal, Vec<RuntimeBlob>), SharedAgentHostError>
    {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let scope = self.scope();
        if descriptor.identity.space.0 != scope.space.0 || committee.space() != scope.space {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let replica = committee
            .member_by_node(scope.node)
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .replica();
        let binding = runtime
            .binding(
                scope.space,
                crate::service::AgentId(descriptor.identity.agent.0),
            )
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let bytes = runtime.exact_bytes().to_vec();
        let catalog = vec![RuntimeBlob {
            reference: crate::service::BlobRef::of_bytes(&bytes),
            bytes,
        }];
        let create = super::journal::ReplayInput {
            runtime: binding,
            operation: super::journal::ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor)),
                authority,
                observed_slot,
            },
        };
        let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_external_shared_genesis_candidate(
            create, replica, committee, &catalog, &self.trust, scope.node,
        ).map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let proposal = prepared
            .ordinary_proposal()
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok((proposal, catalog))
    }

    /// Provision an exact finalized generation, or return its current status
    /// for an exact retry. Finality, catalog shape, package trust, and Create
    /// replay all complete before the first intent byte is written.
    pub fn provision(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        self.provision_intent(intent)
    }

    /// Explicitly provision a generation on a fresh node outside its genesis
    /// committee. The finalized provision is verified exactly as for a member
    /// and its journal is opened at genesis; the node then replays the
    /// authenticated log as a passive replica and gains authority only through
    /// an authority-signed committee change that names it. The retained
    /// intent of a non-member generation is written only here, so reopening
    /// it later is evidence of this explicit admission.
    ///
    /// The node must receive the log from index 1: a compacted generation
    /// needs an authenticated checkpoint transfer, which this does not do.
    pub fn provision_joiner(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        let finality = Arc::clone(&self.finality);
        self.provision_intent_with_role(intent, finality.as_ref(), true)
    }

    /// Provision the first system Agent from direct root/QC finality. Unlike
    /// ordinary Shared admission this path never consults the system-Agent
    /// finality verifier, which would be circular before the authority actor
    /// exists.
    pub(crate) fn provision_system_bootstrap(
        &mut self,
        provision: SystemAgentGenesisProvision,
        committee: AgentReplicaCommittee,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new_system_bootstrap(
            provision,
            committee,
            catalog,
            committee_authority,
        )?;
        self.provision_intent(intent)
    }

    fn provision_intent(
        &mut self,
        intent: SharedGenesisIntent,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        let finality = Arc::clone(&self.finality);
        self.provision_intent_with_finality(intent, finality.as_ref())
    }

    /// The owning system coordinator supplies an exact live-replay proof.
    /// This does not replace the verifier used for other generations or reopen.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn provision_replay_verified(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
        finality: &super::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        self.provision_intent_with_finality(intent, finality)
    }

    fn provision_intent_with_finality(
        &mut self,
        intent: SharedGenesisIntent,
        finality: &dyn AgentGenesisFinalityVerifier,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.provision_intent_with_role(intent, finality, false)
    }

    fn provision_intent_with_role(
        &mut self,
        intent: SharedGenesisIntent,
        finality: &dyn AgentGenesisFinalityVerifier,
        joiner: bool,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        let agent = intent.agent()?;
        if self.deferred_generations.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        if intent.space() != self.scope().space
            || intent
                .committee()
                .member_by_node(self.scope().node)
                .is_none()
                != joiner
            || (joiner
                && !matches!(
                    intent.authority,
                    SharedGenesisAuthority::AuthorityFinalized(_)
                ))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let sealed = self.verify_and_prepare_with_role(&intent, finality, joiner)?;
        if let Some(existing) = self.agents.get(&agent) {
            if existing.intent != intent {
                return Err(SharedAgentHostError::Conflict);
            }
            return status_for(existing, self.transport_is_attached(agent));
        }
        if self
            .agents
            .len()
            .saturating_add(self.deferred_generations.len())
            >= MAX_SHARED_HOST_AGENTS
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        if current.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        install_host_record(&self.intent_path(agent), &intent.encode())?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self.open_generation(
            intent,
            &sealed,
            false,
            GenerationFiles {
                intent: true,
                ..GenerationFiles::default()
            },
            None,
        )?;
        let status = status_for(&hosted, false)?;
        self.agents.insert(agent, hosted);
        Ok(status)
    }

    /// Stage a publication-proved Create during startup without adding it to
    /// the serving set. The normal deferred opener owns physical application
    /// and crash recovery under the existing outer lease.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn stage_deferred_replay_verified(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
        finality: &super::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<(), SharedAgentHostError> {
        if !self.deferred_open
            || self
                .deferred_generations
                .contains_key(&provision.proposal().locator().agent)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        self.stage_unserved_replay_verified(provision, catalog, committee_authority, finality)
    }

    /// Prove absence under the retained physical root lease. A staged namespace
    /// is not absence even when no serving handle has been admitted yet.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn clean_genesis_is_absent(
        &mut self,
        agent: AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if agent == AgentId::ZERO {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(!self.agents.contains_key(&agent)
            && !self.deferred_generations.contains_key(&agent)
            && !scan_generation_namespaces(&self.lease)?.contains_key(&agent))
    }

    /// Check physical capacity before live Authority work, including the system
    /// generation and unserved Creates. This is not a slot reservation or proof
    /// of finality; staging still validates the exact intent and capacity.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn preflight_live_genesis_capacity(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if self.deferred_open {
            return Err(SharedAgentHostError::Conflict);
        }
        if locator.space != self.scope().space || locator.agent == AgentId::ZERO {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if !self.agents.contains_key(&locator.agent)
            && !self.deferred_generations.contains_key(&locator.agent)
            && self
                .agents
                .len()
                .saturating_add(self.deferred_generations.len())
                >= MAX_SHARED_HOST_AGENTS
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        Ok(())
    }

    /// Live Create staging does not enter the global startup gate or change
    /// any existing serving generation. Only the coordinator may promote it.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn stage_live_replay_verified(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
        finality: &super::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<(), SharedAgentHostError> {
        if self.deferred_open {
            return Err(SharedAgentHostError::Conflict);
        }
        self.stage_unserved_replay_verified(provision, catalog, committee_authority, finality)
    }

    #[cfg(all(feature = "network", target_os = "linux"))]
    fn stage_unserved_replay_verified(
        &mut self,
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        committee_authority: CommitteeChangeAuthorityBinding,
        finality: &super::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let intent = SharedGenesisIntent::new(provision, catalog, committee_authority)?;
        let agent = intent.agent()?;
        if self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        if intent.space() != self.scope().space
            || intent
                .committee()
                .member_by_node(self.scope().node)
                .is_none()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if self.deferred_generations.contains_key(&agent) {
            let files = scan_generation_namespaces(&self.lease)?
                .get(&agent)
                .copied()
                .ok_or(SharedAgentHostError::CorruptResidue)?;
            if self.read_intent(agent, files)?.0 != intent {
                return Err(SharedAgentHostError::Conflict);
            }
            self.verify_and_prepare_with_finality(&intent, finality)?;
            return Ok(());
        }
        if self
            .agents
            .len()
            .saturating_add(self.deferred_generations.len())
            >= MAX_SHARED_HOST_AGENTS
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        self.verify_and_prepare_with_finality(&intent, finality)?;
        if scan_generation_namespaces(&self.lease)?.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        install_host_record(&self.intent_path(agent), &intent.encode())?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.deferred_generations.insert(
            agent,
            GenerationFiles {
                intent: true,
                ..GenerationFiles::default()
            },
        );
        Ok(())
    }

    /// Called only after the lifecycle owner verifies signed finalization and
    /// durable retirement. Startup recovery uses the complete-set opener instead.
    #[cfg(all(feature = "network", target_os = "linux"))]
    pub(crate) fn admit_live_replay_verified(
        &mut self,
        agent: AgentId,
        finality: &super::clean_bootstrap::ReplayVerifiedAgentGenesisFinality,
    ) -> Result<(), SharedAgentHostError> {
        if self.deferred_open {
            return Err(SharedAgentHostError::Conflict);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if let Some(existing) = self.agents.get(&agent) {
            let SharedGenesisAuthority::AuthorityFinalized(provision) = &existing.intent.authority
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            return finality
                .verify_finalized(provision)
                .map_err(|_| SharedAgentHostError::ScopeMismatch);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        if current.keys().any(|agent| {
            !self.agents.contains_key(agent) && !self.deferred_generations.contains_key(agent)
        }) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let files = *current
            .get(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let hosted = self.open_deferred_generation(agent, files, finality)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents.insert(agent, hosted);
        self.deferred_generations.remove(&agent);
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SharedAgentStatus>, SharedAgentHostError> {
        self.agents
            .iter()
            .map(|(agent, hosted)| status_for(hosted, self.transport_is_attached(*agent)))
            .collect()
    }

    /// Authenticated ownership facts for transport refresh. Full status also
    /// executes an actor-directory query to derive lanes, which unchanged
    /// network attachments do not consume.
    pub(crate) fn attachment_statuses(
        &self,
    ) -> Result<Vec<SharedAgentAttachmentStatus>, SharedAgentHostError> {
        self.agents
            .iter()
            .map(|(agent, hosted)| {
                attachment_status_for(hosted, self.transport_is_attached(*agent))
            })
            .collect()
    }

    pub fn show(&self, agent: AgentId) -> Result<Option<SharedAgentStatus>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .map(|hosted| status_for(hosted, self.transport_is_attached(agent)))
            .transpose()
    }

    /// Admission needs audited ledger capacity, not an actor-directory query
    /// or the full user-facing status projection. The caller holds the host
    /// lock while comparing these facts with its Raft barrier.
    pub(crate) fn capacity(
        &self,
        agent: AgentId,
    ) -> Result<(u64, u64, bool), SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .capacity()
            .map_err(map_driver_error)
    }

    /// Read only the authenticated generation/committee attachment facts.
    /// Unlike `show`, this does not execute an actor-directory query and is
    /// therefore safe to pair with one keyed invocation-material lookup on a
    /// hot dispatch path.
    pub(crate) fn supervisor_attachment_status(
        &self,
        agent: AgentId,
    ) -> Result<Option<SharedAgentAttachmentStatus>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .map(|hosted| attachment_status_for(hosted, self.transport_is_attached(agent)))
            .transpose()
    }

    /// Read the same trusted clock used by journal admission without loading
    /// actor material or executing a runtime-directory inspection.
    pub(crate) fn current_logical_slot(
        &mut self,
        agent: AgentId,
    ) -> Result<u64, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .current_logical_slot()
            .map_err(map_driver_error)
    }

    /// Read the authenticated descriptor without enumerating actor state.
    pub(crate) fn clean_runtime_descriptor(
        &self,
        agent: AgentId,
    ) -> Result<crate::agent_sdk::AgentDescriptor, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let descriptor = hosted.driver.clean_descriptor().map_err(map_driver_error)?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(descriptor)
    }

    /// Reconstruct a bounded actor-directory projection from the same live
    /// journal driver that supplied the current runtime descriptor. Callers
    /// hold the outer host mutex, so descriptor and directory cannot be mixed
    /// across two locally submitted transitions.
    pub(crate) fn clean_runtime_projection(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentRuntimeProjection, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let descriptor = self.clean_runtime_descriptor(agent)?;
        let maximum = descriptor.capabilities.max_actors as usize;
        let limit = u16::try_from(crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let maximum_pages = maximum
            .div_ceil(crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES)
            .saturating_add(1);
        let mut actors = Vec::new();
        let mut after = None;
        for _ in 0..maximum_pages {
            let outcome = hosted
                .driver
                .inspect_clean_management(&crate::agent_sdk::ManagementRequest::InspectActors {
                    after,
                    limit,
                })
                .map_err(map_driver_error)?;
            let crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Actors(page),
            )) = outcome
            else {
                return Err(SharedAgentHostError::CorruptResidue);
            };
            if page.validate().is_err()
                || page
                    .entries
                    .first()
                    .is_some_and(|record| after.is_some_and(|cursor| record.entry.actor <= cursor))
                || actors
                    .len()
                    .checked_add(page.entries.len())
                    .is_none_or(|count| count > maximum)
                || (page.next.is_some() && page.entries.len() != usize::from(limit))
            {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            actors.extend(page.entries);
            let Some(next) = page.next else {
                return Ok(SharedAgentRuntimeProjection { descriptor, actors });
            };
            if after == Some(next) {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            after = Some(next);
        }
        Err(SharedAgentHostError::CorruptResidue)
    }

    /// Load one complete invocation closure from the exact journal generation
    /// currently owned by this host. Network lifecycle ownership is checked
    /// by the caller before this storage-level read is exposed to a
    /// supervisor route.
    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: AgentId,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedAgentHostError>
    {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .physical_invocation_material(actor)
            .map_err(map_driver_error)
    }

    /// Audit every locally attached Shared generation against one complete
    /// authority subset while the outer host lock is held by the network
    /// owner. The optional root marker comes only from the independently
    /// authenticated system bootstrap plan.
    pub(crate) fn audit_authority_projection(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&super::invocation_preparation::PhysicalRootLineage>,
    ) -> Result<SharedAuthorityProjectionAudit, SharedAgentHostError> {
        self.audit_authority_projection_scoped(head, projected, root, None)
    }

    /// Audit the complete ordinary generation selected by its live route
    /// handle. No root-provenance exception is available on this path.
    pub(crate) fn audit_agent_authority_projection(
        &self,
        agent: AgentId,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<SharedAuthorityProjectionAudit, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if matches!(
            hosted.intent.authority,
            SharedGenesisAuthority::SystemBootstrap { .. }
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.audit_authority_projection_scoped(head, projected, None, Some(agent))
    }

    /// Audit only the independently pinned system generation. Ordinary
    /// generations remain subject to their own complete authority audit.
    pub(crate) fn audit_system_authority_projection(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
        root: &super::invocation_preparation::PhysicalRootLineage,
    ) -> Result<SharedAuthorityProjectionAudit, SharedAgentHostError> {
        self.audit_authority_projection_scoped(
            head,
            projected,
            Some(root),
            Some(AgentId(root.agent.0)),
        )
    }

    fn audit_authority_projection_scoped(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&super::invocation_preparation::PhysicalRootLineage>,
        only: Option<AgentId>,
    ) -> Result<SharedAuthorityProjectionAudit, SharedAgentHostError> {
        match self.audit_authority_projection_exact(projected, root, only) {
            Ok(identities) => return Ok(SharedAuthorityProjectionAudit::Ready(identities)),
            Err(error) => {
                if self.physical_projection_is_one_ack_ahead(head, projected, root, only)? {
                    return Ok(SharedAuthorityProjectionAudit::Lag);
                }
                return Err(error);
            }
        }
    }

    fn audit_authority_projection_exact(
        &self,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&super::invocation_preparation::PhysicalRootLineage>,
        only: Option<AgentId>,
    ) -> Result<Vec<super::supervisor::AgentRouteIdentity>, SharedAgentHostError> {
        let mut local = Vec::new();
        for (agent, hosted) in &self.agents {
            if only.is_some_and(|selected| selected != *agent) {
                continue;
            }
            if hosted
                .driver
                .local_role()
                .map_err(map_driver_error)?
                .is_some()
            {
                local.push((*agent, hosted));
            }
        }
        if local.len() != projected.len() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut identities = Vec::new();
        for ((agent, hosted), authority) in local.into_iter().zip(projected) {
            let descriptor = hosted.driver.clean_descriptor().map_err(map_driver_error)?;
            let directory = self.clean_runtime_projection(agent)?;
            if descriptor != *authority.descriptor()
                || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
                || directory.descriptor != descriptor
                || directory.actors.len() != authority.actors().len()
            {
                tracing::warn!(
                    descriptor_matches = descriptor == *authority.descriptor(),
                    directory_matches = directory.descriptor == descriptor,
                    physical_actors = directory.actors.len(),
                    projected_actors = authority.actors().len(),
                    "Shared authority projection directory mismatch"
                );
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            for actor in authority.actors() {
                let mut material = hosted
                    .driver
                    .physical_authority_material(actor.entry.actor)
                    .map_err(map_driver_error)?;
                match (
                    actor.root_provenance,
                    root.map(|expected| expected.matches(actor)),
                ) {
                    (true, Some(true)) => {
                        material.root_provenance = true;
                    }
                    (false, Some(true)) => {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    (true, _) => return Err(SharedAgentHostError::ScopeMismatch),
                    (false, _) => {}
                }
                if !super::supervisor_adapters::physical_material_matches_authority(
                    &material,
                    authority.descriptor(),
                    actor,
                ) {
                    tracing::warn!(
                        entry_matches = material.actor.entry == actor.entry,
                        installation_matches =
                            material.actor.installation_id == actor.installation_id,
                        reservation_matches =
                            material.actor.registry_reservation == actor.registry_reservation,
                        request_matches = material.install_request == actor.install_request,
                        producer_matches = material.producer == actor.producer,
                        contract_matches = material.contract == actor.contract,
                        requirements_match = material.requirements == actor.requirements,
                        root_matches = material.root_provenance == actor.root_provenance,
                        "Shared authority projection actor mismatch"
                    );
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                if !actor.entry.suspended {
                    identities.push(
                        super::supervisor_adapters::physical_material_identity(&material)
                            .map_err(|_| SharedAgentHostError::ScopeMismatch)?,
                    );
                }
            }
        }
        Ok(identities)
    }

    fn physical_projection_is_one_ack_ahead(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&super::invocation_preparation::PhysicalRootLineage>,
        only: Option<AgentId>,
    ) -> Result<bool, SharedAgentHostError> {
        let mut physical = Vec::new();
        for (agent, hosted) in &self.agents {
            if only.is_some_and(|selected| selected != *agent) {
                continue;
            }
            if hosted
                .driver
                .local_role()
                .map_err(map_driver_error)?
                .is_none()
            {
                continue;
            }
            let directory = self.clean_runtime_projection(*agent)?;
            let sdk_agent = crate::agent_sdk::AgentId(agent.0);
            let authority = projected
                .binary_search_by_key(&sdk_agent, |projection| {
                    projection.descriptor().identity.agent
                })
                .ok()
                .and_then(|index| projected.get(index));
            let mut actors = Vec::with_capacity(directory.actors.len());
            for actor in directory.actors {
                let mut material = hosted
                    .driver
                    .physical_authority_material(actor.entry.actor)
                    .map_err(map_driver_error)?;
                if let Some(candidate) = authority.and_then(|projection| {
                    projection
                        .actors()
                        .binary_search_by_key(&actor.entry.actor, |candidate| candidate.entry.actor)
                        .ok()
                        .and_then(|index| projection.actors().get(index))
                }) {
                    match (
                        candidate.root_provenance,
                        root.map(|expected| expected.matches(candidate)),
                    ) {
                        (true, Some(true)) => material.root_provenance = true,
                        (false, Some(true)) | (true, _) => return Ok(false),
                        (false, _) => {}
                    }
                }
                actors.push(material);
            }
            physical.push(
                super::supervisor_adapters::PhysicalAuthorityRouteProjection {
                    descriptor: directory.descriptor,
                    actors,
                    disposition: hosted
                        .driver
                        .latest_clean_management_disposition()
                        .map_err(map_driver_error)?,
                },
            );
        }
        Ok(
            super::supervisor_adapters::physical_projection_is_exactly_one_ack_ahead(
                head, projected, &physical,
            ),
        )
    }

    pub fn role(&self, agent: AgentId) -> Result<Option<ReplicaRole>, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted.driver.local_role().map_err(map_driver_error)
    }

    pub fn route(&self, agent: AgentId) -> Result<AgentRouteKey, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted.driver.active_route().map_err(map_driver_error)
    }

    pub fn physical_route(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentPhysicalRoute, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let generation = hosted.driver.ledger().generation();
        Ok(SharedAgentPhysicalRoute {
            generation,
            replication_id: generation.replication_id(),
            raft_database: hosted.raft_path.clone(),
        })
    }

    pub fn journal_position(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentJournalPosition, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let (genesis, admission, ordered_index, ordered_head, merge_frontier, runtime) =
            hosted.driver.journal_position();
        Ok(SharedAgentJournalPosition {
            genesis,
            admission,
            ordered_index,
            ordered_head,
            merge_frontier,
            runtime,
        })
    }

    pub(crate) fn management_invocation_after(
        &self,
        agent: AgentId,
        anchor: &SharedAgentJournalPosition,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<super::journal::ReplayInputId>, SharedAgentHostError> {
        let current = self.journal_position(agent)?;
        if current.genesis != anchor.genesis
            || current.admission != anchor.admission
            || current.runtime != anchor.runtime
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_invocation_after(
                super::journal::OrderedBase {
                    index: anchor.ordered_index,
                    head: anchor.ordered_head,
                },
                envelope,
            )
            .map_err(map_driver_error)
    }

    pub(crate) fn management_invocation_after_anchor(
        &self,
        agent: AgentId,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<super::journal::ReplayInputId>, SharedAgentHostError> {
        let current = self.journal_position(agent)?;
        if current.genesis != anchor.genesis
            || current.admission != anchor.admission
            || current.runtime.commitment() != anchor.runtime
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_invocation_after(anchor.ordered, envelope)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_denial_invocation_after_anchor(
        &self,
        agent: AgentId,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<super::journal::ReplayInputId>, SharedAgentHostError> {
        let current = self.journal_position(agent)?;
        if current.genesis != anchor.genesis
            || current.admission != anchor.admission
            || current.runtime.commitment() != anchor.runtime
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_denial_invocation_after(anchor.ordered, envelope)
            .map_err(map_driver_error)
    }

    pub(crate) fn replay_durable_management_denial(
        &mut self,
        agent: AgentId,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.management_denial_invocation_after_anchor(agent, anchor, envelope)?
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .replay_durable_management_denial(anchor.ordered, envelope)
            .map_err(map_driver_error)
    }

    #[cfg(test)]
    pub(crate) fn snapshot_state_for_test(
        &self,
        agent: AgentId,
    ) -> Result<SharedAgentSnapshotState, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        Ok(
            match hosted.driver.current_snapshot().map_err(map_driver_error)? {
                Some(snapshot) => SharedAgentSnapshotState::Installed {
                    raft_index: snapshot.claim.raft_index(),
                    raft_term: snapshot.claim.raft_term(),
                    certificate: snapshot.certificate_commitment,
                },
                None => SharedAgentSnapshotState::None,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn common_snapshot_certificate_for_test(
        &self,
        agent: AgentId,
    ) -> Result<Option<SharedAgentCommonSnapshotCertificate>, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .common_snapshot_authority()
            .map(|authority| authority.map(|(certificate, _)| certificate))
            .map_err(map_driver_error)
    }

    #[cfg(test)]
    pub(crate) fn journal_store_instance_for_test(
        &self,
        agent: AgentId,
    ) -> Result<super::shared_raft::JournalStoreInstanceId, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        Ok(hosted.driver.journal_store_instance_for_test())
    }

    #[cfg(test)]
    pub(crate) fn management_evidence_for_test(
        &self,
        agent: AgentId,
    ) -> Result<Option<super::journal::CleanManagementEvidence>, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        Ok(hosted
            .driver
            .materialization()
            .clean_management_evidence()
            .cloned())
    }

    pub(crate) fn prepare_clean_ordered(
        &self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_clean_ordered(work, authorization)
            .map_err(map_driver_error)
    }

    pub(crate) fn projection_pair_fits(
        &self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .projection_pair_fits(work, authorization)
            .map_err(map_driver_error)
    }

    pub(crate) fn projection_admission_requirement(
        &self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        recovering: bool,
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .projection_admission_requirement(work, authorization, recovering)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_retirement_admission_requirement(
        &self,
        agent: AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_retirement_admission_requirement(envelopes)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_retirement_set_admission_requirement(
        &self,
        agent: AgentId,
        envelopes: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_retirement_set_admission_requirement(envelopes)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_pending_admission_requirement(
        &self,
        agent: AgentId,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_pending_admission_requirement(pending)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_recovery_admission_requirement(
        &self,
        agent: AgentId,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_recovery_admission_requirement(pending, retiring)
            .map_err(map_driver_error)
    }

    pub(crate) fn management_initial_admission_requirement(
        &self,
        agent: AgentId,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<usize>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .management_initial_admission_requirement(anchor, envelope)
            .map_err(map_driver_error)
    }

    pub(crate) fn projection_admission_records(
        &self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        recovering: bool,
    ) -> Result<usize, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .projection_admission_records(work, authorization, recovering)
            .map_err(map_driver_error)
    }

    pub(crate) fn retained_positive_clean_acknowledgement(
        &self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_positive_clean_acknowledgement(work, authorization)
            .map_err(map_driver_error)
    }

    pub(crate) fn recovery_manifest(
        &mut self,
        agent: AgentId,
    ) -> Result<super::shared_recovery::SharedRecoveryManifest, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .recovery_manifest()
            .map_err(map_driver_error)
    }

    pub(crate) fn validate_recovery_registration(
        &mut self,
        agent: AgentId,
        registration: &super::shared_recovery::SharedRecoveryRegistration,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .validate_recovery_registration(registration)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_recovery_expiry(
        &mut self,
        agent: AgentId,
        request: Hash,
    ) -> Result<VerifiedSharedRecoveryExpiryCandidate, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let now = self
            .current_logical_slot(agent)?
            .max(self.recovery_expiry_floor(agent)?);
        let (index, term, ordered, manifest) = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .recovery_expiry_context()
            .map_err(map_driver_error)?;
        let registration = manifest
            .slots()
            .iter()
            .find(|slot| slot.registration().request().request_commitment() == request)
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .registration();
        let claim = manifest
            .expiry_claim(registration.request(), index, term, ordered, now)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        Ok(VerifiedSharedRecoveryExpiryCandidate { claim })
    }

    /// Sign the exact capability just reconstructed under this host's exclusive
    /// access. The route still checks its before/after Raft barrier and freshly
    /// verifies the prefix again after collecting peer votes.
    pub(crate) fn prepare_signed_recovery_expiry(
        &mut self,
        agent: AgentId,
        request: Hash,
    ) -> Result<
        (
            VerifiedSharedRecoveryExpiryCandidate,
            ReplicaCommitSignature,
        ),
        SharedAgentHostError,
    > {
        let candidate = self.prepare_recovery_expiry(agent, request)?;
        let signature = self
            .merge
            .sign_recovery_expiry_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
        Ok((candidate, signature))
    }

    pub(crate) fn verify_recovery_expiry(
        &mut self,
        agent: AgentId,
        claim: &super::shared_recovery::SharedRecoveryExpiryClaim,
    ) -> Result<VerifiedSharedRecoveryExpiryCandidate, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let now = self
            .current_logical_slot(agent)?
            .max(self.recovery_expiry_floor(agent)?);
        let (index, term, ordered, manifest) = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .recovery_expiry_context()
            .map_err(map_driver_error)?;
        if now < claim.observed_slot()
            || index != claim.prefix_index()
            || term != claim.prefix_term()
            || ordered != claim.ordered()
        {
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "recovery_expiry_binding node={:?} now={now}/{} prefix={index}/{term} expected={}/{} ordered={ordered:?}/{:?}",
                    self.merge.node(),
                    claim.observed_slot(),
                    claim.prefix_index(),
                    claim.prefix_term(),
                    claim.ordered(),
                );
            }
            return Err(SharedAgentHostError::Unavailable);
        }
        manifest
            .validate_expiry_claim(claim)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        Ok(VerifiedSharedRecoveryExpiryCandidate {
            claim: claim.clone(),
        })
    }

    pub(crate) fn sign_recovery_expiry(
        &mut self,
        agent: AgentId,
        claim: &super::shared_recovery::SharedRecoveryExpiryClaim,
    ) -> Result<ReplicaCommitSignature, SharedAgentHostError> {
        let candidate = self.verify_recovery_expiry(agent, claim)?;
        self.merge
            .sign_recovery_expiry_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)
    }

    pub(crate) fn recovery_expiry_terminal(
        &mut self,
        agent: AgentId,
        request: Hash,
    ) -> Result<Option<super::shared_recovery::SharedRecoveryExpiryTerminal>, SharedAgentHostError>
    {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .recovery_expiry_terminal(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn recovery_expiry_floor(
        &mut self,
        agent: AgentId,
    ) -> Result<u64, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .recovery_expiry_floor())
    }

    pub(crate) fn retained_terminal_projection_invoke(
        &self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_terminal_projection_invoke(work, authorization)
            .map_err(map_driver_error)
    }

    /// Recover a still-unacknowledged Query's authorization from local
    /// authenticated history, without accepting a peer-provided clock.
    pub(crate) fn retained_projection_authorization(
        &mut self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
    ) -> Result<Option<crate::agent_sdk::InvocationAuthorization>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if work.agent.0 != agent.0 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_projection_authorization(work)
            .map_err(map_driver_error)
    }

    /// Return an exact Query result only after local authenticated application
    /// of both its Invoke and positive ACK. This is not an execution API.
    pub(crate) fn retained_acknowledged_projection(
        &mut self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if work.agent.0 != agent.0 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_acknowledged_projection(work)
            .map_err(map_driver_error)
    }

    pub(crate) fn retained_acknowledged_projection_with_input(
        &mut self,
        agent: AgentId,
        work: &crate::agent_sdk::InvocationWork,
    ) -> Result<
        Option<(
            super::journal::ReplayInputId,
            crate::agent_sdk::RuntimeOutcome,
        )>,
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if work.agent.0 != agent.0 {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .retained_acknowledged_projection_with_input(work)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_clean_ordered_operation(
        &self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_clean_ordered_operation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_terminal_clean_ordered_operation(
        &self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_terminal_clean_ordered_operation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_persisted_management_invocation(
        &self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_persisted_management_invocation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_bootstrap_invocation(
        &self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_bootstrap_invocation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_reserved_projection_operation(
        &self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<super::shared_journal_driver::PreparedCleanOrdered, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_reserved_projection_operation(request, terminal_only)
            .map_err(map_driver_error)
    }

    pub(crate) fn prepare_clean_management(
        &mut self,
        agent: AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<super::shared_journal_driver::PreparedCleanManagement, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_clean_management(request, authority, artifacts)
            .map_err(map_driver_error)
    }

    /// Prepare the committee leg of a Shared `ChangeReplicas`; `None` means
    /// the committee already runs the requested roster.
    pub(crate) fn prepare_clean_committee_change(
        &mut self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
        joining: &[Vec<u8>],
    ) -> Result<Option<super::shared_journal_driver::PreparedCommitteeChange>, SharedAgentHostError>
    {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .prepare_clean_committee_change(request, authority, joining)
            .map_err(map_driver_error)
    }

    /// Fixed-roster recovery commands apply only on the initial committee
    /// with no transition in flight; anything else would be refused by every
    /// replica after commit.
    pub(crate) fn fixed_roster_recovery_admissible(
        &self,
        agent: AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .ledger()
            .fixed_roster_recovery_admissible()
            .map_err(map_ledger_error)
    }

    pub(crate) fn inspect_clean_management(
        &self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .inspect_clean_management(request)
            .map_err(map_driver_error)
    }

    /// Observe the initial ordinary Create from authenticated physical replay,
    /// never from an archive's claimed reply or the runtime's private layout.
    /// Later management mutations deliberately invalidate this initial evidence;
    /// callers must recover an already pledged issuer ACK on that retry path.
    pub(crate) fn observe_clean_genesis_application(
        &self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<
        (
            crate::agent_sdk::ManagementReply,
            crate::agent_sdk::Hash,
            u64,
        ),
        SharedAgentHostError,
    > {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        Self::observe_hosted_clean_genesis_application(hosted, request, receipt)
    }

    fn observe_hosted_clean_genesis_application(
        hosted: &HostedSharedAgent,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<
        (
            crate::agent_sdk::ManagementReply,
            crate::agent_sdk::Hash,
            u64,
        ),
        SharedAgentHostError,
    > {
        let SharedGenesisAuthority::AuthorityFinalized(provision) = &hosted.intent.authority else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let input = provision.proposal().create();
        let super::journal::ReplayOperation::CleanManage {
            request: applied_request,
            authority,
            observed_slot,
        } = &input.operation
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if !matches!(request, crate::agent_sdk::ManagementRequest::Create(_))
            || request != applied_request
            || receipt != authority
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let evidence = hosted
            .driver
            .materialization()
            .clean_management_evidence()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if evidence.input != input.id()
            || evidence.ordered != super::journal::OrderedBase::post_genesis()
            || evidence.authority != receipt.commitment()
            || evidence.request != request.replay_commitment()
            || evidence.epoch != receipt.selector.epoch
            || evidence.sequence != receipt.selector.decision_sequence
            || evidence.observed_slot != *observed_slot
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let application = evidence
            .result
            .clone()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        Ok((
            application,
            hosted
                .driver
                .clean_state_commitment()
                .map_err(map_driver_error)?,
            *observed_slot,
        ))
    }

    pub(crate) fn observe_durable_install(
        &mut self,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<super::shared_journal_driver::SharedInstallObservation, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .observe_durable_install(request, receipt)
            .map_err(map_driver_error)
    }

    pub(crate) fn clean_state_commitment(
        &self,
        agent: AgentId,
    ) -> Result<crate::agent_sdk::Hash, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .clean_state_commitment()
            .map_err(map_driver_error)
    }

    pub(crate) fn replay_durable_clean_terminal(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .replay_durable_clean_terminal(
                super::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                },
            )
            .map_err(map_driver_error)
    }

    pub(crate) fn replay_durable_bootstrap_invocation(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .replay_durable_bootstrap_invocation(
                super::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                },
            )
            .map_err(map_driver_error)
    }

    pub(crate) fn replay_durable_bootstrap_input(
        &mut self,
        agent: AgentId,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<
        Option<(
            crate::agent_sdk::InvocationWork,
            crate::agent_sdk::RuntimeOutcome,
        )>,
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .replay_durable_bootstrap_input(invocation)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_local(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_local(work, authorization)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_local_operation(
        &mut self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_local_operation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_merge(
        &mut self,
        agent: AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_merge(work, authorization)
            .map_err(map_driver_error)
    }

    pub(crate) fn apply_clean_merge_operation(
        &mut self,
        agent: AgentId,
        request: super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .apply_clean_merge_operation(request)
            .map_err(map_driver_error)
    }

    pub(crate) fn take_clean_ordered_result(
        &mut self,
        agent: AgentId,
        input: super::journal::ReplayInputId,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .take_clean_ordered_result(input)
            .map_err(map_driver_error)
    }

    pub(crate) fn try_take_clean_ordered_result(
        &mut self,
        agent: AgentId,
        input: super::journal::ReplayInputId,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedAgentHostError> {
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .try_take_clean_ordered_result(input)
            .map_err(map_driver_error)
    }

    /// Keep singleton image retry compatibility without extending that rule
    /// to external block storage. This also validates the live owner lease.
    pub(crate) fn uses_external_state(
        &mut self,
        agent: AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)
            .map(|entry| entry.driver.uses_external_state())
    }

    /// Exact locally anchored publication whose durable state must be
    /// available on a voter majority before this input's result is delivered.
    pub(crate) fn available_ordered_claim(
        &mut self,
        agent: AgentId,
        input: super::journal::ReplayInputId,
    ) -> Result<super::shared_commit::OrderedCommitClaim, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .available_ordered_claim(input)
            .map_err(map_driver_error)
    }

    /// Authenticate local availability, never just receipt of a Raft entry.
    /// The opaque driver proof is consumed while the host owner is borrowed.
    pub(crate) fn verify_ordered_availability(
        &mut self,
        agent: AgentId,
        index: u64,
        term: u64,
        claim: crate::service::Hash,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .verify_ordered_availability(index, term, claim)
            .map(|_available| ())
            .map_err(map_driver_error)
    }

    /// Strict current-root availability is distinct from historical publication
    /// availability. A newer serving pin cannot attest an older retained root.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn verify_current_ordered_availability(
        &mut self,
        agent: AgentId,
        index: u64,
        term: u64,
        claim: crate::service::Hash,
    ) -> Result<(), SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .verify_current_ordered_availability(index, term, claim)
            .map(|_available| ())
            .map_err(map_driver_error)
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn inspect_external_retained_reply(
        &mut self,
        agent: AgentId,
        request: &super::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<
        Option<super::shared_journal_driver::RetainedExternalReplyProof>,
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .inspect_external_retained_reply(request)
            .map_err(map_driver_error)
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn revalidate_external_retained_reply(
        &mut self,
        agent: AgentId,
        request: &super::shared_journal_driver::CleanInvocationReplayRequest,
        proof: &super::shared_journal_driver::RetainedExternalReplyProof,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .revalidate_external_retained_reply(request, proof)
            .map_err(map_driver_error)
    }

    pub(crate) fn raft_database(
        &self,
        agent: AgentId,
    ) -> Result<Arc<Database>, SharedAgentHostError> {
        Ok(self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .ledger()
            .database())
    }

    /// Apply exactly one slot which the generation's durable Raft metadata
    /// already marks committed. The host never manufactures commit evidence.
    pub fn apply_next(
        &mut self,
        agent: AgentId,
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .apply_next()
            .map(map_apply_outcome)
            .map_err(map_driver_error)
    }

    /// Import one canonical event. Committee ID, complete author identity,
    /// Ed25519 signature, causal closure, and ordered base are all rechecked
    /// before publication.
    pub fn import_merge(
        &mut self,
        agent: AgentId,
        event: &MergeEvent,
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        hosted
            .driver
            .import_merge(event)
            .map(map_apply_outcome)
            .map_err(map_driver_error)
    }

    pub fn import_merge_bytes(
        &mut self,
        agent: AgentId,
        bytes: &[u8],
    ) -> Result<SharedAgentApplyOutcome, SharedAgentHostError> {
        if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        let event =
            MergeEvent::decode(bytes).map_err(|_| SharedAgentHostError::InvalidProvision)?;
        if event.encode() != bytes {
            return Err(SharedAgentHostError::InvalidProvision);
        }
        self.import_merge(agent, &event)
    }

    /// Persist one independently authenticated Merge object without moving
    /// the journal head. Anti-entropy can therefore resume a parent walk after
    /// timeout or process restart without treating mere storage as commit.
    pub(crate) fn stage_merge(
        &mut self,
        agent: AgentId,
        event: &MergeEvent,
    ) -> Result<bool, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .stage_merge(event)
            .map_err(map_driver_error)
    }

    pub(crate) fn merge_object(
        &self,
        agent: AgentId,
        event: MergeEventId,
    ) -> Result<SharedMergeObject, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_object(event)
            .map_err(map_driver_error)
    }

    /// Composite-network hook for serving an authenticated Merge frontier.
    /// The caller remains responsible for committee-gating the Noise peer.
    pub fn merge_roots(&self, agent: AgentId) -> Result<Vec<[u8; 32]>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_roots()
            .map_err(map_driver_error)
    }

    /// Composite-network hook for point-fetching a canonical Merge event.
    pub fn merge_node(
        &self,
        agent: AgentId,
        event: MergeEventId,
    ) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .merge_event_bytes(event)
            .map_err(map_driver_error)
    }

    /// Require a live exact-generation clean network attachment. A durable
    /// Raft file alone is never attachment evidence, and reopen begins
    /// detached until the route owner is installed again.
    pub fn require_transport(&self, agent: AgentId) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        if self.transport_is_attached(agent) {
            Ok(())
        } else {
            Err(SharedAgentHostError::TransportNotAttached)
        }
    }

    fn transport_is_attached(&self, agent: AgentId) -> bool {
        self.transport_leases.get(&agent) == Some(&TransportLeaseState::Attached)
    }

    pub(crate) fn reserve_transport_attachment(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        if !self.agents.contains_key(&agent) {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        match self.transport_leases.entry(agent) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(TransportLeaseState::Attaching);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => Err(SharedAgentHostError::Conflict),
        }
    }

    pub(crate) fn mark_transport_attached(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get_mut(&agent) {
            Some(state @ TransportLeaseState::Attaching) => {
                *state = TransportLeaseState::Attached;
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    pub(crate) fn mark_transport_stopping(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get_mut(&agent) {
            Some(state @ TransportLeaseState::Attached) => {
                *state = TransportLeaseState::Stopping;
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    /// Release a failed setup or a completely stopped attachment. An active
    /// attachment cannot be cleared directly: its owner must first enter
    /// `Stopping` and drain the worker and handler leases.
    pub(crate) fn release_transport_attachment(
        &mut self,
        agent: AgentId,
    ) -> Result<(), SharedAgentHostError> {
        match self.transport_leases.get(&agent) {
            Some(TransportLeaseState::Attaching | TransportLeaseState::Stopping) => {
                self.transport_leases.remove(&agent);
                Ok(())
            }
            _ => Err(SharedAgentHostError::Conflict),
        }
    }

    /// Reconstruct one source-store-independent recovery claim for the exact
    /// installed checkpoint of the clean singleton Shared system Agent.
    /// Ordinary/multi-replica Shared generations remain explicitly
    /// unsupported until their authority transfer has a separately specified
    /// protocol.
    pub fn request_portable_backup(
        &mut self,
        agent: AgentId,
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<VerifiedSharedAgentPortableBackupCandidate, SharedAgentHostError> {
        let (_, _, _, claim) = self.reconstruct_portable_backup(agent, limits)?;
        Ok(VerifiedSharedAgentPortableBackupCandidate::from_reconstructed(claim))
    }

    /// Finish an authenticated portable export after the singleton voter has
    /// signed the exact reconstructed claim. The checkpoint is reconstructed
    /// again, so work committed after candidate issuance makes the supplied
    /// certificate fail closed rather than exporting mixed state.
    pub fn export_portable_backup(
        &mut self,
        agent: AgentId,
        certificate: &SharedAgentPortableSnapshotCertificate,
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<Vec<u8>, SharedAgentHostError> {
        let (intent, root_pins, journal, claim) =
            self.reconstruct_portable_backup(agent, limits)?;
        certificate
            .verify(intent.committee(), &claim)
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        let bundle = SharedAgentPortableBackupBundle {
            intent,
            root_pins,
            certificate: certificate.clone(),
            journal,
        };
        bundle.validate()?;
        Ok(bundle.encode())
    }

    /// Export the exact installed common checkpoint, including the source's
    /// separately authenticated physical binding and complete typed closure.
    pub fn export_common_checkpoint(
        &mut self,
        agent: AgentId,
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<Vec<u8>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let _initial = self.common_snapshot_initial_state(agent)?;
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if hosted.driver.uses_external_state() {
            // External checkpoint publication/reopen does not yet authorize
            // portable transfer or retention/reclamation of its block closure.
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        let (certificate, binding) = hosted
            .driver
            .common_snapshot_authority()
            .map_err(map_driver_error)?
            .ok_or(SharedAgentHostError::SnapshotBoundaryRequired)?;
        let journal = hosted
            .driver
            .portable_checkpoint(limits.journal()?)
            .map_err(map_driver_error)?;
        let recovery = hosted
            .driver
            .ledger()
            .common_snapshot_recovery_manifest()
            .map_err(map_ledger_error)?;
        let recovery = match certificate.claim().recovery_manifest() {
            Some(_) => Some(recovery.ok_or(SharedAgentHostError::CorruptResidue)?),
            None if recovery.as_ref().is_none_or(|manifest| manifest.is_empty()) => None,
            None => return Err(SharedAgentHostError::CorruptResidue),
        };
        let bundle = CommonCheckpointBundle {
            intent: hosted.intent.clone(),
            root_pins: self
                .root_pins
                .clone()
                .ok_or(SharedAgentHostError::InvalidProvision)?,
            certificate,
            binding,
            journal,
            recovery,
        };
        bundle.validate()?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(bundle.encode())
    }

    /// Candidate-only detached maintenance. This streams a storage archive,
    /// not a backup/import bundle or a new checkpoint activation capability.
    #[cfg(all(test, feature = "experimental-state-blocks"))]
    pub(crate) fn export_external_common_checkpoint_archive<W: std::io::Write>(
        &mut self,
        agent: AgentId,
        limits: super::journal_store::ExternalArchiveLimits,
        output: &mut W,
    ) -> Result<super::journal_store::ExternalArchiveReport, SharedAgentHostError> {
        let intent = self.require_external_archive_maintenance(agent)?;
        let _initial = self.common_snapshot_initial_state(agent)?;
        let report = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .export_external_common_checkpoint_archive(limits, output)
            .map_err(map_driver_error)?;
        if self.require_external_archive_maintenance(agent)? != intent {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(report)
    }

    #[cfg(all(test, feature = "experimental-state-blocks"))]
    fn require_external_archive_maintenance(
        &mut self,
        agent: AgentId,
    ) -> Result<Hash, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if !matches!(
            self.execution_selection,
            SharedExecutionSelection::ExternalLinearCandidates
        ) {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if !hosted.driver.uses_external_state()
            || !matches!(
                hosted.intent.authority,
                SharedGenesisAuthority::AuthorityFinalized(_)
            )
        {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        let namespaces = scan_generation_namespaces(&self.lease)?;
        let files = *namespaces
            .get(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if files.intent_stage
            || files.exposed_stage
            || files.portable_restore
            || files.portable_restore_stage
        {
            // Do not interpret pending route/genesis or paired installation
            // recovery as a completed detached export boundary.
            return Err(SharedAgentHostError::Conflict);
        }
        if !files.journal
            || !files.lock
            || !files.intent
            || !files.exposed
            || !files.raft
            || !files.artifacts
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let (intent, _) = self.read_intent(agent, files)?;
        if intent != hosted.intent || !self.read_exposure(agent, intent.id(), files)? {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(intent.id())
    }

    fn validate_common_source(
        &self,
        bundle: &CommonCheckpointBundle,
        limits: PortableJournalLimits,
    ) -> Result<(), SharedAgentHostError> {
        bundle.validate()?;
        if self.root_pins.as_ref() != Some(&bundle.root_pins)
            || self.scope().space != bundle.intent.space()
        {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        bundle
            .journal
            .validate_limits(limits)
            .map_err(|_| SharedAgentHostError::CapacityExhausted)?;
        let SharedGenesisAuthority::SystemBootstrap {
            provision,
            committee,
        } = &bundle.intent.authority
        else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        let source_node = bundle.binding.claim().local_node();
        let member = committee
            .member_by_node(source_node)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        if committee.member_by_node(self.scope().node).is_none() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let source_merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(CommonSnapshotReadOnlyNode(source_node));
        let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
            provision.proposal().create().clone(),
            member.replica(),
            &bundle.intent.catalog,
            Arc::clone(&self.trust),
            Arc::clone(&source_merge),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let sealed = seal_prepared_system_agent_genesis(prepared, &bundle.root_pins, provision)
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        preflight_common_source(
            &sealed,
            &bundle.intent.catalog,
            &bundle.journal,
            bundle.binding.claim(),
            limits.max_index_nodes,
            Arc::clone(&self.trust),
            source_merge,
            committee.clone(),
        )
        .map_err(map_driver_error)
    }

    /// Catch up an existing independently admitted, detached system replica.
    /// Namespace replacement, later log deletion, and a foreign Local lane
    /// are not authorized by this operation.
    #[cfg(test)]
    pub(crate) fn restore_common_checkpoint(
        &mut self,
        bytes: &[u8],
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if bytes.len() > MAX_COMMON_CHECKPOINT_BUNDLE_BYTES {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let bundle = CommonCheckpointBundle::decode(bytes)
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        if bundle.encode() != bytes {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        let journal_limits = limits.journal()?;
        self.validate_common_source(&bundle, journal_limits)?;
        let agent = bundle.intent.agent()?;
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let files = scan_generation_namespaces(&self.lease)?
            .remove(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if let Some(record) = self.read_common_restore(agent, files)? {
            if record.bundle.encode() != bytes {
                return Err(SharedAgentHostError::Conflict);
            }
            self.agents.remove(&agent);
            let hosted = self.resume_common_restore(agent, files, &record)?;
            let status = status_for(&hosted, false)?;
            retire_host_record(&self.portable_restore_path(agent))?;
            self.agents.insert(agent, hosted);
            return Ok(status);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if !hosted.intent.same_common_system_generation(&bundle.intent) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some((current, _)) = hosted
            .driver
            .common_snapshot_authority()
            .map_err(map_driver_error)?
            && current == bundle.certificate
        {
            return status_for(hosted, false);
        }
        hosted
            .driver
            .ledger()
            .validate_common_restore(&bundle.certificate)
            .map_err(map_ledger_error)?;
        let initial = self.common_snapshot_initial_state(agent)?;
        let _ = initial;
        let sealed = self.verify_and_prepare(&hosted.intent)?;
        let predecessor = hosted.driver.materialization().heads().clone();
        let rebound = preflight_common_rebind(
            &sealed,
            &bundle.journal,
            &predecessor,
            journal_limits,
            Arc::clone(&self.trust),
            Arc::clone(&self.merge),
            bundle.intent.committee().clone(),
        )
        .map_err(map_driver_error)?;
        let foundation = hosted
            .driver
            .ledger()
            .common_restore_foundation(&bundle.certificate)
            .map_err(map_ledger_error)?;
        let claim = rebound
            .physical_claim(bundle.certificate.claim(), &foundation)
            .map_err(map_driver_error)?;
        let candidate = VerifiedSharedAgentLocalSnapshotCandidate::from_reconstructed(
            bundle.certificate.commitment(),
            claim,
        );
        let signature = self
            .merge
            .sign_local_snapshot_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
        let binding = SharedAgentLocalSnapshotBinding::new(
            bundle.certificate.commitment(),
            candidate.claim().clone(),
            signature,
        )
        .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        rebound
            .validate(
                binding
                    .verify(&bundle.certificate, binding.claim())
                    .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?,
            )
            .map_err(map_driver_error)?;
        let record = CommonRestoreRecord {
            bundle,
            predecessor,
            binding,
        };
        // The exact source proof, destination predecessor and signed binding
        // survive both journal-first and ledger-first process interruption.
        if let Err(error) =
            install_host_record(&self.portable_restore_path(agent), &record.encode())
        {
            // Even an error may have left durable/staged recovery authority.
            // The predecessor must stop advancing until reopen audits it.
            self.agents.remove(&agent);
            return Err(error);
        }
        drop(
            self.agents
                .remove(&agent)
                .ok_or(SharedAgentHostError::AgentNotFound)?,
        );
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Marker)?;
        let files = scan_generation_namespaces(&self.lease)?
            .remove(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let hosted = self.resume_common_restore(agent, files, &record)?;
        let status = status_for(&hosted, false)?;
        retire_host_record(&self.portable_restore_path(agent))?;
        self.agents.insert(agent, hosted);
        Ok(status)
    }

    fn read_common_restore(
        &self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<Option<CommonRestoreRecord>, SharedAgentHostError> {
        if !files.portable_restore && !files.portable_restore_stage {
            return Ok(None);
        }
        let bytes =
            read_host_record_pair(&self.portable_restore_path(agent), MAX_COMMON_RESTORE_BYTES)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
        if !bytes.starts_with(&CommonRestoreRecord::MAGIC) {
            return Ok(None);
        }
        // Retained post-ACK recovery pins are not integrated yet. Production
        // cannot activate this test-qualified mutation through marker input.
        #[cfg(not(test))]
        return Err(SharedAgentHostError::PortableBackupUnsupported);
        #[cfg(test)]
        {
            let record = CommonRestoreRecord::decode(&bytes)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            if record.encode() != bytes
                || record.bundle.intent.agent()? != agent
                || record.binding.claim().local_node() != self.scope().node
            {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            Ok(Some(record))
        }
    }

    #[cfg(test)]
    fn read_common_install(
        &self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<Option<CommonInstallRecord>, SharedAgentHostError> {
        if !files.portable_restore && !files.portable_restore_stage {
            return Ok(None);
        }
        let bytes =
            read_host_record_pair(&self.portable_restore_path(agent), MAX_COMMON_RESTORE_BYTES)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
        if !bytes.starts_with(&CommonInstallRecord::MAGIC) {
            return Ok(None);
        }
        let record = CommonInstallRecord::decode(&bytes)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if record.encode() != bytes
            || record.target.runtime.agent != agent
            || record.target.node != self.scope().node
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(Some(record))
    }

    #[cfg(test)]
    fn resume_common_install(
        &mut self,
        agent: AgentId,
        files: GenerationFiles,
        record: &CommonInstallRecord,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        record.validate()?;
        let (intent, _) = self.read_intent(agent, files)?;
        if intent.id() != record.intent || !self.read_exposure(agent, intent.id(), files)? {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let sealed = self.verify_and_prepare(&intent)?;
        self.require_common_snapshot_genesis(&intent, &sealed)?;
        #[cfg(feature = "experimental-state-blocks")]
        if let PreparedSharedGenesis::ExternalAuthorityFinalized(external) = &sealed {
            return self.resume_external_common_install(agent, files, record, intent, external);
        }
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            self.scope().node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        slot.recover_portable_heads_stage(&record.predecessor, &record.target)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let mut store = slot
            .open(&sealed, true)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let heads = store
            .heads()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if heads != record.predecessor && heads != record.target {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        if heads == record.target {
            let generation = AgentGenerationRouteKey::new(
                self.scope().space,
                agent,
                sealed.genesis().id(),
                sealed.admission_record().id(),
            )
            .map_err(|_| SharedAgentHostError::InvalidProvision)?;
            validate_database_path(&self.raft_path(agent), true)?;
            let database = Arc::new(
                Database::create(self.raft_path(agent))
                    .map_err(|_| SharedAgentHostError::Unavailable)?,
            );
            let ledger = AgentRaftApplicationLedgerV2::open(
                database,
                generation,
                store.instance_id(),
                self.scope().node,
                intent.committee().clone(),
                intent.committee_authority,
            )
            .map_err(map_ledger_error)?;
            if record.binding.claim().journal_store().0 != *store.instance_id().as_bytes() {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            let resolver =
                super::journal_store::CatalogBlobResolverFactory::catalog_blob_resolver(&store)
                    .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let mut executor = super::local_journal_driver::StandardLocalReplayExecutor::new_shared(
                resolver,
                Arc::clone(&self.trust),
                Arc::clone(&self.merge),
                ledger.committee_history().map_err(map_ledger_error)?,
            );
            let materialization = super::replay::materialize_common_checkpoint(
                &mut store,
                &mut executor,
                &super::replay::NoPrunedOrderedBases,
                &record.certificate,
                &record.binding,
            )
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            super::replay::validate_common_checkpoint_state(
                &store,
                &materialization,
                record.binding.claim(),
                sealed.post_create(),
            )
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            ledger
                .install_common_snapshot(
                    &record.certificate,
                    &record.binding,
                    Some(&record.logical),
                )
                .map_err(map_ledger_error)?;
            drop(ledger);
        }
        drop(store);
        let mut hosted = self.open_generation(intent, &sealed, true, files, None)?;
        hosted
            .driver
            .install_common_snapshot(&record.certificate, &record.binding, sealed.post_create())
            .map_err(map_driver_error)?;
        Ok(hosted)
    }

    #[cfg(all(test, feature = "experimental-state-blocks"))]
    fn resume_external_common_install(
        &mut self,
        agent: AgentId,
        files: GenerationFiles,
        record: &CommonInstallRecord,
        intent: SharedGenesisIntent,
        external: &Arc<super::replay::ReplaySealedExternalGenesis>,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        let sealed = PreparedSharedGenesis::ExternalAuthorityFinalized(Arc::clone(external));
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            self.scope().node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let ledger = self.open_generation_ledger(&intent, &sealed, slot.instance_id(), true)?;
        if record.binding.claim().journal_store().0 != *slot.instance_id().as_bytes()
            || record.binding.claim().local_node() != self.scope().node
            || record.certificate.claim().active_committee() != intent.committee()
            || record.certificate.claim().authority_epoch()
                != intent.committee_authority.initial_epoch()
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let installed = ledger
            .common_snapshot_authority()
            .map_err(map_ledger_error)?;
        let exact_installed = installed.as_ref().is_some_and(|(certificate, binding)| {
            certificate == &record.certificate && binding == &record.binding
        });
        if !exact_installed {
            // A signed marker is not permission to discard a later durable
            // suffix. Check its entire physical ledger foundation before the
            // opener may promote or clean any staged journal endpoint.
            let context = ledger
                .snapshot_context(&record.logical)
                .map_err(map_ledger_error)?;
            let claim = record.binding.claim();
            let recovery_matches = match (
                record.certificate.claim().recovery_manifest(),
                context.recovery_manifest.as_ref(),
            ) {
                (Some(expected), Some(manifest)) => expected == manifest.commitment(),
                (None, manifest) => manifest.is_none_or(|manifest| manifest.is_empty()),
                _ => false,
            };
            if claim.ordered() != &context.ordered
                || claim.active_committee() != &context.active_committee
                || claim.authority_epoch() != context.authority_epoch
                || claim.boundary_payload_commitment() != context.boundary_payload_commitment
                || claim.ordered_successor() != context.ordered_successor
                || claim.retired_audit_root() != context.retired_audit_root
                || claim.committee_evidence_root() != context.committee_evidence_root
                || claim.previous_snapshot() != context.previous_snapshot
                || !recovery_matches
            {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
        }
        let mut budget = FileSharedDriver::external_recovery_budget();
        let (mut store, _, validated) = slot
            .open_external_shared_checkpoint_with_executor(
                external,
                |store| {
                    if store.instance_id() != ledger.journal_store() {
                        return Err(super::journal_store::JournalStoreError::ScopeMismatch);
                    }
                    let executor =
                        super::local_journal_driver::StandardLocalReplayExecutor::new_shared(
                            store.catalog_blob_resolver()?,
                            Arc::clone(&self.trust),
                            Arc::clone(&self.merge),
                            ledger
                                .committee_history()
                                .map_err(|_| super::journal_store::JournalStoreError::Corrupt)?,
                        );
                    Ok((executor, installed.clone()))
                },
                &super::replay::NoPrunedOrderedBases,
                &mut budget,
                Some((
                    &record.certificate,
                    &record.binding,
                    &record.predecessor,
                    &record.target,
                )),
            )
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let heads = store
            .heads()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if heads != record.predecessor && heads != record.target {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        if heads == record.target {
            let (materialization, availability) = validated
                .into_external_common_shared_availability(
                    &store,
                    external,
                    &record.certificate,
                    &record.binding,
                )
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            super::replay::validate_published_external_shared_checkpoint(
                &mut store,
                &materialization,
                record.binding.claim(),
                external,
                &availability,
                &mut budget,
            )
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            ledger
                .install_common_snapshot(
                    &record.certificate,
                    &record.binding,
                    Some(&record.logical),
                )
                .map_err(map_ledger_error)?;
        } else if exact_installed {
            // Ledger-first authority cannot coexist with its old journal head.
            return Err(SharedAgentHostError::CorruptResidue);
        }
        drop(store);
        drop(ledger);
        let mut hosted = self.open_generation(intent, &sealed, true, files, None)?;
        hosted
            .driver
            .install_common_snapshot(&record.certificate, &record.binding, external.post_create())
            .map_err(map_driver_error)?;
        Ok(hosted)
    }

    fn resume_common_restore(
        &mut self,
        agent: AgentId,
        files: GenerationFiles,
        record: &CommonRestoreRecord,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        self.validate_common_source(&record.bundle, absolute_portable_journal_limits())?;
        let (intent, _) = self.read_intent(agent, files)?;
        if !intent.same_common_system_generation(&record.bundle.intent)
            || !self.read_exposure(agent, intent.id(), files)?
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let sealed = self.verify_and_prepare(&intent)?;
        let rebound = preflight_common_rebind(
            &sealed,
            &record.bundle.journal,
            &record.predecessor,
            absolute_portable_journal_limits(),
            Arc::clone(&self.trust),
            Arc::clone(&self.merge),
            intent.committee().clone(),
        )
        .map_err(map_driver_error)?;
        let target = rebound.image().heads().clone();
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            self.scope().node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let generation = AgentGenerationRouteKey::new(
            self.scope().space,
            agent,
            sealed.genesis().id(),
            sealed.admission_record().id(),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        validate_database_path(&self.raft_path(agent), true)?;
        let database = Arc::new(
            Database::create(self.raft_path(agent))
                .map_err(|_| SharedAgentHostError::Unavailable)?,
        );
        let signed_store = super::shared_raft::JournalStoreInstanceId::from_bytes(
            record.binding.claim().journal_store().0,
        )
        .ok_or(SharedAgentHostError::CorruptResidue)?;
        let ledger = AgentRaftApplicationLedgerV2::open(
            database,
            generation,
            signed_store,
            self.scope().node,
            intent.committee().clone(),
            intent.committee_authority,
        )
        .map_err(map_ledger_error)?;
        let foundation = ledger
            .common_restore_foundation(&record.bundle.certificate)
            .map_err(map_ledger_error)?;
        let expected = rebound
            .physical_claim(record.bundle.certificate.claim(), &foundation)
            .map_err(map_driver_error)?;
        let verified = record
            .binding
            .verify(&record.bundle.certificate, &expected)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        let exact_installed = ledger
            .common_snapshot_authority()
            .map_err(map_ledger_error)?
            .is_some_and(|(certificate, binding)| {
                certificate == record.bundle.certificate && binding == record.binding
            });
        if !exact_installed {
            ledger
                .validate_common_restore(&record.bundle.certificate)
                .map_err(map_ledger_error)?;
        }
        let checkpoint = rebound.validate(verified).map_err(map_driver_error)?;
        // Recheck the durable Raft boundary before completing even an exact
        // staged journal CAS. A recovery marker never authorizes dropping a
        // later physical suffix that might have committed on another voter.
        slot.recover_portable_heads_stage(&record.predecessor, &target)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let mut store = slot
            .open(&sealed, true)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if store.instance_id() != signed_store {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        store
            .install_common_checkpoint(&checkpoint, MAX_PORTABLE_JOURNAL_OBJECTS)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        #[cfg(test)]
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Journal)?;
        let recovery = record.bundle.recovery_manifest_for_restore()?;
        ledger
            .restore_common_snapshot(&record.bundle.certificate, &record.binding, &recovery)
            .map_err(map_ledger_error)?;
        #[cfg(test)]
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Ledger)?;
        drop(store);
        drop(ledger);
        self.open_generation(intent, &sealed, true, files, None)
    }

    /// Import one fully preflighted portable system-Agent checkpoint into an
    /// absent generation. The configured root pins remain independent input;
    /// bytes carried by the bundle can only match them, never replace them.
    pub fn restore_portable_backup(
        &mut self,
        bytes: &[u8],
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.restore_portable_backup_inner(bytes, limits, false)
    }

    #[cfg(test)]
    pub(crate) fn restore_portable_backup_through_heads_stage_for_test(
        &mut self,
        bytes: &[u8],
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.restore_portable_backup_inner(bytes, limits, true)
    }

    fn restore_portable_backup_inner(
        &mut self,
        bytes: &[u8],
        limits: SharedAgentPortableBackupLimits,
        stage_heads_only_for_test: bool,
    ) -> Result<SharedAgentStatus, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let journal_limits = limits.journal()?;
        let maximum = usize::try_from(limits.max_bytes)
            .ok()
            .and_then(|maximum| maximum.checked_add(MAX_SHARED_GENESIS_INTENT_BYTES))
            .and_then(|maximum| maximum.checked_add(MAX_ROOT_ANCHOR_PINS_BYTES))
            .and_then(|maximum| {
                maximum.checked_add(MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES)
            })
            .and_then(|maximum| maximum.checked_add(4096))
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        let mut recovery = self.prepare_portable_restore(bytes, journal_limits, maximum)?;
        recovery.stage_heads_only_for_test = stage_heads_only_for_test;
        let agent = recovery.bundle.intent.agent()?;
        if self.agents.contains_key(&agent) || self.deferred_generations.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let current = scan_generation_namespaces(&self.lease)?;
        if self
            .agents
            .len()
            .saturating_add(self.deferred_generations.len())
            >= MAX_SHARED_HOST_AGENTS
            || !current.contains_key(&agent) && current.len() == MAX_SHARED_HOST_AGENTS
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        if let Some(files) = current.get(&agent) {
            if !files.portable_restore && !files.portable_restore_stage {
                return Err(SharedAgentHostError::Conflict);
            }
            let retained = read_host_record_pair(
                &self.portable_restore_path(agent),
                MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES,
            )?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
            if retained != bytes {
                return Err(SharedAgentHostError::Conflict);
            }
        }

        // This independently authenticated full bundle is the sole recovery
        // authority across the journal/Raft commit boundary. It is durable
        // before the first generation byte and retained until both stores
        // have reopened against the exact logical checkpoint.
        install_host_record(&self.portable_restore_path(agent), bytes)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let mut files = scan_generation_namespaces(&self.lease)?
            .remove(&agent)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if files.intent || files.intent_stage {
            let (intent, _) = self.read_intent(agent, files)?;
            if intent != recovery.bundle.intent {
                return Err(SharedAgentHostError::Conflict);
            }
        }
        let sealed = self.verify_and_prepare(&recovery.bundle.intent)?;
        install_host_record(&self.intent_path(agent), &recovery.bundle.intent.encode())?;
        files.intent = true;
        let exposed = self.read_exposure(agent, recovery.bundle.intent.id(), files)?;
        let hosted = self.open_generation(
            recovery.bundle.intent.clone(),
            &sealed,
            exposed,
            files,
            Some(&recovery),
        )?;
        let status = status_for(&hosted, false)?;
        retire_host_record(&self.portable_restore_path(agent))?;
        if self.agents.insert(agent, hosted).is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(status)
    }

    #[cfg(test)]
    pub(crate) fn retain_portable_restore_marker_for_test(
        &mut self,
        bytes: &[u8],
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<AgentId, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let journal_limits = limits.journal()?;
        let maximum = usize::try_from(limits.max_bytes)
            .ok()
            .and_then(|maximum| maximum.checked_add(MAX_SHARED_GENESIS_INTENT_BYTES))
            .and_then(|maximum| maximum.checked_add(MAX_ROOT_ANCHOR_PINS_BYTES))
            .and_then(|maximum| {
                maximum.checked_add(MAX_SHARED_AGENT_PORTABLE_SNAPSHOT_CERTIFICATE_BYTES)
            })
            .and_then(|maximum| maximum.checked_add(4096))
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        let recovery = self.prepare_portable_restore(bytes, journal_limits, maximum)?;
        let agent = recovery.bundle.intent.agent()?;
        if self.agents.contains_key(&agent)
            || scan_generation_namespaces(&self.lease)?.contains_key(&agent)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        install_host_record(&self.portable_restore_path(agent), bytes)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(agent)
    }

    fn prepare_portable_restore(
        &self,
        bytes: &[u8],
        journal_limits: PortableJournalLimits,
        maximum_bundle_bytes: usize,
    ) -> Result<PreparedPortableRestore, SharedAgentHostError> {
        if bytes.len() > maximum_bundle_bytes
            || bytes.len() > MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let bundle = SharedAgentPortableBackupBundle::decode(bytes)
            .map_err(|_| SharedAgentHostError::PortableBackupInvalid)?;
        if bundle.encode() != bytes {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        let verified = bundle.validate()?;
        bundle
            .journal
            .validate_limits(journal_limits)
            .map_err(|_| SharedAgentHostError::CapacityExhausted)?;
        let configured_root = self
            .root_pins
            .as_ref()
            .ok_or(SharedAgentHostError::PortableBackupUnsupported)?;
        if configured_root != &bundle.root_pins
            || self.scope().space != bundle.intent.space()
            || self.scope().node != bundle.certificate.claim().local_node()
        {
            return Err(SharedAgentHostError::PortableBackupInvalid);
        }
        let sealed = self.verify_and_prepare(&bundle.intent)?;
        preflight_portable_checkpoint(
            &sealed,
            &bundle.intent.catalog,
            &bundle.journal,
            bundle.certificate.claim(),
            journal_limits.max_index_nodes,
            Arc::clone(&self.trust),
            Arc::clone(&self.merge),
            bundle.intent.committee().clone(),
        )
        .map_err(map_driver_error)?;
        Ok(PreparedPortableRestore {
            bundle,
            verified,
            maximum_index_nodes: journal_limits.max_index_nodes,
            stage_heads_only_for_test: false,
        })
    }

    fn read_portable_restore(
        &self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<Option<PreparedPortableRestore>, SharedAgentHostError> {
        if !files.portable_restore && !files.portable_restore_stage {
            return Ok(None);
        }
        let bytes = read_host_record_pair(
            &self.portable_restore_path(agent),
            MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES,
        )?
        .ok_or(SharedAgentHostError::CorruptResidue)?;
        let recovery = self.prepare_portable_restore(
            &bytes,
            absolute_portable_journal_limits(),
            MAX_SHARED_AGENT_PORTABLE_BACKUP_BYTES,
        )?;
        if recovery.bundle.intent.agent()? != agent {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        install_host_record(&self.portable_restore_path(agent), &bytes)?;
        Ok(Some(recovery))
    }

    fn reconstruct_portable_backup(
        &mut self,
        agent: AgentId,
        limits: SharedAgentPortableBackupLimits,
    ) -> Result<
        (
            SharedGenesisIntent,
            RootAnchorPins,
            PortableJournalCheckpoint,
            SharedAgentPortableSnapshotClaim,
        ),
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let journal_limits = limits.journal()?;
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let SharedGenesisAuthority::SystemBootstrap {
            provision,
            committee,
        } = &hosted.intent.authority
        else {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        };
        let root_pins = self
            .root_pins
            .as_ref()
            .ok_or(SharedAgentHostError::PortableBackupUnsupported)?;
        if provision.root() != root_pins
            || committee.members().len() != 1
            || committee.voter_count() != 1
        {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        let (journal, claim) = hosted
            .driver
            .portable_snapshot_candidate(
                hosted.intent.id(),
                portable_root_pins_commitment(root_pins),
                journal_limits,
            )
            .map_err(map_driver_error)?;
        if claim.active_committee() != committee
            || claim.authority_epoch() != hosted.intent.committee_authority.initial_epoch()
            || claim.local_node() != self.scope().node
        {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        Ok((hosted.intent.clone(), root_pins.clone(), journal, claim))
    }

    /// Derive and locally verify an exact Agent checkpoint candidate without
    /// mutation. Only the opaque result exposes the signing message; decoding
    /// an unsigned claim is never signing authority. Remote voters must also
    /// validate authenticated candidate evidence before signing. That
    /// composite-network evidence exchange is not attached by this host.
    pub fn request_snapshot_compaction(
        &mut self,
        agent: AgentId,
    ) -> Result<VerifiedSharedAgentSnapshotCandidate, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let claim = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .snapshot_candidate()
            .map_err(map_driver_error)?;
        Ok(VerifiedSharedAgentSnapshotCandidate::from_reconstructed(
            claim,
        ))
    }

    fn common_snapshot_initial_state(
        &self,
        agent: AgentId,
    ) -> Result<super::wire::RuntimeState, SharedAgentHostError> {
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let sealed = self.verify_and_prepare(&hosted.intent)?;
        self.require_common_snapshot_genesis(&hosted.intent, &sealed)?;
        if hosted.driver.materialization().runtime() != sealed.genesis().runtime() {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        hosted
            .driver
            .require_common_snapshot_profile(sealed.post_create())
            .map_err(map_driver_error)?;
        Ok(sealed.post_create().clone())
    }

    /// Common checkpoints remain restricted to the fixed system image or an
    /// explicitly selected, Authority-finalized external Linear candidate.
    /// Ordinary image Agents and decoded external descriptor bytes cannot opt
    /// into either profile by themselves.
    fn require_common_snapshot_genesis(
        &self,
        intent: &SharedGenesisIntent,
        sealed: &PreparedSharedGenesis,
    ) -> Result<(), SharedAgentHostError> {
        let supported = match sealed {
            PreparedSharedGenesis::SystemBootstrap(_) => matches!(
                intent.authority,
                SharedGenesisAuthority::SystemBootstrap { .. }
            ),
            #[cfg(feature = "experimental-state-blocks")]
            PreparedSharedGenesis::ExternalAuthorityFinalized(external) => {
                external.is_shared()
                    && matches!(
                        self.execution_selection,
                        SharedExecutionSelection::ExternalLinearCandidates
                    )
                    && matches!(
                        intent.authority,
                        SharedGenesisAuthority::AuthorityFinalized(_)
                    )
            }
            PreparedSharedGenesis::AuthorityFinalized(_) => false,
        };
        let committee = intent.committee();
        if !supported || committee.members().len() != 3 || committee.voter_count() != 3 {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        Ok(())
    }

    /// Independently reconstruct this replica's common checkpoint boundary.
    /// Only the fixed-three-voter system image and explicitly selected external
    /// Linear candidates qualify; arbitrary node-private histories do not.
    pub fn request_common_snapshot_compaction(
        &mut self,
        agent: AgentId,
    ) -> Result<VerifiedSharedAgentCommonSnapshotCandidate, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        let initial = self.common_snapshot_initial_state(agent)?;
        let (claim, _, _) = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .common_snapshot_candidate(&initial)
            .map_err(map_driver_error)?;
        let intent = &self
            .agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .intent;
        if claim.active_committee() != intent.committee()
            || claim.authority_epoch() != intent.committee_authority.initial_epoch()
        {
            return Err(SharedAgentHostError::PortableBackupUnsupported);
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        Ok(VerifiedSharedAgentCommonSnapshotCandidate::from_reconstructed(claim))
    }

    pub fn verify_common_snapshot_candidate(
        &mut self,
        agent: AgentId,
        claim: &SharedAgentCommonSnapshotClaim,
    ) -> Result<VerifiedSharedAgentCommonSnapshotCandidate, SharedAgentHostError> {
        let candidate = self.request_common_snapshot_compaction(agent)?;
        if candidate.claim() != claim {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        Ok(candidate)
    }

    pub fn sign_common_snapshot_candidate(
        &mut self,
        agent: AgentId,
        claim: &SharedAgentCommonSnapshotClaim,
    ) -> Result<ReplicaCommitSignature, SharedAgentHostError> {
        let candidate = self.verify_common_snapshot_candidate(agent, claim)?;
        self.merge
            .sign_common_snapshot_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)
    }

    #[cfg(test)]
    pub(crate) fn common_snapshot_authority_for_test(
        &mut self,
        agent: AgentId,
    ) -> Result<
        Option<(
            SharedAgentCommonSnapshotCertificate,
            SharedAgentLocalSnapshotBinding,
        )>,
        SharedAgentHostError,
    > {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .common_snapshot_authority()
            .map_err(map_driver_error)
    }

    #[cfg(test)]
    pub(crate) fn common_snapshot_recovery_manifest_for_test(
        &mut self,
        agent: AgentId,
    ) -> Result<Option<super::shared_recovery::SharedRecoveryManifest>, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .common_snapshot_recovery_manifest()
            .map_err(map_driver_error)
    }

    #[cfg(all(test, feature = "experimental-state-blocks"))]
    pub(crate) fn external_inspection_lanes_for_test(
        &mut self,
        agent: AgentId,
    ) -> Result<Vec<crate::agent_sdk::state_execution::ExternalLaneWork>, SharedAgentHostError>
    {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .materialization()
            .external_inspection_lanes()
            .map_err(|_| SharedAgentHostError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn shared_genesis_intent_for_test(
        &mut self,
        agent: AgentId,
    ) -> Result<Hash, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        self.agents
            .get(&agent)
            .map(|hosted| hosted.intent.id())
            .ok_or(SharedAgentHostError::AgentNotFound)
    }

    /// Each voter binds the common certificate to its own reconstructed store.
    /// As with legacy snapshots, the Raft worker must be detached first.
    #[cfg(test)]
    pub(crate) fn install_common_snapshot(
        &mut self,
        agent: AgentId,
        certificate: &SharedAgentCommonSnapshotCertificate,
    ) -> Result<SharedAgentSnapshotInstall, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let initial = self.common_snapshot_initial_state(agent)?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if certificate.claim().active_committee() != hosted.intent.committee()
            || certificate.claim().authority_epoch()
                != hosted.intent.committee_authority.initial_epoch()
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let existing = hosted
            .driver
            .common_snapshot_authority()
            .map_err(map_driver_error)?;
        let binding = if let Some((old, binding)) = existing.filter(|(old, _)| old == certificate) {
            let _ = old;
            binding
        } else {
            let (common, physical, target) = hosted
                .driver
                .common_snapshot_candidate(&initial)
                .map_err(map_driver_error)?;
            certificate
                .verify(common.active_committee(), &common)
                .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
            let candidate = VerifiedSharedAgentLocalSnapshotCandidate::from_reconstructed(
                certificate.commitment(),
                physical,
            );
            let signature = self
                .merge
                .sign_local_snapshot_candidate(&candidate)
                .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
            let binding = SharedAgentLocalSnapshotBinding::new(
                certificate.commitment(),
                candidate.claim().clone(),
                signature,
            )
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
            let record = CommonInstallRecord {
                intent: hosted.intent.id(),
                certificate: certificate.clone(),
                binding: binding.clone(),
                predecessor: hosted.driver.materialization().heads().clone(),
                target,
                logical: hosted
                    .driver
                    .snapshot_boundary_claim()
                    .map_err(map_driver_error)?,
            };
            record.validate()?;
            let marker = self.lease.root().join(format!(
                "{}{}",
                encode_agent_id(agent),
                PORTABLE_RESTORE_SUFFIX
            ));
            if let Err(error) = install_host_record(&marker, &record.encode()) {
                self.agents.remove(&agent);
                return Err(error);
            }
            binding
        };
        // From the first possible head mutation until marker retirement this
        // owner must not be discoverable or reattached to a Raft worker.
        // Any error drops it; only exact marker recovery can make it live.
        let mut hosted = self
            .agents
            .remove(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Marker)?;
        let installed =
            if self.common_checkpoint_crash == Some(CommonCheckpointCrashStage::Journal) {
                self.common_checkpoint_crash = None;
                hosted
                    .driver
                    .install_common_snapshot_through_journal_for_test(
                        certificate,
                        &binding,
                        &initial,
                    )
            } else {
                hosted
                    .driver
                    .install_common_snapshot(certificate, &binding, &initial)
            }
            .map_err(map_driver_error)?;
        self.common_checkpoint_crash_at(CommonCheckpointCrashStage::Ledger)?;
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        retire_host_record(&self.portable_restore_path(agent))?;
        self.agents.insert(agent, hosted);
        Ok(SharedAgentSnapshotInstall {
            raft_index: installed.claim.raft_index(),
            raft_term: installed.claim.raft_term(),
            certificate: installed.certificate_commitment,
            journal_heads: installed.claim.journal_heads(),
        })
    }

    /// Verify, publish, and atomically install one exact Agent snapshot.
    pub fn install_snapshot(
        &mut self,
        agent: AgentId,
        certificate: &SharedAgentSnapshotCertificate,
    ) -> Result<SharedAgentSnapshotInstall, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        // The current full-NodeId worker intentionally has no generic byte
        // snapshot bridge for an authenticated Agent journal certificate.
        // Mutating its shared database underneath a live storage cache would
        // desynchronize the worker and make its next reopen fail closed.
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let installed = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .install_snapshot(certificate)
            .map_err(map_driver_error)?;
        Ok(SharedAgentSnapshotInstall {
            raft_index: installed.claim.raft_index(),
            raft_term: installed.claim.raft_term(),
            certificate: installed.certificate_commitment,
            journal_heads: installed.claim.journal_heads(),
        })
    }

    pub fn install_snapshot_bytes(
        &mut self,
        agent: AgentId,
        bytes: &[u8],
    ) -> Result<SharedAgentSnapshotInstall, SharedAgentHostError> {
        if bytes.len() > super::shared_commit::MAX_SHARED_AGENT_SNAPSHOT_CERTIFICATE_BYTES {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let certificate = SharedAgentSnapshotCertificate::decode(bytes)
            .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        if certificate.encode() != bytes {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        self.install_snapshot(agent, &certificate)
    }

    /// Resume fail-closed retirement of Shared commit bindings and bounded
    /// retirement of unreachable journal objects/blobs after a snapshot is
    /// durably installed. Binding validation is limited by the fixed
    /// namespace capacity, while `max_binding_unlinks` bounds mutations. A
    /// false `complete` is backpressure, never a claim that cleanup finished.
    pub fn compact_snapshot(
        &mut self,
        agent: AgentId,
        limits: SharedAgentCompactionLimits,
    ) -> Result<SharedAgentCompaction, SharedAgentHostError> {
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        // Live anti-entropy may have authenticated parent objects durably
        // staged but not yet reachable from Heads. Generic journal GC quite
        // correctly treats those as garbage, so compaction requires the exact
        // generation transport to be retired first. Reattachment resumes from
        // every staged object which survived a crash; an operator-triggered
        // detached GC deliberately chooses to discard that cache and refetch.
        if self.transport_leases.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        if limits.max_binding_unlinks == 0 {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let outcome = self
            .agents
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .driver
            .compact_snapshot(
                limits.max_binding_unlinks,
                super::journal_store::GcLimits {
                    max_index_nodes: limits.max_index_nodes,
                    max_marked_objects: limits.max_marked_objects,
                    max_marked_blobs: limits.max_marked_blobs,
                    max_scanned_files: limits.max_scanned_files,
                    max_scanned_bytes: limits.max_scanned_bytes,
                    max_unlinks_per_run: limits.max_unlinks,
                },
            )
            .map_err(map_driver_error)?;
        let journal = outcome.journal;
        Ok(SharedAgentCompaction {
            bindings_removed: outcome.bindings_removed,
            bindings_remaining: outcome.bindings_remaining,
            objects_removed: journal.map_or(0, |gc| gc.objects_removed),
            blobs_removed: journal.map_or(0, |gc| gc.blobs_removed),
            aliases_removed: journal.map_or(0, |gc| gc.aliases_removed),
            resumed: journal.is_some_and(|gc| gc.resumed),
            complete: outcome.bindings_remaining == 0 && journal.is_some_and(|gc| gc.complete),
        })
    }

    fn verify_and_prepare(
        &self,
        intent: &SharedGenesisIntent,
    ) -> Result<PreparedSharedGenesis, SharedAgentHostError> {
        self.verify_and_prepare_with_finality(intent, self.finality.as_ref())
    }

    fn verify_and_prepare_with_finality(
        &self,
        intent: &SharedGenesisIntent,
        finality: &dyn AgentGenesisFinalityVerifier,
    ) -> Result<PreparedSharedGenesis, SharedAgentHostError> {
        self.verify_and_prepare_with_role(intent, finality, false)
    }

    /// Like `verify_and_prepare_with_finality`; `allow_joiner` additionally
    /// seals an ordinary generation for a local node outside its genesis
    /// committee. Only explicit joiner provisioning and the reopen of an
    /// already retained intent pass it.
    fn verify_and_prepare_with_role(
        &self,
        intent: &SharedGenesisIntent,
        finality: &dyn AgentGenesisFinalityVerifier,
        allow_joiner: bool,
    ) -> Result<PreparedSharedGenesis, SharedAgentHostError> {
        intent.validate()?;
        match &intent.authority {
            SharedGenesisAuthority::AuthorityFinalized(provision) => {
                let verified = VerifiedAgentGenesisProvision::verify(provision.clone(), finality)
                    .map_err(map_provision_verification_error)?;
                let Some(member) = verified
                    .provision()
                    .replicas()
                    .member_by_node(self.scope().node)
                else {
                    if !allow_joiner {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    #[cfg(feature = "experimental-state-blocks")]
                    if verified
                        .provision()
                        .proposal()
                        .create()
                        .runtime
                        .is_external_state()
                    {
                        return Err(SharedAgentHostError::InvalidProvision);
                    }
                    return LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_shared_joiner_genesis(
                        &verified,
                        joiner_storage_replica(self.scope().node),
                        &intent.catalog,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                    )
                    .map(PreparedSharedGenesis::AuthorityFinalized)
                    .map_err(|_| SharedAgentHostError::InvalidProvision);
                };
                #[cfg(feature = "experimental-state-blocks")]
                if verified
                    .provision()
                    .proposal()
                    .create()
                    .runtime
                    .is_external_state()
                {
                    if !matches!(
                        self.execution_selection,
                        SharedExecutionSelection::ExternalLinearCandidates
                    ) {
                        return Err(SharedAgentHostError::InvalidProvision);
                    }
                    return LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_external_shared_genesis(
                        &verified, member.replica(), &intent.catalog, &self.trust, self.scope().node,
                    )
                    .map(|sealed| PreparedSharedGenesis::ExternalAuthorityFinalized(Arc::new(sealed)))
                    .map_err(|_| SharedAgentHostError::InvalidProvision);
                }
                LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_shared_genesis(
                    &verified,
                    member.replica(),
                    &intent.catalog,
                    Arc::clone(&self.trust),
                    Arc::clone(&self.merge),
                )
                .map(PreparedSharedGenesis::AuthorityFinalized)
                .map_err(|_| SharedAgentHostError::InvalidProvision)
            }
            SharedGenesisAuthority::SystemBootstrap {
                provision,
                committee,
            } => {
                let configured_root = self
                    .root_pins
                    .as_ref()
                    .ok_or(SharedAgentHostError::InvalidProvision)?;
                if provision.root() != configured_root {
                    return Err(SharedAgentHostError::InvalidProvision);
                }
                let member = committee
                    .member_by_node(self.scope().node)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                let prepared =
                    LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
                        provision.proposal().create().clone(),
                        member.replica(),
                        &intent.catalog,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                    )
                    .map_err(|_| SharedAgentHostError::InvalidProvision)?;
                seal_prepared_system_agent_genesis(prepared, configured_root, provision)
                    .map(PreparedSharedGenesis::SystemBootstrap)
                    .map_err(|_| SharedAgentHostError::InvalidProvision)
            }
        }
    }

    fn open_generation_ledger(
        &self,
        intent: &SharedGenesisIntent,
        sealed: &PreparedSharedGenesis,
        journal_store: super::shared_raft::JournalStoreInstanceId,
        externally_exposed: bool,
    ) -> Result<AgentRaftApplicationLedgerV2, SharedAgentHostError> {
        let agent = intent.agent()?;
        let generation = AgentGenerationRouteKey::new(
            self.scope().space,
            agent,
            sealed.genesis().id(),
            sealed.admission_record().id(),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        validate_database_path(&self.raft_path(agent), externally_exposed)?;
        let database = Arc::new(
            Database::create(self.raft_path(agent))
                .map_err(|_| SharedAgentHostError::Unavailable)?,
        );
        // Only joiner provisioning (or the reopen of its retained intent)
        // reaches here for a node outside the genesis committee.
        let open = if intent
            .committee()
            .member_by_node(self.scope().node)
            .is_some()
        {
            AgentRaftApplicationLedgerV2::open
        } else {
            AgentRaftApplicationLedgerV2::open_joiner
        };
        let ledger = open(
            database,
            generation,
            journal_store,
            self.scope().node,
            intent.committee().clone(),
            intent.committee_authority,
        )
        .map_err(map_ledger_error)?;
        #[cfg(not(test))]
        {
            #[cfg(feature = "experimental-state-blocks")]
            let external_candidate = matches!(
                (self.execution_selection, sealed),
                (
                    SharedExecutionSelection::ExternalLinearCandidates,
                    PreparedSharedGenesis::ExternalAuthorityFinalized(_)
                )
            );
            #[cfg(not(feature = "experimental-state-blocks"))]
            let external_candidate = false;
            if !external_candidate
                && ledger
                    .common_snapshot_authority()
                    .map_err(map_ledger_error)?
                    .is_some()
            {
                return Err(SharedAgentHostError::PortableBackupUnsupported);
            }
        }
        Ok(ledger)
    }

    fn open_generation(
        &mut self,
        intent: SharedGenesisIntent,
        sealed: &PreparedSharedGenesis,
        externally_exposed: bool,
        files: GenerationFiles,
        portable_restore: Option<&PreparedPortableRestore>,
    ) -> Result<HostedSharedAgent, SharedAgentHostError> {
        let started = std::time::Instant::now();
        let report_phase = |phase: &'static str| {
            tracing::debug!(
                phase,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Shared generation open phase complete"
            );
        };
        let agent = intent.agent()?;
        let scope = self.scope();
        if portable_restore.is_some_and(|recovery| recovery.bundle.intent != intent) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        if externally_exposed && !(files.journal && files.lock && files.raft && files.artifacts) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let (journal_parent, authority_parent) = self
            .lease
            .clone_generation_parents()
            .map_err(map_outer_lease_error)?;
        let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_path(agent),
            self.journal_lock_path(agent),
            scope.node,
            intent.id(),
            &journal_parent,
            &authority_parent,
        )
        .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if let Some(recovery) = portable_restore {
            slot.recover_portable_heads_stage(
                &sealed.initial_heads(),
                recovery.bundle.journal.heads(),
            )
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        }
        #[cfg(feature = "experimental-state-blocks")]
        let mut external_ledger = None;
        let store_result = match sealed {
            #[cfg(feature = "experimental-state-blocks")]
            PreparedSharedGenesis::ExternalAuthorityFinalized(external) => {
                if portable_restore.is_some() {
                    return Err(SharedAgentHostError::PortableBackupUnsupported);
                }
                if externally_exposed {
                    // The stable slot identity is known before a journal head
                    // is admitted. Read its exact installed common authority
                    // from the generation-bound ledger, never from file names.
                    let ledger =
                        self.open_generation_ledger(&intent, sealed, slot.instance_id(), true)?;
                    // Construct the verifier from this exact locked namespace;
                    // both durable and staged external heads are audited before
                    // a store or network route becomes available.
                    let result = slot.open_external_shared_checkpoint_with_executor(
                        external,
                        |store| {
                            if store.instance_id() != ledger.journal_store() {
                                return Err(super::journal_store::JournalStoreError::ScopeMismatch);
                            }
                            let committees = ledger.committee_history()
                                .map_err(|_| super::journal_store::JournalStoreError::Corrupt)?;
                            let authority = ledger.common_snapshot_authority()
                                .map_err(|_| super::journal_store::JournalStoreError::Corrupt)?;
                            let executor = super::local_journal_driver::StandardLocalReplayExecutor::new_shared(
                                store.catalog_blob_resolver()?,
                                Arc::clone(&self.trust),
                                Arc::clone(&self.merge),
                                committees,
                            );
                            Ok((executor, authority))
                        },
                        &super::replay::NoPrunedOrderedBases,
                        &mut FileSharedDriver::external_recovery_budget(),
                        None,
                    );
                    external_ledger = Some(ledger);
                    result.map(|(store, _, _)| store)
                } else {
                    slot.open_external_genesis(
                        external,
                        false,
                        &mut FileSharedDriver::external_recovery_budget(),
                    )
                }
            }
            _ => slot.open(sealed, externally_exposed),
        };
        let mut store = store_result.map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let state = (store.genesis(), store.heads());
        let state = match state {
            (Ok(genesis), Ok(heads)) => (genesis, heads),
            _ => return Err(SharedAgentHostError::CorruptResidue),
        };
        let portable_already_activated = if let Some(recovery) = portable_restore {
            if let Some(heads) = &state.1 {
                if heads != &sealed.initial_heads() && heads != recovery.bundle.journal.heads() {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
            }
            state.1.as_ref() == Some(recovery.bundle.journal.heads())
        } else {
            false
        };
        if portable_already_activated {
            let recovery = portable_restore.ok_or(SharedAgentHostError::CorruptResidue)?;
            store
                .install_portable_checkpoint(&recovery.bundle.journal, recovery.maximum_index_nodes)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        }

        report_phase("journal_store");
        let generation = AgentGenerationRouteKey::new(
            scope.space,
            agent,
            sealed.genesis().id(),
            sealed.admission_record().id(),
        )
        .map_err(|_| SharedAgentHostError::InvalidProvision)?;
        let raft_path = self.raft_path(agent);
        #[cfg(feature = "experimental-state-blocks")]
        let ledger = match external_ledger {
            Some(ledger) => ledger,
            None => self.open_generation_ledger(
                &intent,
                sealed,
                store.instance_id(),
                externally_exposed,
            )?,
        };
        #[cfg(not(feature = "experimental-state-blocks"))]
        let ledger =
            self.open_generation_ledger(&intent, sealed, store.instance_id(), externally_exposed)?;
        if portable_already_activated {
            let recovery = portable_restore.ok_or(SharedAgentHostError::CorruptResidue)?;
            ledger
                .restore_portable_snapshot(&recovery.bundle.certificate, &recovery.verified)
                .map_err(map_ledger_error)?;
        }

        report_phase("raft_ledger");
        let artifact_path = self.artifact_path(agent);
        validate_artifact_path(&artifact_path, externally_exposed)?;
        let artifacts = FileSharedArtifactStager::open(&artifact_path, generation)
            .map_err(map_artifact_error)?;
        report_phase("artifact_store");
        let mut driver = match state {
            (None, None) | (Some(_), None) => match sealed {
                PreparedSharedGenesis::AuthorityFinalized(sealed) => {
                    FileSharedDriver::create_shared_unexposed(
                        store,
                        artifacts,
                        ledger,
                        sealed,
                        &intent.catalog,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                    )
                }
                PreparedSharedGenesis::SystemBootstrap(sealed) => {
                    FileSharedDriver::create_shared_unexposed(
                        store,
                        artifacts,
                        ledger,
                        sealed,
                        &intent.catalog,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                    )
                }
                #[cfg(feature = "experimental-state-blocks")]
                PreparedSharedGenesis::ExternalAuthorityFinalized(sealed) => {
                    FileSharedDriver::create_external_unexposed(
                        store,
                        artifacts,
                        ledger,
                        Arc::clone(sealed),
                        &intent.catalog,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                    )
                }
            },
            (Some(_), Some(_)) => match sealed {
                #[cfg(feature = "experimental-state-blocks")]
                PreparedSharedGenesis::ExternalAuthorityFinalized(sealed) => {
                    FileSharedDriver::open_external(
                        store,
                        artifacts,
                        ledger,
                        Arc::clone(&self.trust),
                        Arc::clone(&self.merge),
                        Arc::clone(sealed),
                    )
                }
                _ => FileSharedDriver::open_shared_unexposed(
                    store,
                    artifacts,
                    ledger,
                    Arc::clone(&self.trust),
                    Arc::clone(&self.merge),
                ),
            },
            (None, Some(_)) => return Err(SharedAgentHostError::CorruptResidue),
        }
        .map_err(map_driver_error)?;

        report_phase("journal_driver");
        self.lease
            .arm_after_agent_open()
            .map_err(map_outer_lease_error)?;
        match sealed {
            PreparedSharedGenesis::AuthorityFinalized(sealed) => {
                driver.commit_exposure(sealed, intent.id())
            }
            PreparedSharedGenesis::SystemBootstrap(sealed) => {
                driver.commit_exposure(sealed, intent.id())
            }
            #[cfg(feature = "experimental-state-blocks")]
            PreparedSharedGenesis::ExternalAuthorityFinalized(sealed) => {
                if externally_exposed {
                    // Exposed slot open already checked the durable stable-lock
                    // marker and replayed the current roots. The genesis-only
                    // publication check must not be applied to a later head.
                    Ok(())
                } else {
                    driver.commit_external_genesis_exposure(sealed, intent.id())
                }
            }
        }
        .map_err(map_driver_error)?;
        install_host_record(&self.exposure_path(agent), intent.id().as_bytes())?;
        if let Some(recovery) = portable_restore {
            #[cfg(test)]
            if recovery.stage_heads_only_for_test {
                driver
                    .stage_portable_checkpoint_for_test(
                        &recovery.bundle.journal,
                        recovery.maximum_index_nodes,
                    )
                    .map_err(map_driver_error)?;
                return Err(SharedAgentHostError::Unavailable);
            }
            driver
                .restore_portable_checkpoint(
                    &recovery.bundle.journal,
                    recovery.maximum_index_nodes,
                    &recovery.bundle.certificate,
                    &recovery.verified,
                )
                .map_err(map_driver_error)?;
        }
        self.lease.validate_live().map_err(map_outer_lease_error)?;
        report_phase("exposure_and_restore");
        Ok(HostedSharedAgent {
            intent,
            raft_path,
            driver,
        })
    }

    fn read_intent(
        &self,
        agent: AgentId,
        files: GenerationFiles,
    ) -> Result<(SharedGenesisIntent, Vec<u8>), SharedAgentHostError> {
        if !files.intent && !files.intent_stage {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let bytes =
            read_host_record_pair(&self.intent_path(agent), MAX_SHARED_GENESIS_INTENT_BYTES)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
        let intent = SharedGenesisIntent::decode(&bytes)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if intent.encode() != bytes || intent.agent()? != agent {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok((intent, bytes))
    }

    fn read_exposure(
        &self,
        agent: AgentId,
        intent: Hash,
        files: GenerationFiles,
    ) -> Result<bool, SharedAgentHostError> {
        if !files.exposed && !files.exposed_stage {
            return Ok(false);
        }
        let bytes = read_host_record_pair(&self.exposure_path(agent), 32)?
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if bytes.as_slice() != intent.as_bytes() {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(true)
    }

    fn journal_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .root()
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX))
    }

    fn journal_lock_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX))
    }

    fn intent_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), INTENT_SUFFIX))
    }

    fn exposure_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), EXPOSURE_SUFFIX))
    }

    fn portable_restore_path(&self, agent: AgentId) -> PathBuf {
        self.lease.root().join(format!(
            "{}{}",
            encode_agent_id(agent),
            PORTABLE_RESTORE_SUFFIX
        ))
    }

    fn raft_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), RAFT_SUFFIX))
    }

    fn artifact_path(&self, agent: AgentId) -> PathBuf {
        self.lease
            .authority_root()
            .expect("validated lease authority root")
            .join(format!("{}{}", encode_agent_id(agent), ARTIFACT_SUFFIX))
    }
}

fn status_for(
    hosted: &HostedSharedAgent,
    transport_attached: bool,
) -> Result<SharedAgentStatus, SharedAgentHostError> {
    let attachment = attachment_status_for(hosted, transport_attached)?;
    let lanes = hosted.driver.engine_lanes().map_err(map_driver_error)?;
    let (applied_slots, remaining_slots, reservation_pending) =
        hosted.driver.capacity().map_err(map_driver_error)?;
    let snapshots = match hosted.driver.current_snapshot().map_err(map_driver_error)? {
        Some(snapshot) => SharedAgentSnapshotState::Installed {
            raft_index: snapshot.claim.raft_index(),
            raft_term: snapshot.claim.raft_term(),
            certificate: snapshot.certificate_commitment,
        },
        None => SharedAgentSnapshotState::None,
    };
    Ok(SharedAgentStatus {
        identity: attachment.identity,
        generation: attachment.generation,
        route: attachment.route,
        replication_id: attachment.replication_id,
        local_role: attachment.local_role,
        replicas: attachment.replicas,
        committee_transition: attachment.committee_transition,
        engines: SharedAgentEnginePlan {
            control_raft: true,
            linear_raft: lanes.contains(StateLane::Linear),
            merge: lanes.contains(StateLane::Merge),
            local: lanes.contains(StateLane::Local),
        },
        applied_slots,
        remaining_slots,
        reservation_pending,
        transport: attachment.transport,
        snapshots,
    })
}

fn attachment_status_for(
    hosted: &HostedSharedAgent,
    transport_attached: bool,
) -> Result<SharedAgentAttachmentStatus, SharedAgentHostError> {
    let identity = hosted.driver.identity().map_err(map_driver_error)?;
    let generation = hosted.driver.ledger().generation();
    let route = hosted.driver.active_route().map_err(map_driver_error)?;
    let committee_state = hosted
        .driver
        .network_committee_state()
        .map_err(map_driver_error)?;
    let committee = &committee_state.active;
    let local_node = hosted.driver.ledger().local_node();
    let named_next = committee_state
        .next
        .as_ref()
        .is_some_and(|next| next.member_by_node(local_node).is_some());
    // An explicit joiner outside the active committee replays the log as a
    // passive observer: it is not a member until the stable leg names it.
    let joiner = hosted.driver.ledger().is_joiner();
    let local_role = match hosted.driver.local_role().map_err(map_driver_error)? {
        None if joiner => Some(ReplicaRole::Observer),
        role => role,
    };
    let joining = joiner && committee.member_by_node(local_node).is_none() && !named_next;
    let replica_route = |member: &super::genesis::AgentReplicaMember| SharedReplicaRoute {
        node: member.replica().node,
        role: member.replica().role,
        peer_id: member.peer_id().to_vec(),
        ed25519_public_key: *member.ed25519_public_key(),
        raft_slot: member.raft_slot(),
    };
    let replicas = committee.members().iter().map(replica_route).collect();
    let committee_transition = committee_state
        .next
        .map(|next| SharedCommitteeTransitionRoute {
            next_committee: next.id(),
            next_replicas: next.members().iter().map(replica_route).collect(),
            joint: committee_state.joint,
        });
    Ok(SharedAgentAttachmentStatus {
        identity,
        generation,
        route,
        replication_id: generation.replication_id(),
        local_role,
        replicas,
        committee_transition,
        transport: if transport_attached {
            SharedAgentTransportState::Attached
        } else {
            SharedAgentTransportState::NotAttached
        },
        joining,
    })
}

/// Local storage identity of a joiner's journal. It fixes the node owning the
/// journal heads and Local lane; it is never a roster entry; the authority-
/// signed committee change names the joiner's real principal and role.
fn joiner_storage_replica(node: NodeId) -> super::AgentReplica {
    super::AgentReplica {
        node,
        principal: crate::service::PrincipalId(node.0),
        role: ReplicaRole::Observer,
    }
}

fn map_apply_outcome(outcome: SharedPhysicalApplyOutcome) -> SharedAgentApplyOutcome {
    match outcome {
        SharedPhysicalApplyOutcome::Applied { index } => SharedAgentApplyOutcome::Applied { index },
        SharedPhysicalApplyOutcome::Duplicate { index } => {
            SharedAgentApplyOutcome::Duplicate { index }
        }
        SharedPhysicalApplyOutcome::Idle => SharedAgentApplyOutcome::Idle,
    }
}

fn map_outer_lease_error(error: AgentHostError) -> SharedAgentHostError {
    match error {
        AgentHostError::DirectoryInUse => SharedAgentHostError::DirectoryInUse,
        AgentHostError::InvalidScope => SharedAgentHostError::InvalidScope,
        AgentHostError::ScopeMismatch => SharedAgentHostError::ScopeMismatch,
        AgentHostError::Conflict => SharedAgentHostError::Conflict,
        AgentHostError::Unavailable => SharedAgentHostError::Unavailable,
        _ => SharedAgentHostError::CorruptResidue,
    }
}

fn map_provision_verification_error(
    error: AgentGenesisProvisionVerificationError,
) -> SharedAgentHostError {
    match error {
        AgentGenesisProvisionVerificationError::InvalidProvision(_) => {
            SharedAgentHostError::InvalidProvision
        }
        AgentGenesisProvisionVerificationError::Finality(error) => {
            SharedAgentHostError::Finality(error)
        }
    }
}

fn map_driver_error(error: SharedJournalDriverError) -> SharedAgentHostError {
    tracing::warn!(?error, "Shared journal operation failed");
    match error {
        SharedJournalDriverError::Ledger(error) => map_ledger_error(error),
        SharedJournalDriverError::Artifact(error) => map_artifact_error(error),
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::LimitExceeded)
        | SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Backpressure) => {
            SharedAgentHostError::CapacityExhausted
        }
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Conflict) => {
            SharedAgentHostError::Conflict
        }
        SharedJournalDriverError::Store(super::journal_store::JournalStoreError::Unavailable) => {
            SharedAgentHostError::Unavailable
        }
        SharedJournalDriverError::WrongReplica | SharedJournalDriverError::InvalidProfile => {
            SharedAgentHostError::ScopeMismatch
        }
        SharedJournalDriverError::Executor(
            super::local_journal_driver::LocalReplayExecutorError::TrustUnavailable,
        ) => SharedAgentHostError::Unavailable,
        SharedJournalDriverError::Executor(
            super::local_journal_driver::LocalReplayExecutorError::InvalidAuthority
            | super::local_journal_driver::LocalReplayExecutorError::InvalidRequest,
        ) => SharedAgentHostError::InvalidProvision,
        SharedJournalDriverError::Snapshot(
            super::shared_commit::SharedCommitError::WrongSnapshotClaim,
        ) => SharedAgentHostError::SnapshotReplay,
        SharedJournalDriverError::Snapshot(_) => SharedAgentHostError::SnapshotCertificateInvalid,
        SharedJournalDriverError::CommitteeChange(
            super::shared_journal_driver::CommitteeChangeRefusal::TransitionPending,
        ) => SharedAgentHostError::Unavailable,
        SharedJournalDriverError::CommitteeChange(_) => {
            SharedAgentHostError::CommitteeChangeRefused
        }
        SharedJournalDriverError::InvalidArtifactBatch
        | SharedJournalDriverError::CrossStoreMismatch
        | SharedJournalDriverError::Executor(_)
        | SharedJournalDriverError::Replay(_)
        | SharedJournalDriverError::Store(_) => SharedAgentHostError::CorruptResidue,
    }
}

fn map_ledger_error(error: AgentRaftApplicationErrorV2) -> SharedAgentHostError {
    match error {
        AgentRaftApplicationErrorV2::BacklogLimit => SharedAgentHostError::CapacityExhausted,
        AgentRaftApplicationErrorV2::SnapshotBoundaryRequired => {
            SharedAgentHostError::SnapshotBoundaryRequired
        }
        AgentRaftApplicationErrorV2::SnapshotCertificateInvalid => {
            SharedAgentHostError::SnapshotCertificateInvalid
        }
        AgentRaftApplicationErrorV2::SnapshotStale => SharedAgentHostError::SnapshotStale,
        AgentRaftApplicationErrorV2::SnapshotReplay => SharedAgentHostError::SnapshotReplay,
        AgentRaftApplicationErrorV2::SnapshotEvidenceLimit => {
            SharedAgentHostError::SnapshotEvidenceLimit
        }
        AgentRaftApplicationErrorV2::ConfigurationMismatch
        | AgentRaftApplicationErrorV2::WrongGeneration
        | AgentRaftApplicationErrorV2::WrongLocalReplica
        | AgentRaftApplicationErrorV2::StaleCommittee => SharedAgentHostError::ScopeMismatch,
        AgentRaftApplicationErrorV2::Backend(_) => SharedAgentHostError::Unavailable,
        _ => SharedAgentHostError::CorruptResidue,
    }
}

fn map_artifact_error(error: SharedArtifactStagerError) -> SharedAgentHostError {
    match error {
        SharedArtifactStagerError::Unavailable => SharedAgentHostError::Unavailable,
        SharedArtifactStagerError::Conflict => SharedAgentHostError::Conflict,
        SharedArtifactStagerError::LimitExceeded => SharedAgentHostError::CapacityExhausted,
        SharedArtifactStagerError::Corrupt => SharedAgentHostError::CorruptResidue,
    }
}

fn install_host_record(path: &Path, bytes: &[u8]) -> Result<(), SharedAgentHostError> {
    install_immutable_file(path, bytes).map_err(map_artifact_error)
}

fn retire_host_record(path: &Path) -> Result<(), SharedAgentHostError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SharedAgentHostError::CorruptResidue)?;
    let staged = path.with_file_name(format!("{name}.next"));
    for candidate in [&staged, path] {
        match fs::symlink_metadata(candidate) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                fs::remove_file(candidate).map_err(|_| SharedAgentHostError::Unavailable)?;
            }
            Ok(_) => return Err(SharedAgentHostError::CorruptResidue),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SharedAgentHostError::Unavailable),
        }
    }
    let parent = path.parent().ok_or(SharedAgentHostError::CorruptResidue)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SharedAgentHostError::Unavailable)
}

fn read_host_record_pair(
    canonical: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
    use std::os::unix::fs::MetadataExt as _;

    let name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SharedAgentHostError::CorruptResidue)?;
    let staged = canonical.with_file_name(format!("{name}.next"));
    let canonical_bytes = read_optional_record(canonical, maximum)?;
    let staged_bytes = read_optional_record(&staged, maximum)?;
    match (canonical_bytes, staged_bytes) {
        (None, None) => Ok(None),
        (Some(bytes), None) | (None, Some(bytes)) => Ok(Some(bytes)),
        (Some(canonical_bytes), Some(staged_bytes)) => {
            let canonical_meta =
                fs::metadata(canonical).map_err(|_| SharedAgentHostError::Unavailable)?;
            let staged_meta =
                fs::metadata(&staged).map_err(|_| SharedAgentHostError::Unavailable)?;
            if canonical_bytes != staged_bytes
                || canonical_meta.dev() != staged_meta.dev()
                || canonical_meta.ino() != staged_meta.ino()
            {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            Ok(Some(canonical_bytes))
        }
    }
}

fn read_optional_record(
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            read_regular_bounded(path, maximum)
                .map(Some)
                .map_err(map_artifact_error)
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

fn validate_database_path(path: &Path, must_exist: bool) -> Result<(), SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SharedAgentHostError::CorruptResidue)
        }
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

fn validate_artifact_path(path: &Path, must_exist: bool) -> Result<(), SharedAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SharedAgentHostError::CorruptResidue),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SharedAgentHostError::CorruptResidue)
        }
        Err(_) => Err(SharedAgentHostError::Unavailable),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GenerationFiles {
    journal: bool,
    lock: bool,
    intent: bool,
    intent_stage: bool,
    exposed: bool,
    exposed_stage: bool,
    portable_restore: bool,
    portable_restore_stage: bool,
    raft: bool,
    artifacts: bool,
}

fn scan_generation_namespaces(
    lease: &AgentHostRootLease,
) -> Result<BTreeMap<AgentId, GenerationFiles>, SharedAgentHostError> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(lease.root()).map_err(|_| SharedAgentHostError::Unavailable)? {
        let entry = entry.map_err(|_| SharedAgentHostError::Unavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let file_type = entry
            .file_type()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some(agent) = decode_suffixed_agent(&name, JOURNAL_SUFFIX) {
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            let row = generation_row(&mut files, agent)?;
            if core::mem::replace(&mut row.journal, true) {
                return Err(SharedAgentHostError::CorruptResidue);
            }
            continue;
        }
        let (agent, staged) = decode_suffixed_agent(&name, PORTABLE_RESTORE_STAGE_SUFFIX)
            .map(|agent| (agent, true))
            .or_else(|| {
                decode_suffixed_agent(&name, PORTABLE_RESTORE_SUFFIX).map(|agent| (agent, false))
            })
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let row = generation_row(&mut files, agent)?;
        let present = if staged {
            &mut row.portable_restore_stage
        } else {
            &mut row.portable_restore
        };
        if core::mem::replace(present, true) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    let authority_root = lease.authority_root().map_err(map_outer_lease_error)?;
    for entry in fs::read_dir(authority_root).map_err(|_| SharedAgentHostError::Unavailable)? {
        let entry = entry.map_err(|_| SharedAgentHostError::Unavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let (agent, kind) =
            decode_authority_name(&name).ok_or(SharedAgentHostError::CorruptResidue)?;
        let file_type = entry
            .file_type()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if file_type.is_symlink()
            || (kind == AuthorityFileKind::Artifacts && !file_type.is_dir())
            || (kind != AuthorityFileKind::Artifacts && !file_type.is_file())
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let row = generation_row(&mut files, agent)?;
        let present = match kind {
            AuthorityFileKind::Lock => &mut row.lock,
            AuthorityFileKind::Intent => &mut row.intent,
            AuthorityFileKind::IntentStage => &mut row.intent_stage,
            AuthorityFileKind::Exposure => &mut row.exposed,
            AuthorityFileKind::ExposureStage => &mut row.exposed_stage,
            AuthorityFileKind::Raft => &mut row.raft,
            AuthorityFileKind::Artifacts => &mut row.artifacts,
        };
        if core::mem::replace(present, true) {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    for row in files.values() {
        if !row.intent && !row.intent_stage && !row.portable_restore && !row.portable_restore_stage
        {
            return Err(SharedAgentHostError::CorruptResidue);
        }
    }
    Ok(files)
}

fn generation_row(
    files: &mut BTreeMap<AgentId, GenerationFiles>,
    agent: AgentId,
) -> Result<&mut GenerationFiles, SharedAgentHostError> {
    if !files.contains_key(&agent) && files.len() == MAX_SHARED_HOST_AGENTS {
        return Err(SharedAgentHostError::CapacityExhausted);
    }
    Ok(files.entry(agent).or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorityFileKind {
    Lock,
    Intent,
    IntentStage,
    Exposure,
    ExposureStage,
    Raft,
    Artifacts,
}

fn decode_authority_name(name: &str) -> Option<(AgentId, AuthorityFileKind)> {
    [
        (INTENT_STAGE_SUFFIX, AuthorityFileKind::IntentStage),
        (EXPOSURE_STAGE_SUFFIX, AuthorityFileKind::ExposureStage),
        (INTENT_SUFFIX, AuthorityFileKind::Intent),
        (EXPOSURE_SUFFIX, AuthorityFileKind::Exposure),
        (JOURNAL_LOCK_SUFFIX, AuthorityFileKind::Lock),
        (RAFT_SUFFIX, AuthorityFileKind::Raft),
        (ARTIFACT_SUFFIX, AuthorityFileKind::Artifacts),
    ]
    .into_iter()
    .find_map(|(suffix, kind)| decode_suffixed_agent(name, suffix).map(|agent| (agent, kind)))
}

fn encode_agent_id(agent: AgentId) -> String {
    let mut output = String::with_capacity(64);
    for byte in agent.0 {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_suffixed_agent(name: &str, suffix: &str) -> Option<AgentId> {
    let encoded = name.strip_suffix(suffix)?;
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex(pair[0])? << 4) | decode_hex(pair[1])?;
    }
    let agent = AgentId(bytes);
    (agent != AgentId::ZERO && encode_agent_id(agent) == encoded).then_some(agent)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(feature = "pvm")]
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };
    use vos_raft::EntryKind;

    use super::super::authority::{
        AgentAuthorityBinding, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use super::super::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature,
    };
    use super::super::genesis::{
        AgentGenesisAdmissionId, AgentGenesisClaim, AgentGenesisDecision, AgentGenesisEvidence,
        AgentGenesisExpectations, AgentGenesisLocator, AgentGenesisProposal, AgentReplicaCommittee,
        AgentReplicaMember, derive_replica_raft_slot,
    };
    use super::super::journal::{
        ReplayInput, ReplayOperation, system_genesis_artifact_closure_commitment,
        system_genesis_post_create_state_commitment,
    };
    use super::super::package::Package;
    use super::super::shared_commit::ReplicaCommitSignature;
    use super::super::{AgentConfig, AgentReplica};
    use crate::service::{ActorId, DeploymentId, PrincipalId, ProducerId, ProgramId, SpaceId};

    const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    #[test]
    fn merge_store_capacity_errors_have_one_stable_host_projection() {
        for error in [
            super::super::journal_store::JournalStoreError::Backpressure,
            super::super::journal_store::JournalStoreError::LimitExceeded,
        ] {
            let driver_error: SharedJournalDriverError = error.into();
            assert_eq!(
                map_driver_error(driver_error),
                SharedAgentHostError::CapacityExhausted
            );
        }
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vos_shared_host_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn root(&self) -> PathBuf {
            self.0.join("agents")
        }

        fn lock(&self) -> PathBuf {
            self.0.join("shared-host.lock")
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct StaticTrust(AgentAuthorityBinding);

    impl AgentTrustProvider for StaticTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(20)
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            Some(self.0.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }

        fn use_native_standard_runtime_for_test(&self) -> bool {
            true
        }

        fn use_native_clean_runtime_for_test(&self) -> bool {
            false
        }
    }

    #[cfg(feature = "pvm")]
    struct NativeCleanTrust {
        authority: AgentAuthorityBinding,
        slot: Arc<AtomicU64>,
    }

    #[cfg(feature = "pvm")]
    impl AgentTrustProvider for NativeCleanTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(self.slot.load(Ordering::SeqCst))
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            Some(self.authority.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }

        fn use_native_standard_runtime_for_test(&self) -> bool {
            true
        }

        fn use_native_clean_runtime_for_test(&self) -> bool {
            true
        }
    }

    #[cfg(feature = "pvm")]
    struct CleanTrust {
        authority: AgentAuthorityBinding,
        slot: Arc<AtomicU64>,
    }

    #[cfg(feature = "pvm")]
    impl AgentTrustProvider for CleanTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(self.slot.load(Ordering::SeqCst))
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            Some(self.authority.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }
    }

    struct AcceptFinality;

    impl AgentGenesisFinalityVerifier for AcceptFinality {
        fn verify_finalized(
            &self,
            _provision: &AgentGenesisProvision,
        ) -> Result<(), AgentGenesisFinalityError> {
            Ok(())
        }
    }

    struct SigningMerge(SigningKey);

    impl LocalMergeAuthenticator for SigningMerge {
        fn node(&self) -> NodeId {
            NodeId::of_authenticated_peer(&peer_id(&self.0))
        }

        fn sign_event(&self, event: &mut MergeEvent) -> bool {
            if event.author != self.node() || !event.signature.is_empty() {
                return false;
            }
            event.signature = self.0.sign(&event.signing_message().0).to_bytes().to_vec();
            true
        }

        fn verify_event(&self, event: &MergeEvent) -> bool {
            event.author == self.node() && event.signature.len() == ED25519_SIGNATURE_BYTES
        }

        fn sign_snapshot_candidate(
            &self,
            candidate: &VerifiedSharedAgentSnapshotCandidate,
        ) -> Option<ReplicaCommitSignature> {
            let member = candidate
                .claim()
                .active_committee()
                .member_by_node(self.node())?;
            if member.replica().role != ReplicaRole::Voter
                || member.ed25519_public_key() != &self.0.verifying_key().to_bytes()
                || member.peer_id() != peer_id(&self.0)
            {
                return None;
            }
            ReplicaCommitSignature::new(
                self.node(),
                self.0.sign(&candidate.signing_message().0).to_bytes(),
            )
            .ok()
        }

        fn sign_recovery_expiry_candidate(
            &self,
            candidate: &VerifiedSharedRecoveryExpiryCandidate,
        ) -> Option<ReplicaCommitSignature> {
            let member = candidate.claim().committee().member_by_node(self.node())?;
            if member.replica().role != ReplicaRole::Voter
                || member.ed25519_public_key() != &self.0.verifying_key().to_bytes()
                || member.peer_id() != peer_id(&self.0)
            {
                return None;
            }
            ReplicaCommitSignature::new(
                self.node(),
                self.0.sign(&candidate.signing_message().0).to_bytes(),
            )
            .ok()
        }
    }

    struct Fixture {
        provision: AgentGenesisProvision,
        catalog: Vec<RuntimeBlob>,
        descriptor: crate::agent_sdk::AgentDescriptor,
        authority: AgentAuthorityBinding,
        authority_key: SigningKey,
        committee_authority: CommitteeChangeAuthorityBinding,
        replica_keys: Vec<SigningKey>,
        agent: AgentId,
        space: SpaceId,
    }

    #[cfg(feature = "pvm")]
    struct CleanFixture {
        shared: Fixture,
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime: super::super::package_admission::AdmittedRuntimePackage,
        upgrade_runtime: super::super::package_admission::AdmittedRuntimePackage,
        actor_package: super::super::package_admission::AdmittedActorPackage,
        authority_key: SigningKey,
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn peer_id(key: &SigningKey) -> Vec<u8> {
        let mut peer = PEER_ID_PREFIX.to_vec();
        peer.extend_from_slice(&key.verifying_key().to_bytes());
        peer
    }

    fn replica_member(key: &SigningKey, role: ReplicaRole) -> AgentReplicaMember {
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

    fn authority_binding(key: &SigningKey) -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire(key.verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: AgentId([0xa1; 32]),
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn committee_authority_binding(key: &SigningKey) -> CommitteeChangeAuthorityBinding {
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
            41,
        )
        .unwrap()
    }

    fn clean_management_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        sequence: u64,
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
        };

        let operation = request.authority_operation().unwrap();
        let (actor, actor_deployment) = request.authority_actor_selector();
        let runtime_deployment = match request {
            crate::agent_sdk::ManagementRequest::Create(descriptor) => {
                descriptor.identity.runtime_deployment
            }
            crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => upgrade.from_deployment,
            _ => descriptor.identity.runtime_deployment,
        };
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: descriptor.authority.policy,
                issuer: descriptor.authority.issuer,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                operation,
                runtime_deployment,
                actor,
                actor_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0xd1; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: operation
                    .uses_management_decision_journal()
                    .then_some(sequence)
                    .unwrap_or(0),
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 30,
                request: request.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0; 64],
        };
        receipt.signature = authority_key.sign(&receipt.signing_bytes()).to_bytes();
        receipt.validate_shape().unwrap();
        receipt
    }

    fn clean_descriptor_for_runtime(
        runtime: &super::super::package_admission::AdmittedRuntimePackage,
        space: crate::agent_sdk::SpaceId,
        agent: crate::agent_sdk::AgentId,
        owner: crate::agent_sdk::PrincipalId,
        nonce: crate::agent_sdk::Hash,
        members: &[AgentReplicaMember],
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::AgentDescriptor {
        let public_key = authority_key.verifying_key().to_bytes();
        let descriptor = crate::agent_sdk::AgentDescriptor {
            identity: crate::agent_sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: crate::agent_sdk::AgentProfile::Shared,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: crate::agent_sdk::ProducerId([0x92; 32]),
            },
            creation_nonce: nonce,
            authority: crate::agent_sdk::authority::AgentAuthorityBinding {
                policy: crate::agent_sdk::Hash([0x81; 32]),
                issuer: crate::agent_sdk::authority::AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([0x82; 32]),
                    actor: crate::agent_sdk::ActorId([0x83; 32]),
                    deployment: crate::agent_sdk::DeploymentId([0x84; 32]),
                    program: crate::agent_sdk::ProgramId([0x85; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: members
                .iter()
                .map(|member| crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId(member.replica().node.0),
                    principal: crate::agent_sdk::PrincipalId(member.replica().principal.0),
                    role: match member.replica().role {
                        ReplicaRole::Voter => crate::agent_sdk::ReplicaRole::Voter,
                        ReplicaRole::Observer => crate::agent_sdk::ReplicaRole::Observer,
                    },
                })
                .collect(),
        };
        descriptor.validate().unwrap();
        descriptor
    }

    fn clean_runtime_state(control: &[u8]) -> crate::agent_sdk::RuntimeState {
        crate::agent_sdk::RuntimeState {
            control: control.to_vec(),
            linear: Vec::new(),
            merge: Vec::new(),
            local: Vec::new(),
        }
    }

    fn clean_identity_bytes(identity: &crate::agent_sdk::AgentIdentity) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(225);
        bytes.extend_from_slice(identity.space.as_bytes());
        bytes.extend_from_slice(identity.agent.as_bytes());
        bytes.extend_from_slice(identity.owner.as_bytes());
        bytes.push(identity.profile as u8);
        bytes.extend_from_slice(identity.runtime_deployment.as_bytes());
        bytes.extend_from_slice(identity.runtime_program.as_bytes());
        bytes.extend_from_slice(identity.runtime_producer.as_bytes());
        bytes.extend_from_slice(identity.transition_producer.as_bytes());
        bytes
    }

    fn unique_subslice_offset(haystack: &[u8], needle: &[u8]) -> usize {
        let mut matches = haystack
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset));
        let offset = matches.next().expect("scripted identity preimage");
        assert!(matches.next().is_none(), "scripted identity must be unique");
        offset
    }

    fn copy_from_first_input_to_all_outputs(
        case: &mut super::super::package_admission::ScriptedRuntimeCase,
        needle: &[u8],
    ) {
        let mut inputs = case
            .input
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset));
        let input_offset = inputs.next().expect("script input preimage");
        assert!(
            inputs.next().is_none(),
            "script input preimage is ambiguous"
        );
        let outputs = case
            .output
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
            .collect::<Vec<_>>();
        assert!(!outputs.is_empty(), "script output preimage");
        case.copies.extend(outputs.into_iter().map(|output_offset| {
            super::super::package_admission::ScriptedRuntimeCopy {
                input_offset,
                output_offset,
                len: needle.len(),
            }
        }));
    }

    fn scripted_management_case(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        state: crate::agent_sdk::RuntimeState,
        request: crate::agent_sdk::ManagementRequest,
        sequence: Option<u64>,
        authority_key: &SigningKey,
        next_state: crate::agent_sdk::RuntimeState,
        outcome: crate::agent_sdk::RuntimeOutcome,
    ) -> super::super::package_admission::ScriptedRuntimeCase {
        use crate::agent_sdk::wire::CanonicalWire as _;

        let authority = sequence.map(|sequence| {
            Box::new(clean_management_receipt(
                descriptor,
                &request,
                sequence,
                authority_key,
            ))
        });
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: authority
                .as_ref()
                .map_or(descriptor.identity.runtime_deployment, |receipt| {
                    receipt.selector.runtime_deployment
                }),
            state,
            request: Box::new(request),
            authority,
            observed_slot: 20,
        }
        .encode()
        .unwrap();
        let output = crate::agent_sdk::RuntimeTransition {
            state: next_state,
            outcome,
        }
        .encode()
        .unwrap();
        super::super::package_admission::ScriptedRuntimeCase {
            input: work,
            output,
            copies: Vec::new(),
        }
    }

    fn scripted_rejected_invocation_case(
        state: crate::agent_sdk::RuntimeState,
        work: crate::agent_sdk::InvocationWork,
    ) -> super::super::package_admission::ScriptedRuntimeCase {
        use crate::agent_sdk::wire::CanonicalWire as _;

        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        let input = crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: 20,
        }
        .encode()
        .unwrap();
        let output = crate::agent_sdk::RuntimeTransition {
            state,
            outcome: crate::agent_sdk::RuntimeOutcome::Completed(Err(
                crate::agent_sdk::InvocationError::NotFound,
            )),
        }
        .encode()
        .unwrap();
        super::super::package_admission::ScriptedRuntimeCase {
            input,
            output,
            copies: Vec::new(),
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_fixture(nonce_byte: u8) -> CleanFixture {
        use super::super::package_admission::{
            ScriptedRuntimeCopy, admitted_scripted_runtime_for_test,
            admitted_standard_actor_for_test,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;

        let space = SpaceId([0x11; 32]);
        let clean_space = crate::agent_sdk::SpaceId(space.0);
        let owner = crate::agent_sdk::PrincipalId([0x12; 32]);
        let nonce = crate::agent_sdk::Hash([nonce_byte; 32]);
        let agent = crate::agent_sdk::AgentId::derive(clean_space, owner, nonce.as_bytes());
        let replica_keys = vec![key(0x31)];
        let member = replica_member(&replica_keys[0], ReplicaRole::Voter);
        let authority_key = key(0x41);

        // The committed standard blob is intentionally still r7 while the
        // SDK is moving through r11. Build a small current-ABI custom runtime
        // which is physically interpreted as PVM bytecode; no native Standard
        // oracle participates in this generic journal/host test.
        let placeholder = admitted_scripted_runtime_for_test(
            "script-shape-only",
            0x60,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let placeholder_descriptor = clean_descriptor_for_runtime(
            &placeholder,
            clean_space,
            agent,
            owner,
            nonce,
            core::slice::from_ref(&member),
            &authority_key,
        );
        let actor_package = admitted_standard_actor_for_test(
            "linear-worker",
            crate::agent_sdk::StateLane::Linear,
            0x63,
        );
        let install = clean_install_request(agent, &actor_package);
        let crate::agent_sdk::ManagementRequest::Install(install_body) = &install else {
            unreachable!()
        };
        let actor_record = crate::agent_sdk::ActorDirectoryRecord {
            entry: install_body.entry.clone(),
            incarnation: crate::agent_sdk::Hash([0x93; 32]),
            installation_id: install_body.installation_id,
            registry_reservation: install_body.registry_reservation,
            install_request: install_body.lineage_commitment(),
        };
        let inspect = crate::agent_sdk::ManagementRequest::InspectActors {
            after: None,
            limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
        };
        let mut actor_predecessor = install_body.entry.actor.0;
        for byte in actor_predecessor.iter_mut().rev() {
            if *byte == 0 {
                *byte = u8::MAX;
            } else {
                *byte -= 1;
                break;
            }
        }
        let keyed_inspect = crate::agent_sdk::ManagementRequest::InspectActors {
            after: Some(crate::agent_sdk::ActorId(actor_predecessor)),
            limit: 1,
        };
        let remove = crate::agent_sdk::ManagementRequest::RemoveLeaf {
            actor: install_body.entry.actor,
            expected_deployment: install_body.entry.deployment,
        };
        let denied = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xa5; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xa6; 32]),
        };
        let empty_state = clean_runtime_state(&[1]);
        let installed_state = clean_runtime_state(&[2, 2]);
        let target_cases = vec![
            scripted_management_case(
                &placeholder_descriptor,
                empty_state.clone(),
                inspect.clone(),
                None,
                &authority_key,
                empty_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Actors(
                        crate::agent_sdk::ActorDirectoryPage {
                            entries: Vec::new(),
                            next: None,
                        },
                    ),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                empty_state.clone(),
                install.clone(),
                Some(3),
                &authority_key,
                installed_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Installed(install_body.entry.clone()),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                installed_state.clone(),
                keyed_inspect,
                None,
                &authority_key,
                installed_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Actors(
                        crate::agent_sdk::ActorDirectoryPage {
                            entries: vec![actor_record.clone()],
                            next: None,
                        },
                    ),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                installed_state.clone(),
                inspect,
                None,
                &authority_key,
                installed_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Actors(
                        crate::agent_sdk::ActorDirectoryPage {
                            entries: vec![actor_record],
                            next: None,
                        },
                    ),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                installed_state,
                remove,
                Some(4),
                &authority_key,
                empty_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Removed(install_body.entry.actor),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                empty_state.clone(),
                denied,
                Some(5),
                &authority_key,
                empty_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::NotFound,
                )),
            ),
        ];
        let upgrade_runtime =
            admitted_scripted_runtime_for_test("shared-current-abi-v2", 0x62, target_cases);

        let create_shape =
            crate::agent_sdk::ManagementRequest::Create(Box::new(placeholder_descriptor.clone()));
        let mut create_case = scripted_management_case(
            &placeholder_descriptor,
            crate::agent_sdk::RuntimeState::default(),
            create_shape,
            Some(1),
            &authority_key,
            empty_state.clone(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(placeholder_descriptor.identity.clone()),
            )),
        );
        let placeholder_identity = clean_identity_bytes(&placeholder_descriptor.identity);
        let create_work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: placeholder_descriptor.identity.space,
            agent: placeholder_descriptor.identity.agent,
            runtime_deployment: placeholder_descriptor.identity.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(crate::agent_sdk::ManagementRequest::Create(Box::new(
                placeholder_descriptor.clone(),
            ))),
            authority: Some(Box::new(clean_management_receipt(
                &placeholder_descriptor,
                &crate::agent_sdk::ManagementRequest::Create(Box::new(
                    placeholder_descriptor.clone(),
                )),
                1,
                &authority_key,
            ))),
            observed_slot: 20,
        }
        .encode()
        .unwrap();
        create_case.copies.push(ScriptedRuntimeCopy {
            input_offset: unique_subslice_offset(&create_work, &placeholder_identity),
            output_offset: unique_subslice_offset(&create_case.output, &placeholder_identity),
            len: placeholder_identity.len(),
        });
        let target_identity = crate::agent_sdk::AgentIdentity {
            runtime_deployment: upgrade_runtime.deployment(),
            runtime_program: upgrade_runtime.program(),
            runtime_producer: upgrade_runtime.producer(),
            ..placeholder_descriptor.identity.clone()
        };
        let upgrade = crate::agent_sdk::ManagementRequest::UpgradeRuntime(Box::new(
            crate::agent_sdk::RuntimeUpgrade {
                from_deployment: placeholder_descriptor.identity.runtime_deployment,
                to_deployment: upgrade_runtime.deployment(),
                to_program: upgrade_runtime.program(),
                producer: upgrade_runtime.producer(),
                package: upgrade_runtime.package_ref().clone(),
                contract: upgrade_runtime.manifest().contract,
                capabilities: upgrade_runtime.capabilities(),
            },
        ));
        let old_cases = vec![
            create_case,
            scripted_management_case(
                &placeholder_descriptor,
                empty_state.clone(),
                crate::agent_sdk::ManagementRequest::InspectActors {
                    after: None,
                    limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
                },
                None,
                &authority_key,
                empty_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Actors(
                        crate::agent_sdk::ActorDirectoryPage {
                            entries: Vec::new(),
                            next: None,
                        },
                    ),
                )),
            ),
            scripted_management_case(
                &placeholder_descriptor,
                empty_state.clone(),
                upgrade,
                Some(2),
                &authority_key,
                empty_state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::RuntimeUpgraded(target_identity),
                )),
            ),
        ];
        let runtime = admitted_scripted_runtime_for_test("shared-current-abi-v1", 0x61, old_cases);
        let descriptor = clean_descriptor_for_runtime(
            &runtime,
            clean_space,
            agent,
            owner,
            nonce,
            core::slice::from_ref(&member),
            &authority_key,
        );
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let receipt = clean_management_receipt(&descriptor, &request, 1, &authority_key);
        let post_create = super::super::wire::RuntimeState {
            control: empty_state.control,
            linear: empty_state.linear,
            merge: empty_state.merge,
            local: empty_state.local,
        };
        let catalog_reference = BlobRef {
            hash: Hash(runtime.package_ref().hash.0),
            len: runtime.package_ref().len,
        };
        assert!(catalog_reference.matches(runtime.exact_bytes()));
        let runtime_binding = RuntimeBinding {
            space,
            agent: AgentId(agent.0),
            deployment: DeploymentId(runtime.deployment().0),
            program: ProgramId(runtime.program().0),
            producer: ProducerId(runtime.producer().0),
            package: catalog_reference.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime: runtime_binding.clone(),
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: receipt,
                observed_slot: 20,
            },
        };
        create.validate().unwrap();
        let expectations = AgentGenesisExpectations::new(
            runtime_binding.commitment(),
            Hash(request.commitment().0),
            system_genesis_post_create_state_commitment(&post_create).unwrap(),
            system_genesis_artifact_closure_commitment(core::slice::from_ref(&catalog_reference))
                .unwrap(),
            1,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space,
                agent: AgentId(agent.0),
            },
            create,
            expectations,
            vec![catalog_reference.clone()],
        )
        .unwrap();
        let replicas =
            AgentReplicaCommittee::new(space, AgentId(agent.0), AgentProfile::Shared, vec![member])
                .unwrap();

        let host_authority_key = key(0x51);
        let host_authority = authority_binding(&host_authority_key);
        let system_key = key(0x52);
        let system_member = AuthorityCommitteeMember::new(
            NodeId([0x53; 32]),
            system_key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = system_member.signer();
        let system_committee = AuthorityCommittee::new(
            space,
            Hash(descriptor.authority.commitment().0),
            1,
            None,
            vec![system_member],
        )
        .unwrap();
        let genesis_claim = AgentGenesisClaim::new(
            host_authority.agent,
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            system_committee.authority_binding(),
            system_committee.epoch(),
            system_committee.commitment(),
            genesis_claim.authority_claim(),
        );
        let signature =
            AuthoritySignature::new(signer, system_key.sign(&message.0).to_bytes()).unwrap();
        let certificate = AuthorityQuorumCertificate::new(
            &system_committee,
            genesis_claim.authority_claim(),
            vec![signature],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(genesis_claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        let shared = Fixture {
            provision,
            catalog: vec![RuntimeBlob {
                reference: catalog_reference,
                bytes: runtime.exact_bytes().to_vec(),
            }],
            descriptor: descriptor.clone(),
            authority: host_authority,
            authority_key: host_authority_key,
            committee_authority: committee_authority_binding(&key(0xe1)),
            replica_keys,
            agent: AgentId(agent.0),
            space,
        };
        CleanFixture {
            shared,
            descriptor,
            runtime,
            upgrade_runtime,
            actor_package,
            authority_key,
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_install_request(
        agent: crate::agent_sdk::AgentId,
        package: &super::super::package_admission::AdmittedActorPackage,
    ) -> crate::agent_sdk::ManagementRequest {
        let schema = crate::agent_sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let name = package.manifest().name.clone();
        let actor = crate::agent_sdk::ActorId::top_level(agent, &name);
        let entry = crate::agent_sdk::ActorEntry {
            actor,
            name,
            parent: None,
            deployment: package.deployment(),
            program: package.program(),
            package: package.package_ref().clone(),
            agent_schema: package.manifest().state_lane_schema.clone(),
            method_policy: package.manifest().method_policy.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: None,
            state_layout: schema.state_layout_hash().unwrap(),
            lanes: package.requirements().lanes,
            suspended: false,
        };
        crate::agent_sdk::ManagementRequest::Install(Box::new(crate::agent_sdk::InstallActor {
            installation_id: crate::agent_sdk::InstallationId([0x91; 32]),
            registry_reservation: crate::agent_sdk::Hash([0x92; 32]),
            entry,
            producer: package.producer(),
            package: package.package_ref().clone(),
            agent_schema: package.manifest().state_lane_schema.clone(),
            method_policy: package.manifest().method_policy.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: None,
            state_layout: schema.state_layout_hash().unwrap(),
            contract: package.manifest().contract,
            requirements: package.requirements(),
        }))
    }

    fn fixture(nonce_byte: u8) -> Fixture {
        let space = SpaceId([0x11; 32]);
        let clean_space = crate::agent_sdk::SpaceId(space.0);
        let owner = crate::agent_sdk::PrincipalId([0x12; 32]);
        let nonce = crate::agent_sdk::Hash([nonce_byte; 32]);
        let clean_agent = crate::agent_sdk::AgentId::derive(clean_space, owner, nonce.as_bytes());
        let agent = AgentId(clean_agent.0);
        let authority_key = key(0x41);
        let authority = authority_binding(&authority_key);
        let placeholder = super::super::package_admission::admitted_scripted_runtime_for_test(
            "shared-host-runtime",
            0x71,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let replica_keys = vec![key(0x31), key(0x32), key(0x33)];
        let mut members = vec![
            replica_member(&replica_keys[0], ReplicaRole::Voter),
            replica_member(&replica_keys[1], ReplicaRole::Voter),
            replica_member(&replica_keys[2], ReplicaRole::Observer),
        ];
        members.sort_by_key(|member| member.replica().node);
        let placeholder_descriptor = clean_descriptor_for_runtime(
            &placeholder,
            clean_space,
            clean_agent,
            owner,
            nonce,
            &members,
            &authority_key,
        );
        let placeholder_request =
            crate::agent_sdk::ManagementRequest::Create(Box::new(placeholder_descriptor.clone()));
        let created_state = clean_runtime_state(&[0x41]);
        let mut create_case = scripted_management_case(
            &placeholder_descriptor,
            crate::agent_sdk::RuntimeState::default(),
            placeholder_request,
            Some(1),
            &authority_key,
            created_state.clone(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(placeholder_descriptor.identity.clone()),
            )),
        );
        copy_from_first_input_to_all_outputs(
            &mut create_case,
            &clean_identity_bytes(&placeholder_descriptor.identity),
        );
        let inspect = crate::agent_sdk::ManagementRequest::InspectActors {
            after: None,
            limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
        };
        let inspect_case = scripted_management_case(
            &placeholder_descriptor,
            created_state.clone(),
            inspect,
            None,
            &authority_key,
            created_state.clone(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Actors(crate::agent_sdk::ActorDirectoryPage {
                    entries: Vec::new(),
                    next: None,
                }),
            )),
        );
        let rejected_management = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xb1; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xb2; 32]),
        };
        let rejected_management_case = scripted_management_case(
            &placeholder_descriptor,
            created_state.clone(),
            rejected_management,
            Some(2),
            &authority_key,
            created_state.clone(),
            crate::agent_sdk::RuntimeOutcome::Management(Err(
                crate::agent_sdk::ManagementError::NotFound,
            )),
        );
        let rejected_invocation_case = scripted_rejected_invocation_case(
            created_state.clone(),
            crate::agent_sdk::InvocationWork {
                space: placeholder_descriptor.identity.space,
                agent: placeholder_descriptor.identity.agent,
                runtime_deployment: placeholder_descriptor.identity.runtime_deployment,
                invocation: crate::agent_sdk::InvocationId([0xb3; 32]),
                actor: crate::agent_sdk::ActorId([0xb4; 32]),
                incarnation: crate::agent_sdk::Hash([0xb5; 32]),
                deployment: crate::agent_sdk::DeploymentId([0xb6; 32]),
                program: crate::agent_sdk::ProgramId([0xb7; 32]),
                mode: crate::agent_sdk::MethodMode::Merge,
                origin: crate::agent_sdk::InvocationOrigin::anonymous(),
                roles: crate::agent_sdk::InvocationRoleClaims::none(),
                message: vec![0xb8],
                installation_data: None,
                availability: Vec::new(),
                gas: 1_000,
                recovery_only: false,
            },
        );
        let admitted_runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "shared-host-current-abi",
            0x72,
            vec![
                create_case,
                inspect_case,
                rejected_management_case,
                rejected_invocation_case,
            ],
        );
        let descriptor = clean_descriptor_for_runtime(
            &admitted_runtime,
            clean_space,
            clean_agent,
            owner,
            nonce,
            &members,
            &authority_key,
        );
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let receipt = clean_management_receipt(&descriptor, &request, 1, &authority_key);
        let catalog_reference = BlobRef {
            hash: Hash(admitted_runtime.package_ref().hash.0),
            len: admitted_runtime.package_ref().len,
        };
        assert!(catalog_reference.matches(admitted_runtime.exact_bytes()));
        let runtime = RuntimeBinding {
            space,
            agent,
            deployment: DeploymentId(descriptor.identity.runtime_deployment.0),
            program: ProgramId(descriptor.identity.runtime_program.0),
            producer: ProducerId(descriptor.identity.runtime_producer.0),
            package: catalog_reference.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime: runtime.clone(),
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: receipt.clone(),
                observed_slot: 20,
            },
        };
        create.validate().unwrap();
        let post_create = super::super::wire::RuntimeState {
            control: created_state.control,
            linear: created_state.linear,
            merge: created_state.merge,
            local: created_state.local,
        };
        let expectations = AgentGenesisExpectations::new(
            runtime.commitment(),
            Hash(request.commitment().0),
            system_genesis_post_create_state_commitment(&post_create).unwrap(),
            system_genesis_artifact_closure_commitment(core::slice::from_ref(&catalog_reference))
                .unwrap(),
            1,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator { space, agent },
            create,
            expectations,
            vec![catalog_reference.clone()],
        )
        .unwrap();
        let replicas =
            AgentReplicaCommittee::new(space, agent, AgentProfile::Shared, members).unwrap();
        let system_key = key(0x51);
        let system_member = AuthorityCommitteeMember::new(
            NodeId([0x52; 32]),
            system_key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = system_member.signer();
        let system_committee = AuthorityCommittee::new(
            space,
            Hash(descriptor.authority.commitment().0),
            1,
            None,
            vec![system_member],
        )
        .unwrap();
        let genesis_claim = AgentGenesisClaim::new(
            authority.agent,
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            system_committee.authority_binding(),
            system_committee.epoch(),
            system_committee.commitment(),
            genesis_claim.authority_claim(),
        );
        let signature =
            AuthoritySignature::new(signer, system_key.sign(&message.0).to_bytes()).unwrap();
        let certificate = AuthorityQuorumCertificate::new(
            &system_committee,
            genesis_claim.authority_claim(),
            vec![signature],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(genesis_claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        let catalog = vec![RuntimeBlob {
            reference: catalog_reference,
            bytes: admitted_runtime.exact_bytes().to_vec(),
        }];
        Fixture {
            provision,
            catalog,
            descriptor,
            authority,
            authority_key,
            committee_authority: committee_authority_binding(&key(0xe1)),
            replica_keys,
            agent,
            space,
        }
    }

    #[cfg(feature = "pvm")]
    fn standard_projection_fixture(nonce_byte: u8) -> Fixture {
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "shared-projection-standard-shape",
            0x74,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        standard_projection_fixture_with_runtime(nonce_byte, runtime)
    }

    #[cfg(feature = "pvm")]
    fn standard_projection_fixture_with_runtime(
        nonce_byte: u8,
        admitted_runtime: super::super::package_admission::AdmittedRuntimePackage,
    ) -> Fixture {
        standard_projection_fixture_with_replicas(
            nonce_byte,
            admitted_runtime,
            &[(0x31, ReplicaRole::Voter)],
            false,
        )
    }

    #[cfg(feature = "pvm")]
    fn standard_projection_fixture_with_replicas(
        nonce_byte: u8,
        admitted_runtime: super::super::package_admission::AdmittedRuntimePackage,
        replica_seeds: &[(u8, ReplicaRole)],
        distinct_owner: bool,
    ) -> Fixture {
        const GENESIS_SLOT: u64 = 19;

        let space = SpaceId([0x11; 32]);
        let clean_space = crate::agent_sdk::SpaceId(space.0);
        let owner = crate::agent_sdk::PrincipalId([0x12; 32]);
        let nonce = crate::agent_sdk::Hash([nonce_byte; 32]);
        let clean_agent = crate::agent_sdk::AgentId::derive(clean_space, owner, nonce.as_bytes());
        let agent = AgentId(clean_agent.0);
        let authority_key = key(0x41);
        let authority = authority_binding(&authority_key);
        let mut keyed_members: Vec<_> = replica_seeds
            .iter()
            .map(|(seed, role)| {
                let signing_key = key(*seed);
                let mut member = replica_member(&signing_key, *role);
                if distinct_owner {
                    let mut replica = member.replica();
                    replica.principal = PrincipalId(owner.0);
                    member = AgentReplicaMember::new(
                        replica,
                        member.peer_id().to_vec(),
                        *member.ed25519_public_key(),
                        member.raft_slot(),
                    )
                    .unwrap();
                }
                (member, signing_key)
            })
            .collect();
        keyed_members.sort_by_key(|(member, _)| member.replica().node);
        let (members, replica_keys): (Vec<_>, Vec<_>) = keyed_members.into_iter().unzip();
        let descriptor = clean_descriptor_for_runtime(
            &admitted_runtime,
            clean_space,
            clean_agent,
            owner,
            nonce,
            &members,
            &authority_key,
        );
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let receipt = clean_management_receipt(&descriptor, &request, 1, &authority_key);
        let transition = super::super::wire::apply_standard_runtime_work(
            crate::agent_sdk::RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: crate::agent_sdk::RuntimeState::default(),
                request: Box::new(request.clone()),
                authority: Some(Box::new(receipt.clone())),
                observed_slot: GENESIS_SLOT,
            },
        )
        .unwrap();
        assert!(matches!(
            transition.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(_)
            ))
        ));
        let catalog_reference = BlobRef {
            hash: Hash(admitted_runtime.package_ref().hash.0),
            len: admitted_runtime.package_ref().len,
        };
        assert!(catalog_reference.matches(admitted_runtime.exact_bytes()));
        let runtime = RuntimeBinding {
            space,
            agent,
            deployment: DeploymentId(descriptor.identity.runtime_deployment.0),
            program: ProgramId(descriptor.identity.runtime_program.0),
            producer: ProducerId(descriptor.identity.runtime_producer.0),
            package: catalog_reference.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime: runtime.clone(),
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: receipt,
                observed_slot: GENESIS_SLOT,
            },
        };
        create.validate().unwrap();
        let post_create = super::super::wire::RuntimeState {
            control: transition.state.control,
            linear: transition.state.linear,
            merge: transition.state.merge,
            local: transition.state.local,
        };
        let expectations = AgentGenesisExpectations::new(
            runtime.commitment(),
            Hash(request.commitment().0),
            system_genesis_post_create_state_commitment(&post_create).unwrap(),
            system_genesis_artifact_closure_commitment(core::slice::from_ref(&catalog_reference))
                .unwrap(),
            1,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator { space, agent },
            create,
            expectations,
            vec![catalog_reference.clone()],
        )
        .unwrap();
        let replicas =
            AgentReplicaCommittee::new(space, agent, AgentProfile::Shared, members).unwrap();
        let system_key = key(0x51);
        let system_member = AuthorityCommitteeMember::new(
            NodeId([0x52; 32]),
            system_key.verifying_key().to_bytes(),
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let signer = system_member.signer();
        let system_committee = AuthorityCommittee::new(
            space,
            Hash(descriptor.authority.commitment().0),
            1,
            None,
            vec![system_member],
        )
        .unwrap();
        let genesis_claim = AgentGenesisClaim::new(
            authority.agent,
            AgentJournalGenesisId::new([0x92; 32]),
            AgentGenesisAdmissionId::from_bytes([0x93; 32]),
            &proposal,
            &replicas,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            system_committee.authority_binding(),
            system_committee.epoch(),
            system_committee.commitment(),
            genesis_claim.authority_claim(),
        );
        let signature =
            AuthoritySignature::new(signer, system_key.sign(&message.0).to_bytes()).unwrap();
        let certificate = AuthorityQuorumCertificate::new(
            &system_committee,
            genesis_claim.authority_claim(),
            vec![signature],
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(genesis_claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let provision = AgentGenesisProvision::new(proposal, replicas, evidence, decision).unwrap();
        Fixture {
            provision,
            catalog: vec![RuntimeBlob {
                reference: catalog_reference,
                bytes: admitted_runtime.exact_bytes().to_vec(),
            }],
            descriptor,
            authority,
            authority_key,
            committee_authority: committee_authority_binding(&key(0xe1)),
            replica_keys,
            agent,
            space,
        }
    }

    fn open_host(directory: &TempDirectory, fixture: &Fixture) -> SharedAgentHost {
        open_host_on_node(
            directory,
            fixture,
            fixture.provision.replicas().members()[0].replica().node,
        )
    }

    #[cfg(feature = "pvm")]
    fn open_native_clean_host(directory: &TempDirectory, fixture: &Fixture) -> SharedAgentHost {
        open_native_clean_host_at_slot(directory, fixture, Arc::new(AtomicU64::new(20)))
    }

    #[cfg(feature = "pvm")]
    fn open_native_clean_host_at_slot(
        directory: &TempDirectory,
        fixture: &Fixture,
        slot: Arc<AtomicU64>,
    ) -> SharedAgentHost {
        let node = fixture.provision.replicas().members()[0].replica().node;
        let merge_key = fixture.replica_keys[0].clone();
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node,
            },
            Arc::new(NativeCleanTrust {
                authority: fixture.authority.clone(),
                slot,
            }),
            Arc::new(SigningMerge(merge_key)),
            Arc::new(AcceptFinality),
        )
        .unwrap()
    }

    #[cfg(feature = "pvm")]
    fn open_clean_host(
        directory: &TempDirectory,
        fixture: &CleanFixture,
        slot: Arc<AtomicU64>,
    ) -> SharedAgentHost {
        try_open_clean_host(directory, fixture, slot).unwrap()
    }

    #[cfg(feature = "pvm")]
    fn try_open_clean_host(
        directory: &TempDirectory,
        fixture: &CleanFixture,
        slot: Arc<AtomicU64>,
    ) -> Result<SharedAgentHost, SharedAgentHostError> {
        let node = fixture.shared.provision.replicas().members()[0]
            .replica()
            .node;
        let merge_key = fixture.shared.replica_keys[0].clone();
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.shared.space,
                node,
            },
            Arc::new(CleanTrust {
                authority: fixture.shared.authority.clone(),
                slot,
            }),
            Arc::new(SigningMerge(merge_key)),
            Arc::new(AcceptFinality),
        )
    }

    fn open_host_on_node(
        directory: &TempDirectory,
        fixture: &Fixture,
        node: NodeId,
    ) -> SharedAgentHost {
        let merge_key = fixture
            .replica_keys
            .iter()
            .find(|key| NodeId::of_authenticated_peer(&peer_id(key)) == node)
            .unwrap()
            .clone();
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node,
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(merge_key)),
            Arc::new(AcceptFinality),
        )
        .unwrap()
    }

    #[cfg(feature = "network")]
    fn live_network(seed: u8, listen: Vec<libp2p::Multiaddr>) -> Arc<crate::network::Network> {
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        let peer = keypair.public().to_peer_id();
        Arc::new(crate::network::Network::start(
            crate::network::NetworkConfig {
                keypair,
                local_prefix: crate::network::derive_node_prefix(&peer),
                listen,
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            },
        ))
    }

    #[cfg(feature = "network")]
    fn wait_until(timeout: std::time::Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if predicate() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[cfg(feature = "network")]
    fn join_live_network(network: Arc<crate::network::Network>) {
        network.shutdown();
        assert!(wait_until(std::time::Duration::from_secs(5), || {
            Arc::strong_count(&network) == 1
        }));
        Arc::try_unwrap(network).ok().unwrap().join();
    }

    fn physical_bytes(directory: &TempDirectory) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, at: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(at)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    visit(root, &path, output);
                } else if kind.is_file() {
                    output.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                } else {
                    panic!("unexpected test namespace entry: {path:?}");
                }
            }
        }

        let mut output = BTreeMap::new();
        visit(&directory.0, &directory.0, &mut output);
        output
    }

    fn provision_apply_candidate(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        term: u64,
    ) -> VerifiedSharedAgentSnapshotCandidate {
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(term, authorized_management(fixture, 2, 0xc1))
            .unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        host.request_snapshot_compaction(fixture.agent).unwrap()
    }

    fn append_rejected_local_invocation(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        discriminator: u8,
    ) {
        let work = crate::agent_sdk::InvocationWork {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            invocation: crate::agent_sdk::InvocationId([discriminator; 32]),
            actor: crate::agent_sdk::ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: crate::agent_sdk::Hash([discriminator.wrapping_add(2); 32]),
            deployment: crate::agent_sdk::DeploymentId([discriminator.wrapping_add(3); 32]),
            program: crate::agent_sdk::ProgramId([discriminator.wrapping_add(4); 32]),
            mode: crate::agent_sdk::MethodMode::Local,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: vec![discriminator],
            installation_data: None,
            availability: Vec::new(),
            gas: 1_000,
            recovery_only: false,
        };
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        assert_eq!(
            host.apply_clean_local(fixture.agent, work, authorization)
                .unwrap(),
            crate::agent_sdk::RuntimeOutcome::Completed(Err(
                crate::agent_sdk::InvocationError::NotFound,
            )),
        );
    }

    #[cfg(feature = "network")]
    fn publish_merge_invocation(
        host: &mut SharedAgentHost,
        fixture: &Fixture,
        discriminator: u8,
    ) -> MergeEventId {
        let work = crate::agent_sdk::InvocationWork {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            invocation: crate::agent_sdk::InvocationId([discriminator; 32]),
            actor: crate::agent_sdk::ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: crate::agent_sdk::Hash([discriminator.wrapping_add(2); 32]),
            deployment: crate::agent_sdk::DeploymentId([discriminator.wrapping_add(3); 32]),
            program: crate::agent_sdk::ProgramId([discriminator.wrapping_add(4); 32]),
            mode: crate::agent_sdk::MethodMode::Merge,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: vec![discriminator],
            installation_data: None,
            availability: Vec::new(),
            gas: 1_000,
            recovery_only: false,
        };
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        host.agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .publish_merge_for_test(ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
                observed_slot: 20,
            })
            .unwrap()
    }

    fn snapshot_certificate(
        candidate: &VerifiedSharedAgentSnapshotCandidate,
        fixture: &Fixture,
    ) -> SharedAgentSnapshotCertificate {
        snapshot_certificate_with_message(candidate, fixture, candidate.signing_message())
    }

    fn authorized_management(
        fixture: &Fixture,
        sequence: u64,
        discriminator: u8,
    ) -> ReplayOperation {
        let request = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([discriminator; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId(
                [discriminator.wrapping_add(1); 32],
            ),
        };
        let authority = clean_management_receipt(
            &fixture.descriptor,
            &request,
            sequence,
            &fixture.authority_key,
        );
        ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot: 20,
        }
    }

    fn snapshot_certificate_with_message(
        candidate: &VerifiedSharedAgentSnapshotCandidate,
        fixture: &Fixture,
        message: Hash,
    ) -> SharedAgentSnapshotCertificate {
        let committee = candidate.claim().active_committee();
        let mut signatures = fixture
            .replica_keys
            .iter()
            .filter_map(|key| {
                let node = NodeId::of_authenticated_peer(&peer_id(key));
                committee
                    .member_by_node(node)
                    .filter(|member| member.replica().role == ReplicaRole::Voter)
                    .map(|_| {
                        ReplicaCommitSignature::new(node, key.sign(&message.0).to_bytes()).unwrap()
                    })
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        SharedAgentSnapshotCertificate::new(candidate.claim().clone(), signatures).unwrap()
    }

    fn compaction_limits(max_unlinks: usize) -> SharedAgentCompactionLimits {
        SharedAgentCompactionLimits {
            max_binding_unlinks: 1,
            max_index_nodes: 10_000,
            max_marked_objects: 10_000,
            max_marked_blobs: 10_000,
            max_scanned_files: 10_000,
            max_scanned_bytes: 64 * 1024 * 1024,
            max_unlinks,
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn prepared_expiry_signing_keeps_clock_and_fresh_prefix_guards() {
        use super::super::shared_raft::AgentRaftCommand;
        use super::super::shared_recovery::{
            SharedRecoveryRegistration, SharedRecoveryRegistrationRequest,
            recovery_registration_for_test,
        };
        use crate::actors::codec::Encode as _;
        use crate::agent_sdk::wire::CanonicalWire as _;

        let directory = TempDirectory::new("prepared_expiry_signing");
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "prepared-expiry-runtime",
            0x75,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let fixture = standard_projection_fixture_with_replicas(
            0x3b,
            runtime,
            &[
                (0x31, ReplicaRole::Voter),
                (0x32, ReplicaRole::Voter),
                (0x33, ReplicaRole::Voter),
            ],
            false,
        );
        let clock = Arc::new(AtomicU64::new(20));
        let mut host = open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&clock));
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let route = host.agents[&fixture.agent].driver.active_route().unwrap();
        let template = recovery_registration_for_test(1, 7);
        let mut query = template.query().clone();
        query.authority.space = fixture.descriptor.identity.space;
        query.authority.system_agent = fixture.descriptor.identity.agent;
        query.authority.system_runtime_deployment = fixture.descriptor.identity.runtime_deployment;
        let scope = query.recovery.as_mut().unwrap();
        scope.generation = crate::agent_sdk::Hash(route.generation().replication_id());
        scope.committee = crate::agent_sdk::Hash(*route.committee().as_bytes());
        let signature = key(7).sign(&query.signing_bytes()).to_bytes();
        let crate::agent_sdk::authority::AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: stored,
            ..
        } = &mut query.authentication
        else {
            panic!("credential-authenticated fixture")
        };
        *stored = signature;
        let mut work = template.work().clone();
        work.space = query.authority.space;
        work.agent = query.authority.system_agent;
        work.runtime_deployment = query.authority.system_runtime_deployment;
        work.invocation = query.expected_invocation();
        work.message = vec![crate::actors::value::TAG_DYNAMIC];
        work.message.extend(
            crate::actors::value::Msg::new("credential_projection")
                .with(
                    "query",
                    crate::actors::value::Value::Bytes(query.encode().unwrap()),
                )
                .encode(),
        );
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 10),
        );
        let request = SharedRecoveryRegistrationRequest::new(
            route.generation(),
            route.committee(),
            host.scope().node,
            1,
            None,
            query,
            work,
            authorization,
        )
        .unwrap();
        let signature = fixture.replica_keys[0]
            .sign(&request.signing_message().0)
            .to_bytes();
        let registration = SharedRecoveryRegistration::new(
            request,
            ReplicaCommitSignature::new(host.scope().node, signature).unwrap(),
        )
        .unwrap();
        host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: AgentRaftCommand::RegisterRecovery {
                        route,
                        registration: registration.clone(),
                    }
                    .encode(),
                },
            )
            .unwrap();
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        let request = registration.request().request_commitment();
        clock.store(19, Ordering::SeqCst);
        assert!(matches!(
            host.prepare_signed_recovery_expiry(fixture.agent, request),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
        clock.store(20, Ordering::SeqCst);
        let (candidate, signature) = host
            .prepare_signed_recovery_expiry(fixture.agent, request)
            .unwrap();
        assert_eq!(candidate.claim().request(), request);
        assert_eq!(candidate.claim().prefix_index(), 1);
        assert_eq!(candidate.claim().prefix_term(), 7);
        assert_eq!(candidate.claim().observed_slot(), 20);
        assert_eq!(signature.signer(), host.scope().node);
        assert_eq!(
            signature.signature(),
            &fixture.replica_keys[0]
                .sign(&candidate.signing_message().0)
                .to_bytes()
        );
        assert_eq!(
            host.sign_recovery_expiry(fixture.agent, candidate.claim())
                .unwrap(),
            signature
        );
        host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 2 }
        );
        assert_eq!(
            host.sign_recovery_expiry(fixture.agent, candidate.claim()),
            Err(SharedAgentHostError::Unavailable)
        );
        let (next, _) = host
            .prepare_signed_recovery_expiry(fixture.agent, request)
            .unwrap();
        assert_eq!(next.claim().prefix_index(), 2);
    }

    #[test]
    fn filesystem_host_provisions_applies_committed_slot_and_reopens_exact_generation() {
        let directory = TempDirectory::new("provision_reopen_apply");
        let fixture = fixture(0x13);
        let mut host = open_host(&directory, &fixture);
        assert!(host.is_empty());
        let status = host
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        assert_eq!(status.identity.agent, fixture.agent);
        assert_eq!(status.replicas.len(), 3);
        assert_eq!(status.applied_slots, 0);
        assert_eq!(
            host.require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        host.reserve_transport_attachment(fixture.agent).unwrap();
        host.mark_transport_attached(fixture.agent).unwrap();
        assert_eq!(host.require_transport(fixture.agent), Ok(()));
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap().transport,
            SharedAgentTransportState::Attached
        );
        host.mark_transport_stopping(fixture.agent).unwrap();
        host.release_transport_attachment(fixture.agent).unwrap();
        assert_eq!(
            host.require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        assert!(matches!(
            host.request_snapshot_compaction(fixture.agent),
            Err(SharedAgentHostError::SnapshotBoundaryRequired)
        ));
        let index = host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        let route = host.physical_route(fixture.agent).unwrap();
        let generation = status.generation;
        drop(host);

        let mut reopened = open_host(&directory, &fixture);
        let recovered = reopened.show(fixture.agent).unwrap().unwrap();
        assert_eq!(recovered.generation, generation);
        assert_eq!(recovered.replication_id, route.replication_id);
        assert_eq!(recovered.applied_slots, 1);
        assert_eq!(reopened.list().unwrap(), vec![recovered]);
        assert_eq!(
            reopened.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Idle
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn physical_current_abi_custom_runtime_clean_management_recovers_and_derives_actor_lanes() {
        use super::super::shared_journal_driver::{
            CleanInvocationReplayRequest, PreparedCleanManagement, PreparedCleanOrdered,
        };
        use super::super::shared_raft::AgentRaftCommand;

        let directory = TempDirectory::new("clean_one_voter_management");
        let fixture = clean_fixture(0x61);
        assert_eq!(
            fixture.descriptor.identity.runtime_program,
            fixture.runtime.program()
        );
        let slot = Arc::new(AtomicU64::new(20));
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        let status = host
            .provision(
                fixture.shared.provision.clone(),
                fixture.shared.catalog.clone(),
                fixture.shared.committee_authority,
            )
            .unwrap();
        assert_eq!(status.replicas.len(), 1);
        assert_eq!(status.applied_slots, 0);
        let ReplayOperation::CleanManage {
            request: create_request,
            authority: create_receipt,
            ..
        } = &fixture.shared.provision.proposal().create().operation
        else {
            panic!("clean Create")
        };
        host.observe_clean_genesis_application(
            fixture.shared.agent,
            create_request,
            create_receipt,
        )
        .expect("custom-runtime genesis has host-owned application evidence");
        assert_eq!(
            status.engines,
            SharedAgentEnginePlan {
                control_raft: true,
                linear_raft: false,
                merge: false,
                local: false,
            },
            "runtime capabilities are not installed-actor lane ownership",
        );

        use crate::agent_sdk::wire::CanonicalWire as _;
        let policy = crate::agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_bytes = policy.encode().unwrap();
        let private = crate::agent_sdk::ManagementRequest::PrivateControl {
            control: Box::new(crate::agent_sdk::private::PrivateControlRecord {
                space: fixture.descriptor.identity.space,
                agent: fixture.descriptor.identity.agent,
                sequence: 0,
                previous: None,
                operation: crate::agent_sdk::private::PrivateControlOperation::SetResourcePolicy {
                    policy: crate::agent_sdk::BlobRef::of_bytes(&policy_bytes),
                },
                signer: crate::agent_sdk::private::PrivateControlSigner::Owner,
                signer_public_key: [0x62; 32],
                signature: [0x63; crate::agent_sdk::private::PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: Box::new(crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(
                policy,
            )),
        };
        assert!(private.is_valid());
        let private_receipt =
            clean_management_receipt(&fixture.descriptor, &private, 2, &fixture.authority_key);
        assert!(matches!(
            host.prepare_clean_management(
                fixture.shared.agent,
                private,
                private_receipt,
                SdkManagementArtifacts::None,
            ),
            Err(SharedAgentHostError::CorruptResidue)
        ));
        assert_eq!(host.list().unwrap()[0].applied_slots, 0);

        let target = &fixture.upgrade_runtime;
        let upgrade = crate::agent_sdk::RuntimeUpgrade {
            from_deployment: fixture.descriptor.identity.runtime_deployment,
            to_deployment: target.deployment(),
            to_program: target.program(),
            producer: target.producer(),
            package: target.package_ref().clone(),
            contract: target.manifest().contract,
            capabilities: target.capabilities(),
        };
        let request = crate::agent_sdk::ManagementRequest::UpgradeRuntime(Box::new(upgrade));
        let receipt =
            clean_management_receipt(&fixture.descriptor, &request, 2, &fixture.authority_key);
        slot.store(21, Ordering::SeqCst);
        let prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                request.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Runtime(target),
            )
            .unwrap();
        let input = prepared.input().expect("fresh upgrade must be proposed");
        let commands = prepared.into_commands();
        assert!(commands.len() >= 2);
        let decoded = commands
            .iter()
            .map(|payload| AgentRaftCommand::decode(payload).unwrap())
            .collect::<Vec<_>>();
        let expected_artifact = BlobRef {
            hash: Hash(target.package_ref().hash.0),
            len: target.package_ref().len,
        };
        let batch = match decoded.last().unwrap() {
            AgentRaftCommand::Ordered {
                artifact_batch: Some(batch),
                entry,
                ..
            } => {
                assert_eq!(entry.input.id(), input);
                *batch
            }
            command => {
                panic!("upgrade did not end in an artifact-bound Ordered command: {command:?}")
            }
        };
        let chunks = decoded[..decoded.len() - 1]
            .iter()
            .map(|command| match command {
                AgentRaftCommand::ArtifactChunk(chunk) => chunk,
                command => panic!("unexpected pre-Ordered command: {command:?}"),
            })
            .collect::<Vec<_>>();
        assert!(!chunks.is_empty());
        assert!(chunks.iter().all(|chunk| {
            chunk.batch() == batch
                && chunk.manifest().artifacts() == core::slice::from_ref(&expected_artifact)
        }));

        // Apply one chunk, restart, and finish the exact original command
        // sequence. Recovery neither restages nor duplicates that physical
        // slot or its content-addressed bytes.
        let first = host.agents[&fixture.shared.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: commands[0].clone(),
                },
            )
            .unwrap();
        assert_eq!(first, 1);
        assert_eq!(
            host.apply_next(fixture.shared.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 },
        );
        drop(host);
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        for payload in commands.iter().skip(1) {
            let index = host.agents[&fixture.shared.agent]
                .driver
                .ledger()
                .append_committed_for_test(
                    7,
                    &EntryKind::Data {
                        payload: payload.clone(),
                    },
                )
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.shared.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index },
            );
        }
        let outcome = host
            .take_clean_ordered_result(fixture.shared.agent, input)
            .unwrap();
        assert!(matches!(
            &outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::RuntimeUpgraded(identity)
            )) if identity.runtime_deployment == target.deployment()
        ));
        assert_eq!(
            host.journal_position(fixture.shared.agent)
                .unwrap()
                .ordered_index,
            1,
        );

        // Lose the reply and reopen on the new PVM. The exact historical
        // from-deployment request is recovered from durable Ordered membership
        // and guest-owned state without ambient bytes or another Raft slot.
        let applied_before_retry = host
            .show(fixture.shared.agent)
            .unwrap()
            .unwrap()
            .applied_slots;
        drop(host);
        slot.store(22, Ordering::SeqCst);
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        let retained = host
            .prepare_clean_management(
                fixture.shared.agent,
                request.clone(),
                receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert_eq!(retained.retained(), Some(&outcome));
        assert!(retained.into_commands().is_empty());
        assert_eq!(
            host.show(fixture.shared.agent)
                .unwrap()
                .unwrap()
                .applied_slots,
            applied_before_retry,
        );
        assert_eq!(
            host.journal_position(fixture.shared.agent)
                .unwrap()
                .ordered_index,
            1,
        );

        let mut current_descriptor = fixture.descriptor.clone();
        current_descriptor.identity.runtime_deployment = target.deployment();
        current_descriptor.identity.runtime_program = target.program();
        current_descriptor.identity.runtime_producer = target.producer();
        current_descriptor.runtime_package = target.package_ref().clone();
        current_descriptor.runtime_contract = target.manifest().contract;
        current_descriptor.capabilities = target.capabilities();
        current_descriptor.validate().unwrap();

        let actor_package = &fixture.actor_package;
        let install = clean_install_request(current_descriptor.identity.agent, actor_package);
        let install_receipt =
            clean_management_receipt(&current_descriptor, &install, 3, &fixture.authority_key);
        let install_receipt_commitment = install_receipt.commitment();
        slot.store(23, Ordering::SeqCst);
        let install_prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                install.clone(),
                install_receipt,
                SdkManagementArtifacts::Actor(actor_package),
            )
            .unwrap();
        let install_input = install_prepared.input().unwrap();
        for payload in install_prepared.into_commands() {
            let index = host.agents[&fixture.shared.agent]
                .driver
                .ledger()
                .append_committed_for_test(8, &EntryKind::Data { payload })
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.shared.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index },
            );
        }
        let installed = host
            .take_clean_ordered_result(fixture.shared.agent, install_input)
            .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Installed(entry),
        )) = installed
        else {
            panic!("install did not return its exact SDK entry")
        };
        let full_status = host.show(fixture.shared.agent).unwrap().unwrap();
        assert_eq!(
            host.capacity(fixture.shared.agent).unwrap(),
            (
                full_status.applied_slots,
                full_status.remaining_slots,
                full_status.reservation_pending,
            ),
            "capacity-only recovery admission must match the full status facts",
        );
        assert!(matches!(
            host.capacity(AgentId::ZERO),
            Err(SharedAgentHostError::AgentNotFound)
        ));
        assert_eq!(
            full_status.engines,
            SharedAgentEnginePlan {
                control_raft: true,
                linear_raft: true,
                merge: false,
                local: false,
            },
        );
        let attachment_status = host
            .supervisor_attachment_status(fixture.shared.agent)
            .unwrap()
            .unwrap();
        assert_eq!(attachment_status.identity, full_status.identity);
        assert_eq!(attachment_status.generation, full_status.generation);
        assert_eq!(attachment_status.route, full_status.route);
        assert_eq!(attachment_status.replication_id, full_status.replication_id);
        assert_eq!(attachment_status.local_role, full_status.local_role);
        assert_eq!(attachment_status.replicas, full_status.replicas);
        assert_eq!(
            attachment_status.committee_transition,
            full_status.committee_transition
        );
        assert_eq!(attachment_status.transport, full_status.transport);
        let physical = host
            .supervisor_invocation_material(fixture.shared.agent, entry.actor)
            .unwrap();
        assert_eq!(physical.descriptor, current_descriptor);
        assert_eq!(physical.actor.entry, entry);
        let crate::agent_sdk::ManagementRequest::Install(installed_request) = &install else {
            unreachable!()
        };
        assert_eq!(
            physical.actor.install_request,
            installed_request.lineage_commitment()
        );
        assert_eq!(physical.install_request, physical.actor.install_request);
        assert_eq!(physical.program.bytes, actor_package.program_bytes());
        assert_eq!(
            physical.schema.bytes,
            actor_package.state_lane_schema_bytes()
        );
        assert_eq!(physical.policies.bytes, actor_package.method_policy_bytes());

        let management_evidence = host.agents[&fixture.shared.agent]
            .driver
            .latest_clean_management_disposition()
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                host.observe_clean_genesis_application(
                    fixture.shared.agent,
                    create_request,
                    create_receipt
                ),
                Err(SharedAgentHostError::ScopeMismatch)
            ),
            "later management evidence cannot stand in for initial Create"
        );
        assert_eq!(management_evidence.authority, install_receipt_commitment);
        assert_eq!(management_evidence.request, install.replay_commitment());
        assert_eq!(
            management_evidence.result,
            Ok(crate::agent_sdk::ManagementReply::Installed(entry.clone()))
        );

        // Cross the real quorum-certified snapshot and physical compaction
        // boundary before testing cold recovery of opaque management evidence.
        let candidate = host
            .request_snapshot_compaction(fixture.shared.agent)
            .unwrap();
        let certificate = snapshot_certificate(&candidate, &fixture.shared);
        host.install_snapshot(fixture.shared.agent, &certificate)
            .unwrap();
        let mut compacted = false;
        for _ in 0..256 {
            if host
                .compact_snapshot(fixture.shared.agent, compaction_limits(16))
                .unwrap()
                .complete
            {
                compacted = true;
                break;
            }
        }
        assert!(compacted);
        drop(host);

        use crate::agent::journal::{CanonicalJournalRecord as _, CheckpointManifest};
        let checkpoints = physical_bytes(&directory)
            .into_iter()
            .filter_map(|(path, bytes)| {
                let checkpoint = CheckpointManifest::decode(&bytes).ok()?;
                (checkpoint.id() == candidate.claim().checkpoint())
                    .then_some((path, bytes, checkpoint))
            })
            .collect::<Vec<_>>();
        let [(checkpoint_path, original_bytes, checkpoint)] = checkpoints.as_slice() else {
            panic!("expected exactly one certified checkpoint file");
        };
        assert!(checkpoint.clean_management.is_some());
        for mutation in 0..5 {
            let mut substituted = checkpoint.clone();
            let evidence = substituted.clean_management.as_mut().unwrap();
            match mutation {
                0 => evidence.authority = crate::agent_sdk::Hash([0xf1; 32]),
                1 => evidence.request = crate::agent_sdk::Hash([0xf2; 32]),
                2 => evidence.sequence += 1,
                3 => evidence.result = Err(crate::agent_sdk::ManagementError::NotFound),
                _ => substituted.clean_management = None,
            }
            substituted.validate().unwrap();
            assert_ne!(substituted.id(), candidate.claim().checkpoint());
            let mut forged_bytes = certificate.encode();
            let offsets = forged_bytes
                .windows(32)
                .enumerate()
                .filter_map(|(offset, bytes)| {
                    (bytes == candidate.claim().checkpoint().as_bytes()).then_some(offset)
                })
                .collect::<Vec<_>>();
            let [offset] = offsets.as_slice() else {
                panic!("expected one checkpoint reference in the canonical certificate");
            };
            forged_bytes[*offset..*offset + 32].copy_from_slice(substituted.id().as_bytes());
            let forged = SharedAgentSnapshotCertificate::decode(&forged_bytes).unwrap();
            assert_eq!(forged.claim().checkpoint(), substituted.id());
            assert!(
                forged
                    .verify(candidate.claim().active_committee(), forged.claim())
                    .is_err(),
                "old signatures authorized substituted checkpoint evidence {mutation}"
            );
            fs::write(directory.0.join(checkpoint_path), substituted.encode()).unwrap();
            assert!(
                try_open_clean_host(&directory, &fixture, Arc::clone(&slot)).is_err(),
                "substituted management evidence {mutation} reopened under the old certificate"
            );
        }
        fs::write(directory.0.join(checkpoint_path), original_bytes).unwrap();
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        assert_eq!(
            host.agents[&fixture.shared.agent]
                .driver
                .latest_clean_management_disposition()
                .unwrap(),
            Some(management_evidence)
        );
        let before_install_projection =
            super::super::supervisor_adapters::AgentAuthorityRouteProjection::new(
                current_descriptor.replica_generation(),
                current_descriptor.clone(),
                Vec::new(),
            )
            .unwrap();
        let head = crate::agent_sdk::authority::AuthorityProjectionHead {
            state_revision: core::num::NonZeroU64::new(3).unwrap(),
            epoch: core::num::NonZeroU64::new(1).unwrap(),
            authorization_sequence: core::num::NonZeroU64::new(3).unwrap(),
            administration_generation: core::num::NonZeroU64::new(1).unwrap(),
            state_commitment: crate::agent_sdk::Hash([0xc1; 32]),
        };
        assert!(
            host.physical_projection_is_one_ack_ahead(
                head,
                core::slice::from_ref(&before_install_projection),
                None,
                None,
            )
            .unwrap()
        );
        let stale_head = crate::agent_sdk::authority::AuthorityProjectionHead {
            authorization_sequence: core::num::NonZeroU64::new(2).unwrap(),
            ..head
        };
        assert!(
            !host
                .physical_projection_is_one_ack_ahead(
                    stale_head,
                    core::slice::from_ref(&before_install_projection),
                    None,
                    None,
                )
                .unwrap()
        );
        assert_eq!(
            host.supervisor_invocation_material(fixture.shared.agent, entry.actor)
                .unwrap()
                .actor,
            physical.actor,
            "the keyed physical actor/material lookup survives journal reopen"
        );

        // Resume and acknowledgement state belongs to the physically admitted
        // runtime. The host retains the exact public request and selector but
        // must not attempt to decode a custom runtime's opaque components as
        // Standard state before the command can enter deterministic replay.
        let mut availability = vec![
            physical.program.clone(),
            physical.schema.clone(),
            physical.policies.clone(),
        ];
        availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        let work = crate::agent_sdk::InvocationWork {
            space: current_descriptor.identity.space,
            agent: current_descriptor.identity.agent,
            runtime_deployment: current_descriptor.identity.runtime_deployment,
            invocation: crate::agent_sdk::InvocationId([0x94; 32]),
            actor: entry.actor,
            incarnation: physical.actor.incarnation,
            deployment: entry.deployment,
            program: entry.program,
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: vec![0x95],
            installation_data: entry.installation_data.clone(),
            availability,
            gas: 1_000,
            recovery_only: false,
        };
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 23),
        );
        let yielded = crate::agent_sdk::YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: crate::agent_sdk::BlobRef::of_bytes(b"custom-runtime-continuation"),
            ready_sequence: 1,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        for request in [
            CleanInvocationReplayRequest::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
                yielded: yielded.clone(),
            },
            CleanInvocationReplayRequest::Acknowledge {
                work: work.clone(),
                authorization: authorization.clone(),
            },
        ] {
            let expected_operation = match request.clone() {
                CleanInvocationReplayRequest::Invoke {
                    context,
                    work,
                    authorization,
                } => ReplayOperation::CleanInvoke {
                    context,
                    work,
                    authorization,
                    observed_slot: 23,
                },
                CleanInvocationReplayRequest::Resume {
                    context,
                    work,
                    authorization,
                    yielded,
                } => ReplayOperation::CleanResume {
                    context,
                    expected_live: None,
                    work,
                    authorization,
                    yielded,
                    observed_slot: 23,
                },
                CleanInvocationReplayRequest::Acknowledge {
                    work,
                    authorization,
                } => ReplayOperation::CleanAcknowledge {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    expected_live: None,
                    work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                    authorization,
                },
            };
            let prepared = host
                .prepare_clean_ordered_operation(fixture.shared.agent, request.clone())
                .unwrap();
            let PreparedCleanOrdered::Proposal { input, payload } = prepared else {
                panic!("unpublished custom-runtime lifecycle request resolved as retained")
            };
            let AgentRaftCommand::Ordered { entry, .. } =
                AgentRaftCommand::decode(&payload).unwrap()
            else {
                panic!("clean lifecycle request was not a canonical Ordered command")
            };
            assert_eq!(entry.input.id(), input);
            assert_eq!(
                entry.input.operation, expected_operation,
                "the proposed command retains the exact public work, authorization, and selector"
            );
        }

        let remove = crate::agent_sdk::ManagementRequest::RemoveLeaf {
            actor: entry.actor,
            expected_deployment: entry.deployment,
        };
        let remove_receipt =
            clean_management_receipt(&current_descriptor, &remove, 4, &fixture.authority_key);
        slot.store(24, Ordering::SeqCst);
        let remove_prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                remove,
                remove_receipt,
                SdkManagementArtifacts::None,
            )
            .unwrap();
        let remove_input = remove_prepared.input().unwrap();
        for payload in remove_prepared.into_commands() {
            let index = host.agents[&fixture.shared.agent]
                .driver
                .ledger()
                .append_committed_for_test(9, &EntryKind::Data { payload })
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.shared.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index },
            );
        }
        assert!(matches!(
            host.take_clean_ordered_result(fixture.shared.agent, remove_input)
                .unwrap(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Removed(_)
            )),
        ));
        assert_eq!(
            host.show(fixture.shared.agent).unwrap().unwrap().engines,
            SharedAgentEnginePlan {
                control_raft: true,
                linear_raft: false,
                merge: false,
                local: false,
            },
        );

        // An unchanged guest denial remains local and consumes no Raft slot.
        let denied_request = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xa5; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xa6; 32]),
        };
        let denied_receipt = clean_management_receipt(
            &current_descriptor,
            &denied_request,
            5,
            &fixture.authority_key,
        );
        slot.store(25, Ordering::SeqCst);
        let denied_prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                denied_request.clone(),
                denied_receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert!(denied_prepared.input().is_none());
        let denied_outcome = denied_prepared.denied().unwrap().clone();
        assert!(denied_prepared.into_commands().is_empty());
        assert!(matches!(
            denied_outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Err(
                crate::agent_sdk::ManagementError::NotFound
            )),
        ));
        let slots_before_denied_retry = host
            .show(fixture.shared.agent)
            .unwrap()
            .unwrap()
            .applied_slots;
        slot.store(26, Ordering::SeqCst);
        let repeated_denial = host
            .prepare_clean_management(
                fixture.shared.agent,
                denied_request,
                denied_receipt,
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert!(matches!(
            repeated_denial,
            PreparedCleanManagement::Denied {
                outcome: crate::agent_sdk::RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::NotFound
                )),
                ..
            }
        ));
        assert_eq!(
            host.show(fixture.shared.agent)
                .unwrap()
                .unwrap()
                .applied_slots,
            slots_before_denied_retry,
        );

        // The descriptor may adopt only a roster the committee already runs.
        // A different roster must first commit its committee transition, so
        // the ordinary ordered path refuses it before allocating a slot.
        let mut changed_roster = current_descriptor.replicas.clone();
        changed_roster[0].role = match changed_roster[0].role {
            crate::agent_sdk::ReplicaRole::Voter => crate::agent_sdk::ReplicaRole::Observer,
            crate::agent_sdk::ReplicaRole::Observer => crate::agent_sdk::ReplicaRole::Voter,
        };
        let change_replicas = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: current_descriptor.replica_generation(),
            replicas: changed_roster,
        };
        let change_receipt = clean_management_receipt(
            &current_descriptor,
            &change_replicas,
            6,
            &fixture.authority_key,
        );
        assert_eq!(
            host.prepare_clean_management(
                fixture.shared.agent,
                change_replicas,
                change_receipt,
                SdkManagementArtifacts::None,
            )
            .unwrap_err(),
            SharedAgentHostError::CommitteeChangeRefused,
        );
        assert_eq!(
            host.show(fixture.shared.agent)
                .unwrap()
                .unwrap()
                .applied_slots,
            slots_before_denied_retry,
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_shared_applied_availability_binds_exact_retained_publication_and_reopen() {
        let directory = TempDirectory::new("clean_applied_availability");
        let fixture = clean_fixture(0x69);
        let slot = Arc::new(AtomicU64::new(20));
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        host.provision(
            fixture.shared.provision.clone(),
            fixture.shared.catalog.clone(),
            fixture.shared.committee_authority,
        )
        .unwrap();
        let target = &fixture.upgrade_runtime;
        let request = crate::agent_sdk::ManagementRequest::UpgradeRuntime(Box::new(
            crate::agent_sdk::RuntimeUpgrade {
                from_deployment: fixture.descriptor.identity.runtime_deployment,
                to_deployment: target.deployment(),
                to_program: target.program(),
                producer: target.producer(),
                package: target.package_ref().clone(),
                contract: target.manifest().contract,
                capabilities: target.capabilities(),
            },
        ));
        let receipt =
            clean_management_receipt(&fixture.descriptor, &request, 2, &fixture.authority_key);
        slot.store(21, Ordering::SeqCst);
        let prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                request.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Runtime(target),
            )
            .unwrap();
        let input = prepared.input().unwrap();
        assert!(
            host.available_ordered_claim(fixture.shared.agent, input)
                .is_err()
        );
        let commands = prepared.into_commands();
        for payload in commands {
            let index = host.agents[&fixture.shared.agent]
                .driver
                .ledger()
                .append_committed_for_test(7, &EntryKind::Data { payload })
                .unwrap();
            assert!(
                host.available_ordered_claim(fixture.shared.agent, input)
                    .is_err(),
                "committed bytes alone are not an available applied result"
            );
            assert_eq!(
                host.apply_next(fixture.shared.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index }
            );
        }
        let claim = host
            .available_ordered_claim(fixture.shared.agent, input)
            .unwrap();
        host.verify_ordered_availability(
            fixture.shared.agent,
            claim.raft_index(),
            claim.raft_term(),
            claim.commitment(),
        )
        .unwrap();
        for (index, term, hash) in [
            (0, claim.raft_term(), claim.commitment()),
            (
                claim.raft_index() + 1,
                claim.raft_term(),
                claim.commitment(),
            ),
            (
                claim.raft_index(),
                claim.raft_term() + 1,
                claim.commitment(),
            ),
            (
                claim.raft_index(),
                claim.raft_term(),
                crate::service::Hash::ZERO,
            ),
            (
                claim.raft_index(),
                claim.raft_term(),
                crate::service::Hash([0x91; 32]),
            ),
        ] {
            assert!(
                host.verify_ordered_availability(fixture.shared.agent, index, term, hash)
                    .is_err()
            );
        }
        let outcome = host
            .take_clean_ordered_result(fixture.shared.agent, input)
            .unwrap();
        let retry = host
            .prepare_clean_management(
                fixture.shared.agent,
                request.clone(),
                receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert_eq!(retry.input(), Some(input));
        assert_eq!(retry.retained(), Some(&outcome));
        assert_eq!(
            host.available_ordered_claim(fixture.shared.agent, input)
                .unwrap(),
            claim
        );
        drop(host);
        let mut reopened = open_clean_host(&directory, &fixture, slot);
        assert_eq!(
            reopened
                .available_ordered_claim(fixture.shared.agent, input)
                .unwrap(),
            claim
        );
        let retry = reopened
            .prepare_clean_management(
                fixture.shared.agent,
                request,
                receipt,
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert_eq!(retry.input(), Some(input));
        assert_eq!(retry.retained(), Some(&outcome));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_shared_upgrade_rejects_ordered_command_without_its_exact_artifact_batch() {
        use super::super::shared_raft::AgentRaftCommand;

        let directory = TempDirectory::new("clean_missing_artifact_batch");
        let fixture = clean_fixture(0x62);
        let slot = Arc::new(AtomicU64::new(20));
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        host.provision(
            fixture.shared.provision.clone(),
            fixture.shared.catalog.clone(),
            fixture.shared.committee_authority,
        )
        .unwrap();
        let target = &fixture.upgrade_runtime;
        let request = crate::agent_sdk::ManagementRequest::UpgradeRuntime(Box::new(
            crate::agent_sdk::RuntimeUpgrade {
                from_deployment: fixture.descriptor.identity.runtime_deployment,
                to_deployment: target.deployment(),
                to_program: target.program(),
                producer: target.producer(),
                package: target.package_ref().clone(),
                contract: target.manifest().contract,
                capabilities: target.capabilities(),
            },
        ));
        let receipt =
            clean_management_receipt(&fixture.descriptor, &request, 2, &fixture.authority_key);
        slot.store(21, Ordering::SeqCst);
        let prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                request,
                receipt,
                SdkManagementArtifacts::Runtime(target),
            )
            .unwrap();
        let input = prepared.input().unwrap();
        let commands = prepared.into_commands();
        assert!(commands[..commands.len() - 1].iter().all(|payload| {
            matches!(
                AgentRaftCommand::decode(payload).unwrap(),
                AgentRaftCommand::ArtifactChunk(_)
            )
        }));
        let hostile = match AgentRaftCommand::decode(commands.last().unwrap()).unwrap() {
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: Some(_),
                entry,
            } => AgentRaftCommand::Ordered {
                route,
                artifact_batch: None,
                entry,
            }
            .encode(),
            command => panic!("expected artifact-bearing Ordered command: {command:?}"),
        };
        let index = host.agents[&fixture.shared.agent]
            .driver
            .ledger()
            .append_committed_for_test(7, &EntryKind::Data { payload: hostile })
            .unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            host.apply_next(fixture.shared.agent),
            Err(SharedAgentHostError::CorruptResidue),
        );
        assert_eq!(
            host.journal_position(fixture.shared.agent)
                .unwrap()
                .ordered_index,
            0,
        );
        assert_eq!(
            host.try_take_clean_ordered_result(fixture.shared.agent, input)
                .unwrap(),
            None,
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_shared_upgrade_rejects_a_substituted_artifact_batch() {
        use super::super::shared_raft::{AgentRaftCommand, ArtifactBatchManifest, ArtifactChunk};

        let directory = TempDirectory::new("clean_substituted_artifact_batch");
        let fixture = clean_fixture(0x64);
        let slot = Arc::new(AtomicU64::new(20));
        let mut host = open_clean_host(&directory, &fixture, Arc::clone(&slot));
        host.provision(
            fixture.shared.provision.clone(),
            fixture.shared.catalog.clone(),
            fixture.shared.committee_authority,
        )
        .unwrap();
        let target = &fixture.upgrade_runtime;
        let request = crate::agent_sdk::ManagementRequest::UpgradeRuntime(Box::new(
            crate::agent_sdk::RuntimeUpgrade {
                from_deployment: fixture.descriptor.identity.runtime_deployment,
                to_deployment: target.deployment(),
                to_program: target.program(),
                producer: target.producer(),
                package: target.package_ref().clone(),
                contract: target.manifest().contract,
                capabilities: target.capabilities(),
            },
        ));
        let receipt =
            clean_management_receipt(&fixture.descriptor, &request, 2, &fixture.authority_key);
        slot.store(21, Ordering::SeqCst);
        let prepared = host
            .prepare_clean_management(
                fixture.shared.agent,
                request,
                receipt,
                SdkManagementArtifacts::Runtime(target),
            )
            .unwrap();
        let input = prepared.input().unwrap();
        let commands = prepared.into_commands();
        for payload in &commands[..commands.len() - 1] {
            let index = host.agents[&fixture.shared.agent]
                .driver
                .ledger()
                .append_committed_for_test(
                    7,
                    &EntryKind::Data {
                        payload: payload.clone(),
                    },
                )
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.shared.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index },
            );
        }
        let (route, entry) = match AgentRaftCommand::decode(commands.last().unwrap()).unwrap() {
            AgentRaftCommand::Ordered {
                route,
                artifact_batch: Some(_),
                entry,
            } => (route, entry),
            command => panic!("expected artifact-bearing Ordered command: {command:?}"),
        };
        let substitute_bytes = b"complete but unrelated artifact batch".to_vec();
        let substitute_manifest = ArtifactBatchManifest::new(
            route,
            vec![crate::service::BlobRef::of_bytes(&substitute_bytes)],
        )
        .unwrap();
        let substitute_batch = substitute_manifest.id();
        let substitute_chunk =
            ArtifactChunk::new(substitute_manifest, 0, 0, substitute_bytes).unwrap();
        let substitute_payload = AgentRaftCommand::ArtifactChunk(substitute_chunk).encode();
        let substitute_index = host.agents[&fixture.shared.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                7,
                &EntryKind::Data {
                    payload: substitute_payload,
                },
            )
            .unwrap();
        assert_eq!(
            host.apply_next(fixture.shared.agent).unwrap(),
            SharedAgentApplyOutcome::Applied {
                index: substitute_index
            },
        );
        let hostile = AgentRaftCommand::Ordered {
            route,
            artifact_batch: Some(substitute_batch),
            entry,
        }
        .encode();
        host.agents[&fixture.shared.agent]
            .driver
            .ledger()
            .append_committed_for_test(7, &EntryKind::Data { payload: hostile })
            .unwrap();
        assert_eq!(
            host.apply_next(fixture.shared.agent),
            Err(SharedAgentHostError::CorruptResidue),
        );
        assert_eq!(
            host.journal_position(fixture.shared.agent)
                .unwrap()
                .ordered_index,
            0,
        );
        assert_eq!(
            host.try_take_clean_ordered_result(fixture.shared.agent, input)
                .unwrap(),
            None,
        );
    }

    #[test]
    #[cfg(feature = "experimental-state-blocks")]
    fn external_candidate_owner_preserves_image_routes_and_public_reopen() {
        let directory = TempDirectory::new("external_candidate_image_owner");
        let fixture = fixture(0x2b);
        let node = fixture.provision.replicas().members()[0].replica().node;
        let key = fixture
            .replica_keys
            .iter()
            .find(|key| NodeId::of_authenticated_peer(&peer_id(key)) == node)
            .unwrap()
            .clone();
        let mut host = SharedAgentHost::open_external_candidates(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node,
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(key)),
            Arc::new(AcceptFinality),
            None,
        )
        .unwrap();
        let provisioned = host
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        assert!(!host.uses_external_state(fixture.agent).unwrap());
        let route = host.physical_route(fixture.agent).unwrap();
        assert_eq!(route.generation, provisioned.generation);
        host.agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(7, authorized_management(&fixture, 2, 0xb1))
            .unwrap();
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );
        let expected = host.show(fixture.agent).unwrap().unwrap();
        let archive_limits = super::super::journal_store::ExternalArchiveLimits {
            max_objects: 100,
            max_blobs: 100,
            max_history_nodes: 100,
            max_wire_bytes: 1_000_000,
        };
        let mut archive = Vec::new();
        assert!(matches!(
            host.agents
                .get_mut(&fixture.agent)
                .unwrap()
                .driver
                .export_external_common_checkpoint_archive(archive_limits, &mut archive),
            Err(SharedJournalDriverError::InvalidProfile)
        ));
        assert_eq!(
            host.export_external_common_checkpoint_archive(
                fixture.agent,
                archive_limits,
                &mut archive,
            )
            .unwrap_err(),
            SharedAgentHostError::PortableBackupUnsupported,
        );
        assert!(archive.is_empty());
        assert_eq!(host.show(fixture.agent).unwrap().unwrap(), expected);
        drop(host);

        // Selecting the candidate owner never rewrites an image generation's
        // identity, admission or storage layout. Ordinary public recovery of
        // that same generation still uses the image executor.
        let mut reopened = open_host(&directory, &fixture);
        assert!(!reopened.uses_external_state(fixture.agent).unwrap());
        assert_eq!(reopened.physical_route(fixture.agent).unwrap(), route);
        assert_eq!(reopened.show(fixture.agent).unwrap().unwrap(), expected);
        assert_eq!(
            reopened
                .export_external_common_checkpoint_archive(
                    fixture.agent,
                    archive_limits,
                    &mut archive,
                )
                .unwrap_err(),
            SharedAgentHostError::PortableBackupUnsupported,
        );
        assert!(archive.is_empty());
    }

    #[test]
    fn pending_shared_binding_before_head_publication_reopens_and_applies_once() {
        for (include_anchor, prefix_slots) in [(false, 0), (true, 0), (false, 1), (true, 1)] {
            let directory = TempDirectory::new("pending_binding_before_heads");
            let fixture = fixture(0x25);
            let mut host = open_host(&directory, &fixture);
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
            if prefix_slots == 1 {
                host.agents
                    .get_mut(&fixture.agent)
                    .unwrap()
                    .driver
                    .append_ordered_for_test(7, authorized_management(&fixture, 2, 0xb3))
                    .unwrap();
                assert_eq!(
                    host.apply_next(fixture.agent).unwrap(),
                    SharedAgentApplyOutcome::Applied { index: 1 }
                );
            }
            let pending_index = prefix_slots + 1;
            let driver = &mut host.agents.get_mut(&fixture.agent).unwrap().driver;
            assert_eq!(
                driver
                    .append_ordered_for_test(7, authorized_management(&fixture, 3, 0xb4))
                    .unwrap(),
                pending_index
            );
            driver
                .stage_next_ordered_before_heads_for_test(include_anchor)
                .unwrap();
            driver.assert_staged_binding_requires_exact_reservation_for_test();
            assert_eq!(driver.capacity().unwrap().0, prefix_slots);
            assert!(driver.capacity().unwrap().2);
            drop(host);

            let mut reopened = open_host(&directory, &fixture);
            assert_eq!(reopened.capacity(fixture.agent).unwrap().0, prefix_slots);
            assert!(reopened.capacity(fixture.agent).unwrap().2);
            assert_eq!(
                reopened.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied {
                    index: pending_index,
                }
            );
            assert_eq!(
                reopened.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Idle
            );
            let completed = reopened.show(fixture.agent).unwrap().unwrap();
            assert_eq!(completed.applied_slots, pending_index);
            assert!(!reopened.capacity(fixture.agent).unwrap().2);
            drop(reopened);
            let reopened = open_host(&directory, &fixture);
            assert_eq!(reopened.show(fixture.agent).unwrap().unwrap(), completed);
        }
    }

    #[test]
    fn filesystem_snapshot_is_authenticated_compacted_repeated_and_reopened_with_suffix() {
        let directory = TempDirectory::new("snapshot_compact_restart");
        let fixture = fixture(0x15);
        let mut host = open_host(&directory, &fixture);
        let provisioned = host
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();

        let first_index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(7, authorized_management(&fixture, 2, 0xb1))
            .unwrap();
        assert_eq!(first_index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 }
        );

        // The signed checkpoint predecessor must remain distinct from the
        // Ordered publication successor when Local work advanced the head.
        // The clean rejected invocation consumes its result synchronously, so
        // no live result can independently block checkpoint creation.
        append_rejected_local_invocation(&mut host, &fixture, 0xb3);

        let first_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(first_candidate.claim().ordered().agent(), fixture.agent);
        assert_eq!(first_candidate.claim().raft_index(), 1);
        assert_eq!(first_candidate.claim().local_node(), host.scope().node);
        assert_ne!(
            first_candidate.claim().checkpoint_predecessor(),
            first_candidate.claim().ordered_successor()
        );
        let forged = snapshot_certificate_with_message(
            &first_candidate,
            &fixture,
            Hash::digest(b"vos/test/forged-snapshot-message", &[]),
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &forged),
            Err(SharedAgentHostError::SnapshotCertificateInvalid)
        );
        let after_forgery = host.show(fixture.agent).unwrap().unwrap();
        assert_eq!(after_forgery.applied_slots, 1);
        assert_eq!(after_forgery.snapshots, SharedAgentSnapshotState::None);
        let unchanged = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(unchanged.claim(), first_candidate.claim());

        let first_certificate = snapshot_certificate(&first_candidate, &fixture);
        let first_install = host
            .install_snapshot(fixture.agent, &first_certificate)
            .unwrap();
        assert_eq!(first_install.raft_index, 1);
        assert_eq!(
            host.install_snapshot(fixture.agent, &first_certificate)
                .unwrap(),
            first_install
        );
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap().snapshots,
            SharedAgentSnapshotState::Installed {
                raft_index: 1,
                raft_term: 7,
                certificate: first_certificate.commitment(),
            }
        );

        // All budgets are rejected before either the authenticated binding
        // namespace or the object/blob namespace is touched.
        let status_before_exhaustion = host.show(fixture.agent).unwrap().unwrap();
        let bytes_before_exhaustion = physical_bytes(&directory);
        let mut exhausted = compaction_limits(1);
        exhausted.max_marked_objects = 0;
        assert_eq!(
            host.compact_snapshot(fixture.agent, exhausted),
            Err(SharedAgentHostError::CapacityExhausted)
        );
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap(),
            status_before_exhaustion
        );
        assert_eq!(physical_bytes(&directory), bytes_before_exhaustion);

        let mut complete = false;
        let mut removed = 0;
        for _ in 0..256 {
            let pass = host
                .compact_snapshot(fixture.agent, compaction_limits(1))
                .unwrap();
            removed += pass.bindings_removed
                + pass.objects_removed
                + pass.blobs_removed
                + pass.aliases_removed;
            if pass.complete {
                complete = true;
                break;
            }
        }
        assert!(complete, "bounded checkpoint cleanup did not converge");
        assert!(removed > 0, "checkpoint cleanup retired no physical data");

        // A committed suffix after the retained checkpoint must replay on
        // reopen without the retired Ordered prefix or Raft audit/log rows.
        let second_index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(8, authorized_management(&fixture, 3, 0xb2))
            .unwrap();
        assert_eq!(second_index, 2);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 2 }
        );
        // Reopen before taking the next snapshot: otherwise the final reopen
        // below only exercises an empty suffix at the second checkpoint.
        let suffix_status = host.show(fixture.agent).unwrap().unwrap();
        assert_eq!(
            suffix_status.snapshots,
            SharedAgentSnapshotState::Installed {
                raft_index: 1,
                raft_term: 7,
                certificate: first_certificate.commitment(),
            }
        );
        drop(host);
        host = open_host(&directory, &fixture);
        assert_eq!(host.show(fixture.agent).unwrap().unwrap(), suffix_status);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Idle
        );
        let second_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(
            second_candidate.claim().previous_snapshot(),
            Some(first_certificate.commitment())
        );
        let second_certificate = snapshot_certificate(&second_candidate, &fixture);
        let second_install = host
            .install_snapshot(fixture.agent, &second_certificate)
            .unwrap();
        assert_eq!(second_install.raft_index, 2);
        assert_eq!(
            host.install_snapshot(fixture.agent, &first_certificate),
            Err(SharedAgentHostError::SnapshotStale)
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &second_certificate)
                .unwrap(),
            second_install
        );
        let route = host.physical_route(fixture.agent).unwrap();
        drop(host);

        let reopened = open_host(&directory, &fixture);
        let status = reopened.show(fixture.agent).unwrap().unwrap();
        assert_eq!(status.generation, provisioned.generation);
        assert_eq!(status.replication_id, route.replication_id);
        assert_eq!(status.applied_slots, 2);
        assert_eq!(
            status.snapshots,
            SharedAgentSnapshotState::Installed {
                raft_index: 2,
                raft_term: 8,
                certificate: second_certificate.commitment(),
            }
        );
    }

    #[test]
    #[cfg(feature = "pvm")]
    #[ignore = "requires AGENT_RUNTIME_CANDIDATE_ELF built from current runtime source"]
    fn compiled_shared_genesis_candidate_matches_source_proposal() {
        let elf = fs::read(std::env::var("AGENT_RUNTIME_CANDIDATE_ELF").unwrap()).unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        let runtime = super::super::package_admission::admitted_runtime_program_for_test(
            "shared-genesis-candidate",
            0x74,
            &program,
        );
        let fixture = standard_projection_fixture_with_runtime(0x24, runtime.clone());
        let committee = fixture.provision.replicas();
        let replica = committee.members()[0].replica();
        // CleanTrust does not enable either native-runtime test oracle.
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(CleanTrust {
            authority: fixture.authority.clone(),
            slot: Arc::new(AtomicU64::new(20)),
        });
        let merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(SigningMerge(fixture.replica_keys[0].clone()));
        let directory = TempDirectory::new("compiled_shared_proposal");
        let mut host = SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node: replica.node,
            },
            trust,
            merge,
            Arc::new(AcceptFinality),
        )
        .unwrap();
        let proposal = host
            .prepare_genesis_proposal(
                fixture.provision.proposal().create().clone(),
                committee,
                &fixture.catalog,
            )
            .unwrap();
        assert_eq!(&proposal, fixture.provision.proposal());
        let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("clean Create")
        };
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
            panic!("Create")
        };
        let (clean_proposal, catalog) = host
            .prepare_clean_genesis_proposal(
                (**descriptor).clone(),
                &runtime,
                authority.clone(),
                *observed_slot,
                committee,
            )
            .unwrap();
        assert_eq!(clean_proposal, proposal);
        assert_eq!(catalog, fixture.catalog);
        assert!(scan_generation_namespaces(&host.lease).unwrap().is_empty());
        assert_multi_replica_genesis_proposals(runtime, false);
    }

    #[cfg(feature = "pvm")]
    fn assert_multi_replica_genesis_proposals(
        runtime: super::super::package_admission::AdmittedRuntimePackage,
        native: bool,
    ) {
        let fixture = standard_projection_fixture_with_replicas(
            0x25,
            runtime.clone(),
            &[
                (0x31, ReplicaRole::Voter),
                (0x32, ReplicaRole::Voter),
                (0x33, ReplicaRole::Voter),
                (0x34, ReplicaRole::Observer),
            ],
            true,
        );
        let committee = fixture.provision.replicas();
        let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("clean Create")
        };
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
            panic!("Create")
        };
        for (member, signing_key) in committee.members().iter().zip(&fixture.replica_keys) {
            assert_ne!(
                member.replica().principal,
                PrincipalId::of_public_key(member.ed25519_public_key())
            );
            let directory = TempDirectory::new("multi_replica_proposal");
            let slot = Arc::new(AtomicU64::new(20));
            let trust: Arc<dyn AgentTrustProvider> = if native {
                Arc::new(NativeCleanTrust {
                    authority: fixture.authority.clone(),
                    slot,
                })
            } else {
                Arc::new(CleanTrust {
                    authority: fixture.authority.clone(),
                    slot,
                })
            };
            let mut host = SharedAgentHost::open(
                directory.root(),
                directory.lock(),
                AgentHostScope {
                    space: fixture.space,
                    node: member.replica().node,
                },
                trust,
                Arc::new(SigningMerge(signing_key.clone())),
                Arc::new(AcceptFinality),
            )
            .unwrap();
            let (proposal, catalog) = host
                .prepare_clean_genesis_proposal(
                    (**descriptor).clone(),
                    &runtime,
                    authority.clone(),
                    *observed_slot,
                    committee,
                )
                .unwrap();
            assert_eq!(
                &proposal,
                fixture.provision.proposal(),
                "all voters and observers derive the same proposal"
            );
            assert_eq!(catalog, fixture.catalog);
            let other_members = committee
                .members()
                .iter()
                .filter(|other| other.replica().node != member.replica().node)
                .cloned()
                .collect();
            let absent = AgentReplicaCommittee::new(
                committee.space(),
                committee.agent(),
                committee.profile(),
                other_members,
            )
            .unwrap();
            assert_eq!(
                host.prepare_clean_genesis_proposal(
                    (**descriptor).clone(),
                    &runtime,
                    authority.clone(),
                    *observed_slot,
                    &absent,
                ),
                Err(SharedAgentHostError::ScopeMismatch)
            );
            assert!(host.is_empty());
            assert!(scan_generation_namespaces(&host.lease).unwrap().is_empty());
        }
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_genesis_proposals_agree_across_voters_and_observer() {
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "multi-replica-proposal",
            0x74,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        assert_multi_replica_genesis_proposals(runtime, true);
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_genesis_application_requires_exact_physical_replay() {
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "clean-genesis-observation",
            0x76,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let fixture = standard_projection_fixture_with_runtime(0x25, runtime);
        let directory = TempDirectory::new("clean_genesis_observation");
        let clock = Arc::new(AtomicU64::new(20));
        let mut host = open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&clock));
        let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("clean Create")
        };
        assert!(matches!(
            host.observe_clean_genesis_application(fixture.agent, request, authority),
            Err(SharedAgentHostError::AgentNotFound)
        ));
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let original = host
            .observe_clean_genesis_application(fixture.agent, request, authority)
            .unwrap();
        assert_eq!(original.2, *observed_slot);
        assert_ne!(original.1, crate::agent_sdk::Hash::ZERO);
        let mut substituted = authority.clone();
        substituted.signature[0] ^= 1;
        assert!(matches!(
            host.observe_clean_genesis_application(fixture.agent, request, &substituted),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
            unreachable!()
        };
        let mut other = (**descriptor).clone();
        other.identity.agent = crate::agent_sdk::AgentId([0xee; 32]);
        assert!(matches!(
            host.observe_clean_genesis_application(
                fixture.agent,
                &crate::agent_sdk::ManagementRequest::Create(Box::new(other)),
                authority
            ),
            Err(SharedAgentHostError::ScopeMismatch)
        ));
        drop(host);
        clock.store(200, Ordering::SeqCst);
        let reopened = open_native_clean_host_at_slot(&directory, &fixture, clock);
        assert_eq!(
            reopened
                .observe_clean_genesis_application(fixture.agent, request, authority)
                .unwrap(),
            original
        );
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_install_failure_requires_fresh_slot_and_recovers() {
        check_clean_shared_install_terminal(Some(crate::agent_sdk::ManagementError::AlreadyExists));
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_install_expiry_fence_recovers_exact_observation() {
        check_clean_shared_install_terminal(Some(
            crate::agent_sdk::ManagementError::ExpiredBeforeApplication,
        ));
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_applied_install_retry_after_expiry_preserves_success() {
        check_clean_shared_install_terminal(None);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_follower_derives_only_exact_committed_merge_seal() {
        use super::super::shared_raft::AgentRaftCommand;
        let fixture = standard_projection_fixture(0x28);
        let leader_directory = TempDirectory::new("management_seal_proposer");
        let clock = Arc::new(AtomicU64::new(20));
        let mut proposer =
            open_native_clean_host_at_slot(&leader_directory, &fixture, clock.clone());
        proposer
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        let ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(descriptor),
            ..
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("Create");
        };
        let package = super::super::package_admission::admitted_standard_actor_for_test(
            "follower-worker",
            crate::agent_sdk::StateLane::Linear,
            0x78,
        );
        let request = clean_install_request(descriptor.identity.agent, &package);
        let receipt = clean_management_receipt(descriptor, &request, 2, &key(0x41));
        let prepared = proposer
            .prepare_clean_management(
                fixture.agent,
                request,
                receipt,
                SdkManagementArtifacts::Actor(&package),
            )
            .unwrap();
        let input = prepared.input().unwrap();
        let commands = prepared.into_commands();
        assert!(!commands.is_empty());
        for alteration in 0..3 {
            let directory = TempDirectory::new("management_seal_follower");
            let mut follower = open_native_clean_host_at_slot(&directory, &fixture, clock.clone());
            follower
                .provision(
                    fixture.provision.clone(),
                    fixture.catalog.clone(),
                    fixture.committee_authority,
                )
                .unwrap();
            let before = follower.journal_position(fixture.agent).unwrap();
            for (position, payload) in commands.iter().enumerate() {
                let mut command = AgentRaftCommand::decode(payload).unwrap();
                if position + 1 == commands.len() {
                    let AgentRaftCommand::Ordered { entry, .. } = &mut command else {
                        panic!("Ordered tail");
                    };
                    assert!(entry.merge_seal.is_some());
                    match alteration {
                        1 => {
                            entry.merge_seal =
                                Some(super::super::journal::MergeSealId::new([0xfe; 32]))
                        }
                        2 => {
                            entry.merge_frontier =
                                super::super::journal::MergeFrontierId::new([0xfd; 32])
                        }
                        _ => {}
                    }
                }
                let index = follower.agents[&fixture.agent]
                    .driver
                    .ledger()
                    .append_committed_for_test(
                        8,
                        &EntryKind::Data {
                            payload: command.encode(),
                        },
                    )
                    .unwrap();
                let outcome = follower.apply_next(fixture.agent);
                if alteration != 0 && position + 1 == commands.len() {
                    assert_eq!(outcome, Err(SharedAgentHostError::CorruptResidue));
                    assert_eq!(follower.journal_position(fixture.agent).unwrap(), before);
                } else {
                    assert_eq!(outcome.unwrap(), SharedAgentApplyOutcome::Applied { index });
                }
            }
            if alteration == 0 {
                assert!(matches!(
                    follower
                        .take_clean_ordered_result(fixture.agent, input)
                        .unwrap(),
                    crate::agent_sdk::RuntimeOutcome::Management(Ok(_))
                ));
                assert_eq!(
                    follower
                        .journal_position(fixture.agent)
                        .unwrap()
                        .ordered_index,
                    before.ordered_index + 1
                );
            }
        }
    }

    #[cfg(feature = "pvm")]
    fn check_clean_shared_install_terminal(error: Option<crate::agent_sdk::ManagementError>) {
        use super::super::shared_journal_driver::PreparedCleanManagement;
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "shared-install-terminal",
            0x77,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let fixture = standard_projection_fixture_with_runtime(0x27, runtime);
        let directory = TempDirectory::new("shared_install_terminal");
        let clock = Arc::new(AtomicU64::new(20));
        let mut host = open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&clock));
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(descriptor),
            ..
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("Create");
        };
        let package = super::super::package_admission::admitted_standard_actor_for_test(
            "terminal-worker",
            crate::agent_sdk::StateLane::Linear,
            0x78,
        );
        let request = clean_install_request(descriptor.identity.agent, &package);
        let receipt = clean_management_receipt(descriptor, &request, 2, &key(0x41));
        let first_receipt = receipt.clone();
        let commit = |host: &mut SharedAgentHost, prepared: PreparedCleanManagement| {
            let input = prepared
                .input()
                .expect("terminal must have an Ordered input");
            for payload in prepared.into_commands() {
                let index = host.agents[&fixture.agent]
                    .driver
                    .ledger()
                    .append_committed_for_test(8, &EntryKind::Data { payload })
                    .unwrap();
                assert_eq!(
                    host.apply_next(fixture.agent).unwrap(),
                    SharedAgentApplyOutcome::Applied { index }
                );
            }
            host.take_clean_ordered_result(fixture.agent, input)
                .unwrap()
        };
        let first = host
            .prepare_clean_management(
                fixture.agent,
                request.clone(),
                receipt,
                SdkManagementArtifacts::Actor(&package),
            )
            .unwrap();
        let applied = commit(&mut host, first);
        assert!(matches!(
            applied,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(_))
        ));
        let Some(error) = error else {
            let observation = host
                .observe_durable_install(fixture.agent, &request, &first_receipt)
                .unwrap();
            let before = host.journal_position(fixture.agent).unwrap();
            drop(host);
            clock.store(first_receipt.selector.expires_at + 1, Ordering::SeqCst);
            let mut reopened = open_native_clean_host_at_slot(&directory, &fixture, clock);
            assert_eq!(
                reopened
                    .observe_durable_install(fixture.agent, &request, &first_receipt)
                    .unwrap(),
                observation
            );
            let retry = reopened
                .prepare_clean_management(
                    fixture.agent,
                    request,
                    first_receipt,
                    SdkManagementArtifacts::Actor(&package),
                )
                .unwrap();
            assert_eq!(retry.retained(), Some(&applied));
            assert!(retry.into_commands().is_empty());
            assert_eq!(reopened.journal_position(fixture.agent).unwrap(), before);
            return;
        };
        let mut rejected = request.clone();
        let crate::agent_sdk::ManagementRequest::Install(install) = &mut rejected else {
            unreachable!();
        };
        install.installation_id = crate::agent_sdk::InstallationId([0x93; 32]);
        install.registry_reservation = crate::agent_sdk::Hash([0x94; 32]);
        let mut receipt = clean_management_receipt(descriptor, &rejected, 3, &key(0x41));
        receipt.selector.acknowledged_through = 2;
        receipt.signature = key(0x41).sign(&receipt.signing_bytes()).to_bytes();
        let before = host.journal_position(fixture.agent).unwrap();
        let denied = host
            .prepare_clean_management(
                fixture.agent,
                rejected.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Actor(&package),
            )
            .unwrap();
        assert_eq!(
            denied.denied(),
            Some(&crate::agent_sdk::RuntimeOutcome::Management(Err(
                crate::agent_sdk::ManagementError::AuthoritySequenceConflict,
            )))
        );
        assert!(denied.into_commands().is_empty());
        assert_eq!(host.journal_position(fixture.agent).unwrap(), before);
        assert!(
            host.observe_durable_install(fixture.agent, &rejected, &receipt)
                .is_err()
        );
        // A distinct signed mutation needs a strictly newer logical slot.
        // Once admitted, the semantic rejection is recorded durably.
        let observed_slot = if error == crate::agent_sdk::ManagementError::ExpiredBeforeApplication
        {
            receipt.selector.expires_at + 1
        } else {
            21
        };
        clock.store(observed_slot, Ordering::SeqCst);
        let expected = crate::agent_sdk::RuntimeOutcome::Management(Err(error));
        let prepared = host
            .prepare_clean_management(
                fixture.agent,
                rejected.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Actor(&package),
            )
            .unwrap();
        assert_eq!(commit(&mut host, prepared), expected);
        let after = host.journal_position(fixture.agent).unwrap();
        assert_eq!(after.ordered_index, before.ordered_index + 1);
        let evidence = host
            .management_evidence_for_test(fixture.agent)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.authority, receipt.commitment());
        assert_eq!(evidence.request, rejected.replay_commitment());
        assert_eq!(evidence.result, Err(error));
        let observation = host
            .observe_durable_install(fixture.agent, &rejected, &receipt)
            .unwrap();
        assert_eq!(observation.result(), &evidence.result);
        assert_eq!(observation.receipt(), &receipt);
        assert_eq!(observation.applied_at(), observed_slot);
        assert!(
            host.observe_durable_install(fixture.agent, &request, &first_receipt)
                .is_err(),
            "later management must not lend its evidence to the previous Install"
        );
        let mut substituted = receipt.clone();
        substituted.signature[0] ^= 1;
        assert!(
            host.observe_durable_install(fixture.agent, &rejected, &substituted)
                .is_err()
        );
        drop(host);
        clock.store(receipt.selector.expires_at + 2, Ordering::SeqCst);
        let mut reopened = open_native_clean_host_at_slot(&directory, &fixture, clock);
        assert_eq!(
            reopened
                .observe_durable_install(fixture.agent, &rejected, &receipt)
                .unwrap(),
            observation
        );
        assert_eq!(
            reopened
                .management_evidence_for_test(fixture.agent)
                .unwrap(),
            Some(evidence)
        );
        let retry = reopened
            .prepare_clean_management(
                fixture.agent,
                rejected,
                receipt.clone(),
                SdkManagementArtifacts::Actor(&package),
            )
            .unwrap();
        assert_eq!(retry.retained(), Some(&expected));
        assert!(retry.into_commands().is_empty());
        assert_eq!(reopened.journal_position(fixture.agent).unwrap(), after);
    }

    #[test]
    #[cfg(feature = "pvm")]
    fn clean_shared_proposal_binds_package_receipt_and_retained_slot() {
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "clean-proposal-boundary",
            0x74,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let fixture = standard_projection_fixture_with_runtime(0x24, runtime.clone());
        let directory = TempDirectory::new("clean_proposal_boundary");
        let clock = Arc::new(AtomicU64::new(20));
        let mut host = open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&clock));
        let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &fixture.provision.proposal().create().operation
        else {
            panic!("clean Create")
        };
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = request else {
            panic!("Create")
        };
        let prepare = |host: &mut SharedAgentHost,
                       descriptor,
                       runtime: &super::super::package_admission::AdmittedRuntimePackage,
                       slot| {
            host.prepare_clean_genesis_proposal(
                descriptor,
                runtime,
                authority.clone(),
                slot,
                fixture.provision.replicas(),
            )
        };
        let (proposal, catalog) =
            prepare(&mut host, (**descriptor).clone(), &runtime, *observed_slot).unwrap();
        assert_eq!(&proposal, fixture.provision.proposal());
        assert_eq!(catalog, fixture.catalog);
        clock.store(21, Ordering::SeqCst);
        assert_eq!(
            prepare(&mut host, (**descriptor).clone(), &runtime, *observed_slot)
                .unwrap()
                .0,
            proposal
        );
        assert!(prepare(&mut host, (**descriptor).clone(), &runtime, 22).is_err());
        let other = super::super::package_admission::admitted_scripted_runtime_for_test(
            "wrong-proposal-package",
            0x75,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        assert!(prepare(&mut host, (**descriptor).clone(), &other, *observed_slot).is_err());
        let mut forged = authority.clone();
        forged.signature[0] ^= 1;
        assert!(
            host.prepare_clean_genesis_proposal(
                (**descriptor).clone(),
                &runtime,
                forged,
                *observed_slot,
                fixture.provision.replicas(),
            )
            .is_err()
        );
        // Ordinary multi-replica preparation must not relax root bootstrap's
        // independent one-voter restriction.
        assert!(
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_system_genesis_input(
                (**descriptor).clone(),
                &runtime,
                authority.clone(),
                *observed_slot,
                &host.trust,
                &host.merge,
            )
            .is_ok()
        );
        let mut expanded = (**descriptor).clone();
        let mut extra = expanded.replicas[0].clone();
        extra.node = crate::agent_sdk::NodeId([0xf1; 32]);
        extra.principal = crate::agent_sdk::PrincipalId([0xf2; 32]);
        expanded.replicas.push(extra);
        expanded.replicas.sort_by_key(|replica| replica.node);
        assert!(
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_shared_system_genesis_input(
                expanded,
                &runtime,
                authority.clone(),
                *observed_slot,
                &host.trust,
                &host.merge,
            )
            .is_err()
        );
        let mut changed = (**descriptor).clone();
        changed.identity.owner = crate::agent_sdk::PrincipalId([0xf1; 32]);
        assert!(prepare(&mut host, changed, &runtime, *observed_slot).is_err());
        assert!(host.is_empty());
        assert!(scan_generation_namespaces(&host.lease).unwrap().is_empty());
    }

    #[test]
    #[cfg(all(feature = "network", target_os = "linux"))]
    fn clean_genesis_absence_rejects_staged_physical_namespace() {
        let directory = TempDirectory::new("genesis_absence");
        let fixture = fixture(0x26);
        let mut host = open_host(&directory, &fixture);
        assert!(host.clean_genesis_is_absent(fixture.agent).unwrap());
        host.deferred_generations
            .insert(fixture.agent, GenerationFiles::default());
        assert!(!host.clean_genesis_is_absent(fixture.agent).unwrap());
        host.deferred_generations.clear();
        // Even incomplete/corrupt physical intent bytes are not absence.
        install_host_record(&host.intent_path(fixture.agent), &[0xff]).unwrap();
        assert!(!host.clean_genesis_is_absent(fixture.agent).unwrap());
        assert!(host.is_empty());
    }

    #[test]
    #[cfg(all(feature = "network", feature = "pvm", target_os = "linux"))]
    fn live_genesis_capacity_counts_serving_and_unserved_generations() {
        let directory = TempDirectory::new("live_genesis_capacity");
        let fixture = fixture(0x25);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let locator = |agent| super::super::genesis::AgentGenesisLocator {
            space: fixture.space,
            agent,
        };
        let fresh = AgentId([0xf0; 32]);
        assert_eq!(host.preflight_live_genesis_capacity(locator(fresh)), Ok(()));
        let before = physical_bytes(&directory);
        // Synthetic occupancy tests the exact boundary without materializing
        // thousands of journals. One real serving generation counts too.
        for index in 1..MAX_SHARED_HOST_AGENTS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
            host.deferred_generations
                .insert(AgentId(bytes), GenerationFiles::default());
        }
        assert_eq!(
            host.preflight_live_genesis_capacity(locator(fresh)),
            Err(SharedAgentHostError::CapacityExhausted)
        );
        assert_eq!(
            host.preflight_live_genesis_capacity(locator(fixture.agent)),
            Ok(())
        );
        let staged = *host.deferred_generations.keys().next().unwrap();
        assert_eq!(
            host.preflight_live_genesis_capacity(locator(staged)),
            Ok(())
        );
        let mut foreign = locator(fresh);
        foreign.space = SpaceId([0xf1; 32]);
        assert_eq!(
            host.preflight_live_genesis_capacity(foreign),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        host.deferred_open = true;
        assert_eq!(
            host.preflight_live_genesis_capacity(locator(staged)),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(physical_bytes(&directory), before);
    }

    #[test]
    fn host_genesis_preparation_checks_scope_without_granting_finality() {
        struct RejectFinality;
        impl AgentGenesisFinalityVerifier for RejectFinality {
            fn verify_finalized(
                &self,
                _: &AgentGenesisProvision,
            ) -> Result<(), AgentGenesisFinalityError> {
                Err(AgentGenesisFinalityError::NotFinalized)
            }
        }
        let directory = TempDirectory::new("proposal_without_finality");
        let fixture = fixture(0x24);
        let mut host = open_host(&directory, &fixture);
        host.finality = Arc::new(RejectFinality);
        let committee = fixture.provision.replicas();
        let create = fixture.provision.proposal().create();
        assert!(scan_generation_namespaces(&host.lease).unwrap().is_empty());
        for _ in 0..2 {
            assert_eq!(
                host.prepare_genesis_proposal(create.clone(), committee, &fixture.catalog)
                    .unwrap(),
                *fixture.provision.proposal()
            );
        }
        let foreign = AgentReplicaCommittee::new(
            SpaceId([0xf1; 32]),
            committee.agent(),
            committee.profile(),
            committee.members().to_vec(),
        )
        .unwrap();
        assert_eq!(
            host.prepare_genesis_proposal(create.clone(), &foreign, &fixture.catalog),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        assert_eq!(
            host.prepare_genesis_proposal(create.clone(), committee, &[]),
            Err(SharedAgentHostError::InvalidProvision)
        );
        assert_eq!(
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority
            ),
            Err(SharedAgentHostError::Finality(
                AgentGenesisFinalityError::NotFinalized
            ))
        );
        assert!(host.is_empty());
        assert!(scan_generation_namespaces(&host.lease).unwrap().is_empty());
    }

    #[test]
    fn deferred_generations_keep_lease_and_require_finality_before_exposure() {
        struct RejectFinality;
        impl AgentGenesisFinalityVerifier for RejectFinality {
            fn verify_finalized(
                &self,
                _: &AgentGenesisProvision,
            ) -> Result<(), AgentGenesisFinalityError> {
                Err(AgentGenesisFinalityError::NotFinalized)
            }
        }
        let directory = TempDirectory::new("deferred_generation_finality");
        let fixture = fixture(0x24);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let scope = host.scope();
        let trust = host.trust.clone();
        let merge = host.merge.clone();
        drop(host);
        let lease = AgentHostRootLease::acquire(directory.root(), directory.lock(), scope).unwrap();
        // Exercise the staging mechanism without inventing a root fixture.
        // The production entrypoint separately requires validated root pins.
        let mut host = SharedAgentHost::open_with_lease_and_root_mode(
            lease,
            trust,
            merge,
            Arc::new(RejectFinality),
            None,
            Some(AgentId([0xf1; 32])),
            SharedExecutionSelection::ImageOnly,
        )
        .unwrap();
        assert!(host.list().unwrap().is_empty());
        assert!(host.show(fixture.agent).unwrap().is_none());
        assert!(host.route(fixture.agent).is_err());
        assert!(AgentHostRootLease::acquire(directory.root(), directory.lock(), scope).is_err());
        assert!(
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority
            )
            .is_err()
        );
        assert!(
            host.reopen_deferred_generations(Arc::new(RejectFinality))
                .is_err()
        );
        assert!(host.agents.is_empty());
        assert_eq!(host.deferred_generations.len(), 1);
        let files = scan_generation_namespaces(&host.lease).unwrap()[&fixture.agent];
        assert!(matches!(
            host.open_deferred_generation(fixture.agent, files, &RejectFinality),
            Err(SharedAgentHostError::Finality(
                AgentGenesisFinalityError::NotFinalized
            ))
        ));
        let staged = host
            .open_deferred_generation(fixture.agent, files, &AcceptFinality)
            .unwrap();
        assert!(host.has_deferred_open());
        assert!(host.agents.is_empty());
        assert_eq!(host.deferred_generations.len(), 1);
        assert!(host.show(fixture.agent).unwrap().is_none());
        assert!(host.route(fixture.agent).is_err());
        assert!(AgentHostRootLease::acquire(directory.root(), directory.lock(), scope).is_err());
        drop(staged);
        host.reopen_deferred_generations(Arc::new(AcceptFinality))
            .unwrap();
        assert!(host.deferred_generations.is_empty());
        assert!(
            host.reopen_deferred_generations(Arc::new(RejectFinality))
                .is_err()
        );
        assert!(host.show(fixture.agent).unwrap().is_some());
        drop(host);
        assert_eq!(open_host(&directory, &fixture).len(), 1);
    }

    #[test]
    fn shared_genesis_candidate_derives_proposal_without_provisioning() {
        let directory = TempDirectory::new("shared_candidate_before_finality");
        let fixture = fixture(0x24);
        let host = open_host(&directory, &fixture);
        let committee = fixture.provision.replicas();
        let replica = committee
            .member_by_node(host.scope().node)
            .unwrap()
            .replica();
        let prepare = |replica, catalog: &[RuntimeBlob]| {
            LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_shared_genesis_candidate(
                fixture.provision.proposal().create().clone(),
                replica,
                committee,
                catalog,
                Arc::clone(&host.trust),
                Arc::clone(&host.merge),
            )
        };
        let candidate = prepare(replica, &fixture.catalog).unwrap();
        assert_eq!(
            &candidate.ordinary_proposal().unwrap(),
            fixture.provision.proposal()
        );
        assert!(
            host.agents.is_empty(),
            "proposal preparation must not provision a generation"
        );
        let mut wrong_replica = replica;
        wrong_replica.principal = PrincipalId([0xf1; 32]);
        assert!(prepare(wrong_replica, &fixture.catalog).is_err());
        let mut corrupt_catalog = fixture.catalog.clone();
        corrupt_catalog[0].bytes.push(0);
        assert!(prepare(replica, &corrupt_catalog).is_err());
        assert!(prepare(replica, &[]).is_err());
        assert!(host.agents.is_empty());
    }

    #[test]
    fn leader_noop_still_rejects_missing_earlier_physical_history() {
        let directory = TempDirectory::new("noop_missing_physical_history");
        let fixture = fixture(0x24);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let before = host.journal_position(fixture.agent).unwrap();
        for index in 1..=2 {
            assert_eq!(
                host.agents[&fixture.agent]
                    .driver
                    .ledger()
                    .append_committed_for_test(
                        7,
                        &EntryKind::Data {
                            payload: Vec::new()
                        }
                    )
                    .unwrap(),
                index
            );
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index }
            );
        }
        let database = host.raft_database(fixture.agent).unwrap();
        let transaction = database.begin_write().unwrap();
        assert!(
            transaction
                .open_table(crate::raft::RAFT_LOG)
                .unwrap()
                .remove(1)
                .unwrap()
                .is_some()
        );
        transaction.commit().unwrap();
        assert_eq!(
            host.agents[&fixture.agent]
                .driver
                .ledger()
                .append_committed_for_test(
                    7,
                    &EntryKind::Data {
                        payload: Vec::new()
                    }
                )
                .unwrap(),
            3
        );
        // Skipping committee-history reconstruction for no-ops must not skip
        // the full recovery audit of earlier durable physical evidence.
        assert_eq!(
            host.apply_next(fixture.agent),
            Err(SharedAgentHostError::CorruptResidue)
        );
        assert_eq!(host.journal_position(fixture.agent).unwrap(), before);
    }

    #[test]
    fn authenticated_snapshots_advance_across_repeated_leader_noops_without_gc() {
        let directory = TempDirectory::new("snapshot_repeated_leader_noops");
        let fixture = fixture(0x24);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let ordered_index = host
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(7, authorized_management(&fixture, 2, 0xc7))
            .unwrap();
        assert_eq!(ordered_index, 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: 1 },
        );
        let first_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        let logical = first_candidate.claim().ordered().ordered();
        let first = snapshot_certificate(&first_candidate, &fixture);
        host.install_snapshot(fixture.agent, &first).unwrap();

        for (term, expected_index) in [(8, 2), (9, 3)] {
            let index = host.agents[&fixture.agent]
                .driver
                .ledger()
                .append_committed_for_test(
                    term,
                    &EntryKind::Data {
                        payload: Vec::new(),
                    },
                )
                .unwrap();
            assert_eq!(index, expected_index);
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied {
                    index: expected_index,
                },
            );
            let candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
            assert_eq!(candidate.claim().raft_index(), expected_index);
            assert_eq!(candidate.claim().raft_term(), term);
            assert_eq!(candidate.claim().ordered().ordered(), logical);
            let certificate = snapshot_certificate(&candidate, &fixture);
            host.install_snapshot(fixture.agent, &certificate).unwrap();

            // Reopen after every synthetic physical foundation. The compacted
            // boundary must authenticate as canonical empty Data, while the
            // logical Ordered projection remains unchanged and the original
            // binding is deliberately still present (no GC between passes).
            drop(host);
            host = open_host(&directory, &fixture);
            let installed = host.agents[&fixture.agent]
                .driver
                .current_snapshot()
                .unwrap()
                .unwrap();
            assert_eq!(installed.claim.raft_index(), expected_index);
            assert_eq!(installed.claim.ordered().ordered(), logical);
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Idle,
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn terminal_projection_invoke_at_authenticated_boundary_reopens_without_replacement() {
        check_terminal_projection_at_authenticated_boundary(false);
    }

    #[cfg(all(feature = "pvm", feature = "network"))]
    #[test]
    fn singleton_image_routes_exact_snapshot_retained_projection() {
        check_terminal_projection_at_authenticated_boundary(true);
    }

    #[cfg(feature = "pvm")]
    fn check_terminal_projection_at_authenticated_boundary(routed: bool) {
        use super::super::shared_journal_driver::{
            CleanInvocationReplayRequest, PreparedCleanOrdered,
        };
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};

        let directory = TempDirectory::new("projection_invoke_boundary");
        let fixture = standard_projection_fixture(0x25);
        let mut host = open_native_clean_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();

        let actor_package = super::super::package_admission::admitted_standard_query_actor_for_test(
            "projection-authority",
            crate::agent_sdk::StateLane::Linear,
            0x75,
        );
        let install = clean_install_request(fixture.descriptor.identity.agent, &actor_package);
        let receipt =
            clean_management_receipt(&fixture.descriptor, &install, 2, &fixture.authority_key);
        let prepared_install = host
            .prepare_clean_management(
                fixture.agent,
                install.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Actor(&actor_package),
            )
            .unwrap();
        let install_input = prepared_install
            .input()
            .unwrap_or_else(|| panic!("fresh actor install: {prepared_install:?}"));
        let mut install_raft_index = 0;
        for payload in prepared_install.into_commands() {
            install_raft_index = host.agents[&fixture.agent]
                .driver
                .ledger()
                .append_committed_for_test(6, &EntryKind::Data { payload })
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied {
                    index: install_raft_index,
                },
            );
        }
        let installed = host
            .take_clean_ordered_result(fixture.agent, install_input)
            .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Installed(entry),
        )) = installed
        else {
            panic!("physical Query actor install did not complete")
        };
        let install_observation = host
            .observe_durable_install(fixture.agent, &install, &receipt)
            .unwrap();
        let material = host
            .supervisor_invocation_material(fixture.agent, entry.actor)
            .unwrap();
        assert_eq!(material.actor.entry, entry);
        let install_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(install_candidate.claim().raft_index(), install_raft_index);
        let install_certificate = snapshot_certificate(&install_candidate, &fixture);
        host.install_snapshot(fixture.agent, &install_certificate)
            .unwrap();

        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("read").encode());
        let mut availability = vec![
            material.program.clone(),
            material.schema.clone(),
            material.policies.clone(),
        ];
        availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        let work = crate::agent_sdk::InvocationWork {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.descriptor.identity.runtime_deployment,
            invocation: crate::agent_sdk::InvocationId([0xd1; 32]),
            actor: entry.actor,
            incarnation: material.actor.incarnation,
            deployment: entry.deployment,
            program: entry.program,
            mode: crate::agent_sdk::MethodMode::Query,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message,
            installation_data: entry.installation_data.clone(),
            availability,
            gas: 10_000_000,
            recovery_only: false,
        };
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        assert_eq!(
            host.projection_admission_requirement(fixture.agent, &work, &authorization, false,)
                .unwrap(),
            Some(2),
        );
        let prepared = host
            .prepare_clean_ordered(fixture.agent, work.clone(), authorization.clone())
            .unwrap();
        let invoke_input = prepared.input();
        let payload = prepared.into_payload().expect("fresh Invoke proposal");
        let invoke_index = host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(7, &EntryKind::Data { payload })
            .unwrap();
        assert_eq!(invoke_index, install_raft_index + 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied {
                index: invoke_index,
            },
        );
        assert_eq!(
            host.projection_admission_requirement(fixture.agent, &work, &authorization, true,)
                .unwrap(),
            Some(1),
        );

        assert_eq!(
            host.observe_durable_install(fixture.agent, &install, &receipt)
                .unwrap(),
            install_observation,
            "later Invoke must not change the identity of the retained Install"
        );

        let candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(candidate.claim().raft_index(), invoke_index);
        let certificate = snapshot_certificate(&candidate, &fixture);
        host.install_snapshot(fixture.agent, &certificate).unwrap();
        drop(host);

        let mut host = open_native_clean_host(&directory, &fixture);
        assert_eq!(
            host.observe_durable_install(fixture.agent, &install, &receipt)
                .unwrap(),
            install_observation
        );
        let no_op_index = host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                8,
                &EntryKind::Data {
                    payload: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(no_op_index, invoke_index + 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: no_op_index },
        );
        let no_op_candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(no_op_candidate.claim().raft_index(), no_op_index);
        assert_eq!(
            no_op_candidate.claim().ordered().ordered().index,
            candidate.claim().ordered().ordered().index,
        );
        let no_op_certificate = snapshot_certificate(&no_op_candidate, &fixture);
        host.install_snapshot(fixture.agent, &no_op_certificate)
            .unwrap();
        drop(host);

        let mut host = open_native_clean_host(&directory, &fixture);
        assert_eq!(
            host.projection_admission_requirement(fixture.agent, &work, &authorization, true,)
                .unwrap(),
            Some(1),
        );
        let retry = host.agents[&fixture.agent]
            .driver
            .prepare_reserved_projection_operation(
                CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
                true,
            )
            .unwrap();
        assert_eq!(retry.input(), invoke_input);
        let _retained_outcome = retry.retained().unwrap().clone();
        assert!(matches!(
            retry,
            PreparedCleanOrdered::Retained {
                outcome: crate::agent_sdk::RuntimeOutcome::Completed(Ok(
                    crate::agent_sdk::InvocationReply {
                        status: crate::agent_sdk::InvocationStatus::Done,
                        ..
                    }
                )),
                ..
            }
        ));

        // The same work under a different valid preflight cannot borrow the
        // boundary result solely by reusing its invocation identity.
        let divergent_authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 19),
        );
        assert!(divergent_authorization.matches_work(&work));
        let before_divergent = host.journal_position(fixture.agent).unwrap();
        assert!(!host
            .retained_terminal_projection_invoke(
                fixture.agent,
                &work,
                &divergent_authorization,
            )
            .unwrap());
        assert_eq!(
            host.journal_position(fixture.agent).unwrap(),
            before_divergent
        );

        // A different valid PAP work item is independently rejected without
        // mutating the journal while recovery compares exact work and auth.
        let mut divergent_work = work.clone();
        divergent_work.invocation = crate::agent_sdk::InvocationId([0xe1; 32]);
        let divergent_authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&divergent_work, 20),
        );
        assert!(
            !host
                .retained_terminal_projection_invoke(
                    fixture.agent,
                    &divergent_work,
                    &divergent_authorization,
                )
                .unwrap()
        );
        assert_eq!(
            host.journal_position(fixture.agent).unwrap(),
            before_divergent
        );

        if routed {
            #[cfg(feature = "network")]
            {
                assert!(
                    host.available_ordered_claim(fixture.agent, invoke_input)
                        .is_err(),
                    "the compacted slot must not masquerade as a retained exact anchor"
                );
                assert!(!host.uses_external_state(fixture.agent).unwrap());
                let host = Arc::new(Mutex::new(host));
                let network = live_network(0x31, Vec::new());
                let signer = SigningMerge(fixture.replica_keys[0].clone());
                let attachment =
                    crate::network::SharedAgentNetworkHost::attach_recovering_projection(
                        Arc::clone(&host),
                        Arc::clone(&network),
                        fixture.agent,
                        &work,
                        &authorization,
                        fixture.provision.replicas(),
                        &signer,
                    )
                    .unwrap();
                let identity = super::super::supervisor::AgentRouteIdentity::new(
                    super::super::supervisor::AgentRouteKey::new(
                        work.space, work.agent, work.actor,
                    )
                    .unwrap(),
                    work.incarnation,
                    work.runtime_deployment,
                    work.deployment,
                    work.program,
                    crate::agent_sdk::AgentProfile::Shared,
                )
                .unwrap();
                let before = host
                    .lock()
                    .unwrap()
                    .journal_position(fixture.agent)
                    .unwrap();
                assert_eq!(
                    attachment
                        .supervisor_invoke_terminal_reserved(
                            identity,
                            work.clone(),
                            authorization.clone(),
                        )
                        .unwrap(),
                    _retained_outcome
                );
                assert_eq!(
                    host.lock()
                        .unwrap()
                        .journal_position(fixture.agent)
                        .unwrap(),
                    before,
                    "serving the snapshot-retained result must not propose another Invoke"
                );
                drop(attachment);
                drop(host);
                join_live_network(network);
                return;
            }
            #[cfg(not(feature = "network"))]
            panic!("routed fixture requires network");
        }

        let acknowledgement = host.agents[&fixture.agent]
            .driver
            .prepare_reserved_projection_operation(
                CleanInvocationReplayRequest::Acknowledge {
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
                false,
            )
            .unwrap();
        let acknowledgement_payload = acknowledgement
            .into_payload()
            .expect("exact Ack must be the only successor");
        let acknowledgement_index = host.agents[&fixture.agent]
            .driver
            .ledger()
            .append_committed_for_test(
                9,
                &EntryKind::Data {
                    payload: acknowledgement_payload,
                },
            )
            .unwrap();
        assert_eq!(acknowledgement_index, no_op_index + 1);
        assert_eq!(
            host.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Applied {
                index: acknowledgement_index,
            },
        );
        assert!(
            host.retained_positive_clean_acknowledgement(fixture.agent, &work, &authorization,)
                .unwrap()
        );
        assert_eq!(
            host.journal_position(fixture.agent).unwrap().ordered_index,
            3
        );
        drop(host);

        let mut host = open_native_clean_host(&directory, &fixture);
        assert_eq!(
            host.observe_durable_install(fixture.agent, &install, &receipt)
                .unwrap(),
            install_observation
        );
        assert!(
            host.retained_positive_clean_acknowledgement(fixture.agent, &work, &authorization,)
                .unwrap()
        );
        assert_eq!(
            host.projection_admission_requirement(fixture.agent, &work, &authorization, true,)
                .unwrap(),
            Some(0),
        );
    }

    #[cfg(all(feature = "pvm", feature = "network"))]
    #[test]
    fn system_attach_checkpoints_and_drains_raw_tail_before_publishing_route() {
        let directory = TempDirectory::new("system_raw_tail_promotion_barrier");
        let fixture = standard_projection_fixture(0x26);
        let logical_slot = Arc::new(AtomicU64::new(20));
        let mut host =
            open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&logical_slot));
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();

        // Establish one real actor and compact its installation so the full
        // physical evidence budget below is post-snapshot capacity.
        let actor_package = super::super::package_admission::admitted_standard_query_actor_for_test(
            "raw-tail-worker",
            crate::agent_sdk::StateLane::Linear,
            0x76,
        );
        let install = clean_install_request(fixture.descriptor.identity.agent, &actor_package);
        let receipt =
            clean_management_receipt(&fixture.descriptor, &install, 2, &fixture.authority_key);
        let prepared_install = host
            .prepare_clean_management(
                fixture.agent,
                install,
                receipt,
                SdkManagementArtifacts::Actor(&actor_package),
            )
            .unwrap();
        let install_input = prepared_install
            .input()
            .unwrap_or_else(|| panic!("fresh actor install: {prepared_install:?}"));
        let mut install_raft_index = 0;
        for payload in prepared_install.into_commands() {
            install_raft_index = host.agents[&fixture.agent]
                .driver
                .ledger()
                .append_committed_for_test(6, &EntryKind::Data { payload })
                .unwrap();
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied {
                    index: install_raft_index,
                },
            );
        }
        let installed = host
            .take_clean_ordered_result(fixture.agent, install_input)
            .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Installed(entry),
        )) = installed
        else {
            panic!("physical Query actor install did not complete")
        };
        let candidate = host.request_snapshot_compaction(fixture.agent).unwrap();
        assert_eq!(candidate.claim().raft_index(), install_raft_index);
        let certificate = snapshot_certificate(&candidate, &fixture);
        host.install_snapshot(fixture.agent, &certificate).unwrap();
        let logical_before_tail = host.journal_position(fixture.agent).unwrap();

        // Fill every post-snapshot physical slot except one with canonical
        // leader-noop evidence. Appending in one transaction keeps this exact
        // 4095-entry capacity fixture practical; ordinary apply/audit still
        // validates each durable row independently.
        let database = host.raft_database(fixture.agent).unwrap();
        let empty = super::super::shared_raft::encode_agent_raft_entry_kind(&EntryKind::Data {
            payload: Vec::new(),
        })
        .unwrap();
        let committed_tail = {
            let mut log = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap();
            let transaction = database.begin_write().unwrap();
            let mut index = install_raft_index;
            for _ in 0..super::super::shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES - 1 {
                index = log.append_in_txn(&transaction, 7, &empty).unwrap();
            }
            let mut meta =
                crate::raft::RaftMeta::load_from_write_transaction(&transaction).unwrap();
            meta.current_term = 7;
            meta.commit_index = index;
            meta.write_worker_fields_in_txn(&transaction).unwrap();
            transaction.commit().unwrap();
            index
        };
        for expected in install_raft_index + 1..=committed_tail {
            assert_eq!(
                host.apply_next(fixture.agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index: expected },
            );
        }
        let full = host.show(fixture.agent).unwrap().unwrap();
        assert_eq!(full.applied_slots, committed_tail);
        assert_eq!(full.remaining_slots, 1);
        assert_eq!(
            host.journal_position(fixture.agent).unwrap(),
            logical_before_tail
        );

        // Prepare a valid Ordered mutation, but persist only its raw old-term
        // Raft row. Metadata deliberately remains committed/applied at N.
        logical_slot.store(21, Ordering::SeqCst);
        let suspend = crate::agent_sdk::ManagementRequest::Suspend {
            actor: entry.actor,
            expected_deployment: entry.deployment,
        };
        let suspend_receipt =
            clean_management_receipt(&fixture.descriptor, &suspend, 3, &fixture.authority_key);
        let prepared_suspend = host
            .prepare_clean_management(
                fixture.agent,
                suspend,
                suspend_receipt,
                SdkManagementArtifacts::None,
            )
            .unwrap();
        let suspend_input = prepared_suspend.input().expect("fresh Suspend proposal");
        let commands = prepared_suspend.into_commands();
        assert_eq!(commands.len(), 1);
        let suspend_payload = commands.into_iter().next().unwrap();
        let meta_before_raw = crate::raft::RaftMeta::load(&database).unwrap();
        let raw_index = {
            let mut log = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap();
            let transaction = database.begin_write().unwrap();
            let index = log
                .append_in_txn(
                    &transaction,
                    7,
                    &super::super::shared_raft::encode_agent_raft_entry_kind(&EntryKind::Data {
                        payload: suspend_payload.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            transaction.commit().unwrap();
            index
        };
        assert_eq!(raw_index, committed_tail + 1);
        assert_eq!(
            crate::raft::RaftMeta::load(&database).unwrap(),
            meta_before_raw
        );
        assert_eq!(
            crate::raft::RaftLog::open(Arc::clone(&database))
                .unwrap()
                .last_index(),
            raw_index
        );
        assert_eq!(
            host.show(fixture.agent).unwrap().unwrap().remaining_slots,
            1
        );
        let raw = crate::raft::RaftLog::open(Arc::clone(&database))
            .unwrap()
            .entries(raw_index, raw_index)
            .unwrap();
        assert!(matches!(
            super::super::shared_raft::decode_agent_raft_entry_kind(&raw[0].payload).unwrap(),
            EntryKind::Data { payload } if payload == suspend_payload
        ));

        let host = Arc::new(Mutex::new(host));
        let network = live_network(0x31, Vec::new());
        let signer = SigningMerge(fixture.replica_keys[0].clone());
        let attachment = crate::network::SharedAgentNetworkHost::attach_system(
            Arc::clone(&host),
            Arc::clone(&network),
            fixture.agent,
            fixture.provision.replicas(),
            &signer,
        )
        .unwrap();

        // This is intentionally immediate: attach may publish only after the
        // preserved raw row and the mandatory current-term no-op are both
        // committed, audited, and applied.
        let after_attach = host.lock().unwrap().show(fixture.agent).unwrap().unwrap();
        assert!(attachment.attachment_for_test(fixture.agent).is_some());
        assert_eq!(after_attach.applied_slots, raw_index + 1);
        assert_eq!(after_attach.remaining_slots, 4_094);
        assert!(!after_attach.reservation_pending);
        let SharedAgentSnapshotState::Installed {
            raft_index,
            raft_term,
            ..
        } = after_attach.snapshots
        else {
            panic!("raw-tail recovery did not install its authenticated checkpoint")
        };
        assert_eq!((raft_index, raft_term), (committed_tail, 7));
        let after_meta = crate::raft::RaftMeta::load(&database).unwrap();
        let after_log = crate::raft::RaftLog::open(Arc::clone(&database)).unwrap();
        assert_eq!(after_meta.commit_index, raw_index + 1);
        assert_eq!(after_meta.last_applied, raw_index + 1);
        assert_eq!(after_meta.snap_last_index, committed_tail);
        assert!(after_meta.current_term > 7);
        assert_eq!(after_log.last_index(), raw_index + 1);
        let promoted = after_log.entries(raw_index, raw_index + 1).unwrap();
        assert_eq!(promoted.len(), 2);
        assert!(matches!(
            super::super::shared_raft::decode_agent_raft_entry_kind(&promoted[0].payload).unwrap(),
            EntryKind::Data { payload } if payload == suspend_payload
        ));
        assert!(matches!(
            super::super::shared_raft::decode_agent_raft_entry_kind(&promoted[1].payload).unwrap(),
            EntryKind::Data { payload } if payload.is_empty()
        ));
        assert_eq!(
            host.lock()
                .unwrap()
                .journal_position(fixture.agent)
                .unwrap()
                .ordered_index,
            logical_before_tail.ordered_index + 1
        );
        assert!(matches!(
            host.lock()
                .unwrap()
                .take_clean_ordered_result(fixture.agent, suspend_input)
                .unwrap(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Suspended(_)
            ))
        ));
        let inspect = crate::agent_sdk::ManagementRequest::InspectActors {
            after: None,
            limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
        };
        let suspended_page = host
            .lock()
            .unwrap()
            .inspect_clean_management(fixture.agent, &inspect)
            .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(suspended_page),
        )) = suspended_page
        else {
            panic!("InspectActors did not complete")
        };
        assert!(
            suspended_page
                .entries
                .iter()
                .any(|record| { record.entry.actor == entry.actor && record.entry.suspended })
        );

        drop(attachment);
        drop(host);
        drop(after_log);
        drop(database);
        let mut reopened =
            open_native_clean_host_at_slot(&directory, &fixture, Arc::clone(&logical_slot));
        let database = reopened.raft_database(fixture.agent).unwrap();
        assert_eq!(
            reopened
                .journal_position(fixture.agent)
                .unwrap()
                .ordered_index,
            logical_before_tail.ordered_index + 1
        );
        assert_eq!(
            reopened.show(fixture.agent).unwrap().unwrap().snapshots,
            after_attach.snapshots
        );
        assert_eq!(crate::raft::RaftMeta::load(&database).unwrap(), after_meta);
        assert_eq!(
            reopened.apply_next(fixture.agent).unwrap(),
            SharedAgentApplyOutcome::Idle
        );

        let host = Arc::new(Mutex::new(reopened));
        let attachment = crate::network::SharedAgentNetworkHost::attach_system(
            Arc::clone(&host),
            Arc::clone(&network),
            fixture.agent,
            fixture.provision.replicas(),
            &signer,
        )
        .unwrap();
        let second_attach = host.lock().unwrap().show(fixture.agent).unwrap().unwrap();
        assert_eq!(second_attach.applied_slots, raw_index + 2);
        assert_eq!(second_attach.remaining_slots, 4_093);
        assert!(!second_attach.reservation_pending);
        assert_eq!(
            host.lock()
                .unwrap()
                .journal_position(fixture.agent)
                .unwrap()
                .ordered_index,
            logical_before_tail.ordered_index + 1
        );
        let second_meta = crate::raft::RaftMeta::load(&database).unwrap();
        assert_eq!(second_meta.commit_index, raw_index + 2);
        assert_eq!(second_meta.last_applied, raw_index + 2);
        assert_eq!(
            crate::raft::RaftLog::open(Arc::clone(&database))
                .unwrap()
                .last_index(),
            raw_index + 2
        );
        logical_slot.store(22, Ordering::SeqCst);
        let resume = crate::agent_sdk::ManagementRequest::Resume {
            actor: entry.actor,
            expected_deployment: entry.deployment,
        };
        let resume_receipt =
            clean_management_receipt(&fixture.descriptor, &resume, 4, &fixture.authority_key);
        assert!(matches!(
            attachment
                .manage_clean(
                    fixture.agent,
                    resume,
                    resume_receipt,
                    SdkManagementArtifacts::None,
                )
                .unwrap(),
            crate::network::shared_agent::CleanManagementSubmission::Applied {
                outcome: crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Resumed(_)
                )),
                new_slot: true,
                ..
            }
        ));
        assert_eq!(
            host.lock()
                .unwrap()
                .journal_position(fixture.agent)
                .unwrap()
                .ordered_index,
            logical_before_tail.ordered_index + 2
        );
        let resumed_page = host
            .lock()
            .unwrap()
            .inspect_clean_management(fixture.agent, &inspect)
            .unwrap();
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(resumed_page),
        )) = resumed_page
        else {
            panic!("InspectActors did not complete")
        };
        assert!(
            resumed_page
                .entries
                .iter()
                .any(|record| { record.entry.actor == entry.actor && !record.entry.suspended })
        );
        drop(attachment);
        drop(host);
        join_live_network(network);
    }

    #[test]
    fn snapshot_certificate_replay_isolated_by_agent_store_node_and_generation() {
        let fixture = fixture(0x16);
        let directory_a = TempDirectory::new("snapshot_isolation_a");
        let directory_b = TempDirectory::new("snapshot_isolation_b");
        let mut host_a = open_host(&directory_a, &fixture);
        let mut host_b = open_host(&directory_b, &fixture);
        let candidate_a = provision_apply_candidate(&mut host_a, &fixture, 9);
        let candidate_b = provision_apply_candidate(&mut host_b, &fixture, 9);
        assert_eq!(
            candidate_a.claim().raft_index(),
            candidate_b.claim().raft_index()
        );
        assert_eq!(candidate_a.claim().ordered(), candidate_b.claim().ordered());
        assert_ne!(
            candidate_a.claim().journal_store(),
            candidate_b.claim().journal_store()
        );
        let certificate_a = snapshot_certificate(&candidate_a, &fixture);
        let certificate_b = snapshot_certificate(&candidate_b, &fixture);
        assert!(
            certificate_b
                .verify(candidate_b.claim().active_committee(), candidate_b.claim(),)
                .is_ok()
        );

        // A valid quorum certificate for the byte-identical generation in a
        // different physical store cannot publish even a checkpoint blob.
        let status_b = host_b.show(fixture.agent).unwrap().unwrap();
        let bytes_b = physical_bytes(&directory_b);
        assert_eq!(
            host_b.install_snapshot(fixture.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_b.show(fixture.agent).unwrap().unwrap(), status_b);
        assert_eq!(physical_bytes(&directory_b), bytes_b);

        // Install A, then present B's independently valid quorum certificate
        // at the same Raft index. It is divergent, not a forged signature,
        // and must be rejected before any journal or Raft mutation.
        host_a
            .install_snapshot(fixture.agent, &certificate_a)
            .unwrap();
        let status_a = host_a.show(fixture.agent).unwrap().unwrap();
        let bytes_a = physical_bytes(&directory_a);
        assert_eq!(
            host_a.install_snapshot(fixture.agent, &certificate_b),
            Err(SharedAgentHostError::SnapshotStale)
        );
        assert_eq!(host_a.show(fixture.agent).unwrap().unwrap(), status_a);
        assert_eq!(physical_bytes(&directory_a), bytes_a);

        // The complete local replica identity is signed too. A certificate
        // from A cannot enter another admitted replica's independent store.
        let directory_node = TempDirectory::new("snapshot_isolation_node");
        let alternate_node = fixture.provision.replicas().members()[1].replica().node;
        assert_ne!(alternate_node, candidate_a.claim().local_node());
        let mut host_node = open_host_on_node(&directory_node, &fixture, alternate_node);
        let candidate_node = provision_apply_candidate(&mut host_node, &fixture, 9);
        assert_eq!(candidate_node.claim().local_node(), alternate_node);
        let status_node = host_node.show(fixture.agent).unwrap().unwrap();
        let bytes_node = physical_bytes(&directory_node);
        assert_eq!(
            host_node.install_snapshot(fixture.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_node.show(fixture.agent).unwrap().unwrap(), status_node);
        assert_eq!(physical_bytes(&directory_node), bytes_node);

        // A distinct Agent necessarily has a distinct full generation route,
        // even under the same space, node keys, and logical slot.
        let other = self::fixture(0x17);
        let directory_other = TempDirectory::new("snapshot_isolation_agent");
        let mut host_other = open_host(&directory_other, &other);
        let candidate_other = provision_apply_candidate(&mut host_other, &other, 9);
        assert_ne!(candidate_other.claim().ordered().agent(), fixture.agent);
        let status_other = host_other.show(other.agent).unwrap().unwrap();
        let bytes_other = physical_bytes(&directory_other);
        assert_eq!(
            host_other.install_snapshot(other.agent, &certificate_a),
            Err(SharedAgentHostError::SnapshotReplay)
        );
        assert_eq!(host_other.show(other.agent).unwrap().unwrap(), status_other);
        assert_eq!(physical_bytes(&directory_other), bytes_other);
    }

    #[test]
    fn live_transport_blocks_snapshot_database_replacement() {
        let fixture = fixture(0x26);
        let directory = TempDirectory::new("snapshot_live_transport");
        let mut host = open_host(&directory, &fixture);
        let candidate = provision_apply_candidate(&mut host, &fixture, 9);
        let certificate = snapshot_certificate(&candidate, &fixture);
        let before = physical_bytes(&directory);

        host.reserve_transport_attachment(fixture.agent).unwrap();
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict),
            "setup must reserve the database before a worker can open it"
        );
        assert_eq!(
            host.compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        host.mark_transport_attached(fixture.agent).unwrap();
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(host.require_transport(fixture.agent), Ok(()));
        assert_eq!(
            host.release_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict),
            "an active worker cannot drop its storage lease directly"
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(physical_bytes(&directory), before);

        host.mark_transport_stopping(fixture.agent).unwrap();
        assert_eq!(
            host.reserve_transport_attachment(fixture.agent),
            Err(SharedAgentHostError::Conflict)
        );
        assert_eq!(
            host.install_snapshot(fixture.agent, &certificate),
            Err(SharedAgentHostError::Conflict),
            "ordered shutdown retains the lease until every cache is gone"
        );
        assert_eq!(
            host.compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        );
        host.release_transport_attachment(fixture.agent).unwrap();
        assert!(host.install_snapshot(fixture.agent, &certificate).is_ok());
    }

    #[test]
    fn discovery_rejects_unknown_authority_namespace_residue() {
        let directory = TempDirectory::new("unknown_namespace");
        let fixture = fixture(0x14);
        let mut host = open_host(&directory, &fixture);
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            fixture.committee_authority,
        )
        .unwrap();
        let authority_root = host.lease.authority_root().unwrap().to_path_buf();
        drop(host);
        fs::write(authority_root.join("unknown-residue"), b"ambiguous").unwrap();
        let error = match SharedAgentHost::reopen(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node: NodeId::of_authenticated_peer(&peer_id(
                    fixture
                        .replica_keys
                        .iter()
                        .find(|key| {
                            NodeId::of_authenticated_peer(&peer_id(key))
                                == fixture.provision.replicas().members()[0].replica().node
                        })
                        .unwrap(),
                )),
            },
            Arc::new(StaticTrust(fixture.authority.clone())),
            Arc::new(SigningMerge(
                fixture
                    .replica_keys
                    .iter()
                    .find(|key| {
                        NodeId::of_authenticated_peer(&peer_id(key))
                            == fixture.provision.replicas().members()[0].replica().node
                    })
                    .unwrap()
                    .clone(),
            )),
            Arc::new(AcceptFinality),
        ) {
            Ok(_) => panic!("ambiguous namespace was accepted"),
            Err(error) => error,
        };
        assert_eq!(error, SharedAgentHostError::CorruptResidue);
    }

    #[cfg(feature = "network")]
    #[test]
    fn authenticated_merge_staging_survives_restart_without_moving_heads() {
        let directory_source = TempDirectory::new("merge_stage_source");
        let directory_target = TempDirectory::new("merge_stage_target");
        let fixture = fixture(0x27);
        let source_node = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[0]));
        let target_node = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[1]));
        let mut source = open_host_on_node(&directory_source, &fixture, source_node);
        let mut target = open_host_on_node(&directory_target, &fixture, target_node);
        for host in [&mut source, &mut target] {
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        }
        let event_id = publish_merge_invocation(&mut source, &fixture, 0xd0);
        let bytes = source.merge_node(fixture.agent, event_id).unwrap().unwrap();
        let event = MergeEvent::decode(&bytes).unwrap();
        let empty_roots = target.merge_roots(fixture.agent).unwrap();

        assert!(target.stage_merge(fixture.agent, &event).unwrap());
        assert_eq!(target.merge_roots(fixture.agent).unwrap(), empty_roots);
        assert!(matches!(
            target.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Staged(found) if found == bytes
        ));

        drop(target);
        let mut reopened = open_host_on_node(&directory_target, &fixture, target_node);
        assert_eq!(reopened.merge_roots(fixture.agent).unwrap(), empty_roots);
        assert!(matches!(
            reopened.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Staged(found) if found == bytes
        ));
        assert!(matches!(
            reopened.import_merge(fixture.agent, &event).unwrap(),
            SharedAgentApplyOutcome::Applied { .. }
        ));
        assert!(matches!(
            reopened.merge_object(fixture.agent, event_id).unwrap(),
            crate::agent::shared_journal_driver::SharedMergeObject::Published(found) if found == bytes
        ));
    }

    #[cfg(feature = "network")]
    #[test]
    fn observer_attaches_as_authenticated_merge_member_with_a_passive_raft_worker() {
        let directory = TempDirectory::new("clean_network_observer");
        let fixture = fixture(0x2a);
        let observer = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[2]));
        let mut opened = open_host_on_node(&directory, &fixture, observer);
        let status = opened
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        let route = crate::network::agent_protocol::AgentGenerationRoute {
            space: crate::agent_sdk::SpaceId(status.generation.space().0),
            agent: crate::agent_sdk::AgentId(status.generation.agent().0),
            generation: crate::agent_sdk::Hash(status.replication_id),
        };
        let host = Arc::new(std::sync::Mutex::new(opened));
        let network = live_network(0x33, Vec::new());
        let attachment =
            crate::network::SharedAgentNetworkHost::attach(Arc::clone(&host), Arc::clone(&network))
                .unwrap();
        let (handler, owns_worker) = attachment.attachment_for_test(fixture.agent).unwrap();
        // The observer runs a passive worker so an authorized joint
        // configuration can reach it; it is never a Raft member until then.
        assert!(owns_worker);
        attachment.assert_merge_noop_gate_for_test(fixture.agent);
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );

        let request = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Merge(
                    crate::network::agent_protocol::MergeMessage::FetchHeads,
                ),
            },
        )
        .unwrap();
        assert!(matches!(
            handler.handle(request),
            Ok(crate::network::agent_protocol::AgentMessage::Merge(
                crate::network::agent_protocol::MergeMessage::Heads(_)
            ))
        ));
        let raft = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Raft(
                    crate::network::agent_protocol::RaftMessage::StatusRequest,
                ),
            },
        )
        .unwrap();
        let local = network.agent_node_id();
        assert!(matches!(
            handler.handle(raft),
            Ok(crate::network::agent_protocol::AgentMessage::Raft(
                crate::network::agent_protocol::RaftMessage::StatusReply(Some(status))
            )) if status.role == crate::network::agent_protocol::RaftRole::Follower
                && !status.members.contains(&local)
                && status.joint_old.is_none()
        ));

        drop(attachment);
        drop(handler);
        drop(host);
        join_live_network(network);
    }

    #[cfg(feature = "network")]
    #[test]
    fn clean_network_attachment_retires_stale_owner_and_rebuilds_after_restart() {
        let directory = TempDirectory::new("clean_network_restart");
        let fixture = fixture(0x28);
        let local = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[0]));
        let mut opened = open_host_on_node(&directory, &fixture, local);
        let status = opened
            .provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        opened
            .agents
            .get_mut(&fixture.agent)
            .unwrap()
            .driver
            .append_ordered_for_test(5, authorized_management(&fixture, 2, 0xd7))
            .unwrap();
        assert_eq!(
            opened.show(fixture.agent).unwrap().unwrap().applied_slots,
            0
        );
        let route = crate::network::agent_protocol::AgentGenerationRoute {
            space: crate::agent_sdk::SpaceId(status.generation.space().0),
            agent: crate::agent_sdk::AgentId(status.generation.agent().0),
            generation: crate::agent_sdk::Hash(status.replication_id),
        };
        let host = Arc::new(std::sync::Mutex::new(opened));
        let network = live_network(0x31, Vec::new());
        let mut attachment =
            crate::network::SharedAgentNetworkHost::attach(Arc::clone(&host), Arc::clone(&network))
                .unwrap();
        assert_eq!(
            host.lock()
                .unwrap()
                .show(fixture.agent)
                .unwrap()
                .unwrap()
                .applied_slots,
            1,
            "attachment must drain a recovered committed suffix before exposing its route"
        );
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );
        assert!(matches!(
            host.lock()
                .unwrap()
                .compact_snapshot(fixture.agent, compaction_limits(1)),
            Err(SharedAgentHostError::Conflict)
        ));
        let (first_owner, owns_worker) = attachment.attachment_for_test(fixture.agent).unwrap();
        assert!(owns_worker, "an active voter owns the full-NodeId worker");

        {
            let host = host.lock().unwrap();
            let full = host.show(fixture.agent).unwrap().unwrap();
            let narrow = host.attachment_statuses().unwrap();
            assert_eq!(narrow.len(), 1);
            let narrow = &narrow[0];
            assert_eq!(narrow.identity, full.identity);
            assert_eq!(narrow.generation, full.generation);
            assert_eq!(narrow.route, full.route);
            assert_eq!(narrow.replication_id, full.replication_id);
            assert_eq!(narrow.local_role, full.local_role);
            assert_eq!(narrow.replicas, full.replicas);
            assert_eq!(narrow.committee_transition, full.committee_transition);
            assert_eq!(narrow.transport, full.transport);
        }
        for _ in 0..3 {
            attachment.refresh().unwrap();
            let (unchanged_owner, owns_worker) =
                attachment.attachment_for_test(fixture.agent).unwrap();
            assert!(Arc::ptr_eq(&first_owner, &unchanged_owner));
            assert!(owns_worker);
        }

        assert!(attachment.mark_stale_for_test(fixture.agent));
        attachment.refresh().unwrap();
        let (replacement_owner, owns_worker) =
            attachment.attachment_for_test(fixture.agent).unwrap();
        assert!(!Arc::ptr_eq(&first_owner, &replacement_owner));
        assert!(owns_worker);
        let stale_request = crate::network::agent_protocol::authenticate_sender(
            &network.peer_id(),
            crate::network::agent_protocol::AgentFrame {
                route,
                sender: network.agent_node_id(),
                message: crate::network::agent_protocol::AgentMessage::Merge(
                    crate::network::agent_protocol::MergeMessage::FetchHeads,
                ),
            },
        )
        .unwrap();
        assert!(
            first_owner.handle(stale_request).is_err(),
            "a cloned retired handler must not cross the generation lease"
        );

        drop(attachment);
        assert_eq!(
            host.lock().unwrap().require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        let unknown = crate::agent_sdk::NodeId([0xfe; 32]);
        assert!(matches!(
            network
                .send_agent_merge_fetch_heads(unknown, route)
                .recv()
                .unwrap(),
            Err(crate::network::agent_network::AgentNetworkError::UnknownRoute(found))
                if found == route
        ));

        drop(first_owner);
        drop(replacement_owner);
        drop(Arc::try_unwrap(host).ok().unwrap().into_inner().unwrap());
        let reopened = Arc::new(std::sync::Mutex::new(open_host_on_node(
            &directory, &fixture, local,
        )));
        assert_eq!(
            reopened.lock().unwrap().require_transport(fixture.agent),
            Err(SharedAgentHostError::TransportNotAttached)
        );
        let restarted = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&reopened),
            Arc::clone(&network),
        )
        .unwrap();
        assert_eq!(
            reopened.lock().unwrap().require_transport(fixture.agent),
            Ok(())
        );
        assert!(restarted.attachment_for_test(fixture.agent).unwrap().1);
        drop(restarted);
        drop(reopened);
        join_live_network(network);
    }

    #[cfg(feature = "network")]
    #[test]
    fn clean_merge_pump_converges_two_real_hosts_after_partition() {
        let directory_a = TempDirectory::new("clean_merge_source");
        let directory_b = TempDirectory::new("clean_merge_target");
        let fixture = fixture(0x29);
        let node_a = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[0]));
        let node_b = NodeId::of_authenticated_peer(&peer_id(&fixture.replica_keys[1]));
        let mut opened_a = open_host_on_node(&directory_a, &fixture, node_a);
        let mut opened_b = open_host_on_node(&directory_b, &fixture, node_b);
        for host in [&mut opened_a, &mut opened_b] {
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                fixture.committee_authority,
            )
            .unwrap();
        }
        let host_a = Arc::new(std::sync::Mutex::new(opened_a));
        let host_b = Arc::new(std::sync::Mutex::new(opened_b));
        let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let network_a = live_network(0x31, vec![listen]);
        let network_b = live_network(0x32, Vec::new());
        assert_eq!(
            network_a.agent_node_id(),
            crate::agent_sdk::NodeId(node_a.0)
        );
        assert_eq!(
            network_b.agent_node_id(),
            crate::agent_sdk::NodeId(node_b.0)
        );
        let attachment_a = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&host_a),
            Arc::clone(&network_a),
        )
        .unwrap();
        let attachment_b = crate::network::SharedAgentNetworkHost::attach(
            Arc::clone(&host_b),
            Arc::clone(&network_b),
        )
        .unwrap();

        let event = publish_merge_invocation(&mut host_a.lock().unwrap(), &fixture, 0xd1);
        let source = host_a
            .lock()
            .unwrap()
            .merge_node(fixture.agent, event)
            .unwrap()
            .unwrap();
        assert_eq!(
            host_b
                .lock()
                .unwrap()
                .merge_node(fixture.agent, event)
                .unwrap(),
            None,
            "the partitioned replica cannot observe a local publication"
        );

        assert!(wait_until(std::time::Duration::from_secs(5), || {
            !network_a.listen_addrs().is_empty()
        }));
        let address = network_a.listen_addrs()[0]
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(network_a.peer_id()));
        let source_roots = host_a.lock().unwrap().merge_roots(fixture.agent).unwrap();
        network_b.connect(address);
        assert!(wait_until(std::time::Duration::from_secs(10), || {
            let Ok(host) = host_b.lock() else {
                return false;
            };
            // A staged authenticated blob precedes integration of its merge
            // heads. Convergence requires both under one host observation.
            host.merge_node(fixture.agent, event)
                .ok()
                .flatten()
                .as_ref()
                == Some(&source)
                && host
                    .merge_roots(fixture.agent)
                    .is_ok_and(|roots| roots == source_roots)
        }));
        assert_eq!(
            host_a.lock().unwrap().merge_roots(fixture.agent).unwrap(),
            host_b.lock().unwrap().merge_roots(fixture.agent).unwrap()
        );

        drop(attachment_a);
        drop(attachment_b);
        drop(host_a);
        drop(host_b);
        join_live_network(network_a);
        join_live_network(network_b);
    }

    #[cfg(feature = "pvm")]
    fn open_native_clean_host_for_seed(
        directory: &TempDirectory,
        fixture: &Fixture,
        seed: u8,
        slot: Arc<AtomicU64>,
    ) -> SharedAgentHost {
        let signing = key(seed);
        let node = NodeId::of_authenticated_peer(&peer_id(&signing));
        SharedAgentHost::open(
            directory.root(),
            directory.lock(),
            AgentHostScope {
                space: fixture.space,
                node,
            },
            Arc::new(NativeCleanTrust {
                authority: fixture.authority.clone(),
                slot,
            }),
            Arc::new(SigningMerge(signing)),
            Arc::new(AcceptFinality),
        )
        .unwrap()
    }

    /// Production derives the committee-change trust root from the Shared
    /// descriptor's authority binding; one receipt then admits both the
    /// committee leg and the runtime's ordered `ChangeReplicas`.
    #[cfg(feature = "pvm")]
    fn descriptor_committee_authority(
        descriptor: &crate::agent_sdk::AgentDescriptor,
    ) -> CommitteeChangeAuthorityBinding {
        CommitteeChangeAuthorityBinding::new(
            descriptor.authority.policy,
            descriptor.authority.issuer,
            descriptor.identity.runtime_deployment,
            descriptor.authority.public_key,
            descriptor.authority.initial_epoch,
        )
        .unwrap()
    }

    #[cfg(feature = "pvm")]
    fn epoch_management_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        sequence: u64,
        epoch: u64,
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        let mut receipt = clean_management_receipt(descriptor, request, sequence, authority_key);
        receipt.selector.epoch = epoch;
        receipt.signature = authority_key.sign(&receipt.signing_bytes()).to_bytes();
        receipt.validate_shape().unwrap();
        receipt
    }

    /// Canonical SDK roster for the given replica seeds, in node order.
    #[cfg(feature = "pvm")]
    fn seeded_roster(replicas: &[(u8, ReplicaRole)]) -> Vec<crate::agent_sdk::AgentReplica> {
        let mut roster = replicas
            .iter()
            .map(|(seed, role)| {
                let replica = replica_member(&key(*seed), *role).replica();
                crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId(replica.node.0),
                    principal: crate::agent_sdk::PrincipalId(replica.principal.0),
                    role: match replica.role {
                        ReplicaRole::Voter => crate::agent_sdk::ReplicaRole::Voter,
                        ReplicaRole::Observer => crate::agent_sdk::ReplicaRole::Observer,
                    },
                }
            })
            .collect::<Vec<_>>();
        roster.sort_by_key(|replica| replica.node);
        roster
    }

    /// Fully connected loopback libp2p mesh keyed by the replica seeds.
    #[cfg(feature = "network")]
    fn live_mesh(seeds: &[u8]) -> Vec<Arc<crate::network::Network>> {
        let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let networks = seeds
            .iter()
            .map(|seed| live_network(*seed, vec![listen.clone()]))
            .collect::<Vec<_>>();
        for network in &networks {
            assert!(wait_until(std::time::Duration::from_secs(5), || {
                !network.listen_addrs().is_empty()
            }));
        }
        for (index, network) in networks.iter().enumerate() {
            for earlier in &networks[..index] {
                network.connect(
                    earlier.listen_addrs()[0]
                        .clone()
                        .with(libp2p::multiaddr::Protocol::P2p(earlier.peer_id())),
                );
            }
        }
        networks
    }

    /// Exact replicated state of one replica: its ordered journal position,
    /// the runtime's management-history commitment, and its actor directory.
    #[cfg(feature = "network")]
    fn replicated_state(
        host: &Arc<Mutex<SharedAgentHost>>,
        agent: AgentId,
    ) -> Option<(
        SharedAgentJournalPosition,
        crate::agent_sdk::Hash,
        crate::agent_sdk::ActorDirectoryPage,
    )> {
        let host = host.lock().ok()?;
        let position = host.journal_position(agent).ok()?;
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::ManagementHistory(history),
        )) = host
            .inspect_clean_management(
                agent,
                &crate::agent_sdk::ManagementRequest::InspectManagementHistory,
            )
            .ok()?
        else {
            return None;
        };
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(actors),
        )) = host
            .inspect_clean_management(
                agent,
                &crate::agent_sdk::ManagementRequest::InspectActors {
                    after: None,
                    limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
                },
            )
            .ok()?
        else {
            return None;
        };
        Some((position, history, actors))
    }

    /// Every listed replica runs `roster` as a stable committee and in its
    /// descriptor, and all of them hold the identical replicated state.
    #[cfg(feature = "network")]
    fn committee_converged(
        hosts: &[&Arc<Mutex<SharedAgentHost>>],
        agent: AgentId,
        roster: &[crate::agent_sdk::AgentReplica],
    ) -> bool {
        let mut first = None;
        for host in hosts {
            let Ok(locked) = host.lock() else {
                return false;
            };
            let Ok(Some(status)) = locked.show(agent) else {
                return false;
            };
            let runs_roster = status.committee_transition.is_none()
                && status.replicas.len() == roster.len()
                && status.replicas.iter().zip(roster).all(|(route, replica)| {
                    route.node.0 == replica.node.0
                        && (route.role == ReplicaRole::Voter)
                            == (replica.role == crate::agent_sdk::ReplicaRole::Voter)
                })
                && locked
                    .clean_runtime_descriptor(agent)
                    .is_ok_and(|descriptor| descriptor.replicas == roster);
            drop(locked);
            if !runs_roster {
                return false;
            }
            let Some(state) = replicated_state(host, agent) else {
                return false;
            };
            match &first {
                None => first = Some(state),
                Some(first) if *first == state => {}
                Some(_) => return false,
            }
        }
        true
    }

    /// Capture Shared journal and network warnings (for example the exact
    /// driver error behind a `CorruptResidue`) in the failing test's output.
    #[cfg(feature = "network")]
    fn init_replica_test_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("vos::agent=warn,vos::network=warn")
            .with_test_writer()
            .try_init();
    }

    /// One line per replica: host committee view, journal position, and the
    /// live Raft worker's role, term, commit and configuration.
    #[cfg(feature = "network")]
    fn replica_diagnostics(
        host: &Arc<Mutex<SharedAgentHost>>,
        attachment: Option<&crate::network::SharedAgentNetworkHost>,
        network: &crate::network::Network,
        agent: AgentId,
    ) -> String {
        let Ok(locked) = host.lock() else {
            return "host lock poisoned".into();
        };
        let node = locked.scope().node;
        let status = locked.show(agent);
        let ordered = locked
            .journal_position(agent)
            .map(|position| position.ordered_index);
        let roster = locked
            .clean_runtime_descriptor(agent)
            .map(|descriptor| descriptor.replicas.len());
        drop(locked);
        let host_view = match &status {
            Ok(Some(status)) => format!(
                "role={:?} committee={:?} transition={:?} replicas={:?} applied={} remaining={}",
                status.local_role,
                status.route.committee(),
                status
                    .committee_transition
                    .as_ref()
                    .map(|transition| (transition.next_committee, transition.joint)),
                status
                    .replicas
                    .iter()
                    .map(|replica| (replica.node, replica.role))
                    .collect::<Vec<_>>(),
                status.applied_slots,
                status.remaining_slots,
            ),
            other => format!("status={other:?}"),
        };
        let raft = match (
            &status,
            attachment.and_then(|attachment| attachment.attachment_for_test(agent)),
        ) {
            (Ok(Some(status)), Some((handler, owns_worker))) => {
                let route = crate::network::agent_protocol::AgentGenerationRoute {
                    space: crate::agent_sdk::SpaceId(status.generation.space().0),
                    agent: crate::agent_sdk::AgentId(status.generation.agent().0),
                    generation: crate::agent_sdk::Hash(status.replication_id),
                };
                let reply = crate::network::agent_protocol::authenticate_sender(
                    &network.peer_id(),
                    crate::network::agent_protocol::AgentFrame {
                        route,
                        sender: network.agent_node_id(),
                        message: crate::network::agent_protocol::AgentMessage::Raft(
                            crate::network::agent_protocol::RaftMessage::StatusRequest,
                        ),
                    },
                )
                .map(|request| handler.handle(request));
                format!("worker={owns_worker} raft={reply:?}")
            }
            (_, None) => "not attached".into(),
            _ => "no status".into(),
        };
        format!("node={node:?} {host_view} ordered={ordered:?} roster={roster:?} {raft}")
    }

    #[cfg(feature = "pvm")]
    fn committee_change_fixture(nonce: u8, replicas: &[(u8, ReplicaRole)]) -> Fixture {
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "shared-committee-change",
            0x74,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        standard_projection_fixture_with_replicas(nonce, runtime, replicas, false)
    }

    /// Single-host, deterministic walk of a complete replica change with a
    /// real SDK receipt: the committee leg admits nodes outside the initial
    /// committee only through their authenticated PeerIds, the ledger
    /// applies Prepare -> Joint -> Stable, ordinary commands wait for it, and
    /// the runtime then adopts the roster in the descriptor.
    #[cfg(feature = "pvm")]
    #[test]
    fn signed_change_replicas_binds_new_nodes_and_applies_every_leg() {
        use crate::service::wire::ServiceWire as _;

        let fixture = committee_change_fixture(0x5c, &[(0x31, ReplicaRole::Voter)]);
        let agent = fixture.agent;
        let directory = TempDirectory::new("committee_change_new_nodes");
        let slot = Arc::new(AtomicU64::new(20));
        let mut host =
            open_native_clean_host_for_seed(&directory, &fixture, 0x31, Arc::clone(&slot));
        host.provision(
            fixture.provision.clone(),
            fixture.catalog.clone(),
            descriptor_committee_authority(&fixture.descriptor),
        )
        .unwrap();
        let roster = seeded_roster(&[
            (0x31, ReplicaRole::Voter),
            (0x3a, ReplicaRole::Voter),
            (0x3b, ReplicaRole::Voter),
        ]);
        let change = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: fixture.descriptor.replica_generation(),
            replicas: roster.clone(),
        };
        let receipt =
            clean_management_receipt(&fixture.descriptor, &change, 2, &fixture.authority_key);
        let new_a = peer_id(&key(0x3a));
        let new_b = peer_id(&key(0x3b));
        let stranger = peer_id(&key(0x3c));
        let applied_before = host.show(agent).unwrap().unwrap().applied_slots;

        // A new node is admitted only by the PeerId whose digest is the
        // authority-signed node; missing, partial or extra identities fail.
        for joining in [
            Vec::new(),
            vec![new_a.clone()],
            vec![new_a.clone(), stranger.clone()],
            vec![new_a.clone(), new_b.clone(), stranger],
        ] {
            assert_eq!(
                host.prepare_clean_committee_change(agent, &change, &receipt, &joining)
                    .unwrap_err(),
                SharedAgentHostError::CommitteeChangeRefused,
            );
        }
        let stale = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: crate::agent_sdk::Hash([0x77; 32]),
            replicas: roster.clone(),
        };
        let stale_receipt =
            clean_management_receipt(&fixture.descriptor, &stale, 2, &fixture.authority_key);
        let joining = vec![new_b.clone(), new_a.clone()];
        assert_eq!(
            host.prepare_clean_committee_change(agent, &stale, &stale_receipt, &joining)
                .unwrap_err(),
            SharedAgentHostError::CommitteeChangeRefused,
        );
        // The ledger's authority epoch is part of the binding.
        let other_epoch =
            epoch_management_receipt(&fixture.descriptor, &change, 2, 2, &fixture.authority_key);
        assert_eq!(
            host.prepare_clean_committee_change(agent, &change, &other_epoch, &joining)
                .unwrap_err(),
            SharedAgentHostError::CommitteeChangeRefused,
        );
        // The descriptor cannot adopt a roster the committee does not run.
        assert_eq!(
            host.prepare_clean_management(
                agent,
                change.clone(),
                receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap_err(),
            SharedAgentHostError::CommitteeChangeRefused,
        );
        assert_eq!(
            host.show(agent).unwrap().unwrap().applied_slots,
            applied_before
        );

        let prepared = host
            .prepare_clean_committee_change(agent, &change, &receipt, &joining)
            .unwrap()
            .unwrap();
        let super::super::shared_raft::AgentRaftCommand::PrepareCommitteeChange(prepare) =
            super::super::shared_raft::AgentRaftCommand::decode(&prepared.command).unwrap()
        else {
            panic!("committee leg is not a PrepareCommitteeChange")
        };
        assert_eq!(prepare.authority(), &receipt);
        assert_eq!(prepare.authority().selector.request, change.commitment());
        assert_eq!(prepare.observed_slot(), 20);
        assert_eq!(
            super::super::shared_raft::committee_sdk_replicas(prepare.next()),
            roster
        );
        for peer in [&new_a, &new_b] {
            assert!(prepare.next().member_by_peer_id(peer).is_some());
        }
        assert_eq!(prepared.next_voters, prepare.next_voters());
        assert_eq!(prepared.next_committee, prepare.next().id());

        let append = |host: &SharedAgentHost, kind: EntryKind<crate::agent_sdk::NodeId>| {
            host.agents[&agent]
                .driver
                .ledger()
                .append_committed_for_test(7, &kind)
                .unwrap()
        };
        let index = append(
            &host,
            EntryKind::Data {
                payload: prepared.command.clone(),
            },
        );
        assert_eq!(
            host.apply_next(agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index }
        );
        let transition = host
            .show(agent)
            .unwrap()
            .unwrap()
            .committee_transition
            .unwrap();
        assert!(!transition.joint);
        assert_eq!(transition.next_committee, prepare.next().id());
        assert!(
            transition
                .next_replicas
                .iter()
                .any(|replica| replica.peer_id == new_a)
        );

        // While the change is pending, nothing else may take a slot.
        let actor_package = super::super::package_admission::admitted_standard_query_actor_for_test(
            "committee-barrier-worker",
            crate::agent_sdk::StateLane::Linear,
            0x78,
        );
        let install = clean_install_request(fixture.descriptor.identity.agent, &actor_package);
        let install_receipt =
            clean_management_receipt(&fixture.descriptor, &install, 3, &fixture.authority_key);
        assert_eq!(
            host.prepare_clean_management(
                agent,
                install,
                install_receipt,
                SdkManagementArtifacts::Actor(&actor_package),
            )
            .unwrap_err(),
            SharedAgentHostError::Unavailable,
        );
        assert_eq!(
            host.prepare_clean_committee_change(agent, &change, &receipt, &joining)
                .unwrap_err(),
            SharedAgentHostError::Unavailable,
        );

        let joint = append(
            &host,
            EntryKind::ConfigChange {
                joint_old: Some(prepare.previous_voters().to_vec()),
                members: prepare.next_voters().to_vec(),
            },
        );
        assert_eq!(joint, index + 1);
        assert_eq!(
            host.apply_next(agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: joint }
        );
        assert!(
            host.show(agent)
                .unwrap()
                .unwrap()
                .committee_transition
                .unwrap()
                .joint
        );
        let stable = append(
            &host,
            EntryKind::ConfigChange {
                joint_old: None,
                members: prepare.next_voters().to_vec(),
            },
        );
        assert_eq!(
            host.apply_next(agent).unwrap(),
            SharedAgentApplyOutcome::Applied { index: stable }
        );
        let status = host.show(agent).unwrap().unwrap();
        assert_eq!(status.committee_transition, None);
        assert_eq!(status.route.committee(), prepare.next().id());
        assert_eq!(
            status
                .replicas
                .iter()
                .map(|replica| (replica.node.0, replica.role))
                .collect::<Vec<_>>(),
            roster
                .iter()
                .map(|replica| (replica.node.0, ReplicaRole::Voter))
                .collect::<Vec<_>>()
        );

        // The committee runs the roster; the descriptor leg is ordinary.
        assert!(
            host.prepare_clean_committee_change(agent, &change, &receipt, &[])
                .unwrap()
                .is_none()
        );
        let descriptor_leg = host
            .prepare_clean_management(
                agent,
                change.clone(),
                receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        let input = descriptor_leg.input().expect("fresh descriptor leg");
        for payload in descriptor_leg.into_commands() {
            let index = append(&host, EntryKind::Data { payload });
            assert_eq!(
                host.apply_next(agent).unwrap(),
                SharedAgentApplyOutcome::Applied { index }
            );
        }
        let generation = crate::agent_sdk::replica_set_generation(
            &fixture.descriptor.identity,
            fixture.descriptor.creation_nonce,
            &roster,
        );
        assert!(matches!(
            host.take_clean_ordered_result(agent, input).unwrap(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::ReplicasChanged { generation: applied }
            )) if applied == generation
        ));
        assert_eq!(
            host.clean_runtime_descriptor(agent).unwrap().replicas,
            roster
        );
        assert!(
            host.prepare_clean_management(
                agent,
                change.clone(),
                receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap()
            .retained()
            .is_some(),
            "an exact replay is retained, never applied twice"
        );

        drop(host);
        let reopened = open_native_clean_host_for_seed(&directory, &fixture, 0x31, slot);
        let status = reopened.show(agent).unwrap().unwrap();
        assert_eq!(status.route.committee(), prepare.next().id());
        assert_eq!(status.committee_transition, None);
        assert_eq!(
            reopened.clean_runtime_descriptor(agent).unwrap().replicas,
            roster
        );
    }

    /// One voter grows online to three by promoting two observers through a
    /// signed SDK `ChangeReplicas`, then commits with a two-of-three quorum.
    #[cfg(all(feature = "network", feature = "pvm"))]
    #[test]
    fn signed_change_replicas_grows_one_voter_to_three_and_commits_with_two() {
        init_replica_test_tracing();
        use crate::network::shared_agent::CleanManagementSubmission;

        let seeds = [0x31_u8, 0x32, 0x33];
        let fixture = committee_change_fixture(
            0x5a,
            &[
                (0x31, ReplicaRole::Voter),
                (0x32, ReplicaRole::Observer),
                (0x33, ReplicaRole::Observer),
            ],
        );
        let agent = fixture.agent;
        let authority = descriptor_committee_authority(&fixture.descriptor);
        let slot = Arc::new(AtomicU64::new(20));
        let directories = seeds
            .iter()
            .map(|seed| TempDirectory::new(&format!("committee_grow_{seed:02x}")))
            .collect::<Vec<_>>();
        let mut hosts = seeds
            .iter()
            .zip(&directories)
            .map(|(seed, directory)| {
                let mut host =
                    open_native_clean_host_for_seed(directory, &fixture, *seed, Arc::clone(&slot));
                host.provision(
                    fixture.provision.clone(),
                    fixture.catalog.clone(),
                    authority,
                )
                .unwrap();
                Arc::new(Mutex::new(host))
            })
            .collect::<Vec<_>>();
        let mut networks = live_mesh(&seeds);
        let mut attachments = hosts
            .iter()
            .zip(&networks)
            .map(|(host, network)| {
                Some(
                    crate::network::SharedAgentNetworkHost::attach(
                        Arc::clone(host),
                        Arc::clone(network),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        for attachment in attachments.iter().flatten() {
            assert!(attachment.attachment_for_test(agent).unwrap().1);
        }

        // An ordered mutation commits on the single voter alone.
        let actor_package = super::super::package_admission::admitted_standard_query_actor_for_test(
            "committee-grow-worker",
            crate::agent_sdk::StateLane::Linear,
            0x76,
        );
        let install = clean_install_request(fixture.descriptor.identity.agent, &actor_package);
        let install_receipt =
            clean_management_receipt(&fixture.descriptor, &install, 2, &fixture.authority_key);
        let CleanManagementSubmission::Applied {
            outcome:
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Installed(entry),
                )),
            ..
        } = manage_live(
            &mut attachments,
            agent,
            &install,
            &install_receipt,
            SdkManagementArtifacts::Actor(&actor_package),
        )
        else {
            panic!("single-voter Install did not apply")
        };

        // Grow to three voters with one exact Authority receipt over the SDK
        // request. The committee leg runs first, then the descriptor leg.
        let grown = seeded_roster(&[
            (0x31, ReplicaRole::Voter),
            (0x32, ReplicaRole::Voter),
            (0x33, ReplicaRole::Voter),
        ]);
        let change = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: fixture.descriptor.replica_generation(),
            replicas: grown.clone(),
        };
        // Every management decision needs a strictly later observed slot.
        slot.store(21, Ordering::SeqCst);
        let change_receipt =
            clean_management_receipt(&fixture.descriptor, &change, 3, &fixture.authority_key);
        let expected_generation = crate::agent_sdk::replica_set_generation(
            &fixture.descriptor.identity,
            fixture.descriptor.creation_nonce,
            &grown,
        );
        assert!(matches!(
            manage_live(
                &mut attachments,
                agent,
                &change,
                &change_receipt,
                SdkManagementArtifacts::None,
            ),
            CleanManagementSubmission::Applied {
                outcome: crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::ReplicasChanged { generation }
                )),
                new_slot: true,
                ..
            } if generation == expected_generation
        ));
        let all = hosts.iter().collect::<Vec<_>>();
        let converged = wait_until(std::time::Duration::from_secs(30), || {
            attachments.iter_mut().flatten().for_each(|attachment| {
                let _ = attachment.refresh();
            });
            committee_converged(&all, agent, &grown)
        });
        assert!(
            converged,
            "growth did not converge:\n{}",
            hosts
                .iter()
                .zip(&attachments)
                .zip(&networks)
                .map(|((host, attachment), network)| {
                    replica_diagnostics(host, attachment.as_ref(), network, agent)
                })
                .collect::<Vec<_>>()
                .join("\n")
        );
        for (host, attachment) in hosts.iter().zip(attachments.iter().flatten()) {
            let host = host.lock().unwrap();
            assert_eq!(
                host.show(agent).unwrap().unwrap().local_role,
                Some(ReplicaRole::Voter)
            );
            drop(host);
            assert!(attachment.attachment_for_test(agent).unwrap().1);
        }
        // The promoted observers replayed the complete log: the actor
        // installed before they were voters is in their directory.
        for host in &hosts {
            assert!(
                replicated_state(host, agent)
                    .unwrap()
                    .2
                    .entries
                    .iter()
                    .any(|record| record.entry.actor == entry.actor)
            );
        }

        // An exact replay of the completed request is retained, not re-run.
        assert!(matches!(
            manage_live(
                &mut attachments,
                agent,
                &change,
                &change_receipt,
                SdkManagementArtifacts::None,
            ),
            CleanManagementSubmission::Applied {
                outcome: crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::ReplicasChanged { generation }
                )),
                new_slot: false,
                ..
            } if generation == expected_generation
        ));

        drop(all);
        // Stop one voter: the remaining two still form the new quorum.
        drop(attachments.pop());
        drop(hosts.pop());
        join_live_network(networks.pop().unwrap());
        let suspend = crate::agent_sdk::ManagementRequest::Suspend {
            actor: entry.actor,
            expected_deployment: entry.deployment,
        };
        slot.store(22, Ordering::SeqCst);
        let suspend_receipt =
            clean_management_receipt(&fixture.descriptor, &suspend, 4, &fixture.authority_key);
        assert!(matches!(
            manage_live(
                &mut attachments,
                agent,
                &suspend,
                &suspend_receipt,
                SdkManagementArtifacts::None,
            ),
            CleanManagementSubmission::Applied {
                outcome: crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Suspended(_)
                )),
                new_slot: true,
                ..
            }
        ));
        let survivors = hosts.iter().collect::<Vec<_>>();
        let converged = wait_until(std::time::Duration::from_secs(30), || {
            committee_converged(&survivors, agent, &grown)
        });
        assert!(
            converged,
            "survivors did not converge:\n{}",
            hosts
                .iter()
                .zip(&attachments)
                .zip(&networks)
                .map(|((host, attachment), network)| {
                    replica_diagnostics(host, attachment.as_ref(), network, agent)
                })
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Reopen the original voter: its durable ledger keeps the new
        // committee and its descriptor keeps the adopted roster.
        let expected_state = replicated_state(&hosts[0], agent).unwrap();
        drop(survivors);
        drop(attachments);
        let first = hosts.remove(0);
        drop(hosts);
        drop(Arc::try_unwrap(first).ok().unwrap().into_inner().unwrap());
        let reopened = Arc::new(Mutex::new(open_native_clean_host_for_seed(
            &directories[0],
            &fixture,
            seeds[0],
            Arc::clone(&slot),
        )));
        assert!(committee_converged(&[&reopened], agent, &grown));
        assert_eq!(replicated_state(&reopened, agent).unwrap(), expected_state);
        drop(reopened);
        for network in networks {
            join_live_network(network);
        }
    }

    /// Receipt valid over a wide logical window, for long concurrent runs in
    /// which every attempt observes a strictly later slot.
    #[cfg(feature = "pvm")]
    fn wide_management_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        sequence: u64,
        epoch: u64,
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        let mut receipt = clean_management_receipt(descriptor, request, sequence, authority_key);
        receipt.selector.epoch = epoch;
        receipt.selector.expires_at = 1_000_000;
        receipt.signature = authority_key.sign(&receipt.signing_bytes()).to_bytes();
        receipt.validate_shape().unwrap();
        receipt
    }

    /// Connect a newly started node to every live node of the mesh.
    #[cfg(feature = "network")]
    fn join_mesh(network: &crate::network::Network, live: &[&Arc<crate::network::Network>]) {
        for peer in live {
            network.connect(
                peer.listen_addrs()[0]
                    .clone()
                    .with(libp2p::multiaddr::Protocol::P2p(peer.peer_id())),
            );
        }
    }

    /// One ordered mutation attempt on whichever live replica leads. `Ok`
    /// carries a definitive submission; `Err` means no replica completed it.
    #[cfg(feature = "network")]
    fn manage_once(
        attachments: &Mutex<Vec<Option<crate::network::SharedAgentNetworkHost>>>,
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        joining: &[Vec<u8>],
    ) -> Result<crate::network::shared_agent::CleanManagementSubmission, SharedAgentHostError> {
        let mut attachments = attachments.lock().unwrap();
        let mut last = SharedAgentHostError::Unavailable;
        for attachment in attachments.iter_mut().flatten() {
            let _ = attachment.refresh();
            match attachment.manage_clean_with_replicas(
                agent,
                request.clone(),
                receipt.clone(),
                joining,
            ) {
                Ok(done) => return Ok(done),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Grow one voter to three with brand-new nodes (fresh keys, empty
    /// stores) while ordered mutations run concurrently, then replace a
    /// killed voter with another brand-new node. Every acknowledged mutation
    /// is retained with its exact result on every voter, and the replicated
    /// state commitment is identical on all of them.
    ///
    /// A second replacement is refused, not wedged: vos-raft starts no new
    /// membership change until every removed voter acknowledges its final
    /// configuration, which a dead voter never does.
    #[cfg(all(feature = "network", feature = "pvm"))]
    #[test]
    fn fresh_joiners_grow_and_replace_voters_under_concurrent_mutations() {
        init_replica_test_tracing();
        use crate::network::shared_agent::CleanManagementSubmission;
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        const GENESIS: u8 = 0x31;
        let fixture = committee_change_fixture(0x5b, &[(GENESIS, ReplicaRole::Voter)]);
        let agent = fixture.agent;
        let authority = descriptor_committee_authority(&fixture.descriptor);
        let slot = Arc::new(AtomicU64::new(20));
        let sequence = Arc::new(AtomicU64::new(1));
        let epoch = Arc::new(AtomicU64::new(1));
        let next_receipt = |request: &crate::agent_sdk::ManagementRequest, epoch: u64| {
            slot.fetch_add(1, Ordering::SeqCst);
            wide_management_receipt(
                &fixture.descriptor,
                request,
                sequence.fetch_add(1, Ordering::SeqCst) + 1,
                epoch,
                &fixture.authority_key,
            )
        };

        // Node registry: seed -> (store, host, network). Index i of every
        // vector belongs to the same node; `None` once the node is lost.
        let mut seeds = vec![GENESIS];
        let mut directories = vec![TempDirectory::new("fresh_joiner_genesis")];
        let mut hosts = vec![Some(Arc::new(Mutex::new({
            let mut host = open_native_clean_host_for_seed(
                &directories[0],
                &fixture,
                GENESIS,
                Arc::clone(&slot),
            );
            host.provision(
                fixture.provision.clone(),
                fixture.catalog.clone(),
                authority,
            )
            .unwrap();
            host
        })))];
        let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let mut networks = vec![Some(live_network(GENESIS, vec![listen.clone()]))];
        let attachments = Arc::new(Mutex::new(vec![Some(
            crate::network::SharedAgentNetworkHost::attach(
                Arc::clone(hosts[0].as_ref().unwrap()),
                Arc::clone(networks[0].as_ref().unwrap()),
            )
            .unwrap(),
        )]));

        // A fresh node: new key, new empty store, explicit joiner provision.
        let start_joiner =
            |seed: u8,
             seeds: &mut Vec<u8>,
             directories: &mut Vec<TempDirectory>,
             hosts: &mut Vec<Option<Arc<Mutex<SharedAgentHost>>>>,
             networks: &mut Vec<Option<Arc<crate::network::Network>>>| {
                let directory = TempDirectory::new(&format!("fresh_joiner_{seed:02x}"));
                let mut host =
                    open_native_clean_host_for_seed(&directory, &fixture, seed, Arc::clone(&slot));
                assert_eq!(
                    host.provision(
                        fixture.provision.clone(),
                        fixture.catalog.clone(),
                        authority
                    )
                    .unwrap_err(),
                    SharedAgentHostError::ScopeMismatch,
                    "the default path never admits a non-member"
                );
                let status = host
                    .provision_joiner(
                        fixture.provision.clone(),
                        fixture.catalog.clone(),
                        authority,
                    )
                    .unwrap();
                assert_eq!(status.local_role, Some(ReplicaRole::Observer));
                assert!(
                    status.replicas.iter().all(|replica| replica.node
                        != NodeId::of_authenticated_peer(&peer_id(&key(seed))))
                );
                let host = Arc::new(Mutex::new(host));
                let network = live_network(seed, vec![listen.clone()]);
                assert!(wait_until(std::time::Duration::from_secs(5), || {
                    !network.listen_addrs().is_empty()
                }));
                join_mesh(&network, &networks.iter().flatten().collect::<Vec<_>>());
                let attachment = crate::network::SharedAgentNetworkHost::attach(
                    Arc::clone(&host),
                    Arc::clone(&network),
                )
                .unwrap();
                assert!(
                    attachment.attachment_for_test(agent).unwrap().1,
                    "passive worker"
                );
                attachments.lock().unwrap().push(Some(attachment));
                seeds.push(seed);
                directories.push(directory);
                hosts.push(Some(host));
                networks.push(Some(network));
            };

        // Install one actor, then keep toggling it from a background thread.
        let actor_package = super::super::package_admission::admitted_standard_query_actor_for_test(
            "fresh-joiner-worker",
            crate::agent_sdk::StateLane::Linear,
            0x77,
        );
        let install = clean_install_request(fixture.descriptor.identity.agent, &actor_package);
        let install_receipt = next_receipt(&install, 1);
        let entry = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let result = {
                    let mut attachments = attachments.lock().unwrap();
                    let attachment = attachments[0].as_mut().unwrap();
                    let _ = attachment.refresh();
                    attachment.manage_clean(
                        agent,
                        install.clone(),
                        install_receipt.clone(),
                        SdkManagementArtifacts::Actor(&actor_package),
                    )
                };
                if let Ok(CleanManagementSubmission::Applied {
                    outcome:
                        crate::agent_sdk::RuntimeOutcome::Management(Ok(
                            crate::agent_sdk::ManagementReply::Installed(entry),
                        )),
                    ..
                }) = result
                {
                    break entry;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "Install: {:?}",
                    result.err()
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(AtomicUsize::new(0));
        // Phase of the most recent acknowledgement, plus one (0: none yet).
        let last_ack = Arc::new(AtomicUsize::new(0));
        let mutations = {
            let attachments = Arc::clone(&attachments);
            let stop = Arc::clone(&stop);
            let phase = Arc::clone(&phase);
            let last_ack = Arc::clone(&last_ack);
            let entry = entry.clone();
            let slot = Arc::clone(&slot);
            let sequence = Arc::clone(&sequence);
            let epoch = Arc::clone(&epoch);
            let descriptor = fixture.descriptor.clone();
            let authority_key = fixture.authority_key.clone();
            std::thread::spawn(move || {
                let mut acknowledged = Vec::new();
                let mut suspended = false;
                let mut pending: Option<(
                    crate::agent_sdk::ManagementRequest,
                    crate::agent_sdk::authority::AuthorityReceipt,
                )> = None;
                while !stop.load(Ordering::Acquire) {
                    let (request, receipt) = pending.take().unwrap_or_else(|| {
                        let request = if suspended {
                            crate::agent_sdk::ManagementRequest::Resume {
                                actor: entry.actor,
                                expected_deployment: entry.deployment,
                            }
                        } else {
                            crate::agent_sdk::ManagementRequest::Suspend {
                                actor: entry.actor,
                                expected_deployment: entry.deployment,
                            }
                        };
                        let receipt = wide_management_receipt(
                            &descriptor,
                            &request,
                            sequence.fetch_add(1, Ordering::SeqCst) + 1,
                            epoch.load(Ordering::SeqCst),
                            &authority_key,
                        );
                        (request, receipt)
                    });
                    slot.fetch_add(1, Ordering::SeqCst);
                    match manage_once(&attachments, agent, &request, &receipt, &[]) {
                        Ok(CleanManagementSubmission::Applied {
                            outcome: outcome @ crate::agent_sdk::RuntimeOutcome::Management(Ok(_)),
                            ..
                        }) => {
                            suspended = !suspended;
                            let acknowledged_phase = phase.load(Ordering::Acquire);
                            acknowledged.push((acknowledged_phase, request, receipt, outcome));
                            last_ack.store(acknowledged_phase + 1, Ordering::Release);
                        }
                        // A definitive refusal consumed nothing that could later
                        // apply: sign a fresh decision (sequence/slot races with
                        // the replica change are expected).
                        Ok(_) => {}
                        // Not definitive (no leader, transition barrier, fence,
                        // lost reply): retry the exact same decision, which is
                        // idempotent if it did commit.
                        Err(_) => pending = Some((request, receipt)),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                (acknowledged, suspended)
            })
        };

        // Drive one replica change on the current leader. A refused
        // descriptor leg (raced by a concurrent decision) is re-signed.
        let drive_change = |roster: &[crate::agent_sdk::AgentReplica],
                            expected_generation: crate::agent_sdk::Hash,
                            change_epoch: u64,
                            joining: &[Vec<u8>]| {
            let change = crate::agent_sdk::ManagementRequest::ChangeReplicas {
                expected_generation,
                replicas: roster.to_vec(),
            };
            let mut receipt = next_receipt(&change, change_epoch);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            let mut last;
            loop {
                slot.fetch_add(1, Ordering::SeqCst);
                match manage_once(&attachments, agent, &change, &receipt, joining) {
                    Ok(CleanManagementSubmission::Applied {
                        outcome:
                            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                                crate::agent_sdk::ManagementReply::ReplicasChanged { .. },
                            )),
                        ..
                    }) => return Ok(()),
                    Ok(CleanManagementSubmission::CommitteeTransition { stable, .. }) => {
                        last = format!("committee leg pending (stable={stable})");
                    }
                    Err(error) => last = format!("refused: {error:?}"),
                    Ok(CleanManagementSubmission::Denied { outcome, .. }) => {
                        last = format!("denied: {outcome:?}");
                        receipt = next_receipt(&change, change_epoch);
                    }
                    Ok(CleanManagementSubmission::Applied { outcome, .. }) => {
                        last = format!("applied without change: {outcome:?}");
                        receipt = next_receipt(&change, change_epoch);
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return Err(last);
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        };
        let live_voters =
            |hosts: &[Option<Arc<Mutex<SharedAgentHost>>>], seeds: &[u8], voters: &[u8]| {
                voters
                    .iter()
                    .map(|seed| {
                        Arc::clone(
                            hosts[seeds
                                .iter()
                                .position(|candidate| candidate == seed)
                                .unwrap()]
                            .as_ref()
                            .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
        let converge = |voters: &[Arc<Mutex<SharedAgentHost>>],
                        roster: &[crate::agent_sdk::AgentReplica]| {
            let voters = voters.iter().collect::<Vec<_>>();
            wait_until(std::time::Duration::from_secs(60), || {
                attachments
                    .lock()
                    .unwrap()
                    .iter_mut()
                    .flatten()
                    .for_each(|attachment| {
                        let _ = attachment.refresh();
                    });
                committee_converged(&voters, agent, roster)
            })
        };
        let diagnose = |hosts: &[Option<Arc<Mutex<SharedAgentHost>>>],
                        networks: &[Option<Arc<crate::network::Network>>]| {
            let attachments = attachments.lock().unwrap();
            hosts
                .iter()
                .zip(attachments.iter())
                .zip(networks)
                .filter_map(|((host, attachment), network)| {
                    Some(replica_diagnostics(
                        host.as_ref()?,
                        attachment.as_ref(),
                        network.as_ref()?,
                        agent,
                    ))
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Wait until a mutation is acknowledged in `wanted`, which also proves
        // a leader exists among the live voters.
        let await_ack = |wanted: usize| {
            wait_until(std::time::Duration::from_secs(60), || {
                last_ack.load(Ordering::Acquire) == wanted + 1
            })
        };
        assert!(
            await_ack(0),
            "no mutation acknowledged in phase 0:\n{}",
            diagnose(&hosts, &networks)
        );

        // (1) Grow 1 -> 3 with two brand-new nodes.
        for seed in [0x61, 0x62] {
            start_joiner(
                seed,
                &mut seeds,
                &mut directories,
                &mut hosts,
                &mut networks,
            );
        }
        let joining = [peer_id(&key(0x61)), peer_id(&key(0x62))];
        let grown = seeded_roster(&[
            (GENESIS, ReplicaRole::Voter),
            (0x61, ReplicaRole::Voter),
            (0x62, ReplicaRole::Voter),
        ]);
        phase.store(1, Ordering::Release);
        if let Err(last) =
            drive_change(&grown, fixture.descriptor.replica_generation(), 1, &joining)
        {
            panic!(
                "growth did not complete ({last}):\n{}",
                diagnose(&hosts, &networks)
            );
        }
        epoch.store(2, Ordering::SeqCst);
        let mut voters = vec![GENESIS, 0x61, 0x62];
        assert!(
            converge(&live_voters(&hosts, &seeds, &voters), &grown),
            "growth did not converge:\n{}",
            diagnose(&hosts, &networks)
        );
        let grown_generation = crate::agent_sdk::replica_set_generation(
            &fixture.descriptor.identity,
            fixture.descriptor.creation_nonce,
            &grown,
        );

        // (2) Kill a voter, wait for a leader among the survivors, then
        // replace it with a brand-new node.
        let kill = |seed: u8,
                    seeds: &[u8],
                    hosts: &mut Vec<Option<Arc<Mutex<SharedAgentHost>>>>,
                    networks: &mut Vec<Option<Arc<crate::network::Network>>>| {
            let index = seeds
                .iter()
                .position(|candidate| *candidate == seed)
                .unwrap();
            drop(attachments.lock().unwrap()[index].take());
            drop(hosts[index].take());
            join_live_network(networks[index].take().unwrap());
        };
        assert!(
            await_ack(1),
            "no mutation acknowledged in phase 1:\n{}",
            diagnose(&hosts, &networks)
        );
        kill(0x62, &seeds, &mut hosts, &mut networks);
        voters.retain(|seed| *seed != 0x62);
        phase.store(2, Ordering::Release);
        // Never change membership across a leader change: wait for the
        // survivors to elect a leader and commit before starting the change.
        assert!(
            await_ack(2),
            "no mutation acknowledged in phase 2:\n{}",
            diagnose(&hosts, &networks)
        );
        start_joiner(
            0x63,
            &mut seeds,
            &mut directories,
            &mut hosts,
            &mut networks,
        );
        let replaced = seeded_roster(&[
            (GENESIS, ReplicaRole::Voter),
            (0x61, ReplicaRole::Voter),
            (0x63, ReplicaRole::Voter),
        ]);
        if let Err(last) = drive_change(&replaced, grown_generation, 2, &[peer_id(&key(0x63))]) {
            panic!(
                "replacement did not complete ({last}):\n{}",
                diagnose(&hosts, &networks)
            );
        }
        epoch.store(3, Ordering::SeqCst);
        voters.push(0x63);
        assert!(
            converge(&live_voters(&hosts, &seeds, &voters), &replaced),
            "replacement did not converge:\n{}",
            diagnose(&hosts, &networks)
        );
        let replaced_generation = crate::agent_sdk::replica_set_generation(
            &fixture.descriptor.identity,
            fixture.descriptor.creation_nonce,
            &replaced,
        );
        phase.store(3, Ordering::Release);
        assert!(
            await_ack(3),
            "no mutation acknowledged in phase 3:\n{}",
            diagnose(&hosts, &networks)
        );

        // (3) The next replacement is refused before any slot is used: the
        // removed voter never acknowledges its retirement.
        kill(0x61, &seeds, &mut hosts, &mut networks);
        voters.retain(|seed| *seed != 0x61);
        phase.store(4, Ordering::Release);
        // Two of three voters still elect and commit.
        assert!(
            await_ack(4),
            "no mutation acknowledged in phase 4:\n{}",
            diagnose(&hosts, &networks)
        );
        start_joiner(
            0x64,
            &mut seeds,
            &mut directories,
            &mut hosts,
            &mut networks,
        );
        let blocked = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: replaced_generation,
            replicas: seeded_roster(&[
                (GENESIS, ReplicaRole::Voter),
                (0x63, ReplicaRole::Voter),
                (0x64, ReplicaRole::Voter),
            ]),
        };
        let blocked_receipt = next_receipt(&blocked, 3);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            slot.fetch_add(1, Ordering::SeqCst);
            let attempt = manage_once(
                &attachments,
                agent,
                &blocked,
                &blocked_receipt,
                &[peer_id(&key(0x64))],
            );
            assert!(
                attempt.is_err(),
                "a membership change with an unacknowledged retirement must be refused:\n{}",
                diagnose(&hosts, &networks)
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let survivors = live_voters(&hosts, &seeds, &voters);
        for host in &survivors {
            assert_eq!(
                host.lock()
                    .unwrap()
                    .show(agent)
                    .unwrap()
                    .unwrap()
                    .committee_transition,
                None,
                "a refused change leaves no prepared transition behind"
            );
        }
        stop.store(true, Ordering::Release);
        let (acknowledged, suspended) = mutations.join().unwrap();
        for wanted in 0..=4 {
            assert!(
                acknowledged.iter().any(|(phase, ..)| *phase == wanted),
                "no mutation was acknowledged in phase {wanted}"
            );
        }
        assert!(
            converge(&survivors, &replaced),
            "survivors did not converge:\n{}",
            diagnose(&hosts, &networks)
        );

        // No acknowledged mutation is lost: each exact decision is retained
        // with its acknowledged result on every surviving voter, and the
        // final directory reflects the last acknowledged toggle.
        for host in &survivors {
            let mut host = host.lock().unwrap();
            for (_, request, receipt, outcome) in &acknowledged {
                let prepared = host
                    .prepare_clean_management(
                        agent,
                        request.clone(),
                        receipt.clone(),
                        SdkManagementArtifacts::None,
                    )
                    .unwrap();
                assert_eq!(prepared.retained(), Some(outcome));
            }
        }
        for host in &survivors {
            let (_, _, actors) = replicated_state(host, agent).unwrap();
            let record = actors
                .entries
                .iter()
                .find(|record| record.entry.actor == entry.actor)
                .expect("installed actor survives every replacement");
            assert_eq!(record.entry.suspended, suspended);
        }

        drop(survivors);
        drop(attachments);
        drop(hosts);
        for network in networks.into_iter().flatten() {
            join_live_network(network);
        }
    }

    /// Submit one exact clean management request to whichever live replica
    /// currently leads. Followers and fenced owners refuse without a slot;
    /// a committee leg is resubmitted until the descriptor leg completes.
    #[cfg(feature = "network")]
    fn manage_live(
        attachments: &mut [Option<crate::network::SharedAgentNetworkHost>],
        agent: AgentId,
        request: &crate::agent_sdk::ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> crate::network::shared_agent::CleanManagementSubmission {
        use crate::network::shared_agent::CleanManagementSubmission;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut last = None;
        loop {
            for attachment in attachments.iter_mut().flatten() {
                let result = attachment.refresh().and_then(|()| {
                    attachment.manage_clean(agent, request.clone(), receipt.clone(), artifacts)
                });
                match result {
                    Ok(CleanManagementSubmission::CommitteeTransition { .. }) => {}
                    Ok(done) => return done,
                    Err(error) => last = Some(error),
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no live replica completed the request; last refusal {last:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}
