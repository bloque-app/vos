//! Signed, runtime-independent replay adapter for the experimental Local
//! journal. It owns no filesystem authority: the lifecycle owner must first
//! select the exact admitted package and genesis, then retain the locked store.

use super::driver::{DEFAULT_MANAGEMENT_GAS, SdkManagementArtifacts};
use super::execution::MAX_EXECUTION_GAS;
use super::journal::{
    AgentJournalGenesis, AgentJournalGenesisId, CanonicalJournalRecord, LaneCursor,
    LaneStateManifest, PersistedLane, ReplayInput, ReplayInputId, ReplayOperation, RuntimeBinding,
};
use super::journal_store::CatalogBlobResolver;
use super::local_journal_driver::LocalReplayExecutorError;
use super::package_admission::{AdmittedStateRuntimePackage, admit_actor_package};
use super::replay::{
    ReplayExecutor, ReplayExternalExecution, ReplayPosition, ReplayTransition, ScopedBlockReader,
};
use super::state_block_pvm::{BlockPvmError, MultiLaneStateBlockHost};
use super::wire::RuntimeState;
use crate::agent_sdk::{
    AgentDescriptor, AgentProfile, InvocationAuthorization, InvocationRetirement,
    ManagementRequest, RuntimeOutcome, state_blocks::ReadBudget,
};
use crate::service::{AgentId, BlobRef, SpaceId};

/// Stable across CMI4 authorization/finalization envelope updates. The
/// request and credential call are immutable for one pledged Create, so the
/// file slot cannot be rebound by a later lifecycle phase or another caller.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) fn external_local_create_intent_hash(
    intent: &super::clean_management_intent::CleanManagementIntent,
) -> crate::service::Hash {
    crate::service::Hash::digest(
        b"vos/agent/local/external-create-intent/v1",
        &[
            &intent.request().commitment().0,
            &intent.call().commitment().0,
        ],
    )
}

#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) fn state_runtime_matches_descriptor(
    descriptor: &AgentDescriptor,
    runtime: &AdmittedStateRuntimePackage,
) -> bool {
    descriptor.validate().is_ok()
        && descriptor.identity.profile == AgentProfile::Local
        && descriptor.runtime_package == *runtime.package_ref()
        && descriptor.identity.runtime_deployment == runtime.deployment()
        && descriptor.identity.runtime_program == runtime.program()
        && descriptor.identity.runtime_producer == runtime.manifest().signing.producer
        && descriptor.runtime_contract == runtime.manifest().contract
        && descriptor.capabilities == runtime.manifest().capabilities
}

/// Reconstructed only from the existing signed Local lifecycle's durable
/// intent/runtime sidecar and the exact receipt recovered from its issuer.
/// Preparing this value executes physical Create but does not stage a journal,
/// sign an application ACK, or expose a route. The lifecycle caller must first
/// authenticate the retained authorization anchor against its independently
/// selected system journal; the intent image alone cannot prove that anchor.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct RetainedExternalLocalCreate {
    seal: super::replay::ReplaySealedExternalLocalGenesis,
    runtime_package: Vec<u8>,
    intent: crate::service::Hash,
}

/// Immutable recovery input for the original Create after the per-Agent CMI4
/// slot has handed off to Install. The exact runtime package remains in the
/// lifecycle runtime sidecar; neither this record nor its file envelope is
/// authority. Startup must independently verify the selected Authority and
/// the physical journal before publishing routes.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct ExternalLocalCreateArchive {
    intent: super::clean_management_intent::CleanManagementIntent,
    receipt: crate::agent_sdk::authority::AuthorityReceipt,
    acknowledgement: crate::agent_sdk::authority::ManagementApplicationAck,
    genesis: AgentJournalGenesisId,
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl ExternalLocalCreateArchive {
    pub(crate) const MAX_BYTES: usize =
        super::clean_authority_issuer::MAX_CLEAN_EXTERNAL_LOCAL_CREATE_ARCHIVE_BYTES;

    pub(crate) fn intent(&self) -> &super::clean_management_intent::CleanManagementIntent {
        &self.intent
    }

    pub(crate) fn acknowledgement(&self) -> &crate::agent_sdk::authority::ManagementApplicationAck {
        &self.acknowledgement
    }

    pub(crate) fn new(
        intent: super::clean_management_intent::CleanManagementIntent,
        receipt: crate::agent_sdk::authority::AuthorityReceipt,
        acknowledgement: crate::agent_sdk::authority::ManagementApplicationAck,
        genesis: AgentJournalGenesisId,
    ) -> Result<Self, crate::service::wire::DecodeError> {
        let archive = Self {
            intent,
            receipt,
            acknowledgement,
            genesis,
        };
        archive.validate_shape()?;
        Ok(archive)
    }

    fn validate_shape(&self) -> Result<(), crate::service::wire::DecodeError> {
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeWork};
        use crate::service::wire::DecodeError;
        let ManagementRequest::Create(descriptor) = self.intent.request() else {
            return Err(DecodeError::NonCanonical);
        };
        let Some(RuntimeWork::Invoke { observed_slot, .. }) = self.intent.authorization_work()
        else {
            return Err(DecodeError::NonCanonical);
        };
        let Some(RuntimeWork::Invoke { invocation, .. }) = self.intent.finalization_work() else {
            return Err(DecodeError::NonCanonical);
        };
        if self.genesis == AgentJournalGenesisId::ZERO
            || self
                .intent
                .verify(
                    self.acknowledgement.authority,
                    self.acknowledgement.managed,
                    &super::clean_bootstrap::RawCredentialVerifier,
                )
                .is_err()
            || self
                .acknowledgement
                .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
                .is_err()
            || self.acknowledgement.receipt != self.receipt
            || self.acknowledgement.credential_call != self.intent.call().commitment()
            || self.acknowledgement.request != self.intent.request().replay_commitment()
            || self.acknowledgement.application
                != ManagementReply::Created(descriptor.identity.clone())
            || self.acknowledgement.applied_at < *observed_slot
            || invocation.message
                != super::clean_management_intent::CleanManagementIntent::finalization_message(
                    &self.acknowledgement,
                )
            || super::driver::verify_clean_management_receipt(
                descriptor,
                self.intent.request(),
                &self.receipt,
                *observed_slot,
                true,
            )
            .is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// A later lifecycle operation may replace CMI4/CIS2, but it cannot
    /// select a different original Create for this Agent's stable lock.
    pub(crate) fn matches_current_scope(
        &self,
        current: &super::clean_management_intent::CleanManagementIntent,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        selected_node: crate::agent_sdk::NodeId,
    ) -> bool {
        let ManagementRequest::Create(descriptor) = self.intent.request() else {
            return false;
        };
        self.validate_shape().is_ok()
            && self.intent.call().authority == selected_authority
            && current.call().authority == selected_authority
            && self.intent.call().managed == current.call().managed
            && descriptor.replicas.len() == 1
            && descriptor.replicas[0].node == selected_node
            && matches!(
                current.request(),
                ManagementRequest::Create(_) | ManagementRequest::Install(_)
            )
            && (!matches!(current.request(), ManagementRequest::Create(_))
                || (current.request() == self.intent.request()
                    && current.call() == self.intent.call()))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::ServiceWire as _;
        let mut bytes = b"ELC1".to_vec();
        let mut encoder = crate::service::wire::Encoder(&mut bytes);
        encoder.bytes(&self.intent.encode());
        encoder.bytes(&self.receipt.encode().expect("validated receipt"));
        encoder.bytes(&self.acknowledgement.encode().expect("validated ACK"));
        encoder.fixed(self.genesis.as_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::service::wire::{DecodeError, Decoder, ServiceWire as _};
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"ELC1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let intent_bytes = decoder.bytes_ref()?;
        let receipt_bytes = decoder.bytes_ref()?;
        let acknowledgement_bytes = decoder.bytes_ref()?;
        let genesis = AgentJournalGenesisId(decoder.fixed()?);
        if !decoder.exhausted()
            || intent_bytes.len() > super::clean_management_intent::MAX_INTENT_BYTES
            || receipt_bytes.len() > crate::agent_sdk::wire::MAX_AUTHORITY_RECEIPT_WIRE_BYTES
            || acknowledgement_bytes.len()
                > crate::agent_sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
        {
            return Err(DecodeError::NonCanonical);
        }
        let archive = Self::new(
            super::clean_management_intent::CleanManagementIntent::decode(intent_bytes)?,
            crate::agent_sdk::authority::AuthorityReceipt::decode(receipt_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
            crate::agent_sdk::authority::ManagementApplicationAck::decode(acknowledgement_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
            genesis,
        )?;
        if archive.encode() != bytes {
            return Err(DecodeError::NonCanonical);
        }
        Ok(archive)
    }

    pub(crate) fn prepare(
        &self,
        runtime_package: Vec<u8>,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        selected_node: crate::agent_sdk::NodeId,
    ) -> Result<RetainedExternalLocalCreate, super::shared_host::SharedAgentHostError> {
        use super::shared_host::SharedAgentHostError;
        self.validate_shape()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if self.acknowledgement.authority != selected_authority {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let prepared = RetainedExternalLocalCreate::prepare_from_retained(
            &self.intent,
            runtime_package,
            selected_authority,
            &self.receipt,
            selected_node,
        )?;
        if prepared.seal.genesis().id() != self.genesis {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(prepared)
    }

    /// Reopen the exact physical generation using only the immutable Create
    /// archive and runtime sidecar, even if CMI4 now names a later Install.
    /// The caller must already have authenticated the archive's system
    /// lifecycle against its independently selected Authority; this method
    /// verifies the signed Create, physical genesis, journal and Create ACK.
    pub(crate) fn open_existing(
        &self,
        runtime_package: Vec<u8>,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        selected_node: crate::agent_sdk::NodeId,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        budget: &mut ReadBudget,
    ) -> Result<ExternalLocalJournalOwner, super::shared_host::SharedAgentHostError> {
        use super::shared_host::SharedAgentHostError;
        if directory.space() != SpaceId(selected_authority.space.0)
            || directory.node() != crate::service::NodeId(selected_node.0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let prepared = self.prepare(runtime_package, selected_authority, selected_node)?;
        let agent = AgentId(self.intent.call().managed.agent.0);
        let slot = directory
            .acquire_existing(agent, prepared.intent())
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let (seal, _) = prepared.into_parts();
        let owner = ExternalLocalJournalOwner::open(slot, seal, budget)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        owner
            .verify_finalized_create_ack(&self.acknowledgement)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        Ok(owner)
    }

    /// Bind a later Install slot to the original signed Create generation
    /// while its file owner is already locked. This avoids releasing the
    /// owner merely to reopen the same generation for lifecycle admission.
    pub(crate) fn matches_owner(
        &self,
        current: &super::clean_management_intent::CleanManagementIntent,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        selected_node: crate::agent_sdk::NodeId,
        owner: &ExternalLocalJournalOwner,
    ) -> bool {
        let crate::agent_sdk::ManagementRequest::Create(descriptor) = self.intent.request() else {
            return false;
        };
        self.matches_current_scope(current, selected_authority, selected_node)
            && self.acknowledgement.authority == selected_authority
            && self.genesis == owner.genesis_id()
            && descriptor.as_ref() == owner.descriptor()
            && owner
                .verify_finalized_create_ack(&self.acknowledgement)
                .is_ok()
    }
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl RetainedExternalLocalCreate {
    pub(crate) fn prepare<B: super::clean_authority_issuer::CleanManagementRuntimeStore>(
        slot: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        issued_receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        selected_node: crate::agent_sdk::NodeId,
    ) -> Result<Self, super::shared_host::SharedAgentHostError> {
        use super::shared_host::SharedAgentHostError;
        if slot
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let runtime_package = slot
            .load_runtime()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        let intent = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
        Self::prepare_from_retained(
            intent,
            runtime_package,
            selected_authority,
            issued_receipt,
            selected_node,
        )
    }

    /// Reconstruct the exact physical Create seal from authenticated retained
    /// inputs without requiring the current mutable lifecycle slot to still
    /// contain Create. An immutable startup archive will supply these bytes
    /// after later Install operations hand off that slot. This function does
    /// not itself prove Authority actor finality or journal publication.
    pub(crate) fn prepare_from_retained(
        intent: &super::clean_management_intent::CleanManagementIntent,
        runtime_package: Vec<u8>,
        selected_authority: crate::agent_sdk::authority::AuthorityActorTarget,
        issued_receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        selected_node: crate::agent_sdk::NodeId,
    ) -> Result<Self, super::shared_host::SharedAgentHostError> {
        use super::shared_host::SharedAgentHostError;
        use crate::agent_sdk::{self as sdk, AgentProfile, ManagementRequest, RuntimeWork};

        if selected_node == sdk::NodeId::ZERO {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let ManagementRequest::Create(descriptor) = intent.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let descriptor = descriptor.as_ref().clone();
        if descriptor.identity.profile != AgentProfile::Local
            || descriptor.identity.space != selected_authority.space
            || descriptor.authority != selected_authority.binding
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != selected_node
            || descriptor.replicas[0].role != sdk::ReplicaRole::Voter
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        intent
            .verify(
                selected_authority,
                intent.call().managed,
                &super::clean_bootstrap::RawCredentialVerifier,
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let request = intent.request().clone();
        let intent_hash = external_local_create_intent_hash(intent);
        let Some(RuntimeWork::Invoke { observed_slot, .. }) = intent.authorization_work() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let observed_slot = *observed_slot;
        super::driver::verify_clean_management_receipt(
            &descriptor,
            &request,
            issued_receipt,
            observed_slot,
            true,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let runtime = super::package_admission::admit_state_runtime_package(&runtime_package)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        if !state_runtime_matches_descriptor(&descriptor, &runtime) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let binding = runtime
            .binding(
                SpaceId(descriptor.identity.space.0),
                AgentId(descriptor.identity.agent.0),
            )
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let replica = descriptor.replicas[0];
        let seal = super::local_journal_driver::LocalJournalAgentDriver::<
            super::journal_store::MemoryAgentJournalStore,
        >::prepare_external_local_genesis(
            ReplayInput {
                runtime: binding,
                operation: ReplayOperation::CleanManage {
                    request,
                    authority: issued_receipt.clone(),
                    observed_slot,
                },
            },
            super::AgentReplica {
                node: crate::service::NodeId(replica.node.0),
                principal: crate::service::PrincipalId(replica.principal.0),
                role: super::ReplicaRole::Voter,
            },
            &[super::execution::RuntimeBlob {
                reference: BlobRef {
                    hash: crate::service::Hash(runtime.package_ref().hash.0),
                    len: runtime.package_ref().len,
                },
                bytes: runtime_package.clone(),
            }],
            crate::service::NodeId(selected_node.0),
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(Self {
            seal,
            runtime_package,
            intent: intent_hash,
        })
    }

    pub(crate) fn intent(&self) -> crate::service::Hash {
        self.intent
    }

    /// Stage exact catalog bytes and the complete checkpoint-bearing Create
    /// closure under this signed intent's locked slot. Exposure is a durable
    /// storage marker, not route publication or Authority finalization. A
    /// crash can repeat this method only while the generation is still at its
    /// initial head; finalized retries with later work reopen the owner and
    /// verify the old ACK instead.
    pub(crate) fn publish_initial(
        self,
        slot: super::journal_store::FileLocalAgentJournalSlot,
        budget: &mut ReadBudget,
    ) -> Result<ExternalLocalJournalOwner, super::journal_store::JournalStoreError> {
        use super::journal_store::{AgentJournalStore, JournalBlobClass, JournalStoreError};
        if slot.intent() != self.intent {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let mut store = slot.open_external_genesis(&self.seal, false, budget)?;
        store.put_blob(
            JournalBlobClass::CatalogArtifact,
            &self.seal.genesis().runtime().package,
            &self.runtime_package,
        )?;
        store.initialize_external_local(&self.seal, budget)?;
        store.commit_external_genesis_exposure(&self.seal, self.intent, budget)?;
        let owner = ExternalLocalJournalOwner::adopt_initial_store(store, self.seal, budget)?;
        owner.observe_create_application()?;
        Ok(owner)
    }

    pub(crate) fn into_parts(self) -> (super::replay::ReplaySealedExternalLocalGenesis, Vec<u8>) {
        (self.seal, self.runtime_package)
    }
}

struct AuthenticatedExternalInput {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
}

/// The greatest valid directory cursor strictly below one nonzero ActorId.
/// InspectActors is exclusive of `after`, so a one-entry page is a targeted
/// lookup even when unrelated actors occupy the same Agent directory.
pub(crate) fn actor_cursor_before(
    actor: crate::agent_sdk::ActorId,
) -> Option<crate::agent_sdk::ActorId> {
    if actor == crate::agent_sdk::ActorId::ZERO {
        return None;
    }
    let mut bytes = actor.0;
    for byte in bytes.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            break;
        }
        *byte = u8::MAX;
    }
    (bytes != [0; 32]).then_some(crate::agent_sdk::ActorId(bytes))
}

/// Reconstruct one immutable route closure from an authenticated directory
/// record and exact catalog blobs. The caller supplies only a resolver owned
/// by its pinned journal; every returned byte is checked against the signed
/// package and current directory, including schema and constructor layout.
#[cfg(all(target_os = "linux", feature = "storage"))]
fn physical_material_from_catalog(
    descriptor: &AgentDescriptor,
    record: crate::agent_sdk::ActorDirectoryRecord,
    observed_slot: u64,
    mut load: impl FnMut(
        &crate::agent_sdk::BlobRef,
    ) -> Result<Vec<u8>, super::journal_store::JournalStoreError>,
) -> Result<
    super::invocation_preparation::PhysicalInvocationMaterial,
    super::journal_store::JournalStoreError,
> {
    use super::journal_store::JournalStoreError;
    use crate::agent_sdk::{self as sdk, RuntimeBlob};

    fn exact(
        reference: &sdk::BlobRef,
        load: &mut impl FnMut(&sdk::BlobRef) -> Result<Vec<u8>, JournalStoreError>,
    ) -> Result<Vec<u8>, JournalStoreError> {
        let bytes = load(reference)?;
        reference
            .matches(&bytes)
            .then_some(bytes)
            .ok_or(JournalStoreError::Corrupt)
    }

    if descriptor.validate().is_err()
        || descriptor.identity.profile != AgentProfile::Local
        || record.validate().is_err()
        || record.entry.suspended
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let entry = &record.entry;
    let package_bytes = exact(&entry.package, &mut load)?;
    let package = admit_actor_package(&package_bytes).map_err(|_| JournalStoreError::Corrupt)?;
    let program = exact(&package.manifest().program, &mut load)?;
    let schema = exact(&entry.agent_schema, &mut load)?;
    let policies = exact(&entry.method_policy, &mut load)?;
    let parsed = sdk::schema::decode(&schema).map_err(|_| JournalStoreError::Corrupt)?;
    let installation_data = entry
        .installation_data
        .as_ref()
        .map(|reference| {
            exact(reference, &mut load).map(|bytes| RuntimeBlob {
                reference: reference.clone(),
                bytes,
            })
        })
        .transpose()?;
    if package.deployment() != entry.deployment
        || package.program() != entry.program
        || package.package_ref() != &entry.package
        || package.manifest().state_lane_schema != entry.agent_schema
        || package.manifest().method_policy != entry.method_policy
        || program != package.program_bytes()
        || schema != package.state_lane_schema_bytes()
        || policies != package.method_policy_bytes()
        || parsed
            .constructor_abi()
            .map_err(|_| JournalStoreError::Corrupt)?
            != entry.constructor_abi
        || parsed
            .state_layout_hash()
            .map_err(|_| JournalStoreError::Corrupt)?
            != entry.state_layout
        || parsed.lanes() != entry.lanes
        || parsed.requires_installation_data() != installation_data.is_some()
        || !package.requirements().supported_by(AgentProfile::Local)
        || !descriptor
            .runtime_contract
            .supports(package.manifest().contract)
        || !descriptor.capabilities.satisfies(package.requirements())
    {
        return Err(JournalStoreError::Corrupt);
    }
    let schema_ref = entry.agent_schema.clone();
    let policy_ref = entry.method_policy.clone();
    Ok(super::invocation_preparation::PhysicalInvocationMaterial {
        descriptor: descriptor.clone(),
        install_request: record.install_request,
        actor: record,
        producer: package.producer(),
        contract: package.manifest().contract,
        requirements: package.requirements(),
        root_provenance: false,
        observed_slot,
        program: RuntimeBlob {
            reference: package.manifest().program.clone(),
            bytes: program,
        },
        schema: RuntimeBlob {
            reference: schema_ref,
            bytes: schema,
        },
        policies: RuntimeBlob {
            reference: policy_ref,
            bytes: policies,
        },
        installation_data,
    })
}

/// A Create result re-observed from the locked external Local journal's
/// authenticated initial head. It is application evidence for the existing
/// management issuer, not Authority approval or route-publication finality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalLocalManagementObservation {
    receipt: crate::agent_sdk::authority::AuthorityReceipt,
    result: crate::agent_sdk::ManagementReply,
    reopened_state: crate::agent_sdk::Hash,
    applied_at: u64,
}

impl ExternalLocalManagementObservation {
    #[cfg(test)]
    pub(crate) fn for_issuer_test(
        receipt: crate::agent_sdk::authority::AuthorityReceipt,
        result: crate::agent_sdk::ManagementReply,
        reopened_state: crate::agent_sdk::Hash,
        applied_at: u64,
    ) -> Self {
        Self {
            receipt,
            result,
            reopened_state,
            applied_at,
        }
    }

    pub(crate) fn receipt(&self) -> &crate::agent_sdk::authority::AuthorityReceipt {
        &self.receipt
    }

    pub(crate) fn result(&self) -> &crate::agent_sdk::ManagementReply {
        &self.result
    }

    pub(crate) fn reopened_state(&self) -> crate::agent_sdk::Hash {
        self.reopened_state
    }

    pub(crate) fn applied_at(&self) -> u64 {
        self.applied_at
    }
}

/// A rejected Install re-observed from the authenticated journal, rather than
/// from a live preflight or a caller-supplied error. It is evidence for a
/// future signed failure-finality protocol, not finality by itself.
#[cfg(feature = "experimental-state-blocks")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalLocalManagementRejection {
    receipt: crate::agent_sdk::authority::AuthorityReceipt,
    error: crate::agent_sdk::ManagementError,
    reopened_state: crate::agent_sdk::Hash,
    applied_at: u64,
}

#[cfg(feature = "experimental-state-blocks")]
impl ExternalLocalManagementRejection {
    pub(crate) fn receipt(&self) -> &crate::agent_sdk::authority::AuthorityReceipt {
        &self.receipt
    }

    pub(crate) fn error(&self) -> crate::agent_sdk::ManagementError {
        self.error
    }

    pub(crate) fn reopened_state(&self) -> crate::agent_sdk::Hash {
        self.reopened_state
    }

    pub(crate) fn applied_at(&self) -> u64 {
        self.applied_at
    }
}

#[cfg(feature = "experimental-state-blocks")]
fn external_install_observation<'a>(
    recovered: &'a super::replay::ReplayMaterialization,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    domain: &'static [u8],
) -> Result<
    (
        &'a super::journal::CleanManagementEvidence,
        crate::agent_sdk::Hash,
    ),
    super::journal_store::JournalStoreError,
> {
    use super::journal_store::JournalStoreError;

    if !matches!(request, ManagementRequest::Install(_)) {
        return Err(JournalStoreError::NonCanonical);
    }
    let evidence = recovered
        .clean_management_evidence()
        .ok_or(JournalStoreError::Unavailable)?;
    let head = evidence.ordered.head.ok_or(JournalStoreError::Corrupt)?;
    if descriptor.validate().is_err()
        || descriptor.identity.profile != AgentProfile::Local
        || descriptor.identity.space.0 != recovered.runtime().space.0
        || descriptor.identity.agent.0 != recovered.runtime().agent.0
        || descriptor.identity.runtime_deployment.0 != recovered.runtime().deployment.0
        || evidence.ordered.index == 0
        || evidence.ordered.index > recovered.heads().ordered_index
        || evidence.input == ReplayInputId::ZERO
        || evidence.request != request.replay_commitment()
        || evidence.authority != receipt.commitment()
        || evidence.epoch != receipt.selector.epoch
        || evidence.sequence != receipt.selector.decision_sequence
        || super::driver::verify_clean_management_receipt(
            descriptor,
            request,
            receipt,
            evidence.observed_slot,
            false,
        )
        .is_err()
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    let reopened_state = crate::agent_sdk::Hash::digest(
        domain,
        &[
            &recovered.heads().genesis.0,
            &evidence.input.0,
            &head.0,
            &evidence.ordered.index.to_le_bytes(),
            &evidence.authority.0,
            &evidence.request.0,
            &evidence.observed_slot.to_le_bytes(),
        ],
    );
    Ok((evidence, reopened_state))
}

/// Derive a stable Install application identity from authenticated replay
/// evidence, not the current journal-head ID. A later Invoke, ACK or
/// maintenance checkpoint may change the head before the issuer retries its
/// acknowledgement; the retained management evidence still names the exact
/// successful Install and its original observation slot. A later management
/// mutation replaces that evidence; the lifecycle coordinator must retire
/// the prior operation before admitting its successor.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn observe_external_install_application(
    recovered: &super::replay::ReplayMaterialization,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<ExternalLocalManagementObservation, super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;
    use crate::agent_sdk::ManagementReply;

    let ManagementRequest::Install(install) = request else {
        return Err(JournalStoreError::NonCanonical);
    };
    let (evidence, reopened_state) = external_install_observation(
        recovered,
        descriptor,
        request,
        receipt,
        b"vos/agent/local/external-install-application/v1",
    )?;
    if evidence.result != Ok(ManagementReply::Installed(install.entry.clone())) {
        return Err(JournalStoreError::ScopeMismatch);
    }
    Ok(ExternalLocalManagementObservation {
        receipt: receipt.clone(),
        result: ManagementReply::Installed(install.entry.clone()),
        reopened_state,
        applied_at: evidence.observed_slot,
    })
}

/// Observe only a durably published guest rejection. Positive Install and
/// uncommitted preflight errors cannot manufacture this evidence.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn observe_external_install_rejection(
    recovered: &super::replay::ReplayMaterialization,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<ExternalLocalManagementRejection, super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;

    let (evidence, reopened_state) = external_install_observation(
        recovered,
        descriptor,
        request,
        receipt,
        b"vos/agent/local/external-install-rejection/v1",
    )?;
    let Err(error) = &evidence.result else {
        return Err(JournalStoreError::ScopeMismatch);
    };
    Ok(ExternalLocalManagementRejection {
        receipt: receipt.clone(),
        error: *error,
        reopened_state,
        applied_at: evidence.observed_slot,
    })
}

/// A finalized issuer ACK is an exact-retry input, not fresh permission to
/// install. Rebind it to the authenticated physical Install evidence before
/// a lifecycle handoff or route refresh may trust it.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn verify_external_install_ack(
    recovered: &super::replay::ReplayMaterialization,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    acknowledgement: &crate::agent_sdk::authority::ManagementApplicationAck,
) -> Result<(), super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;

    let observation =
        observe_external_install_application(recovered, descriptor, request, receipt)?;
    let identity = &descriptor.identity;
    // Authorization and issuer decision sequences are distinct clocks. The
    // retained issuer approval binds the former to this receipt; physical
    // verification must not equate their numeric values.
    if acknowledgement.validate_shape().is_err()
        || acknowledgement
            .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
            .is_err()
        || acknowledgement.authority.space != identity.space
        || acknowledgement.authority.binding != descriptor.authority
        || acknowledgement.managed.space != identity.space
        || acknowledgement.managed.agent != identity.agent
        || acknowledgement.managed.owner != identity.owner
        || acknowledgement.managed.profile != identity.profile
        || acknowledgement.managed.runtime_deployment != identity.runtime_deployment
        || acknowledgement.managed.transition_producer != identity.transition_producer
        || acknowledgement.request != request.replay_commitment()
        || acknowledgement.receipt != *receipt
        || acknowledgement.application != *observation.result()
        || acknowledgement.reopened_state != observation.reopened_state()
        || acknowledgement.applied_at != observation.applied_at()
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    Ok(())
}

#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn verify_external_install_failure(
    recovered: &super::replay::ReplayMaterialization,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    failure: &crate::agent_sdk::authority::ManagementApplicationFailure,
) -> Result<(), super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;

    let observation = observe_external_install_rejection(recovered, descriptor, request, receipt)?;
    let identity = &descriptor.identity;
    if failure
        .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
        .is_err()
        || failure.authority.space != identity.space
        || failure.authority.binding != descriptor.authority
        || failure.managed.space != identity.space
        || failure.managed.agent != identity.agent
        || failure.managed.owner != identity.owner
        || failure.managed.profile != identity.profile
        || failure.managed.runtime_deployment != identity.runtime_deployment
        || failure.managed.transition_producer != identity.transition_producer
        || failure.request != request.replay_commitment()
        || failure.receipt != *receipt
        || failure.error != observation.error()
        || failure.reopened_state != observation.reopened_state()
        || failure.failed_at != observation.applied_at()
    {
        return Err(JournalStoreError::ScopeMismatch);
    }
    Ok(())
}

/// One admitted external runtime, immutable actor catalog resolver and exact
/// genesis descriptor. No standard-runtime private state is decoded here.
/// Unsupported lifecycle forms fail closed until their external lane and
/// publication semantics are qualified.
pub(crate) struct ExternalLocalReplayExecutor<R> {
    runtime: AdmittedStateRuntimePackage,
    descriptor: AgentDescriptor,
    resolver: R,
    seeded: bool,
    seeded_genesis: Option<AgentJournalGenesisId>,
    authenticated: Option<AuthenticatedExternalInput>,
    pending: Option<ReplayExternalExecution>,
    // Keep a bounded replay window in each Ordered/Local domain. Execution is
    // a candidate until an authenticated durable suffix names its exact input
    // and position; this cache alone never authorizes a response.
    recent_outcomes: Vec<(ReplayInputId, ReplayPosition, RuntimeOutcome)>,
}

// Runtime result lanes retain at most 32 results. Keep the same bounded
// response-loss window per journal domain, including ACK outcomes; a miss must
// never cause a second physical execution or an invented response.
const MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN: usize = 32;

impl<R: CatalogBlobResolver> ExternalLocalReplayExecutor<R> {
    /// Rebind a snapshot resolver after catalog staging or rollback. The file
    /// resolver is live, but the in-memory adapter deliberately snapshots its
    /// blob map; neither may retain a rolled-back artifact as an input.
    pub(crate) fn replace_resolver(&mut self, resolver: R) {
        self.resolver = resolver;
    }

    pub(crate) fn new(
        runtime: AdmittedStateRuntimePackage,
        descriptor: AgentDescriptor,
        resolver: R,
    ) -> Result<Self, LocalReplayExecutorError> {
        if descriptor.identity.profile != AgentProfile::Local || descriptor.replicas.len() != 1 {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Self::new_admitted(runtime, descriptor, resolver)
    }

    pub(crate) fn new_shared(
        runtime: AdmittedStateRuntimePackage,
        descriptor: AgentDescriptor,
        resolver: R,
    ) -> Result<Self, LocalReplayExecutorError> {
        if !super::replay::external_shared_descriptor_supported(&descriptor) {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Self::new_admitted(runtime, descriptor, resolver)
    }

    fn new_admitted(
        runtime: AdmittedStateRuntimePackage,
        descriptor: AgentDescriptor,
        resolver: R,
    ) -> Result<Self, LocalReplayExecutorError> {
        let binding = runtime
            .binding(
                SpaceId(descriptor.identity.space.0),
                AgentId(descriptor.identity.agent.0),
            )
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        if descriptor.validate().is_err()
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_package != *runtime.package_ref()
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
            || binding.validate().is_err()
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(Self {
            runtime,
            descriptor,
            resolver,
            seeded: false,
            seeded_genesis: None,
            authenticated: None,
            pending: None,
            recent_outcomes: Vec::new(),
        })
    }

    fn remember_outcome(
        &mut self,
        input: ReplayInputId,
        position: ReplayPosition,
        outcome: RuntimeOutcome,
    ) -> Result<(), LocalReplayExecutorError> {
        if let Some((_, _, retained)) = self
            .recent_outcomes
            .iter()
            .find(|(seen, at, _)| *seen == input && *at == position)
        {
            return if *retained == outcome {
                Ok(())
            } else {
                Err(LocalReplayExecutorError::InvalidState)
            };
        }
        if !matches!(
            position,
            ReplayPosition::Ordered { .. } | ReplayPosition::Local { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        let same_domain = |candidate| {
            matches!(
                (candidate, position),
                (
                    ReplayPosition::Ordered { .. },
                    ReplayPosition::Ordered { .. }
                ) | (ReplayPosition::Local { .. }, ReplayPosition::Local { .. })
            )
        };
        if self
            .recent_outcomes
            .iter()
            .filter(|(_, at, _)| same_domain(*at))
            .count()
            == MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN
        {
            let oldest = self
                .recent_outcomes
                .iter()
                .position(|(_, at, _)| same_domain(*at))
                .expect("full domain has an oldest entry");
            self.recent_outcomes.remove(oldest);
        }
        self.recent_outcomes.push((input, position, outcome));
        Ok(())
    }

    pub(crate) fn replayed_outcome(
        &self,
        input: ReplayInputId,
        position: ReplayPosition,
    ) -> Option<RuntimeOutcome> {
        self.recent_outcomes
            .iter()
            .find(|(retained_input, retained_position, _)| {
                *retained_input == input && *retained_position == position
            })
            .map(|(_, _, outcome)| outcome.clone())
    }

    fn binding(&self) -> Result<RuntimeBinding, LocalReplayExecutorError> {
        self.runtime
            .binding(
                SpaceId(self.descriptor.identity.space.0),
                AgentId(self.descriptor.identity.agent.0),
            )
            .map_err(|_| LocalReplayExecutorError::InvalidState)
    }

    pub(crate) fn runtime(&self) -> &AdmittedStateRuntimePackage {
        &self.runtime
    }

    pub(crate) fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }

    fn load(&self, reference: &BlobRef) -> Result<Vec<u8>, LocalReplayExecutorError> {
        let bytes = self
            .resolver
            .load_catalog(reference)?
            .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))?;
        if !reference.matches(&bytes) {
            return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
        }
        Ok(bytes)
    }

    fn check_install(&self, request: &ManagementRequest) -> Result<(), LocalReplayExecutorError> {
        let ManagementRequest::Install(install) = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        let package_ref = BlobRef {
            hash: crate::service::Hash(install.package.hash.0),
            len: install.package.len,
        };
        let package = admit_actor_package(&self.load(&package_ref)?)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
        super::driver::validate_sdk_management_artifacts(
            &self.descriptor,
            request,
            SdkManagementArtifacts::Actor(&package),
        )
        .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref))?;
        for (reference, expected) in [
            (&install.agent_schema, package.state_lane_schema_bytes()),
            (&install.method_policy, package.method_policy_bytes()),
        ] {
            let reference = BlobRef {
                hash: crate::service::Hash(reference.hash.0),
                len: reference.len,
            };
            if self.load(&reference)? != expected {
                return Err(LocalReplayExecutorError::InvalidArtifact(reference));
            }
        }
        if let Some(data) = &install.installation_data {
            let reference = BlobRef {
                hash: crate::service::Hash(data.reference.hash.0),
                len: data.reference.len,
            };
            if self.load(&reference)? != data.bytes {
                return Err(LocalReplayExecutorError::InvalidArtifact(reference));
            }
        }
        Ok(())
    }

    fn check_authorization(
        &self,
        work: &InvocationRetirement,
        authorization: &InvocationAuthorization,
    ) -> Result<(), LocalReplayExecutorError> {
        if !work.validate()
            || !authorization.matches_retirement(work)
            || work.space != self.descriptor.identity.space
            || work.agent != self.descriptor.identity.agent
            || work.runtime_deployment != self.descriptor.identity.runtime_deployment
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        if let InvocationAuthorization::AuthorityReceipt(receipt) = authorization
            && (!self.descriptor.authority.accepts(receipt)
                || !super::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                ))
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Ok(())
    }

    pub(crate) fn gas(&self, operation: &ReplayOperation) -> Result<u64, LocalReplayExecutorError> {
        let actor = match operation {
            ReplayOperation::CleanInvoke { work, .. }
            | ReplayOperation::CleanResume { work, .. } => {
                if work.gas > super::execution::MAX_INVOCATION_GAS_CEILING {
                    return Err(LocalReplayExecutorError::InvalidRequest);
                }
                work.gas
            }
            ReplayOperation::CleanManage { .. } | ReplayOperation::CleanAcknowledge { .. } => 0,
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        };
        DEFAULT_MANAGEMENT_GAS
            .checked_add(actor)
            .ok_or(LocalReplayExecutorError::InvalidRequest)
    }
}

impl<R: CatalogBlobResolver> ReplayExecutor for ExternalLocalReplayExecutor<R> {
    type Error = LocalReplayExecutorError;

    fn seed_genesis(&mut self, genesis: &AgentJournalGenesis) -> Result<(), Self::Error> {
        if self.seeded_genesis != Some(genesis.id()) {
            self.recent_outcomes.clear();
            self.seeded_genesis = Some(genesis.id());
        }
        self.seeded = false;
        self.authenticated = None;
        self.pending = None;
        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            authority,
            observed_slot,
        } = &genesis.create.operation
        else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        if genesis.create.runtime != self.binding()? || descriptor.as_ref() != &self.descriptor {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        super::driver::verify_clean_management_receipt(
            &self.descriptor,
            &ManagementRequest::Create(descriptor.clone()),
            authority,
            *observed_slot,
            false,
        )
        .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        self.seeded = true;
        Ok(())
    }

    fn trusted_clean_descriptor(
        &self,
        runtime: &RuntimeBinding,
    ) -> Result<Option<AgentDescriptor>, Self::Error> {
        if !self.seeded || *runtime != self.binding()? {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(Some(self.descriptor.clone()))
    }

    fn verify_merge_event(&mut self, _: &super::journal::MergeEvent) -> Result<bool, Self::Error> {
        Err(LocalReplayExecutorError::InvalidRequest)
    }

    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<(), Self::Error> {
        self.authenticated = None;
        self.pending = None;
        if !self.seeded || input.runtime != self.binding()? || position == ReplayPosition::Genesis {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        match &input.operation {
            ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot,
            } => {
                self.check_install(request)?;
                let verify =
                    if self.descriptor.identity.profile == crate::agent_sdk::AgentProfile::Shared {
                        super::driver::verify_clean_management_journal_receipt(
                            &self.descriptor,
                            request,
                            authority,
                            *observed_slot,
                            false,
                        )
                        .map(|_| ())
                    } else {
                        super::driver::verify_clean_management_receipt(
                            &self.descriptor,
                            request,
                            authority,
                            *observed_slot,
                            false,
                        )
                    };
                verify.map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
            }
            ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            }
            | ReplayOperation::CleanResume {
                work,
                authorization,
                observed_slot,
                ..
            } => {
                if !work.validate() || !authorization.matches_invoke(work, *observed_slot) {
                    return Err(LocalReplayExecutorError::InvalidAuthority);
                }
                self.check_authorization(&InvocationRetirement::from_work(work), authorization)?;
            }
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => self.check_authorization(work, authorization)?,
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        }
        self.authenticated = Some(AuthenticatedExternalInput {
            input: input.id(),
            before: before.clone(),
            position,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        _: &ReplayInput,
        _: &RuntimeState,
        _: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error> {
        Err(LocalReplayExecutorError::InvalidRequest)
    }

    fn execute_with_external_state(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        genesis: &AgentJournalGenesis,
        lanes: &[(LaneStateManifest, LaneCursor)],
        reader: &dyn ScopedBlockReader,
        budget: &mut ReadBudget,
    ) -> Result<ReplayTransition, Self::Error> {
        self.pending = None;
        let authenticated = self
            .authenticated
            .take()
            .ok_or(LocalReplayExecutorError::InvalidAuthority)?;
        if authenticated.input != input.id()
            || authenticated.before != *before
            || authenticated.position != position
            || genesis.create.runtime != self.binding()?
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        let gas = self.gas(&input.operation)?;
        let execution = MultiLaneStateBlockHost {
            store: reader,
            budget,
        }
        .execute_admitted_journal(&self.runtime, genesis, input, before, position, lanes, gas)
        .map_err(|error| match error {
            BlockPvmError::Backend => LocalReplayExecutorError::RuntimeBackend,
            BlockPvmError::Exit { reason, pc } => {
                LocalReplayExecutorError::RuntimeExit { reason, pc }
            }
            BlockPvmError::InvalidRequest | BlockPvmError::ProgramMismatch => {
                LocalReplayExecutorError::InvalidRequest
            }
            _ => LocalReplayExecutorError::RuntimeOutput,
        })?;
        if let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &input.operation
        {
            let returned = execution.output().transition();
            if *observed_slot > authority.selector.expires_at
                && (returned.outcome
                    != RuntimeOutcome::Management(Err(
                        crate::agent_sdk::ManagementError::ExpiredBeforeApplication,
                    ))
                    || returned.state == super::replay::sdk_runtime_state(before))
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            if !super::driver::sdk_management_reply_matches(
                &self.descriptor,
                request,
                &returned.outcome,
            ) {
                return Err(LocalReplayExecutorError::InvalidState);
            }
        }
        let transition = execution.transition().clone();
        if matches!(
            input.operation,
            ReplayOperation::CleanInvoke { .. }
                | ReplayOperation::CleanResume { .. }
                | ReplayOperation::CleanAcknowledge { .. }
        ) {
            self.remember_outcome(
                input.id(),
                position,
                execution.output().transition().outcome.clone(),
            )?;
        }
        self.pending = Some(execution);
        Ok(transition)
    }

    fn clean_management_transition_result(
        &self,
        input: &ReplayInput,
        transition: &ReplayTransition,
    ) -> Option<Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>> {
        self.pending
            .as_ref()?
            .management_result_for(input, transition)
    }

    fn take_external_execution(&mut self) -> Result<Option<ReplayExternalExecution>, Self::Error> {
        Ok(self.pending.take())
    }
}

/// The exposed Local generation's locked store, authenticated replay cursor,
/// and catalog-bound physical executor share one owner lifetime. The caller
/// must first select the exact durable external Create intent and seal; this
/// type neither issues Authority receipts nor publishes an ingress route.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct ExternalLocalJournalOwner {
    seal: super::replay::ReplaySealedExternalLocalGenesis,
    cursor: super::replay::PinnedExternalJournal<
        Box<super::journal_store::FileAgentJournalStore>,
        super::journal_store::FileAgentJournalStore,
    >,
    executor: ExternalLocalReplayExecutor<super::journal_store::FileCatalogBlobResolver>,
}

#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn committed_recovery_is_domain_head(
    recovered: &super::replay::ReplayMaterialization,
    recovery: super::replay::ReplayCommittedRecovery,
) -> bool {
    let heads = recovered.heads();
    match recovery.position() {
        ReplayPosition::Ordered {
            id,
            index,
            merge_frontier,
            merge_seal: None,
        } => {
            heads.ordered_head == Some(id)
                && heads.ordered_index == index
                && heads.merge_frontier == merge_frontier
        }
        ReplayPosition::Local {
            id,
            node,
            revision,
            ordered_base,
            merge_frontier,
        } => {
            heads.local_head == Some(id)
                && heads.node == node
                && heads.local_revision == revision
                && recovered.ordered_base() == ordered_base
                && heads.merge_frontier == merge_frontier
        }
        _ => false,
    }
}

/// Recover a physically replayed response only when an authenticated,
/// bounded journal suffix still contains the exact clean operation. A newer
/// lifecycle step for the same invocation blocks an older response. The
/// lookup proves durable ancestry; the cache supplies bytes, never authority.
/// A checkpoint-pruned or evicted result deliberately remains unavailable.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn replayed_committed_suffix_outcome<
    S: super::journal_store::AgentJournalStore,
    R: CatalogBlobResolver,
>(
    store: &S,
    materialization: &super::replay::ReplayMaterialization,
    executor: &ExternalLocalReplayExecutor<R>,
    input: &ReplayInput,
) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
    use super::journal::{LocalEntry, OrderedEntry};
    use super::journal_store::JournalStoreError;
    if !matches!(
        input.operation,
        ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
    ) {
        return Err(JournalStoreError::NonCanonical);
    }
    let (committed_input, position) = match input.persisted_lane() {
        PersistedLane::Control | PersistedLane::Linear => {
            let id = super::local_journal_driver::recent_clean_ordered_operation_bounded(
                store,
                materialization,
                &input.operation,
                MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN,
            )
            .map_err(|error| {
                if error == JournalStoreError::Backpressure {
                    JournalStoreError::Unavailable
                } else {
                    error
                }
            })?
            .ok_or(JournalStoreError::Unavailable)?;
            let mut cursor = materialization.heads().ordered_head;
            let mut position = None;
            for _ in 0..MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN {
                let current = cursor.ok_or(JournalStoreError::Corrupt)?;
                let entry = store
                    .get::<OrderedEntry>(current)?
                    .ok_or(JournalStoreError::MissingObject)?;
                if entry.id() != current || entry.genesis != materialization.heads().genesis {
                    return Err(JournalStoreError::Corrupt);
                }
                if entry.input.id() == id {
                    if entry.input.runtime != input.runtime {
                        return Err(JournalStoreError::Conflict);
                    }
                    position = Some(ReplayPosition::Ordered {
                        id: current,
                        index: entry.index,
                        merge_frontier: entry.merge_frontier,
                        merge_seal: entry.merge_seal,
                    });
                    break;
                }
                cursor = entry.parent;
            }
            (id, position.ok_or(JournalStoreError::Unavailable)?)
        }
        PersistedLane::Local => {
            let id = super::local_journal_driver::recent_clean_local_operation_bounded(
                store,
                materialization,
                &input.operation,
                MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN,
            )
            .map_err(|error| {
                if error == JournalStoreError::Backpressure {
                    JournalStoreError::Unavailable
                } else {
                    error
                }
            })?
            .ok_or(JournalStoreError::Unavailable)?;
            let (_, _, mut cursor) = materialization.local_cursor();
            let mut position = None;
            for _ in 0..MAX_EXTERNAL_REPLAY_OUTCOMES_PER_DOMAIN {
                let current = cursor.ok_or(JournalStoreError::Corrupt)?;
                let entry = store
                    .get::<LocalEntry>(current)?
                    .ok_or(JournalStoreError::MissingObject)?;
                if entry.id() != current || entry.genesis != materialization.heads().genesis {
                    return Err(JournalStoreError::Corrupt);
                }
                if entry.input.id() == id {
                    if entry.input.runtime != input.runtime {
                        return Err(JournalStoreError::Conflict);
                    }
                    position = Some(ReplayPosition::Local {
                        id: current,
                        node: entry.node,
                        revision: entry.revision,
                        ordered_base: entry.ordered_base,
                        merge_frontier: entry.merge_frontier,
                    });
                    break;
                }
                cursor = entry.parent;
            }
            (id, position.ok_or(JournalStoreError::Unavailable)?)
        }
        PersistedLane::Merge => return Err(JournalStoreError::NonCanonical),
    };
    executor
        .replayed_outcome(committed_input, position)
        .ok_or(JournalStoreError::Unavailable)
}

/// The guest's authenticated read-only answer. `Absent` is a positive guest
/// statement that this exact invocation has no retained terminal disposition;
/// storage, execution, and invalid-work failures remain errors, never absence.
#[cfg(feature = "experimental-state-blocks")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RetainedExternalDisposition {
    Absent,
    Completed(RuntimeOutcome),
    Acknowledged(RuntimeOutcome),
}

/// Physically inspect an exact terminal disposition against one independently
/// authenticated runtime head. The caller must keep the store/head pinned;
/// neither this read nor the guest may publish or mutate external blocks.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn inspect_retained_external_disposition<
    S: super::journal_store::AgentJournalStore,
    R: CatalogBlobResolver,
>(
    store: &S,
    recovered: &super::replay::ReplayMaterialization,
    executor: &ExternalLocalReplayExecutor<R>,
    input: &ReplayInput,
    inspection_slot: u64,
    budget: &mut ReadBudget,
) -> Result<RetainedExternalDisposition, super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;
    use crate::agent_sdk::{RuntimeExecutionContext, RuntimeWork};
    if input.runtime != executor.binding().map_err(|_| JournalStoreError::Corrupt)? {
        return Err(JournalStoreError::Conflict);
    }
    let (invocation, authorization) = match &input.operation {
        ReplayOperation::CleanInvoke {
            context: RuntimeExecutionContext::Direct,
            work,
            authorization,
            ..
        } => (InvocationRetirement::from_work(work), authorization.clone()),
        ReplayOperation::CleanAcknowledge {
            context: RuntimeExecutionContext::Direct,
            work,
            authorization,
            ..
        } => (work.clone(), authorization.clone()),
        _ => return Err(JournalStoreError::NonCanonical),
    };
    let work = crate::agent_sdk::state_execution::StateExecutionWork::new(
        RuntimeWork::InspectInvocation {
            context: RuntimeExecutionContext::Direct,
            state: crate::agent_sdk::RuntimeState {
                control: recovered.state().control.clone(),
                linear: recovered.state().linear.clone(),
                merge: recovered.state().merge.clone(),
                local: recovered.state().local.clone(),
            },
            invocation: Box::new(invocation.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: inspection_slot,
        },
        recovered
            .external_inspection_lanes()
            .map_err(|_| JournalStoreError::Corrupt)?,
        executor.runtime.external_state_limits(),
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    let output = MultiLaneStateBlockHost { store, budget }
        .execute_admitted_work(&executor.runtime, &work, DEFAULT_MANAGEMENT_GAS)
        .map_err(|_| JournalStoreError::Unavailable)?;
    let outcome = output.transition().outcome.clone();
    match &outcome {
        RuntimeOutcome::Completed(Ok(reply))
            if reply.invocation == invocation.invocation
                && reply.actor == invocation.actor
                && reply.incarnation == invocation.incarnation
                && reply.deployment == invocation.deployment
                && reply.mode == invocation.mode =>
        {
            Ok(RetainedExternalDisposition::Completed(outcome))
        }
        RuntimeOutcome::Completed(Err(crate::agent_sdk::InvocationError::NotReady)) => {
            Ok(RetainedExternalDisposition::Absent)
        }
        RuntimeOutcome::Completed(Err(error)) if error.is_durable_exact_outcome() => {
            Ok(RetainedExternalDisposition::Completed(outcome))
        }
        RuntimeOutcome::Acknowledged(Ok(reply))
            if reply.invocation == invocation.invocation
                && reply.work == invocation.commitment()
                && reply.authorization == authorization.commitment() =>
        {
            Ok(RetainedExternalDisposition::Acknowledged(outcome))
        }
        _ => Err(JournalStoreError::Unavailable),
    }
}

/// Legacy exact-response projection: the requested terminal kind must match.
/// A positive absence or the opposite lifecycle stage is still unavailable.
#[cfg(feature = "experimental-state-blocks")]
pub(crate) fn inspect_retained_external_outcome<
    S: super::journal_store::AgentJournalStore,
    R: CatalogBlobResolver,
>(
    store: &S,
    recovered: &super::replay::ReplayMaterialization,
    executor: &ExternalLocalReplayExecutor<R>,
    input: &ReplayInput,
    budget: &mut ReadBudget,
) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
    use super::journal_store::JournalStoreError;
    let acknowledge = matches!(&input.operation, ReplayOperation::CleanAcknowledge { .. });
    let inspection_slot = match &input.operation {
        ReplayOperation::CleanInvoke { observed_slot, .. } => *observed_slot,
        ReplayOperation::CleanAcknowledge { .. } => 0,
        _ => return Err(JournalStoreError::NonCanonical),
    };
    match inspect_retained_external_disposition(
        store,
        recovered,
        executor,
        input,
        inspection_slot,
        budget,
    )? {
        RetainedExternalDisposition::Completed(outcome) if !acknowledge => Ok(outcome),
        RetainedExternalDisposition::Acknowledged(outcome) if acknowledge => Ok(outcome),
        _ => Err(JournalStoreError::Unavailable),
    }
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl ExternalLocalJournalOwner {
    fn executor_from_store(
        store: &super::journal_store::FileAgentJournalStore,
        seal: &super::replay::ReplaySealedExternalLocalGenesis,
    ) -> Result<
        ExternalLocalReplayExecutor<super::journal_store::FileCatalogBlobResolver>,
        super::journal_store::JournalStoreError,
    > {
        use super::journal_store::{CatalogBlobResolverFactory, JournalStoreError};
        let resolver = store.catalog_blob_resolver()?;
        let package = &seal.genesis().runtime().package;
        let bytes = resolver
            .load_catalog(package)?
            .ok_or(JournalStoreError::MissingObject)?;
        let runtime = super::package_admission::admit_state_runtime_package(&bytes)
            .map_err(|_| JournalStoreError::Corrupt)?;
        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            ..
        } = &seal.genesis().create.operation
        else {
            return Err(JournalStoreError::Corrupt);
        };
        ExternalLocalReplayExecutor::new(runtime, descriptor.as_ref().clone(), resolver)
            .map_err(|_| JournalStoreError::Corrupt)
    }

    pub(crate) fn open(
        slot: super::journal_store::FileLocalAgentJournalSlot,
        seal: super::replay::ReplaySealedExternalLocalGenesis,
        budget: &mut ReadBudget,
    ) -> Result<Self, super::journal_store::JournalStoreError> {
        let (store, executor, validated) = slot.open_external_journal_with_executor(
            &seal,
            |store| Self::executor_from_store(store, &seal),
            &super::replay::NoPrunedOrderedBases,
            budget,
        )?;
        let cursor =
            super::replay::PinnedExternalJournal::open_validated(Box::new(store), validated)?;
        Ok(Self {
            seal,
            cursor,
            executor,
        })
    }

    fn adopt_initial_store(
        mut store: super::journal_store::FileAgentJournalStore,
        seal: super::replay::ReplaySealedExternalLocalGenesis,
        budget: &mut ReadBudget,
    ) -> Result<Self, super::journal_store::JournalStoreError> {
        use super::journal_store::{AgentJournalStore, JournalStoreError};
        let initial = seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if store.heads()?.as_ref() != Some(&initial) {
            return Err(JournalStoreError::Conflict);
        }
        let mut executor = Self::executor_from_store(&store, &seal)?;
        let validated = super::replay::validate_external_genesis_head(
            &mut store,
            &seal,
            &initial,
            &mut executor,
            &super::replay::NoPrunedOrderedBases,
            budget,
        )?;
        let cursor =
            super::replay::PinnedExternalJournal::open_validated(Box::new(store), validated)?;
        Ok(Self {
            seal,
            cursor,
            executor,
        })
    }

    pub(crate) fn materialization(
        &self,
    ) -> Result<&super::replay::ReplayMaterialization, super::journal_store::JournalStoreError>
    {
        self.cursor.materialization()
    }

    pub(crate) fn descriptor(&self) -> &crate::agent_sdk::AgentDescriptor {
        &self.executor.descriptor
    }

    pub(crate) fn genesis_id(&self) -> AgentJournalGenesisId {
        self.seal.genesis().id()
    }

    /// Return an exact-head response-loss result only while the locked store
    /// still names the same committed input/position. The executor may have
    /// seen an uncommitted staged head during open or a failed preparation;
    /// neither can authorize a response through this check. Checkpoint-pruned
    /// results absent from the replay cache remain unavailable.
    pub(crate) fn committed_outcome(
        &self,
        recovery: super::replay::ReplayCommittedRecovery,
    ) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        self.cursor.inspect(|_, recovered| {
            if !committed_recovery_is_domain_head(recovered, recovery) {
                return Err(JournalStoreError::Conflict);
            }
            self.executor
                .replayed_outcome(recovery.input(), recovery.position())
                .ok_or(JournalStoreError::Unavailable)
        })
    }

    /// Response-loss recovery after an unrelated entry advanced this domain.
    /// Only a still-retained authenticated suffix and its physical replay can
    /// supply the result; checkpoint-pruned history remains a release gate.
    pub(crate) fn committed_suffix_outcome(
        &self,
        input: &ReplayInput,
    ) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
        self.cursor.inspect(|store, recovered| {
            replayed_committed_suffix_outcome(store, recovered, &self.executor, input)
        })
    }

    /// Read a checkpoint-retained exact terminal disposition through the
    /// admitted guest, without executing unseen work or publishing a head.
    /// The guest's authenticated runtime state distinguishes a retained
    /// rejection from absence; the physical frame enforces no state or block
    /// changes. External Resume remains unsupported until yielded execution
    /// and its checkpoint identity are qualified.
    pub(crate) fn inspect_retained_outcome(
        &self,
        input: &ReplayInput,
        budget: &mut ReadBudget,
    ) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
        self.cursor.inspect(|store, recovered| {
            inspect_retained_external_outcome(store, recovered, &self.executor, input, budget)
        })
    }

    /// Preserve positive absence separately from I/O, guest execution, and
    /// mismatched lifecycle stages. Invoke admission may execute only after
    /// `Absent`; ACK admission may execute only after `Completed`. An
    /// `Unavailable` error is never a license to run work. `inspection_slot`
    /// must come from the host's trusted logical clock, not the request.
    pub(crate) fn inspect_retained_disposition(
        &self,
        input: &ReplayInput,
        inspection_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<RetainedExternalDisposition, super::journal_store::JournalStoreError> {
        self.cursor.inspect(|store, recovered| {
            inspect_retained_external_disposition(
                store,
                recovered,
                &self.executor,
                input,
                inspection_slot,
                budget,
            )
        })
    }

    /// Recover a lost Invoke/ACK response from the authenticated committed
    /// suffix when it remains replayable, otherwise ask the guest at the
    /// current committed root. A conflict is never converted into a guest
    /// lookup, and a missing guest disposition remains unavailable. This is
    /// the response handoff that a future routed external Local adapter must
    /// use after restart; it never re-executes an unseen invocation.
    pub(crate) fn recover_retained_outcome(
        &self,
        input: &ReplayInput,
        budget: &mut ReadBudget,
    ) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        match self.committed_suffix_outcome(input) {
            Ok(outcome) => Ok(outcome),
            Err(JournalStoreError::Unavailable) => self.inspect_retained_outcome(input, budget),
            Err(error) => Err(error),
        }
    }

    /// Admit one Direct Invoke or ACK through this locked, per-Agent owner.
    /// Guest inspection is deliberately first: only a positive `Absent`
    /// permits a new Invoke, and only a live `Completed` result permits ACK.
    /// An inspection failure never falls through to execution. This is the
    /// correctness-first route primitive; its extra read-only guest execution
    /// must be measured before the release performance gate.
    pub(crate) fn submit_direct_clean(
        &mut self,
        input: ReplayInput,
        inspection_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<RuntimeOutcome, super::journal_store::JournalStoreError> {
        use super::journal::{LocalEntry, OrderedEntry};
        use super::journal_store::JournalStoreError;
        use super::replay::{ExternalJournalCommit, ReplayError};
        use crate::agent_sdk::RuntimeExecutionContext;

        if input.validate().is_err() || input.runtime != *self.materialization()?.runtime() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let (invoke, recovery_only) = match &input.operation {
            ReplayOperation::CleanInvoke {
                context: RuntimeExecutionContext::Direct,
                work,
                observed_slot,
                ..
            } if *observed_slot == inspection_slot => (true, work.recovery_only),
            ReplayOperation::CleanAcknowledge {
                context: RuntimeExecutionContext::Direct,
                ..
            } => (false, false),
            _ => return Err(JournalStoreError::NonCanonical),
        };
        let lane = input.persisted_lane();
        if lane == PersistedLane::Merge {
            return Err(JournalStoreError::NonCanonical);
        }
        match (
            invoke,
            self.inspect_retained_disposition(&input, inspection_slot, budget)?,
        ) {
            (true, RetainedExternalDisposition::Absent) if !recovery_only => {}
            (false, RetainedExternalDisposition::Completed(_)) => {}
            (true, RetainedExternalDisposition::Completed(outcome))
            | (false, RetainedExternalDisposition::Acknowledged(outcome)) => return Ok(outcome),
            _ => return Err(JournalStoreError::Conflict),
        }

        for attempt in 0..2 {
            let recovered = self.materialization()?;
            let heads = recovered.heads();
            let committed = match lane {
                PersistedLane::Control | PersistedLane::Linear => {
                    let entry = OrderedEntry {
                        genesis: heads.genesis,
                        index: heads
                            .ordered_index
                            .checked_add(1)
                            .ok_or(JournalStoreError::LimitExceeded)?,
                        parent: heads.ordered_head,
                        merge_frontier: heads.merge_frontier,
                        merge_seal: None,
                        input: input.clone(),
                    };
                    self.apply_ordered(&entry, budget)
                }
                PersistedLane::Local => {
                    let entry = LocalEntry {
                        genesis: heads.genesis,
                        node: heads.node,
                        revision: heads
                            .local_revision
                            .checked_add(1)
                            .ok_or(JournalStoreError::LimitExceeded)?,
                        parent: heads.local_head,
                        ordered_base: recovered.ordered_base(),
                        merge_frontier: heads.merge_frontier,
                        input: input.clone(),
                    };
                    self.apply_local(&entry, budget)
                }
                PersistedLane::Merge => unreachable!(),
            };
            match committed {
                Ok(ExternalJournalCommit::Published(_, _, Some(outcome))) => return Ok(outcome),
                Ok(ExternalJournalCommit::AlreadyCommitted(_)) => {
                    return self.recover_retained_outcome(&input, budget);
                }
                Ok(ExternalJournalCommit::Published(_, _, None)) => {
                    return Err(JournalStoreError::Corrupt);
                }
                Ok(ExternalJournalCommit::Rejected(_)) => {
                    return Err(JournalStoreError::Corrupt);
                }
                Err(ReplayError::ReplayLimit) if attempt == 0 => {
                    self.checkpoint(budget)
                        .map_err(|_| JournalStoreError::Unavailable)?;
                }
                Err(ReplayError::Source(
                    super::replay::ReplayMaterializationSourceError::Journal(error),
                )) => return Err(error),
                Err(_) => return Err(JournalStoreError::Unavailable),
            }
        }
        Err(JournalStoreError::LimitExceeded)
    }

    /// The issuer may sign Create application only after the initial
    /// checkpoint-bearing head is durably reopened and exactly matches this
    /// owner seal. Later journal work cannot be mistaken for the first Create
    /// observation; result and receipt come from replay, never caller input.
    pub(crate) fn observe_create_application(
        &self,
    ) -> Result<ExternalLocalManagementObservation, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;

        let initial = self
            .seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let expected = super::replay::clean_create_management_evidence(&self.seal.genesis().create)
            .ok_or(JournalStoreError::NonCanonical)?;
        let ReplayOperation::CleanManage { authority, .. } = &self.seal.genesis().create.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        self.cursor.inspect(|_, recovered| {
            if recovered.heads() != &initial
                || recovered.clean_management_evidence() != Some(&expected)
                || recovered.state() != self.seal.post_create()
            {
                return Err(JournalStoreError::Conflict);
            }
            let Ok(result) = &expected.result else {
                return Err(JournalStoreError::Corrupt);
            };
            Ok(ExternalLocalManagementObservation {
                receipt: authority.clone(),
                result: result.clone(),
                reopened_state: crate::agent_sdk::Hash::digest(
                    b"vos/agent/local/reopened-external-head/v1",
                    &[&recovered.heads_id().0],
                ),
                applied_at: expected.observed_slot,
            })
        })
    }

    /// Re-observe the latest applied Install from authenticated management
    /// evidence, including after unrelated Invoke/ACK and checkpoint work.
    /// The issuer still owns approval, signing, finalization and retirement.
    pub(crate) fn observe_install_application(
        &self,
        request: &ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<ExternalLocalManagementObservation, super::journal_store::JournalStoreError> {
        self.cursor.inspect(|_, recovered| {
            observe_external_install_application(
                recovered,
                &self.executor.descriptor,
                request,
                receipt,
            )
        })
    }

    /// Reopen a terminally published guest rejection through the same locked
    /// generation. A preflight-only rejection has no journal evidence and
    /// cannot be observed here.
    pub(crate) fn observe_install_rejection(
        &self,
        request: &ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<ExternalLocalManagementRejection, super::journal_store::JournalStoreError> {
        self.cursor.inspect(|_, recovered| {
            observe_external_install_rejection(
                recovered,
                &self.executor.descriptor,
                request,
                receipt,
            )
        })
    }

    pub(crate) fn verify_finalized_install_ack(
        &self,
        request: &ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        acknowledgement: &crate::agent_sdk::authority::ManagementApplicationAck,
    ) -> Result<(), super::journal_store::JournalStoreError> {
        self.cursor.inspect(|_, recovered| {
            verify_external_install_ack(
                recovered,
                &self.executor.descriptor,
                request,
                receipt,
                acknowledgement,
            )
        })
    }

    pub(crate) fn verify_finalized_install_failure(
        &self,
        request: &ManagementRequest,
        receipt: &crate::agent_sdk::authority::AuthorityReceipt,
        failure: &crate::agent_sdk::authority::ManagementApplicationFailure,
    ) -> Result<(), super::journal_store::JournalStoreError> {
        self.cursor.inspect(|_, recovered| {
            verify_external_install_failure(
                recovered,
                &self.executor.descriptor,
                request,
                receipt,
                failure,
            )
        })
    }

    /// A finalized exact retry may find later Install/Invoke work at the
    /// durable head. It must verify the original signed Create ACK against the
    /// authenticated generation, not re-observe the latest management result
    /// or issue another ACK. Only the issuer's finalized-record recovery may
    /// supply this acknowledgement; this check does not establish Authority
    /// actor finality on its own.
    pub(crate) fn verify_finalized_create_ack(
        &self,
        acknowledgement: &crate::agent_sdk::authority::ManagementApplicationAck,
    ) -> Result<(), super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        use crate::agent_sdk::{Hash, ManagementReply, ManagementRequest};

        let ReplayOperation::CleanManage {
            request: ManagementRequest::Create(descriptor),
            authority,
            observed_slot,
        } = &self.seal.genesis().create.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        let initial = self
            .seal
            .initial_heads()
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let expected_state = Hash::digest(
            b"vos/agent/local/reopened-external-head/v1",
            &[&initial.id().0],
        );
        if acknowledgement.validate_shape().is_err()
            || acknowledgement.receipt != *authority
            || acknowledgement.request
                != ManagementRequest::Create(descriptor.clone()).replay_commitment()
            || acknowledgement.application != ManagementReply::Created(descriptor.identity.clone())
            || acknowledgement.reopened_state != expected_state
            || acknowledgement.applied_at != *observed_slot
            || acknowledgement.managed.space != descriptor.identity.space
            || acknowledgement.managed.agent != descriptor.identity.agent
            || acknowledgement.managed.owner != descriptor.identity.owner
            || acknowledgement.managed.profile != descriptor.identity.profile
            || acknowledgement.managed.runtime_deployment != descriptor.identity.runtime_deployment
            || acknowledgement.managed.transition_producer
                != descriptor.identity.transition_producer
            || acknowledgement.authority.binding != descriptor.authority
            // Actor authorization and issuer decision sequences are distinct
            // replay clocks. The finalized issuer record binds the former to
            // its approval; the receipt and both signatures are checked here.
            || acknowledgement
                .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
                .is_err()
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        self.cursor.inspect(|store, recovered| {
            self.seal
                .validate_checkpoint_scope(store, recovered.heads())?;
            if recovered.heads() == &initial
                && (recovered.clean_management_evidence()
                    != super::replay::clean_create_management_evidence(&self.seal.genesis().create)
                        .as_ref()
                    || recovered.state() != self.seal.post_create())
            {
                return Err(JournalStoreError::Conflict);
            }
            Ok(())
        })
    }

    /// Inspect the installed directory against this owner's exact pinned
    /// roots and locked store. Read-only guest output cannot publish changes
    /// or replace the authenticated cursor. This is an internal route-building
    /// primitive, not admission of a public route or lifecycle operation.
    pub(crate) fn inspect_actors(
        &self,
        after: Option<crate::agent_sdk::ActorId>,
        limit: u16,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<crate::agent_sdk::ActorDirectoryPage, super::journal_store::JournalStoreError> {
        use super::journal_store::JournalStoreError;
        use crate::agent_sdk::{self as sdk, RuntimeOutcome, state_execution::StateExecutionWork};

        let binding = self
            .executor
            .binding()
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        self.cursor.inspect(|store, recovered| {
            if recovered.runtime() != &binding {
                return Err(JournalStoreError::ScopeMismatch);
            }
            let state = sdk::RuntimeState {
                control: recovered.state().control.clone(),
                linear: recovered.state().linear.clone(),
                merge: recovered.state().merge.clone(),
                local: recovered.state().local.clone(),
            };
            let work = StateExecutionWork::new(
                sdk::RuntimeWork::Manage {
                    context: sdk::RuntimeExecutionContext::Direct,
                    space: self.executor.descriptor.identity.space,
                    agent: self.executor.descriptor.identity.agent,
                    runtime_deployment: self.executor.runtime.deployment(),
                    state,
                    request: Box::new(ManagementRequest::InspectActors { after, limit }),
                    authority: None,
                    observed_slot,
                },
                recovered.external_inspection_lanes()?,
                self.executor.runtime.external_state_limits(),
            )
            .map_err(|_| JournalStoreError::NonCanonical)?;
            let output = MultiLaneStateBlockHost { store, budget }
                .execute_admitted_work(&self.executor.runtime, &work, DEFAULT_MANAGEMENT_GAS)
                .map_err(|_| JournalStoreError::Unavailable)?;
            match &output.transition().outcome {
                RuntimeOutcome::Management(Ok(sdk::ManagementReply::Actors(page))) => {
                    if page.entries.len() > usize::from(limit)
                        || page.entries.first().is_some_and(|record| {
                            after.is_some_and(|after| record.entry.actor <= after)
                        })
                        || (page.next.is_some() && page.entries.len() != usize::from(limit))
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    Ok(page.clone())
                }
                _ => Err(JournalStoreError::Unavailable),
            }
        })
    }

    /// One guest directory execution for a single ActorId. This avoids
    /// fetching every page for routed work, though the current ABI still
    /// transports the runtime's complete metadata for this one execution.
    pub(crate) fn inspect_actor(
        &self,
        actor: crate::agent_sdk::ActorId,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<
        Option<crate::agent_sdk::ActorDirectoryRecord>,
        super::journal_store::JournalStoreError,
    > {
        if actor == crate::agent_sdk::ActorId::ZERO {
            return Err(super::journal_store::JournalStoreError::NonCanonical);
        }
        let page = self.inspect_actors(actor_cursor_before(actor), 1, observed_slot, budget)?;
        Ok(page
            .entries
            .into_iter()
            .next()
            .filter(|record| record.entry.actor == actor))
    }

    /// Build the current Local route identities from this authenticated
    /// journal's runtime directory. This does not publish or authorize a
    /// route; the lifecycle controller must finish recovery/finality first.
    pub(crate) fn route_identities(
        &self,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<Vec<super::supervisor::AgentRouteIdentity>, super::supervisor::AgentRouteError>
    {
        use super::supervisor::AgentRouteError;
        let descriptor = &self.executor.descriptor;
        let records = super::supervisor_adapters::collect_actor_directory(
            descriptor.capabilities.max_actors as usize,
            |after, limit| {
                self.inspect_actors(after, limit, observed_slot, budget)
                    .map_err(|_| AgentRouteError::Unavailable)
            },
        )?;
        super::supervisor_adapters::route_identities(descriptor, records, AgentProfile::Local)
    }

    /// Resolve one installed Actor's complete immutable invocation inputs
    /// from the current authenticated runtime directory and pinned catalog.
    /// Ingress must still compare the returned material to its route snapshot
    /// and authorize the exact signed work before execution.
    pub(crate) fn physical_invocation_material(
        &self,
        actor: crate::agent_sdk::ActorId,
        observed_slot: u64,
        budget: &mut ReadBudget,
    ) -> Result<
        super::invocation_preparation::PhysicalInvocationMaterial,
        super::journal_store::JournalStoreError,
    > {
        use super::journal_store::JournalStoreError;
        let record = self
            .inspect_actor(actor, observed_slot, budget)?
            .ok_or(JournalStoreError::MissingObject)?;
        physical_material_from_catalog(
            &self.executor.descriptor,
            record,
            observed_slot,
            |reference| {
                let reference = BlobRef {
                    hash: crate::service::Hash(reference.hash.0),
                    len: reference.len,
                };
                self.executor
                    .resolver
                    .load_catalog(&reference)?
                    .ok_or(JournalStoreError::MissingObject)
            },
        )
    }

    pub(crate) fn apply_ordered(
        &mut self,
        entry: &super::journal::OrderedEntry,
        budget: &mut ReadBudget,
    ) -> Result<
        super::replay::ExternalJournalCommit,
        super::replay::MaterializeError<core::convert::Infallible, LocalReplayExecutorError>,
    > {
        self.cursor.apply(
            &mut self.executor,
            super::replay::ExternalJournalEntry::Ordered(entry),
            budget,
        )
    }

    /// Publish one Authority-approved Install through the pinned file owner.
    /// The actor's signed closure and constructor bytes are staged under the
    /// current authenticated predecessor, then the physical guest preflight
    /// must accept before any new head is published. `Rejected` leaves the
    /// Authority decision pending; the lifecycle coordinator must not sign an
    /// application ACK or expose a route for it. After any error the caller
    /// must reopen this locked generation before deciding whether to retry.
    pub(crate) fn publish_install(
        &mut self,
        input: ReplayInput,
        package: &super::package_admission::AdmittedActorPackage,
        budget: &mut ReadBudget,
    ) -> Result<super::replay::ExternalJournalCommit, super::journal_store::JournalStoreError> {
        self.publish_install_with_rejection_policy(input, package, budget, false)
    }

    /// Internal failure-finality path. A guest rejection is published as an
    /// authenticated Ordered transition so recovery can observe the exact
    /// result. It still requires a separate signed Authority terminal step.
    pub(crate) fn publish_install_for_finality(
        &mut self,
        input: ReplayInput,
        package: &super::package_admission::AdmittedActorPackage,
        budget: &mut ReadBudget,
    ) -> Result<super::replay::ExternalJournalCommit, super::journal_store::JournalStoreError> {
        self.publish_install_with_rejection_policy(input, package, budget, true)
    }

    fn publish_install_with_rejection_policy(
        &mut self,
        input: ReplayInput,
        package: &super::package_admission::AdmittedActorPackage,
        budget: &mut ReadBudget,
        terminalize_rejection: bool,
    ) -> Result<super::replay::ExternalJournalCommit, super::journal_store::JournalStoreError> {
        use super::journal::OrderedEntry;
        use super::journal_store::{CatalogBlobResolverFactory, JournalStoreError};
        use super::replay::{ReplayError, ReplayMaterializationSourceError};

        let ReplayOperation::CleanManage {
            request: ManagementRequest::Install(install),
            authority,
            observed_slot,
        } = &input.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        if input.validate().is_err() || input.runtime != *self.materialization()?.runtime() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let request = ManagementRequest::Install(install.clone());
        super::driver::verify_clean_management_receipt(
            &self.executor.descriptor,
            &request,
            authority,
            *observed_slot,
            false,
        )
        .map_err(|_| JournalStoreError::ScopeMismatch)?;
        super::driver::validate_sdk_management_artifacts(
            &self.executor.descriptor,
            &request,
            SdkManagementArtifacts::Actor(package),
        )
        .map_err(|_| JournalStoreError::ScopeMismatch)?;
        if self
            .materialization()?
            .clean_management_evidence()
            .is_some_and(|evidence| {
                evidence.request == request.replay_commitment()
                    && evidence.authority == authority.commitment()
            })
        {
            // The lifecycle owner must recover and acknowledge the existing
            // physical application, not append a second ordered transition.
            return Err(JournalStoreError::Conflict);
        }

        let catalog = [
            package.exact_bytes(),
            package.program_bytes(),
            package.state_lane_schema_bytes(),
            package.method_policy_bytes(),
        ]
        .into_iter()
        .chain(
            install
                .installation_data
                .as_ref()
                .map(|data| data.bytes.as_slice()),
        )
        .map(|bytes| super::execution::RuntimeBlob {
            reference: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        })
        .collect::<Vec<_>>();
        let heads = self.materialization()?.heads().clone();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(JournalStoreError::LimitExceeded)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(self.cursor.persist_current_merge_seal(&self.seal)?),
            input,
        };
        let committed = if terminalize_rejection {
            self.cursor.apply_install_with_catalog_terminal(
                &mut self.executor,
                &entry,
                &catalog,
                budget,
                |store, executor| {
                    executor.replace_resolver(store.catalog_blob_resolver()?);
                    Ok(())
                },
            )
        } else {
            self.cursor.apply_install_with_catalog(
                &mut self.executor,
                &entry,
                &catalog,
                budget,
                |store, executor| {
                    executor.replace_resolver(store.catalog_blob_resolver()?);
                    Ok(())
                },
            )
        };
        committed.map_err(|error| match error {
            ReplayError::Source(ReplayMaterializationSourceError::Journal(error)) => error,
            ReplayError::ReplayLimit => JournalStoreError::Backpressure,
            _ => JournalStoreError::Unavailable,
        })
    }

    pub(crate) fn apply_local(
        &mut self,
        entry: &super::journal::LocalEntry,
        budget: &mut ReadBudget,
    ) -> Result<
        super::replay::ExternalJournalCommit,
        super::replay::MaterializeError<core::convert::Infallible, LocalReplayExecutorError>,
    > {
        self.cursor.apply(
            &mut self.executor,
            super::replay::ExternalJournalEntry::Local(entry),
            budget,
        )
    }

    pub(crate) fn checkpoint(
        &mut self,
        budget: &mut ReadBudget,
    ) -> Result<super::journal_store::JournalPublication, super::replay::RecoveryError> {
        self.cursor.checkpoint(&self.seal, budget)
    }
}

#[cfg(test)]
mod tests {
    use super::actor_cursor_before;
    use crate::agent_sdk::ActorId;

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn external_resume_reuses_exact_invoke_authorization_and_gas() {
        use super::{DEFAULT_MANAGEMENT_GAS, ExternalLocalReplayExecutor};
        use crate::agent::{
            MethodMode,
            genesis::AgentGenesisAdmissionId,
            journal::{
                AgentJournalGenesis, CanonicalJournalRecord, LocalEntryId, MergeFrontierId,
                OrderedBase, OrderedEntryId, ReplayOperation,
            },
            journal_store::{CatalogBlobResolver, JournalStoreError},
            package_admission::tests::admitted_state_fixture,
            replay::{ReplayExecutor, ReplayPosition, tests::clean_admitted_invocation},
            wire::RuntimeState,
        };
        use crate::agent_sdk::{
            self as sdk, RuntimeExecutionContext, RuntimeOutcome, YieldReason, YieldedInvocation,
        };

        #[derive(Clone)]
        struct EmptyCatalog;
        impl CatalogBlobResolver for EmptyCatalog {
            fn load_catalog(
                &self,
                _: &crate::service::BlobRef,
            ) -> Result<Option<Vec<u8>>, JournalStoreError> {
                Ok(None)
            }
        }

        let runtime = admitted_state_fixture(
            vos_pvm_compiler::assembler::Assembler::new()
                .trap()
                .build_standard(),
        );
        let (create, _, _) = crate::agent::replay::tests::external_create_fixture(&runtime);
        let ReplayOperation::CleanManage {
            request: sdk::ManagementRequest::Create(descriptor),
            ..
        } = &create.operation
        else {
            unreachable!()
        };
        let mut executor =
            ExternalLocalReplayExecutor::new(runtime, descriptor.as_ref().clone(), EmptyCatalog)
                .unwrap();
        let genesis = AgentJournalGenesis {
            admission: AgentGenesisAdmissionId::from_bytes([0x71; 32]),
            create: create.clone(),
        };
        executor.seed_genesis(&genesis).unwrap();
        let invoke = clean_admitted_invocation(&create.runtime, MethodMode::Linear, 0x72);
        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            observed_slot,
            ..
        } = invoke.operation
        else {
            unreachable!()
        };
        let yielded = YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: sdk::BlobRef::of_bytes(b"retained continuation"),
            ready_sequence: 1,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: YieldReason::Cooperative,
        };
        let resume = crate::agent::journal::ReplayInput {
            runtime: create.runtime.clone(),
            operation: ReplayOperation::CleanResume {
                context: RuntimeExecutionContext::Direct,
                expected_live: None,
                work,
                authorization,
                yielded,
                observed_slot,
            },
        };
        resume.validate().unwrap();
        assert_eq!(
            executor.gas(&resume.operation).unwrap(),
            DEFAULT_MANAGEMENT_GAS + 1_000
        );
        let mut excessive = resume.clone();
        let ReplayOperation::CleanResume { work, .. } = &mut excessive.operation else {
            unreachable!()
        };
        work.gas = super::MAX_EXECUTION_GAS + 1;
        assert!(executor.gas(&excessive.operation).is_err());
        let position = ReplayPosition::Ordered {
            id: OrderedEntryId([0x73; 32]),
            index: 1,
            merge_frontier: MergeFrontierId([0x74; 32]),
            merge_seal: None,
        };
        executor
            .authenticate(&resume, &RuntimeState::default(), position)
            .unwrap();
        let outcome = RuntimeOutcome::Completed(Err(sdk::InvocationError::NotFound));
        executor
            .remember_outcome(resume.id(), position, outcome.clone())
            .unwrap();
        assert_eq!(
            executor.replayed_outcome(resume.id(), position),
            Some(outcome.clone())
        );
        assert!(
            executor
                .replayed_outcome(
                    resume.id(),
                    ReplayPosition::Ordered {
                        id: OrderedEntryId([0x75; 32]),
                        index: 1,
                        merge_frontier: MergeFrontierId([0x74; 32]),
                        merge_seal: None,
                    }
                )
                .is_none()
        );
        assert!(
            executor
                .remember_outcome(
                    resume.id(),
                    position,
                    RuntimeOutcome::Completed(Err(sdk::InvocationError::InvalidAvailability)),
                )
                .is_err()
        );
        executor.seed_genesis(&genesis).unwrap();
        assert_eq!(
            executor.replayed_outcome(resume.id(), position),
            Some(outcome)
        );
        let local = ReplayPosition::Local {
            id: LocalEntryId([0x77; 32]),
            node: crate::service::NodeId([0x35; 32]),
            revision: 1,
            ordered_base: OrderedBase::post_genesis(),
            merge_frontier: MergeFrontierId([0x74; 32]),
        };
        executor
            .remember_outcome(
                resume.id(),
                local,
                RuntimeOutcome::Completed(Err(sdk::InvocationError::NotFound)),
            )
            .unwrap();
        for index in 2..=33 {
            executor
                .remember_outcome(
                    resume.id(),
                    ReplayPosition::Ordered {
                        id: OrderedEntryId([0x78 + index as u8 - 2; 32]),
                        index,
                        merge_frontier: MergeFrontierId([0x74; 32]),
                        merge_seal: None,
                    },
                    RuntimeOutcome::Completed(Err(sdk::InvocationError::NotFound)),
                )
                .unwrap();
        }
        assert_eq!(executor.recent_outcomes.len(), 33);
        assert!(executor.replayed_outcome(resume.id(), position).is_none());
        assert!(executor.replayed_outcome(resume.id(), local).is_some());
        assert!(
            executor
                .replayed_outcome(
                    resume.id(),
                    ReplayPosition::Ordered {
                        id: OrderedEntryId([0x78; 32]),
                        index: 2,
                        merge_frontier: MergeFrontierId([0x74; 32]),
                        merge_seal: None,
                    }
                )
                .is_some()
        );
        executor
            .seed_genesis(&AgentJournalGenesis {
                admission: AgentGenesisAdmissionId::from_bytes([0x76; 32]),
                create: create.clone(),
            })
            .unwrap();
        assert!(executor.replayed_outcome(resume.id(), position).is_none());
        let mut stale = resume.clone();
        let ReplayOperation::CleanResume { observed_slot, .. } = &mut stale.operation else {
            unreachable!()
        };
        *observed_slot -= 1;
        assert!(
            executor
                .authenticate(&stale, &RuntimeState::default(), position)
                .is_err()
        );
        let mut changed = resume;
        let ReplayOperation::CleanResume { work, .. } = &mut changed.operation else {
            unreachable!()
        };
        work.message.push(0xff);
        assert!(
            executor
                .authenticate(&changed, &RuntimeState::default(), position)
                .is_err()
        );
    }

    #[test]
    fn targeted_actor_cursor_handles_first_id_and_borrow() {
        assert_eq!(actor_cursor_before(ActorId::ZERO), None);
        let mut first = [0; 32];
        first[31] = 1;
        assert_eq!(actor_cursor_before(ActorId(first)), None);
        first[30] = 1;
        first[31] = 0;
        let mut expected = [0; 32];
        expected[31] = u8::MAX;
        assert_eq!(actor_cursor_before(ActorId(first)), Some(ActorId(expected)));
        assert!(ActorId(expected) < ActorId(first));
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[test]
    fn external_material_requires_exact_current_actor_artifacts() {
        use std::collections::BTreeMap;

        use super::physical_material_from_catalog;
        use crate::agent::journal::ReplayOperation;
        use crate::agent::journal_store::JournalStoreError;
        use crate::agent::package_admission::tests::{
            admitted_actor_fixture, admitted_state_fixture,
        };
        use crate::agent_sdk::{self as sdk, Hash, InstallationId};

        let runtime = admitted_state_fixture(
            vos_pvm_compiler::assembler::Assembler::new()
                .trap()
                .build_standard(),
        );
        let (create, _, _) = crate::agent::replay::tests::external_create_fixture(&runtime);
        let ReplayOperation::CleanManage {
            request: sdk::ManagementRequest::Create(descriptor),
            ..
        } = create.operation
        else {
            unreachable!()
        };
        let package = admitted_actor_fixture();
        let schema = sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let record = sdk::ActorDirectoryRecord {
            entry: sdk::ActorEntry {
                actor: ActorId([0x21; 32]),
                name: "fixture".into(),
                parent: None,
                deployment: package.deployment(),
                program: package.program(),
                package: package.package_ref().clone(),
                agent_schema: package.manifest().state_lane_schema.clone(),
                method_policy: package.manifest().method_policy.clone(),
                constructor_abi: schema.constructor_abi().unwrap(),
                installation_data: None,
                state_layout: schema.state_layout_hash().unwrap(),
                lanes: schema.lanes(),
                suspended: false,
            },
            incarnation: Hash([0x22; 32]),
            installation_id: InstallationId([0x23; 32]),
            registry_reservation: Hash([0x24; 32]),
            install_request: Hash([0x25; 32]),
        };
        let mut blobs = BTreeMap::from([
            (
                package.package_ref().clone(),
                package.exact_bytes().to_vec(),
            ),
            (
                package.manifest().program.clone(),
                package.program_bytes().to_vec(),
            ),
            (
                package.manifest().state_lane_schema.clone(),
                package.state_lane_schema_bytes().to_vec(),
            ),
            (
                package.manifest().method_policy.clone(),
                package.method_policy_bytes().to_vec(),
            ),
        ]);
        let resolve = |record: sdk::ActorDirectoryRecord,
                       blobs: &BTreeMap<sdk::BlobRef, Vec<u8>>| {
            physical_material_from_catalog(&descriptor, record, 10, |reference| {
                blobs
                    .get(reference)
                    .cloned()
                    .ok_or(JournalStoreError::MissingObject)
            })
        };
        let material = resolve(record.clone(), &blobs).unwrap();
        assert_eq!(material.actor, record);
        assert_eq!(material.program.bytes, package.program_bytes());
        assert_eq!(material.producer, package.producer());
        assert!(!material.root_provenance);

        let mut wrong_layout = record.clone();
        wrong_layout.entry.state_layout.0[0] ^= 1;
        assert_eq!(
            resolve(wrong_layout, &blobs),
            Err(JournalStoreError::Corrupt)
        );
        let mut suspended = record.clone();
        suspended.entry.suspended = true;
        assert_eq!(
            resolve(suspended, &blobs),
            Err(JournalStoreError::ScopeMismatch)
        );
        blobs.get_mut(&record.entry.agent_schema).unwrap()[0] ^= 1;
        assert_eq!(
            resolve(record.clone(), &blobs),
            Err(JournalStoreError::Corrupt)
        );
        blobs.remove(&record.entry.agent_schema);
        assert_eq!(
            resolve(record, &blobs),
            Err(JournalStoreError::MissingObject)
        );
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[test]
    #[ignore = "requires just build-agent-standard-state-guest"]
    fn retained_signed_external_create_reconstructs_physical_seal() {
        use super::RetainedExternalLocalCreate;
        use crate::agent::{
            clean_authority_issuer::{CleanManagementIssuerStore, CleanManagementRuntimeStore},
            clean_management_intent::{
                CleanManagementIntent, CleanManagementIntentSlot, ManagementJournalAnchor,
            },
            genesis::AgentGenesisAdmissionId,
            journal::{AgentJournalGenesisId, OrderedBase, ReplayOperation},
            journal_store::FileLocalAgentJournalSlot,
        };
        use crate::agent_sdk::{
            self as sdk,
            authority::{AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget},
        };
        use ed25519_dalek::{Signer as _, SigningKey};
        use std::num::NonZeroU64;

        #[derive(Default)]
        struct Store {
            intent: Option<Vec<u8>>,
            runtime: Option<Vec<u8>>,
        }
        impl CleanManagementIssuerStore for Store {
            type Error = ();
            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.intent.clone())
            }
            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                self.intent = Some(image.to_vec());
                Ok(())
            }
        }
        impl CleanManagementRuntimeStore for Store {
            fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.runtime.clone())
            }
            fn commit_runtime(&mut self, package: &[u8]) -> Result<(), Self::Error> {
                self.runtime = Some(package.to_vec());
                Ok(())
            }
        }

        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
        let program = vos_pvm_compiler::link_elf_spi(
            &std::fs::read(
                target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
            )
            .expect("build experimental standard guest first"),
        )
        .unwrap();
        let admitted = crate::agent::package_admission::tests::admitted_state_fixture(program);
        let (create, replica, _) = crate::agent::replay::tests::external_create_fixture(&admitted);
        let ReplayOperation::CleanManage {
            request: request @ sdk::ManagementRequest::Create(descriptor),
            authority: receipt,
            observed_slot,
        } = &create.operation
        else {
            unreachable!()
        };
        let identity = &descriptor.identity;
        let authority = AuthorityActorTarget {
            space: identity.space,
            system_agent: sdk::AgentId([0x91; 32]),
            system_runtime_deployment: sdk::DeploymentId([0x92; 32]),
            binding: descriptor.authority,
        };
        let managed = ManagedAgentTarget {
            space: identity.space,
            agent: identity.agent,
            owner: identity.owner,
            profile: identity.profile,
            runtime_deployment: identity.runtime_deployment,
            transition_producer: identity.transition_producer,
        };
        let credential_key = SigningKey::from_bytes(&[0x93; 32]);
        let credential_public_key = credential_key.verifying_key().to_bytes();
        let mut call = AuthorityCredentialCall {
            invocation: sdk::InvocationId::ZERO,
            authority,
            managed,
            principal: identity.owner,
            credential: sdk::CredentialId::of_public_key(&credential_public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key,
            authenticated_node: Some(replica.node),
            requested_valid_from: *observed_slot,
            requested_expires_at: observed_slot + 20,
            plan: request.authorization_plan().unwrap(),
            signature: [0; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = credential_key.sign(&call.signing_bytes()).to_bytes();
        let intent = CleanManagementIntent::new(
            authority,
            managed,
            request.clone(),
            call.clone(),
            &crate::agent::clean_bootstrap::RawCredentialVerifier,
        )
        .unwrap();
        let work = sdk::InvocationWork {
            space: authority.space,
            agent: authority.system_agent,
            runtime_deployment: authority.system_runtime_deployment,
            invocation: call.invocation,
            actor: authority.binding.issuer.actor,
            incarnation: sdk::Hash([0x94; 32]),
            deployment: authority.binding.issuer.deployment,
            program: authority.binding.issuer.program,
            mode: sdk::MethodMode::Linear,
            origin: intent.authorization_origin(),
            roles: sdk::InvocationRoleClaims::none(),
            message: intent.authorization_message(),
            installation_data: None,
            availability: Vec::new(),
            gas: 1_000_000,
            recovery_only: false,
        };
        let authorization = sdk::InvocationAuthorization::PublicPreflight(
            sdk::PublicPreflight::for_work(&work, *observed_slot),
        );
        let mut slot = CleanManagementIntentSlot::open(Store::default()).unwrap();
        slot.pledge(intent).unwrap();
        slot.retain_runtime(admitted.exact_bytes()).unwrap();
        slot.pledge_authorization_work(
            sdk::RuntimeWork::Invoke {
                context: sdk::RuntimeExecutionContext::Direct,
                state: sdk::RuntimeState::default(),
                invocation: Box::new(work),
                authorization: Box::new(authorization),
                observed_slot: *observed_slot,
            },
            ManagementJournalAnchor {
                genesis: AgentJournalGenesisId([0x95; 32]),
                admission: AgentGenesisAdmissionId::from_bytes([0x96; 32]),
                runtime: crate::service::Hash([0x97; 32]),
                ordered: OrderedBase::post_genesis(),
            },
        )
        .unwrap();
        let mut slot = CleanManagementIntentSlot::open(slot.into_store()).unwrap();
        let (seal, runtime) =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap()
                .into_parts();
        assert_eq!(seal.genesis().create, create);
        assert_eq!(runtime, admitted.exact_bytes());
        let archived = RetainedExternalLocalCreate::prepare_from_retained(
            slot.intent().unwrap(),
            runtime.clone(),
            authority,
            receipt,
            replica.node,
        )
        .unwrap();
        let (archived_seal, archived_runtime) = archived.into_parts();
        assert_eq!(archived_seal.genesis(), seal.genesis());
        assert_eq!(archived_seal.initial_heads(), seal.initial_heads());
        assert_eq!(archived_runtime, runtime);
        let unprepared = CleanManagementIntent::new(
            authority,
            managed,
            request.clone(),
            call.clone(),
            &crate::agent::clean_bootstrap::RawCredentialVerifier,
        )
        .unwrap();
        assert!(
            RetainedExternalLocalCreate::prepare_from_retained(
                &unprepared,
                runtime.clone(),
                authority,
                receipt,
                replica.node,
            )
            .is_err()
        );
        let mut altered_receipt = receipt.clone();
        altered_receipt.signature[0] ^= 1;
        assert!(
            RetainedExternalLocalCreate::prepare(
                &mut slot,
                authority,
                &altered_receipt,
                replica.node,
            )
            .is_err()
        );
        assert!(
            RetainedExternalLocalCreate::prepare(
                &mut slot,
                authority,
                receipt,
                sdk::NodeId([0x98; 32]),
            )
            .is_err()
        );
        struct TestDirectory(std::path::PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(target.join("task-tmp").join(format!(
            "retained-external-create-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir_all(&directory.0).unwrap();
        let agent_hex = identity
            .agent
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let agent_root = directory.0.join(format!("{agent_hex}.agent"));
        let agent_lock = directory.0.join(format!("{agent_hex}.agent-lock"));
        let parent = std::fs::File::open(&directory.0).unwrap();
        let prepared =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap();
        let intent_hash = prepared.intent();
        let file_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            agent_root.clone(),
            agent_lock.clone(),
            crate::service::NodeId(replica.node.0),
            intent_hash,
            &parent,
            &parent,
        )
        .unwrap();
        file_slot.verify_absent().unwrap();
        let owner = prepared
            .publish_initial(
                file_slot,
                &mut sdk::state_blocks::ReadBudget::new(10000, 10000000),
            )
            .unwrap();
        assert_eq!(
            owner.observe_create_application().unwrap().receipt(),
            receipt
        );
        let first_head = owner.materialization().unwrap().heads().clone();
        drop(owner);
        let prepared =
            RetainedExternalLocalCreate::prepare(&mut slot, authority, receipt, replica.node)
                .unwrap();
        assert_eq!(prepared.intent(), intent_hash);
        let file_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            agent_root,
            agent_lock,
            crate::service::NodeId(replica.node.0),
            intent_hash,
            &parent,
            &parent,
        )
        .unwrap();
        assert!(matches!(
            file_slot.verify_absent(),
            Err(crate::agent::journal_store::JournalStoreError::Conflict)
        ));
        let owner = prepared
            .publish_initial(
                file_slot,
                &mut sdk::state_blocks::ReadBudget::new(10000, 10000000),
            )
            .unwrap();
        assert_eq!(owner.materialization().unwrap().heads(), &first_head);
        drop(owner);
        let mut store = slot.into_store();
        store.runtime.as_mut().unwrap()[0] ^= 1;
        let mut corrupt = CleanManagementIntentSlot::open(store).unwrap();
        assert!(
            RetainedExternalLocalCreate::prepare(&mut corrupt, authority, receipt, replica.node,)
                .is_err()
        );
    }
}
