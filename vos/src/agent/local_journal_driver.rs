//! Journal-backed process-local Agent execution.
//!
//! This module is the clean-generation replacement for the whole-image local
//! driver.  Its only mutable truth is an [`AgentJournalStore`]; the cached
//! [`ReplayMaterialization`] is replaced only after a consuming replay
//! publication wins the durable heads CAS.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, Gas};

use crate::agent_sdk::wire::CanonicalWire as AgentCanonicalWire;

use super::authority::{ActorInvocationReceipt, AgentAuthorityReceipt};
use super::committee::RootAnchorPins;
use super::driver::{AgentTrustProvider, DEFAULT_MANAGEMENT_GAS, SdkManagementArtifacts};
#[cfg(any(not(test), all(test, not(feature = "pvm"))))]
use super::execution::RuntimeExecutionReturn;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation, RuntimeBlob,
    RuntimeExecutionCall,
};
use super::genesis::{
    AgentReplicaCommittee, AgentReplicaCommitteeId, VerifiedAgentGenesisProvision,
};
use super::invocation_index::{InvocationIndexLookup, InvocationIndexes};
use super::journal::{
    CanonicalJournalRecord, InvocationOutcomeAnchor, InvocationOwnershipKey,
    InvocationOwnershipScope, InvocationResultState, LaneCursor, LocalEntry, MergeEvent,
    MergeEventId, MergeFrontier, MergeFrontierId, MergeSeal, OrderedEntry, OrderedEntryId,
    PersistedLane, ReplayInput, ReplayInputId, ReplayOperation, RuntimeBinding,
};
use super::journal_store::{
    AgentJournalStore, CatalogBlobResolver, CatalogBlobResolverFactory, JournalBlobClass,
    JournalStoreError, StagedTransitionProof, TransitionProofPublicationStore,
    UnpublishedCatalogBlob, UnpublishedCatalogBlobStore,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::journal_store::{
    BoundFileSystemAuthorityLedgerOwner, FileAgentJournalStore, ReverifiedRootJournalStore,
    SystemAuthorityHistoryStore, SystemAuthorityPublicationStore,
};
use super::package::{Package, PackageError};
use super::replay::{
    MaterializeError, NoPrunedOrderedBases, ReplayCommittedRecovery, ReplayDisposition,
    ReplayError, ReplayExecutionResult, ReplayExecutor, ReplayInvocationRecovery,
    ReplayMaterialization, ReplayMaterializationSourceError, ReplayPosition, ReplayPreparation,
    ReplayPreparedGenesis, ReplayProducts, ReplaySealedGenesis, ReplaySealedLocalGenesis,
    ReplaySealedSharedGenesis, ReplayStepOutcome, ReplayTransition, ReplayTransitionProofAccess,
    ReplayTransitionProofBinding, ReplayTransitionProofProjection, derive_lane_state,
    materialize_current, prepare_checkpoint, prepare_local, prepare_merge, prepare_ordered,
    recover_invocation,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::replay::{
    PendingSystemAuthorityCatalogRecovery, PendingSystemAuthorityRotationRecovery,
    SystemAuthorityRecoveryError, materialize_current_reverified,
    materialized_system_authority_view, recover_pending_system_authority_catalog,
    recover_pending_system_authority_rotation,
};
use super::standard::{StandardAgentRuntime, StandardRuntimeState};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::system_authority_ledger::SystemAuthorityLedgerError;
use super::transition_proof_host::{
    PreparedVerifiedTransition, PublishedAttestedTransition, TransitionPublicationFact,
};
#[cfg(test)]
use super::wire::encode_standard_runtime_state;
use super::wire::{
    RuntimeCall, RuntimeJournalContext, RuntimeReturn, RuntimeState, decode_standard_runtime_state,
};
use super::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, AgentConfig, AgentIdentity, AgentProfile,
    AgentReplica, AgentRuntime, InstallActor, InvocationScope, LifecycleAuthorityAdmission,
    LifecycleError, LifecycleReply, LifecycleRequest, PackageKind, UpgradeActor,
};
use crate::service::wire::ServiceWire;
use crate::service::{
    ActorId, BlobRef, CapabilityId, DeploymentId, Hash, NodeId, ProducerId, ProgramId,
};

type LocalReplayError = MaterializeError<core::convert::Infallible, LocalReplayExecutorError>;

/// Replay-derived result recovery and exact-management retry discovery are
/// deliberately bounded to the same newest Ordered suffix. State equality by
/// itself is never treated as retry evidence.
pub(crate) const MAX_PENDING_CLEAN_INVOCATION_RESULTS: usize = 1_024;

pub(super) fn recent_clean_management_input<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    request: &crate::agent_sdk::ManagementRequest,
    authority: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    Ok(
        recent_clean_management_operation(store, materialization, request, authority)?
            .map(|(input, _)| input),
    )
}

/// Locate the exact durable clean-management input and retain the logical
/// slot at which the guest originally admitted it. Post-application authority
/// acknowledgements must bind that historical slot on a result-loss retry;
/// resampling the current clock would produce a different application proof.
pub(super) fn recent_clean_management_operation<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    request: &crate::agent_sdk::ManagementRequest,
    authority: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<Option<(ReplayInputId, u64)>, JournalStoreError> {
    let mut cursor = materialization.heads().ordered_head;
    for _ in 0..MAX_PENDING_CLEAN_INVOCATION_RESULTS {
        let Some(id) = cursor else {
            return Ok(None);
        };
        if materialization.replay_boundary().head == Some(id) {
            return Ok(None);
        }
        let entry = store
            .get::<OrderedEntry>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        if entry.id() != id
            || entry.genesis != materialization.heads().genesis
            || entry.index > materialization.heads().ordered_index
        {
            return Err(JournalStoreError::Corrupt);
        }
        if let ReplayOperation::CleanManage {
            request: prior_request,
            authority: prior_authority,
            observed_slot,
        } = &entry.input.operation
            && prior_request == request
            && prior_authority == authority
        {
            return Ok(Some((entry.input.id(), *observed_slot)));
        }
        cursor = entry.parent;
    }
    Ok(None)
}

/// Locate an exact clean ordered invocation in the bounded durable suffix.
/// The historical observation slot is deliberately retained by the journal;
/// retry identity is the immutable work and authorization pair.
pub(super) fn recent_clean_ordered_input<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    let operation = ReplayOperation::CleanInvoke {
        context: crate::agent_sdk::RuntimeExecutionContext::Direct,
        work: work.clone(),
        authorization: authorization.clone(),
        observed_slot: 0,
    };
    recent_clean_ordered_operation(store, materialization, &operation)
}

/// Locate an exact clean invocation-lifecycle operation in the bounded
/// durable Ordered suffix. Observation slots are execution facts, not retry
/// identity. Encountering a newer lifecycle step for the same invocation
/// stops the search so an old Invoke/Yielded response cannot shadow Resume or
/// acknowledgement progress.
pub(super) fn recent_clean_ordered_operation<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    let started = std::time::Instant::now();
    let result = recent_clean_ordered_operation_bounded(
        store,
        materialization,
        operation,
        MAX_PENDING_CLEAN_INVOCATION_RESULTS,
    );
    tracing::debug!(
        elapsed_us = started.elapsed().as_micros() as u64,
        ordered_index = materialization.heads().ordered_index,
        "Clean ordered retry lookup complete"
    );
    result
}

/// Inspect only the authenticated interval after a caller's pre-dispatch
/// anchor. `None` means not observed in that interval, NOT never accepted in
/// earlier history. A pruned, substituted or unreachable anchor is an error.
/// Finish authenticating the anchor even after finding a matching operation.
pub(super) fn clean_ordered_operation_after<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    anchor: super::journal::OrderedBase,
    operation: &ReplayOperation,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    clean_ordered_operation_after_with_denial_ack(store, materialization, anchor, operation, false)
}

/// Denial completion may replay one exact Invoke followed by its exact ACK.
/// The caller separately verifies the canonical denial and positive ACK result.
pub(super) fn clean_denial_operation_after<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    anchor: super::journal::OrderedBase,
    operation: &ReplayOperation,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    clean_ordered_operation_after_with_denial_ack(store, materialization, anchor, operation, true)
}

fn clean_ordered_operation_after_with_denial_ack<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    anchor: super::journal::OrderedBase,
    operation: &ReplayOperation,
    allow_denial_ack: bool,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    anchor.validate().map_err(|_| JournalStoreError::Corrupt)?;
    let heads = materialization.heads();
    let boundary = materialization.replay_boundary();
    if anchor.index < boundary.index || anchor.index > heads.ordered_index {
        return Err(JournalStoreError::Conflict);
    }
    let distance = heads.ordered_index - anchor.index;
    if distance > super::replay::MAX_REPLAY_SUFFIX_ENTRIES as u64 {
        return Err(JournalStoreError::Backpressure);
    }
    let requested = clean_operation_invocation(operation).ok_or(JournalStoreError::Corrupt)?;
    let mut cursor = heads.ordered_head;
    let mut index = heads.ordered_index;
    let mut found = None;
    let mut acknowledgement = false;
    for _ in 0..distance {
        let id = cursor.ok_or(JournalStoreError::Corrupt)?;
        let entry = store
            .get::<OrderedEntry>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        if entry.id() != id
            || entry.genesis != heads.genesis
            || entry.index != index
            || entry.input.runtime != heads.runtime
        {
            return Err(JournalStoreError::Corrupt);
        }
        if clean_operation_invocation(&entry.input.operation) == Some(requested) {
            if allow_denial_ack
                && matches!((&entry.input.operation, operation),
                (ReplayOperation::CleanAcknowledge { context: a, expected_live: None, work: aw, authorization: aa },
                 ReplayOperation::CleanInvoke { context: b, work: bw, authorization: ba, .. }) if a == b && *aw == crate::agent_sdk::InvocationRetirement::from_work(bw) && aa == ba)
            {
                if found.is_some() || acknowledgement {
                    return Err(JournalStoreError::Conflict);
                }
                acknowledgement = true;
                cursor = entry.parent;
                index -= 1;
                continue;
            }
            // A different lifecycle step or substituted observation must not
            // be mistaken for absence, and duplicate publication is ambiguous.
            if entry.input.operation != *operation || found.is_some() {
                return Err(JournalStoreError::Conflict);
            }
            found = Some(entry.input.id());
        }
        cursor = entry.parent;
        index -= 1;
    }
    if cursor != anchor.head || (anchor.index == boundary.index && anchor != boundary) {
        return Err(JournalStoreError::Conflict);
    }
    if acknowledgement && found.is_none() {
        return Err(JournalStoreError::Conflict);
    }
    Ok(found)
}

pub(super) fn recent_clean_ordered_operation_bounded<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
    maximum: usize,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    let requested_invocation =
        clean_operation_invocation(operation).ok_or(JournalStoreError::Corrupt)?;
    let mut cursor = materialization.heads().ordered_head;
    for _ in 0..maximum {
        let Some(id) = cursor else {
            return Ok(None);
        };
        if materialization.replay_boundary().head == Some(id) {
            return Ok(None);
        }
        let entry = store
            .get::<OrderedEntry>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        if entry.id() != id
            || entry.genesis != materialization.heads().genesis
            || entry.index > materialization.heads().ordered_index
        {
            return Err(JournalStoreError::Corrupt);
        }
        if clean_operation_invocation(&entry.input.operation) == Some(requested_invocation) {
            if clean_operation_retry_equal(&entry.input.operation, operation) {
                return Ok(Some(entry.input.id()));
            }
            return if core::mem::discriminant(&entry.input.operation)
                == core::mem::discriminant(operation)
            {
                Err(JournalStoreError::Conflict)
            } else {
                Ok(None)
            };
        }
        cursor = entry.parent;
    }
    Err(JournalStoreError::Backpressure)
}

/// Locate an exact clean operation in the authenticated Local-lane suffix.
/// The walk is newest-first, bounded, and anchored at the materialized head;
/// objects merely present in the store are never retry evidence.
pub(super) fn recent_clean_local_operation<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    recent_clean_local_operation_bounded(
        store,
        materialization,
        operation,
        MAX_PENDING_CLEAN_INVOCATION_RESULTS,
    )
}

pub(super) fn recent_clean_local_operation_bounded<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
    maximum: usize,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    let requested_invocation =
        clean_operation_invocation(operation).ok_or(JournalStoreError::Corrupt)?;
    let (node, mut revision, mut cursor) = materialization.local_cursor();
    for _ in 0..maximum {
        let Some(id) = cursor else {
            return Ok(None);
        };
        let entry = store
            .get::<LocalEntry>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        if entry.id() != id
            || entry.genesis != materialization.heads().genesis
            || entry.node != node
            || entry.revision != revision
        {
            return Err(JournalStoreError::Corrupt);
        }
        if clean_operation_invocation(&entry.input.operation) == Some(requested_invocation) {
            if clean_operation_retry_equal(&entry.input.operation, operation) {
                return Ok(Some(entry.input.id()));
            }
            return if core::mem::discriminant(&entry.input.operation)
                == core::mem::discriminant(operation)
            {
                Err(JournalStoreError::Conflict)
            } else {
                Ok(None)
            };
        }
        cursor = entry.parent;
        revision = revision.checked_sub(1).ok_or(JournalStoreError::Corrupt)?;
    }
    Err(JournalStoreError::Backpressure)
}

/// Locate the newest exact clean operation for one invocation in the
/// authenticated Merge DAG. Both the visited and pending sets are bounded;
/// excessive fanout fails closed instead of turning retry into a global scan.
pub(super) fn recent_clean_merge_operation<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    recent_clean_merge_operation_bounded(
        store,
        materialization,
        operation,
        MAX_PENDING_CLEAN_INVOCATION_RESULTS,
    )
}

fn recent_clean_merge_operation_bounded<S: AgentJournalStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    operation: &ReplayOperation,
    maximum: usize,
) -> Result<Option<ReplayInputId>, JournalStoreError> {
    let requested_invocation =
        clean_operation_invocation(operation).ok_or(JournalStoreError::Corrupt)?;
    let frontier = store
        .get::<MergeFrontier>(materialization.merge_frontier())?
        .ok_or(JournalStoreError::MissingObject)?;
    if frontier.id() != materialization.merge_frontier()
        || frontier.genesis != materialization.heads().genesis
    {
        return Err(JournalStoreError::Corrupt);
    }
    let mut pending = frontier.events.into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut newest: Option<(u64, MergeEventId, ReplayOperation)> = None;
    while let Some(id) = pending.pop_last() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > maximum || pending.len() > maximum || !materialization.contains_merge(id) {
            return Err(JournalStoreError::Backpressure);
        }
        let event = store
            .get::<MergeEvent>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        if event.id() != id || event.genesis != materialization.heads().genesis {
            return Err(JournalStoreError::Corrupt);
        }
        if clean_operation_invocation(&event.input.operation) == Some(requested_invocation) {
            match &newest {
                Some((height, _, _)) if *height > event.causal_height => {}
                Some((height, _, selected)) if *height == event.causal_height => {
                    if !clean_operation_retry_equal(selected, &event.input.operation) {
                        return Err(JournalStoreError::Conflict);
                    }
                }
                _ => newest = Some((event.causal_height, id, event.input.operation.clone())),
            }
        }
        for parent in event.parents {
            if materialization.contains_merge(parent) && !seen.contains(&parent) {
                pending.insert(parent);
                if pending.len() > maximum {
                    return Err(JournalStoreError::Backpressure);
                }
            }
        }
    }
    let Some((_, id, selected)) = newest else {
        return Ok(None);
    };
    if clean_operation_retry_equal(&selected, operation) {
        let event = store
            .get::<MergeEvent>(id)?
            .ok_or(JournalStoreError::MissingObject)?;
        return Ok(Some(event.input.id()));
    }
    if core::mem::discriminant(&selected) == core::mem::discriminant(operation) {
        Err(JournalStoreError::Conflict)
    } else {
        Ok(None)
    }
}

fn clean_operation_invocation(
    operation: &ReplayOperation,
) -> Option<crate::agent_sdk::InvocationId> {
    match operation {
        ReplayOperation::CleanInvoke { work, .. } | ReplayOperation::CleanResume { work, .. } => {
            Some(work.invocation)
        }
        ReplayOperation::CleanAcknowledge { work, .. } => Some(work.invocation),
        _ => None,
    }
}

fn clean_operation_retry_equal(left: &ReplayOperation, right: &ReplayOperation) -> bool {
    match (left, right) {
        (
            ReplayOperation::CleanInvoke {
                context: left_context,
                work: left_work,
                authorization: left_authorization,
                ..
            },
            ReplayOperation::CleanInvoke {
                context: right_context,
                work: right_work,
                authorization: right_authorization,
                ..
            },
        ) => {
            left_context == right_context
                && left_work == right_work
                && left_authorization == right_authorization
        }
        (
            ReplayOperation::CleanAcknowledge {
                context: left_context,
                expected_live: left_expected_live,
                work: left_work,
                authorization: left_authorization,
            },
            ReplayOperation::CleanAcknowledge {
                context: right_context,
                expected_live: right_expected_live,
                work: right_work,
                authorization: right_authorization,
            },
        ) => {
            left_context == right_context
                && left_expected_live == right_expected_live
                && left_work == right_work
                && left_authorization == right_authorization
        }
        (
            ReplayOperation::CleanResume {
                context: left_context,
                expected_live: left_expected_live,
                work: left_work,
                authorization: left_authorization,
                yielded: left_yielded,
                ..
            },
            ReplayOperation::CleanResume {
                context: right_context,
                expected_live: right_expected_live,
                work: right_work,
                authorization: right_authorization,
                yielded: right_yielded,
                ..
            },
        ) => {
            left_context == right_context
                && left_expected_live == right_expected_live
                && left_work == right_work
                && left_authorization == right_authorization
                && left_yielded == right_yielded
        }
        _ => false,
    }
}

/// Immutable view of the exact catalog supplied alongside one sealed
/// genesis. Create-time validation must not consult the destination store:
/// doing so would either accept stale bytes or require staging untrusted
/// content before the root admission has been fully checked.
#[derive(Clone, Debug)]
struct SuppliedCatalogBlobResolver {
    blobs: Arc<BTreeMap<(Hash, u64), Vec<u8>>>,
}

impl SuppliedCatalogBlobResolver {
    fn from_catalog(catalog: &[RuntimeBlob]) -> Result<Self, LocalReplayExecutorError> {
        let mut blobs = BTreeMap::new();
        let mut aggregate = 0u64;
        for blob in catalog {
            if blob.bytes.len() > super::journal::MAX_ARTIFACT_CLOSURE_BYTES
                || !blob.reference.matches(&blob.bytes)
                || blobs
                    .insert(
                        (blob.reference.hash, blob.reference.len),
                        blob.bytes.clone(),
                    )
                    .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidArtifact(
                    blob.reference.clone(),
                ));
            }
            aggregate = aggregate
                .checked_add(blob.reference.len)
                .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        }
        if aggregate > super::journal::MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        Ok(Self {
            blobs: Arc::new(blobs),
        })
    }
}

impl CatalogBlobResolver for SuppliedCatalogBlobResolver {
    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError> {
        let Some(bytes) = self.blobs.get(&(reference.hash, reference.len)) else {
            return Ok(None);
        };
        if !reference.matches(bytes) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(Some(bytes.clone()))
    }
}

fn lift_checkpoint_error(
    error: MaterializeError<core::convert::Infallible, core::convert::Infallible>,
) -> LocalReplayError {
    match error {
        ReplayError::Source(error) => ReplayError::Source(error),
        ReplayError::Executor(never) => match never {},
        ReplayError::MissingOrdered(id) => ReplayError::MissingOrdered(id),
        ReplayError::MissingLocal(id) => ReplayError::MissingLocal(id),
        ReplayError::MissingMergeEvent(id) => ReplayError::MissingMergeEvent(id),
        ReplayError::MissingMergeFrontier(id) => ReplayError::MissingMergeFrontier(id),
        ReplayError::MissingMergeSeal(id) => ReplayError::MissingMergeSeal(id),
        ReplayError::MissingLaneState(id) => ReplayError::MissingLaneState(id),
        ReplayError::MissingArtifactClosure(id) => ReplayError::MissingArtifactClosure(id),
        ReplayError::MissingInvocationIndex(id) => ReplayError::MissingInvocationIndex(id),
        ReplayError::MissingCheckpoint(id) => ReplayError::MissingCheckpoint(id),
        ReplayError::InvalidRecord => ReplayError::InvalidRecord,
        ReplayError::ScopeMismatch => ReplayError::ScopeMismatch,
        ReplayError::ChainMismatch => ReplayError::ChainMismatch,
        ReplayError::ReplayLimit => ReplayError::ReplayLimit,
        ReplayError::InvalidCausalHeight => ReplayError::InvalidCausalHeight,
        ReplayError::NonMinimalFrontier => ReplayError::NonMinimalFrontier,
        ReplayError::StaleMergeBranch(id) => ReplayError::StaleMergeBranch(id),
        ReplayError::UnauthenticatedMergeEvent(id) => ReplayError::UnauthenticatedMergeEvent(id),
        ReplayError::InvalidOrderedBase => ReplayError::InvalidOrderedBase,
        ReplayError::UnavailableOrderedBase => ReplayError::UnavailableOrderedBase,
        ReplayError::InvalidFence => ReplayError::InvalidFence,
        ReplayError::StalePreFenceEvent(id) => ReplayError::StalePreFenceEvent(id),
        ReplayError::RuntimeMismatch => ReplayError::RuntimeMismatch,
        ReplayError::InvalidRuntimeUpgrade => ReplayError::InvalidRuntimeUpgrade,
        ReplayError::InvalidManagementTransition => ReplayError::InvalidManagementTransition,
        ReplayError::InvalidPosition => ReplayError::InvalidPosition,
        ReplayError::CrossLaneMutation => ReplayError::CrossLaneMutation,
        ReplayError::TerminalMutation => ReplayError::TerminalMutation,
        ReplayError::ForbiddenMergeProducts => ReplayError::ForbiddenMergeProducts,
        ReplayError::UncommittedInvocation(error) => ReplayError::UncommittedInvocation(error),
        ReplayError::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
    }
}

fn lift_prepared_genesis_error(
    error: ReplayError<core::convert::Infallible, LocalReplayExecutorError>,
) -> LocalReplayError {
    match error {
        ReplayError::Source(never) => match never {},
        ReplayError::Executor(error) => ReplayError::Executor(error),
        ReplayError::MissingOrdered(id) => ReplayError::MissingOrdered(id),
        ReplayError::MissingLocal(id) => ReplayError::MissingLocal(id),
        ReplayError::MissingMergeEvent(id) => ReplayError::MissingMergeEvent(id),
        ReplayError::MissingMergeFrontier(id) => ReplayError::MissingMergeFrontier(id),
        ReplayError::MissingMergeSeal(id) => ReplayError::MissingMergeSeal(id),
        ReplayError::MissingLaneState(id) => ReplayError::MissingLaneState(id),
        ReplayError::MissingArtifactClosure(id) => ReplayError::MissingArtifactClosure(id),
        ReplayError::MissingInvocationIndex(id) => ReplayError::MissingInvocationIndex(id),
        ReplayError::MissingCheckpoint(id) => ReplayError::MissingCheckpoint(id),
        ReplayError::InvalidRecord => ReplayError::InvalidRecord,
        ReplayError::ScopeMismatch => ReplayError::ScopeMismatch,
        ReplayError::ChainMismatch => ReplayError::ChainMismatch,
        ReplayError::ReplayLimit => ReplayError::ReplayLimit,
        ReplayError::InvalidCausalHeight => ReplayError::InvalidCausalHeight,
        ReplayError::NonMinimalFrontier => ReplayError::NonMinimalFrontier,
        ReplayError::StaleMergeBranch(id) => ReplayError::StaleMergeBranch(id),
        ReplayError::UnauthenticatedMergeEvent(id) => ReplayError::UnauthenticatedMergeEvent(id),
        ReplayError::InvalidOrderedBase => ReplayError::InvalidOrderedBase,
        ReplayError::UnavailableOrderedBase => ReplayError::UnavailableOrderedBase,
        ReplayError::InvalidFence => ReplayError::InvalidFence,
        ReplayError::StalePreFenceEvent(id) => ReplayError::StalePreFenceEvent(id),
        ReplayError::RuntimeMismatch => ReplayError::RuntimeMismatch,
        ReplayError::InvalidRuntimeUpgrade => ReplayError::InvalidRuntimeUpgrade,
        ReplayError::InvalidManagementTransition => ReplayError::InvalidManagementTransition,
        ReplayError::InvalidPosition => ReplayError::InvalidPosition,
        ReplayError::CrossLaneMutation => ReplayError::CrossLaneMutation,
        ReplayError::TerminalMutation => ReplayError::TerminalMutation,
        ReplayError::ForbiddenMergeProducts => ReplayError::ForbiddenMergeProducts,
        ReplayError::UncommittedInvocation(error) => ReplayError::UncommittedInvocation(error),
        ReplayError::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
    }
}

struct StandardLifecyclePreflight {
    result: Result<LifecycleReply, LifecycleError>,
    successor: StandardRuntimeState,
    unchanged: bool,
}

/// Execute the exact Standard lifecycle transition on a disposable clone.
///
/// Besides classifying byte-identical pre-disposition denials, this tells the
/// live admission boundary whether caller-supplied catalog bytes are actually
/// referenced by a successful successor. Deterministic consumed refusals are
/// journaled, but they never stage irrelevant content.
fn preflight_lifecycle_transition(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<StandardLifecyclePreflight, LocalReplayExecutorError> {
    let decoded =
        decode_standard_runtime_state(state).map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let mut runtime = StandardAgentRuntime::restore(decoded.clone())
        .map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let result = runtime.apply(request.clone());
    let successor = runtime.snapshot();
    let unchanged =
        successor == decoded && successor.authority_dispositions == decoded.authority_dispositions;
    Ok(StandardLifecyclePreflight {
        result,
        successor,
        unchanged,
    })
}

/// Classify lifecycle calls whose exact Standard transition is byte-identical.
/// Such calls are answered locally so they cannot move heads or accidentally
/// finalize unrelated pending Merge work.
fn uncommitted_lifecycle_result(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<Option<Result<LifecycleReply, LifecycleError>>, LocalReplayExecutorError> {
    let preflight = preflight_lifecycle_transition(state, request)?;
    Ok(preflight.unchanged.then_some(preflight.result))
}

fn validate_prospective_artifact_closure(
    genesis: super::journal::AgentJournalGenesisId,
    successor: &StandardRuntimeState,
) -> Result<(), LocalReplayExecutorError> {
    let config = successor
        .config
        .as_ref()
        .ok_or(LocalReplayExecutorError::InvalidState)?;
    let mut artifacts = vec![config.runtime_package.clone()];
    for actor in &successor.actors {
        artifacts.push(actor.record.package.clone());
        artifacts.push(actor.record.agent_schema.clone());
        artifacts.push(actor.record.role_policies.clone());
        if let Some(installation_data) = &actor.record.installation_data {
            artifacts.push(installation_data.clone());
        }
    }
    artifacts.sort_unstable_by_key(|artifact| (artifact.hash, artifact.len));
    artifacts.dedup_by_key(|artifact| (artifact.hash, artifact.len));
    let closure = super::journal::ArtifactClosure { genesis, artifacts };
    closure
        .validate()
        .map_err(|_| LocalReplayExecutorError::InvalidRequest)
}

/// Recover an exact retained lifecycle disposition without consulting live
/// package trust or the current catalog. Historical bytes may already have
/// been garbage-collected after an actor was removed; the signed claim and
/// bounded Standard disposition are the retry authority.
fn retained_lifecycle_disposition(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<Option<Result<LifecycleReply, LifecycleError>>, LocalReplayExecutorError> {
    let LifecycleRequest::Authorized { admission, request } = request else {
        return Err(LocalReplayExecutorError::InvalidRequest);
    };
    let decoded =
        decode_standard_runtime_state(state).map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let claim = &admission.receipt.claim;
    let claim_hash = claim.signing_message();
    Ok(decoded
        .authority_dispositions
        .iter()
        .find(|disposition| disposition.sequence == claim.sequence)
        .filter(|disposition| {
            disposition.credential == claim.credential
                && disposition.claim == claim_hash
                && disposition.operation == request.commitment()
        })
        .map(|disposition| disposition.result.clone()))
}

/// Bind a lifecycle receipt to the driver's trusted clock exactly once.
///
/// Callers provide only the signed receipt and its inner operation.  An
/// already-authorized request is rejected so its unsigned `observed_slot`
/// can never cross this live admission boundary. Historical replay consumes
/// the resulting sealed request without consulting the current clock.
fn seal_lifecycle_request(
    trust: &dyn AgentTrustProvider,
    receipt: AgentAuthorityReceipt,
    request: LifecycleRequest,
) -> Result<LifecycleRequest, LocalReplayExecutorError> {
    if matches!(request, LifecycleRequest::Authorized { .. }) {
        return Err(LocalReplayExecutorError::InvalidRequest);
    }
    let observed_slot = trust
        .current_logical_slot()
        .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
    Ok(LifecycleRequest::Authorized {
        admission: LifecycleAuthorityAdmission {
            receipt,
            observed_slot,
        },
        request: Box::new(request),
    })
}

/// Authority-certified signing and verification for this exact Local replica.
///
/// Implementations are injected by the node identity boundary.  Possessing an
/// arbitrary signing key is not sufficient: the implementation must have
/// already certified that [`Self::node`] is the sole replica admitted by the
/// Agent's immutable Local profile.
pub trait LocalMergeAuthenticator: Send + Sync {
    fn node(&self) -> NodeId;

    /// Sign exactly the canonical Merge-event message in place.
    ///
    /// Keeping the complete event at this seam prevents a daemon-backed key
    /// from becoming a generic signing oracle. Implementations must refuse an
    /// event whose author is not [`Self::node`].
    fn sign_event(&self, event: &mut MergeEvent) -> bool;

    fn verify_event(&self, event: &MergeEvent) -> bool;

    /// Sign one fully reconstructed Shared-Agent checkpoint candidate. The
    /// default is fail-closed; authenticated node-key implementations must
    /// additionally prove that their exact node/key is an admitted voter.
    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_snapshot_candidate(
        &self,
        _candidate: &super::shared_host::VerifiedSharedAgentSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        None
    }

    /// Sign only an independently reconstructed common Shared checkpoint.
    /// The exact admitted voter/key checks remain the signer's responsibility.
    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_common_snapshot_candidate(
        &self,
        _candidate: &super::shared_host::VerifiedSharedAgentCommonSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        None
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_recovery_expiry_candidate(
        &self,
        _candidate: &super::shared_host::VerifiedSharedRecoveryExpiryCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        None
    }

    /// Bind this node's reconstructed physical checkpoint to a verified common
    /// certificate. This is node-local publication authority, not another vote.
    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_local_snapshot_candidate(
        &self,
        _candidate: &super::shared_host::VerifiedSharedAgentLocalSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        None
    }

    /// Sign only a recovery-registration candidate minted by the bootstrap
    /// lifecycle after its preceding local delivery obligation is durably
    /// clear. Decoding an arbitrary registration never grants this authority.
    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_projection_recovery_registration(
        &self,
        _candidate: &super::clean_bootstrap::VerifiedProjectionRecoveryRegistration,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        None
    }
}

/// Why an authenticated node key cannot back Local Merge publications.
#[cfg(feature = "network")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519NodeMergeAuthenticatorError {
    NonEd25519Key,
}

/// Local Merge authenticator backed directly by the daemon's authenticated
/// libp2p Ed25519 identity.
///
/// Construction consumes a keypair handle rather than exporting its secret
/// bytes. The full canonical PeerId, not a compact routing prefix, derives the
/// [`NodeId`] committed by Local journal records.
#[cfg(feature = "network")]
#[derive(Clone)]
pub struct Ed25519NodeMergeAuthenticator {
    keypair: libp2p::identity::Keypair,
    node: NodeId,
}

#[cfg(feature = "network")]
impl Ed25519NodeMergeAuthenticator {
    pub fn new(
        keypair: libp2p::identity::Keypair,
    ) -> Result<Self, Ed25519NodeMergeAuthenticatorError> {
        if keypair.clone().try_into_ed25519().is_err() {
            return Err(Ed25519NodeMergeAuthenticatorError::NonEd25519Key);
        }
        let peer = keypair.public().to_peer_id();
        let node = NodeId::of_authenticated_peer(&peer.to_bytes());
        Ok(Self { keypair, node })
    }
}

#[cfg(feature = "network")]
impl LocalMergeAuthenticator for Ed25519NodeMergeAuthenticator {
    fn node(&self) -> NodeId {
        self.node
    }

    fn sign_event(&self, event: &mut MergeEvent) -> bool {
        if event.author != self.node || !event.signature.is_empty() {
            return false;
        }
        let Ok(signature) = self.keypair.sign(&event.signing_message().0) else {
            return false;
        };
        if signature.len() != super::authority::ED25519_SIGNATURE_BYTES {
            return false;
        }
        event.signature = signature;
        self.verify_event(event)
    }

    fn verify_event(&self, event: &MergeEvent) -> bool {
        event.author == self.node
            && event.signature.len() == super::authority::ED25519_SIGNATURE_BYTES
            && self
                .keypair
                .public()
                .verify(&event.signing_message().0, &event.signature)
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_snapshot_candidate(
        &self,
        candidate: &super::shared_host::VerifiedSharedAgentSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        let committee = candidate.claim().active_committee();
        let member = committee.member_by_node(self.node)?;
        if member.replica().role != super::ReplicaRole::Voter
            || member.ed25519_public_key()
                != &self.keypair.public().try_into_ed25519().ok()?.to_bytes()
            || member.peer_id() != self.keypair.public().to_peer_id().to_bytes()
        {
            return None;
        }
        let signature: [u8; super::authority::ED25519_SIGNATURE_BYTES] = self
            .keypair
            .sign(&candidate.signing_message().0)
            .ok()?
            .try_into()
            .ok()?;
        super::shared_commit::ReplicaCommitSignature::new(self.node, signature).ok()
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_common_snapshot_candidate(
        &self,
        candidate: &super::shared_host::VerifiedSharedAgentCommonSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        let member = candidate
            .claim()
            .active_committee()
            .member_by_node(self.node)?;
        if member.replica().role != super::ReplicaRole::Voter
            || member.ed25519_public_key()
                != &self.keypair.public().try_into_ed25519().ok()?.to_bytes()
            || member.peer_id() != self.keypair.public().to_peer_id().to_bytes()
        {
            return None;
        }
        let signature = self
            .keypair
            .sign(&candidate.signing_message().0)
            .ok()?
            .try_into()
            .ok()?;
        super::shared_commit::ReplicaCommitSignature::new(self.node, signature).ok()
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_recovery_expiry_candidate(
        &self,
        candidate: &super::shared_host::VerifiedSharedRecoveryExpiryCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        let member = candidate.claim().committee().member_by_node(self.node)?;
        if member.replica().role != super::ReplicaRole::Voter
            || member.ed25519_public_key()
                != &self.keypair.public().try_into_ed25519().ok()?.to_bytes()
            || member.peer_id() != self.keypair.public().to_peer_id().to_bytes()
        {
            return None;
        }
        let signature = self
            .keypair
            .sign(&candidate.signing_message().0)
            .ok()?
            .try_into()
            .ok()?;
        super::shared_commit::ReplicaCommitSignature::new(self.node, signature).ok()
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_local_snapshot_candidate(
        &self,
        candidate: &super::shared_host::VerifiedSharedAgentLocalSnapshotCandidate,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        let member = candidate
            .claim()
            .active_committee()
            .member_by_node(self.node)?;
        if candidate.claim().local_node() != self.node
            || member.replica().role != super::ReplicaRole::Voter
            || member.ed25519_public_key()
                != &self.keypair.public().try_into_ed25519().ok()?.to_bytes()
            || member.peer_id() != self.keypair.public().to_peer_id().to_bytes()
        {
            return None;
        }
        let signature = self
            .keypair
            .sign(&candidate.signing_message().0)
            .ok()?
            .try_into()
            .ok()?;
        super::shared_commit::ReplicaCommitSignature::new(self.node, signature).ok()
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn sign_projection_recovery_registration(
        &self,
        candidate: &super::clean_bootstrap::VerifiedProjectionRecoveryRegistration,
    ) -> Option<super::shared_commit::ReplicaCommitSignature> {
        let member = candidate.committee().member_by_node(self.node)?;
        if candidate.owner() != self.node
            || member.replica().role != super::ReplicaRole::Voter
            || member.ed25519_public_key()
                != &self.keypair.public().try_into_ed25519().ok()?.to_bytes()
            || member.peer_id() != self.keypair.public().to_peer_id().to_bytes()
        {
            return None;
        }
        let signature = self
            .keypair
            .sign(&candidate.signing_message().0)
            .ok()?
            .try_into()
            .ok()?;
        super::shared_commit::ReplicaCommitSignature::new(self.node, signature).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalReplayExecutorError {
    InvalidState,
    InvalidProfile,
    WrongReplica,
    TrustUnavailable,
    InvalidAuthority,
    InvalidRequest,
    ArtifactUnavailable(BlobRef),
    InvalidArtifact(BlobRef),
    Package(PackageError),
    RuntimeExit { reason: ExitReason, pc: u32 },
    RuntimeOutput,
    RuntimeBackend,
    RuntimeStateTooLarge,
    Store(JournalStoreError),
}

impl core::fmt::Display for LocalReplayExecutorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "local replay executor: {self:?}")
    }
}

impl std::error::Error for LocalReplayExecutorError {}

impl From<JournalStoreError> for LocalReplayExecutorError {
    fn from(error: JournalStoreError) -> Self {
        Self::Store(error)
    }
}

/// Durable proof-host boundary used by the Standard replay executor.
///
/// The implementation owns the producer sidecar and an authoritative journal
/// reader. It must return the authoritative published tuple for an exact
/// retained key before attempting execution, which is what makes Merge
/// rebuilds and ordered fences reuse an unchanged proof without running
/// application code again. `PublishedOnly` is a strict read mode: absence or
/// corruption must fail without executing, proving, signing, or staging. For
/// new or changed work under `PrepareAllowed` it executes/proves once, stages
/// and reads back the complete public closure, and returns only the resulting
/// thin capability plus the exact transition tuple. The mutable head is never
/// changed through this seam.
pub(crate) trait AttestedReplayTransitionProvider: Send {
    /// Load one exact tuple from authoritative journal state. This method has
    /// no preparation return type, so historical replay and validate-only
    /// projections cannot accidentally authorize a freshly staged proof.
    fn load_published_transition(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        work: &crate::agent_sdk::RuntimeWork,
    ) -> Result<PublishedAttestedTransition, LocalReplayExecutorError>;

    fn prepare_verified_transition(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        work: &crate::agent_sdk::RuntimeWork,
    ) -> Result<AttestedReplayTransitionPreparation, LocalReplayExecutorError>;
}

/// Exact public tuple returned to replay after the provider has either found
/// it in the authoritative journal or staged a newly verified closure there.
///
/// The large producer result is consumed while constructing this value. A
/// replay batch therefore retains only a bounded thin storage capability, not
/// up to 1024 proof-material buffers while waiting for the head CAS.
pub(crate) struct AttestedReplayTransitionPreparation {
    canonical_work: Vec<u8>,
    canonical_transition: Vec<u8>,
    proof_record: crate::agent_sdk::proof::TransitionProofRecord,
    publication: TransitionPublicationFact,
    staged: Option<StagedTransitionProof>,
}

impl AttestedReplayTransitionPreparation {
    /// Consume one host preparation after its complete public closure has
    /// been staged and read back by the authoritative journal writer.
    pub(crate) fn from_staged(
        prepared: PreparedVerifiedTransition,
        staged: StagedTransitionProof,
    ) -> Self {
        Self {
            canonical_work: prepared.canonical_work().to_vec(),
            canonical_transition: prepared.canonical_transition().to_vec(),
            proof_record: prepared.proof_record().clone(),
            publication: prepared.expected_fact(),
            staged: Some(staged),
        }
    }

    /// Reuse the exact tuple reconstructed from authoritative journal state.
    pub(crate) fn from_published(published: PublishedAttestedTransition) -> Self {
        Self {
            canonical_work: published.canonical_work,
            canonical_transition: published.canonical_transition,
            proof_record: published.proof_record,
            publication: published.publication,
            staged: None,
        }
    }
}

/// Driver-level failures. Typed actor and lifecycle refusals are returned by
/// the operation APIs and therefore do not appear here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalJournalDriverError {
    Store(JournalStoreError),
    Replay(LocalReplayError),
    Executor(LocalReplayExecutorError),
    Lifecycle(LifecycleError),
    AuthorityLedger,
    AuthorityRecoveryRequired,
    Conflict,
    InvalidResult,
}

#[cfg(all(feature = "storage", target_os = "linux"))]
pub(crate) enum LocalJournalUnexposedOpenError<E> {
    Driver(LocalJournalDriverError),
    BeforeExposure(E),
}

#[cfg(all(feature = "storage", target_os = "linux"))]
impl From<SystemAuthorityLedgerError> for LocalJournalDriverError {
    fn from(_error: SystemAuthorityLedgerError) -> Self {
        Self::AuthorityLedger
    }
}

#[cfg(all(feature = "storage", target_os = "linux"))]
fn map_system_authority_recovery_error(
    error: SystemAuthorityRecoveryError<LocalReplayExecutorError>,
) -> LocalJournalDriverError {
    match error {
        SystemAuthorityRecoveryError::Journal(error) => error.into(),
        SystemAuthorityRecoveryError::Ledger(_) => LocalJournalDriverError::AuthorityLedger,
        SystemAuthorityRecoveryError::Replay(error) => LocalJournalDriverError::Replay(error),
    }
}

impl core::fmt::Display for LocalJournalDriverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "local journal agent driver: {self:?}")
    }
}

impl std::error::Error for LocalJournalDriverError {}

impl From<JournalStoreError> for LocalJournalDriverError {
    fn from(error: JournalStoreError) -> Self {
        if error == JournalStoreError::Conflict {
            Self::Conflict
        } else {
            Self::Store(error)
        }
    }
}

impl From<LocalReplayError> for LocalJournalDriverError {
    fn from(error: LocalReplayError) -> Self {
        match error {
            ReplayError::Source(ReplayMaterializationSourceError::Journal(
                JournalStoreError::Conflict,
            )) => Self::Conflict,
            error => Self::Replay(error),
        }
    }
}

impl From<LocalReplayExecutorError> for LocalJournalDriverError {
    fn from(error: LocalReplayExecutorError) -> Self {
        Self::Executor(error)
    }
}

/// Recovery capability returned while a Merge source remains pending.
///
/// It is restart-safe until finalization. After the owner becomes a
/// permanent acknowledged-history fact, checkpoint GC may prune this suffix
/// position; callers must then submit a fresh authenticated acknowledgement
/// retry, which resolves that history fact without the historical event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingMergeReceipt {
    pub event: MergeEventId,
    pub frontier: MergeFrontierId,
    pub input: ReplayInput,
    pub position: ReplayPosition,
}

/// Invocation result at the journal boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalInvocationResult {
    Final(Result<ActorExecutionReply, ActorExecutionError>),
    Pending(PendingMergeReceipt),
    Acknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalAcknowledgementResult {
    Acknowledged,
    Pending(PendingMergeReceipt),
    /// This invocation ID is durably owned by a different request
    /// commitment. No information about that request or its result is
    /// disclosed.
    Divergent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalizedMergeInvocation {
    pub input: ReplayInputId,
    pub position: ReplayPosition,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalLifecycleResult {
    pub result: Result<LifecycleReply, LifecycleError>,
    pub finalized_merge_invocations: Vec<FinalizedMergeInvocation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalCleanManagementResult {
    pub outcome: crate::agent_sdk::RuntimeOutcome,
    pub finalized_merge_invocations: Vec<FinalizedMergeInvocation>,
}

/// One deterministic lifecycle request bound to its complete, exact catalog
/// input. The host may expose `request()` for authority signing and later
/// consume the same value for publication; callers cannot accidentally pair
/// an install request with a different package closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalLifecycleOperation {
    request: LifecycleRequest,
    catalog: Vec<RuntimeBlob>,
}

struct StagedCatalog {
    predecessor: super::journal::JournalHeadsId,
    created: Vec<UnpublishedCatalogBlob>,
}

impl LocalLifecycleOperation {
    pub(crate) fn request(&self) -> &LifecycleRequest {
        &self.request
    }

    pub(crate) fn catalog(&self) -> &[RuntimeBlob] {
        &self.catalog
    }

    pub(crate) fn into_parts(self) -> (LifecycleRequest, Vec<RuntimeBlob>) {
        (self.request, self.catalog)
    }
}

/// Fully settled invocation result for synchronous host adapters. Unlike
/// [`LocalInvocationResult`], this type cannot represent a provisional Merge
/// disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalSettledInvocationResult {
    Final(Result<ActorExecutionReply, ActorExecutionError>),
    /// The exact request has already crossed its durable acknowledgement
    /// boundary, so its historical reply is intentionally unavailable.
    Acknowledged,
}

/// Fully settled acknowledgement result for synchronous host adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalSettledAcknowledgementResult {
    Acknowledged,
    Divergent,
}

/// The ordinary handoff is latest-by-input; custody evidence instead names
/// an exact Ordered occurrence. Shared Ordered outcomes live only once here.
enum RecentCleanResult {
    Ordered(OrderedEntryId),
    Unpositioned(crate::agent_sdk::RuntimeOutcome),
}

/// Exact Standard-runtime replay executor backed by an immutable catalog
/// resolver snapshot.
pub(crate) struct StandardLocalReplayExecutor<R> {
    resolver: R,
    #[cfg(feature = "experimental-state-blocks")]
    external: Option<super::external_local_executor::ExternalLocalReplayExecutor<R>>,
    #[cfg(feature = "experimental-state-blocks")]
    external_execution: Option<super::replay::ReplayExternalExecution>,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    profile: AgentProfile,
    shared_committees: BTreeMap<AgentReplicaCommitteeId, AgentReplicaCommittee>,
    /// The local Shared replica is an explicit joiner outside the genesis
    /// descriptor's roster; its ledger, not the descriptor, admits it.
    shared_joiner: bool,
    management_gas: Gas,
    last_management_result: Option<(ReplayInputId, Result<LifecycleReply, LifecycleError>)>,
    pending_clean_invocation_results: BTreeMap<ReplayInputId, crate::agent_sdk::RuntimeOutcome>,
    recent_clean_ordered_results: BTreeMap<ReplayInputId, RecentCleanResult>,
    recent_clean_ordered_order: VecDeque<ReplayInputId>,
    positioned_clean_results:
        BTreeMap<(OrderedEntryId, ReplayInputId), crate::agent_sdk::RuntimeOutcome>,
    positioned_clean_order: VecDeque<(OrderedEntryId, ReplayInputId)>,
    recent_clean_management_results: BTreeMap<ReplayInputId, crate::agent_sdk::RuntimeOutcome>,
    recent_clean_management_order: VecDeque<ReplayInputId>,
    clean_genesis_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    authenticated_execution: Option<AuthenticatedLocalExecution>,
    attested_transition_provider: Option<Box<dyn AttestedReplayTransitionProvider>>,
    allow_attested_preparation: bool,
    pending_transition_proof: Option<PendingReplayTransitionProof>,
    staged_transition_proofs: Vec<StagedTransitionProof>,
    terminal_preflight: std::sync::Mutex<Option<TerminalPreflight>>,
    runtime_preparation: RuntimePreparationCache,
}

/// One bounded immutable preparation per executor; no results or authorization
/// decisions are cached. Exact bytes, not a caller-supplied identity, select it.
#[derive(Default)]
struct RuntimePreparationCache {
    entry: std::sync::Mutex<
        Option<(
            Vec<u8>,
            Arc<vos_pvm::refine::PreparedProgram>,
            vos_pvm::PvmBackend,
        )>,
    >,
}

impl RuntimePreparationCache {
    fn load(
        &self,
        program: &[u8],
        input: &[u8],
        gas: Gas,
    ) -> Result<RefineContext, vos_pvm::refine::RefineError> {
        let backend = super::runtime_pvm::execution_backend();
        // Preserve the cold loader's behavior outside the cache admission
        // bound; this optimization must not introduce a new execution rule.
        if program.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES {
            return RefineContext::load_with_backend(
                program,
                input,
                gas,
                vos_pvm::refine::MemoryModel::Auto,
                backend,
            );
        }
        let prepared = {
            let Ok(mut entry) = self.entry.lock() else {
                return RefineContext::load_with_backend(
                    program,
                    input,
                    gas,
                    vos_pvm::refine::MemoryModel::Auto,
                    backend,
                );
            };
            if let Some((_, prepared, _)) = entry
                .as_ref()
                .filter(|(bytes, _, selected)| bytes.as_slice() == program && *selected == backend)
            {
                Arc::clone(prepared)
            } else {
                let prepared = Arc::new(vos_pvm::refine::PreparedProgram::new_with_backend(
                    program, backend,
                )?);
                *entry = Some((program.to_vec(), Arc::clone(&prepared), backend));
                prepared
            }
        };
        // Do not hold the cache lock while allocating or running a machine.
        RefineContext::load_prepared(&prepared, input, gas, vos_pvm::refine::MemoryModel::Auto)
    }
}

/// Opt-in instruction attribution for physical tests only. It reports no work
/// bytes or guest memory and does not change the production execution path.
#[cfg(test)]
fn profile_refine_machines(
    context: RefineContext,
    input_bytes: usize,
    work_tag: Option<u8>,
) -> vos_pvm::refine::Invocation {
    use vos_pvm::refine_host::{RefineMachineIdentity, RefineObservation};
    let index = |identity| usize::from(!matches!(identity, RefineMachineIdentity::Outer));
    let mut instructions = [0u64; 2];
    let mut elapsed = [0u128; 2];
    let mut entered = [None; 2];
    let mut host_calls = 0u64;
    let mut outer_pc_counts = Vec::<u64>::new();
    let result = context.run_observed(|event| match event {
        RefineObservation::MachineEnter { identity, machine } => {
            if matches!(identity, RefineMachineIdentity::Outer) && outer_pc_counts.is_empty() {
                outer_pc_counts.resize(machine.code.len(), 0);
            }
            entered[index(identity)] = Some(std::time::Instant::now());
        }
        RefineObservation::Instruction {
            identity,
            instruction,
        } => {
            instructions[index(identity)] += 1;
            if matches!(identity, RefineMachineIdentity::Outer) {
                outer_pc_counts[instruction.pc_before as usize] += 1;
            }
        }
        RefineObservation::MachineExit { identity, .. } => {
            let i = index(identity);
            elapsed[i] += entered[i]
                .take()
                .expect("machine entered before exit")
                .elapsed()
                .as_micros();
        }
        RefineObservation::HostCall {
            phase: vos_pvm::refine_host::RefineHostPhase::Before,
            ..
        } => host_calls += 1,
        _ => {}
    });
    eprintln!(
        "refine_machine_profile work_tag={work_tag:?} input_bytes={input_bytes} gas_used={} outer_instructions={} inner_instructions={} outer_observed_us={} inner_observed_us={} host_calls={host_calls}",
        result.gas_used, instructions[0], instructions[1], elapsed[0], elapsed[1]
    );
    assert_eq!(outer_pc_counts.iter().sum::<u64>(), instructions[0]);
    let mut regions: Vec<_> = outer_pc_counts
        .chunks(4096)
        .enumerate()
        .map(|(index, counts)| {
            let (offset, _) = counts
                .iter()
                .enumerate()
                .max_by_key(|&(_, count)| count)
                .unwrap();
            (
                index * 4096,
                index * 4096 + offset,
                counts.iter().sum::<u64>(),
            )
        })
        .collect();
    regions.sort_unstable_by_key(|&(start, _, count)| (core::cmp::Reverse(count), start));
    for (start, pc, count) in regions
        .into_iter()
        .take(16)
        .filter(|&(_, _, count)| count != 0)
    {
        eprintln!("refine_outer_hot_region start={start} pc={pc} instructions={count}");
    }
    let mut hot: Vec<_> = outer_pc_counts.into_iter().enumerate().collect();
    hot.sort_unstable_by_key(|&(pc, count)| (core::cmp::Reverse(count), pc));
    for (pc, count) in hot.into_iter().take(16).filter(|&(_, count)| count != 0) {
        eprintln!("refine_outer_hot_pc pc={pc} instructions={count}");
    }
    result
}

/// One local computation, never durable evidence or an authentication cache.
/// Canonical input includes all state lanes, authorization and blob preimages.
struct TerminalPreflight {
    runtime_pvm: Vec<u8>,
    input: Vec<u8>,
    gas: Gas,
    transition: crate::agent_sdk::RuntimeTransition,
}

impl TerminalPreflight {
    fn consume(
        slot: &mut Option<Self>,
        runtime_pvm: &[u8],
        input: &[u8],
        gas: Gas,
    ) -> Option<crate::agent_sdk::RuntimeTransition> {
        let prepared = slot.take()?;
        (prepared.runtime_pvm == runtime_pvm && prepared.input == input && prepared.gas == gas)
            .then_some(prepared.transition)
    }
}

/// One-shot capability minted by [`ReplayExecutor::authenticate`] and consumed
/// by the immediately following [`ReplayExecutor::execute`]. Keeping the
/// already trusted runtime package here prevents execution from repeating the
/// package/root trust boundary while still refusing unauthenticated direct
/// execution.
struct AuthenticatedLocalExecution {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
    runtime_pvm: Vec<u8>,
    runtime_state_limit: usize,
    clean_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
}

/// Exact proof tuple returned by the provider for the immediately preceding
/// runtime transition. Replay consumes it once, after independently checking
/// the returned transition semantics. A prepared tuple is exposed to the
/// publication coordinator only after that consumption succeeds.
struct PendingReplayTransitionProof {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
    runtime_transition: crate::agent_sdk::RuntimeTransition,
    key: crate::agent_sdk::proof::TransitionProofKey,
    before_roots: crate::agent_sdk::proof::ProofLaneRoots,
    after_roots: crate::agent_sdk::proof::ProofLaneRoots,
    publication: crate::agent_sdk::Hash,
    staged: Option<StagedTransitionProof>,
}

struct ActorCatalogAdmission<'a> {
    package: &'a BlobRef,
    schema: &'a BlobRef,
    policies: &'a BlobRef,
    constructor_abi: Hash,
    deployment: crate::service::DeploymentId,
    program: crate::service::ProgramId,
    producer: crate::service::ProducerId,
    state_layout: Hash,
    contract: super::contract::ActorPackageContract,
    requirements: super::RuntimeRequirements,
}

impl<R: CatalogBlobResolver> StandardLocalReplayExecutor<R> {
    fn clean_blob(reference: &crate::agent_sdk::BlobRef) -> BlobRef {
        BlobRef {
            hash: Hash(reference.hash.0),
            len: reference.len,
        }
    }

    fn validate_clean_genesis_descriptor(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
    ) -> Result<(), LocalReplayExecutorError> {
        let expected_profile = match self.profile {
            AgentProfile::Local => crate::agent_sdk::AgentProfile::Local,
            AgentProfile::Shared => crate::agent_sdk::AgentProfile::Shared,
            AgentProfile::Private => crate::agent_sdk::AgentProfile::Private,
        };
        let local_node = self.merge.node();
        let named = descriptor
            .replicas
            .iter()
            .any(|replica| replica.node.0 == local_node.0);
        if descriptor.validate().is_err()
            || descriptor.identity.profile != expected_profile
            || (self.profile == AgentProfile::Local && descriptor.replicas.len() != 1)
            || named == (self.shared_joiner && self.profile == AgentProfile::Shared)
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(())
    }

    fn clean_runtime_package(
        &self,
        binding: &RuntimeBinding,
    ) -> Result<super::package_admission::AdmittedRuntimePackage, LocalReplayExecutorError> {
        if binding.runtime_abi != super::RUNTIME_ABI_ID
            || binding.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        let reference = binding.package.clone();
        let bytes = self.load(&reference)?;
        let package = super::package_admission::admit_runtime_package(&bytes)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(reference.clone()))?;
        if package.package_ref().hash.0 != binding.package.hash.0
            || package.package_ref().len != binding.package.len
            || package.deployment().0 != binding.deployment.0
            || package.program().0 != binding.program.0
            || package.producer().0 != binding.producer.0
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(reference));
        }
        Ok(package)
    }

    fn current_clean_descriptor(
        genesis: &crate::agent_sdk::AgentDescriptor,
        binding: &RuntimeBinding,
        runtime: &super::package_admission::AdmittedRuntimePackage,
    ) -> Result<crate::agent_sdk::AgentDescriptor, LocalReplayExecutorError> {
        let mut descriptor = genesis.clone();
        if descriptor.identity.space.0 != binding.space.0
            || descriptor.identity.agent.0 != binding.agent.0
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        descriptor.identity.runtime_deployment = runtime.deployment();
        descriptor.identity.runtime_program = runtime.program();
        descriptor.identity.runtime_producer = runtime.producer();
        descriptor.runtime_package = runtime.package_ref().clone();
        descriptor.runtime_contract = runtime.manifest().contract;
        descriptor.capabilities = runtime.capabilities();
        Ok(descriptor)
    }

    /// Execute for an explicit Shared joiner: the local node must be absent
    /// from the genesis descriptor, which never names it.
    pub(crate) fn admit_shared_joiner(&mut self) {
        self.shared_joiner = self.profile == AgentProfile::Shared;
    }

    pub(crate) fn seeded_clean_descriptor(&self) -> Option<&crate::agent_sdk::AgentDescriptor> {
        self.clean_genesis_descriptor.as_ref()
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn external_runtime(
        &self,
    ) -> Option<&super::package_admission::AdmittedStateRuntimePackage> {
        self.external.as_ref().map(|executor| executor.runtime())
    }

    pub(crate) fn trusted_current_clean_descriptor(
        &self,
        binding: &RuntimeBinding,
    ) -> Result<crate::agent_sdk::AgentDescriptor, LocalReplayExecutorError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            return external
                .trusted_clean_descriptor(binding)?
                .ok_or(LocalReplayExecutorError::InvalidState);
        }
        let genesis = self
            .clean_genesis_descriptor
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let runtime = self.clean_runtime_package(binding)?;
        Self::current_clean_descriptor(genesis, binding, &runtime)
    }

    pub(crate) fn preview_clean_management(
        &self,
        binding: &RuntimeBinding,
        before: &RuntimeState,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
        validate_catalog: bool,
    ) -> Result<crate::agent_sdk::RuntimeTransition, LocalReplayExecutorError> {
        let runtime = self.clean_runtime_package(binding)?;
        let descriptor = Self::current_clean_descriptor(
            self.clean_genesis_descriptor
                .as_ref()
                .ok_or(LocalReplayExecutorError::InvalidState)?,
            binding,
            &runtime,
        )?;
        let expiry = super::driver::verify_clean_management_journal_receipt(
            &descriptor,
            request,
            authority,
            observed_slot,
            true,
        )
        .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        if validate_catalog {
            self.validate_clean_management_artifacts(&descriptor, request)?;
        }
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: authority.selector.runtime_deployment,
            state: crate::agent_sdk::RuntimeState {
                control: before.control.clone(),
                linear: before.linear.clone(),
                merge: before.merge.clone(),
                local: before.local.clone(),
            },
            request: Box::new(request.clone()),
            authority: Some(Box::new(authority.clone())),
            observed_slot,
        };
        #[cfg(all(test, feature = "pvm"))]
        let returned: crate::agent_sdk::RuntimeTransition =
            if self.trust.use_native_clean_runtime_for_test() {
                super::wire::apply_standard_runtime_work(work)
                    .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
            } else {
                let encoded = work
                    .encode()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
            };
        #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
        let returned: crate::agent_sdk::RuntimeTransition = {
            let encoded = work
                .encode()
                .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
            self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
        };
        if expiry
            && (returned.outcome
                != crate::agent_sdk::RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::ExpiredBeforeApplication,
                ))
                || (returned.state.control == before.control
                    && returned.state.linear == before.linear
                    && returned.state.merge == before.merge
                    && returned.state.local == before.local))
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        if !super::driver::sdk_management_reply_matches(&descriptor, request, &returned.outcome)
            || returned.state.encoded_len().is_none_or(|bytes| {
                bytes
                    > runtime
                        .manifest()
                        .contract
                        .resources
                        .max_runtime_state_bytes as usize
            })
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(returned)
    }

    /// Execute one read-only SDK management query against the exact current
    /// runtime/state. The transition must preserve every lane byte-for-byte;
    /// this is observational and never enters a journal or Raft slot.
    pub(crate) fn inspect_clean_management(
        &self,
        binding: &RuntimeBinding,
        before: &RuntimeState,
        request: &crate::agent_sdk::ManagementRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, LocalReplayExecutorError> {
        if !matches!(
            request,
            crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::InspectManagementHistory
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        let runtime = self.clean_runtime_package(binding)?;
        let descriptor = Self::current_clean_descriptor(
            self.clean_genesis_descriptor
                .as_ref()
                .ok_or(LocalReplayExecutorError::InvalidState)?,
            binding,
            &runtime,
        )?;
        let observed_slot = self.current_logical_slot()?;
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: crate::agent_sdk::RuntimeState {
                control: before.control.clone(),
                linear: before.linear.clone(),
                merge: before.merge.clone(),
                local: before.local.clone(),
            },
            request: Box::new(request.clone()),
            authority: None,
            observed_slot,
        };
        #[cfg(all(test, feature = "pvm"))]
        let returned: crate::agent_sdk::RuntimeTransition =
            if self.trust.use_native_clean_runtime_for_test() {
                super::wire::apply_standard_runtime_work(work)
                    .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
            } else {
                let encoded = work
                    .encode()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
            };
        #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
        let returned: crate::agent_sdk::RuntimeTransition = {
            let encoded = work
                .encode()
                .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
            self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
        };
        if returned.state.control != before.control
            || returned.state.linear != before.linear
            || returned.state.merge != before.merge
            || returned.state.local != before.local
            || !super::driver::sdk_management_reply_matches(&descriptor, request, &returned.outcome)
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(returned.outcome)
    }

    pub(crate) fn clean_installed_actor_lanes(
        &self,
        binding: &RuntimeBinding,
        before: &RuntimeState,
    ) -> Result<super::LaneSet, LocalReplayExecutorError> {
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork};

        let runtime = self.clean_runtime_package(binding)?;
        let descriptor = Self::current_clean_descriptor(
            self.clean_genesis_descriptor
                .as_ref()
                .ok_or(LocalReplayExecutorError::InvalidState)?,
            binding,
            &runtime,
        )?;
        let observed_slot = self.current_logical_slot()?;
        let mut after = None;
        let mut lanes = crate::agent_sdk::LaneSet::NONE;
        let mut seen = 0_u32;
        loop {
            let request = ManagementRequest::InspectActors {
                after,
                limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
            };
            let work = RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: crate::agent_sdk::RuntimeState {
                    control: before.control.clone(),
                    linear: before.linear.clone(),
                    merge: before.merge.clone(),
                    local: before.local.clone(),
                },
                request: Box::new(request.clone()),
                authority: None,
                observed_slot,
            };
            #[cfg(all(test, feature = "pvm"))]
            let returned: crate::agent_sdk::RuntimeTransition =
                if self.trust.use_native_clean_runtime_for_test() {
                    super::wire::apply_standard_runtime_work(work)
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                } else {
                    let encoded = work
                        .encode()
                        .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                    self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
                };
            #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
            let returned: crate::agent_sdk::RuntimeTransition = {
                let encoded = work
                    .encode()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                self.execute_agent_wire(runtime.program_bytes(), self.management_gas, &encoded)?
            };
            if returned.state.control != before.control
                || returned.state.linear != before.linear
                || returned.state.merge != before.merge
                || returned.state.local != before.local
                || !super::driver::sdk_management_reply_matches(
                    &descriptor,
                    &request,
                    &returned.outcome,
                )
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = returned.outcome
            else {
                return Err(LocalReplayExecutorError::InvalidState);
            };
            page.validate()
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            if page
                .entries
                .first()
                .is_some_and(|record| after.is_some_and(|cursor| record.entry.actor <= cursor))
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            seen = seen
                .checked_add(
                    u32::try_from(page.entries.len())
                        .map_err(|_| LocalReplayExecutorError::InvalidState)?,
                )
                .ok_or(LocalReplayExecutorError::InvalidState)?;
            if seen > descriptor.capabilities.max_actors
                || page.entries.iter().any(|record| {
                    record
                        .entry
                        .validate_for_profile(descriptor.identity.profile)
                        .is_err()
                        || record.entry.lanes.bits() & !descriptor.capabilities.lanes.bits() != 0
                })
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            for record in &page.entries {
                lanes =
                    crate::agent_sdk::LaneSet::from_bits(lanes.bits() | record.entry.lanes.bits())
                        .ok_or(LocalReplayExecutorError::InvalidState)?;
            }
            let Some(next) = page.next else {
                break;
            };
            if page.entries.is_empty() || after.is_some_and(|cursor| next <= cursor) {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            after = Some(next);
        }
        super::LaneSet::from_bits(lanes.bits()).ok_or(LocalReplayExecutorError::InvalidState)
    }

    fn execute_clean_invocation_transition(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        transition_proof_access: ReplayTransitionProofAccess,
        runtime_pvm: &[u8],
        runtime_state_limit: usize,
        allow_native_standard_for_test: bool,
    ) -> Result<ReplayTransition, LocalReplayExecutorError> {
        let work = match &input.operation {
            ReplayOperation::CleanInvoke { work, .. }
            | ReplayOperation::CleanResume { work, .. } => {
                crate::agent_sdk::InvocationRetirement::from_work(work)
            }
            ReplayOperation::CleanAcknowledge { work, .. } => work.clone(),
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        };
        let sdk_work = super::replay::canonical_clean_runtime_work(input, before)
            .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        let encoded = sdk_work
            .encode()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let attested = matches!(
            &sdk_work,
            crate::agent_sdk::RuntimeWork::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
                ..
            } | crate::agent_sdk::RuntimeWork::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
                ..
            }
        );
        let mut pending_transition_proof = None;
        // This function is reached only after ReplayExecutor consumed the
        // authentication capability. Reuse is computational only: every
        // transition, resource, outcome and publication check below still runs.
        let preflight = TerminalPreflight::consume(
            self.terminal_preflight
                .get_mut()
                .map_err(|_| LocalReplayExecutorError::InvalidState)?,
            runtime_pvm,
            &encoded,
            self.management_gas.saturating_add(work.gas),
        );
        let returned: crate::agent_sdk::RuntimeTransition = if attested {
            let provider = self
                .attested_transition_provider
                .as_mut()
                .ok_or(LocalReplayExecutorError::InvalidState)?;
            let preparation = match transition_proof_access {
                ReplayTransitionProofAccess::PublishedOnly => {
                    AttestedReplayTransitionPreparation::from_published(
                        provider.load_published_transition(input, before, position, &sdk_work)?,
                    )
                }
                ReplayTransitionProofAccess::PrepareAllowed => {
                    provider.prepare_verified_transition(input, before, position, &sdk_work)?
                }
            };
            if preparation.staged.is_some()
                && (transition_proof_access == ReplayTransitionProofAccess::PublishedOnly
                    || !self.allow_attested_preparation)
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let AttestedReplayTransitionPreparation {
                canonical_work,
                canonical_transition,
                proof_record: record,
                publication,
                staged,
            } = preparation;
            if canonical_work != encoded
                || !record.validate_shape()
                || record.statement.work
                    != crate::agent_sdk::proof::TransitionProofStatement::work_commitment(
                        &canonical_work,
                    )
                || record.statement.transition
                    != crate::agent_sdk::proof::TransitionProofStatement::transition_commitment(
                        &canonical_transition,
                    )
                || super::transition_proof_host::TransitionPublicationFact::reconstruct(&record)
                    .ok()
                    != Some(publication)
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let transition = crate::agent_sdk::RuntimeTransition::decode(&canonical_transition)
                .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?;
            if transition
                .encode()
                .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                != canonical_transition
            {
                return Err(LocalReplayExecutorError::RuntimeOutput);
            }
            pending_transition_proof = Some(PendingReplayTransitionProof {
                input: input.id(),
                before: before.clone(),
                position,
                runtime_transition: transition.clone(),
                key: record.statement.key(),
                before_roots: record.statement.before,
                after_roots: record.statement.after,
                publication: publication.publication(),
                staged,
            });
            transition
        } else if let Some(transition) = preflight {
            tracing::debug!("consumed exact single-use terminal preflight transition");
            transition
        } else {
            #[cfg(all(test, feature = "pvm"))]
            {
                if allow_native_standard_for_test && self.trust.use_native_clean_runtime_for_test()
                {
                    super::wire::apply_standard_runtime_work(sdk_work)
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                } else {
                    self.execute_agent_wire(
                        runtime_pvm,
                        self.management_gas.saturating_add(work.gas),
                        &encoded,
                    )?
                }
            }
            #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
            {
                let _ = allow_native_standard_for_test;
                self.execute_agent_wire(
                    runtime_pvm,
                    self.management_gas.saturating_add(work.gas),
                    &encoded,
                )?
            }
        };
        if !super::replay::clean_invocation_outcome_matches(input, &returned.outcome)
            || matches!(
                returned.outcome,
                crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_))
            ) && (returned.state.control != before.control
                || returned.state.linear != before.linear
                || returned.state.merge != before.merge
                || returned.state.local != before.local)
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        let state = RuntimeState {
            control: returned.state.control.clone(),
            linear: returned.state.linear.clone(),
            merge: returned.state.merge.clone(),
            local: returned.state.local.clone(),
        };
        if state
            .encoded_len()
            .is_none_or(|bytes| bytes > runtime_state_limit)
        {
            return Err(LocalReplayExecutorError::RuntimeStateTooLarge);
        }
        let disposition = match &returned.outcome {
            crate::agent_sdk::RuntimeOutcome::Completed(Ok(reply)) => match reply.status {
                crate::agent_sdk::InvocationStatus::Done => ReplayDisposition::Applied,
                crate::agent_sdk::InvocationStatus::Forbidden => ReplayDisposition::Forbidden,
                crate::agent_sdk::InvocationStatus::Panicked => ReplayDisposition::Panicked,
                crate::agent_sdk::InvocationStatus::OutOfGas => ReplayDisposition::OutOfGas,
            },
            crate::agent_sdk::RuntimeOutcome::Completed(Err(_)) => ReplayDisposition::Rejected,
            crate::agent_sdk::RuntimeOutcome::Yielded(_) => ReplayDisposition::Applied,
            crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(_)) => ReplayDisposition::Applied,
            crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_)) => ReplayDisposition::Rejected,
            _ => unreachable!("validated above"),
        };
        let attested_transition = match &input.operation {
            ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
                ..
            }
            | ReplayOperation::CleanResume {
                context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
                ..
            } => Some(
                crate::agent_sdk::proof::TransitionProofStatement::transition_commitment(
                    &returned
                        .encode()
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?,
                ),
            ),
            _ => None,
        };
        if attested_transition.is_some() != pending_transition_proof.is_some() {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        self.pending_transition_proof = pending_transition_proof;
        self.record_clean_invocation_result_at(position, input.id(), returned.outcome);
        Ok(ReplayTransition {
            state,
            disposition,
            result: None,
            next_runtime: input.runtime.clone(),
            products: ReplayProducts::default(),
            attested_transition,
        })
    }

    pub(super) fn validate_clean_management_artifacts(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
    ) -> Result<(), LocalReplayExecutorError> {
        use super::driver::SdkManagementArtifacts;
        use crate::agent_sdk::ManagementRequest;

        match request {
            ManagementRequest::Install(install) => {
                let package_ref = Self::clean_blob(&install.package);
                let bytes = self.load(&package_ref)?;
                let package = super::package_admission::admit_actor_package(&bytes)
                    .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
                super::driver::validate_sdk_management_artifacts(
                    descriptor,
                    request,
                    SdkManagementArtifacts::Actor(&package),
                )
                .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
                for (reference, expected) in [
                    (&install.agent_schema, package.state_lane_schema_bytes()),
                    (&install.method_policy, package.method_policy_bytes()),
                ] {
                    let stored = self.load(&Self::clean_blob(reference))?;
                    if stored.as_slice() != expected {
                        return Err(LocalReplayExecutorError::InvalidArtifact(Self::clean_blob(
                            reference,
                        )));
                    }
                }
                if let Some(data) = &install.installation_data {
                    let stored = self.load(&Self::clean_blob(&data.reference))?;
                    if stored != data.bytes {
                        return Err(LocalReplayExecutorError::InvalidArtifact(Self::clean_blob(
                            &data.reference,
                        )));
                    }
                }
            }
            ManagementRequest::UpgradeActor(upgrade) => {
                let package_ref = Self::clean_blob(&upgrade.package);
                let bytes = self.load(&package_ref)?;
                let package = super::package_admission::admit_actor_package(&bytes)
                    .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
                super::driver::validate_sdk_management_artifacts(
                    descriptor,
                    request,
                    SdkManagementArtifacts::Actor(&package),
                )
                .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
                for (reference, expected) in [
                    (&upgrade.agent_schema, package.state_lane_schema_bytes()),
                    (&upgrade.method_policy, package.method_policy_bytes()),
                ] {
                    let stored = self.load(&Self::clean_blob(reference))?;
                    if stored.as_slice() != expected {
                        return Err(LocalReplayExecutorError::InvalidArtifact(Self::clean_blob(
                            reference,
                        )));
                    }
                }
            }
            ManagementRequest::UpgradeRuntime(upgrade) => {
                let package_ref = Self::clean_blob(&upgrade.package);
                let bytes = self.load(&package_ref)?;
                let package = super::package_admission::admit_runtime_package(&bytes)
                    .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
                super::driver::validate_sdk_management_artifacts(
                    descriptor,
                    request,
                    SdkManagementArtifacts::Runtime(&package),
                )
                .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref))?;
            }
            ManagementRequest::Create(_)
            | ManagementRequest::Suspend { .. }
            | ManagementRequest::Resume { .. }
            | ManagementRequest::RemoveLeaf { .. }
            | ManagementRequest::ChangeReplicas { .. } => {
                super::driver::validate_sdk_management_artifacts(
                    descriptor,
                    request,
                    SdkManagementArtifacts::None,
                )
                .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
            }
            ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory => {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
            ManagementRequest::PrivateControl { .. } => {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        Ok(())
    }
    fn new(
        resolver: R,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Self {
        Self {
            resolver,
            #[cfg(feature = "experimental-state-blocks")]
            external: None,
            #[cfg(feature = "experimental-state-blocks")]
            external_execution: None,
            trust,
            merge,
            profile: AgentProfile::Local,
            shared_committees: BTreeMap::new(),
            management_gas: DEFAULT_MANAGEMENT_GAS,
            last_management_result: None,
            pending_clean_invocation_results: BTreeMap::new(),
            recent_clean_ordered_results: BTreeMap::new(),
            recent_clean_ordered_order: VecDeque::new(),
            positioned_clean_results: BTreeMap::new(),
            positioned_clean_order: VecDeque::new(),
            recent_clean_management_results: BTreeMap::new(),
            recent_clean_management_order: VecDeque::new(),
            clean_genesis_descriptor: None,
            shared_joiner: false,
            authenticated_execution: None,
            attested_transition_provider: None,
            allow_attested_preparation: false,
            pending_transition_proof: None,
            staged_transition_proofs: Vec::new(),
            terminal_preflight: std::sync::Mutex::new(None),
            runtime_preparation: RuntimePreparationCache::default(),
        }
    }

    pub(crate) fn new_shared(
        resolver: R,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        committees: Vec<AgentReplicaCommittee>,
    ) -> Self {
        let shared_committees = committees
            .into_iter()
            .map(|committee| (committee.id(), committee))
            .collect();
        Self {
            resolver,
            #[cfg(feature = "experimental-state-blocks")]
            external: None,
            #[cfg(feature = "experimental-state-blocks")]
            external_execution: None,
            trust,
            merge,
            profile: AgentProfile::Shared,
            shared_committees,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            last_management_result: None,
            pending_clean_invocation_results: BTreeMap::new(),
            recent_clean_ordered_results: BTreeMap::new(),
            recent_clean_ordered_order: VecDeque::new(),
            positioned_clean_results: BTreeMap::new(),
            positioned_clean_order: VecDeque::new(),
            recent_clean_management_results: BTreeMap::new(),
            recent_clean_management_order: VecDeque::new(),
            clean_genesis_descriptor: None,
            shared_joiner: false,
            authenticated_execution: None,
            attested_transition_provider: None,
            allow_attested_preparation: false,
            pending_transition_proof: None,
            staged_transition_proofs: Vec::new(),
            terminal_preflight: std::sync::Mutex::new(None),
            runtime_preparation: RuntimePreparationCache::default(),
        }
    }

    /// Install the sole verified Attested execution boundary.
    ///
    /// Replacement invalidates every unconsumed capability. Callers must do
    /// this before materialization if the durable suffix contains Attested
    /// work; otherwise replay fails closed rather than invoking the ordinary
    /// runtime path.
    pub(crate) fn replace_attested_transition_provider(
        &mut self,
        provider: Box<dyn AttestedReplayTransitionProvider>,
    ) {
        self.attested_transition_provider = Some(provider);
        self.allow_attested_preparation = false;
        self.pending_transition_proof = None;
        self.staged_transition_proofs.clear();
        self.authenticated_execution = None;
    }

    /// Begin one replay-sealed publication attempt.
    ///
    /// A prepared host row is durable independently, but only tuples drained
    /// from this exact attempt may be staged under its eventual head CAS.
    pub(crate) fn begin_transition_proof_batch(&mut self) {
        self.allow_attested_preparation = true;
        self.pending_transition_proof = None;
        self.staged_transition_proofs.clear();
    }

    /// Drain freshly staged thin capabilities in canonical replay execution
    /// order. Already-published tuples are intentionally absent: their exact
    /// binding remains in the sealed requirements and storage validates
    /// Preserve. Draining also closes preparation authority for this attempt.
    pub(crate) fn take_staged_transition_proofs(&mut self) -> Vec<StagedTransitionProof> {
        self.allow_attested_preparation = false;
        self.pending_transition_proof = None;
        core::mem::take(&mut self.staged_transition_proofs)
    }

    pub(crate) fn replace_resolver(&mut self, resolver: R) {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &mut self.external {
            external.replace_resolver(resolver.clone());
        }
        self.resolver = resolver;
        self.authenticated_execution = None;
        self.allow_attested_preparation = false;
        self.pending_transition_proof = None;
        self.staged_transition_proofs.clear();
    }

    pub(crate) fn replace_shared_committees(&mut self, committees: Vec<AgentReplicaCommittee>) {
        self.shared_committees = committees
            .into_iter()
            .map(|committee| (committee.id(), committee))
            .collect();
        self.authenticated_execution = None;
        self.allow_attested_preparation = false;
        self.pending_transition_proof = None;
        self.staged_transition_proofs.clear();
    }

    pub(crate) fn current_logical_slot(&self) -> Result<u64, LocalReplayExecutorError> {
        self.trust
            .current_logical_slot()
            .ok_or(LocalReplayExecutorError::TrustUnavailable)
    }

    /// Verify clean invocation authorization and availability against the exact
    /// currently materialized Standard runtime without minting replay's
    /// one-shot execution capability. Shared consensus uses this before a
    /// command can enter Raft; replay repeats the same checks at application.
    pub(crate) fn verify_clean_invocation_input(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
        state: &RuntimeState,
        binding: &RuntimeBinding,
    ) -> Result<(), LocalReplayExecutorError> {
        if self.clean_genesis_descriptor.is_some() {
            let descriptor = self.trusted_current_clean_descriptor(binding)?;
            Self::validate_clean_invocation_envelope(
                &descriptor,
                work,
                authorization,
                observed_slot,
            )?;
            let _ = state;
            return Ok(());
        }
        let decoded = decode_standard_runtime_state(state)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = decoded
            .config
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let _ = self.validate_local_config(config, binding)?;
        let runtime = StandardAgentRuntime::restore(decoded)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        runtime
            .verify_clean_invocation_authorization(work, authorization, observed_slot)
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        super::wire::admit_clean_public_preflight(&runtime, work, authorization)
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        match runtime.resolve_clean_invocation(work) {
            Err(
                crate::agent_sdk::InvocationError::InvalidAvailability
                | crate::agent_sdk::InvocationError::InvalidInput,
            ) => Err(LocalReplayExecutorError::InvalidRequest),
            _ => Ok(()),
        }
    }

    /// Verify a complete clean invocation-lifecycle journal input against the
    /// currently materialized state before it can enter Raft or a physical
    /// Local/Merge lane. Resume derives its executable work from the retained
    /// yielded record; acknowledgement must name an actually retained exact
    /// result at first admission.
    pub(crate) fn verify_clean_operation_input(
        &self,
        operation: &ReplayOperation,
        state: &RuntimeState,
        binding: &RuntimeBinding,
    ) -> Result<(), LocalReplayExecutorError> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &self.external {
            // Shared admission must not commit a command the selected
            // physical executor will reject solely for its static gas bound.
            external.gas(operation)?;
            // The sealed external publication path is currently qualified
            // for direct Invoke/ACK only. Generic image/SDK Resume and
            // Attested execution retain their existing independent paths.
            if operation.persisted_lane() != PersistedLane::Linear
                || !matches!(
                    operation,
                    ReplayOperation::CleanInvoke {
                        context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                        ..
                    } | ReplayOperation::CleanAcknowledge {
                        context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                        ..
                    }
                )
            {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        match operation {
            ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } => self.verify_clean_invocation_input(
                work,
                authorization,
                *observed_slot,
                state,
                binding,
            ),
            ReplayOperation::CleanResume {
                work,
                authorization,
                yielded,
                observed_slot,
                ..
            } => {
                self.verify_clean_invocation_input(
                    work,
                    authorization,
                    *observed_slot,
                    state,
                    binding,
                )?;
                // A clean runtime owns the interpretation of its opaque
                // component state. Replay supplies only the exact original
                // work/authorization and the canonical yielded selector; the
                // physically admitted guest must authenticate that selector
                // against its durable state. Host-side Standard decoding here
                // would make every non-Standard runtime impossible to resume.
                if self.clean_genesis_descriptor.is_some() {
                    return Ok(());
                }
                let decoded = decode_standard_runtime_state(state)
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                let runtime = StandardAgentRuntime::restore(decoded)
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                match runtime
                    .recover_clean_yield(work, authorization, *observed_slot)
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?
                {
                    Some(current) if current == *yielded => Ok(()),
                    _ => Err(LocalReplayExecutorError::InvalidRequest),
                }
            }
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => {
                let slot = match authorization {
                    crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(_) => 0,
                    crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) => {
                        preflight.observed_slot
                    }
                };
                // As with Resume, only the admitted runtime may decide
                // whether its opaque state currently retains this exact
                // result (or acknowledgement fact).
                if self.clean_genesis_descriptor.is_some() {
                    let descriptor = self.trusted_current_clean_descriptor(binding)?;
                    Self::validate_clean_retirement_envelope(
                        &descriptor,
                        work,
                        authorization,
                        slot,
                    )?;
                    return Ok(());
                }
                let decoded = decode_standard_runtime_state(state)
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                let config = decoded
                    .config
                    .as_ref()
                    .ok_or(LocalReplayExecutorError::InvalidState)?;
                let _ = self.validate_local_config(config, binding)?;
                let mut runtime = StandardAgentRuntime::restore(decoded)
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                match runtime.acknowledge_clean_retirement_with_status(work, authorization) {
                    Ok(_) | Err(crate::agent_sdk::InvocationError::NotFound) => Ok(()),
                    Err(_) => Err(LocalReplayExecutorError::InvalidRequest),
                }
            }
            _ => Err(LocalReplayExecutorError::InvalidRequest),
        }
    }

    /// Deterministically execute a direct clean invocation against a borrowed
    /// materialized state without publishing it. The production authority
    /// query path uses this to refuse a Yielded transition before it can
    /// consume durable lifecycle capacity.
    pub(crate) fn clean_invocation_is_terminal(
        &self,
        operation: &ReplayOperation,
        state: &RuntimeState,
        binding: &RuntimeBinding,
    ) -> Result<bool, LocalReplayExecutorError> {
        Ok(self
            .clean_invocation_terminal_preflight(operation, state, binding, true)?
            .is_some())
    }

    pub(crate) fn clean_invocation_terminal_outcome(
        &self,
        operation: &ReplayOperation,
        state: &RuntimeState,
        binding: &RuntimeBinding,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, LocalReplayExecutorError> {
        self.clean_invocation_terminal_preflight(operation, state, binding, false)
    }

    fn clean_invocation_terminal_preflight(
        &self,
        operation: &ReplayOperation,
        state: &RuntimeState,
        binding: &RuntimeBinding,
        retain: bool,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, LocalReplayExecutorError> {
        if retain {
            self.terminal_preflight
                .lock()
                .map_err(|_| LocalReplayExecutorError::InvalidState)?
                .take();
        }
        let ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
            observed_slot,
        } = operation
        else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        let runtime = self.clean_runtime_package(binding)?;
        let runtime_work = crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: crate::agent_sdk::RuntimeState {
                control: state.control.clone(),
                linear: state.linear.clone(),
                merge: state.merge.clone(),
                local: state.local.clone(),
            },
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: *observed_slot,
        };
        let encoded = runtime_work
            .encode()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        #[cfg(all(test, feature = "pvm"))]
        let returned: crate::agent_sdk::RuntimeTransition =
            if self.trust.use_native_clean_runtime_for_test() {
                super::wire::apply_standard_runtime_work(runtime_work)
                    .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
            } else {
                self.execute_agent_wire(
                    runtime.program_bytes(),
                    self.management_gas.saturating_add(work.gas),
                    &encoded,
                )?
            };
        #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
        let returned: crate::agent_sdk::RuntimeTransition = {
            self.execute_agent_wire(
                runtime.program_bytes(),
                self.management_gas.saturating_add(work.gas),
                &encoded,
            )?
        };
        if retain
            && matches!(
                returned.outcome,
                crate::agent_sdk::RuntimeOutcome::Completed(_)
            )
        {
            *self
                .terminal_preflight
                .lock()
                .map_err(|_| LocalReplayExecutorError::InvalidState)? = Some(TerminalPreflight {
                runtime_pvm: runtime.program_bytes().to_vec(),
                input: encoded,
                gas: self.management_gas.saturating_add(work.gas),
                transition: returned.clone(),
            });
        }
        Ok(match returned.outcome {
            outcome @ crate::agent_sdk::RuntimeOutcome::Completed(_) => Some(outcome),
            _ => None,
        })
    }

    fn validate_clean_invocation_envelope(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<(), LocalReplayExecutorError> {
        if !work.validate() {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Self::validate_clean_retirement_envelope(
            descriptor,
            &crate::agent_sdk::InvocationRetirement::from_work(work),
            authorization,
            observed_slot,
        )
    }

    fn validate_clean_retirement_envelope(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<(), LocalReplayExecutorError> {
        if !work.validate()
            || !authorization.matches_retirement(work)
            || matches!(authorization, crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight)
                if observed_slot < preflight.observed_slot)
            || work.space != descriptor.identity.space
            || work.agent != descriptor.identity.agent
            || work.runtime_deployment != descriptor.identity.runtime_deployment
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        if let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) = authorization
            && (!descriptor.authority.accepts(receipt)
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

    pub(crate) fn sign_shared_merge_event(
        &mut self,
        event: &mut MergeEvent,
    ) -> Result<(), LocalReplayExecutorError> {
        if self.profile != AgentProfile::Shared
            || event.author != self.merge.node()
            || event.committee.is_none()
            || !self.merge.sign_event(event)
            || !self.verify_merge_event(event)?
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Ok(())
    }

    fn clear_management_result(&mut self) {
        self.last_management_result = None;
    }

    fn take_management_result(
        &mut self,
        input: ReplayInputId,
    ) -> Option<Result<LifecycleReply, LifecycleError>> {
        match self.last_management_result.take() {
            Some((committed, result)) if committed == input => Some(result),
            _ => None,
        }
    }

    pub(crate) fn take_clean_invocation_result(
        &mut self,
        input: ReplayInputId,
    ) -> Option<crate::agent_sdk::RuntimeOutcome> {
        self.pending_clean_invocation_results.remove(&input)
    }

    pub(crate) fn clean_management_result(
        &self,
        input: ReplayInputId,
    ) -> Option<crate::agent_sdk::RuntimeOutcome> {
        self.recent_clean_management_results.get(&input).cloned()
    }

    pub(crate) fn clean_ordered_result(
        &self,
        input: ReplayInputId,
    ) -> Option<crate::agent_sdk::RuntimeOutcome> {
        match self.recent_clean_ordered_results.get(&input)? {
            RecentCleanResult::Ordered(entry) => self.clean_ordered_result_at(*entry, input),
            RecentCleanResult::Unpositioned(outcome) => Some(outcome.clone()),
        }
    }

    pub(crate) fn clean_ordered_result_at(
        &self,
        entry: OrderedEntryId,
        input: ReplayInputId,
    ) -> Option<crate::agent_sdk::RuntimeOutcome> {
        self.positioned_clean_results.get(&(entry, input)).cloned()
    }

    fn record_clean_invocation_result_at(
        &mut self,
        position: ReplayPosition,
        input: ReplayInputId,
        result: crate::agent_sdk::RuntimeOutcome,
    ) {
        let ReplayPosition::Ordered { id, .. } = position else {
            self.record_clean_invocation_result(input, result);
            return;
        };
        if self.profile != AgentProfile::Shared {
            self.record_clean_invocation_result(input, result);
            return;
        }
        let key = (id, input);
        if !self.positioned_clean_results.contains_key(&key) {
            if self.positioned_clean_results.len() == MAX_PENDING_CLEAN_INVOCATION_RESULTS
                && let Some(evicted) = self.positioned_clean_order.pop_front()
            {
                self.positioned_clean_results.remove(&evicted);
                if matches!(self.recent_clean_ordered_results.get(&evicted.1),
                    Some(RecentCleanResult::Ordered(entry)) if *entry == evicted.0)
                {
                    self.recent_clean_ordered_results.remove(&evicted.1);
                    self.recent_clean_ordered_order
                        .retain(|input| *input != evicted.1);
                }
            }
            self.positioned_clean_order.push_back(key);
        }
        self.record_clean_result_handoff(input, result.clone(), RecentCleanResult::Ordered(id));
        self.positioned_clean_results.insert(key, result);
    }

    fn record_clean_invocation_result(
        &mut self,
        input: ReplayInputId,
        result: crate::agent_sdk::RuntimeOutcome,
    ) {
        self.record_clean_result_handoff(
            input,
            result.clone(),
            RecentCleanResult::Unpositioned(result),
        );
    }

    fn record_clean_result_handoff(
        &mut self,
        input: ReplayInputId,
        result: crate::agent_sdk::RuntimeOutcome,
        recent: RecentCleanResult,
    ) {
        if !self.pending_clean_invocation_results.contains_key(&input)
            && self.pending_clean_invocation_results.len() == MAX_PENDING_CLEAN_INVOCATION_RESULTS
        {
            // This is only the synchronous response handoff. Deterministic
            // eviction cannot affect journal state or management retry proof.
            if let Some(evicted) = self.pending_clean_invocation_results.keys().next().copied() {
                self.pending_clean_invocation_results.remove(&evicted);
            }
        }
        self.pending_clean_invocation_results
            .insert(input, result);
        if let Some(cached) = self.recent_clean_ordered_results.get_mut(&input) {
            *cached = recent;
            return;
        }
        if self.recent_clean_ordered_results.len() == MAX_PENDING_CLEAN_INVOCATION_RESULTS
            && let Some(evicted) = self.recent_clean_ordered_order.pop_front()
        {
            self.recent_clean_ordered_results.remove(&evicted);
        }
        self.recent_clean_ordered_order.push_back(input);
        self.recent_clean_ordered_results.insert(input, recent);
    }

    fn record_clean_management_result(
        &mut self,
        input: ReplayInputId,
        result: crate::agent_sdk::RuntimeOutcome,
    ) {
        self.record_clean_invocation_result(input, result.clone());
        if let Some(cached) = self.recent_clean_management_results.get_mut(&input) {
            *cached = result;
            return;
        }
        if self.recent_clean_management_results.len() == MAX_PENDING_CLEAN_INVOCATION_RESULTS
            && let Some(evicted) = self.recent_clean_management_order.pop_front()
        {
            self.recent_clean_management_results.remove(&evicted);
        }
        self.recent_clean_management_order.push_back(input);
        self.recent_clean_management_results.insert(input, result);
    }

    fn config_for<'a>(
        &self,
        input: &'a ReplayInput,
        state: &'a StandardRuntimeState,
    ) -> Result<&'a AgentConfig, LocalReplayExecutorError> {
        if let Some(config) = state.config.as_ref() {
            return Ok(config);
        }
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &input.operation
        else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        Ok(config)
    }

    fn validate_local_config_shape(
        config: &AgentConfig,
        binding: &RuntimeBinding,
        node: NodeId,
    ) -> Result<(), LocalReplayExecutorError> {
        Self::validate_config_shape(config, binding, node, AgentProfile::Local)
    }

    fn validate_config_shape(
        config: &AgentConfig,
        binding: &RuntimeBinding,
        node: NodeId,
        profile: AgentProfile,
    ) -> Result<(), LocalReplayExecutorError> {
        config
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        if config.identity.profile != profile
            || (profile == AgentProfile::Local && config.replicas.len() != 1)
        {
            return Err(LocalReplayExecutorError::InvalidProfile);
        }
        if !config.replicas.iter().any(|replica| replica.node == node) {
            return Err(LocalReplayExecutorError::WrongReplica);
        }
        if binding.space != config.identity.space
            || binding.agent != config.identity.agent
            || binding.deployment != config.identity.runtime_deployment
            || binding.program != config.identity.runtime_program
            || binding.producer != config.identity.runtime_producer
            || binding.package != config.runtime_package
            || binding.runtime_abi != super::RUNTIME_ABI_ID
            || binding.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(())
    }

    fn validate_local_config(
        &self,
        config: &AgentConfig,
        binding: &RuntimeBinding,
    ) -> Result<Package, LocalReplayExecutorError> {
        Self::validate_config_shape(config, binding, self.merge.node(), self.profile)?;
        let anchored = self
            .trust
            .authority_for_space(config.identity.space)
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        if anchored != config.authority {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        self.runtime_package(config, binding)
    }

    fn load(&self, reference: &BlobRef) -> Result<Vec<u8>, LocalReplayExecutorError> {
        self.resolver
            .load_catalog(reference)?
            .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))
    }

    fn trusted_package(
        &self,
        config: &AgentConfig,
        reference: &BlobRef,
    ) -> Result<Package, LocalReplayExecutorError> {
        let bytes = self.load(reference)?;
        self.trusted_package_bytes(config, reference, &bytes)
    }

    fn trusted_package_bytes(
        &self,
        config: &AgentConfig,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<Package, LocalReplayExecutorError> {
        if !reference.matches(bytes) {
            return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
        }
        let package = Package::decode(bytes)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(reference.clone()))?;
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        if !self.trust.verify_package(config, &package) {
            return Err(LocalReplayExecutorError::Package(
                PackageError::InvalidSignature,
            ));
        }
        Ok(package)
    }

    fn validate_actor_catalog(
        &self,
        config: &AgentConfig,
        supplied: &BTreeMap<(Hash, u64), &[u8]>,
        admission: ActorCatalogAdmission<'_>,
    ) -> Result<(), LocalReplayExecutorError> {
        let lookup = |reference: &BlobRef| {
            supplied
                .get(&(reference.hash, reference.len))
                .copied()
                .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))
        };
        let package_bytes = lookup(admission.package)?;
        let schema = lookup(admission.schema)?;
        let policies = lookup(admission.policies)?;
        let package = self.trusted_package_bytes(config, admission.package, package_bytes)?;
        let PackageKind::Actor {
            contract: package_contract,
            requirements: package_requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        let parsed_schema = crate::agent_sdk::schema::decode(schema)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(admission.schema.clone()))?;
        let state_layout = Hash(
            parsed_schema
                .state_layout_hash()
                .map_err(|_| LocalReplayExecutorError::InvalidArtifact(admission.schema.clone()))?
                .0,
        );
        if package.deployment_id() != admission.deployment
            || package.manifest.program != admission.program
            || package.deployment_signature.producer != admission.producer
            || BlobRef::of_bytes(&package.encode()) != *admission.package
            || BlobRef::of_bytes(&package.agent_schema) != *admission.schema
            || BlobRef::of_bytes(&package.role_policies) != *admission.policies
            || package.agent_schema != schema
            || package.role_policies != policies
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != admission.constructor_abi
            || package_contract != admission.contract
            || package_requirements != admission.requirements
            || !config.runtime_contract.supports(admission.contract)
            || !config.capabilities.satisfies(admission.requirements)
            || state_layout != admission.state_layout
            || crate::service::PackageRolePolicies::decode(policies).is_err()
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                admission.package.clone(),
            ));
        }
        Ok(())
    }

    /// Authenticate the complete catalog closure named by one live
    /// lifecycle request before any content is staged. This is deliberately
    /// stricter than historical replay, whose closure has already crossed an
    /// admission boundary and must remain deterministic without live trust.
    fn validate_lifecycle_catalog(
        &self,
        config: &AgentConfig,
        state: &RuntimeState,
        request: &LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<(), LocalReplayExecutorError> {
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        self.validate_lifecycle_operation_catalog(config, request, catalog)?;
        self.validate_upgrade_installation_shape(state, request, Some(catalog))
    }

    fn validate_upgrade_installation_shape(
        &self,
        state: &RuntimeState,
        request: &LifecycleRequest,
        supplied_catalog: Option<&[RuntimeBlob]>,
    ) -> Result<(), LocalReplayExecutorError> {
        let request = match request {
            LifecycleRequest::Authorized { request, .. } => request.as_ref(),
            request => request,
        };
        let LifecycleRequest::UpgradeActor(upgrade) = request else {
            return Ok(());
        };
        let decoded = decode_standard_runtime_state(state)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let Some(actor) = decoded.actors.iter().find(|actor| {
            actor.record.entry.actor == upgrade.actor
                && actor.record.entry.deployment == upgrade.from_deployment
        }) else {
            // NotFound/StaleDeployment remain exact guest lifecycle outcomes.
            return Ok(());
        };
        let package = match supplied_catalog {
            Some(catalog) => {
                let blob = catalog
                    .iter()
                    .find(|blob| blob.reference == upgrade.package)
                    .ok_or_else(|| {
                        LocalReplayExecutorError::ArtifactUnavailable(upgrade.package.clone())
                    })?;
                Package::decode(&blob.bytes)
            }
            None => Package::decode(&self.load(&upgrade.package)?),
        }
        .map_err(|_| LocalReplayExecutorError::InvalidArtifact(upgrade.package.clone()))?;
        if !package
            .accepts_installation_data_reference(actor.record.installation_data.as_ref())
            .map_err(LocalReplayExecutorError::Package)?
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != actor.record.constructor_abi
        {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_replayed_upgrade_target(
        &self,
        state: &RuntimeState,
        request: &LifecycleRequest,
        expected_result: &Result<LifecycleReply, LifecycleError>,
    ) -> Result<(), LocalReplayExecutorError> {
        if expected_result.is_ok() {
            self.validate_upgrade_installation_shape(state, request, None)
        } else {
            // Live admission never staged a target for an exact rejection,
            // so replay must not invent a dependency on unavailable bytes.
            Ok(())
        }
    }

    fn validate_lifecycle_operation_catalog(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<(), LocalReplayExecutorError> {
        let expected = match request {
            LifecycleRequest::Install(install) => {
                let mut expected = vec![
                    &install.package,
                    &install.agent_schema,
                    &install.role_policies,
                ];
                if let Some(data) = &install.installation_data {
                    expected.push(&data.reference);
                }
                expected
            }
            LifecycleRequest::UpgradeActor(upgrade) => vec![
                &upgrade.package,
                &upgrade.agent_schema,
                &upgrade.role_policies,
            ],
            LifecycleRequest::UpgradeRuntime { package, .. } => vec![package],
            LifecycleRequest::Create(_)
            | LifecycleRequest::Inspect { .. }
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
            | LifecycleRequest::Authorized { .. } => Vec::new(),
        };
        let mut expected_by_id = BTreeMap::new();
        for reference in &expected {
            if expected_by_id
                .insert((reference.hash, reference.len), *reference)
                .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        let mut supplied = BTreeMap::new();
        let mut supplied_bytes = 0u64;
        for blob in catalog {
            if blob.bytes.len() > super::journal::MAX_ARTIFACT_CLOSURE_BYTES
                || !blob.reference.matches(&blob.bytes)
                || supplied
                    .insert(
                        (blob.reference.hash, blob.reference.len),
                        blob.bytes.as_slice(),
                    )
                    .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidArtifact(
                    blob.reference.clone(),
                ));
            }
            supplied_bytes = supplied_bytes
                .checked_add(blob.reference.len)
                .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        }
        if supplied_bytes > super::journal::MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES
            || supplied.len() != expected_by_id.len()
            || supplied.keys().any(|key| !expected_by_id.contains_key(key))
        {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        for reference in expected_by_id.values() {
            if !supplied.contains_key(&(reference.hash, reference.len)) {
                return Err(LocalReplayExecutorError::ArtifactUnavailable(
                    (*reference).clone(),
                ));
            }
        }

        match request {
            LifecycleRequest::Install(install) => {
                self.validate_actor_catalog(
                    config,
                    &supplied,
                    ActorCatalogAdmission {
                        package: &install.package,
                        schema: &install.agent_schema,
                        policies: &install.role_policies,
                        constructor_abi: install.constructor_abi,
                        deployment: install.entry.deployment,
                        program: install.entry.program,
                        producer: install.producer,
                        state_layout: install.state_layout,
                        contract: install.contract,
                        requirements: install.requirements,
                    },
                )?;
                if install.entry.package != install.package
                    || install.entry.agent_schema != install.agent_schema
                    || install.entry.role_policies != install.role_policies
                    || install.entry.constructor_abi != install.constructor_abi
                    || install.entry.installation_data.as_ref()
                        != install
                            .installation_data
                            .as_ref()
                            .map(|data| &data.reference)
                    || install.installation_data.as_ref().is_some_and(|data| {
                        !data.is_valid()
                            || supplied
                                .get(&(data.reference.hash, data.reference.len))
                                .is_none_or(|bytes| *bytes != data.bytes.as_slice())
                    })
                    || install.entry.state_layout != install.state_layout
                    || install.entry.lanes != install.requirements.lanes
                {
                    return Err(LocalReplayExecutorError::InvalidArtifact(
                        install.package.clone(),
                    ));
                }
            }
            LifecycleRequest::UpgradeActor(upgrade) => {
                self.validate_actor_catalog(
                    config,
                    &supplied,
                    ActorCatalogAdmission {
                        package: &upgrade.package,
                        schema: &upgrade.agent_schema,
                        policies: &upgrade.role_policies,
                        constructor_abi: upgrade.constructor_abi,
                        deployment: upgrade.to_deployment,
                        program: upgrade.to_program,
                        producer: upgrade.producer,
                        state_layout: upgrade.state_layout,
                        contract: upgrade.contract,
                        requirements: upgrade.requirements,
                    },
                )?;
            }
            LifecycleRequest::UpgradeRuntime {
                to_deployment,
                to_program,
                producer,
                package,
                contract,
                capabilities,
                ..
            } => {
                let bytes = supplied
                    .get(&(package.hash, package.len))
                    .copied()
                    .ok_or_else(|| {
                        LocalReplayExecutorError::ArtifactUnavailable(package.clone())
                    })?;
                let mut target = config.clone();
                target.identity.runtime_deployment = *to_deployment;
                target.identity.runtime_program = *to_program;
                target.identity.runtime_producer = *producer;
                target.runtime_package = package.clone();
                target.runtime_contract = *contract;
                target.capabilities = *capabilities;
                target
                    .validate()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                let decoded = self.trusted_package_bytes(&target, package, bytes)?;
                let PackageKind::AgentRuntime {
                    contract: package_contract,
                    capabilities: package_capabilities,
                } = decoded.manifest.kind
                else {
                    return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
                };
                if decoded.deployment_id() != *to_deployment
                    || decoded.manifest.program != *to_program
                    || decoded.deployment_signature.producer != *producer
                    || BlobRef::of_bytes(&decoded.encode()) != *package
                    || package_contract != *contract
                    || package_capabilities != *capabilities
                {
                    return Err(LocalReplayExecutorError::InvalidArtifact(package.clone()));
                }
            }
            LifecycleRequest::Create(_)
            | LifecycleRequest::Inspect { .. }
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_) => {}
            LifecycleRequest::Authorized { .. } => {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        Ok(())
    }

    fn runtime_package(
        &self,
        config: &AgentConfig,
        binding: &RuntimeBinding,
    ) -> Result<Package, LocalReplayExecutorError> {
        let package = self.trusted_package(config, &binding.package)?;
        Self::validate_runtime_package_binding(config, binding, &package)?;
        Ok(package)
    }

    fn validate_runtime_package_binding(
        config: &AgentConfig,
        binding: &RuntimeBinding,
        package: &Package,
    ) -> Result<(), LocalReplayExecutorError> {
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        if !contract.is_valid()
            || package.deployment_id() != binding.deployment
            || package.manifest.program != binding.program
            || package.deployment_signature.producer != binding.producer
            || BlobRef::of_bytes(&package.encode()) != binding.package
            || config.runtime_contract != contract
            || config.capabilities != capabilities
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                binding.package.clone(),
            ));
        }
        Ok(())
    }

    fn authenticate_management(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
    ) -> Result<(), LocalReplayExecutorError> {
        let (admission, request) = match request {
            LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_) => return Ok(()),
            LifecycleRequest::Authorized { admission, request } => (admission, request),
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        };
        let inner = request.as_ref();
        let capability = inner
            .required_capability()
            .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        admission
            .receipt
            .verify_guest_signature(&config.authority)
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let claim = &admission.receipt.claim;
        if claim.space != config.identity.space
            || claim.agent != config.identity.agent
            || claim.capability != CapabilityId::named(capability)
            || claim.operation != inner.commitment()
            || matches!(inner, LifecycleRequest::Create(created) if claim.principal != created.identity.owner)
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Ok(())
    }

    fn empty_blob() -> RuntimeBlob {
        RuntimeBlob {
            reference: BlobRef {
                hash: Hash::ZERO,
                len: 0,
            },
            bytes: Vec::new(),
        }
    }

    fn actor_artifacts(
        &self,
        config: &AgentConfig,
        state: &StandardRuntimeState,
        invocation: &ActorInvocation,
    ) -> Result<
        Option<(Vec<u8>, RuntimeBlob, RuntimeBlob, Option<RuntimeBlob>)>,
        LocalReplayExecutorError,
    > {
        let Some(actor) = state
            .actors
            .iter()
            .find(|actor| actor.record.entry.actor == invocation.actor)
        else {
            return Ok(None);
        };
        let record = &actor.record;
        if record.state_generation != invocation.incarnation
            || record.entry.deployment != invocation.deployment
            || record.entry.program != invocation.program
        {
            // The guest must derive the exact durable target error. Empty
            // recovery artifacts are safe because target validation precedes
            // recovery-only admission inside the Standard runtime.
            return Ok(None);
        }
        let package = self.trusted_package(config, &record.package)?;
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        let schema = self.load(&record.agent_schema)?;
        let policies = self.load(&record.role_policies)?;
        let parsed_schema = crate::agent_sdk::schema::decode(&schema)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(record.agent_schema.clone()))?;
        let state_layout = Hash(
            parsed_schema
                .state_layout_hash()
                .map_err(|_| {
                    LocalReplayExecutorError::InvalidArtifact(record.agent_schema.clone())
                })?
                .0,
        );
        if package.deployment_id() != record.entry.deployment
            || package.manifest.program != record.entry.program
            || package.deployment_signature.producer != record.producer
            || BlobRef::of_bytes(&package.encode()) != record.package
            || record.entry.package != record.package
            || record.entry.agent_schema != record.agent_schema
            || record.entry.role_policies != record.role_policies
            || record.entry.constructor_abi != record.constructor_abi
            || record.entry.installation_data != record.installation_data
            || BlobRef::of_bytes(&package.agent_schema) != record.agent_schema
            || BlobRef::of_bytes(&package.role_policies) != record.role_policies
            || package.agent_schema != schema
            || package.role_policies != policies
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != record.constructor_abi
            || record.contract != contract
            || record.requirements != requirements
            || record.entry.lanes != requirements.lanes
            || record.entry.state_layout != record.state_layout
            || !config.runtime_contract.supports(contract)
            || !config.capabilities.satisfies(requirements)
            || state_layout != record.state_layout
            || crate::service::PackageRolePolicies::decode(&policies).is_err()
            || !package
                .accepts_installation_data_reference(record.installation_data.as_ref())
                .map_err(LocalReplayExecutorError::Package)?
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                record.package.clone(),
            ));
        }
        let installation_data = match record.installation_data.as_ref() {
            Some(reference) => {
                let bytes = self.load(reference)?;
                if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES {
                    return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
                }
                Some(RuntimeBlob {
                    reference: reference.clone(),
                    bytes,
                })
            }
            None => None,
        };
        Ok(Some((
            package.pvm,
            RuntimeBlob {
                reference: record.agent_schema.clone(),
                bytes: schema,
            },
            RuntimeBlob {
                reference: record.role_policies.clone(),
                bytes: policies,
            },
            installation_data,
        )))
    }

    fn execute_wire<T: ServiceWire>(
        &self,
        runtime_pvm: &[u8],
        gas: Gas,
        input: &[u8],
    ) -> Result<T, LocalReplayExecutorError> {
        let invocation = self
            .runtime_preparation
            .load(runtime_pvm, input, gas)
            .map_err(|error| match error {
                vos_pvm::refine::RefineError::Backend => LocalReplayExecutorError::RuntimeBackend,
                _ => LocalReplayExecutorError::RuntimeOutput,
            })?
            .try_run()
            .map_err(|_| LocalReplayExecutorError::RuntimeBackend)?;
        if invocation.exit != ExitReason::Halt {
            return Err(LocalReplayExecutorError::RuntimeExit {
                reason: invocation.exit,
                pc: invocation.pc,
            });
        }
        let output = invocation
            .output_bounded(crate::service::wire::MAX_BYTES)
            .ok_or(LocalReplayExecutorError::RuntimeOutput)?;
        T::decode(&output).map_err(|_| LocalReplayExecutorError::RuntimeOutput)
    }

    fn execute_agent_wire<T: AgentCanonicalWire>(
        &self,
        runtime_pvm: &[u8],
        gas: Gas,
        input: &[u8],
    ) -> Result<T, LocalReplayExecutorError> {
        let started = std::time::Instant::now();
        #[cfg(test)]
        let observe = (input.len() > 700_000
            || std::env::var_os("VOS_AGENT_PROFILE_REFINE_ALL_INPUTS").is_some())
            && std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some()
            && std::env::var_os("VOS_AGENT_DISABLE_REFINE_ATTRIBUTION").is_none();
        #[cfg(not(test))]
        let observe = false;
        // Instruction attribution is explicitly the sparse reference path,
        // even when ordinary physical execution selects the native backend.
        // Native-memory snapshots scan the complete logical address span.
        let loaded = if observe {
            RefineContext::load_with_backend(
                runtime_pvm,
                input,
                gas,
                vos_pvm::refine::MemoryModel::Sparse,
                vos_pvm::PvmBackend::ForceInterpreter,
            )
        } else {
            self.runtime_preparation.load(runtime_pvm, input, gas)
        };
        let context = loaded.map_err(|error| match error {
            vos_pvm::refine::RefineError::Backend => LocalReplayExecutorError::RuntimeBackend,
            _ => LocalReplayExecutorError::RuntimeOutput,
        })?;
        let preparation_us = started.elapsed().as_micros() as u64;
        let execution_started = std::time::Instant::now();
        #[cfg(test)]
        // PROFILE_REFINE_MACHINES also disables fixture-native execution.
        // DISABLE_REFINE_ATTRIBUTION keeps that real PVM path unobserved.
        let invocation = if observe {
            profile_refine_machines(
                context,
                input.len(),
                input
                    .get(4 + crate::agent_sdk::RUNTIME_ABI_ID.as_bytes().len())
                    .copied(),
            )
        } else {
            context
                .try_run()
                .map_err(|_| LocalReplayExecutorError::RuntimeBackend)?
        };
        #[cfg(not(test))]
        let invocation = context
            .try_run()
            .map_err(|_| LocalReplayExecutorError::RuntimeBackend)?;
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros() as u64,
            preparation_us,
            execution_us = execution_started.elapsed().as_micros() as u64,
            input_bytes = input.len(),
            gas_limit = gas,
            gas_used = invocation.gas_used,
            "physical Agent runtime execution"
        );
        if invocation.exit != ExitReason::Halt {
            return Err(LocalReplayExecutorError::RuntimeExit {
                reason: invocation.exit,
                pc: invocation.pc,
            });
        }
        let output = invocation
            .output_bounded(T::MAX_ENCODED_BYTES)
            .ok_or(LocalReplayExecutorError::RuntimeOutput)?;
        T::decode(&output).map_err(|_| LocalReplayExecutorError::RuntimeOutput)
    }

    fn validate_state_size(
        &self,
        state: &RuntimeState,
        config: &AgentConfig,
    ) -> Result<(), LocalReplayExecutorError> {
        let bytes = state
            .encoded_len()
            .ok_or(LocalReplayExecutorError::RuntimeStateTooLarge)?;
        if state.is_empty()
            || bytes > super::execution::MAX_RUNTIME_STATE_BYTES
            || bytes > config.runtime_contract.resources.max_runtime_state_bytes as usize
        {
            return Err(LocalReplayExecutorError::RuntimeStateTooLarge);
        }
        Ok(())
    }

    fn management_state_config(
        &self,
        state: &RuntimeState,
        current: &AgentConfig,
        runtime_upgraded: bool,
    ) -> Result<AgentConfig, LocalReplayExecutorError> {
        if !runtime_upgraded {
            return Ok(current.clone());
        }
        decode_standard_runtime_state(state)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?
            .config
            .ok_or(LocalReplayExecutorError::InvalidState)
    }

    fn disposition(result: &Result<ActorExecutionReply, ActorExecutionError>) -> ReplayDisposition {
        match result {
            Ok(reply) => match reply.status {
                ActorExecutionStatus::Done => ReplayDisposition::Applied,
                ActorExecutionStatus::Forbidden => ReplayDisposition::Forbidden,
                ActorExecutionStatus::Panicked => ReplayDisposition::Panicked,
                ActorExecutionStatus::OutOfGas => ReplayDisposition::OutOfGas,
                // The legacy invoke journal has no intermediate-transition
                // record. The SDK Resume/Yielded path owns this case.
                ActorExecutionStatus::Yielded => ReplayDisposition::Rejected,
            },
            Err(_) => ReplayDisposition::Rejected,
        }
    }

    fn runtime_upgrade_target(input: &ReplayInput, applied: bool) -> RuntimeBinding {
        if !applied {
            return input.runtime.clone();
        }
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &input.operation
        else {
            return input.runtime.clone();
        };
        let LifecycleRequest::UpgradeRuntime {
            from_deployment,
            to_deployment,
            to_program,
            producer,
            package,
            ..
        } = request.as_ref()
        else {
            return input.runtime.clone();
        };
        if *from_deployment != input.runtime.deployment {
            return input.runtime.clone();
        }
        let mut next = input.runtime.clone();
        next.deployment = *to_deployment;
        next.program = *to_program;
        next.producer = *producer;
        next.package = package.clone();
        next
    }

    fn clean_runtime_upgrade_target(input: &ReplayInput, applied: bool) -> RuntimeBinding {
        if !applied {
            return input.runtime.clone();
        }
        let ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade),
            ..
        } = &input.operation
        else {
            return input.runtime.clone();
        };
        if upgrade.from_deployment.0 != input.runtime.deployment.0 {
            return input.runtime.clone();
        }
        let mut next = input.runtime.clone();
        next.deployment = DeploymentId(upgrade.to_deployment.0);
        next.program = ProgramId(upgrade.to_program.0);
        next.producer = ProducerId(upgrade.producer.0);
        next.package = Self::clean_blob(&upgrade.package);
        next
    }
}

impl<R: CatalogBlobResolver> ReplayExecutor for StandardLocalReplayExecutor<R> {
    type Error = LocalReplayExecutorError;

    #[cfg(feature = "experimental-state-blocks")]
    fn execute_with_external_state(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        genesis: &super::journal::AgentJournalGenesis,
        lanes: &[(
            super::journal::LaneStateManifest,
            super::journal::LaneCursor,
        )],
        reader: &dyn super::replay::ScopedBlockReader,
        budget: &mut crate::agent_sdk::state_blocks::ReadBudget,
    ) -> Result<ReplayTransition, Self::Error> {
        let external = self
            .external
            .as_mut()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let transition = external
            .execute_with_external_state(input, before, position, genesis, lanes, reader, budget)?;
        let execution = external
            .take_external_execution()?
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let outcome = execution.output().transition().outcome.clone();
        if let crate::agent_sdk::RuntimeOutcome::Management(_) = outcome {
            self.record_clean_management_result(input.id(), outcome);
        } else {
            self.record_clean_invocation_result_at(position, input.id(), outcome);
        }
        self.external_execution = Some(execution);
        Ok(transition)
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn take_external_execution(
        &mut self,
    ) -> Result<Option<super::replay::ReplayExternalExecution>, Self::Error> {
        Ok(self.external_execution.take())
    }

    fn trusted_clean_descriptor(
        &self,
        runtime: &RuntimeBinding,
    ) -> Result<Option<crate::agent_sdk::AgentDescriptor>, Self::Error> {
        self.clean_genesis_descriptor
            .as_ref()
            .map(|_| self.trusted_current_clean_descriptor(runtime))
            .transpose()
    }

    fn take_transition_proof_binding(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        transition: &ReplayTransition,
    ) -> Result<Option<ReplayTransitionProofBinding>, Self::Error> {
        let Some(mut pending) = self.pending_transition_proof.take() else {
            return Ok(None);
        };
        if pending.input != input.id() || pending.before != *before || pending.position != position
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        let projection = if pending.staged.is_some() {
            ReplayTransitionProofProjection::Prepared
        } else {
            ReplayTransitionProofProjection::Published
        };
        let binding = ReplayTransitionProofBinding::new(
            input,
            before,
            position,
            transition,
            &pending.runtime_transition,
            pending.key,
            pending.before_roots,
            pending.after_roots,
            pending.publication,
            projection,
        )
        .ok_or(LocalReplayExecutorError::InvalidState)?;
        if let Some(staged) = pending.staged.take() {
            if self.staged_transition_proofs.len() >= super::journal::MAX_REPLAY_SUFFIX_ENTRIES {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            self.staged_transition_proofs
                .try_reserve(1)
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            self.staged_transition_proofs.push(staged);
        }
        Ok(Some(binding))
    }

    fn clean_management_transition_result(
        &self,
        input: &ReplayInput,
        transition: &ReplayTransition,
    ) -> Option<Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>> {
        let Some(crate::agent_sdk::RuntimeOutcome::Management(result)) =
            self.recent_clean_management_results.get(&input.id())
        else {
            return None;
        };
        matches!(
            (result, transition.disposition),
            (Ok(_), ReplayDisposition::Applied) | (Err(_), ReplayDisposition::Rejected)
        )
        .then(|| result.clone())
    }

    fn seed_genesis(
        &mut self,
        genesis: &super::journal::AgentJournalGenesis,
    ) -> Result<(), Self::Error> {
        match &genesis.create.operation {
            ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(descriptor),
                ..
            } => {
                self.validate_clean_genesis_descriptor(descriptor)?;
                if self
                    .clean_genesis_descriptor
                    .as_ref()
                    .is_some_and(|seeded| seeded != descriptor.as_ref())
                {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                self.clean_genesis_descriptor = Some((**descriptor).clone());
                #[cfg(feature = "experimental-state-blocks")]
                if genesis.runtime().is_external_state() {
                    if self.profile != AgentProfile::Shared {
                        return Err(LocalReplayExecutorError::InvalidState);
                    }
                    let runtime = super::package_admission::admit_state_runtime_package(
                        &self.load(&genesis.runtime().package)?,
                    )
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                    let mut external =
                        super::external_local_executor::ExternalLocalReplayExecutor::new_shared(
                            runtime,
                            (**descriptor).clone(),
                            self.resolver.clone(),
                        )?;
                    external.seed_genesis(genesis)?;
                    self.external = Some(external);
                }
            }
            ReplayOperation::Management { .. } => {
                if self.clean_genesis_descriptor.is_some() {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
            }
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
        }
        Ok(())
    }

    fn verify_merge_event(&mut self, event: &MergeEvent) -> Result<bool, Self::Error> {
        if self.profile == AgentProfile::Local {
            return Ok(event.committee.is_none()
                && event.author == self.merge.node()
                && self.merge.verify_event(event));
        }
        let Some(committee_id) = event.committee else {
            return Ok(false);
        };
        let Some(committee) = self.shared_committees.get(&committee_id) else {
            return Ok(false);
        };
        let Some(member) = committee.member_by_node(event.author) else {
            return Ok(false);
        };
        let Ok(key) = VerifyingKey::from_bytes(member.ed25519_public_key()) else {
            return Ok(false);
        };
        let Ok(signature) = Signature::from_slice(&event.signature) else {
            return Ok(false);
        };
        Ok(key
            .verify_strict(&event.signing_message().0, &signature)
            .is_ok())
    }

    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<(), Self::Error> {
        #[cfg(feature = "experimental-state-blocks")]
        if let Some(external) = &mut self.external {
            self.external_execution = None;
            return external.authenticate(input, before, position);
        }
        // Authentication mints a one-shot execution capability. Invalidate a
        // prior capability first so every error path fails closed.
        self.authenticated_execution = None;
        self.pending_transition_proof = None;
        if let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &input.operation
        {
            let genesis_descriptor = match request {
                crate::agent_sdk::ManagementRequest::Create(descriptor) => {
                    self.validate_clean_genesis_descriptor(descriptor)?;
                    if self
                        .clean_genesis_descriptor
                        .as_ref()
                        .is_some_and(|seeded| seeded != descriptor.as_ref())
                    {
                        return Err(LocalReplayExecutorError::InvalidState);
                    }
                    descriptor.as_ref().clone()
                }
                _ => self
                    .clean_genesis_descriptor
                    .clone()
                    .ok_or(LocalReplayExecutorError::InvalidState)?,
            };
            let runtime = self.clean_runtime_package(&input.runtime)?;
            let descriptor =
                Self::current_clean_descriptor(&genesis_descriptor, &input.runtime, &runtime)?;
            if matches!(request, crate::agent_sdk::ManagementRequest::Create(created) if created.as_ref() != &descriptor)
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            super::driver::verify_clean_management_journal_receipt(
                &descriptor,
                request,
                authority,
                *observed_slot,
                true,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
            self.validate_clean_management_artifacts(&descriptor, request)?;
            self.clean_genesis_descriptor = Some(genesis_descriptor);
            self.authenticated_execution = Some(AuthenticatedLocalExecution {
                input: input.id(),
                before: before.clone(),
                position,
                runtime_pvm: runtime.program_bytes().to_vec(),
                runtime_state_limit: runtime
                    .manifest()
                    .contract
                    .resources
                    .max_runtime_state_bytes as usize,
                clean_descriptor: Some(descriptor),
            });
            return Ok(());
        }
        if let Some((work, authorization, observed_slot)) = match &input.operation {
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
                if !work.validate() {
                    return Err(LocalReplayExecutorError::InvalidAuthority);
                }
                Some((
                    crate::agent_sdk::InvocationRetirement::from_work(work),
                    authorization,
                    *observed_slot,
                ))
            }
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => Some((
                work.clone(),
                authorization,
                match authorization {
                    crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(_) => 0,
                    crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) => {
                        preflight.observed_slot
                    }
                },
            )),
            _ => None,
        } && self.clean_genesis_descriptor.is_some()
        {
            let runtime = self.clean_runtime_package(&input.runtime)?;
            let descriptor = self.trusted_current_clean_descriptor(&input.runtime)?;
            Self::validate_clean_retirement_envelope(
                &descriptor,
                &work,
                authorization,
                observed_slot,
            )?;
            self.authenticated_execution = Some(AuthenticatedLocalExecution {
                input: input.id(),
                before: before.clone(),
                position,
                runtime_pvm: runtime.program_bytes().to_vec(),
                runtime_state_limit: runtime
                    .manifest()
                    .contract
                    .resources
                    .max_runtime_state_bytes as usize,
                clean_descriptor: Some(descriptor),
            });
            return Ok(());
        }
        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?;
        let runtime_pvm = if matches!(
            input.operation,
            ReplayOperation::CleanInvoke { .. }
                | ReplayOperation::CleanResume { .. }
                | ReplayOperation::CleanAcknowledge { .. }
        ) && self.clean_genesis_descriptor.is_some()
        {
            self.clean_runtime_package(&input.runtime)?
                .program_bytes()
                .to_vec()
        } else {
            self.validate_local_config(config, &input.runtime)?.pvm
        };
        match &input.operation {
            ReplayOperation::Management { request } => {
                self.authenticate_management(config, request)
            }
            ReplayOperation::CleanManage { .. } => unreachable!("handled above"),
            ReplayOperation::Invoke {
                invocation,
                authority,
                ..
            }
            | ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => {
                invocation
                    .validate()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                authority
                    .validate_for(
                        &config.authority,
                        config.identity.space,
                        config.identity.agent,
                        invocation,
                    )
                    .map_err(|_| LocalReplayExecutorError::InvalidAuthority)
            }
            ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
                ..
            } => {
                let runtime = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                runtime
                    .verify_clean_invocation_authorization(work, authorization, *observed_slot)
                    .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
                super::wire::admit_clean_public_preflight(&runtime, work, authorization)
                    .map_err(|_| LocalReplayExecutorError::InvalidAuthority)
            }
            ReplayOperation::CleanResume {
                work,
                authorization,
                yielded,
                observed_slot,
                ..
            } => {
                let runtime = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                runtime
                    .verify_clean_invocation_authorization(work, authorization, *observed_slot)
                    .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
                match runtime
                    .recover_clean_yield(work, authorization, *observed_slot)
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?
                {
                    Some(current) if current == *yielded => Ok(()),
                    _ => Err(LocalReplayExecutorError::InvalidRequest),
                }
            }
            ReplayOperation::CleanAcknowledge {
                work,
                authorization,
                ..
            } => {
                let mut runtime = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                match runtime.acknowledge_clean_retirement_with_status(work, authorization) {
                    Ok(_) | Err(crate::agent_sdk::InvocationError::NotFound) => Ok(()),
                    Err(_) => Err(LocalReplayExecutorError::InvalidRequest),
                }
            }
            ReplayOperation::SealMerge => Ok(()),
        }?;
        self.authenticated_execution = Some(AuthenticatedLocalExecution {
            input: input.id(),
            before: before.clone(),
            position,
            runtime_pvm,
            runtime_state_limit: config.runtime_contract.resources.max_runtime_state_bytes as usize,
            clean_descriptor: None,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error> {
        self.execute_with_journal_context(
            input,
            before,
            position,
            ReplayTransitionProofAccess::PublishedOnly,
            None,
        )
    }

    fn execute_with_journal_context(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        transition_proof_access: ReplayTransitionProofAccess,
        journal_context: Option<RuntimeJournalContext>,
    ) -> Result<ReplayTransition, Self::Error> {
        if !matches!(
            &input.operation,
            ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                ..
            }
        ) {
            self.terminal_preflight
                .get_mut()
                .map_err(|_| LocalReplayExecutorError::InvalidState)?
                .take();
        }
        let authenticated = self
            .authenticated_execution
            .take()
            .ok_or(LocalReplayExecutorError::InvalidAuthority)?;
        if authenticated.input != input.id()
            || authenticated.before != *before
            || authenticated.position != position
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        let runtime_pvm = authenticated.runtime_pvm;
        if let ReplayOperation::CleanManage {
            request,
            authority,
            observed_slot,
        } = &input.operation
        {
            if journal_context.is_some() {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let descriptor = authenticated
                .clean_descriptor
                .as_ref()
                .ok_or(LocalReplayExecutorError::InvalidState)?;
            let work = super::replay::canonical_clean_runtime_work(input, before)
                .ok_or(LocalReplayExecutorError::InvalidRequest)?;
            let encoded = work
                .encode()
                .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
            #[cfg(all(test, feature = "pvm"))]
            let returned: crate::agent_sdk::RuntimeTransition =
                if self.trust.use_native_clean_runtime_for_test() {
                    super::wire::apply_standard_runtime_work(work)
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                } else {
                    self.execute_agent_wire(&runtime_pvm, self.management_gas, &encoded)?
                };
            #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
            let returned: crate::agent_sdk::RuntimeTransition =
                self.execute_agent_wire(&runtime_pvm, self.management_gas, &encoded)?;
            if *observed_slot > authority.selector.expires_at
                && (returned.outcome
                    != crate::agent_sdk::RuntimeOutcome::Management(Err(
                        crate::agent_sdk::ManagementError::ExpiredBeforeApplication,
                    ))
                    || (returned.state.control == before.control
                        && returned.state.linear == before.linear
                        && returned.state.merge == before.merge
                        && returned.state.local == before.local))
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            if !super::driver::sdk_management_reply_matches(descriptor, request, &returned.outcome)
                || returned
                    .state
                    .encoded_len()
                    .is_none_or(|bytes| bytes > authenticated.runtime_state_limit)
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let applied = matches!(
                returned.outcome,
                crate::agent_sdk::RuntimeOutcome::Management(Ok(_))
            );
            if applied
                && matches!(request, crate::agent_sdk::ManagementRequest::Create(_))
                && returned.state.is_empty()
            {
                return Err(LocalReplayExecutorError::InvalidState);
            }
            let state = RuntimeState {
                control: returned.state.control,
                linear: returned.state.linear,
                merge: returned.state.merge,
                local: returned.state.local,
            };
            let next_runtime = Self::clean_runtime_upgrade_target(input, applied);
            self.record_clean_management_result(input.id(), returned.outcome);
            return Ok(ReplayTransition {
                state,
                disposition: if applied {
                    ReplayDisposition::Applied
                } else {
                    ReplayDisposition::Rejected
                },
                result: None,
                next_runtime,
                products: ReplayProducts::default(),
                attested_transition: None,
            });
        }
        if matches!(
            input.operation,
            ReplayOperation::CleanInvoke { .. }
                | ReplayOperation::CleanResume { .. }
                | ReplayOperation::CleanAcknowledge { .. }
        ) && authenticated.clean_descriptor.is_some()
        {
            return self.execute_clean_invocation_transition(
                input,
                before,
                position,
                transition_proof_access,
                &runtime_pvm,
                authenticated.runtime_state_limit,
                true,
            );
        }

        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?.clone();

        let transition = match &input.operation {
            ReplayOperation::Management { request } => {
                let mut expected = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                let direct_system_authority = matches!(
                    request,
                    LifecycleRequest::FinalizeSystemAuthority(_)
                        | LifecycleRequest::RotateSystemAuthority(_)
                        | LifecycleRequest::FinalizeCatalog(_)
                );
                if direct_system_authority != journal_context.is_some() {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                let expected_result = match journal_context {
                    Some(context) => expected.apply_guest(Some(context), request.clone()),
                    None => expected.apply(request.clone()),
                };
                // Live admission stages and validates a fresh upgrade target
                // only when the exact Standard preflight succeeds. Historical
                // Busy/NotFound/Stale outcomes therefore must not resolve an
                // artifact which was intentionally never made durable.
                self.validate_replayed_upgrade_target(before, request, &expected_result)?;
                let call = match journal_context {
                    Some(context) => {
                        RuntimeCall::from_replay_context(before.clone(), request.clone(), context)
                    }
                    None => RuntimeCall::new(before.clone(), request.clone()),
                };
                #[cfg(test)]
                let returned: RuntimeReturn = if self.trust.use_native_standard_runtime_for_test() {
                    RuntimeReturn {
                        state: encode_standard_runtime_state(&expected.snapshot()),
                        result: expected_result.clone(),
                    }
                } else {
                    self.execute_wire(&runtime_pvm, self.management_gas, &call.encode())?
                };
                #[cfg(not(test))]
                let returned: RuntimeReturn =
                    self.execute_wire(&runtime_pvm, self.management_gas, &call.encode())?;
                if returned.result != expected_result {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                self.last_management_result = Some((input.id(), returned.result.clone()));
                let applied = returned.result.is_ok();
                let next_runtime = Self::runtime_upgrade_target(input, applied);
                let runtime_upgraded = applied && next_runtime != input.runtime;
                let state_config =
                    self.management_state_config(&returned.state, &config, runtime_upgraded)?;
                self.validate_state_size(&returned.state, &state_config)?;
                if runtime_upgraded {
                    self.validate_local_config(&state_config, &next_runtime)?;
                }
                ReplayTransition {
                    state: returned.state,
                    disposition: if applied {
                        ReplayDisposition::Applied
                    } else {
                        ReplayDisposition::Rejected
                    },
                    result: None,
                    next_runtime,
                    products: ReplayProducts::default(),
                    attested_transition: None,
                }
            }
            ReplayOperation::CleanManage { .. } => unreachable!("handled above"),
            ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => {
                let request = LifecycleRequest::AcknowledgeInvocation {
                    scope: invocation.mode.invocation_scope(),
                    invocation: invocation.invocation,
                    request: invocation.commitment(),
                    authority: Box::new(authority.clone()),
                };
                let call = RuntimeCall::new(before.clone(), request);
                #[cfg(test)]
                let returned = if self.trust.use_native_standard_runtime_for_test() {
                    super::wire::apply_standard(call)
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                } else {
                    self.execute_wire(&runtime_pvm, self.management_gas, &call.encode())?
                };
                #[cfg(not(test))]
                let returned: RuntimeReturn =
                    self.execute_wire(&runtime_pvm, self.management_gas, &call.encode())?;
                self.validate_state_size(&returned.state, &config)?;
                if !matches!(
                    returned.result,
                    Ok(LifecycleReply::InvocationAcknowledged {
                        scope,
                        invocation: id,
                    }) if scope == invocation.mode.invocation_scope() && id == invocation.invocation
                ) {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                ReplayTransition {
                    state: returned.state,
                    disposition: ReplayDisposition::Applied,
                    result: None,
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                    attested_transition: None,
                }
            }
            ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot,
            } => {
                let artifacts = self.actor_artifacts(&config, &decoded, invocation)?;
                let recovery_only = artifacts.is_none();
                let empty = Self::empty_blob;
                let (actor_pvm, actor_schema, actor_policies, installation_data) =
                    artifacts.unwrap_or_else(|| (Vec::new(), empty(), empty(), None));
                let call = RuntimeExecutionCall {
                    state: before.clone(),
                    invocation: invocation.clone(),
                    authority: authority.clone(),
                    observed_slot: *observed_slot,
                    recovery_only,
                    actor_pvm,
                    actor_schema,
                    actor_policies,
                    installation_data,
                };
                #[cfg(all(test, feature = "pvm"))]
                let returned = if self.trust.use_native_standard_runtime_for_test() {
                    super::wire::apply_standard_execution(call)
                        .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
                } else {
                    self.execute_wire(
                        &runtime_pvm,
                        self.management_gas.saturating_add(invocation.gas),
                        &call.encode(),
                    )?
                };
                #[cfg(any(not(test), all(test, not(feature = "pvm"))))]
                let returned: RuntimeExecutionReturn = self.execute_wire(
                    &runtime_pvm,
                    self.management_gas.saturating_add(invocation.gas),
                    &call.encode(),
                )?;
                self.validate_state_size(&returned.state, &config)?;
                ReplayTransition {
                    disposition: Self::disposition(&returned.result),
                    state: returned.state,
                    result: Some(returned.result),
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                    attested_transition: None,
                }
            }
            ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. } => {
                return self.execute_clean_invocation_transition(
                    input,
                    before,
                    position,
                    transition_proof_access,
                    &runtime_pvm,
                    config.runtime_contract.resources.max_runtime_state_bytes as usize,
                    true,
                );
            }
            ReplayOperation::SealMerge => ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Applied,
                result: None,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
                attested_transition: None,
            },
        };
        if !transition.products.is_empty() {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(transition)
    }
}

/// Store/replay nucleus kept generic so both fd-pinned filesystem stores and
/// the deterministic memory store follow the identical publication path.
struct LocalJournalCore<S, E> {
    store: S,
    materialization: ReplayMaterialization,
    executor: E,
}

#[derive(Debug, PartialEq, Eq)]
struct LocalCorePublication {
    executions: Vec<ReplayExecutionResult>,
    committed: Option<ReplayCommittedRecovery>,
    published_position: Option<ReplayPosition>,
}

#[derive(Debug, PartialEq, Eq)]
enum ExistingMergeRecovery {
    Pending(PendingMergeReceipt),
    Acknowledged,
}

impl core::ops::Deref for LocalCorePublication {
    type Target = [ReplayExecutionResult];

    fn deref(&self) -> &Self::Target {
        &self.executions
    }
}

impl<S, E> LocalJournalCore<S, E>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore
        + TransitionProofPublicationStore,
    E: ReplayExecutor<Error = LocalReplayExecutorError>,
{
    fn open(mut store: S, mut executor: E) -> Result<Self, LocalJournalDriverError> {
        let materialization =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
        Ok(Self {
            store,
            materialization,
            executor,
        })
    }

    fn from_materialization(store: S, executor: E, materialization: ReplayMaterialization) -> Self {
        Self {
            store,
            materialization,
            executor,
        }
    }

    fn checkpoint(&mut self) -> Result<(), LocalJournalDriverError> {
        let prepared = prepare_checkpoint(&mut self.store, &self.materialization)
            .map_err(lift_checkpoint_error)?;
        let (_, successor, executions) = prepared.publish()?;
        if !executions.is_empty() {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        self.materialization = successor;
        Ok(())
    }

    fn persist_current_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, LocalJournalDriverError> {
        let state = &self.materialization.state().merge;
        let reference = BlobRef::of_bytes(state);
        self.store
            .put_blob(JournalBlobClass::LaneState, &reference, state)?;
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            self.materialization.heads().genesis,
            self.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: self.materialization.merge_frontier(),
            },
            state,
        )
        .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        self.store.put(&manifest)?;
        let seal = MergeSeal {
            genesis: self.materialization.heads().genesis,
            frontier: self.materialization.merge_frontier(),
            ordered_base: self.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        self.store.put(&seal)?;
        Ok(seal.id())
    }

    fn publish_ordered(
        &mut self,
        entry: &OrderedEntry,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let mut candidate = entry.clone();
        let prepared = match prepare_ordered(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &candidate,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                let merge_seal = if entry.merge_seal.is_some() {
                    Some(self.persist_current_merge_seal()?)
                } else {
                    None
                };
                let heads = self.materialization.heads();
                candidate = OrderedEntry {
                    genesis: heads.genesis,
                    index: heads
                        .ordered_index
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal,
                    input: entry.input.clone(),
                };
                prepare_ordered(
                    &mut self.store,
                    &mut self.executor,
                    &self.materialization,
                    &candidate,
                )
                .map_err(LocalJournalDriverError::from)?
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Ordered {
            id: candidate.id(),
            index: candidate.index,
            merge_frontier: candidate.merge_frontier,
            merge_seal: candidate.merge_seal,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    fn publish_local(
        &mut self,
        entry: &LocalEntry,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let mut candidate = entry.clone();
        let prepared = match prepare_local(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &candidate,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                let heads = self.materialization.heads();
                candidate = LocalEntry {
                    genesis: heads.genesis,
                    node: heads.node,
                    revision: heads
                        .local_revision
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.local_head,
                    ordered_base: self.materialization.ordered_base(),
                    merge_frontier: heads.merge_frontier,
                    input: entry.input.clone(),
                };
                prepare_local(
                    &mut self.store,
                    &mut self.executor,
                    &self.materialization,
                    &candidate,
                )
                .map_err(LocalJournalDriverError::from)?
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Local {
            id: candidate.id(),
            node: candidate.node,
            revision: candidate.revision,
            ordered_base: candidate.ordered_base,
            merge_frontier: candidate.merge_frontier,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    fn publish_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let prepared = match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            event,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                // The checkpoint may replace the canonical OrderedBase. A
                // Merge event signs that base, so only the driver holding the
                // LocalMergeAuthenticator can rebuild it safely.
                return Err(LocalJournalDriverError::Replay(ReplayError::ReplayLimit));
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Merge {
            id: event.id(),
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    /// Resolve a same-request pending Merge owner to its authenticated source
    /// event before proposing any alias event. The returned receipt contains
    /// the exact input and position needed for restart-safe recovery.
    fn existing_merge_recovery(
        &mut self,
        input: &ReplayInput,
    ) -> Result<Option<ExistingMergeRecovery>, LocalJournalDriverError> {
        let (invocation, acknowledgement) = match &input.operation {
            ReplayOperation::Invoke { invocation, .. } => (invocation, false),
            ReplayOperation::Acknowledge { invocation, .. } => (invocation, true),
            ReplayOperation::Management { .. }
            | ReplayOperation::CleanManage { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::SealMerge => return Ok(None),
        };
        if invocation.mode.invocation_scope() != InvocationScope::Merge {
            return Ok(None);
        }
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Merge,
            invocation: invocation.invocation,
        };
        let heads = self.materialization.heads();
        let indexes = InvocationIndexes::open(
            &mut self.store,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
        )
        .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let Some(lookup) = indexes
            .lookup(key)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?
        else {
            return Ok(None);
        };
        let owner = match lookup {
            InvocationIndexLookup::Archived(fact) => {
                if fact.validate().is_err()
                    || fact.genesis() != heads.genesis
                    || fact.key() != key
                    || fact.request_commitment() != invocation.commitment()
                {
                    return Ok(None);
                }
                return Ok(Some(ExistingMergeRecovery::Acknowledged));
            }
            InvocationIndexLookup::Live(owner) => owner,
        };
        if owner.validate().is_err()
            || owner.scope != InvocationOwnershipScope::Merge
            || owner.request_commitment != invocation.commitment()
        {
            return Ok(None);
        }
        let source_event = match (acknowledgement, owner.result_state) {
            (false, InvocationResultState::PendingMerge { source_event }) => source_event,
            (
                true,
                InvocationResultState::PendingMergeAcknowledgement {
                    acknowledgement_event,
                    ..
                },
            ) => acknowledgement_event,
            (false, InvocationResultState::PendingMergeAcknowledgement { .. }) => {
                let outcome = indexes
                    .outcome(key)
                    .map_err(|_| LocalJournalDriverError::InvalidResult)?
                    .ok_or(LocalJournalDriverError::InvalidResult)?;
                match outcome.anchor {
                    InvocationOutcomeAnchor::Merge { source_event, .. } => source_event,
                    InvocationOutcomeAnchor::Ordered { .. }
                    | InvocationOutcomeAnchor::Local { .. } => {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                }
            }
            _ => return Ok(None),
        };
        drop(indexes);

        let event = self
            .store
            .get::<MergeEvent>(source_event)?
            .ok_or(LocalJournalDriverError::InvalidResult)?;
        if event.validate().is_err()
            || event.id() != source_event
            || event.genesis != self.materialization.heads().genesis
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        let position = ReplayPosition::Merge {
            id: source_event,
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        if self.recover(&event.input, position)? != ReplayInvocationRecovery::Pending {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(Some(ExistingMergeRecovery::Pending(PendingMergeReceipt {
            event: source_event,
            frontier: MergeFrontier {
                genesis: event.genesis,
                events: vec![source_event],
            }
            .id(),
            input: event.input,
            position,
        })))
    }

    fn recover(
        &mut self,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<ReplayInvocationRecovery, LocalJournalDriverError> {
        recover_invocation(&mut self.store, &self.materialization, input, position)
            .map_err(|error| LocalJournalDriverError::Replay(lift_checkpoint_error(error)))
    }
}

/// Production journal-backed Local Agent driver.
///
/// `S` may be the memory reference store or the fd-pinned filesystem store;
/// both provide a cloneable read-only resolver snapshot to the exact runtime
/// executor. No whole [`super::driver::AgentImage`] is constructed or used.
pub(crate) struct LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore
        + TransitionProofPublicationStore,
{
    core: LocalJournalCore<S, StandardLocalReplayExecutor<S::Resolver>>,
    #[cfg(test)]
    lifecycle_fault: Option<TestLifecycleFault>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestLifecycleFault {
    CatalogPutAfterFirst,
    BeforeMergeSeal,
    BeforeOrderedPublish,
}

impl<S> LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore
        + TransitionProofPublicationStore,
{
    /// Construct the exact bootstrap-owned Authorized<Create> input and its
    /// single runtime-package catalog. The trusted logical slot is sampled at
    /// this boundary; callers cannot supply an already-authorized envelope.
    ///
    /// This is a provider-miss operation only. Exact retry and reopen must
    /// reproduce the provider's archived proposal/provision unchanged; they
    /// must never resample the logical slot by rebuilding this input.
    pub(crate) fn system_genesis_input(
        config: AgentConfig,
        runtime_package: &Package,
        receipt: AgentAuthorityReceipt,
        configured_root: &RootAnchorPins,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        configured_root
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let system_authority_genesis = config
            .system_authority_genesis
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        system_authority_genesis
            .validate_root_config(configured_root.record(), &config, receipt.claim.sequence)
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let catalog = Self::runtime_package_catalog(runtime_package);
        let runtime = RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: catalog[0].reference.clone(),
            runtime_abi: super::RUNTIME_ABI_ID,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
        };
        let request = seal_lifecycle_request(
            trust.as_ref(),
            receipt,
            LifecycleRequest::Create(config.clone()),
        )?;
        // This provider-miss constructor performs only offline shape and exact
        // content binding checks. Receipt, package-policy, and authority-root
        // authentication happen exactly once in ReplayPreparedGenesis::prepare
        // immediately before the one execution.
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::validate_local_config_shape(
            &config,
            &runtime,
            merge.node(),
        )?;
        runtime_package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::
            validate_runtime_package_binding(&config, &runtime, runtime_package)?;
        Ok((
            ReplayInput {
                runtime,
                operation: ReplayOperation::Management { request },
            },
            catalog,
        ))
    }

    /// Construct the exact Authorized<Create> replay input for an ordinary
    /// Local Agent.  The live trust slot is sampled here and the returned
    /// input is the only value later persisted in the host's durable creation
    /// intent.  Root-system bootstrap data is explicitly forbidden.
    pub(crate) fn local_genesis_input(
        config: AgentConfig,
        runtime_package: &Package,
        receipt: AgentAuthorityReceipt,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        if config.system_authority_genesis.is_some() {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let catalog = Self::runtime_package_catalog(runtime_package);
        let runtime = RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: catalog[0].reference.clone(),
            runtime_abi: super::RUNTIME_ABI_ID,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
        };
        let request = seal_lifecycle_request(
            trust.as_ref(),
            receipt,
            LifecycleRequest::Create(config.clone()),
        )?;
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::validate_local_config_shape(
            &config,
            &runtime,
            merge.node(),
        )?;
        runtime_package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::
            validate_runtime_package_binding(&config, &runtime, runtime_package)?;
        Ok((
            ReplayInput {
                runtime,
                operation: ReplayOperation::Management { request },
            },
            catalog,
        ))
    }

    /// Construct the exact clean SDK Create replay input and runtime catalog
    /// for an ordinary Local Agent. The descriptor and receipt remain SDK
    /// values; no legacy lifecycle projection is created.
    pub(crate) fn clean_local_genesis_input(
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime_package: &super::package_admission::AdmittedRuntimePackage,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        let [replica] = descriptor.replicas.as_slice() else {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        };
        if descriptor.validate().is_err()
            || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Local
            || replica.node.0 != merge.node().0
            || descriptor.runtime_package != *runtime_package.package_ref()
            || descriptor.identity.runtime_deployment != runtime_package.deployment()
            || descriptor.identity.runtime_program != runtime_package.program()
            || descriptor.identity.runtime_producer != runtime_package.producer()
            || descriptor.runtime_contract != runtime_package.manifest().contract
            || descriptor.capabilities != runtime_package.capabilities()
        {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let observed_slot = trust
            .current_logical_slot()
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        super::driver::verify_clean_management_receipt(
            &descriptor,
            &request,
            &authority,
            observed_slot,
            false,
        )
        .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let catalog = vec![Self::runtime_blob(runtime_package.exact_bytes().to_vec())];
        let runtime = RuntimeBinding {
            space: crate::service::SpaceId(descriptor.identity.space.0),
            agent: crate::service::AgentId(descriptor.identity.agent.0),
            deployment: DeploymentId(descriptor.identity.runtime_deployment.0),
            program: ProgramId(descriptor.identity.runtime_program.0),
            producer: ProducerId(descriptor.identity.runtime_producer.0),
            package: catalog[0].reference.clone(),
            runtime_abi: super::RUNTIME_ABI_ID,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot,
            },
        };
        create
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        Ok((create, catalog))
    }

    /// Construct the exact clean SDK Create input used by the independently
    /// root/QC-authorized fixed-roster Shared system Agent. This is deliberately
    /// separate from ordinary system-Agent finality: it performs only package,
    /// descriptor, receipt, clock, and physical-replica binding. The returned
    /// input still has to pass [`Self::prepare_system_genesis`] and the root
    /// seal before any Shared journal bytes may be initialized. Preparation
    /// accepts the existing singleton and a fixed three-voter roster; this
    /// does not enable multi-node startup.
    pub(crate) fn clean_shared_system_genesis_input(
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime_package: &super::package_admission::AdmittedRuntimePackage,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        let Some(replica) = descriptor
            .replicas
            .iter()
            .find(|replica| replica.node.0 == merge.node().0)
        else {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        };
        if !matches!(descriptor.replicas.len(), 1 | 3)
            || descriptor
                .replicas
                .iter()
                .any(|entry| entry.role != crate::agent_sdk::ReplicaRole::Voter)
            || replica.role != crate::agent_sdk::ReplicaRole::Voter
        {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        Self::clean_shared_genesis_input(
            descriptor,
            runtime_package,
            authority,
            observed_slot,
            trust,
            merge,
        )
    }

    /// Build ordinary Shared Create input from an admitted package and signed
    /// receipt. The caller retains the exact observed slot across retries.
    /// This does not authorize the replica committee or establish finality.
    pub(crate) fn clean_shared_genesis_input(
        descriptor: crate::agent_sdk::AgentDescriptor,
        runtime_package: &super::package_admission::AdmittedRuntimePackage,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        observed_slot: u64,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        if descriptor.validate().is_err()
            || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
            || !descriptor
                .replicas
                .iter()
                .any(|replica| replica.node.0 == merge.node().0)
            || descriptor.runtime_package != *runtime_package.package_ref()
            || descriptor.identity.runtime_deployment != runtime_package.deployment()
            || descriptor.identity.runtime_program != runtime_package.program()
            || descriptor.identity.runtime_producer != runtime_package.producer()
            || descriptor.runtime_contract != runtime_package.manifest().contract
            || descriptor.capabilities != runtime_package.capabilities()
        {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        if trust
            .current_logical_slot()
            .is_none_or(|current| current < observed_slot)
        {
            return Err(LocalReplayExecutorError::TrustUnavailable.into());
        }
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        super::driver::verify_clean_management_receipt(
            &descriptor,
            &request,
            &authority,
            observed_slot,
            false,
        )
        .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let catalog = vec![Self::runtime_blob(runtime_package.exact_bytes().to_vec())];
        let runtime = RuntimeBinding {
            space: crate::service::SpaceId(descriptor.identity.space.0),
            agent: crate::service::AgentId(descriptor.identity.agent.0),
            deployment: DeploymentId(descriptor.identity.runtime_deployment.0),
            program: ProgramId(descriptor.identity.runtime_program.0),
            producer: ProducerId(descriptor.identity.runtime_producer.0),
            package: catalog[0].reference.clone(),
            runtime_abi: super::RUNTIME_ABI_ID,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::CleanManage {
                request,
                authority,
                observed_slot,
            },
        };
        create
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        Ok((create, catalog))
    }

    /// Execute and authenticate the bootstrap-owned Create input without
    /// writing a destination store. The returned opaque replay token is the
    /// sole input accepted by the independent genesis proposal/seal path.
    pub(crate) fn prepare_system_genesis(
        create: ReplayInput,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplayPreparedGenesis, LocalJournalDriverError> {
        if replica.node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let ReplayOperation::CleanManage {
            request: crate::agent_sdk::ManagementRequest::Create(descriptor),
            ..
        } = &create.operation
        else {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        };
        if !super::bootstrap::descriptor_matches_root_replica(descriptor, replica) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let expected_catalog = supplied.blobs.clone();
        let mut executor =
            StandardLocalReplayExecutor::new_shared(supplied, trust, merge, Vec::new());
        let prepared = ReplayPreparedGenesis::prepare(create, replica, &mut executor)
            .map_err(lift_prepared_genesis_error)?;
        if expected_catalog.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                expected_catalog
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(prepared)
    }

    /// Authenticate and execute one ordinary Local Create, then mint the
    /// non-root opaque genesis seal.  There is no constructor from decoded
    /// journal bytes or caller-supplied output state.
    pub(crate) fn prepare_local_genesis(
        create: ReplayInput,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplaySealedLocalGenesis, LocalJournalDriverError> {
        if replica.node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let expected_catalog = supplied.blobs.clone();
        let mut executor = StandardLocalReplayExecutor::new(supplied, trust, merge);
        let prepared = ReplayPreparedGenesis::prepare(create, replica, &mut executor)
            .map_err(lift_prepared_genesis_error)?;
        if expected_catalog.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                expected_catalog
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        ReplaySealedLocalGenesis::from_prepared(prepared).map_err(|error| {
            LocalJournalDriverError::Replay(
                error
                    .map_source(|never| match never {})
                    .map_executor(|never| match never {}),
            )
        })
    }

    /// Prepare an experimental Local Create from the same immutable catalog
    /// supplied with its trusted intent. This does not stage a destination,
    /// publish heads or expose a route; the root-bearing seal must be consumed
    /// by a distinct external Local owner after normal lifecycle admission.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn prepare_external_local_genesis(
        create: ReplayInput,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        expected_node: NodeId,
    ) -> Result<super::replay::ReplaySealedExternalLocalGenesis, LocalJournalDriverError> {
        let prepared = Self::prepare_external_genesis_candidate(
            create,
            replica,
            catalog,
            expected_node,
            crate::agent_sdk::AgentProfile::Local,
        )?;
        super::replay::ReplaySealedExternalLocalGenesis::from_prepared(prepared).map_err(|error| {
            LocalJournalDriverError::Replay(
                error
                    .map_source(|never| match never {})
                    .map_executor(|never| match never {}),
            )
        })
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn prepare_external_shared_genesis_candidate(
        create: ReplayInput,
        replica: AgentReplica,
        committee: &AgentReplicaCommittee,
        catalog: &[RuntimeBlob],
        trust: &Arc<dyn AgentTrustProvider>,
        expected_node: NodeId,
    ) -> Result<super::replay::ReplayPreparedExternalGenesis, LocalJournalDriverError> {
        if committee.validate().is_err()
            || committee
                .member_by_node(replica.node)
                .map(|member| member.replica())
                != Some(replica)
            || !super::replay::validates_shared_create_committee(&create, committee)
        {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let ReplayOperation::CleanManage { observed_slot, .. } = &create.operation else {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        };
        if trust
            .current_logical_slot()
            .is_none_or(|slot| slot < *observed_slot)
        {
            return Err(LocalReplayExecutorError::TrustUnavailable.into());
        }
        Self::prepare_external_genesis_candidate(
            create,
            replica,
            catalog,
            expected_node,
            crate::agent_sdk::AgentProfile::Shared,
        )
    }

    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn prepare_external_shared_genesis(
        verified: &VerifiedAgentGenesisProvision,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: &Arc<dyn AgentTrustProvider>,
        expected_node: NodeId,
    ) -> Result<super::replay::ReplaySealedExternalGenesis, LocalJournalDriverError> {
        let provision = verified.provision();
        let prepared = Self::prepare_external_shared_genesis_candidate(
            provision.proposal().create().clone(),
            replica,
            provision.replicas(),
            catalog,
            trust,
            expected_node,
        )?;
        super::replay::ReplaySealedExternalGenesis::from_prepared_shared(verified, prepared)
            .map_err(|error| {
                LocalJournalDriverError::Replay(
                    error
                        .map_source(|never| match never {})
                        .map_executor(|never| match never {}),
                )
            })
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn prepare_external_genesis_candidate(
        create: ReplayInput,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        expected_node: NodeId,
        profile: crate::agent_sdk::AgentProfile,
    ) -> Result<super::replay::ReplayPreparedExternalGenesis, LocalJournalDriverError> {
        use super::replay::{
            ExternalGenesisExecutor, ReplayPreparedExternalGenesis, ScopedBlockReader,
        };
        use crate::agent_sdk::{
            state_blocks::{BlockRef, BlockScope, ReadBudget},
            state_tree::TreeError,
        };

        struct NoGenesisBlocks;
        impl ScopedBlockReader for NoGenesisBlocks {
            fn read_scoped(
                &self,
                _: BlockScope,
                _: BlockRef,
                _: &mut [u8],
            ) -> Result<bool, TreeError> {
                Err(TreeError::Storage)
            }
        }

        struct Executor {
            admitted: super::package_admission::AdmittedStateRuntimePackage,
            replica: AgentReplica,
            profile: crate::agent_sdk::AgentProfile,
            authenticated: Option<ReplayInputId>,
        }
        impl ReplayExecutor for Executor {
            type Error = LocalReplayExecutorError;

            fn verify_merge_event(&mut self, _: &MergeEvent) -> Result<bool, Self::Error> {
                Err(LocalReplayExecutorError::InvalidRequest)
            }

            fn authenticate(
                &mut self,
                input: &ReplayInput,
                before: &RuntimeState,
                position: ReplayPosition,
            ) -> Result<(), Self::Error> {
                self.authenticated = None;
                let ReplayOperation::CleanManage {
                    request: request @ crate::agent_sdk::ManagementRequest::Create(descriptor),
                    authority,
                    observed_slot,
                } = &input.operation
                else {
                    return Err(LocalReplayExecutorError::InvalidRequest);
                };
                let expected = self
                    .admitted
                    .binding(input.runtime.space, input.runtime.agent)
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                if !before.is_empty()
                    || position != ReplayPosition::Genesis
                    || input.runtime != expected
                    || descriptor.validate().is_err()
                    || descriptor.identity.profile != self.profile
                    || (self.profile == crate::agent_sdk::AgentProfile::Local
                        && descriptor.replicas.len() != 1)
                    || (self.profile == crate::agent_sdk::AgentProfile::Shared
                        && !super::replay::external_shared_descriptor_supported(descriptor))
                    || !descriptor.replicas.iter().any(|replica| {
                        replica.node.0 == self.replica.node.0
                            && replica.principal.0 == self.replica.principal.0
                            && replica.role == crate::agent_sdk::ReplicaRole::Voter
                    })
                    || descriptor.identity.runtime_deployment != self.admitted.deployment()
                    || descriptor.identity.runtime_program != self.admitted.program()
                    || descriptor.identity.runtime_producer
                        != self.admitted.manifest().signing.producer
                    || descriptor.runtime_package != *self.admitted.package_ref()
                    || descriptor.runtime_contract != self.admitted.manifest().contract
                    || descriptor.capabilities != self.admitted.manifest().capabilities
                {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                super::driver::verify_clean_management_receipt(
                    descriptor,
                    request,
                    authority,
                    *observed_slot,
                    true,
                )
                .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
                self.authenticated = Some(input.id());
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
        }
        impl ExternalGenesisExecutor for Executor {
            fn execute_external_create(
                &mut self,
                create: &ReplayInput,
                replica: AgentReplica,
            ) -> Result<super::state_block_pvm::ExternalCreateExecution, Self::Error> {
                if self.authenticated.take() != Some(create.id()) || replica != self.replica {
                    return Err(LocalReplayExecutorError::InvalidAuthority);
                }
                let sdk_replica = crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId(replica.node.0),
                    principal: crate::agent_sdk::PrincipalId(replica.principal.0),
                    role: match replica.role {
                        super::ReplicaRole::Voter => crate::agent_sdk::ReplicaRole::Voter,
                        super::ReplicaRole::Observer => crate::agent_sdk::ReplicaRole::Observer,
                    },
                };
                super::state_block_pvm::MultiLaneStateBlockHost {
                    store: &NoGenesisBlocks,
                    budget: &mut ReadBudget::new(0, 0),
                }
                .execute_admitted_create(
                    &self.admitted,
                    create,
                    sdk_replica,
                    DEFAULT_MANAGEMENT_GAS,
                )
                .map_err(|error| match error {
                    super::state_block_pvm::BlockPvmError::Backend => {
                        LocalReplayExecutorError::RuntimeBackend
                    }
                    super::state_block_pvm::BlockPvmError::Exit { reason, pc } => {
                        LocalReplayExecutorError::RuntimeExit { reason, pc }
                    }
                    super::state_block_pvm::BlockPvmError::InvalidRequest
                    | super::state_block_pvm::BlockPvmError::ProgramMismatch => {
                        LocalReplayExecutorError::InvalidRequest
                    }
                    _ => LocalReplayExecutorError::RuntimeOutput,
                })
            }
        }

        if replica.node != expected_node || replica.role != super::ReplicaRole::Voter {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let package_ref = create.runtime.package.clone();
        let package = supplied
            .load_catalog(&package_ref)?
            .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(package_ref.clone()))?;
        let admitted = super::package_admission::admit_state_runtime_package(&package)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(package_ref.clone()))?;
        let mut executor = Executor {
            admitted,
            replica,
            profile,
            authenticated: None,
        };
        let prepared = ReplayPreparedExternalGenesis::prepare(create, replica, &mut executor)
            .map_err(lift_prepared_genesis_error)?;
        if supplied.blobs.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                supplied
                    .blobs
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(prepared)
    }

    /// Re-execute one independently finalized Shared provision for the exact
    /// selected local replica and mint the only seal accepted by Shared
    /// journal initialization. Provider bytes and finality remain separate:
    /// the caller must first obtain `verified` from the configured live
    /// system-Agent verifier.
    pub(crate) fn prepare_shared_genesis(
        verified: &VerifiedAgentGenesisProvision,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplaySealedSharedGenesis, LocalJournalDriverError> {
        let provision = verified.provision();
        let prepared = Self::prepare_shared_genesis_candidate(
            provision.proposal().create().clone(),
            replica,
            provision.replicas(),
            catalog,
            trust,
            merge,
        )?;
        ReplaySealedSharedGenesis::from_prepared_verified(verified, prepared).map_err(|error| {
            LocalJournalDriverError::Replay(
                error
                    .map_source(|never| match never {})
                    .map_executor(|never| match never {}),
            )
        })
    }

    /// Seal one independently finalized Shared provision for an explicit
    /// joiner: a local replica outside the genesis committee. Create is
    /// re-executed exactly as for a member (its result does not depend on the
    /// local replica); only the local storage identity is the joiner's.
    pub(crate) fn prepare_shared_joiner_genesis(
        verified: &VerifiedAgentGenesisProvision,
        joiner: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplaySealedSharedGenesis, LocalJournalDriverError> {
        let provision = verified.provision();
        let committee = provision.replicas();
        let Some(member) = committee.members().first().map(|member| member.replica()) else {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        };
        if joiner.node != merge.node()
            || committee.validate().is_err()
            || committee.member_by_node(joiner.node).is_some()
            || !super::replay::validates_shared_create_committee(
                provision.proposal().create(),
                committee,
            )
        {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let expected_catalog = supplied.blobs.clone();
        let mut executor = StandardLocalReplayExecutor::new_shared(
            supplied,
            trust,
            merge,
            vec![committee.clone()],
        );
        executor.admit_shared_joiner();
        let prepared = ReplayPreparedGenesis::prepare(
            provision.proposal().create().clone(),
            member,
            &mut executor,
        )
        .map_err(lift_prepared_genesis_error)?;
        if expected_catalog.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                expected_catalog
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        ReplaySealedSharedGenesis::joiner_from_prepared_verified(verified, prepared, joiner)
            .map_err(|error| {
                LocalJournalDriverError::Replay(
                    error
                        .map_source(|never| match never {})
                        .map_executor(|never| match never {}),
                )
            })
    }

    /// Execute an ordinary Shared Create before genesis certification. The
    /// returned opaque candidate can derive a proposal but cannot initialize
    /// a journal: only independent finality verification can mint that seal.
    pub(crate) fn prepare_shared_genesis_candidate(
        create: ReplayInput,
        replica: AgentReplica,
        committee: &AgentReplicaCommittee,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplayPreparedGenesis, LocalJournalDriverError> {
        if replica.node != merge.node()
            || committee.validate().is_err()
            || committee
                .member_by_node(replica.node)
                .map(|member| member.replica())
                != Some(replica)
            || !super::replay::validates_shared_create_committee(&create, committee)
        {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let expected_catalog = supplied.blobs.clone();
        let mut executor = StandardLocalReplayExecutor::new_shared(
            supplied,
            trust,
            merge,
            vec![committee.clone()],
        );
        let prepared = ReplayPreparedGenesis::prepare(create, replica, &mut executor)
            .map_err(lift_prepared_genesis_error)?;
        if expected_catalog.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                expected_catalog
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(prepared)
    }

    fn validate_create_state(
        post_create: &RuntimeState,
        binding: &RuntimeBinding,
        replica: AgentReplica,
        resolver: SuppliedCatalogBlobResolver,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(), LocalJournalDriverError> {
        let decoded = decode_standard_runtime_state(post_create)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = decoded
            .config
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let executor =
            StandardLocalReplayExecutor::new(resolver, Arc::clone(trust), Arc::clone(merge));
        executor.validate_local_config(config, binding)?;
        if config.replicas.first().copied() != Some(replica) {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        Ok(())
    }

    /// Validate every semantic input to genesis installation against only the
    /// sealed post-Create state and the caller's immutable catalog snapshot.
    /// This function is intentionally store-free so a failure cannot leave a
    /// genesis, heads envelope, or catalog orphan behind.
    fn preflight_create(
        sealed: &ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(), LocalJournalDriverError> {
        if sealed.replica().node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let resolver = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        if resolver.blobs.len() != sealed.artifacts().artifacts.len()
            || sealed.artifacts().artifacts.iter().any(|reference| {
                resolver
                    .blobs
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }

        Self::validate_create_state(
            sealed.post_create(),
            sealed.genesis().runtime(),
            sealed.replica(),
            resolver,
            trust,
            merge,
        )
    }

    fn preflight_local_create(
        sealed: &ReplaySealedLocalGenesis,
        catalog: &[RuntimeBlob],
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(), LocalJournalDriverError> {
        sealed.validate().map_err(|error| {
            LocalJournalDriverError::Replay(
                error
                    .map_source(|never| match never {})
                    .map_executor(|never| match never {}),
            )
        })?;
        if sealed.replica().node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let resolver = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        if resolver.blobs.len() != sealed.artifacts().artifacts.len()
            || sealed.artifacts().artifacts.iter().any(|reference| {
                resolver
                    .blobs
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        if matches!(
            sealed.genesis().create.operation,
            ReplayOperation::CleanManage {
                request: crate::agent_sdk::ManagementRequest::Create(_),
                ..
            }
        ) {
            if sealed.post_create().is_empty() {
                return Err(LocalReplayExecutorError::InvalidState.into());
            }
            let mut executor =
                StandardLocalReplayExecutor::new(resolver, Arc::clone(trust), Arc::clone(merge));
            executor.seed_genesis(sealed.genesis())?;
            executor.trusted_current_clean_descriptor(sealed.genesis().runtime())?;
            Ok(())
        } else {
            Self::validate_create_state(
                sealed.post_create(),
                sealed.genesis().runtime(),
                sealed.replica(),
                resolver,
                trust,
                merge,
            )
        }
    }

    /// Initialize only from a root/QC-admitted, exactly executed genesis.
    /// The complete catalog closure is made durable before genesis and heads
    /// become visible.
    #[cfg(test)]
    pub(crate) fn create(
        mut store: S,
        sealed: ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::preflight_create(&sealed, catalog, &trust, &merge)?;
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize(&sealed)?;
        let resolver = store.catalog_blob_resolver()?;
        let executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let core = LocalJournalCore::open(store, executor)?;
        let driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
        driver.validate_opened(Some(sealed.replica()))?;
        Ok(driver)
    }

    /// Open a store whose filesystem/root adapter has already reverified the
    /// sealed genesis admission. The only state cache is rebuilt from typed
    /// journal closure and exact replay.
    pub(crate) fn open(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(store, trust, merge, None)
    }

    /// Open with the separate durable producer/journal coordinator required
    /// to replay an Attested suffix. The provider is installed before the
    /// first historical transition is materialized, so reopen can recover the
    /// exact published tuple without executing the application runtime.
    pub(crate) fn open_with_attested_transition_provider(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Box<dyn AttestedReplayTransitionProvider>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(store, trust, merge, Some(provider))
    }

    fn open_with_optional_attested_transition_provider(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Option<Box<dyn AttestedReplayTransitionProvider>>,
    ) -> Result<Self, LocalJournalDriverError> {
        let resolver = store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        if let Some(provider) = provider {
            executor.replace_attested_transition_provider(provider);
        }
        let core = LocalJournalCore::open(store, executor)?;
        let driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
        driver.validate_opened(None)?;
        Ok(driver)
    }

    fn validate_opened(
        &self,
        sealed_replica: Option<AgentReplica>,
    ) -> Result<(), LocalJournalDriverError> {
        if let Some(descriptor) = self.core.executor.seeded_clean_descriptor() {
            let [replica] = descriptor.replicas.as_slice() else {
                return Err(LocalReplayExecutorError::WrongReplica.into());
            };
            let role = match replica.role {
                crate::agent_sdk::ReplicaRole::Voter => super::ReplicaRole::Voter,
                crate::agent_sdk::ReplicaRole::Observer => super::ReplicaRole::Observer,
            };
            let replica = AgentReplica {
                node: NodeId(replica.node.0),
                principal: crate::service::PrincipalId(replica.principal.0),
                role,
            };
            if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Local
                || replica.node != self.core.materialization.heads().node
                || sealed_replica.is_some_and(|sealed| sealed != replica)
            {
                return Err(LocalReplayExecutorError::WrongReplica.into());
            }
            self.core
                .executor
                .trusted_current_clean_descriptor(self.core.materialization.runtime())?;
            return Ok(());
        }
        let state = decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = state
            .config
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        self.core
            .executor
            .validate_local_config(config, self.core.materialization.runtime())?;
        let replica = config.replicas[0];
        if replica.node != self.core.materialization.heads().node
            || sealed_replica.is_some_and(|sealed| sealed != replica)
        {
            return Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::WrongReplica,
            ));
        }
        Ok(())
    }

    /// Current authenticated Standard configuration.
    pub(crate) fn config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        self.trusted_current_config()
    }

    pub(crate) fn identity(&self) -> Result<AgentIdentity, LocalJournalDriverError> {
        if self.core.executor.seeded_clean_descriptor().is_some() {
            let identity = self
                .core
                .executor
                .trusted_current_clean_descriptor(self.core.materialization.runtime())?
                .identity;
            return Ok(AgentIdentity {
                space: crate::service::SpaceId(identity.space.0),
                agent: crate::service::AgentId(identity.agent.0),
                owner: crate::service::PrincipalId(identity.owner.0),
                profile: match identity.profile {
                    crate::agent_sdk::AgentProfile::Local => AgentProfile::Local,
                    crate::agent_sdk::AgentProfile::Shared => AgentProfile::Shared,
                    crate::agent_sdk::AgentProfile::Private => AgentProfile::Private,
                },
                runtime_deployment: DeploymentId(identity.runtime_deployment.0),
                runtime_program: ProgramId(identity.runtime_program.0),
                runtime_producer: ProducerId(identity.runtime_producer.0),
                transition_producer: ProducerId(identity.transition_producer.0),
            });
        }
        Ok(self.config()?.identity)
    }

    /// Revision of the currently materialized durable heads publication.
    pub(crate) fn publication_revision(&self) -> u64 {
        self.core.materialization.heads().publication_revision
    }

    fn runtime_blob(bytes: Vec<u8>) -> RuntimeBlob {
        RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        }
    }

    fn actor_package_catalog(package: &Package) -> Vec<RuntimeBlob> {
        vec![
            Self::runtime_blob(package.encode()),
            Self::runtime_blob(package.agent_schema.clone()),
            Self::runtime_blob(package.role_policies.clone()),
        ]
    }

    fn runtime_package_catalog(package: &Package) -> Vec<RuntimeBlob> {
        vec![Self::runtime_blob(package.encode())]
    }

    fn clean_management_catalog(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<Vec<RuntimeBlob>, LocalJournalDriverError> {
        if matches!(artifacts, SdkManagementArtifacts::None)
            && matches!(
                request,
                crate::agent_sdk::ManagementRequest::Install(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeActor(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_)
            )
        {
            self.core
                .executor
                .validate_clean_management_artifacts(descriptor, request)?;
            return Ok(Vec::new());
        }
        super::driver::validate_sdk_management_artifacts(descriptor, request, artifacts)
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let mut catalog = Vec::new();
        match (request, artifacts) {
            (
                crate::agent_sdk::ManagementRequest::Install(install),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(Self::runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(Self::runtime_blob(
                    package.state_lane_schema_bytes().to_vec(),
                ));
                catalog.push(Self::runtime_blob(package.method_policy_bytes().to_vec()));
                if let Some(data) = &install.installation_data {
                    catalog.push(Self::runtime_blob(data.bytes.clone()));
                }
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeActor(_),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(Self::runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(Self::runtime_blob(
                    package.state_lane_schema_bytes().to_vec(),
                ));
                catalog.push(Self::runtime_blob(package.method_policy_bytes().to_vec()));
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeRuntime(_),
                SdkManagementArtifacts::Runtime(package),
            ) => catalog.push(Self::runtime_blob(package.exact_bytes().to_vec())),
            (_, SdkManagementArtifacts::None) => {}
            _ => return Err(LocalReplayExecutorError::InvalidRequest.into()),
        }
        catalog.sort_by_key(|blob| blob.reference.hash);
        for pair in catalog.windows(2) {
            if pair[0].reference.hash == pair[1].reference.hash && pair[0] != pair[1] {
                return Err(LocalReplayExecutorError::InvalidRequest.into());
            }
        }
        catalog.dedup();
        Ok(catalog)
    }

    fn lifecycle_operation(
        &self,
        request: LifecycleRequest,
        catalog: Vec<RuntimeBlob>,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if matches!(
            request,
            LifecycleRequest::Create(_)
                | LifecycleRequest::Inspect { .. }
                | LifecycleRequest::AcknowledgeInvocation { .. }
                | LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
                | LifecycleRequest::Authorized { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let config = self.trusted_current_config()?;
        self.core
            .executor
            .validate_lifecycle_operation_catalog(&config, &request, &catalog)?;
        Ok(LocalLifecycleOperation { request, catalog })
    }

    /// Construct an exact actor-install request and its complete catalog.
    pub(crate) fn actor_install_operation(
        &self,
        installation_id: crate::service::InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if installation_id == crate::service::InstallationId::ZERO
            || registry_reservation == Hash::ZERO
            || name.is_empty()
            || name.len() > crate::service::MAX_ACTOR_NAME_BYTES
            || parent == Some(ActorId::ZERO)
        {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        if installation_data
            .as_ref()
            .is_some_and(|bytes| bytes.len() > super::MAX_INSTALLATION_DATA_BYTES)
            || !package
                .accepts_installation_data(installation_data.as_deref())
                .map_err(LocalReplayExecutorError::Package)?
        {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let schema = crate::agent_sdk::schema::decode(&package.agent_schema)
            .map_err(|_| LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts))?;
        let config = self.trusted_current_config()?;
        let actor = match parent {
            Some(parent) => ActorId::owned_child(parent, &name),
            None => ActorId::top_level(config.identity.agent, &name),
        };
        let mut catalog = Self::actor_package_catalog(package);
        let installation_data = installation_data.map(|bytes| super::InstallationData {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        if let Some(data) = &installation_data {
            catalog.push(RuntimeBlob {
                reference: data.reference.clone(),
                bytes: data.bytes.clone(),
            });
        }
        let package_reference = catalog[0].reference.clone();
        let schema_reference = catalog[1].reference.clone();
        let policies_reference = catalog[2].reference.clone();
        let state_layout = Hash(
            schema
                .state_layout_hash()
                .map_err(|_| {
                    LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts)
                })?
                .0,
        );
        let constructor_abi = package
            .constructor_abi()
            .map_err(LocalReplayExecutorError::Package)?;
        self.lifecycle_operation(
            LifecycleRequest::Install(InstallActor {
                installation_id,
                registry_reservation,
                entry: ActorEntry {
                    actor,
                    name,
                    parent,
                    deployment: package.deployment_id(),
                    program: package.manifest.program,
                    package: package_reference.clone(),
                    agent_schema: schema_reference.clone(),
                    role_policies: policies_reference.clone(),
                    constructor_abi,
                    installation_data: installation_data
                        .as_ref()
                        .map(|data| data.reference.clone()),
                    state_layout,
                    lanes: requirements.lanes,
                    suspended: false,
                },
                producer: package.deployment_signature.producer,
                package: package_reference,
                agent_schema: schema_reference,
                role_policies: policies_reference,
                constructor_abi,
                installation_data,
                state_layout,
                contract,
                requirements,
            }),
            catalog,
        )
    }

    /// Construct an exact in-place actor-upgrade request and catalog.
    pub(crate) fn actor_upgrade_operation(
        &self,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if actor == ActorId::ZERO || from_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let schema = crate::agent_sdk::schema::decode(&package.agent_schema)
            .map_err(|_| LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts))?;
        let constructor_abi = package
            .constructor_abi()
            .map_err(LocalReplayExecutorError::Package)?;
        match self.inspect_actor(actor) {
            Ok(record) if record.entry.deployment == from_deployment => {
                if !package
                    .accepts_installation_data_reference(record.entry.installation_data.as_ref())
                    .map_err(LocalReplayExecutorError::Package)?
                {
                    return Err(LocalReplayExecutorError::InvalidRequest.into());
                }
                if record.entry.constructor_abi != constructor_abi {
                    return Err(LocalReplayExecutorError::InvalidRequest.into());
                }
            }
            Ok(_) | Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound)) => {}
            Err(error) => return Err(error),
        }
        let catalog = Self::actor_package_catalog(package);
        self.lifecycle_operation(
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment,
                to_deployment: package.deployment_id(),
                to_program: package.manifest.program,
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                state_layout: Hash(
                    schema
                        .state_layout_hash()
                        .map_err(|_| {
                            LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts)
                        })?
                        .0,
                ),
                contract,
                requirements,
            }),
            catalog,
        )
    }

    pub(crate) fn actor_suspend_operation(
        &self,
        actor: ActorId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        let expected_deployment = self.inspect_actor(actor)?.entry.deployment;
        self.lifecycle_operation(
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    pub(crate) fn actor_resume_operation(
        &self,
        actor: ActorId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        let expected_deployment = self.inspect_actor(actor)?.entry.deployment;
        self.lifecycle_operation(
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    pub(crate) fn actor_remove_operation(
        &self,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if actor == ActorId::ZERO || expected_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        self.lifecycle_operation(
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    /// Construct a runtime upgrade against the complete signed target
    /// descriptor, not the current runtime's package-policy descriptor.
    pub(crate) fn runtime_upgrade_operation(
        &self,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if from_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let catalog = Self::runtime_package_catalog(package);
        self.lifecycle_operation(
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment: package.deployment_id(),
                to_program: package.manifest.program,
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                contract,
                capabilities,
            },
            catalog,
        )
    }

    fn rollback_staged_catalog(
        &mut self,
        staged: StagedCatalog,
    ) -> Result<(), LocalJournalDriverError> {
        // A publication error can occur after its durable CAS. Authenticate
        // the physical head before deleting anything; an unreadable or moved
        // head leaves the bytes for normal reopen reconciliation.
        let Ok(Some(current)) = self.core.store.heads() else {
            return Ok(());
        };
        if current.id() != staged.predecessor {
            return Ok(());
        }
        for token in staged.created.into_iter().rev() {
            self.core.store.rollback_catalog_blob(token)?;
        }
        let resolver = self.core.store.catalog_blob_resolver()?;
        self.core.executor.replace_resolver(resolver);
        Ok(())
    }

    fn stage_catalog(
        &mut self,
        catalog: &[RuntimeBlob],
    ) -> Result<StagedCatalog, LocalJournalDriverError> {
        let mut staged = BTreeMap::new();
        for blob in catalog {
            if !blob.reference.matches(&blob.bytes) {
                return Err(
                    LocalReplayExecutorError::InvalidArtifact(blob.reference.clone()).into(),
                );
            }
            match staged.insert(
                (blob.reference.hash, blob.reference.len),
                blob.bytes.as_slice(),
            ) {
                Some(existing) if existing != blob.bytes.as_slice() => {
                    return Err(
                        LocalReplayExecutorError::InvalidArtifact(blob.reference.clone()).into(),
                    );
                }
                _ => {}
            }
        }
        let predecessor = self.core.materialization.heads().id();
        let mut created = Vec::new();
        for blob in catalog {
            match self
                .core
                .store
                .stage_catalog_blob(predecessor, &blob.reference, &blob.bytes)
            {
                Ok(Some(token)) => {
                    created.push(token);
                    #[cfg(test)]
                    if self.lifecycle_fault == Some(TestLifecycleFault::CatalogPutAfterFirst) {
                        self.lifecycle_fault = None;
                        self.rollback_staged_catalog(StagedCatalog {
                            predecessor,
                            created,
                        })?;
                        return Err(JournalStoreError::Unavailable.into());
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.rollback_staged_catalog(StagedCatalog {
                        predecessor,
                        created,
                    })?;
                    return Err(error.into());
                }
            }
        }
        // Memory snapshots are copy-on-write and file snapshots own pinned
        // descriptors. Refresh only after every requested byte is durable.
        let resolver = match self.core.store.catalog_blob_resolver() {
            Ok(resolver) => resolver,
            Err(error) => {
                self.rollback_staged_catalog(StagedCatalog {
                    predecessor,
                    created,
                })?;
                return Err(error.into());
            }
        };
        self.core.executor.replace_resolver(resolver);
        Ok(StagedCatalog {
            predecessor,
            created,
        })
    }

    fn persist_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, LocalJournalDriverError> {
        self.core.persist_current_merge_seal()
    }

    /// Execute and journal one exact clean SDK management mutation. An
    /// unchanged denial is nondurable. A result is retained without another
    /// slot only when a bounded Ordered-suffix lookup proves the exact request
    /// and receipt were already durable; a fresh successful no-op is still
    /// ordered.
    pub(crate) fn clean_manage(
        &mut self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<LocalCleanManagementResult, LocalJournalDriverError> {
        if matches!(
            request,
            crate::agent_sdk::ManagementRequest::Create(_)
                | crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::InspectManagementHistory
                | crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
                | crate::agent_sdk::ManagementRequest::PrivateControl { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let runtime = self.core.materialization.runtime().clone();
        let descriptor = self
            .core
            .executor
            .trusted_current_clean_descriptor(&runtime)?;
        let catalog = self.clean_management_catalog(&descriptor, &request, artifacts)?;
        let staged = self.stage_catalog(&catalog)?;
        let mut published = false;
        let result = (|| -> Result<LocalCleanManagementResult, LocalJournalDriverError> {
            if let Some(input) = recent_clean_management_input(
                &self.core.store,
                &self.core.materialization,
                &request,
                &authority,
            )? {
                let outcome = self
                    .core
                    .executor
                    .clean_management_result(input)
                    .ok_or(LocalJournalDriverError::InvalidResult)?;
                return Ok(LocalCleanManagementResult {
                    outcome,
                    finalized_merge_invocations: Vec::new(),
                });
            }
            let observed_slot = self.core.executor.current_logical_slot()?;
            let input = ReplayInput {
                runtime: runtime.clone(),
                operation: ReplayOperation::CleanManage {
                    request: request.clone(),
                    authority: authority.clone(),
                    observed_slot,
                },
            };
            input
                .validate()
                .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
            let preview = self.core.executor.preview_clean_management(
                &runtime,
                self.core.materialization.state(),
                &request,
                &authority,
                observed_slot,
                true,
            )?;
            let preview_state = RuntimeState {
                control: preview.state.control.clone(),
                linear: preview.state.linear.clone(),
                merge: preview.state.merge.clone(),
                local: preview.state.local.clone(),
            };
            if preview_state == *self.core.materialization.state()
                && matches!(
                    &preview.outcome,
                    crate::agent_sdk::RuntimeOutcome::Management(Err(_))
                )
            {
                return Ok(LocalCleanManagementResult {
                    outcome: preview.outcome,
                    finalized_merge_invocations: Vec::new(),
                });
            }
            let input_id = input.id();
            let merge_seal = self.persist_merge_seal()?;
            let heads = self.core.materialization.heads();
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index: heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(LocalJournalDriverError::InvalidResult)?,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: Some(merge_seal),
                input,
            };
            let executions = self.core.publish_ordered(&entry)?.executions;
            published = true;
            if executions
                .iter()
                .any(|execution| !execution.products().is_empty())
            {
                return Err(LocalJournalDriverError::InvalidResult);
            }
            let outcome = executions
                .iter()
                .find(|execution| execution.input() == input_id)
                .and_then(|execution| execution.clean_management_result())
                .cloned()
                .map(crate::agent_sdk::RuntimeOutcome::Management)
                .ok_or(LocalJournalDriverError::InvalidResult)?;
            // Publication carries the authoritative synchronous result. The
            // executor cache remains only a bounded retry/transport handoff.
            let _ = self.core.executor.take_clean_invocation_result(input_id);
            if outcome != preview.outcome {
                return Err(LocalJournalDriverError::InvalidResult);
            }
            let finalized_merge_invocations = executions
                .into_iter()
                .filter_map(|execution| {
                    execution
                        .result()
                        .cloned()
                        .map(|result| FinalizedMergeInvocation {
                            input: execution.input(),
                            position: execution.position(),
                            result,
                        })
                })
                .collect();
            Ok(LocalCleanManagementResult {
                outcome,
                finalized_merge_invocations,
            })
        })();
        if !published {
            self.rollback_staged_catalog(staged)?;
        }
        result
    }

    /// Seal and apply one authority-signed lifecycle mutation. The trusted
    /// logical slot is sampled here and cannot be supplied by the caller.
    /// Catalog bytes for an install or upgrade are persisted before the
    /// ordered publication can name them.
    pub(crate) fn lifecycle(
        &mut self,
        receipt: AgentAuthorityReceipt,
        request: LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<LocalLifecycleResult, LocalJournalDriverError> {
        if matches!(
            request,
            LifecycleRequest::Create(_)
                | LifecycleRequest::Inspect { .. }
                | LifecycleRequest::AcknowledgeInvocation { .. }
                | LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
                | LifecycleRequest::Authorized { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let config = self.trusted_current_config()?;
        let request = seal_lifecycle_request(self.core.executor.trust.as_ref(), receipt, request)?;
        self.core
            .executor
            .authenticate_management(&config, &request)?;
        let preflight =
            preflight_lifecycle_transition(self.core.materialization.state(), &request)?;
        if preflight.unchanged {
            return Ok(LocalLifecycleResult {
                result: preflight.result,
                finalized_merge_invocations: Vec::new(),
            });
        }
        let staged = if retained_lifecycle_disposition(self.core.materialization.state(), &request)?
            .is_none()
            && preflight.result.is_ok()
        {
            self.core.executor.validate_lifecycle_catalog(
                &config,
                self.core.materialization.state(),
                &request,
                catalog,
            )?;
            validate_prospective_artifact_closure(
                self.core.materialization.heads().genesis,
                &preflight.successor,
            )?;
            Some(self.stage_catalog(catalog)?)
        } else {
            None
        };
        let result = (|| -> Result<LocalLifecycleResult, LocalJournalDriverError> {
            #[cfg(test)]
            if self.lifecycle_fault == Some(TestLifecycleFault::BeforeMergeSeal) {
                self.lifecycle_fault = None;
                return Err(JournalStoreError::Unavailable.into());
            }
            let input = ReplayInput {
                runtime: self.core.materialization.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: request.clone(),
                },
            };
            let input_id = input.id();
            let merge_seal = self.persist_merge_seal()?;
            let heads = self.core.materialization.heads();
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index: heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(LocalJournalDriverError::InvalidResult)?,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: Some(merge_seal),
                input,
            };
            #[cfg(test)]
            if self.lifecycle_fault == Some(TestLifecycleFault::BeforeOrderedPublish) {
                self.lifecycle_fault = None;
                return Err(JournalStoreError::Unavailable.into());
            }
            self.core.executor.clear_management_result();
            let executions = self.core.publish_ordered(&entry)?.executions;
            let finalized_merge_invocations = executions
                .iter()
                .filter_map(|execution| {
                    execution
                        .result()
                        .cloned()
                        .map(|result| FinalizedMergeInvocation {
                            input: execution.input(),
                            position: execution.position(),
                            result,
                        })
                })
                .collect::<Vec<_>>();
            if executions
                .iter()
                .any(|execution| !execution.products().is_empty())
            {
                return Err(LocalJournalDriverError::InvalidResult);
            }
            let result = match self.core.executor.take_management_result(input_id) {
                Some(result) => result,
                None => self.lifecycle_result(&request)?,
            };
            Ok(LocalLifecycleResult {
                result,
                finalized_merge_invocations,
            })
        })();
        if result.is_err()
            && let Some(staged) = staged
        {
            self.rollback_staged_catalog(staged)?;
        }
        result
    }

    fn lifecycle_result(
        &self,
        request: &LifecycleRequest,
    ) -> Result<Result<LifecycleReply, LifecycleError>, LocalJournalDriverError> {
        retained_lifecycle_disposition(self.core.materialization.state(), request)
            .map_err(LocalJournalDriverError::Executor)?
            .ok_or(LocalJournalDriverError::InvalidResult)
    }

    /// Finalize the currently admitted Merge frontier without inventing a
    /// guest lifecycle request. This is an ordered maintenance unit; replay
    /// itself synthesizes and validates the byte-identical no-op transition.
    pub(crate) fn finalize_merge(
        &mut self,
    ) -> Result<Vec<FinalizedMergeInvocation>, LocalJournalDriverError> {
        // SealMerge is maintenance rather than a signed guest operation, but
        // it must still fail closed against the live space-authority and
        // runtime-package trust roots before writing its prospective closure.
        self.trusted_current_config()?;
        let merge_seal = self.persist_merge_seal()?;
        let heads = self.core.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation: ReplayOperation::SealMerge,
        };
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(LocalJournalDriverError::InvalidResult)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input,
        };
        let executions = self.core.publish_ordered(&entry)?.executions;
        if executions
            .iter()
            .any(|execution| !execution.products().is_empty())
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(executions
            .into_iter()
            .filter_map(|execution| {
                execution
                    .result()
                    .cloned()
                    .map(|result| FinalizedMergeInvocation {
                        input: execution.input(),
                        position: execution.position(),
                        result,
                    })
            })
            .collect())
    }

    fn current_config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalJournalDriverError::InvalidResult)?
            .config
            .ok_or(LocalJournalDriverError::InvalidResult)
    }

    fn trusted_current_config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        let config = self.current_config()?;
        self.core
            .executor
            .validate_local_config(&config, self.core.materialization.runtime())?;
        Ok(config)
    }

    fn validate_invocation_capability(
        config: &AgentConfig,
        input: &ReplayInput,
    ) -> Result<(), LocalJournalDriverError> {
        let (invocation, authority) = match &input.operation {
            ReplayOperation::Invoke {
                invocation,
                authority,
                ..
            }
            | ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => (invocation, authority),
            ReplayOperation::Management { .. }
            | ReplayOperation::CleanManage { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::SealMerge => {
                return Err(LocalReplayExecutorError::InvalidRequest.into());
            }
        };
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        Ok(())
    }

    fn merge_event(&self, input: ReplayInput) -> Result<MergeEvent, LocalJournalDriverError> {
        let heads = self.core.materialization.heads();
        let frontier = self
            .core
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(LocalJournalDriverError::InvalidResult)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        let causal_height = if frontier.events.is_empty() {
            1
        } else {
            let mut maximum = 0_u64;
            for parent in &frontier.events {
                let event = self
                    .core
                    .store
                    .get::<MergeEvent>(*parent)?
                    .ok_or(LocalJournalDriverError::InvalidResult)?;
                if event.id() != *parent || event.genesis != heads.genesis {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                maximum = maximum.max(event.causal_height);
            }
            maximum
                .checked_add(1)
                .ok_or(LocalJournalDriverError::InvalidResult)?
        };
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: heads.node,
            committee: None,
            ordered_base: self.core.materialization.ordered_base(),
            causal_height,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        if !self.core.executor.merge.sign_event(&mut event) {
            return Err(LocalReplayExecutorError::InvalidAuthority.into());
        }
        if event.validate().is_err()
            || event.author != self.core.executor.merge.node()
            || !self.core.executor.merge.verify_event(&event)
        {
            return Err(LocalReplayExecutorError::InvalidAuthority.into());
        }
        Ok(event)
    }

    fn authoritative_publication_position(
        input: ReplayInputId,
        proposed: ReplayPosition,
        publication: LocalCorePublication,
    ) -> Result<(ReplayPosition, Vec<ReplayExecutionResult>, bool), LocalJournalDriverError> {
        let LocalCorePublication {
            executions,
            committed,
            published_position,
        } = publication;
        let (position, already_committed) = match committed {
            Some(committed) => {
                if committed.input() != input || published_position.is_some() {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                (committed.position(), true)
            }
            None => (
                published_position.ok_or(LocalJournalDriverError::InvalidResult)?,
                false,
            ),
        };
        let same_scope = matches!(
            (proposed, position),
            (
                ReplayPosition::Ordered { .. },
                ReplayPosition::Ordered { .. }
            ) | (ReplayPosition::Local { .. }, ReplayPosition::Local { .. })
                | (ReplayPosition::Merge { .. }, ReplayPosition::Merge { .. })
        );
        if !same_scope || already_committed && !executions.is_empty() {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok((position, executions, already_committed))
    }

    fn is_checkpoint_only_delta(
        before: &ReplayMaterialization,
        after: &ReplayMaterialization,
    ) -> bool {
        let old = before.heads();
        let new = after.heads();
        Self::is_canonical_checkpoint_state_delta(before.state(), after.state())
            && old.genesis == new.genesis
            && old.admission == new.admission
            && old.node == new.node
            && old.runtime == new.runtime
            && old.ordered_head == new.ordered_head
            && old.ordered_index == new.ordered_index
            && old.merge_frontier == new.merge_frontier
            && old.merge_fence == new.merge_fence
            && old.merge_seal == new.merge_seal
            && old.ordered_invocations == new.ordered_invocations
            && old.merge_invocations == new.merge_invocations
            && old.local_invocations == new.local_invocations
            && old.local_head == new.local_head
            && old.local_revision == new.local_revision
            && new.checkpoint.is_some()
            && new.publication_revision == old.publication_revision.checked_add(1).unwrap_or(0)
            && new.previous == Some(before.heads_id())
    }

    fn is_canonical_checkpoint_state_delta(before: &RuntimeState, after: &RuntimeState) -> bool {
        let Some(mut runtime) = decode_standard_runtime_state(before)
            .ok()
            .and_then(|decoded| StandardAgentRuntime::restore(decoded).ok())
        else {
            return false;
        };
        runtime.compact_historical_lane_entries_for_checkpoint();
        super::wire::encode_standard_runtime_state(&runtime.snapshot()) == *after
    }

    fn publish_invocation_input(
        &mut self,
        input: ReplayInput,
    ) -> Result<
        (
            ReplayPosition,
            Vec<ReplayExecutionResult>,
            Option<PendingMergeReceipt>,
        ),
        LocalJournalDriverError,
    > {
        let scope = match &input.operation {
            ReplayOperation::Invoke { invocation, .. }
            | ReplayOperation::Acknowledge { invocation, .. } => invocation.mode.invocation_scope(),
            // Clean InvocationWork has a separate lossless Shared-driver
            // admission path. Never route it through this legacy
            // ActorInvocation/result projection surface.
            ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::CleanResume { .. }
            | ReplayOperation::CleanAcknowledge { .. }
            | ReplayOperation::CleanManage { .. }
            | ReplayOperation::Management { .. }
            | ReplayOperation::SealMerge => {
                return Err(LocalJournalDriverError::InvalidResult);
            }
        };
        match scope {
            InvocationScope::Ordered => {
                let input_id = input.id();
                let heads = self.core.materialization.heads();
                let entry = OrderedEntry {
                    genesis: heads.genesis,
                    index: heads
                        .ordered_index
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input,
                };
                let position = ReplayPosition::Ordered {
                    id: entry.id(),
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: None,
                };
                let publication = self.core.publish_ordered(&entry)?;
                let (position, executions, _) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                Ok((position, executions, None))
            }
            InvocationScope::Local => {
                let input_id = input.id();
                let heads = self.core.materialization.heads();
                let entry = LocalEntry {
                    genesis: heads.genesis,
                    node: heads.node,
                    revision: heads
                        .local_revision
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.local_head,
                    ordered_base: self.core.materialization.ordered_base(),
                    merge_frontier: heads.merge_frontier,
                    input,
                };
                let position = ReplayPosition::Local {
                    id: entry.id(),
                    node: entry.node,
                    revision: entry.revision,
                    ordered_base: entry.ordered_base,
                    merge_frontier: entry.merge_frontier,
                };
                let publication = self.core.publish_local(&entry)?;
                let (position, executions, _) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                Ok((position, executions, None))
            }
            InvocationScope::Merge => {
                let input_id = input.id();
                let mut event = self.merge_event(input.clone())?;
                let mut position = ReplayPosition::Merge {
                    id: event.id(),
                    causal_height: event.causal_height,
                    ordered_base: event.ordered_base,
                };
                let publication = match self.core.publish_merge(&event) {
                    Err(LocalJournalDriverError::Replay(ReplayError::ReplayLimit)) => {
                        event = self.merge_event(input)?;
                        position = ReplayPosition::Merge {
                            id: event.id(),
                            causal_height: event.causal_height,
                            ordered_base: event.ordered_base,
                        };
                        self.core.publish_merge(&event)?
                    }
                    result => result?,
                };
                let (position, executions, already_committed) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                if !executions.is_empty() {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                let ReplayPosition::Merge { id, .. } = position else {
                    return Err(LocalJournalDriverError::InvalidResult);
                };
                let frontier = if already_committed {
                    MergeFrontier {
                        genesis: self.core.materialization.heads().genesis,
                        events: vec![id],
                    }
                    .id()
                } else {
                    self.core.materialization.merge_frontier()
                };
                let pending = PendingMergeReceipt {
                    event: id,
                    frontier,
                    input: event.input.clone(),
                    position,
                };
                Ok((position, executions, Some(pending)))
            }
        }
    }

    fn check_execution_results(
        input: &ReplayInput,
        executions: &[ReplayExecutionResult],
    ) -> Result<(), LocalJournalDriverError> {
        if executions.iter().any(|execution| {
            !execution.products().is_empty()
                || execution.input() != input.id()
                || matches!(execution.outcome(), ReplayStepOutcome::DivergentInvocation)
                    && execution.result().is_some()
        }) {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(())
    }

    /// Execute or recover one invocation. The source Merge publication never
    /// exposes its provisional guest result; it returns only a pending
    /// journal receipt until [`Self::finalize_merge`] commits the frontier.
    pub(crate) fn invoke(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                &invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let observed_slot = self
            .core
            .executor
            .trust
            .current_logical_slot()
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        let input = ReplayInput {
            runtime: self.core.materialization.runtime().clone(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot,
            },
        };
        if let Some(existing) = self.core.existing_merge_recovery(&input)? {
            return Ok(match existing {
                ExistingMergeRecovery::Pending(pending) => LocalInvocationResult::Pending(pending),
                ExistingMergeRecovery::Acknowledged => LocalInvocationResult::Acknowledged,
            });
        }
        let before = self.core.materialization.clone();
        let (position, executions, pending) = match self.publish_invocation_input(input.clone()) {
            Ok(published) => published,
            Err(LocalJournalDriverError::Replay(ReplayError::UncommittedInvocation(error))) => {
                let after = &self.core.materialization;
                if (after != &before && !Self::is_checkpoint_only_delta(&before, after))
                    || self.core.store.heads()? != Some(after.heads().clone())
                {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                return Ok(LocalInvocationResult::Final(Err(error)));
            }
            Err(error) => return Err(error),
        };
        Self::check_execution_results(&input, &executions)?;
        let recovered = self.core.recover(&input, position)?;
        self.map_invocation_recovery(recovered, pending, &executions)
    }

    /// Execute one invocation to a non-provisional result. A Merge source is
    /// immediately finalized by an ordered maintenance publication and then
    /// recovered through its exact authenticated input/position capability.
    pub(crate) fn invoke_synchronous(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalSettledInvocationResult, LocalJournalDriverError> {
        match self.invoke(invocation, authority)? {
            LocalInvocationResult::Final(result) => Ok(LocalSettledInvocationResult::Final(result)),
            LocalInvocationResult::Acknowledged => Ok(LocalSettledInvocationResult::Acknowledged),
            LocalInvocationResult::Pending(pending) => {
                self.finalize_merge()?;
                match self.recover_committed_invocation(&pending.input, pending.position)? {
                    LocalInvocationResult::Final(result) => {
                        Ok(LocalSettledInvocationResult::Final(result))
                    }
                    LocalInvocationResult::Acknowledged => {
                        Ok(LocalSettledInvocationResult::Acknowledged)
                    }
                    LocalInvocationResult::Pending(_) => {
                        Err(LocalJournalDriverError::InvalidResult)
                    }
                }
            }
        }
    }

    fn map_invocation_recovery(
        &self,
        recovered: ReplayInvocationRecovery,
        pending: Option<PendingMergeReceipt>,
        executions: &[ReplayExecutionResult],
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        match recovered {
            ReplayInvocationRecovery::Retained(result) => {
                if executions
                    .iter()
                    .filter_map(ReplayExecutionResult::result)
                    .any(|direct| direct != &result)
                {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                Ok(LocalInvocationResult::Final(result))
            }
            ReplayInvocationRecovery::Pending => pending
                .map(LocalInvocationResult::Pending)
                .ok_or(LocalJournalDriverError::InvalidResult),
            ReplayInvocationRecovery::Divergent => Ok(LocalInvocationResult::Final(Err(
                ActorExecutionError::DivergentInvocation,
            ))),
            ReplayInvocationRecovery::Acknowledged => Ok(LocalInvocationResult::Acknowledged),
            ReplayInvocationRecovery::NotCommitted => Err(LocalJournalDriverError::InvalidResult),
        }
    }

    /// Recover a response from current authenticated ownership without
    /// executing runtime code. The complete input and exact committed
    /// position are the suffix-scoped lookup capability. Live config and
    /// package trust plus the invocation receipt are revalidated before that
    /// capability can disclose status or result bytes.
    pub(crate) fn recover_committed_invocation(
        &mut self,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        Self::validate_invocation_capability(&config, input)?;
        let pending = match position {
            ReplayPosition::Merge { id, .. } => Some(PendingMergeReceipt {
                event: id,
                frontier: MergeFrontier {
                    genesis: self.core.materialization.heads().genesis,
                    events: vec![id],
                }
                .id(),
                input: input.clone(),
                position,
            }),
            ReplayPosition::Genesis
            | ReplayPosition::Ordered { .. }
            | ReplayPosition::Local { .. } => None,
        };
        let recovered = self.core.recover(input, position)?;
        self.map_invocation_recovery(recovered, pending, &[])
    }

    pub(crate) fn acknowledge_invocation(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalAcknowledgementResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                &invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let input = ReplayInput {
            runtime: self.core.materialization.runtime().clone(),
            operation: ReplayOperation::Acknowledge {
                invocation,
                authority,
            },
        };
        if let Some(existing) = self.core.existing_merge_recovery(&input)? {
            return Ok(match existing {
                ExistingMergeRecovery::Pending(pending) => {
                    LocalAcknowledgementResult::Pending(pending)
                }
                ExistingMergeRecovery::Acknowledged => LocalAcknowledgementResult::Acknowledged,
            });
        }
        let (position, executions, pending) = self.publish_invocation_input(input.clone())?;
        Self::check_execution_results(&input, &executions)?;
        Self::map_acknowledgement_recovery(self.core.recover(&input, position)?, pending)
    }

    /// Acknowledge one invocation to a non-provisional result. Merge
    /// acknowledgement events are finalized and then recovered through the
    /// exact event input/position before success is exposed.
    pub(crate) fn acknowledge_invocation_synchronous(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalSettledAcknowledgementResult, LocalJournalDriverError> {
        match self.acknowledge_invocation(invocation, authority)? {
            LocalAcknowledgementResult::Acknowledged => {
                Ok(LocalSettledAcknowledgementResult::Acknowledged)
            }
            LocalAcknowledgementResult::Divergent => {
                Ok(LocalSettledAcknowledgementResult::Divergent)
            }
            LocalAcknowledgementResult::Pending(pending) => {
                self.finalize_merge()?;
                let config = self.trusted_current_config()?;
                Self::validate_invocation_capability(&config, &pending.input)?;
                match Self::map_acknowledgement_recovery(
                    self.core.recover(&pending.input, pending.position)?,
                    None,
                )? {
                    LocalAcknowledgementResult::Acknowledged => {
                        Ok(LocalSettledAcknowledgementResult::Acknowledged)
                    }
                    LocalAcknowledgementResult::Divergent => {
                        Ok(LocalSettledAcknowledgementResult::Divergent)
                    }
                    LocalAcknowledgementResult::Pending(_) => {
                        Err(LocalJournalDriverError::InvalidResult)
                    }
                }
            }
        }
    }

    fn map_acknowledgement_recovery(
        recovered: ReplayInvocationRecovery,
        pending: Option<PendingMergeReceipt>,
    ) -> Result<LocalAcknowledgementResult, LocalJournalDriverError> {
        match recovered {
            ReplayInvocationRecovery::Acknowledged => Ok(LocalAcknowledgementResult::Acknowledged),
            ReplayInvocationRecovery::Pending => pending
                .map(LocalAcknowledgementResult::Pending)
                .ok_or(LocalJournalDriverError::InvalidResult),
            ReplayInvocationRecovery::Divergent => Ok(LocalAcknowledgementResult::Divergent),
            _ => Err(LocalJournalDriverError::InvalidResult),
        }
    }

    /// Resolve one exact actor incarnation through authenticated, read-only
    /// Standard directory pages.
    pub(crate) fn inspect_actor(
        &self,
        actor: ActorId,
    ) -> Result<ActorDirectoryRecord, LocalJournalDriverError> {
        if actor == ActorId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        let config = self.trusted_current_config()?;
        let page_limit = usize::from(super::standard::MAX_DIRECTORY_PAGE);
        let max_actors = usize::try_from(config.capabilities.max_actors)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let max_pages = max_actors.div_ceil(page_limit).saturating_add(1);
        let mut after = None;
        for _ in 0..max_pages {
            let page = self.inspect(after, super::standard::MAX_DIRECTORY_PAGE)?;
            if let Ok(index) = page
                .entries
                .binary_search_by_key(&actor, |record| record.entry.actor)
            {
                return Ok(page.entries[index].clone());
            }
            if page
                .entries
                .last()
                .is_some_and(|record| record.entry.actor > actor)
            {
                return Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound));
            }
            let Some(next) = page.next else {
                return Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound));
            };
            if after == Some(next) {
                return Err(LocalJournalDriverError::InvalidResult);
            }
            after = Some(next);
        }
        Err(LocalJournalDriverError::InvalidResult)
    }

    fn valid_directory_page(
        after: Option<crate::service::ActorId>,
        limit: usize,
        max_actors: usize,
        page: &ActorDirectoryPage,
    ) -> bool {
        page.entries.len() <= limit
            && page.entries.len() <= max_actors
            && !page
                .entries
                .windows(2)
                .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
            && after.is_none_or(|cursor| {
                page.entries
                    .first()
                    .is_none_or(|record| record.entry.actor > cursor)
            })
            && match page.next {
                Some(next) => {
                    page.entries.len() == limit
                        && page
                            .entries
                            .last()
                            .is_some_and(|record| record.entry.actor == next)
                        && after.is_none_or(|cursor| next > cursor)
                }
                None => true,
            }
            && page.entries.iter().all(|record| {
                record.incarnation != Hash::ZERO
                    && record.installation_id != crate::service::InstallationId::ZERO
                    && record.registry_reservation != Hash::ZERO
            })
    }

    /// Read-only Standard-runtime directory inspection. Any byte change in
    /// any state component is a protocol violation and is never published.
    pub(crate) fn inspect(
        &self,
        after: Option<crate::service::ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        let runtime = self
            .core
            .executor
            .runtime_package(&config, self.core.materialization.runtime())?;
        let request = LifecycleRequest::Inspect { after, limit };
        let decoded = decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let mut expected = StandardAgentRuntime::restore(decoded)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let expected_result = expected.apply(request.clone());
        #[cfg(test)]
        let returned = if self
            .core
            .executor
            .trust
            .use_native_standard_runtime_for_test()
        {
            RuntimeReturn {
                state: encode_standard_runtime_state(&expected.snapshot()),
                result: expected_result.clone(),
            }
        } else {
            self.core.executor.execute_wire(
                &runtime.pvm,
                self.core.executor.management_gas,
                &RuntimeCall::new(self.core.materialization.state().clone(), request).encode(),
            )?
        };
        #[cfg(not(test))]
        let returned: RuntimeReturn = self.core.executor.execute_wire(
            &runtime.pvm,
            self.core.executor.management_gas,
            &RuntimeCall::new(self.core.materialization.state().clone(), request).encode(),
        )?;
        if returned.state != *self.core.materialization.state()
            || returned.result != expected_result
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        match returned.result {
            Ok(LifecycleReply::Directory(page))
                if Self::valid_directory_page(
                    after,
                    limit as usize,
                    config.capabilities.max_actors as usize,
                    &page,
                ) =>
            {
                Ok(page)
            }
            Ok(_) => Err(LocalJournalDriverError::InvalidResult),
            Err(error) => Err(LocalJournalDriverError::Lifecycle(error)),
        }
    }
}

#[cfg(all(feature = "storage", target_os = "linux"))]
impl LocalJournalAgentDriver<FileAgentJournalStore> {
    /// Initialize an ordinary Local journal from its opaque receipt-verified
    /// seal.  The complete catalog and generation are synced before the host
    /// may publish its external exposure marker.
    pub(crate) fn create_local(
        mut store: FileAgentJournalStore,
        sealed: ReplaySealedLocalGenesis,
        intent: Hash,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::preflight_local_create(&sealed, catalog, &trust, &merge)?;
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize_local(&sealed)?;
        store.sync_unexposed_generation()?;
        let replica = sealed.replica();
        let resolver = store.catalog_blob_resolver()?;
        let executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let core = LocalJournalCore::open(store, executor)?;
        let mut driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
        driver.validate_opened(Some(replica))?;
        let materialized_heads = driver.core.materialization.heads().clone();
        driver.core.store.finish_reverified_open()?;
        if driver.core.store.heads()?.as_ref() != Some(&materialized_heads) {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        driver.core.store.commit_local_exposure(&sealed, intent)?;
        Ok(driver)
    }

    /// Reopen an ordinary Local generation, replay and authenticate its full
    /// current closure, then finish any deferred cleanup and make its stable
    /// exposure witness durable. This is also the recovery boundary for a
    /// crash after generation sync but before Host published the marker.
    pub(crate) fn open_local(
        store: FileAgentJournalStore,
        sealed: &ReplaySealedLocalGenesis,
        intent: Hash,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::open_local_with_optional_attested_transition_provider(
            store, sealed, intent, trust, merge, None,
        )
    }

    /// Production reopen for an ordinary Local agent whose retained suffix
    /// may contain Attested Invoke/Resume work.
    pub(crate) fn open_local_with_attested_transition_provider(
        store: FileAgentJournalStore,
        sealed: &ReplaySealedLocalGenesis,
        intent: Hash,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Box<dyn AttestedReplayTransitionProvider>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::open_local_with_optional_attested_transition_provider(
            store,
            sealed,
            intent,
            trust,
            merge,
            Some(provider),
        )
    }

    fn open_local_with_optional_attested_transition_provider(
        store: FileAgentJournalStore,
        sealed: &ReplaySealedLocalGenesis,
        intent: Hash,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Option<Box<dyn AttestedReplayTransitionProvider>>,
    ) -> Result<Self, LocalJournalDriverError> {
        let resolver = store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        if let Some(provider) = provider {
            executor.replace_attested_transition_provider(provider);
        }
        let core = LocalJournalCore::open(store, executor)?;
        let mut driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
        driver.validate_opened(Some(sealed.replica()))?;
        let materialized_heads = driver.core.materialization.heads().clone();
        driver.core.store.finish_reverified_open()?;
        if driver.core.store.heads()?.as_ref() != Some(&materialized_heads) {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        driver.core.store.commit_local_exposure(sealed, intent)?;
        Ok(driver)
    }
}

#[cfg(all(feature = "storage", target_os = "linux"))]
impl<S> LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore
        + TransitionProofPublicationStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + SystemAuthorityHistoryStore,
{
    fn validate_route_owner(
        store: &S,
        materialization: &ReplayMaterialization,
        authority: &BoundFileSystemAuthorityLedgerOwner,
    ) -> Result<(), LocalJournalDriverError> {
        let (_, view) = materialized_system_authority_view(store, materialization)?;
        if view.route() != authority.route()
            || view.journal_store() != authority.journal_store()
            || store.instance_id() != authority.journal_store()
            || materialization.heads().node != authority.local_node()
        {
            return Err(LocalJournalDriverError::AuthorityLedger);
        }
        Ok(())
    }

    /// Initialize a reverified root store while the Host holds the owner's
    /// no-pending mutation writer. Materialization retains the sealed root
    /// provenance instead of taking the generic unverified replay path.
    pub(crate) fn create_reverified_with_owner<E>(
        mut store: S,
        sealed: ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
        after_validate_before_marker: impl FnOnce() -> Result<(), E>,
    ) -> Result<Self, LocalJournalUnexposedOpenError<E>> {
        let system_genesis = sealed.genesis().id();
        authority
            .with_unexposed_journal_initialization(system_genesis, move || {
                let driver = (|| -> Result<Self, LocalJournalDriverError> {
                    Self::preflight_create(&sealed, catalog, &trust, &merge)?;
                    for blob in catalog {
                        store.put_blob(
                            JournalBlobClass::CatalogArtifact,
                            &blob.reference,
                            &blob.bytes,
                        )?;
                    }
                    store.initialize(&sealed)?;
                    let resolver = store.catalog_blob_resolver()?;
                    let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                    let materialization = materialize_current_reverified(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                    )?;
                    Self::validate_route_owner(&store, &materialization, authority)?;
                    let core =
                        LocalJournalCore::from_materialization(store, executor, materialization);
                    let driver = Self {
                        core,
                        #[cfg(test)]
                        lifecycle_fault: None,
                    };
                    driver.validate_opened(Some(sealed.replica()))?;
                    Ok(driver)
                })()
                .map_err(LocalJournalUnexposedOpenError::Driver)?;
                driver
                    .core
                    .store
                    .sync_unexposed_generation()
                    .map_err(LocalJournalDriverError::from)
                    .map_err(LocalJournalUnexposedOpenError::Driver)?;
                after_validate_before_marker()
                    .map_err(LocalJournalUnexposedOpenError::BeforeExposure)?;
                Ok(driver)
            })
            .map_err(|error| {
                LocalJournalUnexposedOpenError::Driver(LocalJournalDriverError::from(error))
            })?
    }

    /// Reverify a completely initialized journal left by a crash immediately
    /// before its permanent exposure marker was committed. The owner's
    /// pristine-unexposed writer excludes evidence creation and installs the
    /// marker only after the rebuilt driver has passed every open invariant.
    pub(crate) fn open_unexposed_reverified_with_owner<E>(
        mut store: S,
        sealed: &ReplaySealedGenesis,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
        after_validate_before_marker: impl FnOnce() -> Result<(), E>,
    ) -> Result<Self, LocalJournalUnexposedOpenError<E>> {
        let system_genesis = sealed.genesis().id();
        let initial_heads = sealed.initial_heads();
        authority
            .with_unexposed_journal_initialization(system_genesis, move || {
                let driver = (|| -> Result<Self, LocalJournalDriverError> {
                    if store.heads()?.as_ref() != Some(&initial_heads) {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                    let resolver = store.catalog_blob_resolver()?;
                    let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                    let materialization = materialize_current_reverified(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                    )?;
                    if materialization.heads() != &initial_heads {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                    Self::validate_route_owner(&store, &materialization, authority)?;
                    let core =
                        LocalJournalCore::from_materialization(store, executor, materialization);
                    let driver = Self {
                        core,
                        #[cfg(test)]
                        lifecycle_fault: None,
                    };
                    driver.validate_opened(None)?;
                    Ok(driver)
                })()
                .map_err(LocalJournalUnexposedOpenError::Driver)?;
                driver
                    .core
                    .store
                    .sync_unexposed_generation()
                    .map_err(LocalJournalDriverError::from)
                    .map_err(LocalJournalUnexposedOpenError::Driver)?;
                after_validate_before_marker()
                    .map_err(LocalJournalUnexposedOpenError::BeforeExposure)?;
                Ok(driver)
            })
            .map_err(|error| {
                LocalJournalUnexposedOpenError::Driver(LocalJournalDriverError::from(error))
            })?
    }

    /// Rebuild a reverified root materialization and reconcile any exact
    /// pending rotation or catalog publication before exposing a mutable
    /// driver. This path uses only the signer-independent route owner; a
    /// predecessor without durable intent stays quarantined and no driver is
    /// returned.
    pub(crate) fn open_reverified_with_owner(
        mut store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
    ) -> Result<Self, LocalJournalDriverError> {
        authority
            .with_recovery_owner(move |owner| {
                let resolver = store.catalog_blob_resolver()?;
                let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                let current = materialize_current_reverified(
                    &mut store,
                    &mut executor,
                    &NoPrunedOrderedBases,
                )?;
                Self::validate_route_owner(&store, &current, authority)?;
                let materialization = match owner.recover_pending_claim()? {
                    None => current,
                    Some(pending) if pending.catalog_request().is_some() => {
                        match recover_pending_system_authority_catalog(
                            &mut store,
                            &mut executor,
                            current,
                            pending,
                            owner,
                        )
                        .map_err(map_system_authority_recovery_error)?
                        {
                            PendingSystemAuthorityCatalogRecovery::Pending(_quarantine) => {
                                return Err(LocalJournalDriverError::AuthorityRecoveryRequired);
                            }
                            PendingSystemAuthorityCatalogRecovery::Retired(retired) => {
                                let (_publication, materialization, _executions) =
                                    retired.into_parts();
                                materialization
                            }
                        }
                    }
                    Some(pending) if pending.rotation_request().is_some() => {
                        match recover_pending_system_authority_rotation(
                            &mut store,
                            &mut executor,
                            current,
                            pending,
                            owner,
                        )
                        .map_err(map_system_authority_recovery_error)?
                        {
                            PendingSystemAuthorityRotationRecovery::Pending(_quarantine) => {
                                return Err(LocalJournalDriverError::AuthorityRecoveryRequired);
                            }
                            PendingSystemAuthorityRotationRecovery::Retired(retired) => {
                                let (_publication, materialization, _executions) =
                                    retired.into_parts();
                                materialization
                            }
                        }
                    }
                    Some(_) => return Err(LocalJournalDriverError::AuthorityLedger),
                };
                Self::validate_route_owner(&store, &materialization, authority)?;
                let (_, replayed_authority) =
                    materialized_system_authority_view(&store, &materialization)?;
                owner.validate_replayed_view(&replayed_authority)?;
                // Filesystem crash cleanup is deliberately deferred until
                // the current heads have survived full replay and the
                // external authority META fence. A deleted required
                // directory therefore fails without being recreated.
                store.finish_reverified_open()?;
                if store.heads()?.as_ref() != Some(materialization.heads()) {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                Self::validate_route_owner(&store, &materialization, authority)?;
                let core = LocalJournalCore::from_materialization(store, executor, materialization);
                let driver = Self {
                    core,
                    #[cfg(test)]
                    lifecycle_fault: None,
                };
                driver.validate_opened(None)?;
                Ok(driver)
            })
            .map_err(LocalJournalDriverError::from)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_preflight_reuse_is_exact_and_single_use() {
        let transition = crate::agent_sdk::RuntimeTransition {
            state: crate::agent_sdk::RuntimeState::default(),
            outcome: crate::agent_sdk::RuntimeOutcome::Completed(Err(
                crate::agent_sdk::InvocationError::NotFound,
            )),
        };
        let prepare = || {
            Some(TerminalPreflight {
                runtime_pvm: vec![1, 2, 3],
                input: vec![4, 5, 6, 7],
                gas: 100,
                transition: transition.clone(),
            })
        };
        let mut slot = prepare();
        assert_eq!(
            TerminalPreflight::consume(&mut slot, &[1, 2, 3], &[4, 5, 6, 7], 100),
            Some(transition.clone())
        );
        assert!(TerminalPreflight::consume(&mut slot, &[1, 2, 3], &[4, 5, 6, 7], 100).is_none());

        for offset in 0..4 {
            let mut input = vec![4, 5, 6, 7];
            input[offset] ^= 1;
            let mut slot = prepare();
            assert!(TerminalPreflight::consume(&mut slot, &[1, 2, 3], &input, 100).is_none());
            assert!(slot.is_none(), "a mismatch must consume the candidate");
        }
        for (runtime, input, gas) in [
            (vec![1, 2, 4], vec![4, 5, 6, 7], 100),
            (vec![1, 2, 3, 0], vec![4, 5, 6, 7], 100),
            (vec![1, 2, 3], vec![4, 5, 6], 100),
            (vec![1, 2, 3], vec![4, 5, 6, 7, 0], 100),
            (vec![1, 2, 3], vec![4, 5, 6, 7], 101),
        ] {
            let mut slot = prepare();
            assert!(TerminalPreflight::consume(&mut slot, &runtime, &input, gas).is_none());
            assert!(slot.is_none());
        }
    }

    use super::super::authority::{
        ActorInvocationClaim, AgentAuthorityBinding, AgentAuthorityClaim,
    };
    use super::super::contract::{ActorPackageContract, RuntimePackageContract};
    use super::super::execution::ActorInvocationAuth;
    use super::super::journal_store::{
        AgentJournalGarbageCollection, GcLimits, MemoryAgentJournalStore,
    };
    use super::super::package::{PackageManifest, sdk_actor_runtime_requirements};
    use super::super::wire::encode_standard_runtime_state;
    use super::super::{
        ActorEntry, InstallActor, LaneSet, MethodMode, RuntimeCapabilities, RuntimeRequirements,
        StateLane,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, InvocationId,
        PackageRolePolicies, ProducerId, ProgramId, SpaceId, artifact_hash, task_dependencies_hash,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn runtime_preparation_cache_is_exact_bounded_and_state_independent() {
        fn wrap(code_blob: &[u8]) -> Vec<u8> {
            let mut blob = vec![0; 11];
            blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
            blob.extend_from_slice(code_blob);
            blob
        }
        let halt = wrap(&[0, 1, 2, 50, 0, 1]);
        let trap = wrap(&[0, 1, 1, 0, 1]);
        let cache = RuntimePreparationCache::default();
        assert_eq!(
            cache.load(&halt, &[], 1_000_000).unwrap().run().exit,
            ExitReason::Halt
        );
        let original = Arc::clone(&cache.entry.lock().unwrap().as_ref().unwrap().1);
        for (args, gas) in [(&b""[..], 0), (&b"different arguments"[..], 1_000_000)] {
            let cold = RefineContext::load(&halt, args, gas).unwrap().run();
            let reused = cache.load(&halt, args, gas).unwrap().run();
            assert_eq!(cold.exit, reused.exit);
            assert_eq!(cold.gas_used, reused.gas_used);
            assert_eq!(cold.registers, reused.registers);
            assert!(Arc::ptr_eq(
                &original,
                &cache.entry.lock().unwrap().as_ref().unwrap().1
            ));
        }
        assert_eq!(
            cache.load(&trap, &[], 1_000_000).unwrap().run().exit,
            ExitReason::Panic
        );
        let replacement = Arc::clone(&cache.entry.lock().unwrap().as_ref().unwrap().1);
        assert!(!Arc::ptr_eq(&original, &replacement));
        for invalid in [
            vec![0xff; 4],
            vec![0xff; super::super::execution::MAX_EXECUTION_PROGRAM_BYTES + 1],
        ] {
            assert!(cache.load(&invalid, &[], 1_000_000).is_err());
            assert!(Arc::ptr_eq(
                &replacement,
                &cache.entry.lock().unwrap().as_ref().unwrap().1
            ));
        }
        assert_eq!(cache.entry.lock().unwrap().as_ref().unwrap().0, trap);
        assert_eq!(
            cache.load(&halt, &[], 1_000_000).unwrap().run().exit,
            ExitReason::Halt
        );
    }

    struct StaticTrust {
        slot: Option<u64>,
        authority: Option<AgentAuthorityBinding>,
        trust_packages: bool,
    }

    impl AgentTrustProvider for StaticTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            self.authority.clone()
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            self.trust_packages
        }

        fn use_native_standard_runtime_for_test(&self) -> bool {
            true
        }
    }

    struct MutableTrust {
        slot: Option<u64>,
        authority: Mutex<Option<AgentAuthorityBinding>>,
    }

    impl AgentTrustProvider for MutableTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            self.authority.lock().unwrap().clone()
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }
    }

    struct CleanClockTrust {
        slot: Arc<AtomicU64>,
    }

    impl AgentTrustProvider for CleanClockTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(self.slot.load(Ordering::SeqCst))
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            None
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            false
        }
    }

    struct StaticMerge(NodeId);

    impl LocalMergeAuthenticator for StaticMerge {
        fn node(&self) -> NodeId {
            self.0
        }

        fn sign_event(&self, event: &mut MergeEvent) -> bool {
            if event.author != self.0 || !event.signature.is_empty() {
                return false;
            }
            event.signature = vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES];
            true
        }

        fn verify_event(&self, event: &MergeEvent) -> bool {
            event.author == self.0
                && event.signature.len() == super::super::authority::ED25519_SIGNATURE_BYTES
        }
    }

    struct ScriptedAttestedProvider {
        preparations: VecDeque<AttestedReplayTransitionPreparation>,
        published: VecDeque<PublishedAttestedTransition>,
        prepare_calls: Arc<AtomicU64>,
        published_calls: Arc<AtomicU64>,
    }

    impl AttestedReplayTransitionProvider for ScriptedAttestedProvider {
        fn load_published_transition(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
            _work: &crate::agent_sdk::RuntimeWork,
        ) -> Result<PublishedAttestedTransition, LocalReplayExecutorError> {
            self.published_calls.fetch_add(1, Ordering::SeqCst);
            self.published
                .pop_front()
                .ok_or(LocalReplayExecutorError::InvalidState)
        }

        fn prepare_verified_transition(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
            _work: &crate::agent_sdk::RuntimeWork,
        ) -> Result<AttestedReplayTransitionPreparation, LocalReplayExecutorError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.preparations
                .pop_front()
                .ok_or(LocalReplayExecutorError::InvalidState)
        }
    }

    fn scripted_attested_transition(
        seed: u8,
    ) -> (
        ReplayInput,
        RuntimeState,
        super::super::transition_proof_host::PublishedAttestedTransition,
    ) {
        use crate::agent_sdk::proof::{
            ProofLaneRoots, TransitionProofMaterialManifest, TransitionProofRecord,
            TransitionProofStatement, TransitionProofSubject,
        };

        let mut operation = clean_scan_operation(seed);
        let ReplayOperation::CleanInvoke { context, work, .. } = &mut operation else {
            unreachable!()
        };
        let proof_system = crate::agent_sdk::Hash([0xa8; 32]);
        *context = crate::agent_sdk::RuntimeExecutionContext::Attested { proof_system };
        let runtime_package = BlobRef::of_bytes(b"attested-replay-runtime");
        let runtime = RuntimeBinding {
            space: SpaceId(work.space.0),
            agent: super::super::AgentId(work.agent.0),
            deployment: DeploymentId(work.runtime_deployment.0),
            program: ProgramId([0xa1; 32]),
            producer: ProducerId([0xa2; 32]),
            package: runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let input = ReplayInput { runtime, operation };
        let before = RuntimeState {
            control: vec![0xa3],
            linear: vec![0xa4],
            merge: Vec::new(),
            local: Vec::new(),
        };
        let ReplayOperation::CleanInvoke {
            context,
            work,
            authorization,
            observed_slot,
        } = &input.operation
        else {
            unreachable!()
        };
        let sdk_work = crate::agent_sdk::RuntimeWork::Invoke {
            context: *context,
            state: crate::agent_sdk::RuntimeState {
                control: before.control.clone(),
                linear: before.linear.clone(),
                merge: before.merge.clone(),
                local: before.local.clone(),
            },
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: *observed_slot,
        };
        let canonical_work = sdk_work.encode().unwrap();
        let transition = crate::agent_sdk::RuntimeTransition {
            state: crate::agent_sdk::RuntimeState {
                control: before.control.clone(),
                linear: before.linear.clone(),
                merge: before.merge.clone(),
                local: before.local.clone(),
            },
            outcome: crate::agent_sdk::RuntimeOutcome::Completed(Err(
                crate::agent_sdk::InvocationError::NotFound,
            )),
        };
        let canonical_transition = transition.encode().unwrap();
        let roots = ProofLaneRoots {
            control: crate::agent_sdk::Hash([0xa5; 32]),
            linear: Some(crate::agent_sdk::Hash([0xa6; 32])),
            merge: None,
            local: None,
        };
        let proof_material = vec![0xa7];
        let manifest = TransitionProofMaterialManifest::for_material(&proof_material).unwrap();
        let proof_manifest_bytes = manifest.encode().unwrap();
        let producer_public_key = [0xa9; 32];
        let record = TransitionProofRecord {
            statement: TransitionProofStatement {
                subject: TransitionProofSubject {
                    space: work.space,
                    agent: work.agent,
                    runtime_deployment: work.runtime_deployment,
                    runtime_program: crate::agent_sdk::ProgramId(input.runtime.program.0),
                    runtime_package: crate::agent_sdk::BlobRef {
                        hash: crate::agent_sdk::Hash(runtime_package.hash.0),
                        len: runtime_package.len,
                    },
                    actor: work.actor,
                    incarnation: work.incarnation,
                    actor_deployment: work.deployment,
                    actor_program: work.program,
                    invocation: work.invocation,
                    method: "call".to_owned(),
                    mode: work.mode,
                },
                before: roots,
                after: roots,
                work: TransitionProofStatement::work_commitment(&canonical_work),
                transition: TransitionProofStatement::transition_commitment(&canonical_transition),
                refine_trace: crate::agent_sdk::Hash([0xaa; 32]),
                public_io: crate::agent_sdk::Hash([0xab; 32]),
                proof_system,
            },
            proof: crate::agent_sdk::BlobRef::of_bytes(&proof_manifest_bytes),
            producer: crate::agent_sdk::ProducerId::of_public_key(&producer_public_key),
            producer_public_key,
            producer_signature: [0xac; 64],
        };
        assert!(manifest.matches_material(&proof_material));
        let publication = record.verified_publication_commitment().unwrap();
        let published =
            super::super::transition_proof_host::PublishedAttestedTransition::reconstruct(
                canonical_work,
                canonical_transition,
                record,
                proof_manifest_bytes,
                publication,
            )
            .unwrap();
        (input, before, published)
    }

    fn clean_test_descriptor(
        runtime: &super::super::package_admission::AdmittedRuntimePackage,
        node: NodeId,
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::AgentDescriptor {
        let space = crate::agent_sdk::SpaceId([0x31; 32]);
        let owner = crate::agent_sdk::PrincipalId([0x32; 32]);
        let creation_nonce = crate::agent_sdk::Hash([0x33; 32]);
        let agent = crate::agent_sdk::AgentId::derive(space, owner, creation_nonce.as_bytes());
        let public_key = authority_key.verifying_key().to_bytes();
        let descriptor = crate::agent_sdk::AgentDescriptor {
            identity: crate::agent_sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: crate::agent_sdk::AgentProfile::Local,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: crate::agent_sdk::ProducerId([0x93; 32]),
            },
            creation_nonce,
            authority: crate::agent_sdk::authority::AgentAuthorityBinding {
                policy: crate::agent_sdk::Hash([0x34; 32]),
                issuer: crate::agent_sdk::authority::AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([0x35; 32]),
                    actor: crate::agent_sdk::ActorId([0x36; 32]),
                    deployment: crate::agent_sdk::DeploymentId([0x37; 32]),
                    program: crate::agent_sdk::ProgramId([0x38; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![crate::agent_sdk::AgentReplica {
                node: crate::agent_sdk::NodeId(node.0),
                principal: owner,
                role: crate::agent_sdk::ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        descriptor
    }

    fn clean_test_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        sequence: u64,
        authority_key: &SigningKey,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityReceipt, AuthorityReceiptSelector,
        };

        let operation = request
            .authority_operation()
            .expect("mutating clean local test request");
        let (actor, actor_deployment) = request.authority_actor_selector();
        let decision_sequence = operation
            .uses_management_decision_journal()
            .then_some(sequence)
            .unwrap_or(0);
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: descriptor.authority.policy,
                issuer: descriptor.authority.issuer,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                operation,
                runtime_deployment: descriptor.identity.runtime_deployment,
                actor,
                actor_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x39; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: 100,
                request: request.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0; 64],
        };
        receipt.signature = authority_key.sign(&receipt.signing_bytes()).to_bytes();
        receipt.validate_shape().unwrap();
        receipt
    }

    #[test]
    fn fixed_system_genesis_preparation_is_replica_independent() {
        use super::super::bootstrap::{
            SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvision,
            seal_prepared_system_agent_genesis,
        };
        use super::super::committee::{
            AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
            AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorPins,
            RootAnchorRecord, SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
        };
        use super::super::replay::ReplaySealedOrdinaryGenesis;
        use crate::agent_sdk as sdk;
        type Driver = LocalJournalAgentDriver<MemoryAgentJournalStore>;
        let runtime = super::super::package_admission::admitted_standard_runtime_for_test(
            "fixed-system-genesis",
            0x42,
        );
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let nodes = [NodeId([0x40; 32]), NodeId([0x50; 32]), NodeId([0x60; 32])];
        let mut descriptor = clean_test_descriptor(&runtime, nodes[0], &key);
        descriptor.identity.profile = sdk::AgentProfile::Shared;
        descriptor.replicas = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| sdk::AgentReplica {
                node: sdk::NodeId(node.0),
                principal: sdk::PrincipalId([0x70 + index as u8; 32]),
                role: sdk::ReplicaRole::Voter,
            })
            .collect();
        descriptor.validate().unwrap();
        let request = sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let receipt = clean_test_receipt(&descriptor, &request, 1, &key);
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(CleanClockTrust {
            slot: Arc::new(AtomicU64::new(10)),
        });
        assert!(!trust.use_native_clean_runtime_for_test());
        let mut expected = None;
        let mut certification: Option<(RootAnchorPins, SystemAgentGenesisEvidence)> = None;
        let mut genesis = None;
        let mut first_provision = None;
        let mut local_heads = Vec::new();
        for entry in &descriptor.replicas {
            let merge: Arc<dyn LocalMergeAuthenticator> =
                Arc::new(StaticMerge(NodeId(entry.node.0)));
            let (input, catalog) = Driver::clean_shared_system_genesis_input(
                descriptor.clone(),
                &runtime,
                receipt.clone(),
                10,
                &trust,
                &merge,
            )
            .unwrap();
            let replica = AgentReplica {
                node: NodeId(entry.node.0),
                principal: crate::service::PrincipalId(entry.principal.0),
                role: super::super::ReplicaRole::Voter,
            };
            let prepared = Driver::prepare_system_genesis(
                input.clone(),
                replica,
                &catalog,
                trust.clone(),
                merge.clone(),
            )
            .unwrap();
            assert_eq!(prepared.replica(), replica);
            let commitments = (
                prepared.create().clone(),
                prepared.expectations(),
                prepared.artifacts().to_vec(),
            );
            if let Some(expected) = &expected {
                assert_eq!(&commitments, expected);
            } else {
                expected = Some(commitments);
            }
            if certification.is_none() {
                // One independently configured root certifies the shared
                // commitments once, not a new genesis per local node.
                let root_key = SigningKey::from_bytes(&[0x81; 32]);
                let committee = AuthorityCommittee::new(
                    SpaceId(descriptor.identity.space.0),
                    Hash(descriptor.authority.commitment().0),
                    1,
                    None,
                    vec![
                        AuthorityCommitteeMember::new(
                            NodeId([0x82; 32]),
                            root_key.verifying_key().to_bytes(),
                            AuthorityMemberRole::Voter,
                        )
                        .unwrap(),
                    ],
                )
                .unwrap();
                let record = RootAnchorRecord::new(
                    1,
                    SpaceId(descriptor.identity.space.0),
                    crate::service::AgentId(descriptor.identity.agent.0),
                    Hash(descriptor.authority.commitment().0),
                    Hash([0x83; 32]),
                    committee.clone(),
                )
                .unwrap();
                let claim = SystemAgentGenesisClaim::new(&record, prepared.expectations()).unwrap();
                let message = AuthorityQuorumCertificate::signing_message(
                    committee.authority_binding(),
                    committee.epoch(),
                    committee.commitment(),
                    claim.authority_claim(),
                );
                let certificate = AuthorityQuorumCertificate::new(
                    &committee,
                    claim.authority_claim(),
                    vec![
                        AuthoritySignature::new(
                            AuthoritySignerId::of_raw_ed25519(&root_key.verifying_key().to_bytes()),
                            root_key.sign(&message.0).to_bytes(),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap();
                let pins = RootAnchorPins::new(
                    record.clone(),
                    record.config_version(),
                    record.id(),
                    record.config_commitment(),
                    claim.authority_claim(),
                )
                .unwrap();
                certification = Some((
                    pins,
                    SystemAgentGenesisEvidence::new(claim, certificate).unwrap(),
                ));
            }
            let (pins, evidence) = certification.as_ref().unwrap();
            let proposal = SystemAgentGenesisProposal::from_prepared(
                SystemAgentGenesisLocator {
                    space: SpaceId(descriptor.identity.space.0),
                    agent: crate::service::AgentId(descriptor.identity.agent.0),
                    node: replica.node,
                },
                &prepared,
            )
            .unwrap();
            let provision =
                SystemAgentGenesisProvision::new(proposal, pins.clone(), evidence.clone()).unwrap();
            if let Some(first) = &first_provision {
                let wrong_local_prepared = Driver::prepare_system_genesis(
                    input.clone(),
                    replica,
                    &catalog,
                    trust.clone(),
                    merge.clone(),
                )
                .unwrap();
                assert!(
                    seal_prepared_system_agent_genesis(wrong_local_prepared, pins, first).is_err()
                );
            } else {
                first_provision = Some(provision.clone());
            }
            let sealed = seal_prepared_system_agent_genesis(prepared, pins, &provision).unwrap();
            assert_eq!(sealed.replica(), replica);
            if let Some(genesis) = genesis {
                assert_eq!(sealed.genesis().id(), genesis);
            } else {
                genesis = Some(sealed.genesis().id());
            }
            assert!(ReplaySealedOrdinaryGenesis::validates_post_create_state(
                &sealed
            ));
            assert!(ReplaySealedOrdinaryGenesis::validate_seal(&sealed).is_ok());
            assert!(!local_heads.contains(&sealed.initial_heads()));
            local_heads.push(sealed.initial_heads());
            let mut store =
                MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, replica.node)
                    .unwrap();
            for blob in &catalog {
                store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &blob.reference,
                        &blob.bytes,
                    )
                    .unwrap();
            }
            assert!(store.initialize(&sealed).unwrap());
            assert!(!store.initialize(&sealed).unwrap());
            assert_eq!(store.genesis().unwrap().as_ref(), Some(sealed.genesis()));
            assert_eq!(
                store.heads().unwrap().as_ref(),
                Some(&sealed.initial_heads())
            );
            let mut wrong_node_store =
                MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, NodeId([0x7f; 32]))
                    .unwrap();
            assert_eq!(
                wrong_node_store.initialize(&sealed),
                Err(JournalStoreError::ScopeMismatch)
            );
            assert!(wrong_node_store.genesis().unwrap().is_none());
            let mut wrong_principal = replica;
            wrong_principal.principal = crate::service::PrincipalId([0x7f; 32]);
            assert!(
                Driver::prepare_system_genesis(
                    input,
                    wrong_principal,
                    &catalog,
                    trust.clone(),
                    merge,
                )
                .is_err()
            );
        }
        // A newly signed Create with a changed roster is still not authorized
        // by the independently pinned original genesis certificate.
        let mut changed = descriptor.clone();
        changed.replicas[2].principal = sdk::PrincipalId([0x7e; 32]);
        let request = sdk::ManagementRequest::Create(Box::new(changed.clone()));
        let changed_receipt = clean_test_receipt(&changed, &request, 1, &key);
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(nodes[0]));
        let (input, catalog) = Driver::clean_shared_system_genesis_input(
            changed,
            &runtime,
            changed_receipt,
            10,
            &trust,
            &merge,
        )
        .unwrap();
        let replica = first_provision.as_ref().unwrap().proposal().replica();
        let prepared =
            Driver::prepare_system_genesis(input, replica, &catalog, trust.clone(), merge).unwrap();
        assert!(
            seal_prepared_system_agent_genesis(
                prepared,
                &certification.as_ref().unwrap().0,
                first_provision.as_ref().unwrap(),
            )
            .is_err()
        );
        let outsider: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(NodeId([0x7f; 32])));
        assert!(
            Driver::clean_shared_system_genesis_input(
                descriptor.clone(),
                &runtime,
                receipt.clone(),
                10,
                &trust,
                &outsider,
            )
            .is_err()
        );
        // Signed but unsupported roster shapes must not reach preparation.
        for observer in [false, true] {
            let mut invalid = descriptor.clone();
            if observer {
                invalid.replicas[2].role = sdk::ReplicaRole::Observer;
            } else {
                invalid.replicas.pop();
            }
            let request = sdk::ManagementRequest::Create(Box::new(invalid.clone()));
            let receipt = clean_test_receipt(&invalid, &request, 1, &key);
            let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(nodes[0]));
            assert!(
                Driver::clean_shared_system_genesis_input(
                    invalid, &runtime, receipt, 10, &trust, &merge,
                )
                .is_err()
            );
        }
    }

    fn clean_test_state(control: &[u8]) -> crate::agent_sdk::RuntimeState {
        crate::agent_sdk::RuntimeState {
            control: control.to_vec(),
            linear: Vec::new(),
            merge: Vec::new(),
            local: Vec::new(),
        }
    }

    fn clean_test_identity_bytes(identity: &crate::agent_sdk::AgentIdentity) -> Vec<u8> {
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

    fn clean_test_unique_offset(haystack: &[u8], needle: &[u8]) -> usize {
        let mut matches = haystack
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset));
        let offset = matches.next().unwrap();
        assert!(matches.next().is_none());
        offset
    }

    fn clean_test_scripted_case(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        state: crate::agent_sdk::RuntimeState,
        request: crate::agent_sdk::ManagementRequest,
        sequence: u64,
        authority_key: &SigningKey,
        next_state: crate::agent_sdk::RuntimeState,
        outcome: crate::agent_sdk::RuntimeOutcome,
    ) -> super::super::package_admission::ScriptedRuntimeCase {
        let authority = clean_test_receipt(descriptor, &request, sequence, authority_key);
        let input = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: authority.selector.runtime_deployment,
            state,
            request: Box::new(request),
            authority: Some(Box::new(authority)),
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
            input,
            output,
            copies: Vec::new(),
        }
    }

    fn clean_test_runtime_fixture() -> (
        super::super::package_admission::AdmittedRuntimePackage,
        crate::agent_sdk::AgentDescriptor,
        SigningKey,
        crate::agent_sdk::ManagementRequest,
        crate::agent_sdk::ManagementRequest,
    ) {
        use super::super::package_admission::{
            ScriptedRuntimeCopy, admitted_scripted_runtime_for_test,
        };

        let node = NodeId([0x40; 32]);
        let authority_key = SigningKey::from_bytes(&[0x41; 32]);
        // The bundled Standard test blob can intentionally lag the current
        // SDK ABI. Use a small admitted current-ABI PVM only to establish the
        // canonical descriptor shape consumed by the scripted cases below.
        let placeholder = admitted_scripted_runtime_for_test(
            "local-script-shape",
            0x42,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: vec![0],
                output: vec![0],
                copies: Vec::new(),
            }],
        );
        let placeholder_descriptor = clean_test_descriptor(&placeholder, node, &authority_key);
        let actor = crate::agent_sdk::ActorId::top_level(
            placeholder_descriptor.identity.agent,
            "opaque-child",
        );
        let deployment = crate::agent_sdk::DeploymentId([0x43; 32]);
        let suspended_entry = crate::agent_sdk::ActorEntry {
            actor,
            name: "opaque-child".into(),
            parent: None,
            deployment,
            program: crate::agent_sdk::ProgramId([0x44; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"opaque-child-package"),
            agent_schema: crate::agent_sdk::BlobRef::of_bytes(b"opaque-child-schema"),
            method_policy: crate::agent_sdk::BlobRef::of_bytes(b"opaque-child-policy"),
            constructor_abi: crate::agent_sdk::Hash([0x45; 32]),
            installation_data: None,
            state_layout: crate::agent_sdk::Hash([0x46; 32]),
            lanes: crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
            suspended: true,
        };
        suspended_entry.validate().unwrap();
        let success = crate::agent_sdk::ManagementRequest::Suspend {
            actor,
            expected_deployment: deployment,
        };
        let denied = crate::agent_sdk::ManagementRequest::Resume {
            actor,
            expected_deployment: deployment,
        };
        let state = clean_test_state(&[1]);
        let create =
            crate::agent_sdk::ManagementRequest::Create(Box::new(placeholder_descriptor.clone()));
        let mut create_case = clean_test_scripted_case(
            &placeholder_descriptor,
            crate::agent_sdk::RuntimeState::default(),
            create.clone(),
            1,
            &authority_key,
            state.clone(),
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(placeholder_descriptor.identity.clone()),
            )),
        );
        let identity = clean_test_identity_bytes(&placeholder_descriptor.identity);
        create_case.copies.push(ScriptedRuntimeCopy {
            input_offset: clean_test_unique_offset(&create_case.input, &identity),
            output_offset: clean_test_unique_offset(&create_case.output, &identity),
            len: identity.len(),
        });
        let cases = vec![
            create_case,
            clean_test_scripted_case(
                &placeholder_descriptor,
                state.clone(),
                success.clone(),
                2,
                &authority_key,
                state.clone(),
                crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Suspended(suspended_entry),
                )),
            ),
            clean_test_scripted_case(
                &placeholder_descriptor,
                state.clone(),
                denied.clone(),
                3,
                &authority_key,
                state,
                crate::agent_sdk::RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::NotFound,
                )),
            ),
        ];
        let runtime = admitted_scripted_runtime_for_test("local-current-abi", 0x47, cases);
        let descriptor = clean_test_descriptor(&runtime, node, &authority_key);
        (runtime, descriptor, authority_key, success, denied)
    }

    #[cfg(all(feature = "pvm", feature = "storage", target_os = "linux"))]
    #[test]
    fn physical_current_abi_custom_local_create_manage_restart_and_retry_is_exact() {
        use super::super::journal_store::FileLocalAgentJournalSlot;
        use std::fs::{self, File};

        let (runtime, descriptor, authority_key, success, denied) = clean_test_runtime_fixture();
        let slot = Arc::new(AtomicU64::new(20));
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(CleanClockTrust {
            slot: Arc::clone(&slot),
        });
        let replica = AgentReplica {
            node: NodeId(descriptor.replicas[0].node.0),
            principal: crate::service::PrincipalId(descriptor.replicas[0].principal.0),
            role: super::super::ReplicaRole::Voter,
        };
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(replica.node));
        let create_request =
            crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let create_receipt = clean_test_receipt(&descriptor, &create_request, 1, &authority_key);
        let (create, catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::clean_local_genesis_input(
                descriptor.clone(),
                &runtime,
                create_receipt,
                &trust,
                &merge,
            )
            .unwrap();
        let sealed = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_local_genesis(
            create.clone(),
            replica,
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        let reopen_seal = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_local_genesis(
            create,
            replica,
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("vos-clean-local-{}-{unique}", std::process::id()));
        let journal_parent_path = base.join("journals");
        let authority_parent_path = base.join("authority");
        fs::create_dir_all(&journal_parent_path).unwrap();
        fs::create_dir_all(&authority_parent_path).unwrap();
        let encoded_agent = descriptor
            .identity
            .agent
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let journal_path = journal_parent_path.join(format!("{encoded_agent}.agent"));
        let lock_path = authority_parent_path.join(format!("{encoded_agent}.agent-lock"));
        let journal_parent = File::open(&journal_parent_path).unwrap();
        let authority_parent = File::open(&authority_parent_path).unwrap();
        let intent = Hash::digest(b"vos/test/clean-local-intent/v1", &[&[0x51]]);
        let physical = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            &journal_path,
            &lock_path,
            replica.node,
            intent,
            &journal_parent,
            &authority_parent,
        )
        .unwrap();
        let store = physical.open(&sealed, false).unwrap();
        let mut driver = LocalJournalAgentDriver::create_local(
            store,
            sealed,
            intent,
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        assert_eq!(driver.core.materialization.heads().ordered_index, 0);

        let mut not_yet_valid = clean_test_receipt(&descriptor, &success, 2, &authority_key);
        not_yet_valid.selector.valid_from = 21;
        not_yet_valid.signature = authority_key
            .sign(&not_yet_valid.signing_bytes())
            .to_bytes();
        assert!(matches!(
            driver.clean_manage(success.clone(), not_yet_valid, SdkManagementArtifacts::None,),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidAuthority
            ))
        ));
        let mut expired = clean_test_receipt(&descriptor, &success, 2, &authority_key);
        expired.selector.expires_at = 19;
        expired.signature = authority_key.sign(&expired.signing_bytes()).to_bytes();
        assert!(matches!(
            driver.clean_manage(success.clone(), expired, SdkManagementArtifacts::None),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidAuthority
            ))
        ));
        assert_eq!(driver.core.materialization.heads().ordered_index, 0);

        slot.store(21, Ordering::SeqCst);
        let success_receipt = clean_test_receipt(&descriptor, &success, 2, &authority_key);
        let first = driver
            .clean_manage(
                success.clone(),
                success_receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert!(matches!(
            &first.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Suspended(_)
            ))
        ));
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);
        let immediate_retry = driver
            .clean_manage(
                success.clone(),
                success_receipt.clone(),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert_eq!(immediate_retry.outcome, first.outcome);
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);
        drop(driver);

        let physical = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            &journal_path,
            &lock_path,
            replica.node,
            intent,
            &journal_parent,
            &authority_parent,
        )
        .unwrap();
        let store = physical.open(&reopen_seal, true).unwrap();
        let mut driver = LocalJournalAgentDriver::open_local(
            store,
            &reopen_seal,
            intent,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        slot.store(22, Ordering::SeqCst);
        let retained = driver
            .clean_manage(success, success_receipt, SdkManagementArtifacts::None)
            .unwrap();
        assert_eq!(retained.outcome, first.outcome);
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);

        let policy = crate::agent_sdk::contract::RuntimeResourcePolicy::standard();
        let policy_bytes = policy.encode().unwrap();
        let private = crate::agent_sdk::ManagementRequest::PrivateControl {
            control: Box::new(crate::agent_sdk::private::PrivateControlRecord {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                sequence: 0,
                previous: None,
                operation: crate::agent_sdk::private::PrivateControlOperation::SetResourcePolicy {
                    policy: crate::agent_sdk::BlobRef::of_bytes(&policy_bytes),
                },
                signer: crate::agent_sdk::private::PrivateControlSigner::Owner,
                signer_public_key: [0x52; 32],
                signature: [0x53; crate::agent_sdk::private::PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: Box::new(crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(
                policy,
            )),
        };
        assert!(private.is_valid());
        let private_receipt = clean_test_receipt(&descriptor, &private, 3, &authority_key);
        assert!(matches!(
            driver.clean_manage(private, private_receipt, SdkManagementArtifacts::None),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        ));
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);

        slot.store(23, Ordering::SeqCst);
        let denied_receipt = clean_test_receipt(&descriptor, &denied, 3, &authority_key);
        let denial = driver
            .clean_manage(denied, denied_receipt, SdkManagementArtifacts::None)
            .unwrap();
        assert_eq!(
            denial.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Err(
                crate::agent_sdk::ManagementError::NotFound
            ))
        );
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);

        let change = crate::agent_sdk::ManagementRequest::ChangeReplicas {
            expected_generation: descriptor.replica_generation(),
            replicas: descriptor.replicas.clone(),
        };
        let change_receipt = clean_test_receipt(&descriptor, &change, 4, &authority_key);
        assert!(matches!(
            driver.clean_manage(change, change_receipt, SdkManagementArtifacts::None),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        ));
        assert_eq!(driver.core.materialization.heads().ordered_index, 1);
        drop(driver);
        fs::remove_dir_all(base).unwrap();
    }

    #[derive(Default)]
    struct ExactTestExecutor {
        executions: usize,
        refusal: Option<ActorExecutionError>,
    }

    impl ReplayExecutor for ExactTestExecutor {
        type Error = LocalReplayExecutorError;

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn authenticate(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            let state = decode_standard_runtime_state(before)
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            let mut runtime = StandardAgentRuntime::restore(state)
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            match &input.operation {
                ReplayOperation::Management { request } => {
                    let applied = runtime.apply(request.clone()).is_ok();
                    Ok(ReplayTransition {
                        state: encode_standard_runtime_state(&runtime.snapshot()),
                        disposition: if applied {
                            ReplayDisposition::Applied
                        } else {
                            ReplayDisposition::Rejected
                        },
                        result: None,
                        next_runtime: input.runtime.clone(),
                        products: ReplayProducts::default(),
                        attested_transition: None,
                    })
                }
                ReplayOperation::Invoke {
                    invocation,
                    observed_slot,
                    ..
                } => {
                    if let Some(error) = self.refusal.take() {
                        return Ok(ReplayTransition {
                            state: before.clone(),
                            disposition: ReplayDisposition::Rejected,
                            result: Some(Err(error)),
                            next_runtime: input.runtime.clone(),
                            products: ReplayProducts::default(),
                            attested_transition: None,
                        });
                    }
                    runtime
                        .commit_exact_outcome_clock(invocation, *observed_slot)
                        .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                    Ok(ReplayTransition {
                        state: encode_standard_runtime_state(&runtime.snapshot()),
                        disposition: ReplayDisposition::Rejected,
                        result: Some(Err(ActorExecutionError::NotFound)),
                        next_runtime: input.runtime.clone(),
                        products: ReplayProducts::default(),
                        attested_transition: None,
                    })
                }
                ReplayOperation::Acknowledge { .. }
                | ReplayOperation::CleanManage { .. }
                | ReplayOperation::SealMerge => Err(LocalReplayExecutorError::InvalidRequest),
                ReplayOperation::CleanInvoke { .. }
                | ReplayOperation::CleanResume { .. }
                | ReplayOperation::CleanAcknowledge { .. } => Ok(ReplayTransition {
                    state: before.clone(),
                    disposition: ReplayDisposition::Rejected,
                    result: None,
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                    attested_transition: None,
                }),
            }
        }
    }

    fn initialized_core() -> LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor> {
        let sealed = super::super::replay::tests::admitted_local_genesis(0xe1);
        let node = sealed.replica().node;
        let mut store =
            MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, node).unwrap();
        assert_eq!(sealed.artifacts().artifacts.len(), 1);
        let runtime_bytes = b"replay-runtime-package";
        let runtime_reference = &sealed.artifacts().artifacts[0];
        assert!(runtime_reference.matches(runtime_bytes));
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                runtime_reference,
                runtime_bytes,
            )
            .unwrap();
        assert!(store.initialize_ordinary_for_test(&sealed).unwrap());
        LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap()
    }

    fn current_test_config(materialization: &ReplayMaterialization) -> AgentConfig {
        decode_standard_runtime_state(materialization.state())
            .unwrap()
            .config
            .unwrap()
    }

    fn admitted_authority_key() -> SigningKey {
        // `replay::tests::admitted_genesis` uses this fixed authority key.
        SigningKey::from_bytes(&[0x90; 32])
    }

    fn lifecycle_receipt(
        config: &AgentConfig,
        request: &LifecycleRequest,
        sequence: u64,
    ) -> AgentAuthorityReceipt {
        let mut credential = [0u8; 32];
        credential[..8].copy_from_slice(&sequence.to_le_bytes());
        let claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: CredentialId(credential),
            capability: CapabilityId::named(request.required_capability().unwrap()),
            operation: request.commitment(),
            sequence,
            valid_from: 10,
            valid_until: 1_000,
        };
        let signature = admitted_authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        AgentAuthorityReceipt { claim, signature }
    }

    fn deployment_signature(discriminator: u8) -> DeploymentSignature {
        let public_key = vec![discriminator; 32];
        DeploymentSignature {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: vec![discriminator; super::super::authority::ED25519_SIGNATURE_BYTES],
        }
    }

    fn host_surface_runtime_package(name: &str) -> Package {
        let pvm = include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec();
        let generated_interfaces = b"host-surface-runtime-interface".to_vec();
        let schemas = b"host-surface-runtime-schema".to_vec();
        Package {
            manifest: PackageManifest {
                name: name.into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: deployment_signature(0x71),
        }
    }

    const HOST_SURFACE_ACTOR_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        actor_name: "merge-fixture",
        messages: &[crate::metadata::MessageMeta {
            name: "mutate",
            is_query: false,
            fields: &[],
            returns: "()",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
            capability: None,
        }],
        constructor: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    const HOST_SURFACE_PARAMETERIZED_META: crate::metadata::ActorMeta =
        crate::metadata::ActorMeta {
            constructor: &[crate::metadata::FieldMeta {
                name: "tenant",
                ty: "u64",
            }],
            ..HOST_SURFACE_ACTOR_META
        };

    const HOST_SURFACE_STRING_PARAMETER_META: crate::metadata::ActorMeta =
        crate::metadata::ActorMeta {
            constructor: &[crate::metadata::FieldMeta {
                name: "tenant",
                ty: "String",
            }],
            ..HOST_SURFACE_ACTOR_META
        };

    const FRESH_UPGRADE_METHODS: &[crate::agent_sdk::schema::MethodMeta] =
        &[crate::agent_sdk::schema::MethodMeta {
            source_index: 0,
            name: "mutate",
            mode: crate::agent_sdk::MethodMode::Merge,
            explicit: false,
        }];
    const HOST_SURFACE_ACTOR_FIELDS: &[crate::agent_sdk::schema::FieldMeta] =
        &[crate::agent_sdk::schema::FieldMeta::Inline(
            crate::agent_sdk::schema::InlineFieldMeta {
                source_index: 0,
                name: "value",
                type_identity: "fixture::Vec<u8>",
                persistence: crate::agent_sdk::FieldPersistence::State(
                    crate::agent_sdk::StateLane::Merge,
                ),
            },
        )];
    const HOST_SURFACE_U64_CONSTRUCTOR: &[crate::agent_sdk::schema::ConstructorArgumentMeta] =
        &[crate::agent_sdk::schema::ConstructorArgumentMeta {
            name: "tenant",
            type_identity: "core::primitive::u64",
        }];
    const HOST_SURFACE_STRING_CONSTRUCTOR: &[crate::agent_sdk::schema::ConstructorArgumentMeta] =
        &[crate::agent_sdk::schema::ConstructorArgumentMeta {
            name: "tenant",
            type_identity: "alloc::string::String",
        }];
    const HOST_SURFACE_ACTOR_SCHEMA: crate::agent_sdk::schema::SchemaMeta =
        crate::agent_sdk::schema::SchemaMeta {
            constructor: crate::agent_sdk::schema::ConstructorMeta::Forbidden,
            fields: HOST_SURFACE_ACTOR_FIELDS,
            methods: FRESH_UPGRADE_METHODS,
        };
    const HOST_SURFACE_U64_SCHEMA: crate::agent_sdk::schema::SchemaMeta =
        crate::agent_sdk::schema::SchemaMeta {
            constructor: crate::agent_sdk::schema::ConstructorMeta::RequiredNamed(
                HOST_SURFACE_U64_CONSTRUCTOR,
            ),
            fields: HOST_SURFACE_ACTOR_FIELDS,
            methods: FRESH_UPGRADE_METHODS,
        };
    const HOST_SURFACE_STRING_SCHEMA: crate::agent_sdk::schema::SchemaMeta =
        crate::agent_sdk::schema::SchemaMeta {
            constructor: crate::agent_sdk::schema::ConstructorMeta::RequiredNamed(
                HOST_SURFACE_STRING_CONSTRUCTOR,
            ),
            fields: HOST_SURFACE_ACTOR_FIELDS,
            methods: FRESH_UPGRADE_METHODS,
        };
    const FRESH_UPGRADE_SCHEMA: crate::agent_sdk::schema::SchemaMeta =
        crate::agent_sdk::schema::SchemaMeta {
            constructor: crate::agent_sdk::schema::ConstructorMeta::Forbidden,
            fields: HOST_SURFACE_ACTOR_FIELDS,
            methods: FRESH_UPGRADE_METHODS,
        };

    fn host_surface_actor_package() -> Package {
        host_surface_actor_package_with_meta(&HOST_SURFACE_ACTOR_META)
    }

    fn host_surface_actor_package_with_meta(meta: &crate::metadata::ActorMeta) -> Package {
        let pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let (metadata_bytes, metadata_len) = crate::metadata::encode::<1024>(meta);
        let schemas = metadata_bytes[..metadata_len].to_vec();
        let metadata = crate::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&metadata)
            .unwrap()
            .encode();
        let schema = match meta.constructor {
            [] => &HOST_SURFACE_ACTOR_SCHEMA,
            [field] if field.name == "tenant" && field.ty == "u64" => &HOST_SURFACE_U64_SCHEMA,
            [field] if field.name == "tenant" && field.ty == "String" => {
                &HOST_SURFACE_STRING_SCHEMA
            }
            _ => panic!("unsupported host-surface constructor fixture"),
        };
        let (schema_bytes, schema_len) = crate::agent_sdk::schema::encode::<1024>(schema);
        let agent_schema = schema_bytes[..schema_len].to_vec();
        let parsed_schema = crate::agent_sdk::schema::decode(&agent_schema).unwrap();
        let requirements = sdk_actor_runtime_requirements(&parsed_schema, &metadata, false);
        let generated_interfaces = b"host-surface-actor-interface".to_vec();
        Package {
            manifest: PackageManifest {
                name: meta.actor_name.into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::Actor {
                    contract: ActorPackageContract::canonical(),
                    requirements,
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &agent_schema),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies,
            schemas,
            agent_schema,
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: deployment_signature(0x72),
        }
    }

    fn fresh_upgrade_actor_package(
        meta: &crate::metadata::ActorMeta,
        discriminator: u8,
    ) -> Package {
        let mut package = host_surface_actor_package_with_meta(meta);
        let (schema, schema_len) = crate::agent_sdk::schema::encode::<1024>(&FRESH_UPGRADE_SCHEMA);
        package.agent_schema = schema[..schema_len].to_vec();
        package.manifest.agent_schema_hash = artifact_hash(b"agent-schema", &package.agent_schema);
        package.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(StateLane::Merge),
                scheduling: false,
                proofs: false,
            },
        };
        package.pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: vec![discriminator],
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        package.manifest.program = ProgramId::of_pvm(&package.pvm);
        package.deployment_signature = deployment_signature(discriminator);
        package.validate().unwrap_or_else(|error| {
            panic!(
                "fresh actor package with {} constructor fields: {error:?}",
                meta.constructor.len()
            )
        });
        package
    }

    fn host_surface_config_and_runtime(name: &str) -> (AgentConfig, Package) {
        let template = super::super::replay::tests::admitted_local_genesis(0xe7);
        let mut config = decode_standard_runtime_state(template.post_create())
            .unwrap()
            .config
            .unwrap();
        let runtime_package = host_surface_runtime_package(name);
        config.identity.runtime_deployment = runtime_package.deployment_id();
        config.identity.runtime_program = runtime_package.manifest.program;
        config.identity.runtime_producer = runtime_package.deployment_signature.producer;
        config.runtime_package = BlobRef::of_bytes(&runtime_package.encode());
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = runtime_package.manifest.kind
        else {
            unreachable!()
        };
        config.runtime_contract = contract;
        config.capabilities = capabilities;
        config.system_authority_genesis = None;
        config.validate().unwrap();
        runtime_package.validate().unwrap();
        (config, runtime_package)
    }

    fn host_surface_driver() -> (
        LocalJournalAgentDriver<MemoryAgentJournalStore>,
        AgentConfig,
        Arc<dyn AgentTrustProvider>,
        Arc<dyn LocalMergeAuthenticator>,
    ) {
        let (config, runtime_package) = host_surface_config_and_runtime("host-surface-runtime");
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(StaticMerge(config.replicas[0].node));
        let create = LifecycleRequest::Create(config.clone());
        let receipt = lifecycle_receipt(&config, &create, 1);
        let (input, catalog) =
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::local_genesis_input(
                config.clone(),
                &runtime_package,
                receipt,
                &trust,
                &merge,
            )
            .unwrap();
        let sealed = LocalJournalAgentDriver::<MemoryAgentJournalStore>::prepare_local_genesis(
            input,
            config.replicas[0],
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        for blob in &catalog {
            store
                .put_blob(
                    JournalBlobClass::CatalogArtifact,
                    &blob.reference,
                    &blob.bytes,
                )
                .unwrap();
        }
        assert!(store.initialize_ordinary_for_test(&sealed).unwrap());
        let resolver = store.catalog_blob_resolver().unwrap();
        let executor =
            StandardLocalReplayExecutor::new(resolver, Arc::clone(&trust), Arc::clone(&merge));
        let core = LocalJournalCore::open(store, executor).unwrap();
        let driver = LocalJournalAgentDriver {
            core,
            lifecycle_fault: None,
        };
        driver.validate_opened(Some(config.replicas[0])).unwrap();
        (driver, config, trust, merge)
    }

    #[test]
    fn install_identity_is_idempotent_and_exact_across_journal_reopen() {
        let (mut driver, config, trust, merge) = host_surface_driver();
        let package = host_surface_actor_package();
        let installation_id = crate::service::InstallationId([0xa1; 32]);
        let registry_reservation = Hash([0xa2; 32]);
        let operation = driver
            .actor_install_operation(
                installation_id,
                registry_reservation,
                "journal-identity".into(),
                None,
                None,
                &package,
            )
            .unwrap();
        let request = operation.request().clone();
        let catalog = operation.catalog().to_vec();

        let first = driver
            .lifecycle(
                lifecycle_receipt(&config, &request, 2),
                request.clone(),
                &catalog,
            )
            .unwrap();
        let entry = match first.result.unwrap() {
            LifecycleReply::Installed(entry) => entry,
            other => panic!("unexpected install result: {other:?}"),
        };
        let first_record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(first_record.installation_id, installation_id);
        assert_eq!(first_record.registry_reservation, registry_reservation);

        let retry = driver
            .lifecycle(
                lifecycle_receipt(&config, &request, 3),
                request.clone(),
                &catalog,
            )
            .unwrap();
        assert_eq!(retry.result, Ok(LifecycleReply::Installed(entry.clone())));
        let retry_record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(retry_record, first_record);

        let mut mismatch = match request {
            LifecycleRequest::Install(install) => install,
            _ => unreachable!("fixture constructs an install"),
        };
        mismatch.registry_reservation = Hash([0xa3; 32]);
        let mismatch = LifecycleRequest::Install(mismatch);
        let rejected = driver
            .lifecycle(lifecycle_receipt(&config, &mismatch, 4), mismatch, &catalog)
            .unwrap();
        assert_eq!(rejected.result, Err(LifecycleError::InvalidRequest));
        assert_eq!(driver.inspect_actor(entry.actor).unwrap(), first_record);

        let store = driver.core.store;
        let reopened = LocalJournalAgentDriver::open(store, trust, merge).unwrap();
        assert_eq!(reopened.inspect_actor(entry.actor).unwrap(), first_record);
    }

    #[test]
    fn fresh_upgrade_catalog_preserves_the_installed_constructor_argument_shape() {
        fn installed_state(
            driver: &LocalJournalAgentDriver<MemoryAgentJournalStore>,
            config: &AgentConfig,
            package: &Package,
            installation_data: Option<Vec<u8>>,
            discriminator: u8,
        ) -> (RuntimeState, ActorEntry) {
            let catalog =
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(package);
            let PackageKind::Actor {
                contract,
                requirements,
            } = package.manifest.kind
            else {
                panic!("fixture is an actor package")
            };
            let name = format!("upgrade-shape-{discriminator}");
            let installation_data = installation_data.map(|bytes| super::super::InstallationData {
                reference: BlobRef::of_bytes(&bytes),
                bytes,
            });
            let parsed_schema = crate::agent_sdk::schema::decode(&package.agent_schema).unwrap();
            let constructor_abi = package.constructor_abi().unwrap();
            let entry = ActorEntry {
                actor: ActorId::top_level(config.identity.agent, &name),
                name,
                parent: None,
                deployment: package.deployment_id(),
                program: package.manifest.program,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                installation_data: installation_data
                    .as_ref()
                    .map(|data| data.reference.clone()),
                state_layout: Hash(parsed_schema.state_layout_hash().unwrap().0),
                lanes: requirements.lanes,
                suspended: false,
            };
            let request = LifecycleRequest::Install(InstallActor {
                installation_id: crate::service::InstallationId([discriminator; 32]),
                registry_reservation: Hash([discriminator.wrapping_add(1); 32]),
                entry: entry.clone(),
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                installation_data,
                state_layout: entry.state_layout,
                contract,
                requirements,
            });
            let request = authorized_at(config, request, 2, 20);
            let mut runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(driver.core.materialization.state()).unwrap(),
            )
            .unwrap();
            let reply = runtime.apply(request).unwrap();
            let LifecycleReply::Installed(entry) = reply else {
                panic!("expected installed actor")
            };
            (encode_standard_runtime_state(&runtime.snapshot()), entry)
        }

        fn upgrade_validation(
            driver: &LocalJournalAgentDriver<MemoryAgentJournalStore>,
            config: &AgentConfig,
            state: &RuntimeState,
            installed: &ActorEntry,
            target: &Package,
        ) -> Result<(), LocalReplayExecutorError> {
            let catalog =
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(target);
            let PackageKind::Actor {
                contract,
                requirements,
            } = target.manifest.kind
            else {
                panic!("fixture is an actor package")
            };
            let parsed_schema = crate::agent_sdk::schema::decode(&target.agent_schema).unwrap();
            let constructor_abi = target.constructor_abi().unwrap();
            let request = LifecycleRequest::UpgradeActor(UpgradeActor {
                actor: installed.actor,
                from_deployment: installed.deployment,
                to_deployment: target.deployment_id(),
                to_program: target.manifest.program,
                producer: target.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                state_layout: Hash(parsed_schema.state_layout_hash().unwrap().0),
                contract,
                requirements,
            });
            let target_reference = catalog[0].reference.clone();
            assert!(matches!(
                driver.core.executor.load(&target_reference),
                Err(LocalReplayExecutorError::ArtifactUnavailable(reference))
                    if reference == target_reference
            ));
            let authorized = authorized_at(config, request, 3, 20);
            driver.core.executor.validate_upgrade_installation_shape(
                state,
                &authorized,
                Some(&catalog),
            )
        }

        let driver = standard_test_driver();
        let config = current_test_config(&driver.core.materialization);
        let ordinary = fresh_upgrade_actor_package(&HOST_SURFACE_ACTOR_META, 0xb0);
        let ordinary_target = fresh_upgrade_actor_package(&HOST_SURFACE_ACTOR_META, 0xb1);
        let required = fresh_upgrade_actor_package(&HOST_SURFACE_PARAMETERIZED_META, 0xb2);
        let incompatible_typed =
            fresh_upgrade_actor_package(&HOST_SURFACE_STRING_PARAMETER_META, 0xb5);

        let (absent_state, absent_actor) = installed_state(&driver, &config, &ordinary, None, 0xb3);
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &absent_state,
                &absent_actor,
                &ordinary_target,
            ),
            Ok(()),
            "live admission must authenticate a fresh package from the supplied catalog"
        );
        assert_eq!(
            upgrade_validation(&driver, &config, &absent_state, &absent_actor, &required),
            Err(LocalReplayExecutorError::InvalidRequest),
            "an absent argument object cannot upgrade into a parameterized constructor"
        );

        let (present_state, present_actor) =
            installed_state(&driver, &config, &required, Some(vec![0x44]), 0xb4);
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &present_state,
                &present_actor,
                &ordinary_target,
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "immutable constructor arguments cannot be stranded by an upgrade"
        );
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &present_state,
                &present_actor,
                &incompatible_typed,
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "equal constructor presence cannot reinterpret typed argument bytes"
        );

        let target_catalog =
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(
                &ordinary_target,
            );
        let PackageKind::Actor {
            contract,
            requirements,
        } = ordinary_target.manifest.kind
        else {
            unreachable!()
        };
        let target_schema =
            crate::agent_sdk::schema::decode(&ordinary_target.agent_schema).unwrap();
        let busy_upgrade = authorized_at(
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor: absent_actor.actor,
                from_deployment: absent_actor.deployment,
                to_deployment: ordinary_target.deployment_id(),
                to_program: ordinary_target.manifest.program,
                producer: ordinary_target.deployment_signature.producer,
                package: target_catalog[0].reference.clone(),
                agent_schema: target_catalog[1].reference.clone(),
                role_policies: target_catalog[2].reference.clone(),
                constructor_abi: ordinary_target.constructor_abi().unwrap(),
                state_layout: Hash(target_schema.state_layout_hash().unwrap().0),
                contract,
                requirements,
            }),
            4,
            20,
        );
        let mut busy = decode_standard_runtime_state(&absent_state).unwrap();
        busy.actors[0].debt.lifecycle_operations = 1;
        let busy_state = encode_standard_runtime_state(&busy);
        let preflight = preflight_lifecycle_transition(&busy_state, &busy_upgrade).unwrap();
        assert!(matches!(preflight.result, Err(LifecycleError::Busy(_))));
        assert!(matches!(
            driver.core.executor.load(&target_catalog[0].reference),
            Err(LocalReplayExecutorError::ArtifactUnavailable(_))
        ));
        assert_eq!(
            driver.core.executor.validate_replayed_upgrade_target(
                &busy_state,
                &busy_upgrade,
                &preflight.result,
            ),
            Ok(()),
            "historical Busy replay must not resolve an unstaged target"
        );
    }

    #[test]
    fn lifecycle_catalog_staging_rolls_back_each_prepublication_failure_boundary() {
        for (index, fault) in [
            TestLifecycleFault::CatalogPutAfterFirst,
            TestLifecycleFault::BeforeMergeSeal,
            TestLifecycleFault::BeforeOrderedPublish,
        ]
        .into_iter()
        .enumerate()
        {
            let mut driver = standard_test_driver();
            let catalog = (0..3_u8)
                .map(|item| {
                    let bytes = vec![0xc0 + index as u8, item];
                    RuntimeBlob {
                        reference: BlobRef::of_bytes(&bytes),
                        bytes,
                    }
                })
                .collect::<Vec<_>>();
            let predecessor = driver.core.store.heads().unwrap().unwrap();

            // Content which predates the attempted transaction mints no
            // deletion capability and must survive every cleanup boundary.
            assert!(
                driver
                    .core
                    .store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &catalog[0].reference,
                        &catalog[0].bytes,
                    )
                    .unwrap()
            );
            if fault == TestLifecycleFault::CatalogPutAfterFirst {
                driver.lifecycle_fault = Some(fault);
                assert!(matches!(
                    driver.stage_catalog(&catalog),
                    Err(LocalJournalDriverError::Store(
                        JournalStoreError::Unavailable
                    ))
                ));
            } else {
                // These are the two error boundaries immediately after
                // staging in `lifecycle`: merge-seal preparation and ordered
                // publication. Both consume the same opaque transaction.
                let staged = driver.stage_catalog(&catalog).unwrap();
                driver.rollback_staged_catalog(staged).unwrap();
            }
            assert_eq!(driver.core.store.heads().unwrap(), Some(predecessor));
            assert_eq!(
                driver
                    .core
                    .store
                    .load_blob(JournalBlobClass::CatalogArtifact, &catalog[0].reference)
                    .unwrap(),
                Some(catalog[0].bytes.clone())
            );
            for blob in &catalog[1..] {
                assert_eq!(
                    driver
                        .core
                        .store
                        .load_blob(JournalBlobClass::CatalogArtifact, &blob.reference)
                        .unwrap(),
                    None,
                    "{fault:?} left an unpublished catalog orphan"
                );
                assert!(matches!(
                    driver.core.executor.load(&blob.reference),
                    Err(LocalReplayExecutorError::ArtifactUnavailable(_))
                ));
            }
        }
    }

    #[cfg(feature = "network")]
    #[test]
    fn ed25519_node_merge_authenticator_binds_the_full_peer_and_exact_event() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let expected_node =
            NodeId::of_authenticated_peer(&keypair.public().to_peer_id().to_bytes());
        let authenticator = Ed25519NodeMergeAuthenticator::new(keypair).unwrap();
        assert_eq!(authenticator.node(), expected_node);

        let core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0x91);
        let frontier = core
            .store
            .get::<MergeFrontier>(core.materialization.merge_frontier())
            .unwrap()
            .unwrap();
        let mut event = MergeEvent {
            genesis: core.materialization.heads().genesis,
            committee: None,
            author: expected_node,
            ordered_base: core.materialization.ordered_base(),
            causal_height: 1,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        assert!(authenticator.sign_event(&mut event));
        assert_eq!(
            event.signature.len(),
            super::super::authority::ED25519_SIGNATURE_BYTES
        );
        assert!(authenticator.verify_event(&event));
        assert!(!authenticator.sign_event(&mut event));

        let mut tampered = event.clone();
        tampered.signature[0] ^= 1;
        assert!(!authenticator.verify_event(&tampered));
        let mut wrong_author = event;
        wrong_author.author = NodeId([0x92; 32]);
        assert!(!authenticator.verify_event(&wrong_author));
    }

    #[test]
    fn memory_host_surface_builds_exact_management_operations() {
        let (mut driver, config, _, _) = host_surface_driver();
        assert_eq!(driver.config().unwrap(), config);
        assert_eq!(driver.identity().unwrap(), config.identity);
        assert_eq!(driver.publication_revision(), 0);

        let before_create_retry = driver.publication_revision();
        let forbidden_create = LifecycleRequest::Create(config.clone());
        assert_eq!(
            driver.lifecycle(
                lifecycle_receipt(&config, &forbidden_create, 2),
                forbidden_create,
                &[],
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        );
        assert_eq!(driver.publication_revision(), before_create_retry);

        let actor_package = host_surface_actor_package();
        actor_package.validate().unwrap();
        let operation = driver
            .actor_install_operation(
                crate::service::InstallationId([0x91; 32]),
                Hash([0x92; 32]),
                "merge-fixture".into(),
                None,
                None,
                &actor_package,
            )
            .unwrap();
        assert_eq!(operation.catalog().len(), 3);
        assert!(
            operation
                .catalog()
                .iter()
                .all(|blob| blob.reference.matches(&blob.bytes))
        );
        let install_receipt = lifecycle_receipt(&config, operation.request(), 2);
        let (request, catalog) = operation.into_parts();
        let installed = driver
            .lifecycle(install_receipt, request, &catalog)
            .unwrap();
        let entry = match installed.result.unwrap() {
            LifecycleReply::Installed(entry) => entry,
            other => panic!("unexpected install result: {other:?}"),
        };
        let record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(record.entry, entry);

        let suspend = driver.actor_suspend_operation(entry.actor).unwrap();
        assert!(suspend.catalog().is_empty());
        assert!(matches!(
            suspend.request(),
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            } if *actor == entry.actor && *expected_deployment == entry.deployment
        ));
        let resume = driver.actor_resume_operation(entry.actor).unwrap();
        assert!(resume.catalog().is_empty());
        let remove = driver
            .actor_remove_operation(entry.actor, entry.deployment)
            .unwrap();
        assert!(remove.catalog().is_empty());

        let actor_upgrade = driver
            .actor_upgrade_operation(entry.actor, entry.deployment, &actor_package)
            .unwrap();
        assert_eq!(actor_upgrade.catalog().len(), 3);
        assert!(matches!(
            actor_upgrade.request(),
            LifecycleRequest::UpgradeActor(upgrade)
                if upgrade.actor == entry.actor
                    && upgrade.from_deployment == entry.deployment
        ));

        let target_runtime = host_surface_runtime_package("host-surface-runtime-next");
        let runtime_upgrade = driver
            .runtime_upgrade_operation(config.identity.runtime_deployment, &target_runtime)
            .unwrap();
        assert_eq!(runtime_upgrade.catalog().len(), 1);
        assert!(matches!(
            runtime_upgrade.request(),
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment,
                package,
                ..
            } if *from_deployment == config.identity.runtime_deployment
                && *to_deployment == target_runtime.deployment_id()
                && package == &runtime_upgrade.catalog()[0].reference
        ));
    }

    fn authorized_at(
        config: &AgentConfig,
        request: LifecycleRequest,
        sequence: u64,
        slot: u64,
    ) -> LifecycleRequest {
        let receipt = lifecycle_receipt(config, &request, sequence);
        seal_lifecycle_request(
            &StaticTrust {
                slot: Some(slot),
                authority: Some(config.authority.clone()),
                trust_packages: true,
            },
            receipt,
            request,
        )
        .unwrap()
    }

    fn standard_test_driver() -> LocalJournalAgentDriver<MemoryAgentJournalStore> {
        let LocalJournalCore {
            store,
            materialization,
            ..
        } = initialized_core();
        let config = current_test_config(&materialization);
        let node = materialization.heads().node;
        let resolver = store.catalog_blob_resolver().unwrap();
        let executor = StandardLocalReplayExecutor::new(
            resolver,
            Arc::new(StaticTrust {
                slot: Some(20),
                authority: Some(config.authority),
                trust_packages: true,
            }),
            Arc::new(StaticMerge(node)),
        );
        LocalJournalAgentDriver {
            core: LocalJournalCore {
                store,
                materialization,
                executor,
            },
            lifecycle_fault: None,
        }
    }

    #[test]
    fn shared_ordered_result_provenance_survives_repeated_inputs_and_other_handoffs() {
        let mut driver = standard_test_driver();
        let executor = &mut driver.core.executor;
        executor.profile = AgentProfile::Shared;
        let input = ReplayInputId([0x41; 32]);
        let first = OrderedEntryId([0x51; 32]);
        let second = OrderedEntryId([0x52; 32]);
        let outcome_a = crate::agent_sdk::RuntimeOutcome::Completed(Err(
            crate::agent_sdk::InvocationError::NotFound,
        ));
        let outcome_b = crate::agent_sdk::RuntimeOutcome::Completed(Err(
            crate::agent_sdk::InvocationError::Suspended,
        ));
        let position = |id| ReplayPosition::Ordered {
            id,
            index: 1,
            merge_frontier: MergeFrontierId([0x61; 32]),
            merge_seal: None,
        };
        executor.record_clean_invocation_result_at(position(first), input, outcome_a.clone());
        executor.record_clean_invocation_result_at(position(second), input, outcome_b.clone());
        assert_eq!(
            executor.clean_ordered_result(input),
            Some(outcome_b.clone())
        );
        assert_eq!(
            executor.clean_ordered_result_at(first, input),
            Some(outcome_a.clone())
        );
        assert_eq!(
            executor.clean_ordered_result_at(second, input),
            Some(outcome_b.clone())
        );
        assert_eq!(
            executor.clean_ordered_result_at(first, ReplayInputId([0x42; 32])),
            None
        );
        for value in 0..=MAX_PENDING_CLEAN_INVOCATION_RESULTS {
            let mut id = [0x71; 32];
            id[..8].copy_from_slice(&(value as u64).to_le_bytes());
            executor.record_clean_invocation_result(ReplayInputId(id), outcome_a.clone());
        }
        assert_eq!(
            executor.clean_ordered_result_at(first, input),
            Some(outcome_a.clone())
        );
        assert_eq!(
            executor.clean_ordered_result_at(second, input),
            Some(outcome_b.clone())
        );
        // Restore the ordinary latest pointer, then evict A from the exact
        // FIFO without removing the pointer to the newer B occurrence.
        executor.record_clean_invocation_result_at(position(second), input, outcome_b.clone());
        for value in 0..MAX_PENDING_CLEAN_INVOCATION_RESULTS - 1 {
            let mut id = [0x81; 32];
            id[..8].copy_from_slice(&(value as u64).to_le_bytes());
            executor.record_clean_invocation_result_at(
                position(OrderedEntryId(id)),
                ReplayInputId(id),
                outcome_a.clone(),
            );
        }
        assert_eq!(executor.clean_ordered_result_at(first, input), None);
        assert_eq!(
            executor.clean_ordered_result_at(second, input),
            Some(outcome_b.clone())
        );
        assert_eq!(executor.clean_ordered_result(input), Some(outcome_b));
        assert_eq!(
            executor.positioned_clean_results.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
        assert_eq!(
            executor.positioned_clean_order.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
    }

    #[test]
    fn clean_reply_handoff_and_management_recovery_are_keyed_and_bounded() {
        let mut driver = standard_test_driver();
        let first = ReplayInputId([0x11; 32]);
        let second = ReplayInputId([0x22; 32]);
        let first_outcome = crate::agent_sdk::RuntimeOutcome::Completed(Err(
            crate::agent_sdk::InvocationError::NotFound,
        ));
        let second_outcome = crate::agent_sdk::RuntimeOutcome::Completed(Err(
            crate::agent_sdk::InvocationError::Suspended,
        ));
        driver
            .core
            .executor
            .record_clean_invocation_result(first, first_outcome.clone());
        driver
            .core
            .executor
            .record_clean_invocation_result(second, second_outcome.clone());

        assert_eq!(
            driver.core.executor.take_clean_invocation_result(first),
            Some(first_outcome.clone())
        );
        assert_eq!(
            driver.core.executor.take_clean_invocation_result(second),
            Some(second_outcome)
        );
        assert_eq!(
            driver.core.executor.take_clean_invocation_result(first),
            None,
            "the synchronous handoff remains one-shot"
        );

        for value in 0..=MAX_PENDING_CLEAN_INVOCATION_RESULTS {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(value as u64).to_le_bytes());
            id[31] = 1;
            driver.core.executor.record_clean_invocation_result(
                ReplayInputId(id),
                crate::agent_sdk::RuntimeOutcome::Completed(Err(
                    crate::agent_sdk::InvocationError::NotFound,
                )),
            );
        }
        assert_eq!(
            driver.core.executor.pending_clean_invocation_results.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );

        let management_outcome = crate::agent_sdk::RuntimeOutcome::Management(Err(
            crate::agent_sdk::ManagementError::NotFound,
        ));
        for value in 0..=MAX_PENDING_CLEAN_INVOCATION_RESULTS {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(value as u64).to_le_bytes());
            id[31] = 2;
            driver
                .core
                .executor
                .record_clean_management_result(ReplayInputId(id), management_outcome.clone());
        }
        let mut oldest = [0; 32];
        oldest[31] = 2;
        assert_eq!(
            driver
                .core
                .executor
                .clean_management_result(ReplayInputId(oldest)),
            None,
            "FIFO eviction is aligned with the newest durable suffix"
        );
        let mut newest = [0; 32];
        newest[..8].copy_from_slice(&(MAX_PENDING_CLEAN_INVOCATION_RESULTS as u64).to_le_bytes());
        newest[31] = 2;
        assert!(
            driver
                .core
                .executor
                .clean_management_result(ReplayInputId(newest))
                .is_some()
        );
        assert_eq!(
            driver.core.executor.recent_clean_management_results.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
        assert_eq!(
            driver.core.executor.recent_clean_management_order.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );

        let executor = &mut driver.core.executor;
        let ordered_before = executor.recent_clean_ordered_order.clone();
        let management_before = executor.recent_clean_management_order.clone();
        let oldest_live = *management_before.front().unwrap();
        let replacement = crate::agent_sdk::RuntimeOutcome::Management(Err(
            crate::agent_sdk::ManagementError::InvalidRequest,
        ));
        executor.record_clean_management_result(oldest_live, replacement.clone());
        assert_eq!(executor.recent_clean_ordered_order, ordered_before);
        assert_eq!(executor.recent_clean_management_order, management_before);
        assert_eq!(
            executor.clean_ordered_result(oldest_live),
            Some(replacement.clone())
        );
        assert_eq!(
            executor.clean_management_result(oldest_live),
            Some(replacement.clone())
        );
        assert_eq!(
            executor.take_clean_invocation_result(oldest_live),
            Some(replacement)
        );
        assert_eq!(executor.take_clean_invocation_result(oldest_live), None);

        executor.record_clean_management_result(ReplayInputId([0xff; 32]), management_outcome);
        assert_eq!(executor.clean_ordered_result(oldest_live), None);
        assert_eq!(executor.clean_management_result(oldest_live), None);
        assert_eq!(
            executor.recent_clean_ordered_results.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
        assert_eq!(
            executor.recent_clean_management_results.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
        assert_eq!(
            executor.recent_clean_ordered_order.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
        assert_eq!(
            executor.recent_clean_management_order.len(),
            MAX_PENDING_CLEAN_INVOCATION_RESULTS
        );
    }

    fn clean_scan_operation(seed: u8) -> ReplayOperation {
        let work = crate::agent_sdk::InvocationWork {
            space: crate::agent_sdk::SpaceId([0x11; 32]),
            agent: crate::agent_sdk::AgentId([0x12; 32]),
            runtime_deployment: crate::agent_sdk::DeploymentId([0x13; 32]),
            invocation: crate::agent_sdk::InvocationId([seed; 32]),
            actor: crate::agent_sdk::ActorId([0x14; 32]),
            incarnation: crate::agent_sdk::Hash([0x15; 32]),
            deployment: crate::agent_sdk::DeploymentId([0x16; 32]),
            program: crate::agent_sdk::ProgramId([0x17; 32]),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: vec![seed],
            installation_data: None,
            availability: Vec::new(),
            gas: 100,
            recovery_only: false,
        };
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
            observed_slot: 20,
        }
    }

    #[test]
    fn terminal_preflight_matches_physical_output_without_bypassing_authentication_or_limits() {
        let (mut input, before, published) = scripted_attested_transition(0xb1);
        let ReplayOperation::CleanInvoke { context, work, .. } = &mut input.operation else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Direct;
        let gas = DEFAULT_MANAGEMENT_GAS.saturating_add(work.gas);
        let mut sdk_work =
            crate::agent_sdk::RuntimeWork::decode(&published.canonical_work).unwrap();
        let crate::agent_sdk::RuntimeWork::Invoke { context, .. } = &mut sdk_work else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Direct;
        let encoded = sdk_work.encode().unwrap();
        let runtime = super::super::package_admission::admitted_scripted_runtime_for_test(
            "terminal-preflight-equivalence",
            0xb2,
            vec![super::super::package_admission::ScriptedRuntimeCase {
                input: encoded.clone(),
                output: published.canonical_transition,
                copies: Vec::new(),
            }],
        );
        let resolver = SuppliedCatalogBlobResolver::from_catalog(&[]).unwrap();
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: None,
            trust_packages: false,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(NodeId([0xb3; 32])));
        let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let transition: crate::agent_sdk::RuntimeTransition = executor
            .execute_agent_wire(runtime.program_bytes(), gas, &encoded)
            .unwrap();
        let candidate = || {
            Some(TerminalPreflight {
                runtime_pvm: runtime.program_bytes().to_vec(),
                input: encoded.clone(),
                gas,
                transition: transition.clone(),
            })
        };
        let position = ReplayPosition::Merge {
            id: MergeEventId([0xb4; 32]),
            causal_height: 1,
            ordered_base: super::super::journal::OrderedBase::post_genesis(),
        };
        *executor.terminal_preflight.get_mut().unwrap() = candidate();
        assert!(
            matches!(
                executor.execute(&input, &before, position),
                Err(LocalReplayExecutorError::InvalidAuthority)
            ),
            "prepared computation must not grant an authentication capability"
        );

        // Exercise the post-authentication execution helper directly, just as
        // the Attested provider tests do. Only the first call can consume reuse.
        let cached = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                position,
                ReplayTransitionProofAccess::PublishedOnly,
                runtime.program_bytes(),
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                false,
            )
            .unwrap();
        assert!(executor.terminal_preflight.get_mut().unwrap().is_none());
        let cached_outcome = executor.take_clean_invocation_result(input.id()).unwrap();
        let physical = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                position,
                ReplayTransitionProofAccess::PublishedOnly,
                runtime.program_bytes(),
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                false,
            )
            .unwrap();
        assert_eq!(cached, physical);
        assert_eq!(
            cached_outcome,
            executor.take_clean_invocation_result(input.id()).unwrap()
        );
        assert_eq!(cached_outcome, transition.outcome);

        *executor.terminal_preflight.get_mut().unwrap() = candidate();
        assert!(matches!(
            executor.execute_clean_invocation_transition(
                &input,
                &before,
                position,
                ReplayTransitionProofAccess::PublishedOnly,
                runtime.program_bytes(),
                0,
                false,
            ),
            Err(LocalReplayExecutorError::RuntimeStateTooLarge)
        ));
        assert!(executor.terminal_preflight.get_mut().unwrap().is_none());
    }

    #[test]
    fn standard_executor_consumes_exact_verified_binding_once_and_reuses_published_merge_work() {
        let (input, before, published) = scripted_attested_transition(0xc1);
        let hostile_preflight_input = published.canonical_work.clone();
        let prepare_calls = Arc::new(AtomicU64::new(0));
        let published_calls = Arc::new(AtomicU64::new(0));
        let provider = ScriptedAttestedProvider {
            preparations: VecDeque::from([
                AttestedReplayTransitionPreparation::from_published(published.clone()),
                AttestedReplayTransitionPreparation::from_published(published),
            ]),
            published: VecDeque::new(),
            prepare_calls: Arc::clone(&prepare_calls),
            published_calls: Arc::clone(&published_calls),
        };
        let resolver = SuppliedCatalogBlobResolver::from_catalog(&[]).unwrap();
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: None,
            trust_packages: false,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(NodeId([0xc2; 32])));
        let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        executor.replace_attested_transition_provider(Box::new(provider));
        executor.begin_transition_proof_batch();
        // Even a test-injected exact Attested tuple must not bypass the proof
        // provider. Production preflight only prepares Direct work.
        *executor.terminal_preflight.get_mut().unwrap() = Some(TerminalPreflight {
            runtime_pvm: Vec::new(),
            input: hostile_preflight_input,
            gas: DEFAULT_MANAGEMENT_GAS + 100,
            transition: crate::agent_sdk::RuntimeTransition {
                state: crate::agent_sdk::RuntimeState::default(),
                outcome: crate::agent_sdk::RuntimeOutcome::Completed(Err(
                    crate::agent_sdk::InvocationError::NotFound,
                )),
            },
        });

        let first_position = ReplayPosition::Merge {
            id: MergeEventId([0xc3; 32]),
            causal_height: 1,
            ordered_base: super::super::journal::OrderedBase::post_genesis(),
        };
        let first = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                first_position,
                ReplayTransitionProofAccess::PrepareAllowed,
                &[],
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                true,
            )
            .unwrap();
        let first_binding = executor
            .take_transition_proof_binding(&input, &before, first_position, &first)
            .unwrap()
            .expect("fresh prepared proof binds the exact replay transition");
        assert_eq!(Some(first_binding.transition()), first.attested_transition);
        assert_eq!(
            first_binding.projection(),
            ReplayTransitionProofProjection::Published
        );
        assert!(
            executor
                .take_transition_proof_binding(&input, &before, first_position, &first)
                .unwrap()
                .is_none(),
            "the proof capability is one-shot"
        );
        assert!(executor.take_staged_transition_proofs().is_empty());

        executor.begin_transition_proof_batch();
        let fence_replay_position = ReplayPosition::Merge {
            id: MergeEventId([0xc4; 32]),
            causal_height: 2,
            ordered_base: super::super::journal::OrderedBase::post_genesis(),
        };
        let replayed = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                fence_replay_position,
                ReplayTransitionProofAccess::PrepareAllowed,
                &[],
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                true,
            )
            .unwrap();
        let fence_binding = executor
            .take_transition_proof_binding(&input, &before, fence_replay_position, &replayed)
            .unwrap()
            .expect("the retained published tuple covers fence replay");
        assert_eq!(
            fence_binding.projection(),
            ReplayTransitionProofProjection::Published
        );
        assert!(executor.take_staged_transition_proofs().is_empty());
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 2);
        assert_eq!(published_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn standard_executor_drops_pending_binding_on_mismatch_or_batch_reset() {
        let (input, before, published) = scripted_attested_transition(0xc5);
        let prepare_calls = Arc::new(AtomicU64::new(0));
        let published_calls = Arc::new(AtomicU64::new(0));
        let provider = ScriptedAttestedProvider {
            preparations: VecDeque::new(),
            published: VecDeque::from([published.clone()]),
            prepare_calls: Arc::clone(&prepare_calls),
            published_calls: Arc::clone(&published_calls),
        };
        let resolver = SuppliedCatalogBlobResolver::from_catalog(&[]).unwrap();
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: None,
            trust_packages: false,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(NodeId([0xc6; 32])));
        let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        executor.replace_attested_transition_provider(Box::new(provider));
        let position = ReplayPosition::Merge {
            id: MergeEventId([0xc7; 32]),
            causal_height: 1,
            ordered_base: super::super::journal::OrderedBase::post_genesis(),
        };
        let replayed = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                position,
                ReplayTransitionProofAccess::PublishedOnly,
                &[],
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                true,
            )
            .unwrap();
        let wrong_position = ReplayPosition::Merge {
            id: MergeEventId([0xc8; 32]),
            causal_height: 1,
            ordered_base: super::super::journal::OrderedBase::post_genesis(),
        };
        assert_eq!(
            executor.take_transition_proof_binding(&input, &before, wrong_position, &replayed,),
            Err(LocalReplayExecutorError::InvalidState)
        );
        assert!(executor.take_staged_transition_proofs().is_empty());
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(published_calls.load(Ordering::SeqCst), 1);

        let provider = ScriptedAttestedProvider {
            preparations: VecDeque::new(),
            published: VecDeque::from([published]),
            prepare_calls: Arc::new(AtomicU64::new(0)),
            published_calls: Arc::new(AtomicU64::new(0)),
        };
        executor.replace_attested_transition_provider(Box::new(provider));
        let replayed = executor
            .execute_clean_invocation_transition(
                &input,
                &before,
                position,
                ReplayTransitionProofAccess::PublishedOnly,
                &[],
                super::super::execution::MAX_RUNTIME_STATE_BYTES,
                true,
            )
            .unwrap();
        executor.begin_transition_proof_batch();
        assert!(
            executor
                .take_transition_proof_binding(&input, &before, position, &replayed)
                .unwrap()
                .is_none()
        );
        assert!(executor.take_staged_transition_proofs().is_empty());
    }

    #[test]
    fn clean_retry_identity_ignores_only_trusted_slot_and_keeps_lifecycle_exact() {
        let invoke = clean_scan_operation(0xd1);
        let mut shifted = invoke.clone();
        let ReplayOperation::CleanInvoke { observed_slot, .. } = &mut shifted else {
            unreachable!()
        };
        *observed_slot = 99;
        assert!(clean_operation_retry_equal(&invoke, &shifted));

        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            ..
        } = invoke.clone()
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
            continuation: crate::agent_sdk::BlobRef::of_bytes(b"bounded-scan-continuation"),
            ready_sequence: 7,
            installation_data: None,
            required: Vec::new(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        let resume = ReplayOperation::CleanResume {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: work.clone(),
            authorization: authorization.clone(),
            yielded: yielded.clone(),
            observed_slot: 20,
        };
        let mut shifted_resume = resume.clone();
        let ReplayOperation::CleanResume { observed_slot, .. } = &mut shifted_resume else {
            unreachable!()
        };
        *observed_slot = 100;
        assert!(clean_operation_retry_equal(&resume, &shifted_resume));

        let mut divergent_resume = resume.clone();
        let ReplayOperation::CleanResume { yielded, .. } = &mut divergent_resume else {
            unreachable!()
        };
        yielded.ready_sequence += 1;
        assert!(!clean_operation_retry_equal(&resume, &divergent_resume));
        let mut divergent_live_resume = resume.clone();
        let ReplayOperation::CleanResume { expected_live, .. } = &mut divergent_live_resume else {
            unreachable!()
        };
        *expected_live = Some(crate::agent_sdk::proof::TransitionProofKey {
            invocation: work.invocation,
            execution: crate::agent_sdk::Hash([0x9d; 32]),
        });
        assert!(!clean_operation_retry_equal(
            &resume,
            &divergent_live_resume
        ));
        assert!(!clean_operation_retry_equal(
            &invoke,
            &ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                authorization,
            }
        ));
    }

    #[test]
    fn clean_ordered_lifecycle_exact_bytes_survive_response_loss_and_reopen_without_new_slots() {
        let mut core = initialized_core();
        let binding = core.materialization.runtime().clone();
        let ReplayOperation::CleanInvoke { mut work, .. } = clean_scan_operation(0xd8) else {
            unreachable!()
        };
        work.space = crate::agent_sdk::SpaceId(binding.space.0);
        work.agent = crate::agent_sdk::AgentId(binding.agent.0);
        work.runtime_deployment = crate::agent_sdk::DeploymentId(binding.deployment.0);
        let authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 20),
        );
        let yielded = crate::agent_sdk::YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: crate::agent_sdk::BlobRef::of_bytes(b"durable-response-loss-selector"),
            ready_sequence: 1,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        let operations = [
            ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
                observed_slot: 20,
            },
            ReplayOperation::CleanResume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: work.clone(),
                authorization: authorization.clone(),
                yielded,
                observed_slot: 21,
            },
            ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(&work),
                authorization: authorization.clone(),
            },
        ];
        let mut persisted = Vec::new();
        for operation in &operations {
            let input = ReplayInput {
                runtime: binding.clone(),
                operation: operation.clone(),
            };
            input.validate().unwrap();
            let exact = input.encode();
            let publication = TestPublication::for_input(&core, input);
            let TestPublication::Ordered(entry) = &publication else {
                panic!("Linear clean lifecycle must use the Ordered lane")
            };
            persisted.push((entry.id(), exact));
            publication.publish(&mut core).unwrap();
        }
        let ordered_index = core.materialization.heads().ordered_index;
        let store = core.store.clone();
        drop(core);

        let reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        assert_eq!(
            reopened.materialization.heads().ordered_index,
            ordered_index
        );
        for (entry, exact) in persisted {
            let stored = reopened.store.get::<OrderedEntry>(entry).unwrap().unwrap();
            assert_eq!(stored.input.encode(), exact);
        }
        let acknowledged_input = reopened
            .store
            .get::<OrderedEntry>(reopened.materialization.heads().ordered_head.unwrap())
            .unwrap()
            .unwrap()
            .input
            .id();
        assert_eq!(
            recent_clean_ordered_operation(
                &reopened.store,
                &reopened.materialization,
                &operations[2],
            )
            .unwrap(),
            Some(acknowledged_input)
        );
        assert_eq!(
            recent_clean_ordered_operation(
                &reopened.store,
                &reopened.materialization,
                &operations[1],
            )
            .unwrap(),
            None,
            "the durable acknowledgement prevents an older Resume response from shadowing it"
        );
        assert_eq!(
            reopened.materialization.heads().ordered_index,
            ordered_index,
            "durable retry lookup never prepares or publishes another slot"
        );
    }

    #[test]
    fn clean_retry_walks_fail_backpressure_at_their_exact_scope_bound() {
        fn publish_two(
            core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
            mode: MethodMode,
        ) {
            for seed in [0xd2, 0xd3] {
                let input = invocation_input(&core.materialization, mode, seed);
                TestPublication::for_input(core, input)
                    .publish(core)
                    .unwrap();
            }
        }

        let target = clean_scan_operation(0xd4);

        let mut ordered = initialized_core();
        publish_two(&mut ordered, MethodMode::Linear);
        assert_eq!(
            recent_clean_ordered_operation_bounded(
                &ordered.store,
                &ordered.materialization,
                &target,
                1,
            ),
            Err(JournalStoreError::Backpressure)
        );

        let mut local = initialized_core();
        publish_two(&mut local, MethodMode::Local);
        assert_eq!(
            recent_clean_local_operation_bounded(&local.store, &local.materialization, &target, 1,),
            Err(JournalStoreError::Backpressure)
        );

        let mut merge = initialized_core();
        publish_two(&mut merge, MethodMode::Merge);
        assert_eq!(
            recent_clean_merge_operation_bounded(&merge.store, &merge.materialization, &target, 1,),
            Err(JournalStoreError::Backpressure)
        );
    }

    #[test]
    fn local_lifecycle_surface_rejects_direct_system_authority_commands() {
        let sealed = super::super::replay::tests::admitted_genesis(0xe9);
        let finalize = super::super::replay::tests::admitted_finalize_for_test(&sealed, 2);
        let mut driver = standard_test_driver();
        let config = current_test_config(&driver.core.materialization);
        let dummy = LifecycleRequest::Suspend {
            actor: ActorId([0xea; 32]),
            expected_deployment: DeploymentId([0xeb; 32]),
        };
        let receipt = lifecycle_receipt(&config, &dummy, 2);
        let heads_before = driver.core.store.heads().unwrap().unwrap();
        assert!(matches!(
            driver.lifecycle(
                receipt,
                LifecycleRequest::FinalizeSystemAuthority(finalize),
                &[],
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        ));
        assert_eq!(driver.core.store.heads().unwrap().unwrap(), heads_before);
    }

    fn invocation_input(
        materialization: &ReplayMaterialization,
        mode: MethodMode,
        discriminator: u8,
    ) -> ReplayInput {
        let config = decode_standard_runtime_state(materialization.state())
            .unwrap()
            .config
            .unwrap();
        let invocation = ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: Hash([discriminator.wrapping_add(2); 32]),
            deployment: DeploymentId([discriminator.wrapping_add(3); 32]),
            program: ProgramId([discriminator.wrapping_add(4); 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![discriminator],
            availability: Vec::new(),
            gas: 100,
        };
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: config.authority,
                space: config.identity.space,
                agent: config.identity.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 100,
            },
            // ReplayInput canonicality checks the exact claim linkage and
            // signature shape. ExactTestExecutor is the explicit test trust
            // boundary and deliberately accepts this fixed signature.
            signature: vec![0x5a; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime: materialization.runtime().clone(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot: 10,
            },
        }
    }

    fn local_entry(materialization: &ReplayMaterialization, input: ReplayInput) -> LocalEntry {
        let heads = materialization.heads();
        LocalEntry {
            genesis: heads.genesis,
            node: heads.node,
            revision: heads.local_revision + 1,
            parent: heads.local_head,
            ordered_base: materialization.ordered_base(),
            merge_frontier: materialization.merge_frontier(),
            input,
        }
    }

    fn persist_test_merge_seal(
        core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
    ) -> super::super::journal::MergeSealId {
        let state = &core.materialization.state().merge;
        let reference = BlobRef::of_bytes(state);
        core.store
            .put_blob(JournalBlobClass::LaneState, &reference, state)
            .unwrap();
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            core.materialization.heads().genesis,
            core.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: core.materialization.merge_frontier(),
            },
            state,
        )
        .unwrap();
        core.store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: core.materialization.heads().genesis,
            frontier: core.materialization.merge_frontier(),
            ordered_base: core.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        core.store.put(&seal).unwrap();
        seal.id()
    }

    fn finalize_test_merge(
        core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
    ) -> LocalCorePublication {
        let merge_seal = persist_test_merge_seal(core);
        let heads = core.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads.ordered_index + 1,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: heads.runtime.clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        core.publish_ordered(&entry).unwrap()
    }

    fn acknowledgement_for(
        materialization: &ReplayMaterialization,
        input: &ReplayInput,
        message_byte: u8,
    ) -> ReplayInput {
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            panic!("acknowledgement helper requires an invocation")
        };
        let mut invocation = invocation.clone();
        invocation.message = vec![message_byte];
        let config = current_test_config(materialization);
        assert_eq!(input.runtime.agent, config.identity.agent);
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: config.authority,
                space: config.identity.space,
                agent: config.identity.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 100,
            },
            signature: vec![0x5a; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime: input.runtime.clone(),
            operation: ReplayOperation::Acknowledge {
                invocation,
                authority,
            },
        }
    }

    #[derive(Clone)]
    enum TestPublication {
        Ordered(OrderedEntry),
        Local(LocalEntry),
        Merge(MergeEvent),
    }

    impl TestPublication {
        fn for_input(
            core: &LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
            input: ReplayInput,
        ) -> Self {
            let heads = core.materialization.heads();
            let scope = match &input.operation {
                ReplayOperation::Invoke { invocation, .. }
                | ReplayOperation::Acknowledge { invocation, .. } => {
                    invocation.mode.invocation_scope()
                }
                ReplayOperation::CleanInvoke {
                    work: crate::agent_sdk::InvocationWork { mode, .. },
                    ..
                }
                | ReplayOperation::CleanResume {
                    work: crate::agent_sdk::InvocationWork { mode, .. },
                    ..
                }
                | ReplayOperation::CleanAcknowledge {
                    work: crate::agent_sdk::InvocationRetirement { mode, .. },
                    ..
                } => match mode {
                    crate::agent_sdk::MethodMode::Query
                    | crate::agent_sdk::MethodMode::LinearizableQuery
                    | crate::agent_sdk::MethodMode::Linear => InvocationScope::Ordered,
                    crate::agent_sdk::MethodMode::Merge => InvocationScope::Merge,
                    crate::agent_sdk::MethodMode::LocalQuery
                    | crate::agent_sdk::MethodMode::Local => InvocationScope::Local,
                },
                _ => panic!("test publication requires an invocation operation"),
            };
            match scope {
                InvocationScope::Ordered => Self::Ordered(OrderedEntry {
                    genesis: heads.genesis,
                    index: heads.ordered_index + 1,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input,
                }),
                InvocationScope::Local => Self::Local(local_entry(&core.materialization, input)),
                InvocationScope::Merge => {
                    let frontier = core
                        .store
                        .get::<MergeFrontier>(core.materialization.merge_frontier())
                        .unwrap()
                        .unwrap();
                    let causal_height = frontier
                        .events
                        .iter()
                        .map(|id| {
                            core.store
                                .get::<MergeEvent>(*id)
                                .unwrap()
                                .unwrap()
                                .causal_height
                        })
                        .max()
                        .unwrap_or(0)
                        + 1;
                    Self::Merge(MergeEvent {
                        genesis: heads.genesis,
                        committee: None,
                        author: heads.node,
                        ordered_base: core.materialization.ordered_base(),
                        causal_height,
                        parents: frontier.events,
                        input,
                        signature: vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES],
                    })
                }
            }
        }

        fn position(&self) -> ReplayPosition {
            match self {
                Self::Ordered(entry) => ReplayPosition::Ordered {
                    id: entry.id(),
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
                Self::Local(entry) => ReplayPosition::Local {
                    id: entry.id(),
                    node: entry.node,
                    revision: entry.revision,
                    ordered_base: entry.ordered_base,
                    merge_frontier: entry.merge_frontier,
                },
                Self::Merge(event) => ReplayPosition::Merge {
                    id: event.id(),
                    causal_height: event.causal_height,
                    ordered_base: event.ordered_base,
                },
            }
        }

        fn publish(
            &self,
            core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
        ) -> Result<LocalCorePublication, LocalJournalDriverError> {
            match self {
                Self::Ordered(entry) => core.publish_ordered(entry),
                Self::Local(entry) => core.publish_local(entry),
                Self::Merge(event) => core.publish_merge(event),
            }
        }
    }

    #[test]
    fn applied_runtime_upgrade_uses_the_target_signed_state_ceiling() {
        let driver = standard_test_driver();
        let mut target =
            decode_standard_runtime_state(driver.core.materialization.state()).unwrap();
        target
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = super::super::execution::MAX_RUNTIME_STATE_BYTES as u32;
        let returned = encode_standard_runtime_state(&target);

        let mut current = target.config.as_ref().unwrap().clone();
        current.runtime_contract.resources.max_runtime_state_bytes = 1;
        assert!(
            driver
                .core
                .executor
                .validate_state_size(&returned, &current)
                .is_err(),
            "the successor intentionally exceeds the old signed ceiling"
        );

        let selected = driver
            .core
            .executor
            .management_state_config(&returned, &current, true)
            .unwrap();
        assert_eq!(selected, target.config.unwrap());
        driver
            .core
            .executor
            .validate_state_size(&returned, &selected)
            .unwrap();
        assert_eq!(
            driver
                .core
                .executor
                .management_state_config(&returned, &current, false)
                .unwrap(),
            current,
            "rejected and non-upgrade management stays under the current contract"
        );
    }

    #[test]
    fn create_preflight_rejects_profile_trust_binding_and_package_before_store_writes() {
        let sealed = super::super::replay::tests::admitted_local_genesis(0xe4);
        let node = sealed.replica().node;
        let store = MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, node).unwrap();
        let decoded = decode_standard_runtime_state(sealed.post_create()).unwrap();
        let config = decoded.config.as_ref().unwrap();
        let catalog = [RuntimeBlob {
            reference: sealed.artifacts().artifacts[0].clone(),
            bytes: b"replay-runtime-package".to_vec(),
        }];
        let trusted: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(node));

        assert!(matches!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::preflight_local_create(
                &sealed,
                &catalog,
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidArtifact(reference)
            )) if reference == catalog[0].reference
        ));

        let resolver = SuppliedCatalogBlobResolver::from_catalog(&catalog).unwrap();
        let mut shared = decoded.clone();
        shared.config.as_mut().unwrap().identity.profile = AgentProfile::Shared;
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                &encode_standard_runtime_state(&shared),
                sealed.genesis().runtime(),
                sealed.replica(),
                resolver.clone(),
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidProfile
            ))
        );

        let rejecting_trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: None,
            trust_packages: false,
        });
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                sealed.post_create(),
                sealed.genesis().runtime(),
                sealed.replica(),
                resolver.clone(),
                &rejecting_trust,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );

        let mut wrong_binding = sealed.genesis().runtime().clone();
        wrong_binding.runtime_abi = Hash([0xee; 32]);
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                sealed.post_create(),
                &wrong_binding,
                sealed.replica(),
                resolver,
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidState
            ))
        );

        assert_eq!(store.genesis().unwrap(), None);
        assert_eq!(store.heads().unwrap(), None);
        assert_eq!(
            store
                .load_blob(JournalBlobClass::CatalogArtifact, &catalog[0].reference)
                .unwrap(),
            None,
            "every semantic create failure precedes catalog staging"
        );
    }

    #[test]
    fn lifecycle_admission_seals_only_the_trusted_slot_and_ratchets_that_h() {
        let core = initialized_core();
        let decoded = decode_standard_runtime_state(core.materialization.state()).unwrap();
        let config = decoded.config.clone().unwrap();
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xc1; 32]),
            expected_deployment: DeploymentId([0xc2; 32]),
        };
        let receipt = lifecycle_receipt(&config, &inner, 2);
        let trust = StaticTrust {
            slot: Some(77),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        };
        let sealed = seal_lifecycle_request(&trust, receipt.clone(), inner.clone()).unwrap();
        assert!(matches!(
            &sealed,
            LifecycleRequest::Authorized { admission, request }
                if admission.observed_slot == 77 && request.as_ref() == &inner
        ));

        let mut runtime = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            runtime.apply(sealed),
            Err(LifecycleError::NotFound),
            "a fresh deterministic refusal still consumes authority H"
        );
        assert_eq!(runtime.snapshot().authority_slot_high_water, Some(77));

        let forged = LifecycleRequest::Authorized {
            admission: LifecycleAuthorityAdmission {
                receipt,
                observed_slot: 999,
            },
            request: Box::new(inner.clone()),
        };
        let outer_receipt = lifecycle_receipt(&config, &inner, 3);
        assert_eq!(
            seal_lifecycle_request(&trust, outer_receipt, forged),
            Err(LocalReplayExecutorError::InvalidRequest),
            "an unsigned caller slot cannot enter through the inner-request API"
        );
    }

    #[test]
    fn evicted_lifecycle_retry_is_uncommitted_and_cannot_finalize_pending_merge() {
        let mut runtime = {
            let core = initialized_core();
            StandardAgentRuntime::restore(
                decode_standard_runtime_state(core.materialization.state()).unwrap(),
            )
            .unwrap()
        };
        let config = runtime.config().unwrap().clone();
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xd1; 32]),
            expected_deployment: DeploymentId([0xd2; 32]),
        };
        let mut evicted = None;
        for sequence in 2..=258 {
            let request = authorized_at(&config, inner.clone(), sequence, 20);
            if sequence == 2 {
                evicted = Some(request.clone());
            }
            assert_eq!(runtime.apply(request), Err(LifecycleError::NotFound));
        }
        let snapshot = runtime.snapshot();
        assert_eq!(
            snapshot.authority_dispositions.len(),
            super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(snapshot.authority_dispositions[0].sequence, 3);
        assert_eq!(snapshot.authority_sequence_high_water, Some(258));
        let encoded = encode_standard_runtime_state(&snapshot);
        let evicted = evicted.unwrap();

        let mut core = initialized_core();
        let merge_input = invocation_input(&core.materialization, MethodMode::Merge, 0xd3);
        let merge_publication = TestPublication::for_input(&core, merge_input.clone());
        let merge_position = merge_publication.position();
        assert!(merge_publication.publish(&mut core).unwrap().is_empty());
        assert_eq!(
            core.recover(&merge_input, merge_position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        let durable_heads = core.store.heads().unwrap().unwrap();
        let cached = core.materialization.clone();

        for _ in 0..2 {
            assert_eq!(
                uncommitted_lifecycle_result(&encoded, &evicted).unwrap(),
                Some(Err(LifecycleError::AuthoritySequenceRegressed))
            );
            // This is the exact preflight branch used by `lifecycle`; it
            // returns before catalog staging, Merge sealing, or publication.
            assert_eq!(core.store.heads().unwrap(), Some(durable_heads.clone()));
            assert_eq!(core.materialization, cached);
            assert_eq!(
                core.recover(&merge_input, merge_position).unwrap(),
                ReplayInvocationRecovery::Pending
            );
        }
    }

    #[test]
    fn retained_success_retry_needs_no_historical_catalog_and_only_advances_slot_h() {
        let core = initialized_core();
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(core.materialization.state()).unwrap(),
        )
        .unwrap();
        let config = runtime.config().unwrap().clone();
        let package = BlobRef::of_bytes(b"historical-package");
        let schema = BlobRef::of_bytes(b"historical-schema");
        let policies = BlobRef::of_bytes(b"historical-policies");
        let deployment = DeploymentId([0xde; 32]);
        let actor = ActorId::top_level(config.identity.agent, "historical-actor");
        let requirements = RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proofs: false,
        };
        let install = LifecycleRequest::Install(InstallActor {
            installation_id: crate::service::InstallationId([0xd8; 32]),
            registry_reservation: Hash([0xd9; 32]),
            entry: ActorEntry {
                actor,
                name: "historical-actor".into(),
                parent: None,
                deployment,
                program: ProgramId([0xdf; 32]),
                package: package.clone(),
                agent_schema: schema.clone(),
                role_policies: policies.clone(),
                constructor_abi: Hash([0xe1; 32]),
                installation_data: None,
                state_layout: Hash([0xe0; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package,
            agent_schema: schema,
            role_policies: policies,
            constructor_abi: Hash([0xe1; 32]),
            installation_data: None,
            state_layout: Hash([0xe0; 32]),
            contract: super::super::contract::ActorPackageContract::canonical(),
            requirements,
        });
        let original = authorized_at(&config, install.clone(), 2, 20);
        let installed = runtime.apply(original).unwrap();
        assert!(matches!(installed, LifecycleReply::Installed(_)));
        assert_eq!(
            runtime.apply(authorized_at(
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor,
                    expected_deployment: deployment,
                },
                3,
                21,
            )),
            Ok(LifecycleReply::Removed(actor))
        );
        assert!(runtime.actor(actor).is_none());
        let state = encode_standard_runtime_state(&runtime.snapshot());

        let same_slot_retry = authorized_at(&config, install.clone(), 2, 21);
        assert_eq!(
            uncommitted_lifecycle_result(&state, &same_slot_retry).unwrap(),
            Some(Ok(installed.clone())),
            "an exact retained retry with no H change remains local"
        );

        let newer_slot_retry = authorized_at(&config, install, 2, 50);
        assert_eq!(
            retained_lifecycle_disposition(&state, &newer_slot_retry).unwrap(),
            Some(Ok(installed.clone())),
            "the disposition, not GC-prunable package bytes, authenticates retry"
        );
        assert_eq!(
            uncommitted_lifecycle_result(&state, &newer_slot_retry).unwrap(),
            None,
            "a newer trusted slot must still publish its H advancement"
        );
        let mut reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&state).unwrap()).unwrap();
        assert_eq!(reopened.apply(newer_slot_retry), Ok(installed));
        assert!(reopened.actor(actor).is_none(), "retry must not reinstall");
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(50));
    }

    #[test]
    fn divergent_acknowledgement_is_typed_and_exact_across_restart_for_every_scope() {
        for (mode, discriminator) in [
            (MethodMode::Linear, 0xe1),
            (MethodMode::Local, 0xe2),
            (MethodMode::Merge, 0xe3),
        ] {
            let mut core = initialized_core();
            let original = invocation_input(&core.materialization, mode, discriminator);
            let original_publication = TestPublication::for_input(&core, original.clone());
            original_publication.publish(&mut core).unwrap();

            let acknowledgement = acknowledgement_for(
                &core.materialization,
                &original,
                discriminator.wrapping_add(1),
            );
            let acknowledgement_publication =
                TestPublication::for_input(&core, acknowledgement.clone());
            let acknowledgement_position = acknowledgement_publication.position();
            let divergent = acknowledgement_publication.publish(&mut core).unwrap();
            assert!(divergent.len() <= 1);
            assert!(divergent.iter().all(|execution| {
                matches!(execution.outcome(), ReplayStepOutcome::DivergentInvocation)
                    && execution.result().is_none()
                    && execution.products().is_empty()
            }));
            assert_eq!(
                core.recover(&acknowledgement, acknowledgement_position)
                    .unwrap(),
                ReplayInvocationRecovery::Divergent
            );
            assert_eq!(
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::map_acknowledgement_recovery(
                    ReplayInvocationRecovery::Divergent,
                    None,
                )
                .unwrap(),
                LocalAcknowledgementResult::Divergent
            );

            // Simulate loss of the acknowledgement response after its CAS.
            let LocalJournalCore { store, .. } = core;
            let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
            let executions_after_replay = reopened.executor.executions;
            let heads_after_commit = reopened.store.heads().unwrap().unwrap();
            assert!(
                acknowledgement_publication
                    .publish(&mut reopened)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(reopened.executor.executions, executions_after_replay);
            assert_eq!(reopened.store.heads().unwrap(), Some(heads_after_commit));
            assert_eq!(
                reopened
                    .recover(&acknowledgement, acknowledgement_position)
                    .unwrap(),
                ReplayInvocationRecovery::Divergent
            );
            assert_eq!(
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::map_acknowledgement_recovery(
                    ReplayInvocationRecovery::Divergent,
                    None,
                )
                .unwrap(),
                LocalAcknowledgementResult::Divergent
            );
        }
    }

    #[test]
    fn exact_retry_uses_the_authenticated_committed_anchor_for_every_scope() {
        for (mode, discriminator) in [
            (MethodMode::Linear, 0xe8),
            (MethodMode::Local, 0xe9),
            (MethodMode::Merge, 0xea),
        ] {
            let mut core = initialized_core();
            let input = invocation_input(&core.materialization, mode, discriminator);
            let original = TestPublication::for_input(&core, input.clone());
            let exact_retry = original.clone();
            let committed_position = original.position();
            let first = original.publish(&mut core).unwrap();
            assert!(first.committed.is_none());

            let uncommitted_proposal = TestPublication::for_input(&core, input.clone()).position();
            assert_ne!(uncommitted_proposal, committed_position);
            let retried = exact_retry.publish(&mut core).unwrap();
            assert!(retried.executions.is_empty());
            assert_eq!(
                retried.committed.map(ReplayCommittedRecovery::position),
                Some(committed_position)
            );
            let (authoritative, executions, already_committed) = LocalJournalAgentDriver::<
                MemoryAgentJournalStore,
            >::authoritative_publication_position(
                input.id(),
                uncommitted_proposal,
                retried,
            )
            .unwrap();
            assert!(already_committed);
            assert!(executions.is_empty());
            assert_eq!(authoritative, committed_position);
            assert!(matches!(
                core.recover(&input, authoritative).unwrap(),
                ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
                    | ReplayInvocationRecovery::Pending
            ));
        }
    }

    #[test]
    fn pending_merge_invoke_and_ack_retries_recover_canonical_sources_after_reopen() {
        let mut core = initialized_core();
        let original = invocation_input(&core.materialization, MethodMode::Merge, 0xeb);
        let source = TestPublication::for_input(&core, original.clone());
        let source_position = source.position();
        let ReplayPosition::Merge {
            id: source_event, ..
        } = source_position
        else {
            unreachable!()
        };
        assert!(source.publish(&mut core).unwrap().is_empty());

        let LocalJournalCore { store, .. } = core;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let mut retry = original.clone();
        let ReplayOperation::Invoke { observed_slot, .. } = &mut retry.operation else {
            unreachable!()
        };
        *observed_slot += 1;
        let alias = TestPublication::for_input(&reopened, retry.clone());
        let alias_id = match alias {
            TestPublication::Merge(ref event) => event.id(),
            TestPublication::Ordered(_) | TestPublication::Local(_) => unreachable!(),
        };
        assert_ne!(alias_id, source_event);
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        let ExistingMergeRecovery::Pending(pending) =
            reopened.existing_merge_recovery(&retry).unwrap().unwrap()
        else {
            panic!("pending invocation resolved as acknowledged history")
        };
        assert_eq!(pending.event, source_event);
        assert_eq!(pending.position, source_position);
        assert_eq!(pending.input, original);
        assert_eq!(
            reopened.recover(&pending.input, pending.position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
        assert_eq!(reopened.store.get::<MergeEvent>(alias_id).unwrap(), None);

        let finalized = finalize_test_merge(&mut reopened);
        assert_eq!(
            finalized
                .executions
                .iter()
                .filter(|execution| execution.result().is_some())
                .count(),
            1
        );
        let acknowledgement = acknowledgement_for(&reopened.materialization, &original, 0xeb);
        let acknowledgement_source = TestPublication::for_input(&reopened, acknowledgement.clone());
        let acknowledgement_position = acknowledgement_source.position();
        let ReplayPosition::Merge {
            id: acknowledgement_event,
            ..
        } = acknowledgement_position
        else {
            unreachable!()
        };
        assert!(
            acknowledgement_source
                .publish(&mut reopened)
                .unwrap()
                .is_empty()
        );

        let LocalJournalCore { store, .. } = reopened;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let acknowledgement_alias = TestPublication::for_input(&reopened, acknowledgement.clone());
        let acknowledgement_alias_id = match acknowledgement_alias {
            TestPublication::Merge(ref event) => event.id(),
            TestPublication::Ordered(_) | TestPublication::Local(_) => unreachable!(),
        };
        assert_ne!(acknowledgement_alias_id, acknowledgement_event);
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        let ExistingMergeRecovery::Pending(pending) = reopened
            .existing_merge_recovery(&acknowledgement)
            .unwrap()
            .unwrap()
        else {
            panic!("pending acknowledgement resolved as acknowledged history")
        };
        assert_eq!(pending.event, acknowledgement_event);
        assert_eq!(pending.position, acknowledgement_position);
        assert_eq!(pending.input, acknowledgement);
        assert_eq!(
            reopened.recover(&pending.input, pending.position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
        assert_eq!(
            reopened
                .store
                .get::<MergeEvent>(acknowledgement_alias_id)
                .unwrap(),
            None
        );

        let old_pending_receipt = pending.clone();
        finalize_test_merge(&mut reopened);
        let advancing_input = invocation_input(&reopened.materialization, MethodMode::Merge, 0xec);
        assert!(
            TestPublication::for_input(&reopened, advancing_input)
                .publish(&mut reopened)
                .unwrap()
                .is_empty()
        );
        finalize_test_merge(&mut reopened);
        reopened.checkpoint().unwrap();
        let expected_heads = reopened.materialization.heads_id();
        let limits = GcLimits {
            max_index_nodes: 100_000,
            max_marked_objects: 100_000,
            max_marked_blobs: 100_000,
            max_scanned_files: 100_000,
            max_scanned_bytes: u64::MAX,
            max_unlinks_per_run: 100_000,
        };
        loop {
            let collected = reopened
                .store
                .collect_garbage(expected_heads, limits)
                .unwrap();
            if collected.complete {
                break;
            }
        }
        assert_eq!(
            reopened
                .store
                .get::<MergeEvent>(acknowledgement_event)
                .unwrap(),
            None,
            "permanent acknowledged history does not retain the acknowledgement suffix anchor"
        );

        let LocalJournalCore { store, .. } = reopened;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        assert_eq!(
            reopened
                .recover(&old_pending_receipt.input, old_pending_receipt.position)
                .unwrap(),
            ReplayInvocationRecovery::NotCommitted,
            "the explicitly pending receipt fails closed after finalization and GC"
        );
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        assert_eq!(
            reopened.existing_merge_recovery(&acknowledgement).unwrap(),
            Some(ExistingMergeRecovery::Acknowledged)
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
    }

    #[test]
    fn live_trust_change_blocks_pending_owner_shortcuts_without_disclosure() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0xed);
        let source = TestPublication::for_input(&core, input.clone());
        let source_position = source.position();
        assert!(source.publish(&mut core).unwrap().is_empty());
        let config = current_test_config(&core.materialization);
        let node = core.materialization.heads().node;
        let resolver = core.store.catalog_blob_resolver().unwrap();
        let mutable_trust = Arc::new(MutableTrust {
            slot: Some(20),
            authority: Mutex::new(Some(config.authority.clone())),
        });
        let trust: Arc<dyn AgentTrustProvider> = mutable_trust.clone();
        let executor =
            StandardLocalReplayExecutor::new(resolver, trust, Arc::new(StaticMerge(node)));
        let mut driver = LocalJournalAgentDriver {
            core: LocalJournalCore {
                store: core.store,
                materialization: core.materialization,
                executor,
            },
            lifecycle_fault: None,
        };
        *mutable_trust.authority.lock().unwrap() = None;
        let recovery_input = input.clone();
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = input.operation
        else {
            unreachable!()
        };
        let acknowledgement_input = acknowledgement_for(
            &driver.core.materialization,
            &ReplayInput {
                runtime: driver.core.materialization.runtime().clone(),
                operation: ReplayOperation::Invoke {
                    invocation: invocation.clone(),
                    authority: authority.clone(),
                    observed_slot: 10,
                },
            },
            0xed,
        );
        let ReplayOperation::Acknowledge {
            invocation: acknowledged_invocation,
            authority: acknowledgement_authority,
        } = acknowledgement_input.operation
        else {
            unreachable!()
        };
        let heads_before = driver.core.store.heads().unwrap().unwrap();
        let merge_state = BlobRef::of_bytes(&driver.core.materialization.state().merge);
        let merge_blob_before = driver
            .core
            .store
            .load_blob(JournalBlobClass::LaneState, &merge_state)
            .unwrap();
        assert_eq!(
            driver.invoke(invocation, authority),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.acknowledge_invocation(acknowledged_invocation, acknowledgement_authority),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.recover_committed_invocation(&recovery_input, source_position),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.finalize_merge(),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.inspect(None, 1),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        let lifecycle_request = LifecycleRequest::Suspend {
            actor: ActorId([0xee; 32]),
            expected_deployment: DeploymentId([0xef; 32]),
        };
        let lifecycle_receipt = lifecycle_receipt(&config, &lifecycle_request, 2);
        assert_eq!(
            driver.lifecycle(lifecycle_receipt, lifecycle_request, &[]),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(driver.core.store.heads().unwrap(), Some(heads_before));
        assert_eq!(
            driver
                .core
                .store
                .load_blob(JournalBlobClass::LaneState, &merge_state)
                .unwrap(),
            merge_blob_before
        );
    }

    #[test]
    fn invalid_actor_catalog_is_rejected_before_blob_or_head_publication() {
        let driver = standard_test_driver();
        let config = driver.current_config().unwrap();
        let package_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-a-signed-package"),
            bytes: b"not-a-signed-package".to_vec(),
        };
        let schema_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-an-agent-schema"),
            bytes: b"not-an-agent-schema".to_vec(),
        };
        let policies_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-role-policies"),
            bytes: b"not-role-policies".to_vec(),
        };
        let requirements = RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proofs: false,
        };
        let deployment = DeploymentId([0xf1; 32]);
        let program = ProgramId([0xf2; 32]);
        let state_layout = Hash([0xf3; 32]);
        let actor = ActorId::top_level(config.identity.agent, "catalog-admission");
        let install = InstallActor {
            installation_id: crate::service::InstallationId([0xed; 32]),
            registry_reservation: Hash([0xee; 32]),
            entry: ActorEntry {
                actor,
                name: "catalog-admission".into(),
                parent: None,
                deployment,
                program,
                package: package_blob.reference.clone(),
                agent_schema: schema_blob.reference.clone(),
                role_policies: policies_blob.reference.clone(),
                constructor_abi: Hash([0xf4; 32]),
                installation_data: None,
                state_layout,
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package: package_blob.reference.clone(),
            agent_schema: schema_blob.reference.clone(),
            role_policies: policies_blob.reference.clone(),
            constructor_abi: Hash([0xf4; 32]),
            installation_data: None,
            state_layout,
            contract: super::super::contract::ActorPackageContract::canonical(),
            requirements,
        };
        let request = LifecycleRequest::Install(install);
        let receipt = lifecycle_receipt(&config, &request, 2);
        let authorized = seal_lifecycle_request(
            &StaticTrust {
                slot: Some(20),
                authority: Some(config.authority.clone()),
                trust_packages: true,
            },
            receipt,
            request,
        )
        .unwrap();
        let before_heads = driver.core.store.heads().unwrap().unwrap();
        let before_materialization = driver.core.materialization.clone();

        assert_eq!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                driver.core.materialization.state(),
                &authorized,
                &[package_blob.clone(), schema_blob.clone()],
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "a fresh catalog closure must be complete"
        );
        let extra_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"unreferenced-extra"),
            bytes: b"unreferenced-extra".to_vec(),
        };
        assert_eq!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                driver.core.materialization.state(),
                &authorized,
                &[
                    package_blob.clone(),
                    schema_blob.clone(),
                    policies_blob.clone(),
                    extra_blob.clone(),
                ],
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "a fresh catalog closure must contain no unreferenced content"
        );

        assert!(matches!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                driver.core.materialization.state(),
                &authorized,
                &[package_blob.clone(), schema_blob.clone(), policies_blob.clone()],
            ),
            Err(LocalReplayExecutorError::InvalidArtifact(reference))
                if reference == package_blob.reference
        ));
        assert_eq!(driver.core.store.heads().unwrap(), Some(before_heads));
        assert_eq!(driver.core.materialization, before_materialization);
        for blob in [&package_blob, &schema_blob, &policies_blob, &extra_blob] {
            assert_eq!(
                driver
                    .core
                    .store
                    .load_blob(JournalBlobClass::CatalogArtifact, &blob.reference)
                    .unwrap(),
                None,
                "semantic catalog rejection must precede staging"
            );
        }
    }

    #[test]
    fn consumed_lifecycle_refusal_does_not_stage_unreferenced_catalog() {
        let core = initialized_core();
        let config = current_test_config(&core.materialization);
        let request = authorized_at(
            &config,
            LifecycleRequest::Suspend {
                actor: ActorId([0xf7; 32]),
                expected_deployment: DeploymentId([0xf8; 32]),
            },
            2,
            20,
        );
        let preflight =
            preflight_lifecycle_transition(core.materialization.state(), &request).unwrap();
        assert_eq!(preflight.result, Err(LifecycleError::NotFound));
        assert!(!preflight.unchanged, "the authority disposition is durable");
        assert_eq!(
            retained_lifecycle_disposition(core.materialization.state(), &request).unwrap(),
            None
        );

        let irrelevant = RuntimeBlob {
            reference: BlobRef::of_bytes(b"must-not-be-staged-on-refusal"),
            bytes: b"must-not-be-staged-on-refusal".to_vec(),
        };
        assert!(preflight.result.is_err());
        assert_eq!(
            core.store
                .load_blob(JournalBlobClass::CatalogArtifact, &irrelevant.reference)
                .unwrap(),
            None,
            "the live lifecycle branch stages only when this preflight is successful"
        );
    }

    #[test]
    fn memory_result_loss_restart_and_exact_retry_do_not_reexecute() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Local, 0x31);
        let entry = local_entry(&core.materialization, input.clone());
        let position = ReplayPosition::Local {
            id: entry.id(),
            node: entry.node,
            revision: entry.revision,
            ordered_base: entry.ordered_base,
            merge_frontier: entry.merge_frontier,
        };
        let lost = core.publish_local(&entry).unwrap();
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].result(), Some(&Err(ActorExecutionError::NotFound)));
        assert!(lost[0].products().is_empty());

        let LocalJournalCore { store, .. } = core;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let executions_after_replay = reopened.executor.executions;
        assert_eq!(
            reopened.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
        assert_eq!(reopened.executor.executions, executions_after_replay);

        let retry_executions = reopened.publish_local(&entry).unwrap();
        assert!(retry_executions.is_empty());
        assert_eq!(reopened.executor.executions, executions_after_replay);
        assert_eq!(
            reopened.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
        assert_eq!(reopened.executor.executions, executions_after_replay);
    }

    #[test]
    fn memory_stale_materialization_conflict_never_installs_candidate_cache() {
        let mut core = initialized_core();
        let stale = core.materialization.clone();
        let committed_input = invocation_input(&stale, MethodMode::Local, 0x41);
        let committed = local_entry(&stale, committed_input);
        core.publish_local(&committed).unwrap();
        let durable_heads = core.store.heads().unwrap().unwrap();

        core.materialization = stale.clone();
        let conflicting_input = invocation_input(&stale, MethodMode::Local, 0x42);
        let conflicting = local_entry(&stale, conflicting_input);
        assert_eq!(
            core.publish_local(&conflicting),
            Err(LocalJournalDriverError::Conflict)
        );
        assert_eq!(core.materialization, stale);
        assert_eq!(core.store.heads().unwrap(), Some(durable_heads));
    }

    #[test]
    fn checkpoint_delta_accepts_only_exact_historical_lane_compaction() {
        let core = initialized_core();
        let mut before = decode_standard_runtime_state(core.materialization.state()).unwrap();
        before
            .lane_state
            .merge
            .push(super::super::standard::StandardLaneEntry {
                actor: ActorId([0xf8; 32]),
                state_generation: Hash([0xf9; 32]),
                value: vec![0xfa],
                rows: Default::default(),
            });
        let before = encode_standard_runtime_state(&before);
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&before).expect("historical state is canonical"),
        )
        .unwrap();
        runtime.compact_historical_lane_entries_for_checkpoint();
        let after = encode_standard_runtime_state(&runtime.snapshot());

        assert_ne!(before, after, "the fixture must exercise real compaction");
        assert!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_canonical_checkpoint_state_delta(
                &before, &after
            )
        );
        let mut noncanonical = decode_standard_runtime_state(&after).unwrap();
        noncanonical.authority_slot_high_water = Some(999);
        assert!(!LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_canonical_checkpoint_state_delta(
            &before,
            &encode_standard_runtime_state(&noncanonical),
        ));
    }

    #[test]
    fn refusal_from_a_fresh_checkpoint_base_remains_uncommitted() {
        let mut core = initialized_core();
        core.checkpoint().unwrap();
        core.executor.refusal = Some(ActorExecutionError::AuthorityExpired);
        let mut input = invocation_input(&core.materialization, MethodMode::Local, 0xf0);
        let ReplayOperation::Invoke { observed_slot, .. } = &mut input.operation else {
            unreachable!()
        };
        *observed_slot = 101;
        assert!(input.validate().is_ok());
        let entry = local_entry(&core.materialization, input);
        assert_eq!(
            core.publish_local(&entry),
            Err(LocalJournalDriverError::Replay(
                ReplayError::UncommittedInvocation(ActorExecutionError::AuthorityExpired)
            ))
        );
    }

    #[test]
    fn suffix_boundary_refusal_allows_only_the_automatic_checkpoint_delta() {
        let mut core = initialized_core();
        let config = current_test_config(&core.materialization);
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xfb; 32]),
            expected_deployment: DeploymentId([0xfc; 32]),
        };
        for sequence in 2..=(super::super::replay::MAX_REPLAY_SUFFIX_ENTRIES as u64 + 1) {
            let input = ReplayInput {
                runtime: core.materialization.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: authorized_at(&config, inner.clone(), sequence, 20),
                },
            };
            let merge_seal = persist_test_merge_seal(&mut core);
            let heads = core.materialization.heads();
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index: heads.ordered_index + 1,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: Some(merge_seal),
                input,
            };
            let published = core.publish_ordered(&entry).unwrap();
            assert!(published.committed.is_none());
        }

        let before = core.materialization.clone();
        core.executor.refusal = Some(ActorExecutionError::AuthorityExpired);
        let mut input = invocation_input(&core.materialization, MethodMode::Local, 0xf0);
        let ReplayOperation::Invoke { observed_slot, .. } = &mut input.operation else {
            unreachable!()
        };
        *observed_slot = 101;
        assert!(input.validate().is_ok());
        let entry = local_entry(&core.materialization, input.clone());
        let position = ReplayPosition::Local {
            id: entry.id(),
            node: entry.node,
            revision: entry.revision,
            ordered_base: entry.ordered_base,
            merge_frontier: entry.merge_frontier,
        };
        assert_eq!(
            core.publish_local(&entry),
            Err(LocalJournalDriverError::Replay(
                ReplayError::UncommittedInvocation(ActorExecutionError::AuthorityExpired)
            ))
        );
        assert!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_checkpoint_only_delta(
                &before,
                &core.materialization,
            )
        );
        assert_eq!(
            core.store.heads().unwrap(),
            Some(core.materialization.heads().clone())
        );
        assert_eq!(core.store.get::<LocalEntry>(entry.id()).unwrap(), None);
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::NotCommitted
        );
    }

    #[test]
    fn memory_merge_source_is_pending_until_genuine_seal_merge() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0x51);
        let event = MergeEvent {
            genesis: core.materialization.heads().genesis,
            committee: None,
            author: core.materialization.heads().node,
            ordered_base: core.materialization.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: input.clone(),
            signature: vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        // Keep the signing preimage construction exercised even though the
        // explicit test authenticator accepts this fixed signature.
        assert_ne!(event.signing_message(), Hash::ZERO);
        let position = ReplayPosition::Merge {
            id: event.id(),
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        assert!(core.publish_merge(&event).unwrap().is_empty());
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Pending
        );

        let merge_bytes = core.materialization.state().merge.clone();
        let reference = BlobRef::of_bytes(&merge_bytes);
        core.store
            .put_blob(JournalBlobClass::LaneState, &reference, &merge_bytes)
            .unwrap();
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            core.materialization.heads().genesis,
            core.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: core.materialization.merge_frontier(),
            },
            &merge_bytes,
        )
        .unwrap();
        core.store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: core.materialization.heads().genesis,
            frontier: core.materialization.merge_frontier(),
            ordered_base: core.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        core.store.put(&seal).unwrap();
        let seal_input = ReplayInput {
            runtime: core.materialization.runtime().clone(),
            operation: ReplayOperation::SealMerge,
        };
        let ordered = OrderedEntry {
            genesis: core.materialization.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: core.materialization.merge_frontier(),
            merge_seal: Some(seal.id()),
            input: seal_input,
        };
        let finalized = core.publish_ordered(&ordered).unwrap();
        assert_eq!(
            finalized
                .iter()
                .filter_map(ReplayExecutionResult::result)
                .filter(|result| **result == Err(ActorExecutionError::NotFound))
                .count(),
            1
        );
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
    }
}
