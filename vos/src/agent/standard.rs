//! Deterministic policy core of the bundled agent runtime.
//!
//! Persistence and execution are supplied by the guest entry around this
//! type. The state machine itself is `no_std`, permits an empty actor forest,
//! and keeps lifecycle safety independent of the 63 live-machine limit.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::ops::Bound::{Excluded, Unbounded};

use super::{
    ActorEntry, ActorLifecycleDebt, ActorRecord, AgentConfig, AgentConfigError, AgentRuntime,
    InvocationResultStorage, InvocationScope, LaneSet, LifecycleError, LifecycleReply,
    LifecycleRequest, RuntimeRequirements, StateLane,
};
use crate::service::{
    ActorId, BlobRef, CredentialId, DeploymentId, Hash, InstallationId, InvocationId, ProducerId,
    ProgramId,
};

pub const MAX_DIRECTORY_PAGE: u16 = 256;
pub const MAX_INVOCATION_RESULTS_PER_LANE: usize = 32;
/// Maximum delivered-result retirement facts retained in each independently
/// persisted result component. Positive facts are never evicted: a full
/// component rejects the next acknowledgement before retiring its terminal
/// result, preserving exact retry evidence without an unbounded tombstone log.
/// The one exception is a sequenced invocation identity
/// ([`crate::agent_sdk::SequencedInvocation`]): when the component is full, the
/// fact at the component's next sequence position is replaced by the
/// component's retirement watermark, which refuses that identity forever
/// without retaining it.
pub const MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE: usize = MAX_INVOCATION_RESULTS_PER_LANE;
pub const MAX_INVOCATION_RESULT_BYTES_PER_LANE: usize = 64 * 1024;
pub const MAX_AUTHORITY_DISPOSITIONS: usize = 256;
/// Continuations are bounded independently of the encoded runtime image so a
/// hostile list declaration is rejected before allocating snapshots.
pub const MAX_MACHINE_CONTINUATIONS: usize = 4_096;
/// Maximum number of retired installation identities representable in one
/// canonical runtime image. The aggregate encoded-state limit is stricter once
/// any other state is present, while this explicit cap rejects hostile list
/// declarations before allocation.
pub const MAX_RETIRED_INSTALLATION_IDS: usize =
    super::execution::MAX_RUNTIME_STATE_BYTES / core::mem::size_of::<InstallationId>();
/// Explicit cap below both the runtime-image byte limit and the generic wire
/// item limit. Historical entries are retained until checkpoint compaction.
pub const MAX_LANE_STATE_ENTRIES: usize = 16_384;

/// The actor program is `P`: owned for callers that keep it, and borrowed
/// from the work for execution, which never needs its own copy.
type CleanInvocationParts<P = Vec<u8>> = (
    super::execution::ActorInvocation,
    P,
    crate::agent_sdk::RuntimeBlob,
    crate::agent_sdk::RuntimeBlob,
    Option<crate::agent_sdk::RuntimeBlob>,
);

/// Immutable result of resolving one borrowed SDK work value against an exact
/// actor record. Only this module can construct it. It proves correspondence,
/// not authorization, execution success, or validity against a changed catalog.
pub(crate) struct ResolvedCleanInvocation<'work> {
    work: &'work crate::agent_sdk::InvocationWork,
    actor: ActorRecord,
    parts: CleanInvocationParts<&'work [u8]>,
    /// The work came from the canonical decoder of this execution, which
    /// validated its metadata and availability preimages.
    work_validated: bool,
}

impl ResolvedCleanInvocation<'_> {
    /// The authenticated availability reference of the resolved program.
    pub(crate) fn program_reference(&self) -> Option<crate::agent_sdk::BlobRef> {
        let program = self.parts.1;
        self.work
            .availability
            .iter()
            .find(|blob| core::ptr::eq(blob.bytes.as_slice(), program))
            .map(|blob| blob.reference.clone())
    }

    pub(crate) fn actor_id(&self) -> ActorId {
        self.actor.entry.actor
    }

    pub(crate) fn work_validated(&self) -> bool {
        self.work_validated
    }
}

impl<'work> ResolvedCleanInvocation<'work> {
    pub(crate) fn parts(&self) -> &CleanInvocationParts<&'work [u8]> {
        &self.parts
    }
}

#[derive(Default)]
struct ArtifactResourceUsage {
    /// Catalog storage is hash-keyed. Retaining the one admitted length here
    /// both deduplicates exact references and rejects an unsatisfiable second
    /// length for the same content identity.
    lengths: BTreeMap<Hash, u64>,
    referenced_bytes: u64,
}

impl ArtifactResourceUsage {
    fn insert(
        &mut self,
        reference: &BlobRef,
        limits: super::contract::RuntimeResourceLimits,
    ) -> Result<(), LifecycleError> {
        if reference.hash == Hash::ZERO {
            return Err(LifecycleError::InvalidRequest);
        }
        if let Some(encoded_len) = self.lengths.get(&reference.hash) {
            return if *encoded_len == reference.len {
                Ok(())
            } else {
                Err(LifecycleError::InvalidRequest)
            };
        }
        let references = self
            .lengths
            .len()
            .checked_add(1)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or(LifecycleError::ResourceLimit)?;
        let referenced_bytes = self
            .referenced_bytes
            .checked_add(reference.len)
            .ok_or(LifecycleError::ResourceLimit)?;
        if reference.len > super::MAX_CATALOG_ARTIFACT_BYTES
            || references > limits.max_artifact_references
            || referenced_bytes > limits.max_artifact_referenced_bytes
        {
            return Err(LifecycleError::ResourceLimit);
        }
        self.lengths.insert(reference.hash, reference.len);
        self.referenced_bytes = referenced_bytes;
        Ok(())
    }
}

fn validate_artifact_resources<'a>(
    limits: super::contract::RuntimeResourceLimits,
    references: impl IntoIterator<Item = &'a BlobRef>,
) -> Result<(), LifecycleError> {
    if !limits.is_valid() {
        return Err(LifecycleError::InvalidRequest);
    }
    let mut usage = ArtifactResourceUsage::default();
    for reference in references {
        usage.insert(reference, limits)?;
    }
    Ok(())
}

fn actor_artifact_references(actor: &ManagedActor) -> impl Iterator<Item = &BlobRef> {
    [
        &actor.record.package,
        &actor.record.agent_schema,
        &actor.record.role_policies,
    ]
    .into_iter()
    .chain(actor.record.installation_data.iter())
}

fn installation_data_aliases_actor_artifact(
    installation_data: Option<&BlobRef>,
    package: &BlobRef,
    agent_schema: &BlobRef,
    role_policies: &BlobRef,
) -> bool {
    installation_data.is_some_and(|data| {
        [package, agent_schema, role_policies]
            .into_iter()
            .any(|artifact| data.hash == artifact.hash)
    })
}

/// Fetch an actor program by its ProgramId through Refine `historical_lookup` (call 7),
/// from a host that verified the preimage natively (`vos_pvm::refine_host::
/// serve_historical_lookup`). The allocation is leaked: it lives as long as this one
/// execution's guest.
#[cfg(all(feature = "runtime-program-lookup", target_arch = "riscv64"))]
fn lookup_program(
    program: &crate::agent_sdk::ProgramId,
) -> Result<&'static [u8], crate::agent_sdk::InvocationError> {
    use crate::agent_sdk::InvocationError;
    const NONE: u64 = u64::MAX;
    let hash = program.0;
    let length = crate::abi::pvm::ecall::ecall5(7, NONE, hash.as_ptr() as u64, 0, 0, 0);
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length != 0 && *length <= super::execution::MAX_EXECUTION_PROGRAM_BYTES)
        .ok_or(InvocationError::InvalidAvailability)?;
    let mut bytes = alloc::vec![0u8; length];
    let written = crate::abi::pvm::ecall::ecall5(
        7,
        NONE,
        hash.as_ptr() as u64,
        bytes.as_mut_ptr() as u64,
        0,
        length as u64,
    );
    if written != length as u64 {
        return Err(InvocationError::InvalidAvailability);
    }
    Ok(alloc::boxed::Box::leak(bytes.into_boxed_slice()))
}

fn install_matches(record: &ActorRecord, install: &super::InstallActor) -> bool {
    record.installation_id == install.installation_id
        && record.registry_reservation == install.registry_reservation
        && record.install_request_commitment
            == LifecycleRequest::Install(install.clone()).commitment()
}

#[derive(Clone, Debug)]
struct ManagedActor {
    record: ActorRecord,
    /// Non-structural durable work. Child debt is derived from the directory.
    debt: ActorLifecycleDebt,
    /// Exact portable package compatibility admitted for a clean actor.
    /// Legacy actors deliberately carry no such binding.
    clean_package: Option<StandardCleanActorPackage>,
    /// Immutable exact SDK install-time binding. Unlike `clean_package`, this
    /// is never rewritten by an in-place actor upgrade and therefore remains
    /// the authority for `InstallationId` replay equality.
    clean_installation: Option<StandardCleanActorInstallation>,
}

#[derive(Clone, Debug, Default)]
pub struct StandardAgentRuntime {
    config: Option<AgentConfig>,
    /// Exact portable descriptor supplied by the successful clean Create.
    /// This is never reconstructed from transitional service identities.
    clean_creation_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    /// Current portable runtime/replica view. Immutable creation identity and
    /// authority fields must remain equal to `clean_creation_descriptor`.
    clean_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    clean_authority_epoch_high_water: Option<u64>,
    clean_decision_sequence_high_water: Option<u64>,
    clean_acknowledged_through: u64,
    clean_management_dispositions: Vec<StandardCleanManagementDisposition>,
    active_resource_policy: Option<crate::agent_sdk::contract::RuntimeResourcePolicy>,
    private_runtime_control_commitment: Option<crate::agent_sdk::Hash>,
    private_runtime_control_sequence: Option<u64>,
    private_authority_epoch_high_water: Option<u64>,
    private_control_slot_high_water: Option<u64>,
    private_management_dispositions: Vec<StandardPrivateManagementDisposition>,
    system_authority: Option<super::system_authority::SystemAuthorityState>,
    actors: BTreeMap<ActorId, ManagedActor>,
    /// Guest-verified program bindings: for an installed actor, the
    /// availability reference whose bytes this runtime has hashed to the
    /// actor's current ProgramId. Valid only while that ProgramId is current.
    program_bindings: BTreeMap<ActorId, StandardProgramBinding>,
    /// Installation identities remain consumed after their actor leaves the
    /// live directory, preventing an install replay from becoming a new
    /// incarnation after `RemoveLeaf`.
    retired_installation_ids: BTreeSet<InstallationId>,
    lane_state: StandardLaneState,
    invocation_results: BTreeMap<(InvocationScope, InvocationId), StandardInvocationResult>,
    clean_invocation_errors:
        BTreeMap<(InvocationScope, InvocationId), StandardCleanInvocationError>,
    /// Bounded, insertion-ordered facts for successfully retired clean
    /// results. These are guest state (not host retry cache), survive journal
    /// checkpoints, and are encoded in the same physical component as the
    /// result they replaced.
    clean_invocation_acknowledgements: Vec<crate::agent_sdk::InvocationAcknowledgement>,
    /// Per-component watermark of compacted sequenced retirement facts.
    sequenced_retired_through: StandardSequencedRetirement,
    /// Cooperative actor slices ordered by `(owning component, ready_sequence)`.
    /// A yielded slice moves to the tail of its component queue on every
    /// subsequent yield, providing deterministic FIFO round-robin behavior.
    machine_continuations: Vec<StandardMachineContinuation>,
    lane_revisions: StandardLaneRevisions,
    control_authority_slot: Option<u64>,
    authority_slot_high_water: Option<u64>,
    /// Highest binding-global authority sequence durably consumed.
    authority_sequence_high_water: Option<u64>,
    authority_dispositions: Vec<StandardAuthorityDisposition>,
}

/// Canonical persisted state of the bundled runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardRuntimeState {
    pub config: Option<AgentConfig>,
    pub clean_creation_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    pub clean_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    pub clean_authority_epoch_high_water: Option<u64>,
    pub clean_decision_sequence_high_water: Option<u64>,
    pub clean_acknowledged_through: u64,
    pub clean_management_dispositions: Vec<StandardCleanManagementDisposition>,
    pub active_resource_policy: Option<crate::agent_sdk::contract::RuntimeResourcePolicy>,
    pub private_runtime_control_commitment: Option<crate::agent_sdk::Hash>,
    pub private_runtime_control_sequence: Option<u64>,
    pub private_authority_epoch_high_water: Option<u64>,
    pub private_control_slot_high_water: Option<u64>,
    pub private_management_dispositions: Vec<StandardPrivateManagementDisposition>,
    pub system_authority: Option<super::system_authority::SystemAuthorityState>,
    pub actors: Vec<StandardActorState>,
    /// Exact portable package compatibility, ordered by actor identity.
    /// `None` denotes a legacy image; every clean image, including an empty
    /// directory, carries `Some` so old images cannot silently regain a
    /// collapsed boolean proof capability after restart.
    pub clean_actor_packages: Option<Vec<StandardCleanActorPackage>>,
    /// Immutable exact SDK install-time bindings, ordered by actor identity.
    /// This is separate from `clean_actor_packages`, whose requirements track
    /// the currently installed deployment and may change on `UpgradeActor`.
    pub clean_actor_installations: Option<Vec<StandardCleanActorInstallation>>,
    /// Strictly ordered grow-only tombstones for removed installations.
    pub retired_installation_ids: Vec<InstallationId>,
    pub lane_state: StandardLaneState,
    pub invocation_results: Vec<StandardInvocationResult>,
    pub(crate) clean_invocation_errors: Vec<StandardCleanInvocationError>,
    pub clean_invocation_acknowledgements: Vec<crate::agent_sdk::InvocationAcknowledgement>,
    /// Zero in every component unless sequenced retirement facts were
    /// compacted, so images that never compact encode byte-identically.
    pub sequenced_retired_through: StandardSequencedRetirement,
    pub(crate) machine_continuations: Vec<StandardMachineContinuation>,
    pub lane_revisions: StandardLaneRevisions,
    pub control_authority_slot: Option<u64>,
    pub authority_slot_high_water: Option<u64>,
    pub authority_sequence_high_water: Option<u64>,
    pub authority_dispositions: Vec<StandardAuthorityDisposition>,
    /// Guest-verified program bindings, ordered by actor. Empty in every image
    /// written before an actor's first invocation, which then encodes exactly
    /// as it did before bindings existed.
    pub program_bindings: Vec<StandardProgramBinding>,
}

/// The availability reference of one actor's program, bound to its ProgramId
/// by this runtime: on the first invocation that resolved the program, the
/// guest computed the ProgramId of the exact bytes it then executed, and those
/// bytes had just been authenticated against `reference` by the work decoder.
/// Later invocations identify the program by that verified reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardProgramBinding {
    pub actor: ActorId,
    pub program: ProgramId,
    pub reference: crate::agent_sdk::BlobRef,
}

/// Replay-only durable objects selected by an authenticated native reapply.
/// Guest execution never exposes this metadata and raw journal-context bytes
/// cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StandardSystemAuthorityWrite {
    Finalize {
        admitted_fact: Option<super::system_authority::SystemAuthorityDecisionFact>,
        history: super::system_authority::SystemAuthorityDecisionWritePlan,
    },
    Rotation {
        record: super::system_authority::SystemAuthorityRotationRecord,
        history: super::system_authority::SystemAuthorityRotationWritePlan,
    },
    Catalog {
        record: Option<super::system_authority::SystemAuthorityCatalogRecord>,
        history: super::system_authority::SystemAuthorityCatalogWritePlan,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardScopedApply {
    result: Result<LifecycleReply, LifecycleError>,
    system_authority_write: Option<StandardSystemAuthorityWrite>,
}

impl StandardScopedApply {
    pub(crate) const fn result(&self) -> &Result<LifecycleReply, LifecycleError> {
        &self.result
    }

    pub(crate) const fn system_authority_write(&self) -> Option<&StandardSystemAuthorityWrite> {
        self.system_authority_write.as_ref()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Result<LifecycleReply, LifecycleError>,
        Option<StandardSystemAuthorityWrite>,
    ) {
        (self.result, self.system_authority_write)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardAuthorityDisposition {
    pub credential: CredentialId,
    /// Globally unique within the immutable authority binding.
    pub sequence: u64,
    pub claim: Hash,
    pub operation: Hash,
    pub result: Result<LifecycleReply, LifecycleError>,
}

/// Bounded exact-result record for the portable management ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardCleanManagementDisposition {
    /// Commitment of the complete signed receipt, including its signature.
    pub authority: crate::agent_sdk::Hash,
    pub request: crate::agent_sdk::Hash,
    pub epoch: u64,
    pub sequence: u64,
    pub observed_slot: u64,
    pub result: Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
}

/// Bounded exact-result record for owner-signed Private runtime controls.
/// Private receipts deliberately do not use the general management decision
/// clock, so the signed PCTL chain supplies this replay domain instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardPrivateManagementDisposition {
    pub authority: crate::agent_sdk::Hash,
    pub control: crate::agent_sdk::Hash,
    pub request: crate::agent_sdk::Hash,
    pub sequence: u64,
    pub previous: Option<crate::agent_sdk::Hash>,
    pub epoch: u64,
    pub observed_slot: u64,
    pub result: Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardInvocationResult {
    pub scope: InvocationScope,
    pub invocation: InvocationId,
    /// Install incarnation which owns this retained result.
    pub incarnation: Hash,
    /// Clean results use the authenticated SDK work commitment. Legacy results
    /// use ActorInvocation::commitment and are never interchangeable with them.
    pub request: Hash,
    pub reply: super::execution::ActorExecutionReply,
    /// Physical durable component retaining this exact result. Query replies
    /// have no logical write lane, so this cannot be inferred from `reply`.
    pub storage: InvocationResultStorage,
    /// Clean-generation acceptance data. Legacy execution results keep this
    /// absent and can never be retired through the clean acknowledgement ABI.
    pub(crate) clean: Option<StandardCleanInvocationResult>,
}

/// A durable clean rejection is not an actor reply. Its accepted work remains
/// authoritative even when the actor/installation no longer resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardCleanInvocationError {
    pub binding: StandardCleanInvocationResult,
    pub error: crate::agent_sdk::InvocationError,
}

impl StandardCleanInvocationError {
    pub(crate) fn key(&self) -> (InvocationScope, InvocationId) {
        (
            clean_method_mode(self.binding.accepted.mode).invocation_scope(),
            InvocationId(self.binding.accepted.invocation.0),
        )
    }

    pub(crate) fn storage(&self) -> InvocationResultStorage {
        clean_method_mode(self.binding.accepted.mode).result_storage()
    }
}

/// One guest-owned yielded inner-machine continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardMachineContinuation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: super::MethodMode,
    /// Internal execution request commitment used by exact-result recovery.
    pub request: Hash,
    /// Clean SDK InvocationWork commitment. Legacy execution records set this
    /// equal to `request` and have no accepted clean work metadata.
    pub work: Hash,
    pub ready_sequence: u64,
    /// Clean work and authorization accepted on the first slice. Immutable
    /// availability bytes are deliberately absent; only their sorted refs are
    /// retained and every resume must supply the exact preimages again.
    pub accepted: Option<StandardAcceptedInvocation>,
    pub authorization: Option<crate::agent_sdk::InvocationAuthorization>,
    pub observed_slot: u64,
    pub continuation: super::execution::ActorMachineContinuation,
}

// Retained acceptance and compact retirement share one portable metadata
// contract. State validation additionally refuses recovery-only acceptance.
pub(crate) type StandardAcceptedInvocation = crate::agent_sdk::InvocationRetirement;

/// Immutable clean authorization accepted with one retained terminal `Done`.
///
/// Availability payloads are represented by their canonical references so a
/// result cannot retain caller-sized blob preimages. Signed receipts are
/// retained in full for guest re-verification; unsigned PublicPreflight values
/// retain their exact work/origin/acceptance-slot binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandardCleanInvocationResult {
    pub accepted: StandardAcceptedInvocation,
    pub authorization: crate::agent_sdk::InvocationAuthorization,
    pub work: crate::agent_sdk::Hash,
    pub observed_slot: u64,
}

/// Read-only evidence for an exact accepted clean invocation. `None` from
/// inspection is distinct from a retained application `NotFound` rejection;
/// callers must never turn absence into a successful retry response.
#[cfg(feature = "experimental-state-blocks")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RetainedCleanTerminal {
    Completed(Result<super::execution::ActorExecutionReply, crate::agent_sdk::InvocationError>),
    Acknowledged(crate::agent_sdk::InvocationAcknowledgement),
}

impl StandardCleanInvocationResult {
    fn from_work(
        work: &crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Self {
        Self {
            accepted: StandardAcceptedInvocation::from_work(work),
            authorization,
            work: work.commitment(),
            observed_slot,
        }
    }

    fn matches(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> bool {
        self.matches_retirement(&StandardAcceptedInvocation::from_work(work), authorization)
    }

    fn matches_retirement(
        &self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> bool {
        self.accepted == *work
            && self.work == work.commitment()
            && self.authorization == *authorization
            && self.authorization.commitment() == authorization.commitment()
    }
}

impl StandardMachineContinuation {
    fn storage(&self) -> InvocationResultStorage {
        self.mode.result_storage()
    }

    pub(crate) fn validate_record(&self) -> bool {
        let clean_pair = match (&self.accepted, &self.authorization) {
            (Some(accepted), Some(authorization)) => {
                accepted.validate_accepted()
                    && accepted.invocation.0 == self.invocation.0
                    && accepted.actor.0 == self.actor.0
                    && accepted.incarnation.0 == self.incarnation.0
                    && accepted.deployment.0 == self.deployment.0
                    && accepted.program.0 == self.program.0
                    && accepted.mode as u8 == self.mode as u8
                    && clean_authorization_matches_accepted(
                        accepted,
                        authorization,
                        self.work,
                        self.observed_slot,
                    )
            }
            (None, None) => self.work == self.request,
            _ => false,
        };
        self.invocation != InvocationId::ZERO
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.program != ProgramId::ZERO
            && self.request != Hash::ZERO
            && self.work != Hash::ZERO
            && self.ready_sequence != 0
            && self.continuation.validate()
            && clean_pair
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, crate::service::wire::DecodeError> {
        super::wire::encode_standard_machine_continuation(self)
    }

    pub(crate) fn clean_reference(
        &self,
    ) -> Result<crate::agent_sdk::BlobRef, crate::service::wire::DecodeError> {
        self.canonical_bytes()
            .map(|bytes| crate::agent_sdk::BlobRef::of_bytes(&bytes))
    }

    pub(crate) fn yielded(
        &self,
    ) -> Result<crate::agent_sdk::YieldedInvocation, crate::service::wire::DecodeError> {
        let accepted = self
            .accepted
            .as_ref()
            .ok_or(crate::service::wire::DecodeError::NonCanonical)?;
        Ok(crate::agent_sdk::YieldedInvocation {
            invocation: accepted.invocation,
            actor: accepted.actor,
            incarnation: accepted.incarnation,
            deployment: accepted.deployment,
            program: accepted.program,
            mode: accepted.mode,
            continuation: self.clean_reference()?,
            ready_sequence: self.ready_sequence,
            installation_data: accepted.installation_data.clone(),
            required: accepted.required.clone(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        })
    }
}

fn clean_authorization_matches_accepted(
    accepted: &StandardAcceptedInvocation,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    expected_work: Hash,
    observed_slot: u64,
) -> bool {
    use crate::agent_sdk::InvocationAuthorization;
    use crate::agent_sdk::authority::AuthorityOperationKind;

    if accepted.commitment().0 != expected_work.0 {
        return false;
    }

    match authorization {
        InvocationAuthorization::AuthorityReceipt(receipt) => {
            receipt.validate_shape().is_ok()
                && receipt.selector.operation == AuthorityOperationKind::InvokeActor
                && receipt.selector.space == accepted.space
                && receipt.selector.agent == accepted.agent
                && receipt.selector.runtime_deployment == accepted.runtime_deployment
                && receipt.selector.actor == Some(accepted.actor)
                && receipt.selector.actor_deployment == Some(accepted.deployment)
                && receipt.selector.request.0 == expected_work.0
        }
        InvocationAuthorization::PublicPreflight(preflight) => {
            authorization.validate_shape()
                && preflight.work.0 == expected_work.0
                && preflight.origin == accepted.origin
                && preflight.observed_slot == observed_slot
                && accepted.roles == crate::agent_sdk::InvocationRoleClaims::none()
                && accepted.origin.capability.is_none()
        }
    }
}

pub(crate) fn clean_authorization_is_live_at(
    authorization: &crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
) -> bool {
    match authorization {
        crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) => {
            receipt.selector.is_live_at(observed_slot)
        }
        crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) => {
            preflight.observed_slot == observed_slot
        }
    }
}

pub(crate) fn clean_authorization_work(
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Hash {
    match authorization {
        crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) => {
            Hash(receipt.selector.request.0)
        }
        crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) => {
            Hash(preflight.work.0)
        }
    }
}

fn continuation_storage_tag(storage: InvocationResultStorage) -> u8 {
    match storage {
        InvocationResultStorage::Control => 0,
        InvocationResultStorage::Lane(StateLane::Linear) => 1,
        InvocationResultStorage::Lane(StateLane::Merge) => 2,
        InvocationResultStorage::Lane(StateLane::Local) => 3,
    }
}

fn continuation_order_key(continuation: &StandardMachineContinuation) -> (u8, u64) {
    (
        continuation_storage_tag(continuation.storage()),
        continuation.ready_sequence,
    )
}

fn clean_profile_to_legacy(profile: crate::agent_sdk::AgentProfile) -> super::AgentProfile {
    match profile {
        crate::agent_sdk::AgentProfile::Local => super::AgentProfile::Local,
        crate::agent_sdk::AgentProfile::Shared => super::AgentProfile::Shared,
        crate::agent_sdk::AgentProfile::Private => super::AgentProfile::Private,
    }
}

fn clean_lanes_to_legacy(lanes: crate::agent_sdk::LaneSet) -> super::LaneSet {
    super::LaneSet::from_bits(lanes.bits()).expect("portable lanes share the closed three-bit set")
}

fn clean_capabilities_to_legacy(
    capabilities: crate::agent_sdk::RuntimeCapabilities,
    profile: crate::agent_sdk::AgentProfile,
) -> super::RuntimeCapabilities {
    let mut lanes = capabilities.lanes.bits();
    if profile == crate::agent_sdk::AgentProfile::Private {
        lanes &= !super::LaneSet::of(super::StateLane::Linear).bits();
    }
    super::RuntimeCapabilities {
        lanes: super::LaneSet::from_bits(lanes).expect("masked portable lanes remain canonical"),
        scheduling: capabilities.scheduling,
        proofs: !capabilities.proof_systems.is_empty(),
        max_actors: capabilities.max_actors,
    }
}

fn clean_runtime_contract_to_legacy(
    contract: crate::agent_sdk::contract::RuntimePackageContract,
) -> super::contract::RuntimePackageContract {
    super::contract::RuntimePackageContract {
        // The transitional state machinery is an implementation detail. Its
        // own codec pins remain local and are never exposed as the portable
        // package contract.
        lifecycle_abi: super::RUNTIME_ABI_ID,
        actor_abis: super::contract::ActorAbiRange {
            minimum: contract.actor_abis.minimum,
            maximum: contract.actor_abis.maximum,
        },
        control_schema: super::contract::CONTROL_SCHEMA_ID,
        resources: super::contract::RuntimeResourceLimits {
            max_runtime_state_bytes: contract.resources.max_runtime_state_bytes,
            max_artifact_references: contract.resources.max_artifact_references,
            max_artifact_referenced_bytes: contract.resources.max_artifact_referenced_bytes,
        },
        migration: super::contract::RuntimeMigrationPolicy::None,
    }
}

pub(crate) fn clean_descriptor_to_legacy_config(
    descriptor: &crate::agent_sdk::AgentDescriptor,
) -> Result<AgentConfig, LifecycleError> {
    descriptor
        .validate()
        .map_err(|_| LifecycleError::InvalidRequest)?;
    let raw_key = descriptor.authority.public_key;
    let public_key = super::authority::ed25519_public_key_wire(raw_key);
    let profile = clean_profile_to_legacy(descriptor.identity.profile);
    let config = AgentConfig {
        identity: super::AgentIdentity {
            space: crate::service::SpaceId(descriptor.identity.space.0),
            agent: crate::service::AgentId(descriptor.identity.agent.0),
            owner: crate::service::PrincipalId(descriptor.identity.owner.0),
            profile,
            runtime_deployment: crate::service::DeploymentId(
                descriptor.identity.runtime_deployment.0,
            ),
            runtime_program: crate::service::ProgramId(descriptor.identity.runtime_program.0),
            runtime_producer: crate::service::ProducerId(descriptor.identity.runtime_producer.0),
            transition_producer: crate::service::ProducerId(
                descriptor.identity.transition_producer.0,
            ),
        },
        creation_nonce: Hash(descriptor.creation_nonce.0),
        authority: super::authority::AgentAuthorityBinding {
            agent: crate::service::AgentId(descriptor.identity.agent.0),
            actor: crate::service::ActorId(descriptor.authority.issuer.actor.0),
            deployment: crate::service::DeploymentId(descriptor.authority.issuer.deployment.0),
            program: crate::service::ProgramId(descriptor.authority.issuer.program.0),
            producer: crate::service::ProducerId::of_public_key(&public_key),
            public_key,
        },
        system_authority_genesis: None,
        runtime_package: crate::service::BlobRef {
            hash: Hash(descriptor.runtime_package.hash.0),
            len: descriptor.runtime_package.len,
        },
        runtime_contract: clean_runtime_contract_to_legacy(descriptor.runtime_contract),
        capabilities: clean_capabilities_to_legacy(
            descriptor.capabilities,
            descriptor.identity.profile,
        ),
        replicas: descriptor
            .replicas
            .iter()
            .map(|replica| super::AgentReplica {
                node: crate::service::NodeId(replica.node.0),
                principal: crate::service::PrincipalId(replica.principal.0),
                role: match replica.role {
                    crate::agent_sdk::ReplicaRole::Voter => super::ReplicaRole::Voter,
                    crate::agent_sdk::ReplicaRole::Observer => super::ReplicaRole::Observer,
                },
            })
            .collect(),
    };
    // `AgentConfig` is an internal compatibility projection. Its historical
    // validator derives AgentId in the legacy domain, while the portable SDK
    // descriptor deliberately derives the identity in the SDK domain. The
    // descriptor above is the authoritative validation boundary for this
    // path; do not reinterpret its identity through the legacy derivation.
    Ok(config)
}

fn clean_descriptors_share_immutable_creation(
    creation: &crate::agent_sdk::AgentDescriptor,
    current: &crate::agent_sdk::AgentDescriptor,
) -> bool {
    creation.identity.space == current.identity.space
        && creation.identity.agent == current.identity.agent
        && creation.identity.owner == current.identity.owner
        && creation.identity.profile == current.identity.profile
        && creation.creation_nonce == current.creation_nonce
        && creation.authority == current.authority
}

fn clean_requirements_to_legacy(
    requirements: crate::agent_sdk::RuntimeRequirements,
) -> super::RuntimeRequirements {
    super::RuntimeRequirements {
        lanes: clean_lanes_to_legacy(requirements.lanes),
        scheduling: requirements.scheduling,
        proofs: !requirements.proof_systems.is_empty(),
    }
}

fn clean_actor_contract_to_legacy(
    contract: crate::agent_sdk::contract::ActorPackageContract,
) -> super::contract::ActorPackageContract {
    super::contract::ActorPackageContract {
        actor_abi: contract.actor_abi,
    }
}

fn clean_blob_to_legacy(reference: &crate::agent_sdk::BlobRef) -> crate::service::BlobRef {
    crate::service::BlobRef {
        hash: Hash(reference.hash.0),
        len: reference.len,
    }
}

fn clean_reference_matches_record(
    reference: &crate::agent_sdk::BlobRef,
    expected: &crate::service::BlobRef,
) -> bool {
    reference.hash.0 == expected.hash.0 && reference.len == expected.len
}

fn clean_entry_to_legacy(entry: &crate::agent_sdk::ActorEntry) -> super::ActorEntry {
    super::ActorEntry {
        actor: crate::service::ActorId(entry.actor.0),
        name: entry.name.clone(),
        parent: entry.parent.map(|value| crate::service::ActorId(value.0)),
        deployment: crate::service::DeploymentId(entry.deployment.0),
        program: crate::service::ProgramId(entry.program.0),
        package: clean_blob_to_legacy(&entry.package),
        agent_schema: clean_blob_to_legacy(&entry.agent_schema),
        role_policies: clean_blob_to_legacy(&entry.method_policy),
        constructor_abi: Hash(entry.constructor_abi.0),
        installation_data: entry.installation_data.as_ref().map(clean_blob_to_legacy),
        state_layout: Hash(entry.state_layout.0),
        lanes: clean_lanes_to_legacy(entry.lanes),
        suspended: entry.suspended,
    }
}

pub(crate) fn legacy_entry_to_clean(entry: &super::ActorEntry) -> crate::agent_sdk::ActorEntry {
    crate::agent_sdk::ActorEntry {
        actor: crate::agent_sdk::ActorId(entry.actor.0),
        name: entry.name.clone(),
        parent: entry.parent.map(|value| crate::agent_sdk::ActorId(value.0)),
        deployment: crate::agent_sdk::DeploymentId(entry.deployment.0),
        program: crate::agent_sdk::ProgramId(entry.program.0),
        package: crate::agent_sdk::BlobRef {
            hash: crate::agent_sdk::Hash(entry.package.hash.0),
            len: entry.package.len,
        },
        agent_schema: crate::agent_sdk::BlobRef {
            hash: crate::agent_sdk::Hash(entry.agent_schema.hash.0),
            len: entry.agent_schema.len,
        },
        method_policy: crate::agent_sdk::BlobRef {
            hash: crate::agent_sdk::Hash(entry.role_policies.hash.0),
            len: entry.role_policies.len,
        },
        constructor_abi: crate::agent_sdk::Hash(entry.constructor_abi.0),
        installation_data: entry.installation_data.as_ref().map(|reference| {
            crate::agent_sdk::BlobRef {
                hash: crate::agent_sdk::Hash(reference.hash.0),
                len: reference.len,
            }
        }),
        state_layout: crate::agent_sdk::Hash(entry.state_layout.0),
        lanes: crate::agent_sdk::LaneSet::from_bits(entry.lanes.bits())
            .expect("transitional lanes share the closed three-bit set"),
        suspended: entry.suspended,
    }
}

pub(crate) fn legacy_actor_record_to_clean(
    record: &ActorRecord,
    install_request: crate::agent_sdk::Hash,
) -> crate::agent_sdk::ActorDirectoryRecord {
    crate::agent_sdk::ActorDirectoryRecord {
        entry: legacy_entry_to_clean(&record.entry),
        incarnation: crate::agent_sdk::Hash(record.state_generation.0),
        installation_id: crate::agent_sdk::InstallationId(record.installation_id.0),
        registry_reservation: crate::agent_sdk::Hash(record.registry_reservation.0),
        install_request,
    }
}

fn clean_install_to_legacy(install: &crate::agent_sdk::InstallActor) -> super::InstallActor {
    super::InstallActor {
        installation_id: crate::service::InstallationId(install.installation_id.0),
        registry_reservation: Hash(install.registry_reservation.0),
        entry: clean_entry_to_legacy(&install.entry),
        producer: crate::service::ProducerId(install.producer.0),
        package: clean_blob_to_legacy(&install.package),
        agent_schema: clean_blob_to_legacy(&install.agent_schema),
        role_policies: clean_blob_to_legacy(&install.method_policy),
        constructor_abi: Hash(install.constructor_abi.0),
        installation_data: install
            .installation_data
            .as_ref()
            .map(|data| super::InstallationData {
                reference: clean_blob_to_legacy(&data.reference),
                bytes: data.bytes.clone(),
            }),
        state_layout: Hash(install.state_layout.0),
        contract: clean_actor_contract_to_legacy(install.contract),
        requirements: clean_requirements_to_legacy(install.requirements),
    }
}

pub(crate) fn clean_installation_binding(
    install: &crate::agent_sdk::InstallActor,
) -> StandardCleanActorInstallation {
    StandardCleanActorInstallation {
        actor: install.entry.actor,
        commitment: install.lineage_commitment(),
        contract: install.contract,
        requirements: install.requirements,
        original: crate::agent_sdk::authority::CompactInstallActor {
            installation_id: install.installation_id,
            registry_reservation: install.registry_reservation,
            entry: install.entry.clone(),
            producer: install.producer,
            contract: install.contract,
            requirements: install.requirements,
        },
    }
}

fn clean_upgrade_to_legacy(upgrade: &crate::agent_sdk::UpgradeActor) -> super::UpgradeActor {
    super::UpgradeActor {
        actor: crate::service::ActorId(upgrade.actor.0),
        from_deployment: crate::service::DeploymentId(upgrade.from_deployment.0),
        to_deployment: crate::service::DeploymentId(upgrade.to_deployment.0),
        to_program: crate::service::ProgramId(upgrade.to_program.0),
        producer: crate::service::ProducerId(upgrade.producer.0),
        package: clean_blob_to_legacy(&upgrade.package),
        agent_schema: clean_blob_to_legacy(&upgrade.agent_schema),
        role_policies: clean_blob_to_legacy(&upgrade.method_policy),
        constructor_abi: Hash(upgrade.constructor_abi.0),
        state_layout: Hash(upgrade.state_layout.0),
        contract: clean_actor_contract_to_legacy(upgrade.contract),
        requirements: clean_requirements_to_legacy(upgrade.requirements),
    }
}

fn legacy_identity_to_clean(identity: &super::AgentIdentity) -> crate::agent_sdk::AgentIdentity {
    crate::agent_sdk::AgentIdentity {
        space: crate::agent_sdk::SpaceId(identity.space.0),
        agent: crate::agent_sdk::AgentId(identity.agent.0),
        owner: crate::agent_sdk::PrincipalId(identity.owner.0),
        profile: match identity.profile {
            super::AgentProfile::Local => crate::agent_sdk::AgentProfile::Local,
            super::AgentProfile::Shared => crate::agent_sdk::AgentProfile::Shared,
            super::AgentProfile::Private => crate::agent_sdk::AgentProfile::Private,
        },
        runtime_deployment: crate::agent_sdk::DeploymentId(identity.runtime_deployment.0),
        runtime_program: crate::agent_sdk::ProgramId(identity.runtime_program.0),
        runtime_producer: crate::agent_sdk::ProducerId(identity.runtime_producer.0),
        transition_producer: crate::agent_sdk::ProducerId(identity.transition_producer.0),
    }
}

fn legacy_debt_to_clean(debt: super::ActorLifecycleDebt) -> crate::agent_sdk::ActorLifecycleDebt {
    crate::agent_sdk::ActorLifecycleDebt {
        children: debt.children,
        continuations: debt.continuations,
        inbox: debt.inbox,
        outbox: debt.outbox,
        schedules: debt.schedules,
        proof_artifacts: debt.proof_artifacts,
        lifecycle_operations: debt.lifecycle_operations,
    }
}

fn legacy_management_error(error: LifecycleError) -> crate::agent_sdk::ManagementError {
    use crate::agent_sdk::ManagementError;
    match error {
        LifecycleError::NotCreated => ManagementError::NotCreated,
        LifecycleError::AlreadyCreated => ManagementError::AlreadyCreated,
        LifecycleError::NotFound => ManagementError::NotFound,
        LifecycleError::AlreadyExists => ManagementError::AlreadyExists,
        LifecycleError::StaleDeployment => ManagementError::StaleDeployment,
        LifecycleError::UnsupportedRuntime => ManagementError::UnsupportedRuntime,
        LifecycleError::UnsupportedLane => ManagementError::UnsupportedLane,
        LifecycleError::Busy(debt) => ManagementError::Busy(legacy_debt_to_clean(debt)),
        LifecycleError::DirectoryFull => ManagementError::DirectoryFull,
        LifecycleError::InvalidRequest | LifecycleError::SystemAuthority(_) => {
            ManagementError::InvalidRequest
        }
        LifecycleError::AuthoritySequenceRegressed => ManagementError::AuthoritySequenceRegressed,
        LifecycleError::AuthoritySequenceConflict => ManagementError::AuthoritySequenceConflict,
        LifecycleError::AuthoritySlotRegressed => ManagementError::AuthoritySlotRegressed,
        LifecycleError::ResourceLimit => ManagementError::ResourceLimit,
    }
}

const fn clean_method_mode(mode: crate::agent_sdk::MethodMode) -> super::MethodMode {
    match mode {
        crate::agent_sdk::MethodMode::Query => super::MethodMode::Query,
        crate::agent_sdk::MethodMode::LinearizableQuery => super::MethodMode::LinearizableQuery,
        crate::agent_sdk::MethodMode::LocalQuery => super::MethodMode::LocalQuery,
        crate::agent_sdk::MethodMode::Linear => super::MethodMode::Linear,
        crate::agent_sdk::MethodMode::Merge => super::MethodMode::Merge,
        crate::agent_sdk::MethodMode::Local => super::MethodMode::Local,
    }
}

fn valid_clean_invocation_acknowledgements(
    acknowledgements: &[crate::agent_sdk::InvocationAcknowledgement],
) -> bool {
    acknowledgements.len() <= MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE * 4
        && acknowledgements
            .iter()
            .all(crate::agent_sdk::InvocationAcknowledgement::validate)
        && acknowledgements.iter().enumerate().all(|(index, item)| {
            let scope = clean_method_mode(item.mode).invocation_scope();
            acknowledgements[..index].iter().all(|prior| {
                prior.invocation != item.invocation
                    || clean_method_mode(prior.mode).invocation_scope() != scope
            })
        })
        && acknowledgements.windows(2).all(|pair| {
            clean_acknowledgement_storage_tag(pair[0].mode)
                <= clean_acknowledgement_storage_tag(pair[1].mode)
        })
        && [
            InvocationResultStorage::Control,
            InvocationResultStorage::Lane(StateLane::Linear),
            InvocationResultStorage::Lane(StateLane::Merge),
            InvocationResultStorage::Lane(StateLane::Local),
        ]
        .into_iter()
        .all(|storage| {
            acknowledgements
                .iter()
                .filter(|item| clean_method_mode(item.mode).result_storage() == storage)
                .count()
                <= MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE
        })
}

const fn clean_acknowledgement_storage_tag(mode: crate::agent_sdk::MethodMode) -> u8 {
    match clean_method_mode(mode).result_storage() {
        InvocationResultStorage::Control => 0,
        InvocationResultStorage::Lane(StateLane::Linear) => 1,
        InvocationResultStorage::Lane(StateLane::Merge) => 2,
        InvocationResultStorage::Lane(StateLane::Local) => 3,
    }
}

/// Authenticated system-authority projections are read-only and carry their
/// complete replay binding inside the signed query. Their ordered journal
/// acknowledgement is therefore the durable retirement fact; retaining a
/// second positive acknowledgement forever in guest state would exhaust the
/// generic 32-result lane after 32 inventory pages. No other clean invocation
/// is eligible for this compaction.
fn is_system_authority_projection_query(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    work: &crate::agent_sdk::InvocationRetirement,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> bool {
    use crate::actors::codec::{Decode as _, Encode as _};
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::agent_sdk::authority::{
        AuthorityActorTarget, AuthorityProjectionQuery, AuthorityProjectionSelector,
    };
    use crate::agent_sdk::wire::CanonicalWire as _;

    if descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
        || work.mode != crate::agent_sdk::MethodMode::Query
        || !matches!(
            authorization,
            crate::agent_sdk::InvocationAuthorization::PublicPreflight(_)
        )
        || work.space != descriptor.identity.space
        || work.agent != descriptor.identity.agent
        || work.actor != descriptor.authority.issuer.actor
        || work.deployment != descriptor.authority.issuer.deployment
        || work.program != descriptor.authority.issuer.program
        || work.origin.principal.is_some()
        || work.origin.credential.is_some()
        || work.origin.actor.is_some()
        || work.origin.capability.is_some()
        || work.roles != crate::agent_sdk::InvocationRoleClaims::none()
    {
        return false;
    }
    let Some(message) = work
        .message
        .strip_prefix(&[TAG_DYNAMIC])
        .and_then(Msg::try_decode)
    else {
        return false;
    };
    if message.args.0.len() != 1 {
        return false;
    }
    let Some(Value::Bytes(query_bytes)) = message.args.get("query") else {
        return false;
    };
    let Ok(query) = AuthorityProjectionQuery::decode(query_bytes) else {
        return false;
    };
    let expected_method = match query.selector {
        AuthorityProjectionSelector::Inventory { .. } => "inventory_projection_page",
        AuthorityProjectionSelector::Credential => "credential_projection",
        AuthorityProjectionSelector::Agents { .. } => "agent_projection_page",
        AuthorityProjectionSelector::AgentReplicas { .. } => "agent_replica_projection_page",
        AuthorityProjectionSelector::Actors { .. } => "actor_projection_page",
    };
    query.validate_shape().is_ok()
        && query.encode().ok().as_deref() == Some(query_bytes.as_slice())
        && message.name == expected_method
        && query.authority
            == (AuthorityActorTarget {
                space: descriptor.identity.space,
                system_agent: descriptor.identity.agent,
                system_runtime_deployment: descriptor.identity.runtime_deployment,
                binding: descriptor.authority,
            })
        && query.attesting_node() == work.origin.transport_node
        && work.invocation
            == crate::agent_sdk::InvocationId(
                crate::agent_sdk::Hash::digest(
                    b"vos/system-authority/projection-invocation/v2",
                    &[query.commitment().as_bytes()],
                )
                .0,
            )
        && message.encode() == work.message[1..]
}

/// Highest sequence position whose retirement fact each result component has
/// compacted. Every sequenced identity at or below it was accepted and
/// retired; it is refused as divergent and can never become unseen work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StandardSequencedRetirement {
    pub control: u64,
    pub linear: u64,
    pub merge: u64,
    pub local: u64,
}

impl StandardSequencedRetirement {
    pub fn get(self, storage: InvocationResultStorage) -> u64 {
        match storage {
            InvocationResultStorage::Control => self.control,
            InvocationResultStorage::Lane(StateLane::Linear) => self.linear,
            InvocationResultStorage::Lane(StateLane::Merge) => self.merge,
            InvocationResultStorage::Lane(StateLane::Local) => self.local,
        }
    }

    fn set(&mut self, storage: InvocationResultStorage, value: u64) {
        *match storage {
            InvocationResultStorage::Control => &mut self.control,
            InvocationResultStorage::Lane(StateLane::Linear) => &mut self.linear,
            InvocationResultStorage::Lane(StateLane::Merge) => &mut self.merge,
            InvocationResultStorage::Lane(StateLane::Local) => &mut self.local,
        } = value;
    }
}

/// The sequence position a clean identity names in `mode`'s own result
/// component: `Ok(None)` for an unsequenced identity, `Err` for a malformed
/// one or one naming another component.
fn clean_sequenced_position(
    invocation: crate::agent_sdk::InvocationId,
    mode: crate::agent_sdk::MethodMode,
) -> Result<Option<u64>, crate::agent_sdk::InvocationError> {
    use crate::agent_sdk::{SequencedInvocation, SequencedInvocationId};
    match SequencedInvocation::classify(invocation) {
        SequencedInvocationId::Unsequenced => Ok(None),
        SequencedInvocationId::Malformed => {
            Err(crate::agent_sdk::InvocationError::DivergentInvocation)
        }
        SequencedInvocationId::Sequenced(sequenced) => {
            if sequenced.storage != mode.result_storage() {
                return Err(crate::agent_sdk::InvocationError::DivergentInvocation);
            }
            Ok(Some(sequenced.sequence.get()))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StandardLaneRevisions {
    pub linear: u64,
    pub merge: u64,
    pub local: u64,
    pub linear_authority_slot: Option<u64>,
    pub merge_authority_slot: Option<u64>,
    pub local_authority_slot: Option<u64>,
}

impl StandardLaneRevisions {
    fn authority_slot(self, lane: StateLane) -> Option<u64> {
        match lane {
            StateLane::Linear => self.linear_authority_slot,
            StateLane::Merge => self.merge_authority_slot,
            StateLane::Local => self.local_authority_slot,
        }
    }

    fn revision(self, lane: StateLane) -> u64 {
        match lane {
            StateLane::Linear => self.linear,
            StateLane::Merge => self.merge,
            StateLane::Local => self.local,
        }
    }

    fn set_authority_slot(&mut self, lane: StateLane, slot: u64) {
        *match lane {
            StateLane::Linear => &mut self.linear_authority_slot,
            StateLane::Merge => &mut self.merge_authority_slot,
            StateLane::Local => &mut self.local_authority_slot,
        } = Some(slot);
    }

    fn authority_slot_high_water(self) -> Option<u64> {
        [
            self.linear_authority_slot,
            self.merge_authority_slot,
            self.local_authority_slot,
        ]
        .into_iter()
        .flatten()
        .max()
    }

    #[cfg(feature = "pvm")]
    fn increment(&mut self, lane: StateLane) -> Result<(), super::execution::ActorExecutionError> {
        let revision = match lane {
            StateLane::Linear => &mut self.linear,
            StateLane::Merge => &mut self.merge,
            StateLane::Local => &mut self.local,
        };
        *revision = revision
            .checked_add(1)
            .ok_or(super::execution::ActorExecutionError::InvalidActorOutput)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardActorState {
    pub record: ActorRecord,
    pub debt: ActorLifecycleDebt,
}

/// Exact SDK package contract and runtime requirements retained for one
/// clean actor. These fields cannot be reconstructed from the legacy
/// compatibility projection because that projection collapses proof-system
/// identities to a boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardCleanActorPackage {
    pub actor: crate::agent_sdk::ActorId,
    pub contract: crate::agent_sdk::contract::ActorPackageContract,
    pub requirements: crate::agent_sdk::RuntimeRequirements,
}

/// Original compact install facts retained independently of upgradeable actor
/// metadata. Recomputing the SDK lineage commitment binds the exact contract
/// and requirements even after upgrade, without retaining constructor bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardCleanActorInstallation {
    pub actor: crate::agent_sdk::ActorId,
    pub commitment: crate::agent_sdk::Hash,
    pub contract: crate::agent_sdk::contract::ActorPackageContract,
    pub requirements: crate::agent_sdk::RuntimeRequirements,
    pub original: crate::agent_sdk::authority::CompactInstallActor,
}

impl StandardCleanActorInstallation {
    fn validates_original(&self, record: &ActorRecord) -> bool {
        self.original.is_valid()
            && self.original.entry.actor == self.actor
            && self.original.installation_id.0 == record.installation_id.0
            && self.original.registry_reservation.0 == record.registry_reservation.0
            && self.original.contract == self.contract
            && self.original.requirements == self.requirements
            && self.original.lineage_commitment() == self.commitment
    }
}

/// One independently keyed physical lane entry. Active entries are selected
/// by the directory's exact `(actor, state_generation)` pair. Nonmatching
/// entries are historical and remain authenticated until checkpoint-only
/// compaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardLaneEntry {
    pub actor: ActorId,
    pub state_generation: Hash,
    /// Inline fields only; row collections never enter inner FETCH snapshots.
    pub value: Vec<u8>,
    pub rows: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Sparse physical state of all three independently persisted lanes. A
/// supported active actor with no matching entry hydrates as canonical empty
/// state; unsupported lanes hydrate as absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StandardLaneState {
    pub linear: Vec<StandardLaneEntry>,
    pub merge: Vec<StandardLaneEntry>,
    pub local: Vec<StandardLaneEntry>,
}

impl StandardAgentRuntime {
    pub const fn new() -> Self {
        Self {
            config: None,
            clean_creation_descriptor: None,
            clean_descriptor: None,
            clean_authority_epoch_high_water: None,
            clean_decision_sequence_high_water: None,
            clean_acknowledged_through: 0,
            clean_management_dispositions: Vec::new(),
            active_resource_policy: None,
            private_runtime_control_commitment: None,
            private_runtime_control_sequence: None,
            private_authority_epoch_high_water: None,
            private_control_slot_high_water: None,
            private_management_dispositions: Vec::new(),
            system_authority: None,
            actors: BTreeMap::new(),
            program_bindings: BTreeMap::new(),
            retired_installation_ids: BTreeSet::new(),
            lane_state: StandardLaneState {
                linear: Vec::new(),
                merge: Vec::new(),
                local: Vec::new(),
            },
            invocation_results: BTreeMap::new(),
            clean_invocation_errors: BTreeMap::new(),
            clean_invocation_acknowledgements: Vec::new(),
            sequenced_retired_through: StandardSequencedRetirement {
                control: 0,
                linear: 0,
                merge: 0,
                local: 0,
            },
            machine_continuations: Vec::new(),
            lane_revisions: StandardLaneRevisions {
                linear: 0,
                merge: 0,
                local: 0,
                linear_authority_slot: None,
                merge_authority_slot: None,
                local_authority_slot: None,
            },
            control_authority_slot: None,
            authority_slot_high_water: None,
            authority_sequence_high_water: None,
            authority_dispositions: Vec::new(),
        }
    }

    pub fn config(&self) -> Option<&AgentConfig> {
        self.config.as_ref()
    }

    pub fn clean_descriptor(&self) -> Option<&crate::agent_sdk::AgentDescriptor> {
        self.clean_descriptor.as_ref()
    }

    pub(crate) fn system_authority(
        &self,
    ) -> Option<&super::system_authority::SystemAuthorityState> {
        self.system_authority.as_ref()
    }

    pub fn actor(&self, actor: ActorId) -> Option<&ActorEntry> {
        self.actors.get(&actor).map(|actor| &actor.record.entry)
    }

    /// Project one exact clean actor record from this already validated
    /// runtime image. Physical hosts use this only while they retain their
    /// exclusive image/journal ownership; it does not resolve catalog bytes
    /// and therefore cannot by itself make a route ready.
    pub(crate) fn clean_actor_record(
        &self,
        actor: crate::agent_sdk::ActorId,
    ) -> Option<crate::agent_sdk::ActorDirectoryRecord> {
        self.actors.get(&ActorId(actor.0)).and_then(|managed| {
            Some(legacy_actor_record_to_clean(
                &managed.record,
                managed.clean_installation.as_ref()?.commitment,
            ))
        })
    }

    /// Return the immutable SDK install lineage retained separately from the
    /// actor's upgradeable directory/package facts.
    pub(crate) fn clean_actor_installation(
        &self,
        actor: crate::agent_sdk::ActorId,
    ) -> Option<StandardCleanActorInstallation> {
        self.actors
            .get(&ActorId(actor.0))
            .and_then(|managed| managed.clean_installation.clone())
    }

    pub fn actor_record(&self, actor: ActorId) -> Option<&ActorRecord> {
        self.actors.get(&actor).map(|actor| &actor.record)
    }

    pub fn len(&self) -> usize {
        self.actors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    pub fn snapshot(&self) -> StandardRuntimeState {
        StandardRuntimeState {
            config: self.config.clone(),
            clean_creation_descriptor: self.clean_creation_descriptor.clone(),
            clean_descriptor: self.clean_descriptor.clone(),
            clean_authority_epoch_high_water: self.clean_authority_epoch_high_water,
            clean_decision_sequence_high_water: self.clean_decision_sequence_high_water,
            clean_acknowledged_through: self.clean_acknowledged_through,
            clean_management_dispositions: self.clean_management_dispositions.clone(),
            active_resource_policy: self.active_resource_policy,
            private_runtime_control_commitment: self.private_runtime_control_commitment,
            private_runtime_control_sequence: self.private_runtime_control_sequence,
            private_authority_epoch_high_water: self.private_authority_epoch_high_water,
            private_control_slot_high_water: self.private_control_slot_high_water,
            private_management_dispositions: self.private_management_dispositions.clone(),
            system_authority: self.system_authority.clone(),
            actors: self
                .actors
                .values()
                .map(|actor| StandardActorState {
                    record: actor.record.clone(),
                    debt: actor.debt,
                })
                .collect(),
            clean_actor_packages: self.clean_descriptor.as_ref().and_then(|_| {
                self.actors
                    .values()
                    .map(|actor| actor.clean_package)
                    .collect()
            }),
            clean_actor_installations: self.clean_descriptor.as_ref().and_then(|_| {
                self.actors
                    .values()
                    .map(|actor| actor.clean_installation.clone())
                    .collect()
            }),
            retired_installation_ids: self.retired_installation_ids.iter().copied().collect(),
            lane_state: self.lane_state.clone(),
            invocation_results: self.invocation_results.values().cloned().collect(),
            clean_invocation_errors: self.clean_invocation_errors.values().cloned().collect(),
            clean_invocation_acknowledgements: self.clean_invocation_acknowledgements.clone(),
            sequenced_retired_through: self.sequenced_retired_through,
            machine_continuations: self.machine_continuations.clone(),
            lane_revisions: self.lane_revisions,
            control_authority_slot: self.control_authority_slot,
            authority_slot_high_water: self.authority_slot_high_water,
            authority_sequence_high_water: self.authority_sequence_high_water,
            authority_dispositions: self.authority_dispositions.clone(),
            program_bindings: self.program_bindings.values().cloned().collect(),
        }
    }

    /// The verified reference bound to `actor`'s current program, if any.
    fn bound_program_reference(&self, actor: ActorId) -> Option<&crate::agent_sdk::BlobRef> {
        let binding = self.program_bindings.get(&actor)?;
        let current = self.actors.get(&actor)?;
        (current.record.entry.program == binding.program).then_some(&binding.reference)
    }

    /// Record that the bytes behind `reference` are `actor`'s current program.
    /// Callers pass only a reference the decoder authenticated for bytes whose
    /// ProgramId this guest has just computed (`resolve_clean_invocation`).
    #[cfg(feature = "pvm")]
    pub(crate) fn bind_program(&mut self, actor: ActorId, reference: crate::agent_sdk::BlobRef) {
        let Some(current) = self.actors.get(&actor) else {
            return;
        };
        let program = current.record.entry.program;
        self.program_bindings.insert(
            actor,
            StandardProgramBinding {
                actor,
                program,
                reference,
            },
        );
    }

    /// Drop only lane entries which do not belong to an active install.
    ///
    /// This is intentionally not part of ordinary lifecycle or actor
    /// execution. A checkpoint publisher may call it only while materializing
    /// a new authenticated checkpoint; journal history remains the authority
    /// for the compacted generations.
    #[allow(dead_code)]
    pub(crate) fn compact_historical_lane_entries_for_checkpoint(&mut self) {
        let actors = &self.actors;
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            self.lane_state.select_mut(lane).retain(|entry| {
                actors.get(&entry.actor).is_some_and(|actor| {
                    actor.record.state_generation == entry.state_generation
                        && actor.record.entry.lanes.contains(lane)
                })
            });
        }
    }

    pub fn restore(state: StandardRuntimeState) -> Result<Self, LifecycleError> {
        let clean_creation_descriptor = state.clean_creation_descriptor.clone();
        let clean_descriptor = state.clean_descriptor.clone();
        let clean_authority_epoch_high_water = state.clean_authority_epoch_high_water;
        let clean_decision_sequence_high_water = state.clean_decision_sequence_high_water;
        let clean_acknowledged_through = state.clean_acknowledged_through;
        let clean_management_dispositions = state.clean_management_dispositions.clone();
        let clean_actor_packages = state.clean_actor_packages.clone();
        let clean_actor_installations = state.clean_actor_installations.clone();
        let active_resource_policy = state.active_resource_policy;
        let private_runtime_control_commitment = state.private_runtime_control_commitment;
        let private_runtime_control_sequence = state.private_runtime_control_sequence;
        let private_authority_epoch_high_water = state.private_authority_epoch_high_water;
        let private_control_slot_high_water = state.private_control_slot_high_water;
        let private_management_dispositions = state.private_management_dispositions.clone();
        let Some(config) = state.config else {
            return if state.actors.is_empty()
                && state.clean_creation_descriptor.is_none()
                && state.clean_descriptor.is_none()
                && state.clean_authority_epoch_high_water.is_none()
                && state.clean_decision_sequence_high_water.is_none()
                && state.clean_acknowledged_through == 0
                && state.clean_management_dispositions.is_empty()
                && state.active_resource_policy.is_none()
                && state.private_runtime_control_commitment.is_none()
                && state.private_runtime_control_sequence.is_none()
                && state.private_authority_epoch_high_water.is_none()
                && state.private_control_slot_high_water.is_none()
                && state.private_management_dispositions.is_empty()
                && state.clean_actor_packages.is_none()
                && state.clean_actor_installations.is_none()
                && state.retired_installation_ids.is_empty()
                && state.system_authority.is_none()
                && state.lane_state == StandardLaneState::default()
                && state.invocation_results.is_empty()
                && state.clean_invocation_errors.is_empty()
                && state.clean_invocation_acknowledgements.is_empty()
                && state.sequenced_retired_through == StandardSequencedRetirement::default()
                && state.machine_continuations.is_empty()
                && state.lane_revisions == StandardLaneRevisions::default()
                && state.control_authority_slot.is_none()
                && state.authority_slot_high_water.is_none()
                && state.authority_sequence_high_water.is_none()
                && state.authority_dispositions.is_empty()
            {
                Ok(Self::new())
            } else {
                Err(LifecycleError::InvalidRequest)
            };
        };
        if state
            .actors
            .windows(2)
            .any(|pair| pair[0].record.entry.actor >= pair[1].record.entry.actor)
            || state.actors.iter().any(|actor| {
                actor.debt.children != 0
                    || actor.record.state_generation == Hash::ZERO
                    || actor.record.install_request_commitment == Hash::ZERO
            })
            || state.retired_installation_ids.len() > MAX_RETIRED_INSTALLATION_IDS
            || state
                .retired_installation_ids
                .iter()
                .any(|installation_id| *installation_id == InstallationId::ZERO)
            || state
                .retired_installation_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || state.actors.iter().any(|actor| {
                state
                    .retired_installation_ids
                    .binary_search(&actor.record.installation_id)
                    .is_ok()
            })
            || state.invocation_results.windows(2).any(|pair| {
                (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation)
            })
            || !valid_clean_invocation_acknowledgements(&state.clean_invocation_acknowledgements)
            || state.machine_continuations.len() > MAX_MACHINE_CONTINUATIONS
            || state
                .machine_continuations
                .iter()
                .any(|continuation| !continuation.validate_record())
            || state
                .machine_continuations
                .windows(2)
                .any(|pair| continuation_order_key(&pair[0]) >= continuation_order_key(&pair[1]))
            || state
                .machine_continuations
                .iter()
                .enumerate()
                .any(|(index, item)| {
                    state.machine_continuations[index + 1..]
                        .iter()
                        .any(|other| {
                            item.mode.invocation_scope() == other.mode.invocation_scope()
                                && item.invocation == other.invocation
                        })
                })
            || !state.lane_state.is_canonical()
            || state.authority_dispositions.len() > MAX_AUTHORITY_DISPOSITIONS
            || state
                .authority_dispositions
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(LifecycleError::InvalidRequest);
        }

        match (&clean_creation_descriptor, &clean_descriptor) {
            (None, None)
                if clean_authority_epoch_high_water.is_none()
                    && clean_decision_sequence_high_water.is_none()
                    && clean_acknowledged_through == 0
                    && clean_management_dispositions.is_empty()
                    && clean_actor_packages.is_none()
                    && clean_actor_installations.is_none() => {}
            (Some(creation), Some(current))
                if creation.validate().is_ok()
                    && current.validate().is_ok()
                    && clean_descriptors_share_immutable_creation(creation, current)
                    && clean_descriptor_to_legacy_config(current)
                        .is_ok_and(|projected| projected == config)
                    && clean_authority_epoch_high_water.is_some_and(|high_water| {
                        high_water >= creation.authority.initial_epoch
                            && clean_management_dispositions
                                .iter()
                                .all(|item| item.epoch <= high_water)
                            && clean_management_dispositions
                                .last()
                                .is_some_and(|item| item.epoch == high_water)
                    })
                    && clean_decision_sequence_high_water.is_some_and(|high_water| {
                        high_water > clean_acknowledged_through
                            && clean_management_dispositions
                                .last()
                                .is_some_and(|item| item.sequence == high_water)
                    })
                    && !clean_management_dispositions.is_empty()
                    && clean_management_dispositions.len() <= MAX_AUTHORITY_DISPOSITIONS
                    && clean_management_dispositions.iter().all(|item| {
                        item.authority != crate::agent_sdk::Hash::ZERO
                            && item.request != crate::agent_sdk::Hash::ZERO
                            && item.epoch >= creation.authority.initial_epoch
                            && item.sequence > clean_acknowledged_through
                    })
                    && clean_management_dispositions
                        .iter()
                        .enumerate()
                        .all(|(index, item)| {
                            clean_management_dispositions[index + 1..]
                                .iter()
                                .all(|other| item.authority != other.authority)
                        })
                    && clean_management_dispositions.windows(2).all(|pair| {
                        pair[0].sequence < pair[1].sequence
                            && pair[0].epoch <= pair[1].epoch
                            && pair[0].observed_slot < pair[1].observed_slot
                    })
                    && clean_management_dispositions.last().is_some_and(|item| {
                        state
                            .authority_slot_high_water
                            .is_some_and(|high_water| item.observed_slot <= high_water)
                    })
                    && clean_actor_packages.as_ref().is_some_and(|packages| {
                        packages.len() == state.actors.len()
                            && packages
                                .windows(2)
                                .all(|pair| pair[0].actor < pair[1].actor)
                            && packages.iter().zip(&state.actors).all(|(package, actor)| {
                                package.actor.0 == actor.record.entry.actor.0
                                    && package.contract.is_valid()
                                    && package.requirements.supported_by(current.identity.profile)
                                    && current.runtime_contract.supports(package.contract)
                                    && current.capabilities.satisfies(package.requirements)
                                    && actor.record.contract
                                        == clean_actor_contract_to_legacy(package.contract)
                                    && actor.record.requirements
                                        == clean_requirements_to_legacy(package.requirements)
                            })
                    })
                    && clean_actor_installations
                        .as_ref()
                        .is_some_and(|installations| {
                            installations.len() == state.actors.len()
                                && installations
                                    .windows(2)
                                    .all(|pair| pair[0].actor < pair[1].actor)
                                && installations.iter().zip(&state.actors).all(
                                    |(installation, actor)| {
                                        installation.actor.0 == actor.record.entry.actor.0
                                            && installation.validates_original(&actor.record)
                                            && installation.commitment
                                                != crate::agent_sdk::Hash::ZERO
                                            && installation.contract.is_valid()
                                            && installation
                                                .requirements
                                                .supported_by(current.identity.profile)
                                            && installation.requirements.lanes.bits()
                                                == actor.record.entry.lanes.bits()
                                    },
                                )
                        }) => {}
            _ => return Err(LifecycleError::InvalidRequest),
        }

        match (&clean_descriptor, active_resource_policy) {
            (None, None)
                if private_runtime_control_commitment.is_none()
                    && private_runtime_control_sequence.is_none()
                    && private_authority_epoch_high_water.is_none()
                    && private_control_slot_high_water.is_none()
                    && private_management_dispositions.is_empty() => {}
            (Some(descriptor), Some(policy))
                if policy.is_within(
                    descriptor.capabilities,
                    descriptor.runtime_contract.resources,
                ) && match descriptor.identity.profile {
                    crate::agent_sdk::AgentProfile::Private => {
                        let retained_policy = private_management_dispositions
                            .iter()
                            .rev()
                            .find_map(|item| match item.result.as_ref() {
                                Ok(crate::agent_sdk::ManagementReply::ResourcePolicySet(
                                    policy,
                                )) => Some(*policy),
                                _ => None,
                            })
                            .unwrap_or_else(|| descriptor.initial_resource_policy());
                        if private_management_dispositions.is_empty() {
                            policy == descriptor.initial_resource_policy()
                                && private_runtime_control_commitment.is_none()
                                && private_runtime_control_sequence.is_none()
                                && private_authority_epoch_high_water.is_none()
                                && private_control_slot_high_water.is_none()
                        } else {
                            policy == retained_policy
                                && private_management_dispositions.len()
                                    <= MAX_AUTHORITY_DISPOSITIONS
                                && private_runtime_control_commitment.is_some()
                                && private_runtime_control_sequence.is_some()
                                && private_authority_epoch_high_water.is_some()
                                && private_control_slot_high_water.is_some()
                                && private_management_dispositions.iter().all(|item| {
                                    item.authority != crate::agent_sdk::Hash::ZERO
                                        && item.control != crate::agent_sdk::Hash::ZERO
                                        && item.request != crate::agent_sdk::Hash::ZERO
                                        && (item.sequence == 0) == item.previous.is_none()
                                        && item.previous.is_none_or(|previous| {
                                            previous != crate::agent_sdk::Hash::ZERO
                                        })
                                        && item.epoch >= descriptor.authority.initial_epoch
                                        && matches!(
                                            &item.result,
                                            Ok(
                                                crate::agent_sdk::ManagementReply::ResourcePolicySet(
                                                    _
                                                ) | crate::agent_sdk::ManagementReply::Installed(_)
                                                    | crate::agent_sdk::ManagementReply::Upgraded(_)
                                                    | crate::agent_sdk::ManagementReply::Suspended(_)
                                                    | crate::agent_sdk::ManagementReply::Resumed(_)
                                                    | crate::agent_sdk::ManagementReply::Removed(_)
                                            )
                                        )
                                })
                                && private_management_dispositions.windows(2).all(|pair| {
                                    pair[0].sequence < pair[1].sequence
                                        && pair[0].epoch <= pair[1].epoch
                                        && pair[0].observed_slot <= pair[1].observed_slot
                                        && (pair[0].sequence.checked_add(1)
                                            != Some(pair[1].sequence)
                                            || pair[1].previous == Some(pair[0].control))
                                })
                                && private_management_dispositions.iter().enumerate().all(
                                    |(index, item)| {
                                        private_management_dispositions[index + 1..].iter().all(
                                            |other| {
                                                item.authority != other.authority
                                                    && item.control != other.control
                                            },
                                        )
                                    },
                                )
                                && private_management_dispositions.last().is_some_and(|item| {
                                    private_runtime_control_commitment == Some(item.control)
                                        && private_runtime_control_sequence == Some(item.sequence)
                                        && private_authority_epoch_high_water == Some(item.epoch)
                                        && private_control_slot_high_water
                                            == Some(item.observed_slot)
                                })
                        }
                    }
                    crate::agent_sdk::AgentProfile::Local
                    | crate::agent_sdk::AgentProfile::Shared => {
                        policy == descriptor.initial_resource_policy()
                            && private_runtime_control_commitment.is_none()
                            && private_runtime_control_sequence.is_none()
                            && private_authority_epoch_high_water.is_none()
                            && private_control_slot_high_water.is_none()
                            && private_management_dispositions.is_empty()
                    }
                } => {}
            _ => return Err(LifecycleError::InvalidRequest),
        }

        let mut runtime = Self::new();
        if clean_descriptor.is_some() {
            // A clean state has already been validated against its exact SDK
            // descriptor and compatibility projection above. Re-running the
            // legacy Create validator would reject the SDK AgentId domain.
            runtime.config = Some(config);
        } else {
            runtime.apply_mutation(LifecycleRequest::Create(config))?;
        }
        runtime.clean_creation_descriptor = clean_creation_descriptor;
        runtime.clean_descriptor = clean_descriptor;
        runtime.clean_authority_epoch_high_water = clean_authority_epoch_high_water;
        runtime.clean_decision_sequence_high_water = clean_decision_sequence_high_water;
        runtime.clean_acknowledged_through = clean_acknowledged_through;
        runtime.clean_management_dispositions = clean_management_dispositions;
        runtime.active_resource_policy = active_resource_policy;
        runtime.private_runtime_control_commitment = private_runtime_control_commitment;
        runtime.private_runtime_control_sequence = private_runtime_control_sequence;
        runtime.private_authority_epoch_high_water = private_authority_epoch_high_water;
        runtime.private_control_slot_high_water = private_control_slot_high_water;
        runtime.private_management_dispositions = private_management_dispositions;
        match (
            runtime
                .config
                .as_ref()
                .and_then(|config| config.system_authority_genesis.as_ref()),
            state.system_authority,
        ) {
            (Some(genesis), Some(system_authority)) => {
                system_authority
                    .validate_against_genesis(runtime.created()?.identity.agent, genesis)
                    .map_err(LifecycleError::SystemAuthority)?;
                runtime.system_authority = Some(system_authority);
            }
            (None, None) => {}
            _ => return Err(LifecycleError::InvalidRequest),
        }
        // Preserve the prior first-ready ordering without repeatedly scanning
        // and shifting the remaining forest. Each edge becomes ready once.
        let mut ready = BTreeSet::new();
        let mut children: BTreeMap<ActorId, Vec<usize>> = BTreeMap::new();
        let mut pending: Vec<_> = state.actors.into_iter().map(Some).collect();
        for (index, actor) in pending.iter().enumerate() {
            match actor.as_ref().unwrap().record.entry.parent {
                None => {
                    ready.insert(index);
                }
                Some(parent) => children.entry(parent).or_default().push(index),
            }
        }
        let mut restored = 0;
        let mut installation_ids = BTreeSet::new();
        let mut artifact_usage = ArtifactResourceUsage::default();
        let config = runtime.created()?;
        artifact_usage.insert(&config.runtime_package, config.runtime_contract.resources)?;
        let mut suspended = Vec::new();
        while let Some(index) = ready.pop_first() {
            let StandardActorState { mut record, debt } = pending[index].take().unwrap();
            if record.entry.suspended {
                suspended.push((record.entry.actor, record.entry.deployment));
                record.entry.suspended = false;
            }
            let actor_id = record.entry.actor;
            let clean_package = clean_actor_packages.as_ref().and_then(|packages| {
                packages
                    .binary_search_by_key(&crate::agent_sdk::ActorId(actor_id.0), |item| item.actor)
                    .ok()
                    .map(|index| packages[index])
            });
            let clean_installation = clean_actor_installations
                .as_ref()
                .and_then(|installations| {
                    installations
                        .binary_search_by_key(&crate::agent_sdk::ActorId(actor_id.0), |item| {
                            item.actor
                        })
                        .ok()
                        .map(|index| installations[index].clone())
                });
            let config = runtime.created()?;
            if record.installation_id == InstallationId::ZERO
                || record.registry_reservation == Hash::ZERO
                || record.entry.name.is_empty()
                || record.entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
                || record.entry.lanes != record.requirements.lanes
                || record.entry.deployment == DeploymentId::ZERO
                || record.entry.program == ProgramId::ZERO
                || record.entry.package != record.package
                || record.entry.agent_schema != record.agent_schema
                || record.entry.role_policies != record.role_policies
                || record.entry.constructor_abi != record.constructor_abi
                || record.entry.installation_data != record.installation_data
                || record.entry.state_layout != record.state_layout
                || record.producer == ProducerId::ZERO
                || record.package.hash == Hash::ZERO
                || record.package.len == 0
                || record.agent_schema.hash == Hash::ZERO
                || record.agent_schema.len == 0
                || record.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
                || record.role_policies.hash == Hash::ZERO
                || record.role_policies.len == 0
                || record.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
                || record.constructor_abi == Hash::ZERO
                || record.installation_data.as_ref().is_some_and(|reference| {
                    reference.hash == Hash::ZERO
                        || reference.len > super::MAX_INSTALLATION_DATA_BYTES as u64
                })
                || installation_data_aliases_actor_artifact(
                    record.installation_data.as_ref(),
                    &record.package,
                    &record.agent_schema,
                    &record.role_policies,
                )
                || record.state_layout == Hash::ZERO
                || runtime.expected_actor_id(&record.entry) != actor_id
                || !installation_ids.insert(record.installation_id)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.validate_requirements(record.requirements)?;
            if !config.runtime_contract.supports(record.contract) {
                return Err(LifecycleError::UnsupportedRuntime);
            }
            if runtime.actors.len() >= config.capabilities.max_actors as usize {
                return Err(LifecycleError::DirectoryFull);
            }
            for reference in [&record.package, &record.agent_schema, &record.role_policies]
                .into_iter()
                .chain(record.installation_data.iter())
            {
                artifact_usage.insert(reference, config.runtime_contract.resources)?;
            }
            runtime.actors.insert(
                actor_id,
                ManagedActor {
                    record,
                    debt,
                    clean_package,
                    clean_installation,
                },
            );
            restored += 1;
            if let Some(indices) = children.remove(&actor_id) {
                ready.extend(indices);
            }
        }
        if restored != pending.len() {
            // Missing parents and cycles never become ready.
            return Err(LifecycleError::InvalidRequest);
        }
        runtime.retired_installation_ids = state.retired_installation_ids.into_iter().collect();
        if state
            .program_bindings
            .windows(2)
            .any(|pair| pair[0].actor >= pair[1].actor)
        {
            return Err(LifecycleError::InvalidRequest);
        }
        for binding in state.program_bindings {
            // Canonical images bind only installed actors, at their current
            // program, by a nonempty reference.
            if binding.reference.len == 0
                || binding.reference.len > super::execution::MAX_EXECUTION_PROGRAM_BYTES as u64
                || runtime
                    .actors
                    .get(&binding.actor)
                    .is_none_or(|actor| actor.record.entry.program != binding.program)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.program_bindings.insert(binding.actor, binding);
        }
        for (actor, expected_deployment) in suspended {
            runtime.set_suspended(actor, expected_deployment, true)?;
        }
        runtime.lane_state = state.lane_state;
        runtime.lane_revisions = state.lane_revisions;
        runtime.control_authority_slot = state.control_authority_slot;
        runtime.validate_restored_lane_state()?;
        for result in state.invocation_results {
            let actor = runtime.actors.get(&result.reply.actor);
            let clean_binding_valid = match result.clean.as_ref() {
                None => true,
                Some(binding) => {
                    binding.accepted.validate_accepted()
                        && binding.work != crate::agent_sdk::Hash::ZERO
                        && result.request.0 == binding.work.0
                        && binding.authorization.commitment() != crate::agent_sdk::Hash::ZERO
                        && binding.accepted.invocation.0 == result.invocation.0
                        && binding.accepted.actor.0 == result.reply.actor.0
                        && binding.accepted.incarnation.0 == result.incarnation.0
                        && binding.accepted.deployment.0 == result.reply.deployment.0
                        && clean_method_mode(binding.accepted.mode) == result.reply.mode
                        && actor.is_some_and(|actor| {
                            actor.record.entry.program.0 == binding.accepted.program.0
                        })
                        && runtime
                            .verify_clean_accepted_authorization(
                                &binding.accepted,
                                &binding.authorization,
                                Hash(binding.work.0),
                                binding.observed_slot,
                            )
                            .is_ok()
                        && clean_authorization_is_live_at(
                            &binding.authorization,
                            binding.observed_slot,
                        )
                        && runtime
                            .result_authority_slot(result.storage)
                            .is_some_and(|slot| slot >= binding.observed_slot)
                }
            };
            if result.invocation == InvocationId::ZERO
                || result.incarnation == Hash::ZERO
                || result.reply.invocation != result.invocation
                || result.reply.incarnation != result.incarnation
                || result.request == Hash::ZERO
                || !match result.reply.status {
                    super::execution::ActorExecutionStatus::Done => true,
                    super::execution::ActorExecutionStatus::Forbidden
                    | super::execution::ActorExecutionStatus::Panicked
                    | super::execution::ActorExecutionStatus::OutOfGas => {
                        result.clean.is_some()
                            && result.reply.observation
                                == super::execution::ActorObservation::default()
                    }
                    super::execution::ActorExecutionStatus::Yielded => false,
                }
                || actor.is_none_or(|actor| {
                    actor.record.state_generation != result.incarnation
                        || actor.record.entry.deployment != result.reply.deployment
                })
                || result.scope != result.reply.mode.invocation_scope()
                || result.storage != result.reply.mode.result_storage()
                || !runtime.result_storage_supported(result.storage)
                || !clean_binding_valid
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime
                .invocation_results
                .insert((result.scope, result.invocation), result);
        }
        if state
            .clean_invocation_errors
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(LifecycleError::InvalidRequest);
        }
        for error in state.clean_invocation_errors {
            if !runtime.clean_invocation_error_is_valid(&error)
                || runtime.invocation_results.contains_key(&error.key())
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.clean_invocation_errors.insert(error.key(), error);
        }
        if runtime.clean_descriptor.is_none() && !state.clean_invocation_acknowledgements.is_empty()
        {
            return Err(LifecycleError::InvalidRequest);
        }
        for acknowledgement in state.clean_invocation_acknowledgements {
            let key = (
                clean_method_mode(acknowledgement.mode).invocation_scope(),
                InvocationId(acknowledgement.invocation.0),
            );
            if runtime.invocation_results.contains_key(&key)
                || runtime.clean_invocation_errors.contains_key(&key)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime
                .clean_invocation_acknowledgements
                .push(acknowledgement);
        }
        runtime.sequenced_retired_through = state.sequenced_retired_through;
        for storage in [
            InvocationResultStorage::Control,
            InvocationResultStorage::Lane(StateLane::Linear),
            InvocationResultStorage::Lane(StateLane::Merge),
            InvocationResultStorage::Lane(StateLane::Local),
        ] {
            if runtime.sequenced_retired_through.get(storage) != 0
                && (runtime.clean_descriptor.is_none()
                    || !runtime.result_storage_supported(storage))
            {
                return Err(LifecycleError::InvalidRequest);
            }
        }
        for continuation in state.machine_continuations {
            let actor = runtime.actors.get(&continuation.actor);
            let clean_target_valid = match (&continuation.accepted, &continuation.authorization) {
                (Some(accepted), Some(authorization)) => {
                    runtime
                        .verify_clean_accepted_authorization(
                            accepted,
                            authorization,
                            continuation.work,
                            continuation.observed_slot,
                        )
                        .is_ok()
                        // The immutable acceptance slot is checked against
                        // the signed window once on every hostile-state
                        // restore. Current-time expiry is deliberately not
                        // reapplied when Resume later executes.
                        && clean_authorization_is_live_at(
                            authorization,
                            continuation.observed_slot,
                        )
                        && runtime
                            .result_authority_slot(continuation.storage())
                            .is_some_and(|high_water| high_water >= continuation.observed_slot)
                }
                (None, None) => true,
                _ => false,
            };
            if actor.is_none_or(|actor| {
                actor.record.state_generation != continuation.incarnation
                    || actor.record.entry.deployment != continuation.deployment
                    || actor.record.entry.program != continuation.program
                    || actor.record.entry.suspended
                    || continuation
                        .mode
                        .write_lane()
                        .is_some_and(|lane| !actor.record.entry.lanes.contains(lane))
            }) || !clean_target_valid
                || !runtime.result_storage_supported(continuation.storage())
                || runtime.invocation_results.contains_key(&(
                    continuation.mode.invocation_scope(),
                    continuation.invocation,
                ))
            {
                return Err(LifecycleError::InvalidRequest);
            }
            if runtime.clean_invocation_errors.contains_key(&(
                continuation.mode.invocation_scope(),
                continuation.invocation,
            )) {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.machine_continuations.push(continuation);
        }
        // No retained clean record may name a compacted or foreign position.
        if !runtime
            .invocation_results
            .values()
            .filter_map(|result| result.clean.as_ref().map(|binding| &binding.accepted))
            .chain(
                runtime
                    .clean_invocation_errors
                    .values()
                    .map(|error| &error.binding.accepted),
            )
            .chain(
                runtime
                    .machine_continuations
                    .iter()
                    .filter_map(|continuation| continuation.accepted.as_ref()),
            )
            .map(|accepted| (accepted.invocation, accepted.mode))
            .chain(
                runtime
                    .clean_invocation_acknowledgements
                    .iter()
                    .map(|item| (item.invocation, item.mode)),
            )
            .all(|(invocation, mode)| runtime.sequenced_position_is_live(invocation, mode))
        {
            return Err(LifecycleError::InvalidRequest);
        }
        for storage in [
            InvocationResultStorage::Control,
            InvocationResultStorage::Lane(StateLane::Linear),
            InvocationResultStorage::Lane(StateLane::Merge),
            InvocationResultStorage::Lane(StateLane::Local),
        ] {
            if runtime.invocation_result_count(storage) > MAX_INVOCATION_RESULTS_PER_LANE
                || runtime.invocation_result_bytes(storage) > MAX_INVOCATION_RESULT_BYTES_PER_LANE
            {
                return Err(LifecycleError::InvalidRequest);
            }
        }
        runtime.authority_slot_high_water = state.authority_slot_high_water;
        runtime.authority_sequence_high_water = state.authority_sequence_high_water;
        for disposition in state.authority_dispositions {
            if disposition.credential == CredentialId::ZERO
                || disposition.sequence == 0
                || disposition.claim == Hash::ZERO
                || disposition.operation == Hash::ZERO
                || runtime
                    .authority_sequence_high_water
                    .is_none_or(|high_water| disposition.sequence > high_water)
            {
                return Err(LifecycleError::InvalidRequest);
            }
            runtime.authority_dispositions.push(disposition);
        }
        if runtime.authority_dispositions.is_empty() {
            if runtime.authority_sequence_high_water.is_some()
                || (runtime.clean_descriptor.is_none()
                    && runtime.authority_slot_high_water.is_none())
            {
                return Err(LifecycleError::InvalidRequest);
            }
        } else if runtime.authority_sequence_high_water.is_none()
            || runtime.authority_slot_high_water.is_none()
            || runtime
                .authority_dispositions
                .last()
                .map(|item| item.sequence)
                != runtime.authority_sequence_high_water
        {
            return Err(LifecycleError::InvalidRequest);
        }
        runtime.validate_signed_state_resource()?;
        Ok(runtime)
    }

    /// Update non-structural lifecycle debt from durable runtime indexes.
    pub fn set_lifecycle_debt(
        &mut self,
        actor: ActorId,
        mut debt: ActorLifecycleDebt,
    ) -> Result<(), LifecycleError> {
        let managed = self
            .actors
            .get_mut(&actor)
            .ok_or(LifecycleError::NotFound)?;
        debt.children = 0;
        managed.debt = debt;
        Ok(())
    }

    fn created(&self) -> Result<&AgentConfig, LifecycleError> {
        self.config.as_ref().ok_or(LifecycleError::NotCreated)
    }

    fn clean_actor_packages_are_exact(&self) -> bool {
        match self.clean_descriptor.as_ref() {
            None => self
                .actors
                .values()
                .all(|actor| actor.clean_package.is_none() && actor.clean_installation.is_none()),
            Some(descriptor) => self.actors.values().all(|actor| {
                actor.clean_package.as_ref().is_some_and(|package| {
                    package.actor.0 == actor.record.entry.actor.0
                        && package.contract.is_valid()
                        && package
                            .requirements
                            .supported_by(descriptor.identity.profile)
                        && descriptor.runtime_contract.supports(package.contract)
                        && descriptor.capabilities.satisfies(package.requirements)
                        && actor.record.contract == clean_actor_contract_to_legacy(package.contract)
                        && actor.record.requirements
                            == clean_requirements_to_legacy(package.requirements)
                }) && actor
                    .clean_installation
                    .as_ref()
                    .is_some_and(|installation| {
                        installation.actor.0 == actor.record.entry.actor.0
                            && installation.validates_original(&actor.record)
                            && installation.commitment != crate::agent_sdk::Hash::ZERO
                            && installation.contract.is_valid()
                            && installation
                                .requirements
                                .supported_by(descriptor.identity.profile)
                            && installation.requirements.lanes.bits()
                                == actor.record.entry.lanes.bits()
                    })
            }),
        }
    }

    fn validate_signed_state_resource(&self) -> Result<(), LifecycleError> {
        if !self.clean_actor_packages_are_exact() {
            return Err(LifecycleError::InvalidRequest);
        }
        let config = self.created()?;
        let limit = config.runtime_contract.resources.max_runtime_state_bytes as usize;
        // Keep only the measured length. Holding this encoded image while
        // usage accounting snapshots/encodes it again doubles peak heap use.
        let state_bytes = super::wire::encode_standard_runtime_state(&self.snapshot())
            .encoded_len()
            .filter(|bytes| *bytes <= limit)
            .ok_or(LifecycleError::ResourceLimit)?;
        match (&self.clean_descriptor, self.active_resource_policy) {
            (None, None) => Ok(()),
            (Some(descriptor), Some(policy))
                if policy.is_within(
                    descriptor.capabilities,
                    descriptor.runtime_contract.resources,
                ) && self
                    .clean_resource_usage_with_state_bytes(state_bytes)
                    .is_ok_and(|usage| policy.admits_usage(usage)) =>
            {
                Ok(())
            }
            (Some(_), Some(_)) => Err(LifecycleError::ResourceLimit),
            _ => Err(LifecycleError::InvalidRequest),
        }
    }

    fn record_authority_disposition(
        &mut self,
        credential: CredentialId,
        sequence: u64,
        claim: Hash,
        operation: Hash,
        observed_slot: u64,
        result: &Result<LifecycleReply, LifecycleError>,
    ) {
        self.authority_sequence_high_water = Some(sequence);
        self.authority_slot_high_water = Some(observed_slot);
        if self.authority_dispositions.len() == MAX_AUTHORITY_DISPOSITIONS {
            // Globally monotone sequences make the oldest journal entry the
            // only canonical eviction candidate. Its sequence remains below
            // the durable high-water, so a later retry is rejected without
            // reapplying the lifecycle operation.
            self.authority_dispositions.remove(0);
        }
        self.authority_dispositions
            .push(StandardAuthorityDisposition {
                credential,
                sequence,
                claim,
                operation,
                result: result.clone(),
            });
    }

    fn logical_slot_high_water(&self) -> Option<u64> {
        self.authority_slot_high_water
            .into_iter()
            .chain(self.control_authority_slot)
            .chain(self.private_control_slot_high_water)
            .chain(self.lane_revisions.authority_slot_high_water())
            .max()
    }

    fn advance_result_authority_slot(
        &mut self,
        storage: InvocationResultStorage,
        observed_slot: u64,
    ) {
        match storage {
            InvocationResultStorage::Control => {
                self.control_authority_slot = Some(
                    self.control_authority_slot
                        .map_or(observed_slot, |current| current.max(observed_slot)),
                );
            }
            InvocationResultStorage::Lane(lane) => {
                let current = self.lane_revisions.authority_slot(lane);
                self.lane_revisions.set_authority_slot(
                    lane,
                    current.map_or(observed_slot, |v| v.max(observed_slot)),
                );
            }
        }
    }

    fn result_authority_slot(&self, storage: InvocationResultStorage) -> Option<u64> {
        match storage {
            InvocationResultStorage::Control => self.control_authority_slot,
            InvocationResultStorage::Lane(lane) => self.lane_revisions.authority_slot(lane),
        }
    }

    /// Commit only the monotone authority clock for one externally retained
    /// exact outcome. Terminal replies and deterministic execution errors do
    /// not enter the guest result table and cannot mutate actor state.
    pub(crate) fn commit_exact_outcome_clock(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let storage = invocation.mode.result_storage();
        if !self.result_storage_supported(storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(())
    }

    pub(crate) fn commit_clean_exact_outcome_clock(
        &mut self,
        mode: crate::agent_sdk::MethodMode,
        observed_slot: u64,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        let storage = clean_method_mode(mode).result_storage();
        if !self.result_storage_supported(storage) {
            return Err(crate::agent_sdk::InvocationError::UnsupportedResultStorage);
        }
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(())
    }

    /// Admit only invocation modes whose exact result has a durable owning
    /// component in this immutable profile/capability set.
    pub(crate) fn validate_invocation_result_storage(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<(), super::execution::ActorExecutionError> {
        if self.result_storage_supported(invocation.mode.result_storage()) {
            Ok(())
        } else {
            Err(super::execution::ActorExecutionError::UnsupportedResultStorage)
        }
    }

    fn expected_actor_id(&self, entry: &ActorEntry) -> ActorId {
        if let Some(descriptor) = &self.clean_descriptor {
            return match entry.parent {
                Some(parent) => crate::service::ActorId(
                    crate::agent_sdk::ActorId::owned_child(
                        crate::agent_sdk::ActorId(parent.0),
                        &entry.name,
                    )
                    .0,
                ),
                None => crate::service::ActorId(
                    crate::agent_sdk::ActorId::top_level(descriptor.identity.agent, &entry.name).0,
                ),
            };
        }
        match entry.parent {
            Some(parent) => ActorId::owned_child(parent, &entry.name),
            None => ActorId::top_level(
                self.config
                    .as_ref()
                    .expect("created runtime has an identity")
                    .identity
                    .agent,
                &entry.name,
            ),
        }
    }

    fn validate_requirements(
        &self,
        requirements: RuntimeRequirements,
    ) -> Result<(), LifecycleError> {
        let config = self.created()?;
        if !requirements.lanes.supported_by(config.identity.profile) {
            return Err(LifecycleError::UnsupportedLane);
        }
        if !config.capabilities.satisfies(requirements) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        Ok(())
    }

    /// Whether a clean identity may still be retained: unsequenced, or a
    /// sequenced position of its own component above that component's
    /// compaction watermark.
    fn sequenced_position_is_live(
        &self,
        invocation: crate::agent_sdk::InvocationId,
        mode: crate::agent_sdk::MethodMode,
    ) -> bool {
        match clean_sequenced_position(invocation, mode) {
            Ok(None) => true,
            Ok(Some(position)) => {
                position
                    > self
                        .sequenced_retired_through
                        .get(clean_method_mode(mode).result_storage())
            }
            Err(_) => false,
        }
    }

    fn result_storage_supported(&self, storage: InvocationResultStorage) -> bool {
        let Some(config) = self.config.as_ref() else {
            return false;
        };
        match storage {
            InvocationResultStorage::Control => true,
            InvocationResultStorage::Lane(lane) => {
                config.identity.profile.supports(lane) && config.capabilities.lanes.contains(lane)
            }
        }
    }

    fn directory_page(
        &self,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<LifecycleReply, LifecycleError> {
        self.created()?;
        if limit == 0 || limit > MAX_DIRECTORY_PAGE {
            return Err(LifecycleError::InvalidRequest);
        }
        let mut entries = Vec::with_capacity(usize::from(limit));
        let mut iterator: Box<dyn Iterator<Item = (&ActorId, &ManagedActor)> + '_> = match after {
            Some(after) => Box::new(self.actors.range((Excluded(after), Unbounded))),
            None => Box::new(self.actors.iter()),
        };
        for (_, actor) in iterator.by_ref().take(usize::from(limit)) {
            entries.push(super::ActorDirectoryRecord {
                entry: actor.record.entry.clone(),
                incarnation: actor.record.state_generation,
                installation_id: actor.record.installation_id,
                registry_reservation: actor.record.registry_reservation,
            });
        }
        let next = if entries.len() == usize::from(limit) && iterator.next().is_some() {
            entries.last().map(|record| record.entry.actor)
        } else {
            None
        };
        Ok(LifecycleReply::Directory(super::ActorDirectoryPage {
            entries,
            next,
        }))
    }

    fn install(
        &mut self,
        install: super::InstallActor,
        state_generation: Hash,
    ) -> Result<LifecycleReply, LifecycleError> {
        let config = self.created()?;
        if install.installation_id == InstallationId::ZERO
            || install.registry_reservation == Hash::ZERO
            || install.entry.name.is_empty()
            || install.entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
            || install.entry.lanes != install.requirements.lanes
            || install.entry.deployment == DeploymentId::ZERO
            || install.entry.program == ProgramId::ZERO
            || install.entry.package != install.package
            || install.entry.agent_schema != install.agent_schema
            || install.entry.role_policies != install.role_policies
            || install.entry.constructor_abi != install.constructor_abi
            || install.entry.installation_data.as_ref()
                != install
                    .installation_data
                    .as_ref()
                    .map(|data| &data.reference)
            || install.entry.state_layout != install.state_layout
            || install.entry.suspended
            || install.producer == ProducerId::ZERO
            || install.package.hash == Hash::ZERO
            || install.package.len == 0
            || install.agent_schema.hash == Hash::ZERO
            || install.agent_schema.len == 0
            || install.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
            || install.role_policies.hash == Hash::ZERO
            || install.role_policies.len == 0
            || install.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
            || install.constructor_abi == Hash::ZERO
            || install.installation_data.as_ref().is_some_and(|data| {
                if self.clean_descriptor.is_some() {
                    !crate::agent_sdk::BlobRef {
                        hash: crate::agent_sdk::Hash(data.reference.hash.0),
                        len: data.reference.len,
                    }
                    .matches(&data.bytes)
                } else {
                    !data.is_valid()
                }
            })
            || installation_data_aliases_actor_artifact(
                install
                    .installation_data
                    .as_ref()
                    .map(|data| &data.reference),
                &install.package,
                &install.agent_schema,
                &install.role_policies,
            )
            || install.state_layout == Hash::ZERO
            || state_generation == Hash::ZERO
            || self.expected_actor_id(&install.entry) != install.entry.actor
        {
            return Err(LifecycleError::InvalidRequest);
        }

        // InstallationId is a stable operation identity, not an alias for an
        // ActorId. Reusing it for another actor, or changing any committed
        // install input while retaining it, is never a new installation.
        if let Some((actor_id, existing)) = self
            .actors
            .iter()
            .find(|(_, actor)| actor.record.installation_id == install.installation_id)
        {
            if *actor_id != install.entry.actor || !install_matches(&existing.record, &install) {
                return Err(LifecycleError::InvalidRequest);
            }
            // The install disposition is defined by the immutable request,
            // not by a later suspension or in-place upgrade. Return the exact
            // original reply while leaving current actor state untouched.
            return Ok(LifecycleReply::Installed(install.entry));
        }
        if self
            .retired_installation_ids
            .contains(&install.installation_id)
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if self.actors.contains_key(&install.entry.actor) {
            return Err(LifecycleError::AlreadyExists);
        }
        self.validate_requirements(install.requirements)?;
        if !config.runtime_contract.supports(install.contract) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        if self.actors.len() >= config.capabilities.max_actors as usize {
            return Err(LifecycleError::DirectoryFull);
        }
        if let Some(parent) = install.entry.parent {
            let parent = self.actors.get(&parent).ok_or(LifecycleError::NotFound)?;
            if parent.record.entry.suspended {
                return Err(LifecycleError::Busy(
                    self.lifecycle_debt(parent.record.entry.actor)?,
                ));
            }
        }
        validate_artifact_resources(
            config.runtime_contract.resources,
            core::iter::once(&config.runtime_package)
                .chain(self.actors.values().flat_map(actor_artifact_references))
                .chain([
                    &install.package,
                    &install.agent_schema,
                    &install.role_policies,
                ])
                .chain(
                    install
                        .installation_data
                        .as_ref()
                        .map(|data| &data.reference),
                ),
        )?;
        let entry = install.entry.clone();
        let install_request_commitment = LifecycleRequest::Install(install.clone()).commitment();
        self.actors.insert(
            entry.actor,
            ManagedActor {
                record: ActorRecord {
                    entry: install.entry,
                    state_generation,
                    installation_id: install.installation_id,
                    registry_reservation: install.registry_reservation,
                    install_request_commitment,
                    producer: install.producer,
                    package: install.package,
                    agent_schema: install.agent_schema,
                    role_policies: install.role_policies,
                    constructor_abi: install.constructor_abi,
                    installation_data: install.installation_data.map(|data| data.reference),
                    state_layout: install.state_layout,
                    contract: install.contract,
                    requirements: install.requirements,
                },
                debt: ActorLifecycleDebt::default(),
                clean_package: None,
                clean_installation: None,
            },
        );
        Ok(LifecycleReply::Installed(entry))
    }

    #[cfg(any(feature = "pvm", feature = "std"))]
    fn validate_invocation_target(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<&ManagedActor, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        invocation.validate()?;
        self.config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if actor.record.state_generation != invocation.incarnation {
            return Err(ActorExecutionError::StaleIncarnation);
        }
        if actor.record.entry.deployment != invocation.deployment {
            return Err(ActorExecutionError::StaleDeployment);
        }
        if actor.record.entry.program != invocation.program {
            return Err(ActorExecutionError::WrongProgram);
        }
        Ok(actor)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn recover_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        observed_slot: u64,
    ) -> Result<Option<super::execution::ActorExecutionReply>, super::execution::ActorExecutionError>
    {
        use super::execution::ActorExecutionError;
        invocation.validate()?;
        let key = (invocation.mode.invocation_scope(), invocation.invocation);
        if self.clean_invocation_errors.contains_key(&key) {
            return Err(ActorExecutionError::DivergentInvocation);
        }
        if let Some(result) = self.invocation_results.get(&key) {
            if result.clean.is_some() || result.request != invocation.commitment() {
                return Err(ActorExecutionError::DivergentInvocation);
            }
            let reply = result.reply.clone();
            let storage = result.storage;
            self.advance_result_authority_slot(storage, observed_slot);
            return Ok(Some(reply));
        }
        self.validate_invocation_target(invocation)?;
        Ok(None)
    }

    /// Recover only a result created through the clean SDK ABI. Both the
    /// canonical work commitment and complete typed-authorization commitment
    /// must match the immutable acceptance record; a legacy result with the
    /// same invocation key is deliberately divergent rather than adaptable.
    pub(crate) fn recover_clean_execution(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<super::execution::ActorExecutionReply>, crate::agent_sdk::InvocationError>
    {
        self.verify_clean_invocation_authorization(work, authorization, observed_slot)?;
        self.recover_clean_execution_after_authorization(work, authorization, observed_slot)
    }

    /// [`Self::recover_clean_execution`] for work the decoder has just
    /// validated: authorization is still verified, but the work's metadata and
    /// availability preimages are not hashed a second time.
    #[cfg(feature = "pvm")]
    pub(super) fn recover_validated_clean_execution(
        &mut self,
        validated: super::wire::ValidatedInvocationWork<'_>,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<super::execution::ActorExecutionReply>, crate::agent_sdk::InvocationError>
    {
        let work = validated.work();
        self.verify_clean_invocation_authorization_after_work_validation(
            work,
            authorization,
            observed_slot,
        )?;
        self.recover_clean_execution_after_authorization(work, authorization, observed_slot)
    }

    fn recover_clean_execution_after_authorization(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<super::execution::ActorExecutionReply>, crate::agent_sdk::InvocationError>
    {
        use crate::agent_sdk::InvocationError;

        // Acknowledgement deletes the delivered reply, not the consumed
        // invocation identity. Treating that absent reply as unseen work would
        // execute the same mutation again. Keep exact ACK retries available,
        // but never admit Invoke through a retained retirement fact.
        if self
            .recover_clean_acknowledgement_after_work_validation(work, authorization)?
            .is_some()
        {
            return Err(InvocationError::DivergentInvocation);
        }
        let scope = clean_method_mode(work.mode).invocation_scope();
        let key = (scope, InvocationId(work.invocation.0));
        if self.clean_invocation_errors.contains_key(&key) {
            return Err(InvocationError::DivergentInvocation);
        }
        let Some(result) = self.invocation_results.get(&key) else {
            return Ok(None);
        };
        let binding = result
            .clean
            .as_ref()
            .ok_or(InvocationError::DivergentInvocation)?;
        if !binding.matches(work, authorization)
            || !clean_authorization_is_live_at(&binding.authorization, binding.observed_slot)
            || observed_slot < binding.observed_slot
            || self
                .result_authority_slot(result.storage)
                .is_none_or(|slot| slot < binding.observed_slot)
        {
            return Err(InvocationError::DivergentInvocation);
        }
        self.clean_invocation_target(work.actor, work.incarnation, work.deployment, work.program)?;
        if result.request.0 != binding.work.0
            || result.scope != scope
            || result.invocation.0 != work.invocation.0
            || result.incarnation.0 != work.incarnation.0
            || result.reply.actor.0 != work.actor.0
            || result.reply.deployment.0 != work.deployment.0
            || result.reply.mode != clean_method_mode(work.mode)
        {
            return Err(InvocationError::DivergentInvocation);
        }
        let reply = result.reply.clone();
        let storage = result.storage;
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(Some(reply))
    }

    /// Inspect committed terminal disposition without actor execution,
    /// publication, clock advancement or availability preimages. The exact
    /// reference-only work and authorization must match guest-owned retained
    /// acceptance. This is intentionally separate from Invoke recovery, which
    /// can execute unseen work and advance a result authority clock.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn inspect_clean_retained_terminal(
        &self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<RetainedCleanTerminal>, crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;

        if !work.validate() || !authorization.matches_retirement(work) {
            return Err(InvocationError::InvalidAuthorization);
        }
        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(InvocationError::NotCreated)?;
        if work.space != descriptor.identity.space
            || work.agent != descriptor.identity.agent
            || work.runtime_deployment != descriptor.identity.runtime_deployment
        {
            return Err(InvocationError::InvalidAuthorization);
        }
        if let Some(acknowledgement) = self.recover_clean_retirement(work, authorization)? {
            return Ok(Some(RetainedCleanTerminal::Acknowledged(acknowledgement)));
        }
        let scope = clean_method_mode(work.mode).invocation_scope();
        let key = (scope, InvocationId(work.invocation.0));
        if let Some(record) = self.clean_invocation_errors.get(&key) {
            if !self.clean_invocation_error_is_valid(record)
                || !record.binding.matches_retirement(work, authorization)
                || observed_slot < record.binding.observed_slot
            {
                return Err(InvocationError::DivergentInvocation);
            }
            return Ok(Some(RetainedCleanTerminal::Completed(Err(record.error))));
        }
        let Some(result) = self.invocation_results.get(&key) else {
            return Ok(None);
        };
        let binding = result
            .clean
            .as_ref()
            .ok_or(InvocationError::DivergentInvocation)?;
        if !binding.matches_retirement(work, authorization)
            || !clean_authorization_is_live_at(&binding.authorization, binding.observed_slot)
            || observed_slot < binding.observed_slot
            || self
                .result_authority_slot(result.storage)
                .is_none_or(|slot| slot < binding.observed_slot)
            || result.storage != clean_method_mode(work.mode).result_storage()
            || result.request.0 != binding.work.0
            || result.scope != scope
            || result.invocation.0 != work.invocation.0
            || result.incarnation.0 != work.incarnation.0
            || result.reply.actor.0 != work.actor.0
            || result.reply.deployment.0 != work.deployment.0
            || result.reply.mode != clean_method_mode(work.mode)
        {
            return Err(InvocationError::DivergentInvocation);
        }
        Ok(Some(RetainedCleanTerminal::Completed(Ok(result
            .reply
            .clone()))))
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn verify_invocation_authority(
        &self,
        invocation: &super::execution::ActorInvocation,
        authority: &super::authority::ActorInvocationReceipt,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let config = self
            .config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                invocation,
            )
            .map_err(|_| ActorExecutionError::InvalidAuthorization)
    }

    pub(crate) fn verify_clean_invocation_authorization(
        &self,
        invocation: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        if self.clean_descriptor.is_none() {
            return Err(crate::agent_sdk::InvocationError::NotCreated);
        }
        if !invocation.validate() {
            return Err(crate::agent_sdk::InvocationError::InvalidAuthorization);
        }
        self.verify_clean_invocation_authorization_after_work_validation(
            invocation,
            authorization,
            observed_slot,
        )
    }

    // Private continuation of validation within one immutable-work call chain.
    // This still authenticates scope and signatures; callers must have just
    // validated all work metadata and availability preimages themselves.
    fn verify_clean_invocation_authorization_after_work_validation(
        &self,
        invocation: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(InvocationError::NotCreated)?;
        if !authorization.matches_invoke(invocation, observed_slot)
            || invocation.space != descriptor.identity.space
            || invocation.agent != descriptor.identity.agent
            || invocation.runtime_deployment != descriptor.identity.runtime_deployment
        {
            return Err(InvocationError::InvalidAuthorization);
        }
        match authorization {
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) => {
                if !descriptor.authority.accepts(receipt)
                    || !super::authority::verify_raw_ed25519(
                        &receipt.public_key,
                        &receipt.signing_bytes(),
                        &receipt.signature,
                    )
                {
                    return Err(InvocationError::InvalidAuthorization);
                }
                Ok(())
            }
            crate::agent_sdk::InvocationAuthorization::PublicPreflight(_) => Ok(()),
        }
    }

    /// Revalidate the immutable authorization embedded in portable state.
    /// Signed receipts are verified again. PublicPreflight remains only a
    /// structural, exact-input binding; the installed AMP2 selector is
    /// resolved again before a retry, Resume, acknowledgement, or execution.
    fn verify_clean_accepted_authorization(
        &self,
        accepted: &StandardAcceptedInvocation,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        expected_work: Hash,
        observed_slot: u64,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(InvocationError::NotCreated)?;
        if !accepted.validate_accepted()
            || !clean_authorization_matches_accepted(
                accepted,
                authorization,
                expected_work,
                observed_slot,
            )
            || accepted.space != descriptor.identity.space
            || accepted.agent != descriptor.identity.agent
            || accepted.runtime_deployment != descriptor.identity.runtime_deployment
        {
            return Err(InvocationError::InvalidAuthorization);
        }
        match authorization {
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) => {
                if !descriptor.authority.accepts(receipt)
                    || !super::authority::verify_raw_ed25519(
                        &receipt.public_key,
                        &receipt.signing_bytes(),
                        &receipt.signature,
                    )
                {
                    return Err(InvocationError::InvalidAuthorization);
                }
                Ok(())
            }
            crate::agent_sdk::InvocationAuthorization::PublicPreflight(_) => Ok(()),
        }
    }

    #[cfg(any(feature = "pvm", feature = "std"))]
    pub(crate) fn validate_clean_unseen_invocation_slot(
        &self,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;

        if !clean_authorization_is_live_at(authorization, observed_slot) {
            return Err(InvocationError::AuthorityExpired);
        }
        if let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) = authorization
        {
            if self
                .clean_authority_epoch_high_water
                .is_some_and(|high_water| receipt.selector.epoch < high_water)
            {
                return Err(InvocationError::InvalidAuthorization);
            }
        }
        if self
            .logical_slot_high_water()
            .is_some_and(|high_water| observed_slot < high_water)
        {
            return Err(InvocationError::AuthoritySlotRegressed);
        }
        Ok(())
    }

    fn clean_invocation_target(
        &self,
        actor: crate::agent_sdk::ActorId,
        incarnation: crate::agent_sdk::Hash,
        deployment: crate::agent_sdk::DeploymentId,
        program: crate::agent_sdk::ProgramId,
    ) -> Result<&ManagedActor, crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;
        let actor = self
            .actors
            .get(&ActorId(actor.0))
            .ok_or(InvocationError::NotFound)?;
        if actor.record.state_generation.0 != incarnation.0 {
            return Err(InvocationError::StaleIncarnation);
        }
        if actor.record.entry.deployment.0 != deployment.0 {
            return Err(InvocationError::StaleDeployment);
        }
        if actor.record.entry.program.0 != program.0 {
            return Err(InvocationError::WrongProgram);
        }
        Ok(actor)
    }

    pub(crate) fn resolve_clean_invocation(
        &self,
        work: &crate::agent_sdk::InvocationWork,
    ) -> Result<CleanInvocationParts, crate::agent_sdk::InvocationError> {
        self.resolve_clean_invocation_borrowed(work).map(
            |(invocation, program, schema, policies, installation_data)| {
                (
                    invocation,
                    program.to_vec(),
                    schema,
                    policies,
                    installation_data,
                )
            },
        )
    }

    fn resolve_clean_invocation_borrowed<'work>(
        &self,
        work: &'work crate::agent_sdk::InvocationWork,
    ) -> Result<CleanInvocationParts<&'work [u8]>, crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;

        let actor_id = ActorId(work.actor.0);
        let actor = self.clean_invocation_target(
            work.actor,
            work.incarnation,
            work.deployment,
            work.program,
        )?;
        let mut program_index = None;
        let mut schema_index = None;
        let mut policy_index = None;
        let mut installation_data_index = None;
        // A bound program is identified by the reference the decoder
        // authenticated its bytes against; its ProgramId was computed by this
        // guest over those bytes on an earlier invocation. Otherwise every
        // candidate is hashed to its ProgramId.
        let bound = self.bound_program_reference(actor_id);
        for (index, blob) in work.availability.iter().enumerate() {
            // The VOS-native profile never receives the program as availability.
            let is_program = !cfg!(all(feature = "runtime-program-lookup", target_arch = "riscv64"))
                && match bound {
                Some(reference) => {
                    blob.reference == *reference && blob.bytes.len() as u64 == reference.len
                }
                None => {
                    blob.bytes.len() <= super::execution::MAX_EXECUTION_PROGRAM_BYTES
                        && crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program
                }
            };
            if is_program {
                if program_index.replace(index).is_some() {
                    return Err(InvocationError::InvalidAvailability);
                }
            }
            // Artifact references bind both length and digest. Reject an
            // impossible role by the actual preimage length before hashing;
            // never use the caller-supplied reference as proof of its bytes.
            // In particular, large program blobs usually cannot be schema,
            // policy or constructor data. Program identity above remains an
            // independent, domain-separated digest of the complete bytes.
            let len = blob.bytes.len() as u64;
            if len != actor.record.agent_schema.len
                && len != actor.record.role_policies.len
                && actor
                    .record
                    .installation_data
                    .as_ref()
                    .is_none_or(|expected| len != expected.len)
            {
                continue;
            }
            let portable = crate::agent_sdk::BlobRef::of_bytes(&blob.bytes);
            if portable.hash.0 == actor.record.agent_schema.hash.0
                && portable.len == actor.record.agent_schema.len
            {
                if schema_index.replace(index).is_some() {
                    return Err(InvocationError::InvalidAvailability);
                }
            }
            if portable.hash.0 == actor.record.role_policies.hash.0
                && portable.len == actor.record.role_policies.len
            {
                if policy_index.replace(index).is_some() {
                    return Err(InvocationError::InvalidAvailability);
                }
            }
            if actor
                .record
                .installation_data
                .as_ref()
                .is_some_and(|expected| {
                    portable.hash.0 == expected.hash.0 && portable.len == expected.len
                })
            {
                if blob.bytes.len() > super::MAX_INSTALLATION_DATA_BYTES
                    || installation_data_index.replace(index).is_some()
                {
                    return Err(InvocationError::InvalidAvailability);
                }
            }
        }
        #[cfg(not(all(feature = "runtime-program-lookup", target_arch = "riscv64")))]
        let program_bytes = {
            let index = program_index.ok_or(InvocationError::InvalidAvailability)?;
            work.availability[index].bytes.as_slice()
        };
        // VOS-native profile: the host supplies the program by its ProgramId through
        // historical_lookup, having verified the preimage natively; the guest does not
        // hash it. The bytes outlive this one execution's guest by design.
        #[cfg(all(feature = "runtime-program-lookup", target_arch = "riscv64"))]
        let program_bytes: &'work [u8] = lookup_program(&work.program)?;
        let schema_index = schema_index.ok_or(InvocationError::InvalidAvailability)?;
        let policy_index = policy_index.ok_or(InvocationError::InvalidAvailability)?;
        let installation_data_index = match (
            actor.record.installation_data.as_ref(),
            work.installation_data.as_ref(),
            installation_data_index,
        ) {
            (Some(_), Some(role), Some(index)) if work.availability[index].reference == *role => {
                Some(index)
            }
            (None, None, None) => None,
            _ => return Err(InvocationError::InvalidAvailability),
        };
        let mut role_indices = Vec::from([schema_index, policy_index]);
        role_indices.extend(program_index);
        role_indices.extend(installation_data_index);
        role_indices.sort_unstable();
        if role_indices.windows(2).any(|pair| pair[0] == pair[1]) {
            // Artifact roles are independently authenticated. Even when two
            // catalog hashes happen to alias, one availability entry cannot
            // stand in for more than one role.
            return Err(InvocationError::InvalidAvailability);
        }

        let mut application_availability = work
            .availability
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                Some(*index) != program_index
                    && *index != schema_index
                    && *index != policy_index
                    && Some(*index) != installation_data_index
            })
            .map(|(_, blob)| super::execution::RuntimeBlob {
                reference: crate::service::BlobRef::of_bytes(&blob.bytes),
                bytes: blob.bytes.clone(),
            })
            .collect::<Vec<_>>();
        application_availability.sort_unstable_by_key(|blob| blob.reference.hash);
        let invocation = super::execution::ActorInvocation {
            invocation: InvocationId(work.invocation.0),
            actor: actor_id,
            incarnation: Hash(work.incarnation.0),
            deployment: DeploymentId(work.deployment.0),
            program: ProgramId(work.program.0),
            mode: clean_method_mode(work.mode),
            // Clean authentication is carried only by the exact AIC1
            // invocation context. Do not project it into the transitional
            // service-era authorization frame.
            auth: super::execution::ActorInvocationAuth::anonymous(),
            message: work.message.clone(),
            availability: application_availability,
            gas: work.gas,
        };
        invocation
            .validate()
            .map_err(|_| InvocationError::InvalidInput)?;
        let actor_schema = work.availability[schema_index].clone();
        let actor_policies = work.availability[policy_index].clone();
        let installation_data =
            installation_data_index.map(|index| work.availability[index].clone());
        Ok((
            invocation,
            program_bytes,
            actor_schema,
            actor_policies,
            installation_data,
        ))
    }

    pub(crate) fn resolve_clean_invocation_for_execution<'work>(
        &self,
        work: &'work crate::agent_sdk::InvocationWork,
    ) -> Result<ResolvedCleanInvocation<'work>, crate::agent_sdk::InvocationError> {
        let parts = self.resolve_clean_invocation_borrowed(work)?;
        let actor = self
            .clean_invocation_target(work.actor, work.incarnation, work.deployment, work.program)?
            .record
            .clone();
        Ok(ResolvedCleanInvocation {
            work,
            actor,
            parts,
            work_validated: false,
        })
    }

    /// [`Self::resolve_clean_invocation_for_execution`] for work the decoder
    /// has just validated; its commit does not re-hash the availability.
    #[cfg(feature = "pvm")]
    pub(super) fn resolve_validated_clean_invocation_for_execution<'work>(
        &self,
        validated: super::wire::ValidatedInvocationWork<'work>,
    ) -> Result<ResolvedCleanInvocation<'work>, crate::agent_sdk::InvocationError> {
        let mut resolved = self.resolve_clean_invocation_for_execution(validated.work())?;
        resolved.work_validated = true;
        Ok(resolved)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_unseen_invocation_slot(
        &self,
        _invocation: &super::execution::ActorInvocation,
        authority: &super::authority::ActorInvocationReceipt,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        if observed_slot < authority.claim.valid_from || observed_slot > authority.claim.valid_until
        {
            return Err(ActorExecutionError::AuthorityExpired);
        }
        let high_water = self.logical_slot_high_water();
        if high_water.is_some_and(|high_water| observed_slot < high_water) {
            return Err(ActorExecutionError::AuthoritySlotRegressed);
        }
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn prepare_execution_state(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<super::execution::ActorStateLanes, super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorStateLanes};

        let config = self
            .config
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        let actor = self.validate_invocation_target(invocation)?;
        if actor.record.entry.suspended {
            return Err(ActorExecutionError::Suspended);
        }
        if let Some(lane) = invocation.mode.write_lane() {
            if !config.identity.profile.supports(lane) || !actor.record.entry.lanes.contains(lane) {
                return Err(ActorExecutionError::UnsupportedMethod);
            }
        }
        let result_storage = invocation.mode.result_storage();
        if !self.result_storage_supported(result_storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        if self.invocation_result_count(result_storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self.invocation_result_bytes(result_storage) >= MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        let resolve = |lane| -> Result<Option<Vec<u8>>, ActorExecutionError> {
            if !actor.record.entry.lanes.contains(lane) {
                return Ok(None);
            }
            Ok(Some(
                self.lane_state
                    .lookup(
                        lane,
                        actor.record.entry.actor,
                        actor.record.state_generation,
                    )
                    .map_or_else(Vec::new, |entry| entry.value.clone()),
            ))
        };
        let state = ActorStateLanes {
            linear: resolve(StateLane::Linear)?,
            merge: resolve(StateLane::Merge)?,
            local: resolve(StateLane::Local)?,
        };
        if state
            .encoded_len()
            .is_none_or(|len| len > super::execution::MAX_EXECUTION_STATE_TOTAL_BYTES)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        Ok(state)
    }

    /// Resolve an exact yielded invocation only when it is at the head of its
    /// owning component's FIFO. Unrelated fresh work may still execute; FIFO
    /// constrains continuation resumes rather than globally serializing all
    /// actor messages across independent replication lanes.
    #[cfg(feature = "pvm")]
    pub(crate) fn machine_continuation(
        &self,
        invocation: &super::execution::ActorInvocation,
    ) -> Result<
        Option<(u64, super::execution::ActorMachineContinuation)>,
        super::execution::ActorExecutionError,
    > {
        use super::execution::ActorExecutionError;

        let scope = invocation.mode.invocation_scope();
        let Some(record) = self.machine_continuations.iter().find(|record| {
            record.mode.invocation_scope() == scope && record.invocation == invocation.invocation
        }) else {
            return Ok(None);
        };
        if record.request != invocation.commitment()
            || record.actor != invocation.actor
            || record.incarnation != invocation.incarnation
            || record.deployment != invocation.deployment
            || record.program != invocation.program
            || record.mode != invocation.mode
        {
            return Err(ActorExecutionError::DivergentInvocation);
        }
        let storage = record.storage();
        let head = self
            .machine_continuations
            .iter()
            .find(|candidate| candidate.storage() == storage)
            .expect("the matching continuation is in its owning component");
        if head.ready_sequence != record.ready_sequence
            || head.invocation != record.invocation
            || head.mode.invocation_scope() != scope
        {
            return Err(ActorExecutionError::ContinuationNotReady);
        }
        Ok(Some((record.ready_sequence, record.continuation.clone())))
    }

    pub(crate) fn recover_clean_yield(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<crate::agent_sdk::YieldedInvocation>, crate::agent_sdk::InvocationError>
    {
        use crate::agent_sdk::InvocationError;

        let scope = clean_method_mode(work.mode).invocation_scope();
        let Some(record) = self.machine_continuations.iter().find(|record| {
            record.mode.invocation_scope() == scope && record.invocation.0 == work.invocation.0
        }) else {
            return Ok(None);
        };
        let (invocation, ..) = self.resolve_clean_invocation(work)?;
        let expected = StandardAcceptedInvocation::from_work(work);
        if record.accepted.as_ref() != Some(&expected)
            || record.work.0 != work.commitment().0
            || record.request != invocation.commitment()
            || observed_slot < record.observed_slot
            || record.authorization.as_ref().is_none_or(|accepted| {
                accepted != authorization || accepted.commitment() != authorization.commitment()
            })
        {
            return Err(InvocationError::DivergentInvocation);
        }
        record
            .yielded()
            .map(Some)
            .map_err(|_| InvocationError::StaleContinuation)
    }

    pub(crate) fn resolve_clean_resume(
        &self,
        resume: &crate::agent_sdk::ResumeWork,
    ) -> Result<
        (
            StandardMachineContinuation,
            crate::agent_sdk::InvocationWork,
        ),
        crate::agent_sdk::InvocationError,
    > {
        use crate::agent_sdk::InvocationError;

        let mode = clean_method_mode(resume.mode);
        let Some(record) = self.machine_continuations.iter().find(|record| {
            record.mode.invocation_scope() == mode.invocation_scope()
                && record.invocation.0 == resume.invocation.0
        }) else {
            return Err(InvocationError::StaleContinuation);
        };
        if record.actor.0 != resume.actor.0
            || record.incarnation.0 != resume.incarnation.0
            || record.deployment.0 != resume.deployment.0
            || record.program.0 != resume.program.0
            || record.mode != mode
            || record.clean_reference().ok().as_ref() != Some(&resume.continuation)
            || record
                .accepted
                .as_ref()
                .and_then(|accepted| accepted.installation_data.as_ref())
                != resume.installation_data.as_ref()
        {
            return Err(InvocationError::StaleContinuation);
        }
        if record.ready_sequence != resume.ready_sequence {
            return Err(InvocationError::NotReady);
        }
        let head = self
            .machine_continuations
            .iter()
            .find(|candidate| candidate.storage() == record.storage())
            .ok_or(InvocationError::StaleContinuation)?;
        if head.invocation != record.invocation || head.ready_sequence != record.ready_sequence {
            return Err(InvocationError::NotReady);
        }
        let accepted = record
            .accepted
            .as_ref()
            .ok_or(InvocationError::StaleContinuation)?;
        let supplied = resume
            .availability
            .iter()
            .map(|blob| blob.reference.clone())
            .collect::<Vec<_>>();
        if supplied != accepted.required {
            return Err(InvocationError::InvalidAvailability);
        }
        let work = accepted.with_availability(resume.availability.clone());
        if !work.validate() {
            return Err(InvocationError::InvalidAvailability);
        }
        if work.commitment().0 != record.work.0
            || record.authorization.as_ref().is_none_or(|authorization| {
                !clean_authorization_matches_accepted(
                    accepted,
                    authorization,
                    record.work,
                    record.observed_slot,
                )
            })
        {
            return Err(InvocationError::StaleContinuation);
        }
        Ok((record.clone(), work))
    }

    pub(crate) fn consume_machine_continuation(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        expected_sequence: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let scope = invocation.mode.invocation_scope();
        let index = self
            .machine_continuations
            .iter()
            .position(|record| {
                record.mode.invocation_scope() == scope
                    && record.invocation == invocation.invocation
            })
            .ok_or(ActorExecutionError::InvalidActorOutput)?;
        let record = &self.machine_continuations[index];
        if record.ready_sequence != expected_sequence
            || record.request != invocation.commitment()
            || record.actor != invocation.actor
            || record.incarnation != invocation.incarnation
            || record.deployment != invocation.deployment
            || record.program != invocation.program
            || record.mode != invocation.mode
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        self.machine_continuations.remove(index);
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn commit_yielded_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        reply: &super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        after: super::execution::ActorStateLanes,
        observed_slot: u64,
        expected_sequence: Option<u64>,
        continuation: super::execution::ActorMachineContinuation,
        accepted: Option<(
            StandardAcceptedInvocation,
            crate::agent_sdk::InvocationAuthorization,
        )>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        // Yield is one atomic runtime transition even when this method is
        // reused outside the current top-level pristine-clone wrapper.
        let mut candidate = self.clone();
        candidate.commit_yielded_execution_inner(
            invocation,
            reply,
            before,
            after,
            observed_slot,
            expected_sequence,
            continuation,
            accepted,
        )?;
        *self = candidate;
        Ok(())
    }

    #[cfg(feature = "pvm")]
    fn commit_yielded_execution_inner(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        reply: &super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        mut after: super::execution::ActorStateLanes,
        observed_slot: u64,
        expected_sequence: Option<u64>,
        continuation: super::execution::ActorMachineContinuation,
        accepted: Option<(
            StandardAcceptedInvocation,
            crate::agent_sdk::InvocationAuthorization,
        )>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorExecutionStatus};

        self.validate_invocation_target(invocation)?;
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.lane != invocation.mode.write_lane()
            || reply.status != ActorExecutionStatus::Yielded
            || self
                .clean_invocation_errors
                .contains_key(&(invocation.mode.invocation_scope(), invocation.invocation))
            || reply.observation != super::execution::ActorObservation::default()
            || !continuation.validate()
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let write_lane = invocation.mode.write_lane();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let previous = before.get(lane);
            if Some(lane) != write_lane && !invocation.mode.can_read(lane) {
                if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) {
                    return Err(ActorExecutionError::InvalidActorOutput);
                }
            } else if Some(lane) != write_lane {
                match previous {
                    Some(previous) if after.get(lane) != Some(previous) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    None if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    Some(_) | None => {}
                }
            }
        }
        if let Some(lane) = write_lane {
            let state = after
                .take(lane)
                .ok_or(ActorExecutionError::InvalidActorOutput)?;
            if state.len() > super::execution::MAX_EXECUTION_STATE_BYTES {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
            let actor = self
                .actors
                .get(&reply.actor)
                .ok_or(ActorExecutionError::NotFound)?;
            self.lane_state.upsert(
                lane,
                actor.record.entry.actor,
                actor.record.state_generation,
                state,
            )?;
            self.lane_revisions.increment(lane)?;
        }
        if let Some(sequence) = expected_sequence {
            self.consume_machine_continuation(invocation, sequence)?;
        } else if self.machine_continuations.iter().any(|record| {
            record.mode.invocation_scope() == invocation.mode.invocation_scope()
                && record.invocation == invocation.invocation
        }) {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        if self.machine_continuations.len() >= MAX_MACHINE_CONTINUATIONS {
            return Err(ActorExecutionError::ResultCapacity);
        }
        let storage = invocation.mode.result_storage();
        let ready_sequence = self
            .machine_continuations
            .iter()
            .filter(|record| record.storage() == storage)
            .map(|record| record.ready_sequence)
            .max()
            .unwrap_or(0)
            .max(expected_sequence.unwrap_or(0))
            .checked_add(1)
            .ok_or(ActorExecutionError::ResultCapacity)?;
        let (work, accepted, authorization) = match accepted {
            Some((accepted, authorization)) => (
                clean_authorization_work(&authorization),
                Some(accepted),
                Some(authorization),
            ),
            None => (invocation.commitment(), None, None),
        };
        let record = StandardMachineContinuation {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            program: invocation.program,
            mode: invocation.mode,
            request: invocation.commitment(),
            work,
            ready_sequence,
            accepted,
            authorization,
            observed_slot,
            continuation,
        };
        if !record.validate_record() {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let key = continuation_order_key(&record);
        let index = self
            .machine_continuations
            .binary_search_by_key(&key, continuation_order_key)
            .unwrap_or_else(|index| index);
        self.machine_continuations.insert(index, record);
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_clean_execution_schema(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<(), super::execution::ActorExecutionError> {
        self.resolve_clean_storage_access(work, schema_blob)
            .map(|_| ())
    }

    /// Derive row scope only from this installed actor's exact schema. This
    /// authenticates the schema and generation, not caller authorization;
    /// policy admission must still succeed before the scope is used for IO.
    #[cfg(feature = "pvm")]
    pub(crate) fn resolve_clean_storage_access(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<super::actor_storage::ActorStorageAccess, super::execution::ActorExecutionError>
    {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};

        let actor = self
            .actors
            .get(&ActorId(work.actor.0))
            .ok_or(ActorExecutionError::NotFound)?;
        if actor.record.state_generation.0 != work.incarnation.0 {
            return Err(ActorExecutionError::StaleIncarnation);
        }
        if actor.record.entry.deployment.0 != work.deployment.0 {
            return Err(ActorExecutionError::StaleDeployment);
        }
        if actor.record.entry.program.0 != work.program.0 {
            return Err(ActorExecutionError::WrongProgram);
        }
        if !clean_reference_matches_record(&schema_blob.reference, &actor.record.agent_schema)
            || !schema_blob.validate()
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let schema = crate::agent_sdk::schema::decode(&schema_blob.bytes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        let state_layout = schema
            .state_layout_hash()
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        if state_layout.0 != actor.record.state_layout.0
            || schema.lanes().bits() != actor.record.requirements.lanes.bits()
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let message = work
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let method = schema
            .methods
            .iter()
            .find(|method| method.name == message.name)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if method.mode != work.mode {
            return Err(ActorExecutionError::UnsupportedMethod);
        }
        super::actor_storage::ActorStorageAccess::new(&schema, &message.name, work.mode)
            .map_err(|_| ActorExecutionError::InvalidAvailability)
    }

    /// Resolve row data from the same actor/incarnation whose installed schema
    /// authenticates its namespace scope. No host-selected image or lane may
    /// substitute for these runtime-owned entries. Caller policy admission is
    /// still required before entering the inner machine.
    #[cfg(feature = "pvm")]
    pub(crate) fn resolve_clean_storage_reader<'a>(
        &'a self,
        work: &crate::agent_sdk::InvocationWork,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<super::actor_storage::ActorStorageReader<'a>, super::execution::ActorExecutionError>
    {
        let access = self.resolve_clean_storage_access(work, schema_blob)?;
        let rows = |lane| {
            self.lane_state
                .lookup(lane, ActorId(work.actor.0), Hash(work.incarnation.0))
                .map(|entry| &entry.rows)
        };
        super::actor_storage::ActorStorageReader::from_rows(
            access,
            [
                rows(StateLane::Linear),
                rows(StateLane::Merge),
                rows(StateLane::Local),
            ],
        )
        .map_err(|_| super::execution::ActorExecutionError::InvalidAvailability)
    }

    /// External metadata must never silently retain image-backed row data,
    /// including historical incarnations that are no longer active.
    #[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
    pub(crate) fn has_image_rows(&self) -> bool {
        self.lane_state
            .linear
            .iter()
            .chain(&self.lane_state.merge)
            .chain(&self.lane_state.local)
            .any(|entry| !entry.rows.is_empty())
    }

    /// Resolve external rows using the same installed schema and incarnation
    /// checks as the image backend. The enclosing runtime must obtain trees
    /// from its authenticated lane roots and admit caller policy before IO.
    /// This neither imports image rows nor grants authority to supplied roots.
    /// The returned reader borrows this runtime so its installation cannot be
    /// changed while the resolved access scope is in use.
    #[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
    pub(crate) fn resolve_clean_external_storage_reader<
        'a,
        R: crate::agent_sdk::state_tree::BlockReader,
    >(
        &'a self,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        lanes: [Option<(crate::agent_sdk::state_tree::StateTree, R)>; 3],
        budget: &'a mut crate::agent_sdk::state_blocks::ReadBudget,
    ) -> Result<
        super::actor_storage::ExternalActorStorageReader<'a, R>,
        super::execution::ActorExecutionError,
    > {
        use super::execution::ActorExecutionError;
        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(ActorExecutionError::NotCreated)?;
        if work.space != descriptor.identity.space
            || work.agent != descriptor.identity.agent
            || work.runtime_deployment != descriptor.identity.runtime_deployment
            || lanes.iter().flatten().any(|(tree, _)| {
                tree.scope().space() != work.space || tree.scope().agent() != work.agent
            })
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let access = self.resolve_clean_storage_access(work, schema)?;
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            if self
                .lane_state
                .lookup(lane, ActorId(work.actor.0), Hash(work.incarnation.0))
                .is_some_and(|entry| !entry.rows.is_empty())
            {
                // No mixed-backend migration: selecting an external tree must
                // not silently hide the installed actor's existing image rows.
                return Err(ActorExecutionError::InvalidAvailability);
            }
        }
        super::actor_storage::ExternalActorStorageReader::new(
            access,
            work.actor,
            work.incarnation,
            lanes,
            budget,
        )
        .map_err(|_| ActorExecutionError::InvalidAvailability)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_clean_execution_installation_data(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        data: Option<&crate::agent_sdk::RuntimeBlob>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let actor = self
            .actors
            .get(&ActorId(work.actor.0))
            .ok_or(ActorExecutionError::NotFound)?;
        match (
            actor.record.installation_data.as_ref(),
            work.installation_data.as_ref(),
            data,
        ) {
            (None, None, None) => Ok(()),
            (Some(expected), Some(selected), Some(data))
                if data.bytes.len() <= super::MAX_INSTALLATION_DATA_BYTES
                    && clean_reference_matches_record(selected, expected)
                    && data.reference == *selected
                    && data.validate() =>
            {
                Ok(())
            }
            _ => Err(ActorExecutionError::InvalidAvailability),
        }
    }

    /// Resolve the exact AMP2 method policy and enforce it against the clean
    /// authenticated invocation envelope. The policy is closed over the exact
    /// AAS2 preimage before its selected method can authorize execution.
    pub(crate) fn authorize_clean_execution(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
        policy_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        self.authorize_clean_execution_with_proof(
            work,
            authorization,
            schema_blob,
            policy_blob,
            None,
        )
    }

    #[cfg(feature = "std")]
    pub(crate) fn authorize_clean_attested_execution(
        &self,
        authenticated: &super::transition_proof_host::AuthenticatedAttestedTransition,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
        policy_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let actor = self
            .actors
            .get(&ActorId(work.actor.0))
            .ok_or(ActorExecutionError::NotFound)?;
        let runtime_contract = authenticated
            .runtime_contract()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let runtime_capabilities = authenticated
            .runtime_capabilities()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let actor_entry = authenticated
            .actor_entry()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let actor_contract = authenticated
            .actor_contract()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let actor_requirements = authenticated
            .actor_requirements()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let clean_package = actor
            .clean_package
            .as_ref()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        if descriptor.identity.space != authenticated.space()
            || descriptor.identity.agent != authenticated.agent()
            || descriptor.identity.runtime_deployment != authenticated.runtime_deployment()
            || descriptor.identity.runtime_program != authenticated.runtime_program()
            || &descriptor.runtime_package != authenticated.runtime_package()
            || descriptor.runtime_contract != runtime_contract
            || descriptor.capabilities != runtime_capabilities
            || actor.record.entry != clean_entry_to_legacy(actor_entry)
            || clean_package.actor.0 != actor.record.entry.actor.0
            || clean_package.contract != actor_contract
            || clean_package.requirements != actor_requirements
            || actor.record.contract != clean_actor_contract_to_legacy(clean_package.contract)
            || actor.record.requirements != clean_requirements_to_legacy(clean_package.requirements)
            || !runtime_contract.supports(actor_contract)
            || !runtime_capabilities.satisfies(actor_requirements)
            || !runtime_capabilities
                .proof_systems
                .contains(authenticated.proof_system())
            || !actor_requirements
                .proof_systems
                .contains(authenticated.proof_system())
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        self.authorize_clean_execution_with_proof(
            work,
            authorization,
            schema_blob,
            policy_blob,
            Some(authenticated.proof_system()),
        )
    }

    /// Guest half of proof-host attested admission.
    ///
    /// The host has already authenticated the exact runtime package,
    /// program, actor package and work in an unforgeable capability before it
    /// starts this bundled PVM. The guest independently re-resolves the
    /// installed package requirements and exact AMP2 method policy from its
    /// committed state. Keeping this entry proof-system-only prevents a
    /// caller-controlled copy of the host capability from entering the PVM
    /// ABI while still enforcing Required{same proof system} in the runtime.
    #[cfg(feature = "pvm")]
    pub(crate) fn authorize_clean_proof_host_execution(
        &self,
        proof_system: crate::agent_sdk::Hash,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
        policy_blob: &crate::agent_sdk::RuntimeBlob,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        let actor = self
            .actors
            .get(&ActorId(work.actor.0))
            .ok_or(ActorExecutionError::NotFound)?;
        let package = actor
            .clean_package
            .as_ref()
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        if proof_system == crate::agent_sdk::Hash::ZERO
            || !descriptor.capabilities.proof_systems.contains(proof_system)
            || !package.requirements.proof_systems.contains(proof_system)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        self.authorize_clean_execution_with_proof(
            work,
            authorization,
            schema_blob,
            policy_blob,
            Some(proof_system),
        )
    }

    fn authorize_clean_execution_with_proof(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        schema_blob: &crate::agent_sdk::RuntimeBlob,
        policy_blob: &crate::agent_sdk::RuntimeBlob,
        attested_proof_system: Option<crate::agent_sdk::Hash>,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::agent_sdk::method_policy::{
            ActorMethodPolicyArtifact, AttestationRequirement, AuthorizationPolicySelector,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;

        let actor = self
            .actors
            .get(&ActorId(work.actor.0))
            .ok_or(ActorExecutionError::NotFound)?;
        if !clean_reference_matches_record(&schema_blob.reference, &actor.record.agent_schema)
            || !schema_blob.validate()
            || !clean_reference_matches_record(&policy_blob.reference, &actor.record.role_policies)
            || !policy_blob.validate()
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let policies = ActorMethodPolicyArtifact::decode(&policy_blob.bytes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        policies
            .validate_against_schema_bytes(&schema_blob.bytes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        let message = work
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let policy = policies
            .method(&message.name)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let attestation_matches = match (policy.attestation, attested_proof_system) {
            (AttestationRequirement::None, None) => true,
            (AttestationRequirement::Required { proof_system }, Some(attested_proof_system)) => {
                proof_system == attested_proof_system
            }
            (AttestationRequirement::None, Some(_))
            | (AttestationRequirement::Required { .. }, None) => false,
        };
        // A missing/wrong proof is a retryable admission rejection, not an
        // executed method's durable UnsupportedMethod outcome.
        if !attestation_matches {
            return Err(ActorExecutionError::InvalidAuthorization);
        }
        if policy.mode != work.mode {
            return Err(ActorExecutionError::UnsupportedMethod);
        }
        Ok(match authorization {
            crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) => {
                // PublicPreflight is deliberately unsigned. The exact
                // installed AMP2 Public selector is the sole admission
                // policy; the envelope itself authenticates no identity.
                preflight.matches(work, preflight.observed_slot)
                    && policy.authorization_policy == AuthorizationPolicySelector::Public
                    && work.origin.capability.is_none()
                    && work.roles == crate::agent_sdk::InvocationRoleClaims::none()
            }
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(_) => {
                match policy.authorization_policy {
                    AuthorizationPolicySelector::Public => {
                        work.origin.capability.is_none()
                            && work.roles == crate::agent_sdk::InvocationRoleClaims::none()
                    }
                    AuthorizationPolicySelector::Capability(required) => {
                        work.origin.capability == Some(required)
                            && work.roles == crate::agent_sdk::InvocationRoleClaims::none()
                    }
                    AuthorizationPolicySelector::SpaceRole(required) => {
                        work.origin.capability.is_none()
                            && work.roles.space == Some(required)
                            && work.roles.actor.is_none()
                    }
                    AuthorizationPolicySelector::ActorRole(required) => {
                        work.origin.capability.is_none()
                            && work.roles.actor == Some(required)
                            && work.roles.space.is_none()
                    }
                }
            }
        })
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_execution_schema(
        &self,
        invocation: &super::execution::ActorInvocation,
        schema_blob: &super::execution::RuntimeBlob,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};

        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if schema_blob.reference != actor.record.agent_schema
            || !schema_blob.reference.matches(&schema_blob.bytes)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let schema = super::schema::decode(&schema_blob.bytes)
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        if schema.state_layout_hash() != actor.record.state_layout
            || schema.lanes() != actor.record.requirements.lanes
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let message = invocation
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let method = schema
            .method(&message.name)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if method.mode != invocation.mode {
            return Err(ActorExecutionError::UnsupportedMethod);
        }
        Ok(())
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn validate_execution_installation_data(
        &self,
        invocation: &super::execution::ActorInvocation,
        data: Option<&super::execution::RuntimeBlob>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        match (actor.record.installation_data.as_ref(), data) {
            (None, None) => Ok(()),
            (Some(expected), Some(data))
                if data.bytes.len() <= super::MAX_INSTALLATION_DATA_BYTES
                    && data.reference == *expected
                    && data.reference.matches(&data.bytes) =>
            {
                Ok(())
            }
            _ => Err(ActorExecutionError::InvalidAvailability),
        }
    }

    /// Resolve the canonical signed method policy and enforce it against the
    /// host-authenticated invocation context before application code runs.
    /// Package signature verification and lifecycle authority bind the
    /// guest-owned reference; callers never select these policy bytes.
    #[cfg(feature = "pvm")]
    pub(crate) fn authorize_execution(
        &self,
        invocation: &super::execution::ActorInvocation,
        policy_blob: &super::execution::RuntimeBlob,
    ) -> Result<bool, super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::PackageRolePolicies;
        use crate::service::wire::ServiceWire as _;

        let actor = self
            .actors
            .get(&invocation.actor)
            .ok_or(ActorExecutionError::NotFound)?;
        if policy_blob.reference != actor.record.role_policies
            || !policy_blob.reference.matches(&policy_blob.bytes)
        {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let policies = PackageRolePolicies::decode(&policy_blob.bytes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        let message = invocation
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let policy = policies
            .methods
            .binary_search_by(|policy| policy.method.as_str().cmp(message.name.as_str()))
            .ok()
            .and_then(|index| policies.methods.get(index))
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        if policy.schema == Hash::ZERO {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        if policy.attested {
            // The bundled runtime advertises `proofs = false`; a valid
            // package requiring attestation is rejected at install. Keep the
            // execution boundary fail-closed even if an untrusted host tries
            // to construct lifecycle state without package verification.
            return Err(ActorExecutionError::UnsupportedMethod);
        }

        if policy.public {
            return Ok(true);
        }
        match invocation.auth.origin {
            crate::service::Origin::Anonymous => return Ok(false),
            // System has no grant-bearing principal. It may exercise only a
            // capability-only policy, and only with the exact capability
            // authenticated by the host boundary.
            crate::service::Origin::System => {
                return Ok(policy.space_role.is_none()
                    && policy.actor_role.is_none()
                    && policy
                        .capability
                        .is_some_and(|required| invocation.auth.capability == Some(required)));
            }
            crate::service::Origin::Member(_) | crate::service::Origin::Actor(_) => {}
        }
        Ok(policy.space_role.is_none_or(|required| {
            invocation
                .auth
                .space_role
                .is_some_and(|actual| actual >= required)
        }) && policy
            .capability
            .is_none_or(|required| invocation.auth.capability == Some(required))
            && policy.actor_role.is_none_or(|required| {
                invocation
                    .auth
                    .actor_role
                    .is_some_and(|actual| actual >= required)
            }))
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn commit_execution(
        &mut self,
        invocation: &super::execution::ActorInvocation,
        reply: &mut super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        mut after: super::execution::ActorStateLanes,
        observed_slot: u64,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, MAX_EXECUTION_STATE_BYTES};
        self.validate_invocation_target(invocation)?;
        if reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.lane != invocation.mode.write_lane()
            || reply.observation != super::execution::ActorObservation::default()
            || self
                .invocation_results
                .contains_key(&(invocation.mode.invocation_scope(), invocation.invocation))
            || self
                .clean_invocation_errors
                .contains_key(&(invocation.mode.invocation_scope(), invocation.invocation))
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let write_lane = invocation.mode.write_lane();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let previous = before.get(lane);
            // Generated actors normalize every non-owned fresh lane back to
            // the runtime's empty sentinel after checking the reconstructed
            // canonical frame. Exact comparison is therefore sound from the
            // first invocation onward, including for hand-written PVMs.
            if Some(lane) != write_lane && !invocation.mode.can_read(lane) {
                if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) {
                    return Err(ActorExecutionError::InvalidActorOutput);
                }
            } else if Some(lane) != write_lane {
                match previous {
                    Some(previous) if after.get(lane) != Some(previous) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    None if after.get(lane).is_some_and(|bytes| !bytes.is_empty()) => {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    Some(_) | None => {}
                }
            }
        }
        let result_storage = invocation.mode.result_storage();
        if !self.result_storage_supported(result_storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        if self.invocation_result_count(result_storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self
                .invocation_result_bytes(result_storage)
                .saturating_add(reply.reply.len())
                > MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }
        if let Some(lane) = write_lane {
            let state = after
                .take(lane)
                .ok_or(ActorExecutionError::InvalidActorOutput)?;
            if state.len() > MAX_EXECUTION_STATE_BYTES {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
            let actor = self
                .actors
                .get(&reply.actor)
                .ok_or(ActorExecutionError::NotFound)?;
            if actor.record.state_generation != reply.incarnation {
                return Err(ActorExecutionError::StaleIncarnation);
            }
            self.lane_state.upsert(
                lane,
                actor.record.entry.actor,
                actor.record.state_generation,
                state,
            )?;
            self.lane_revisions.increment(lane)?;
        }
        reply.observation = self.observation(reply.actor, reply.mode)?;
        self.advance_result_authority_slot(result_storage, observed_slot);
        let scope = invocation.mode.invocation_scope();
        self.invocation_results.insert(
            (scope, invocation.invocation),
            StandardInvocationResult {
                scope,
                invocation: invocation.invocation,
                incarnation: invocation.incarnation,
                request: invocation.commitment(),
                reply: reply.clone(),
                storage: result_storage,
                clean: None,
            },
        );
        Ok(())
    }

    /// Atomically commit a clean terminal result together with the acceptance
    /// data required for exact retry and explicit delivery acknowledgement.
    /// A resumed terminal slice consumes its continuation in the same
    /// candidate, so no partially bound result can enter durable state.
    ///
    /// Row-producing calls must enclose this method in commit_clean_row_batch
    /// so the row delta and result share one final resource check and commit.
    #[cfg(feature = "pvm")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_clean_execution(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        invocation: &super::execution::ActorInvocation,
        reply: &mut super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        after: super::execution::ActorStateLanes,
        observed_slot: u64,
        terminal_continuation: Option<u64>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        self.commit_clean_execution_inner(
            work,
            authorization,
            invocation,
            reply,
            before,
            after,
            observed_slot,
            terminal_continuation,
            None,
            false,
        )
    }

    /// Use the same immutable resolution consumed by execution. Callers cannot
    /// substitute work or an execution request. Current authorization and actor
    /// provenance are still checked before any mutation.
    #[cfg(feature = "pvm")]
    pub(crate) fn commit_resolved_clean_execution(
        &mut self,
        resolved: &ResolvedCleanInvocation<'_>,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        reply: &mut super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        after: super::execution::ActorStateLanes,
        observed_slot: u64,
        terminal_continuation: Option<u64>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        self.commit_clean_execution_inner(
            resolved.work,
            authorization,
            &resolved.parts.0,
            reply,
            before,
            after,
            observed_slot,
            terminal_continuation,
            Some(&resolved.actor),
            resolved.work_validated,
        )
    }

    #[cfg(feature = "pvm")]
    fn commit_clean_execution_inner(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        invocation: &super::execution::ActorInvocation,
        reply: &mut super::execution::ActorExecutionReply,
        before: &super::execution::ActorStateLanes,
        after: super::execution::ActorStateLanes,
        observed_slot: u64,
        terminal_continuation: Option<u64>,
        resolved_actor: Option<&ActorRecord>,
        work_validated: bool,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        if work_validated {
            self.verify_clean_invocation_authorization_after_work_validation(
                work,
                authorization,
                observed_slot,
            )
        } else {
            self.verify_clean_invocation_authorization(work, authorization, observed_slot)
        }
            .map_err(|error| match error {
                crate::agent_sdk::InvocationError::NotCreated => ActorExecutionError::NotCreated,
                _ => ActorExecutionError::InvalidAuthorization,
            })?;
        if !clean_authorization_is_live_at(authorization, observed_slot) {
            return Err(ActorExecutionError::AuthorityExpired);
        }
        let accepted = StandardAcceptedInvocation::from_work(work);
        // Establish the complete SDK-to-execution correspondence before any
        // lane/result publication, not only when a later ACK reconstructs it.
        // Identity equality alone does not bind message, gas, legacy auth or
        // the application availability selected from the signed SDK work.
        if let Some(expected_actor) = resolved_actor {
            let current = self
                .clean_invocation_target(
                    work.actor,
                    work.incarnation,
                    work.deployment,
                    work.program,
                )
                .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
            if current.record != *expected_actor {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
        } else {
            let (resolved, ..) = self
                .resolve_clean_invocation(work)
                .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
            if resolved != *invocation {
                return Err(ActorExecutionError::InvalidActorOutput);
            }
        }
        if !accepted.validate_accepted()
            || invocation.invocation.0 != work.invocation.0
            || invocation.actor.0 != work.actor.0
            || invocation.incarnation.0 != work.incarnation.0
            || invocation.deployment.0 != work.deployment.0
            || invocation.program.0 != work.program.0
            || invocation.mode != clean_method_mode(work.mode)
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let mut candidate = self.clone();
        if let Some(sequence) = terminal_continuation {
            candidate.consume_machine_continuation(invocation, sequence)?;
        }
        candidate.commit_execution(invocation, reply, before, after, observed_slot)?;
        let key = (invocation.mode.invocation_scope(), invocation.invocation);
        let result = candidate
            .invocation_results
            .get_mut(&key)
            .ok_or(ActorExecutionError::InvalidActorOutput)?;
        if result.clean.is_some() {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        result.request = Hash(work.commitment().0);
        result.clean = Some(StandardCleanInvocationResult::from_work(
            work,
            authorization.clone(),
            observed_slot,
        ));
        *self = candidate;
        Ok(())
    }

    /// Stage an authenticated lane delta and its terminal/yield transition in
    /// one candidate. `commit` must perform the existing caller-authorization
    /// and result/continuation binding; its owned return value is exposed only
    /// after the complete encoded runtime satisfies signed resource limits.
    /// Row data must never be committed separately from that transition.
    #[cfg(feature = "pvm")]
    pub(crate) fn commit_clean_row_batch<R>(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        inline: Vec<u8>,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        commit: impl FnOnce(&mut Self) -> Result<R, super::execution::ActorExecutionError>,
    ) -> Result<R, super::execution::ActorExecutionError> {
        use super::actor_storage::{ActorLaneImage, StorageAccessError};
        use super::execution::ActorExecutionError;
        let access = self.resolve_clean_storage_access(work, schema)?;
        let lane = clean_method_mode(work.mode)
            .write_lane()
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let clean_lane = work
            .mode
            .write_lane()
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let actor = ActorId(work.actor.0);
        let generation = Hash(work.incarnation.0);
        let mut candidate = self.clone();
        let entries = candidate.lane_state.select_mut(lane);
        let index = entries.binary_search_by_key(&(actor, generation), |entry| {
            (entry.actor, entry.state_generation)
        });
        let mut image = match index {
            Ok(index) => ActorLaneImage::from_parts(
                core::mem::take(&mut entries[index].value),
                core::mem::take(&mut entries[index].rows),
            ),
            Err(_) => ActorLaneImage::default(),
        };
        access
            .apply_batch(clean_lane, &mut image, inline, changes)
            .map_err(|error| match error {
                StorageAccessError::Image(crate::service::wire::DecodeError::LimitExceeded) => {
                    ActorExecutionError::ResultCapacity
                }
                _ => ActorExecutionError::InvalidActorOutput,
            })?;
        let (value, rows) = image.into_parts();
        let empty = value.is_empty() && rows.is_empty();
        match index {
            Ok(index) if empty => {
                entries.remove(index);
            }
            Ok(index) => {
                entries[index].value = value;
                entries[index].rows = rows;
            }
            Err(_) if empty => {}
            Err(index) => {
                if entries.len() >= MAX_LANE_STATE_ENTRIES {
                    return Err(ActorExecutionError::ResultCapacity);
                }
                entries.insert(
                    index,
                    StandardLaneEntry {
                        actor,
                        state_generation: generation,
                        value,
                        rows,
                    },
                );
            }
        }
        let result = commit(&mut candidate)?;
        candidate
            .validate_restored_lane_state()
            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
        candidate
            .validate_signed_state_resource()
            .map_err(|error| match error {
                LifecycleError::ResourceLimit => ActorExecutionError::ResultCapacity,
                _ => ActorExecutionError::InvalidActorOutput,
            })?;
        *self = candidate;
        Ok(result)
    }

    /// Prepare one external lane's rows and existing runtime result/inline
    /// semantics as one candidate. Neither this runtime nor the provider is
    /// mutated. The caller must publish the returned root and enclosing runtime
    /// transition together; it must not install the returned runtime separately.
    /// `commit` retains the existing authorization/result/continuation checks.
    #[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_clean_external_row_batch<
        R: crate::agent_sdk::state_tree::BlockReader,
        T,
    >(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
        limits: crate::agent_sdk::contract::ExternalStateResourceLimits,
        lanes: [Option<(crate::agent_sdk::state_tree::StateTree, R)>; 3],
        (reads, writes): (
            &mut crate::agent_sdk::state_blocks::ReadBudget,
            &mut crate::agent_sdk::state_tree::WriteBudget,
        ),
        commit: impl FnOnce(&mut Self) -> Result<T, super::execution::ActorExecutionError>,
    ) -> Result<
        (Self, crate::agent_sdk::state_tree::TreeUpdate, T),
        super::execution::ActorExecutionError,
    > {
        use super::{actor_storage::ActorRowStorage, execution::ActorExecutionError};
        let lane = clean_method_mode(work.mode)
            .write_lane()
            .ok_or(ActorExecutionError::UnsupportedMethod)?;
        let reader = self.resolve_clean_external_storage_reader(work, schema, lanes, reads)?;
        reader
            .validate_delta(changes)
            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
        let before = super::wire::encode_standard_runtime_state(&self.snapshot());
        let metadata = reader
            .read_write_lane_metadata(super::execution::MAX_RUNTIME_STATE_BYTES)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?
            .ok_or(ActorExecutionError::InvalidAvailability)?;
        if metadata != before.component(lane) {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        let mut candidate = self.clone();
        let result = commit(&mut candidate)?;
        candidate
            .validate_restored_lane_state()
            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
        candidate
            .validate_signed_state_resource()
            .map_err(|error| match error {
                LifecycleError::ResourceLimit => ActorExecutionError::ResultCapacity,
                _ => ActorExecutionError::InvalidActorOutput,
            })?;
        let after = super::wire::encode_standard_runtime_state(&candidate.snapshot());
        if before.control != after.control
            || [StateLane::Linear, StateLane::Merge, StateLane::Local]
                .into_iter()
                .any(|other| other != lane && before.component(other) != after.component(other))
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let metadata = crate::agent_sdk::state_metadata::RuntimeMetadataUpdate::new(
            after.component(lane),
            super::execution::MAX_RUNTIME_STATE_BYTES,
        )
        .map_err(|_| ActorExecutionError::ResultCapacity)?;
        let (update, _) = reader
            .prepare_delta_with_metadata(changes, limits, metadata, writes)
            .map_err(|_| ActorExecutionError::InvalidAvailability)?;
        Ok((candidate, update, result))
    }

    /// Retain an authenticated terminal actor failure without committing any
    /// actor writes or lane revision. Unlike a successful execution, a failure
    /// has no committed observation. Its result and optional continuation
    /// retirement are one bounded, atomic update.
    ///
    /// This primitive is intentionally separate from the legacy clock-only
    /// failure path. Clean guest dispatch and the native successor verifier
    /// both derive terminal failure successors through this operation.
    #[cfg(any(feature = "pvm", feature = "std"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_clean_terminal_failure(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        invocation: &super::execution::ActorInvocation,
        reply: &super::execution::ActorExecutionReply,
        observed_slot: u64,
        terminal_continuation: Option<u64>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorExecutionStatus, ActorObservation};

        self.verify_clean_invocation_authorization(work, authorization, observed_slot)
            .map_err(|_| ActorExecutionError::InvalidAuthorization)?;
        if !clean_authorization_is_live_at(authorization, observed_slot) {
            return Err(ActorExecutionError::AuthorityExpired);
        }
        let (resolved, ..) = self
            .resolve_clean_invocation(work)
            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
        self.validate_invocation_target(invocation)?;
        let key = (invocation.mode.invocation_scope(), invocation.invocation);
        if resolved.commitment() != invocation.commitment()
            || !matches!(
                reply.status,
                ActorExecutionStatus::Forbidden
                    | ActorExecutionStatus::Panicked
                    | ActorExecutionStatus::OutOfGas
            )
            || reply.invocation != invocation.invocation
            || reply.actor != invocation.actor
            || reply.incarnation != invocation.incarnation
            || reply.deployment != invocation.deployment
            || reply.mode != invocation.mode
            || reply.lane != invocation.mode.write_lane()
            || reply.gas_remaining > invocation.gas
            || reply.observation != ActorObservation::default()
            || self.invocation_results.contains_key(&key)
            || self.clean_invocation_errors.contains_key(&key)
            || self
                .recover_clean_acknowledgement(work, authorization)
                .map_err(|_| ActorExecutionError::InvalidAuthorization)?
                .is_some()
        {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let storage = invocation.mode.result_storage();
        if !self.result_storage_supported(storage) {
            return Err(ActorExecutionError::UnsupportedResultStorage);
        }
        if self.invocation_result_count(storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self
                .invocation_result_bytes(storage)
                .saturating_add(reply.reply.len())
                > MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(ActorExecutionError::ResultCapacity);
        }

        let mut candidate = self.clone();
        if let Some(sequence) = terminal_continuation {
            candidate.consume_machine_continuation(invocation, sequence)?;
        }
        candidate.advance_result_authority_slot(storage, observed_slot);
        candidate.invocation_results.insert(
            key,
            StandardInvocationResult {
                scope: key.0,
                invocation: invocation.invocation,
                incarnation: invocation.incarnation,
                request: Hash(work.commitment().0),
                reply: reply.clone(),
                storage,
                clean: Some(StandardCleanInvocationResult::from_work(
                    work,
                    authorization.clone(),
                    observed_slot,
                )),
            },
        );
        *self = candidate;
        Ok(())
    }

    /// Retire one exact clean terminal result after re-authenticating the
    /// original work and typed authorization. No clock or state is touched until every
    /// comparison has succeeded.
    pub(crate) fn recover_clean_acknowledgement(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<
        Option<crate::agent_sdk::InvocationAcknowledgement>,
        crate::agent_sdk::InvocationError,
    > {
        use crate::agent_sdk::InvocationError;

        if !work.validate() {
            return Err(InvocationError::InvalidAuthorization);
        }
        self.recover_clean_acknowledgement_after_work_validation(work, authorization)
    }

    // Invoke recovery has already validated all availability preimages. The
    // retained retirement fact binds their references, not another transport
    // of their bytes.
    fn recover_clean_acknowledgement_after_work_validation(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<
        Option<crate::agent_sdk::InvocationAcknowledgement>,
        crate::agent_sdk::InvocationError,
    > {
        self.recover_clean_retirement(
            &crate::agent_sdk::InvocationRetirement::from_work(work),
            authorization,
        )
    }

    /// Recover only an exact previously committed retirement fact. Structural
    /// authorization matching is sufficient here because the full authorization
    /// commitment must equal the retained fact; this cannot accept unseen work.
    pub(crate) fn recover_clean_retirement(
        &self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<
        Option<crate::agent_sdk::InvocationAcknowledgement>,
        crate::agent_sdk::InvocationError,
    > {
        use crate::agent_sdk::InvocationError;

        if !work.validate() || !authorization.matches_retirement(work) {
            return Err(InvocationError::InvalidAuthorization);
        }
        let scope = clean_method_mode(work.mode).invocation_scope();
        let Some(retained) = self.clean_invocation_acknowledgements.iter().find(|item| {
            item.invocation == work.invocation
                && clean_method_mode(item.mode).invocation_scope() == scope
        }) else {
            // A compacted sequenced fact is summarized by its component's
            // watermark. It remains consumed: every caller of this recovery
            // refuses it exactly as it refuses a retained divergent fact.
            if let Some(position) = clean_sequenced_position(work.invocation, work.mode)?
                && position
                    <= self
                        .sequenced_retired_through
                        .get(clean_method_mode(work.mode).result_storage())
            {
                return Err(InvocationError::DivergentInvocation);
            }
            return Ok(None);
        };
        if retained.actor != work.actor
            || retained.incarnation != work.incarnation
            || retained.deployment != work.deployment
            || retained.mode != work.mode
            || retained.work != work.commitment()
            || retained.authorization != authorization.commitment()
        {
            return Err(InvocationError::DivergentInvocation);
        }
        Ok(Some(*retained))
    }

    pub(crate) fn acknowledge_clean_invocation(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::InvocationAcknowledgement, crate::agent_sdk::InvocationError>
    {
        self.acknowledge_clean_invocation_with_status(work, authorization)
            .map(|(acknowledgement, _)| acknowledgement)
    }

    /// Return the exact acknowledgement and whether this call applied it.
    /// An already retained acknowledgement must preserve the caller's original
    /// encoded state without reserializing it. Keep recovery and application in
    /// one call so that fresh work is not validated twice just to learn this bit.
    pub(crate) fn acknowledge_clean_invocation_with_status(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<
        (crate::agent_sdk::InvocationAcknowledgement, bool),
        crate::agent_sdk::InvocationError,
    > {
        if !work.validate() {
            return Err(crate::agent_sdk::InvocationError::InvalidAuthorization);
        }
        self.acknowledge_clean_retirement_with_status(
            &crate::agent_sdk::InvocationRetirement::from_work(work),
            authorization,
        )
    }

    /// Retire an exact authenticated retained result using references only.
    /// This never authorizes execution or supplies missing artifact preimages.
    pub(crate) fn acknowledge_clean_retirement_with_status(
        &mut self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<
        (crate::agent_sdk::InvocationAcknowledgement, bool),
        crate::agent_sdk::InvocationError,
    > {
        if let Some(retained) = self.recover_clean_retirement(work, authorization)? {
            return Ok((retained, false));
        }
        self.acknowledge_new_clean_retirement(work, authorization)
            .map(|acknowledgement| (acknowledgement, true))
    }

    // Only called immediately after authenticated recovery found no retained
    // acknowledgement; never expose an entry point that skips that check.
    fn acknowledge_new_clean_retirement(
        &mut self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::InvocationAcknowledgement, crate::agent_sdk::InvocationError>
    {
        use crate::agent_sdk::{InvocationAcknowledgement, InvocationError};

        // Recovery validated the immutable metadata and authorization binding.
        // Fresh retirement additionally authenticates scope and receipt signatures.
        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(InvocationError::NotCreated)?;
        if work.space != descriptor.identity.space
            || work.agent != descriptor.identity.agent
            || work.runtime_deployment != descriptor.identity.runtime_deployment
        {
            return Err(InvocationError::InvalidAuthorization);
        }
        if let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) = authorization
        {
            if !descriptor.authority.accepts(receipt)
                || !super::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                )
            {
                return Err(InvocationError::InvalidAuthorization);
            }
        }
        let scope = clean_method_mode(work.mode).invocation_scope();
        let key = (scope, InvocationId(work.invocation.0));
        if let Some(record) = self.clean_invocation_errors.get(&key) {
            if !self.clean_invocation_error_is_valid(record)
                || !record.binding.matches_retirement(work, authorization)
            {
                return Err(InvocationError::DivergentInvocation);
            }
            let acknowledgement = InvocationAcknowledgement {
                invocation: work.invocation,
                actor: work.actor,
                incarnation: work.incarnation,
                deployment: work.deployment,
                mode: work.mode,
                work: record.binding.work,
                authorization: record.binding.authorization.commitment(),
            };
            return self.commit_clean_acknowledgement(work, authorization, acknowledgement);
        }
        let result = self
            .invocation_results
            .get(&key)
            .ok_or(InvocationError::NotFound)?;
        let binding = result
            .clean
            .as_ref()
            .ok_or(InvocationError::DivergentInvocation)?;
        // The full check above authenticated these same immutable work,
        // authorization and runtime values. Only the observation slot differs
        // here: preserve that check (notably PublicPreflight's lower bound)
        // without hashing availability and verifying the signature again.
        if matches!(authorization,
            crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight)
                if binding.observed_slot < preflight.observed_slot)
        {
            return Err(InvocationError::InvalidAuthorization);
        }
        if !binding.matches_retirement(work, authorization)
            || !clean_authorization_is_live_at(&binding.authorization, binding.observed_slot)
            || self
                .result_authority_slot(result.storage)
                .is_none_or(|slot| slot < binding.observed_slot)
        {
            return Err(InvocationError::DivergentInvocation);
        }
        self.clean_invocation_target(work.actor, work.incarnation, work.deployment, work.program)?;
        if result.request.0 != binding.work.0
            || result.scope != scope
            || result.invocation.0 != work.invocation.0
            || result.incarnation.0 != work.incarnation.0
            || result.reply.actor.0 != work.actor.0
            || result.reply.deployment.0 != work.deployment.0
            || result.reply.mode != clean_method_mode(work.mode)
        {
            return Err(InvocationError::DivergentInvocation);
        }
        let acknowledgement = InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: binding.work,
            authorization: binding.authorization.commitment(),
        };
        self.commit_clean_acknowledgement(work, authorization, acknowledgement)
    }

    fn commit_clean_acknowledgement(
        &mut self,
        work: &crate::agent_sdk::InvocationRetirement,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        acknowledgement: crate::agent_sdk::InvocationAcknowledgement,
    ) -> Result<crate::agent_sdk::InvocationAcknowledgement, crate::agent_sdk::InvocationError>
    {
        use crate::agent_sdk::InvocationError;
        let key = (
            clean_method_mode(work.mode).invocation_scope(),
            InvocationId(work.invocation.0),
        );
        if self.clean_descriptor.as_ref().is_some_and(|descriptor| {
            is_system_authority_projection_query(descriptor, work, authorization)
        }) {
            // Replay of the ordered acknowledgement reconstructs this same
            // transition before the result disappears. A later whole-query
            // retry is safe because the signed request is read-only and
            // response-bound, while no positive guest fact or live proof edge
            // remains to consume bounded lifecycle capacity.
            self.invocation_results.remove(&key);
            self.clean_invocation_errors.remove(&key);
            return Ok(acknowledgement);
        }
        let storage = clean_method_mode(work.mode).result_storage();
        // At capacity, only the component's next sequence position may be
        // compacted: the new fact itself or a retained one. Anything else
        // (an unsequenced fact, or a gap below the oldest retained position)
        // keeps today's fail-closed refusal.
        let compaction = if self
            .clean_invocation_acknowledgements
            .iter()
            .filter(|item| clean_method_mode(item.mode).result_storage() == storage)
            .count()
            >= MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE
        {
            let next = self
                .sequenced_retired_through
                .get(storage)
                .checked_add(1)
                .ok_or(InvocationError::ResultCapacity)?;
            if clean_sequenced_position(acknowledgement.invocation, acknowledgement.mode)?
                == Some(next)
            {
                Some((next, None))
            } else {
                let retained = self
                    .clean_invocation_acknowledgements
                    .iter()
                    .position(|item| {
                        clean_method_mode(item.mode).result_storage() == storage
                            && clean_sequenced_position(item.invocation, item.mode)
                                == Ok(Some(next))
                    })
                    .ok_or(InvocationError::ResultCapacity)?;
                Some((next, Some(retained)))
            }
        } else {
            None
        };
        self.invocation_results.remove(&key);
        self.clean_invocation_errors.remove(&key);
        if let Some((next, retained)) = compaction {
            self.sequenced_retired_through.set(storage, next);
            match retained {
                // The watermark now refuses this identity; no fact is kept.
                None => return Ok(acknowledgement),
                Some(index) => {
                    self.clean_invocation_acknowledgements.remove(index);
                }
            }
        }
        let storage_tag = clean_acknowledgement_storage_tag(acknowledgement.mode);
        let insertion = self
            .clean_invocation_acknowledgements
            .iter()
            .position(|item| clean_acknowledgement_storage_tag(item.mode) > storage_tag)
            .unwrap_or(self.clean_invocation_acknowledgements.len());
        self.clean_invocation_acknowledgements
            .insert(insertion, acknowledgement);
        Ok(acknowledgement)
    }

    fn clean_invocation_error_is_valid(&self, record: &StandardCleanInvocationError) -> bool {
        let binding = &record.binding;
        self.clean_descriptor.is_some()
            && record.error.is_durable_exact_outcome()
            && binding.accepted.validate_accepted()
            && binding.work != crate::agent_sdk::Hash::ZERO
            && self.result_storage_supported(record.storage())
            && Self::clean_error_authorization_window_is_valid(
                &binding.authorization,
                record.error,
                binding.observed_slot,
            )
            && self
                .result_authority_slot(record.storage())
                .is_some_and(|slot| slot >= binding.observed_slot)
            && self
                .verify_clean_accepted_authorization(
                    &binding.accepted,
                    &binding.authorization,
                    Hash(binding.work.0),
                    binding.observed_slot,
                )
                .is_ok()
    }

    pub(crate) fn recover_clean_invocation_error(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<crate::agent_sdk::InvocationError>, crate::agent_sdk::InvocationError> {
        self.verify_clean_invocation_authorization(work, authorization, observed_slot)?;
        self.recover_clean_invocation_error_after_authorization(work, authorization, observed_slot)
    }

    #[cfg(feature = "pvm")]
    pub(super) fn recover_validated_clean_invocation_error(
        &mut self,
        validated: super::wire::ValidatedInvocationWork<'_>,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<crate::agent_sdk::InvocationError>, crate::agent_sdk::InvocationError> {
        let work = validated.work();
        self.verify_clean_invocation_authorization_after_work_validation(
            work,
            authorization,
            observed_slot,
        )?;
        self.recover_clean_invocation_error_after_authorization(work, authorization, observed_slot)
    }

    fn recover_clean_invocation_error_after_authorization(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<Option<crate::agent_sdk::InvocationError>, crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;
        if self
            .recover_clean_acknowledgement_after_work_validation(work, authorization)?
            .is_some()
        {
            return Err(InvocationError::DivergentInvocation);
        }
        let key = (
            clean_method_mode(work.mode).invocation_scope(),
            InvocationId(work.invocation.0),
        );
        let Some(record) = self.clean_invocation_errors.get(&key) else {
            return Ok(None);
        };
        if !self.clean_invocation_error_is_valid(record)
            || !record.binding.matches(work, authorization)
            || observed_slot < record.binding.observed_slot
        {
            return Err(InvocationError::DivergentInvocation);
        }
        let (error, storage) = (record.error, record.storage());
        self.advance_result_authority_slot(storage, observed_slot);
        Ok(Some(error))
    }

    pub(crate) fn clean_error_authorization_window_is_valid(
        authorization: &crate::agent_sdk::InvocationAuthorization,
        error: crate::agent_sdk::InvocationError,
        observed_slot: u64,
    ) -> bool {
        if error == crate::agent_sdk::InvocationError::ExpiredBeforeExecution {
            matches!(authorization,
                crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt)
                    if observed_slot > receipt.selector.expires_at)
        } else {
            clean_authorization_is_live_at(authorization, observed_slot)
        }
    }

    /// Resolve only an unseen signed invocation whose execution window ended.
    /// Existing results and continuations stay on their exact recovery paths.
    pub(crate) fn retain_clean_unseen_expiry(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        observed_slot: u64,
    ) -> Result<bool, crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};
        if !matches!(authorization, InvocationAuthorization::AuthorityReceipt(receipt)
            if observed_slot > receipt.selector.expires_at)
        {
            return Ok(false);
        }
        let key = (
            clean_method_mode(work.mode).invocation_scope(),
            InvocationId(work.invocation.0),
        );
        if self.invocation_results.contains_key(&key)
            || self
                .machine_continuations
                .iter()
                .any(|record| (record.mode.invocation_scope(), record.invocation) == key)
        {
            return Ok(false);
        }
        self.retain_clean_invocation_error(
            work,
            authorization,
            InvocationError::ExpiredBeforeExecution,
            observed_slot,
            None,
        )?;
        Ok(true)
    }

    /// Retain only an authenticated durable rejection, including a stale or
    /// absent target. No actor state/revision is ever accepted by this path.
    pub(crate) fn retain_clean_invocation_error(
        &mut self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        error: crate::agent_sdk::InvocationError,
        observed_slot: u64,
        terminal_continuation: Option<u64>,
    ) -> Result<(), crate::agent_sdk::InvocationError> {
        use crate::agent_sdk::InvocationError;
        self.verify_clean_invocation_authorization(work, authorization, observed_slot)?;
        if !error.is_durable_exact_outcome() {
            return Err(InvocationError::InvalidInput);
        }
        if !Self::clean_error_authorization_window_is_valid(authorization, error, observed_slot) {
            return Err(InvocationError::AuthorityExpired);
        }
        if error == InvocationError::ExpiredBeforeExecution {
            // This fence only resolves work that never started. Continuations
            // must retain their accepted execution semantics across expiry.
            if terminal_continuation.is_some() {
                return Err(InvocationError::StaleContinuation);
            }
            if self
                .logical_slot_high_water()
                .is_some_and(|high_water| observed_slot < high_water)
            {
                return Err(InvocationError::AuthoritySlotRegressed);
            }
        }
        let record = StandardCleanInvocationError {
            binding: StandardCleanInvocationResult::from_work(
                work,
                authorization.clone(),
                observed_slot,
            ),
            error,
        };
        let key = record.key();
        let storage = record.storage();
        if !self.result_storage_supported(storage) {
            return Err(InvocationError::UnsupportedResultStorage);
        }
        if self.invocation_results.contains_key(&key)
            || self.clean_invocation_errors.contains_key(&key)
            || self
                .recover_clean_acknowledgement(work, authorization)?
                .is_some()
        {
            return Err(InvocationError::DivergentInvocation);
        }
        if self.invocation_result_count(storage) >= MAX_INVOCATION_RESULTS_PER_LANE
            || self
                .invocation_result_bytes(storage)
                .saturating_add(super::wire::encode_clean_invocation_error(&record).len())
                > MAX_INVOCATION_RESULT_BYTES_PER_LANE
        {
            return Err(InvocationError::ResultCapacity);
        }
        let continuation = self
            .machine_continuations
            .iter()
            .position(|item| (item.mode.invocation_scope(), item.invocation) == key);
        match (terminal_continuation, continuation) {
            (None, None) => {}
            (Some(sequence), Some(index)) => {
                let item = &self.machine_continuations[index];
                if item.ready_sequence != sequence
                    || item.observed_slot != observed_slot
                    || item.accepted.as_ref() != Some(&record.binding.accepted)
                    || item.authorization.as_ref() != Some(authorization)
                    || item.work != Hash(record.binding.work.0)
                    || self
                        .machine_continuations
                        .iter()
                        .position(|item| item.storage() == storage)
                        != Some(index)
                {
                    return Err(InvocationError::StaleContinuation);
                }
            }
            _ => return Err(InvocationError::StaleContinuation),
        }
        let mut candidate = self.clone();
        if let Some(index) = continuation {
            candidate.machine_continuations.remove(index);
        }
        candidate.advance_result_authority_slot(storage, observed_slot);
        if !candidate.clean_invocation_error_is_valid(&record) {
            return Err(InvocationError::InvalidAuthorization);
        }
        candidate.clean_invocation_errors.insert(key, record);
        *self = candidate;
        Ok(())
    }

    fn invocation_result_count(&self, storage: InvocationResultStorage) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.storage == storage)
            .count()
            + self
                .clean_invocation_errors
                .values()
                .filter(|item| item.storage() == storage)
                .count()
    }

    fn invocation_result_bytes(&self, storage: InvocationResultStorage) -> usize {
        self.invocation_results
            .values()
            .filter(|result| result.storage == storage)
            .fold(0usize, |total, result| {
                total.saturating_add(result.reply.reply.len())
            })
            .saturating_add(
                self.clean_invocation_errors
                    .values()
                    .filter(|item| item.storage() == storage)
                    .fold(0usize, |total, item| {
                        total.saturating_add(super::wire::encode_clean_invocation_error(item).len())
                    }),
            )
    }

    #[cfg(feature = "pvm")]
    fn observation(
        &self,
        actor: ActorId,
        mode: super::MethodMode,
    ) -> Result<super::execution::ActorObservation, super::execution::ActorExecutionError> {
        use super::execution::{ActorExecutionError, ActorObservation};

        let actor = self
            .actors
            .get(&actor)
            .ok_or(ActorExecutionError::NotFound)?;
        Ok(ActorObservation {
            linear_revision: (actor.record.entry.lanes.contains(StateLane::Linear)
                && mode.can_read(StateLane::Linear))
            .then_some(self.lane_revisions.linear),
            merge_frontier: (actor.record.entry.lanes.contains(StateLane::Merge)
                && mode.can_read(StateLane::Merge))
            .then(|| {
                let merge = self
                    .lane_state
                    .lookup(
                        StateLane::Merge,
                        actor.record.entry.actor,
                        actor.record.state_generation,
                    )
                    .map(|entry| {
                        super::actor_storage::ActorLaneImage::encode_parts(
                            &entry.value,
                            &entry.rows,
                        )
                    });
                Hash::digest(
                    b"vos/agent/merge-frontier",
                    &[&actor.record.entry.actor.0, merge.as_deref().unwrap_or(&[])],
                )
            }),
            local_revision: (actor.record.entry.lanes.contains(StateLane::Local)
                && mode.can_read(StateLane::Local))
            .then_some(self.lane_revisions.local),
        })
    }

    fn validate_restored_lane_state(&self) -> Result<(), LifecycleError> {
        if !self.lane_state.is_canonical() {
            return Err(LifecycleError::InvalidRequest);
        }
        let profile = self.created()?.identity.profile;
        for (lane, entries) in self.lane_state.lanes() {
            // Profile support is immutable. Unlike a Local/Shared runtime
            // capability downgrade, a Private agent could never have owned
            // Linear history, so any such bytes or cursor are corruption.
            if !profile.supports(lane)
                && (!entries.is_empty()
                    || self.lane_revisions.revision(lane) != 0
                    || self.lane_revisions.authority_slot(lane).is_some())
            {
                return Err(LifecycleError::InvalidRequest);
            }
            for entry in entries {
                if let Some(actor) = self.actors.get(&entry.actor)
                    && actor.record.state_generation == entry.state_generation
                    && !actor.record.entry.lanes.contains(lane)
                {
                    return Err(LifecycleError::InvalidRequest);
                }
            }
        }
        for actor in self.actors.values() {
            let total = [StateLane::Linear, StateLane::Merge, StateLane::Local]
                .into_iter()
                .filter(|lane| actor.record.entry.lanes.contains(*lane))
                .try_fold(0usize, |total, lane| {
                    total.checked_add(
                        self.lane_state
                            .lookup(
                                lane,
                                actor.record.entry.actor,
                                actor.record.state_generation,
                            )
                            .map_or(0, |entry| entry.value.len()),
                    )
                });
            if total.is_none_or(|len| len > super::execution::MAX_EXECUTION_STATE_TOTAL_BYTES) {
                return Err(LifecycleError::InvalidRequest);
            }
        }
        Ok(())
    }

    fn upgrade_actor(
        &mut self,
        upgrade: super::UpgradeActor,
    ) -> Result<LifecycleReply, LifecycleError> {
        self.validate_requirements(upgrade.requirements)?;
        if !self.created()?.runtime_contract.supports(upgrade.contract) {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        let debt = self.lifecycle_debt(upgrade.actor)?;
        if !quiescent(debt) {
            return Err(LifecycleError::Busy(debt));
        }
        let actor = self
            .actors
            .get(&upgrade.actor)
            .ok_or(LifecycleError::NotFound)?;
        if actor.record.entry.deployment != upgrade.from_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if actor.record.requirements.lanes != upgrade.requirements.lanes {
            // Lane-shape migration needs an explicit runtime migration
            // payload. Reinterpreting existing bytes under a new lane set is
            // never a safe package-only upgrade.
            return Err(LifecycleError::UnsupportedLane);
        }
        if actor.record.requirements.lanes != LaneSet::NONE
            && actor.record.entry.program != upgrade.to_program
        {
            // Source-level layout metadata is not a semantic codec or state
            // migration proof. Until runtimes expose an explicit migration
            // ABI, only same-program repackaging is safe for stateful actors.
            return Err(LifecycleError::UnsupportedLane);
        }
        if upgrade.to_deployment == DeploymentId::ZERO || upgrade.to_program == ProgramId::ZERO {
            return Err(LifecycleError::InvalidRequest);
        }
        if upgrade.producer == ProducerId::ZERO
            || upgrade.package.hash == Hash::ZERO
            || upgrade.package.len == 0
            || upgrade.agent_schema.hash == Hash::ZERO
            || upgrade.agent_schema.len == 0
            || upgrade.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
            || upgrade.role_policies.hash == Hash::ZERO
            || upgrade.role_policies.len == 0
            || upgrade.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
            || upgrade.constructor_abi == Hash::ZERO
            || upgrade.state_layout == Hash::ZERO
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if actor.record.state_layout != upgrade.state_layout {
            return Err(LifecycleError::UnsupportedLane);
        }
        if actor.record.constructor_abi != upgrade.constructor_abi {
            return Err(LifecycleError::InvalidRequest);
        }
        let installation_data = actor.record.installation_data.as_ref();
        let config = self.created()?;
        validate_artifact_resources(
            config.runtime_contract.resources,
            core::iter::once(&config.runtime_package)
                .chain(
                    self.actors
                        .iter()
                        .filter(|(actor, _)| **actor != upgrade.actor)
                        .flat_map(|(_, actor)| actor_artifact_references(actor)),
                )
                .chain([
                    &upgrade.package,
                    &upgrade.agent_schema,
                    &upgrade.role_policies,
                ])
                .chain(installation_data),
        )?;
        if self
            .program_bindings
            .get(&upgrade.actor)
            .is_some_and(|binding| binding.program != upgrade.to_program)
        {
            // A binding names one ProgramId; a new program is bound afresh.
            self.program_bindings.remove(&upgrade.actor);
        }
        let actor = self
            .actors
            .get_mut(&upgrade.actor)
            .expect("validated actor remains installed");
        actor.record.entry.deployment = upgrade.to_deployment;
        actor.record.entry.program = upgrade.to_program;
        actor.record.entry.package = upgrade.package.clone();
        actor.record.entry.agent_schema = upgrade.agent_schema.clone();
        actor.record.entry.role_policies = upgrade.role_policies.clone();
        actor.record.entry.constructor_abi = upgrade.constructor_abi;
        actor.record.entry.state_layout = upgrade.state_layout;
        actor.record.entry.lanes = upgrade.requirements.lanes;
        actor.record.producer = upgrade.producer;
        actor.record.package = upgrade.package;
        actor.record.agent_schema = upgrade.agent_schema;
        actor.record.role_policies = upgrade.role_policies;
        actor.record.constructor_abi = upgrade.constructor_abi;
        actor.record.state_layout = upgrade.state_layout;
        actor.record.contract = upgrade.contract;
        actor.record.requirements = upgrade.requirements;
        Ok(LifecycleReply::Upgraded(actor.record.entry.clone()))
    }

    fn set_suspended(
        &mut self,
        actor: ActorId,
        expected_deployment: DeploymentId,
        suspended: bool,
    ) -> Result<LifecycleReply, LifecycleError> {
        let actor = self
            .actors
            .get_mut(&actor)
            .ok_or(LifecycleError::NotFound)?;
        if actor.record.entry.deployment != expected_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if actor.record.entry.suspended == suspended {
            return Err(LifecycleError::InvalidRequest);
        }
        actor.record.entry.suspended = suspended;
        if suspended {
            Ok(LifecycleReply::Suspended(actor.record.entry.clone()))
        } else {
            Ok(LifecycleReply::Resumed(actor.record.entry.clone()))
        }
    }

    fn acknowledge_invocation(
        &mut self,
        scope: InvocationScope,
        invocation: InvocationId,
        request: Hash,
        authority: super::authority::ActorInvocationReceipt,
    ) -> Result<LifecycleReply, LifecycleError> {
        let result = self
            .invocation_results
            .get(&(scope, invocation))
            .ok_or(LifecycleError::NotFound)?;
        if result.clean.is_some() || result.request != request || result.scope != scope {
            return Err(LifecycleError::InvalidRequest);
        }
        let config = self.created()?;
        if authority.verify_guest_signature(&config.authority).is_err()
            || authority.claim.space != config.identity.space
            || authority.claim.agent != config.identity.agent
            || authority.claim.authorization
                != Hash::digest(b"vos/agent/invocation-authorization", &[&request.0])
        {
            return Err(LifecycleError::InvalidRequest);
        }
        self.invocation_results.remove(&(scope, invocation));
        Ok(LifecycleReply::InvocationAcknowledged { scope, invocation })
    }

    fn remove_leaf(
        &mut self,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<LifecycleReply, LifecycleError> {
        let managed = self.actors.get(&actor).ok_or(LifecycleError::NotFound)?;
        if managed.record.entry.deployment != expected_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        let debt = self.lifecycle_debt(actor)?;
        if !debt.is_clear() {
            return Err(LifecycleError::Busy(debt));
        }
        if self.retired_installation_ids.len() >= MAX_RETIRED_INSTALLATION_IDS {
            return Err(LifecycleError::ResourceLimit);
        }
        let installation_id = managed.record.installation_id;
        self.actors.remove(&actor);
        self.program_bindings.remove(&actor);
        let inserted = self.retired_installation_ids.insert(installation_id);
        debug_assert!(inserted, "a live installation cannot already be retired");
        Ok(LifecycleReply::Removed(actor))
    }

    fn upgrade_runtime(
        &mut self,
        from_deployment: DeploymentId,
        to_deployment: DeploymentId,
        to_program: ProgramId,
        producer: crate::service::ProducerId,
        package: crate::service::BlobRef,
        contract: super::contract::RuntimePackageContract,
        capabilities: super::RuntimeCapabilities,
        allow_outer_proofs: bool,
    ) -> Result<LifecycleReply, LifecycleError> {
        let config = self.created()?;
        let intrinsic = super::RuntimeCapabilities::standard();
        if config.identity.runtime_deployment != from_deployment {
            return Err(LifecycleError::StaleDeployment);
        }
        if !contract.is_valid()
            || to_deployment == DeploymentId::ZERO
            || to_program == ProgramId::ZERO
            || producer == ProducerId::ZERO
            || producer == config.identity.transition_producer
            || package.hash == Hash::ZERO
            || package.len == 0
            || capabilities.max_actors > intrinsic.max_actors
            || capabilities.lanes.bits() & !intrinsic.lanes.bits() != 0
            || (capabilities.scheduling && !intrinsic.scheduling)
            || (capabilities.proofs && !intrinsic.proofs && !allow_outer_proofs)
            || capabilities.max_actors < self.actors.len() as u32
            || !capabilities.lanes.supported_by(config.identity.profile)
            || self.actors.values().any(|actor| {
                !capabilities.satisfies(actor.record.requirements)
                    || !contract.supports(actor.record.contract)
            })
            || self.invocation_results.values().any(|result| {
                matches!(
                    result.storage,
                    InvocationResultStorage::Lane(lane)
                        if !config.identity.profile.supports(lane)
                            || !capabilities.lanes.contains(lane)
                )
            })
            || self.clean_invocation_errors.values().any(|result| {
                matches!(result.storage(), InvocationResultStorage::Lane(lane)
                    if !config.identity.profile.supports(lane) || !capabilities.lanes.contains(lane))
            })
        {
            return Err(LifecycleError::UnsupportedRuntime);
        }
        validate_artifact_resources(
            contract.resources,
            core::iter::once(&package)
                .chain(self.actors.values().flat_map(actor_artifact_references)),
        )?;
        if let Some(debt) = self
            .actors
            .keys()
            .filter_map(|actor| self.lifecycle_debt(*actor).ok())
            .find(|debt| !quiescent(*debt))
        {
            return Err(LifecycleError::Busy(debt));
        }
        let mut next = self.clone();
        let config = next.config.as_mut().expect("created agent has config");
        config.identity.runtime_deployment = to_deployment;
        config.identity.runtime_program = to_program;
        config.identity.runtime_producer = producer;
        config.runtime_package = package;
        config.runtime_contract = contract;
        config.capabilities = capabilities;
        let identity = config.identity.clone();
        next.validate_signed_state_resource()?;
        *self = next;
        Ok(LifecycleReply::RuntimeUpgraded(identity))
    }

    fn clean_resource_usage(
        &self,
    ) -> Result<crate::agent_sdk::RuntimeResourceUsage, crate::agent_sdk::ManagementError> {
        let state_bytes = super::wire::encode_standard_runtime_state(&self.snapshot())
            .encoded_len()
            .ok_or(crate::agent_sdk::ManagementError::ResourceLimit)?;
        self.clean_resource_usage_with_state_bytes(state_bytes)
    }

    /// Reuse a length measured from this same immutable runtime, never a
    /// caller-supplied size. All non-state resource accounting still runs.
    fn clean_resource_usage_with_state_bytes(
        &self,
        state_bytes: usize,
    ) -> Result<crate::agent_sdk::RuntimeResourceUsage, crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::ManagementError;

        let config = self.created().map_err(legacy_management_error)?;
        let mut usage = crate::agent_sdk::RuntimeResourceUsage {
            actors: u32::try_from(self.actors.len()).map_err(|_| ManagementError::ResourceLimit)?,
            // Management executes between scheduler slices; persisted
            // continuations are dormant snapshots, not live PVM machines.
            active_machines: 0,
            continuations: u32::try_from(self.machine_continuations.len())
                .map_err(|_| ManagementError::ResourceLimit)?,
            ..crate::agent_sdk::RuntimeResourceUsage::default()
        };
        let mut artifact_usage = ArtifactResourceUsage::default();
        for reference in core::iter::once(&config.runtime_package)
            .chain(self.actors.values().flat_map(actor_artifact_references))
        {
            artifact_usage
                .insert(reference, config.runtime_contract.resources)
                .map_err(legacy_management_error)?;
        }
        usage.artifact_references = u32::try_from(artifact_usage.lengths.len())
            .map_err(|_| ManagementError::ResourceLimit)?;
        usage.artifact_referenced_bytes = artifact_usage.referenced_bytes;
        for actor in self.actors.keys().copied() {
            let debt = self
                .lifecycle_debt(actor)
                .map_err(legacy_management_error)?;
            usage.inbox = usage
                .inbox
                .checked_add(debt.inbox)
                .ok_or(ManagementError::ResourceLimit)?;
            usage.outbox = usage
                .outbox
                .checked_add(debt.outbox)
                .ok_or(ManagementError::ResourceLimit)?;
            usage.schedules = usage
                .schedules
                .checked_add(debt.schedules)
                .ok_or(ManagementError::ResourceLimit)?;
            usage.proof_artifacts = usage
                .proof_artifacts
                .checked_add(debt.proof_artifacts)
                .ok_or(ManagementError::ResourceLimit)?;
        }
        usage.state_bytes =
            u32::try_from(state_bytes).map_err(|_| ManagementError::ResourceLimit)?;
        Ok(usage)
    }

    fn verify_clean_management_authority(
        &self,
        space: crate::agent_sdk::SpaceId,
        agent: crate::agent_sdk::AgentId,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
        allow_historical_runtime: bool,
    ) -> Result<(), crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::ManagementError;
        use crate::agent_sdk::authority::AuthorityOperationKind;

        let descriptor = match request {
            crate::agent_sdk::ManagementRequest::Create(requested) => {
                let selected = self
                    .clean_creation_descriptor
                    .as_ref()
                    .unwrap_or(requested.as_ref());
                if requested.as_ref() != selected {
                    return Err(ManagementError::AuthoritySequenceConflict);
                }
                selected
            }
            _ => self
                .clean_descriptor
                .as_ref()
                .ok_or(ManagementError::NotCreated)?,
        };
        let expected_runtime = match request {
            crate::agent_sdk::ManagementRequest::Create(descriptor) => {
                descriptor.identity.runtime_deployment
            }
            crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => upgrade.from_deployment,
            _ => descriptor.identity.runtime_deployment,
        };
        let expected_operation = match request {
            crate::agent_sdk::ManagementRequest::Create(_) => AuthorityOperationKind::CreateAgent,
            crate::agent_sdk::ManagementRequest::Install(_) => AuthorityOperationKind::InstallActor,
            crate::agent_sdk::ManagementRequest::UpgradeActor(_) => {
                AuthorityOperationKind::UpgradeActor
            }
            crate::agent_sdk::ManagementRequest::Suspend { .. } => {
                AuthorityOperationKind::SuspendActor
            }
            crate::agent_sdk::ManagementRequest::Resume { .. } => {
                AuthorityOperationKind::ResumeActor
            }
            crate::agent_sdk::ManagementRequest::RemoveLeaf { .. } => {
                AuthorityOperationKind::RemoveActor
            }
            crate::agent_sdk::ManagementRequest::UpgradeRuntime(_) => {
                AuthorityOperationKind::UpgradeRuntime
            }
            crate::agent_sdk::ManagementRequest::ChangeReplicas { .. } => {
                AuthorityOperationKind::ChangeReplicaSet
            }
            crate::agent_sdk::ManagementRequest::InspectActors { .. }
            | crate::agent_sdk::ManagementRequest::InspectResources
            | crate::agent_sdk::ManagementRequest::InspectManagementHistory
            | crate::agent_sdk::ManagementRequest::PrivateControl { .. } => {
                return Err(ManagementError::InvalidRequest);
            }
        };
        let expected_actor = match request {
            crate::agent_sdk::ManagementRequest::Install(install) => {
                Some((install.entry.actor, install.entry.deployment))
            }
            crate::agent_sdk::ManagementRequest::UpgradeActor(upgrade) => {
                Some((upgrade.actor, upgrade.to_deployment))
            }
            crate::agent_sdk::ManagementRequest::Suspend {
                actor,
                expected_deployment,
            }
            | crate::agent_sdk::ManagementRequest::Resume {
                actor,
                expected_deployment,
            }
            | crate::agent_sdk::ManagementRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => Some((*actor, *expected_deployment)),
            _ => None,
        };
        let selector = &authority.selector;
        let selector_actor = selector.actor.zip(selector.actor_deployment);
        let runtime_is_request_bound = matches!(
            request,
            crate::agent_sdk::ManagementRequest::Create(_)
                | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_)
        );
        if descriptor.identity.space != space
            || descriptor.identity.agent != agent
            || ((!allow_historical_runtime || runtime_is_request_bound)
                && expected_runtime != runtime_deployment)
            || (!allow_historical_runtime
                && !matches!(request, crate::agent_sdk::ManagementRequest::Create(_))
                && descriptor.identity.runtime_deployment != expected_runtime)
            || !descriptor.authority.accepts(authority)
            || authority.validate_shape().is_err()
            || selector.space != space
            || selector.agent != agent
            || selector.runtime_deployment != runtime_deployment
            || selector.operation != expected_operation
            || selector_actor != expected_actor
            || selector.request != request.commitment()
            || !super::authority::verify_raw_ed25519(
                &authority.public_key,
                &authority.signing_bytes(),
                &authority.signature,
            )
        {
            return Err(ManagementError::InvalidRequest);
        }
        Ok(())
    }

    fn clean_management_mutation(
        &mut self,
        request: &crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::Hash,
        observed_slot: u64,
        pristine_input: bool,
    ) -> Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::{ManagementError, ManagementReply, ManagementRequest};

        match request {
            ManagementRequest::Create(descriptor) => {
                if self.config.is_some() {
                    return Err(ManagementError::AlreadyCreated);
                }
                if !pristine_input {
                    return Err(ManagementError::InvalidRequest);
                }
                let intrinsic = crate::agent_sdk::RuntimeCapabilities::standard();
                if descriptor.validate().is_err()
                    || descriptor.capabilities.max_actors > intrinsic.max_actors
                    || descriptor.capabilities.lanes.bits() & !intrinsic.lanes.bits() != 0
                    || (descriptor.capabilities.scheduling && !intrinsic.scheduling)
                {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                // Proof systems are implemented by the outer proof host, not
                // by the deterministic Standard guest. Their exact bounded
                // set remains authenticated by the pinned runtime package
                // descriptor and is enforced again for every attested slice.
                let config = clean_descriptor_to_legacy_config(descriptor)
                    .map_err(legacy_management_error)?;
                validate_artifact_resources(
                    config.runtime_contract.resources,
                    core::iter::once(&config.runtime_package),
                )
                .map_err(legacy_management_error)?;
                // The exact SDK descriptor is the validation and identity
                // authority here. `AgentConfig` remains private transitional
                // state and uses a historical AgentId hash domain.
                self.config = Some(config);
                self.clean_creation_descriptor = Some((**descriptor).clone());
                self.clean_descriptor = Some((**descriptor).clone());
                self.active_resource_policy = Some(descriptor.initial_resource_policy());
                Ok(ManagementReply::Created(descriptor.identity.clone()))
            }
            ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory => Err(ManagementError::InvalidRequest),
            ManagementRequest::Install(install) => {
                let descriptor = self
                    .clean_descriptor
                    .as_ref()
                    .ok_or(ManagementError::NotCreated)?;
                install
                    .validate_for_profile(descriptor.identity.profile)
                    .map_err(|error| match error {
                        crate::agent_sdk::ModelError::InvalidProfile => {
                            ManagementError::UnsupportedLane
                        }
                        _ => ManagementError::InvalidRequest,
                    })?;
                let actor = crate::service::ActorId(install.entry.actor.0);
                let exact_package = StandardCleanActorPackage {
                    actor: install.entry.actor,
                    contract: install.contract,
                    requirements: install.requirements,
                };
                let exact_installation = clean_installation_binding(install);
                let existing = self
                    .actors
                    .values()
                    .find(|managed| managed.record.installation_id.0 == install.installation_id.0);
                let generation = derive_state_generation(
                    Hash(authority.0),
                    observed_slot,
                    Hash(request.commitment().0),
                    actor,
                );
                if let Some(existing) = existing {
                    if existing.clean_installation.as_ref() != Some(&exact_installation) {
                        return Err(ManagementError::InvalidRequest);
                    }
                    return match self.install(clean_install_to_legacy(install), generation) {
                        Ok(LifecycleReply::Installed(entry)) => {
                            Ok(ManagementReply::Installed(legacy_entry_to_clean(&entry)))
                        }
                        Ok(_) => Err(ManagementError::InvalidRequest),
                        Err(error) => Err(legacy_management_error(error)),
                    };
                }
                if !descriptor.runtime_contract.supports(install.contract)
                    || !descriptor.capabilities.satisfies(install.requirements)
                {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                match self.install(clean_install_to_legacy(install), generation) {
                    Ok(LifecycleReply::Installed(entry)) => {
                        let managed = self
                            .actors
                            .get_mut(&actor)
                            .ok_or(ManagementError::InvalidRequest)?;
                        managed.clean_package = Some(exact_package);
                        managed.clean_installation = Some(exact_installation);
                        Ok(ManagementReply::Installed(legacy_entry_to_clean(&entry)))
                    }
                    Ok(_) => Err(ManagementError::InvalidRequest),
                    Err(error) => Err(legacy_management_error(error)),
                }
            }
            ManagementRequest::UpgradeActor(upgrade) => {
                let descriptor = self
                    .clean_descriptor
                    .as_ref()
                    .ok_or(ManagementError::NotCreated)?;
                if !upgrade
                    .requirements
                    .supported_by(descriptor.identity.profile)
                {
                    return Err(ManagementError::UnsupportedLane);
                }
                if !descriptor.runtime_contract.supports(upgrade.contract)
                    || !descriptor.capabilities.satisfies(upgrade.requirements)
                {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                match self.upgrade_actor(clean_upgrade_to_legacy(upgrade)) {
                    Ok(LifecycleReply::Upgraded(entry)) => {
                        self.actors
                            .get_mut(&crate::service::ActorId(upgrade.actor.0))
                            .expect("successfully upgraded actor remains installed")
                            .clean_package = Some(StandardCleanActorPackage {
                            actor: upgrade.actor,
                            contract: upgrade.contract,
                            requirements: upgrade.requirements,
                        });
                        Ok(ManagementReply::Upgraded(legacy_entry_to_clean(&entry)))
                    }
                    Ok(_) => Err(ManagementError::InvalidRequest),
                    Err(error) => Err(legacy_management_error(error)),
                }
            }
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            } => match self.set_suspended(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
                true,
            ) {
                Ok(LifecycleReply::Suspended(entry)) => {
                    Ok(ManagementReply::Suspended(legacy_entry_to_clean(&entry)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
            ManagementRequest::Resume {
                actor,
                expected_deployment,
            } => match self.set_suspended(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
                false,
            ) {
                Ok(LifecycleReply::Resumed(entry)) => {
                    Ok(ManagementReply::Resumed(legacy_entry_to_clean(&entry)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
            ManagementRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => match self.remove_leaf(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
            ) {
                Ok(LifecycleReply::Removed(actor)) => {
                    Ok(ManagementReply::Removed(crate::agent_sdk::ActorId(actor.0)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
            ManagementRequest::UpgradeRuntime(upgrade) => {
                if !self.actors.values().all(|actor| {
                    actor.clean_package.as_ref().is_some_and(|package| {
                        upgrade.contract.supports(package.contract)
                            && upgrade.capabilities.satisfies(package.requirements)
                    })
                }) {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                if self.active_resource_policy.is_none_or(|policy| {
                    !policy.is_within(upgrade.capabilities, upgrade.contract.resources)
                }) {
                    return Err(ManagementError::ResourceLimit);
                }
                let legacy_capabilities = clean_capabilities_to_legacy(
                    upgrade.capabilities,
                    self.clean_descriptor
                        .as_ref()
                        .ok_or(ManagementError::NotCreated)?
                        .identity
                        .profile,
                );
                self.upgrade_runtime(
                    crate::service::DeploymentId(upgrade.from_deployment.0),
                    crate::service::DeploymentId(upgrade.to_deployment.0),
                    crate::service::ProgramId(upgrade.to_program.0),
                    crate::service::ProducerId(upgrade.producer.0),
                    clean_blob_to_legacy(&upgrade.package),
                    clean_runtime_contract_to_legacy(upgrade.contract),
                    legacy_capabilities,
                    true,
                )
                .map_err(legacy_management_error)?;
                let current = self
                    .clean_descriptor
                    .as_mut()
                    .ok_or(ManagementError::NotCreated)?;
                current.identity.runtime_deployment = upgrade.to_deployment;
                current.identity.runtime_program = upgrade.to_program;
                current.identity.runtime_producer = upgrade.producer;
                current.runtime_package = upgrade.package.clone();
                current.runtime_contract = upgrade.contract;
                current.capabilities = upgrade.capabilities;
                Ok(ManagementReply::RuntimeUpgraded(current.identity.clone()))
            }
            ManagementRequest::ChangeReplicas {
                expected_generation,
                replicas,
            } => {
                let current = self
                    .clean_descriptor
                    .as_ref()
                    .ok_or(ManagementError::NotCreated)?;
                if current.replica_generation() != *expected_generation {
                    return Err(ManagementError::StaleDeployment);
                }
                let mut next = current.clone();
                next.replicas = replicas.clone();
                next.validate()
                    .map_err(|_| ManagementError::InvalidRequest)?;
                let generation = next.replica_generation();
                let projected =
                    clean_descriptor_to_legacy_config(&next).map_err(legacy_management_error)?;
                self.config = Some(projected);
                self.clean_descriptor = Some(next);
                Ok(ManagementReply::ReplicasChanged { generation })
            }
            ManagementRequest::PrivateControl { .. } => Err(ManagementError::InvalidRequest),
        }
    }

    fn verify_private_management_authority(
        &self,
        space: crate::agent_sdk::SpaceId,
        agent: crate::agent_sdk::AgentId,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        request: &crate::agent_sdk::ManagementRequest,
        authority: &crate::agent_sdk::authority::AuthorityReceipt,
        allow_historical_runtime: bool,
    ) -> Result<(), crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::{AgentProfile, ManagementError, ManagementRequest};

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(ManagementError::NotCreated)?;
        let ManagementRequest::PrivateControl { control, .. } = request else {
            return Err(ManagementError::InvalidRequest);
        };
        let selector = &authority.selector;
        if descriptor.identity.profile != AgentProfile::Private
            || !request.is_valid()
            || control.space != space
            || control.agent != agent
            || descriptor.identity.space != space
            || descriptor.identity.agent != agent
            || (!allow_historical_runtime
                && descriptor.identity.runtime_deployment != runtime_deployment)
            || !descriptor.authority.accepts(authority)
            || authority.validate_shape().is_err()
            || selector.space != space
            || selector.agent != agent
            || selector.runtime_deployment != runtime_deployment
            || Some(selector.operation) != request.authority_operation()
            || (selector.actor, selector.actor_deployment) != request.authority_actor_selector()
            || selector.request != request.commitment()
            || !super::authority::verify_raw_ed25519(
                &authority.public_key,
                &authority.signing_bytes(),
                &authority.signature,
            )
        {
            return Err(ManagementError::InvalidRequest);
        }
        Ok(())
    }

    fn private_management_mutation(
        &mut self,
        mutation: &crate::agent_sdk::PrivateRuntimeMutation,
        control: crate::agent_sdk::Hash,
        request: crate::agent_sdk::Hash,
        observed_slot: u64,
    ) -> Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::{ManagementError, ManagementReply, PrivateRuntimeMutation};

        let descriptor = self
            .clean_descriptor
            .as_ref()
            .ok_or(ManagementError::NotCreated)?
            .clone();
        match mutation {
            PrivateRuntimeMutation::SetResourcePolicy(policy) => {
                if !policy.is_within(
                    descriptor.capabilities,
                    descriptor.runtime_contract.resources,
                ) || !self
                    .clean_resource_usage()
                    .is_ok_and(|usage| policy.admits_usage(usage))
                {
                    return Err(ManagementError::ResourceLimit);
                }
                self.active_resource_policy = Some(*policy);
                Ok(ManagementReply::ResourcePolicySet(*policy))
            }
            PrivateRuntimeMutation::Install(install) => {
                install
                    .validate_for_profile(crate::agent_sdk::AgentProfile::Private)
                    .map_err(|error| match error {
                        crate::agent_sdk::ModelError::InvalidProfile => {
                            ManagementError::UnsupportedLane
                        }
                        _ => ManagementError::InvalidRequest,
                    })?;
                let actor = crate::service::ActorId(install.entry.actor.0);
                let exact_package = StandardCleanActorPackage {
                    actor: install.entry.actor,
                    contract: install.contract,
                    requirements: install.requirements,
                };
                let exact_installation = clean_installation_binding(install);
                let existing = self
                    .actors
                    .values()
                    .find(|managed| managed.record.installation_id.0 == install.installation_id.0);
                let generation =
                    derive_state_generation(Hash(control.0), observed_slot, Hash(request.0), actor);
                if let Some(existing) = existing {
                    if existing.clean_installation.as_ref() != Some(&exact_installation) {
                        return Err(ManagementError::InvalidRequest);
                    }
                    return match self.install(clean_install_to_legacy(install), generation) {
                        Ok(LifecycleReply::Installed(entry)) => {
                            Ok(ManagementReply::Installed(legacy_entry_to_clean(&entry)))
                        }
                        Ok(_) => Err(ManagementError::InvalidRequest),
                        Err(error) => Err(legacy_management_error(error)),
                    };
                }
                if !descriptor.runtime_contract.supports(install.contract)
                    || !descriptor.capabilities.satisfies(install.requirements)
                {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                match self.install(clean_install_to_legacy(install), generation) {
                    Ok(LifecycleReply::Installed(entry)) => {
                        let managed = self
                            .actors
                            .get_mut(&actor)
                            .ok_or(ManagementError::InvalidRequest)?;
                        managed.clean_package = Some(exact_package);
                        managed.clean_installation = Some(exact_installation);
                        Ok(ManagementReply::Installed(legacy_entry_to_clean(&entry)))
                    }
                    Ok(_) => Err(ManagementError::InvalidRequest),
                    Err(error) => Err(legacy_management_error(error)),
                }
            }
            PrivateRuntimeMutation::UpgradeActor(upgrade) => {
                if !upgrade
                    .requirements
                    .supported_by(crate::agent_sdk::AgentProfile::Private)
                {
                    return Err(ManagementError::UnsupportedLane);
                }
                if !descriptor.runtime_contract.supports(upgrade.contract)
                    || !descriptor.capabilities.satisfies(upgrade.requirements)
                {
                    return Err(ManagementError::UnsupportedRuntime);
                }
                match self.upgrade_actor(clean_upgrade_to_legacy(upgrade)) {
                    Ok(LifecycleReply::Upgraded(entry)) => {
                        self.actors
                            .get_mut(&crate::service::ActorId(upgrade.actor.0))
                            .expect("successfully upgraded actor remains installed")
                            .clean_package = Some(StandardCleanActorPackage {
                            actor: upgrade.actor,
                            contract: upgrade.contract,
                            requirements: upgrade.requirements,
                        });
                        Ok(ManagementReply::Upgraded(legacy_entry_to_clean(&entry)))
                    }
                    Ok(_) => Err(ManagementError::InvalidRequest),
                    Err(error) => Err(legacy_management_error(error)),
                }
            }
            PrivateRuntimeMutation::Suspend {
                actor,
                expected_deployment,
            } => match self.set_suspended(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
                true,
            ) {
                Ok(LifecycleReply::Suspended(entry)) => {
                    Ok(ManagementReply::Suspended(legacy_entry_to_clean(&entry)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
            PrivateRuntimeMutation::Resume {
                actor,
                expected_deployment,
            } => match self.set_suspended(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
                false,
            ) {
                Ok(LifecycleReply::Resumed(entry)) => {
                    Ok(ManagementReply::Resumed(legacy_entry_to_clean(&entry)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
            PrivateRuntimeMutation::RemoveLeaf {
                actor,
                expected_deployment,
            } => match self.remove_leaf(
                crate::service::ActorId(actor.0),
                crate::service::DeploymentId(expected_deployment.0),
            ) {
                Ok(LifecycleReply::Removed(actor)) => {
                    Ok(ManagementReply::Removed(crate::agent_sdk::ActorId(actor.0)))
                }
                Ok(_) => Err(ManagementError::InvalidRequest),
                Err(error) => Err(legacy_management_error(error)),
            },
        }
    }

    fn apply_private_management(
        &mut self,
        space: crate::agent_sdk::SpaceId,
        agent: crate::agent_sdk::AgentId,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: Option<crate::agent_sdk::authority::AuthorityReceipt>,
        observed_slot: u64,
    ) -> Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::{ManagementError, ManagementRequest};

        let authority = authority.ok_or(ManagementError::InvalidRequest)?;
        self.verify_private_management_authority(
            space,
            agent,
            runtime_deployment,
            &request,
            &authority,
            true,
        )?;
        let ManagementRequest::PrivateControl { control, mutation } = &request else {
            return Err(ManagementError::InvalidRequest);
        };
        let authority_id = authority.commitment();
        let control_id = control.commitment();
        let request_id = request.replay_commitment();
        if let Some(disposition) = self
            .private_management_dispositions
            .iter()
            .find(|item| item.authority == authority_id || item.control == control_id)
        {
            if disposition.authority != authority_id
                || disposition.control != control_id
                || disposition.request != request_id
                || disposition.sequence != control.sequence
                || disposition.previous != control.previous
                || disposition.epoch != authority.selector.epoch
                || !disposition
                    .result
                    .as_ref()
                    .is_ok_and(|reply| request.private_runtime_reply_matches(reply))
            {
                return Err(ManagementError::AuthoritySequenceConflict);
            }
            if observed_slot < disposition.observed_slot {
                return Err(ManagementError::AuthoritySlotRegressed);
            }
            return disposition.result.clone();
        }

        self.verify_private_management_authority(
            space,
            agent,
            runtime_deployment,
            &request,
            &authority,
            false,
        )?;
        if !authority.selector.is_live_at(observed_slot) {
            return Err(ManagementError::InvalidRequest);
        }
        if self
            .private_runtime_control_sequence
            .is_some_and(|sequence| control.sequence <= sequence)
        {
            return Err(ManagementError::AuthoritySequenceRegressed);
        }
        if self
            .private_runtime_control_sequence
            .is_some_and(|sequence| {
                sequence.checked_add(1) == Some(control.sequence)
                    && control.previous != self.private_runtime_control_commitment
            })
        {
            return Err(ManagementError::AuthoritySequenceConflict);
        }
        if self
            .private_authority_epoch_high_water
            .is_some_and(|epoch| authority.selector.epoch < epoch)
        {
            return Err(ManagementError::AuthoritySequenceRegressed);
        }
        if self
            .logical_slot_high_water()
            .is_some_and(|slot| observed_slot < slot)
        {
            return Err(ManagementError::AuthoritySlotRegressed);
        }

        let before = self.clone();
        let mut candidate = before.clone();
        let result =
            candidate.private_management_mutation(mutation, control_id, request_id, observed_slot);
        let Ok(reply) = result else {
            return result;
        };
        candidate.private_runtime_control_commitment = Some(control_id);
        candidate.private_runtime_control_sequence = Some(control.sequence);
        candidate.private_authority_epoch_high_water = Some(authority.selector.epoch);
        candidate.private_control_slot_high_water = Some(observed_slot);
        if candidate.private_management_dispositions.len() == MAX_AUTHORITY_DISPOSITIONS {
            let incoming_sets_policy = matches!(
                &reply,
                crate::agent_sdk::ManagementReply::ResourcePolicySet(_)
            );
            let retained_policy = if incoming_sets_policy {
                None
            } else {
                candidate
                    .private_management_dispositions
                    .iter()
                    .rposition(|item| {
                        matches!(
                            &item.result,
                            Ok(crate::agent_sdk::ManagementReply::ResourcePolicySet(_))
                        )
                    })
            };
            let remove_index = usize::from(retained_policy == Some(0));
            candidate
                .private_management_dispositions
                .remove(remove_index);
        }
        candidate
            .private_management_dispositions
            .push(StandardPrivateManagementDisposition {
                authority: authority_id,
                control: control_id,
                request: request_id,
                sequence: control.sequence,
                previous: control.previous,
                epoch: authority.selector.epoch,
                observed_slot,
                result: Ok(reply.clone()),
            });
        if candidate.validate_signed_state_resource().is_err() {
            return Err(ManagementError::ResourceLimit);
        }
        *self = candidate;
        Ok(reply)
    }

    /// Apply one clean-generation management operation. Authentication is
    /// repeated inside the guest; host-side RuntimeWork validation is never a
    /// trust decision.
    pub(crate) fn apply_clean_management(
        &mut self,
        space: crate::agent_sdk::SpaceId,
        agent: crate::agent_sdk::AgentId,
        runtime_deployment: crate::agent_sdk::DeploymentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: Option<crate::agent_sdk::authority::AuthorityReceipt>,
        observed_slot: u64,
        pristine_input: bool,
    ) -> Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        use crate::agent_sdk::{ManagementError, ManagementReply, ManagementRequest};

        if matches!(request, ManagementRequest::PrivateControl { .. }) {
            return self.apply_private_management(
                space,
                agent,
                runtime_deployment,
                request,
                authority,
                observed_slot,
            );
        }

        if matches!(
            request,
            ManagementRequest::InspectActors { .. }
                | ManagementRequest::InspectResources
                | ManagementRequest::InspectManagementHistory
        ) {
            if authority.is_some() {
                return Err(ManagementError::InvalidRequest);
            }
            let descriptor = self
                .clean_descriptor
                .as_ref()
                .ok_or(ManagementError::NotCreated)?;
            if descriptor.identity.space != space
                || descriptor.identity.agent != agent
                || descriptor.identity.runtime_deployment != runtime_deployment
            {
                return Err(ManagementError::InvalidRequest);
            }
            return match request {
                ManagementRequest::InspectActors { after, limit } => {
                    let reply = self
                        .directory_page(after.map(|value| crate::service::ActorId(value.0)), limit)
                        .map_err(legacy_management_error)?;
                    let LifecycleReply::Directory(page) = reply else {
                        return Err(ManagementError::InvalidRequest);
                    };
                    let page = crate::agent_sdk::ActorDirectoryPage {
                        entries: page
                            .entries
                            .into_iter()
                            .map(|record| {
                                self.clean_actor_record(crate::agent_sdk::ActorId(
                                    record.entry.actor.0,
                                ))
                                .ok_or(ManagementError::InvalidRequest)
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        next: page.next.map(|value| crate::agent_sdk::ActorId(value.0)),
                    };
                    page.validate()
                        .map_err(|_| ManagementError::InvalidRequest)?;
                    Ok(ManagementReply::Actors(page))
                }
                ManagementRequest::InspectResources => {
                    self.clean_resource_usage().map(ManagementReply::Resources)
                }
                ManagementRequest::InspectManagementHistory => {
                    use crate::agent_sdk::recovery::{
                        ManagementHistoryEntry, management_history_commitment,
                    };
                    management_history_commitment(
                        self.clean_acknowledged_through,
                        self.clean_management_dispositions.iter().map(|record| {
                            ManagementHistoryEntry {
                                authority: record.authority,
                                request: record.request,
                                epoch: record.epoch,
                                sequence: record.sequence,
                                observed_slot: record.observed_slot,
                                result: &record.result,
                            }
                        }),
                    )
                    .map(ManagementReply::ManagementHistory)
                    .map_err(|_| ManagementError::InvalidRequest)
                }
                _ => unreachable!("read-only branch selected above"),
            };
        }

        let authority = authority.ok_or(ManagementError::InvalidRequest)?;
        // Authenticate immutable trust, the exact typed request, and the
        // receipt-selected runtime before consulting durable history. A
        // retained receipt may name the runtime deployment under which it was
        // originally consumed, so current-runtime validation belongs only on
        // the unseen path below.
        self.verify_clean_management_authority(
            space,
            agent,
            runtime_deployment,
            &request,
            &authority,
            true,
        )?;
        let authority_id = authority.commitment();
        let request_id = request.replay_commitment();
        if let Some(disposition) = self
            .clean_management_dispositions
            .iter()
            .find(|item| item.authority == authority_id)
        {
            if disposition.request != request_id
                || disposition.epoch != authority.selector.epoch
                || disposition.sequence != authority.selector.decision_sequence
            {
                return Err(ManagementError::AuthoritySequenceConflict);
            }
            return disposition.result.clone();
        }

        // A second, differently signed decision cannot reuse a retained
        // binding-global sequence. A decision at or below the durable high
        // water but absent from the retained journal is either acknowledged
        // or an already-skipped sequence; neither can become unseen work.
        if self
            .clean_management_dispositions
            .iter()
            .any(|item| item.sequence == authority.selector.decision_sequence)
        {
            return Err(ManagementError::AuthoritySequenceConflict);
        }
        let prior_decision_high_water = self.clean_decision_sequence_high_water.unwrap_or(0);
        if authority.selector.decision_sequence <= prior_decision_high_water {
            return Err(ManagementError::AuthoritySequenceRegressed);
        }
        if authority.selector.acknowledged_through < self.clean_acknowledged_through {
            return Err(ManagementError::AuthoritySequenceRegressed);
        }
        if authority.selector.acknowledged_through > prior_decision_high_water {
            return Err(ManagementError::AuthoritySequenceConflict);
        }
        self.verify_clean_management_authority(
            space,
            agent,
            runtime_deployment,
            &request,
            &authority,
            false,
        )?;
        let expired_install = observed_slot > authority.selector.expires_at
            && matches!(request, ManagementRequest::Install(_))
            && self.clean_descriptor.as_ref().is_some_and(|descriptor| {
                matches!(
                    descriptor.identity.profile,
                    crate::agent_sdk::AgentProfile::Local | crate::agent_sdk::AgentProfile::Shared
                )
            });
        if !authority.selector.is_live_at(observed_slot) && !expired_install {
            return Err(ManagementError::InvalidRequest);
        }
        if self
            .clean_authority_epoch_high_water
            .is_some_and(|high_water| authority.selector.epoch < high_water)
        {
            return Err(ManagementError::AuthoritySequenceRegressed);
        }
        if let Some(high_water) = self.logical_slot_high_water() {
            if observed_slot < high_water {
                return Err(ManagementError::AuthoritySlotRegressed);
            }
            if observed_slot == high_water {
                return Err(ManagementError::AuthoritySequenceConflict);
            }
        }

        let before = self.clone();
        let mut compacted = before.clone();
        compacted
            .clean_management_dispositions
            .retain(|item| item.sequence > authority.selector.acknowledged_through);
        compacted.clean_acknowledged_through = authority.selector.acknowledged_through;

        // Refuse an unacknowledged full journal without consuming authority.
        // An advancing acknowledgement only creates headroom when it actually
        // retires at least one retained result.
        if compacted.clean_management_dispositions.len() == MAX_AUTHORITY_DISPOSITIONS {
            return Err(ManagementError::ResourceLimit);
        }

        // Reserve enough signed-state headroom for the smallest durable
        // disposition before applying any established-Agent mutation. If
        // even the fixed ResourceLimit record cannot fit, this receipt is an
        // unconsumed admission failure and state remains byte-identical.
        let reserved_limit = if before.config.is_some() {
            let mut fallback = compacted.clone();
            fallback.clean_authority_epoch_high_water = Some(authority.selector.epoch);
            fallback.clean_decision_sequence_high_water =
                Some(authority.selector.decision_sequence);
            fallback.authority_slot_high_water = Some(observed_slot);
            fallback
                .clean_management_dispositions
                .push(StandardCleanManagementDisposition {
                    authority: authority_id,
                    request: request_id,
                    epoch: authority.selector.epoch,
                    sequence: authority.selector.decision_sequence,
                    observed_slot,
                    result: Err(ManagementError::ResourceLimit),
                });
            if fallback.validate_signed_state_resource().is_err() {
                return Err(ManagementError::ResourceLimit);
            }
            Some(fallback)
        } else {
            None
        };

        *self = compacted.clone();
        let result = if expired_install {
            // Only the authenticated management disposition advances. No
            // artifact, constructor, directory or actor state may be touched.
            Err(ManagementError::ExpiredBeforeApplication)
        } else {
            self.clean_management_mutation(&request, authority_id, observed_slot, pristine_input)
        };
        if result.is_err() {
            *self = compacted;
        }
        if before.config.is_none() && result.is_err() {
            *self = before;
            return result;
        }
        self.clean_authority_epoch_high_water = Some(authority.selector.epoch);
        self.clean_decision_sequence_high_water = Some(authority.selector.decision_sequence);
        self.authority_slot_high_water = Some(observed_slot);
        self.clean_management_dispositions
            .push(StandardCleanManagementDisposition {
                authority: authority_id,
                request: request_id,
                epoch: authority.selector.epoch,
                sequence: authority.selector.decision_sequence,
                observed_slot,
                result: result.clone(),
            });
        if self.validate_signed_state_resource().is_ok() {
            return result;
        }

        *self = reserved_limit.unwrap_or(before);
        Err(ManagementError::ResourceLimit)
    }

    fn apply_authorized(
        &mut self,
        admission: super::LifecycleAuthorityAdmission,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        let authority = match (&request, self.config.as_ref()) {
            (LifecycleRequest::Create(config), None) => &config.authority,
            (LifecycleRequest::Create(_), Some(config)) => &config.authority,
            (_, _) => &self.created()?.authority,
        };
        let claim = &admission.receipt.claim;
        let required_capability = request
            .required_capability()
            .ok_or(LifecycleError::InvalidRequest)?;
        let (space, agent) = match (&request, self.config.as_ref()) {
            (LifecycleRequest::Create(config), _) => (config.identity.space, config.identity.agent),
            (_, Some(config)) => (config.identity.space, config.identity.agent),
            (_, None) => return Err(LifecycleError::NotCreated),
        };
        if admission.receipt.verify_guest_signature(authority).is_err()
            || claim.space != space
            || claim.agent != agent
            || matches!(
                &request,
                LifecycleRequest::Create(config)
                    if claim.principal != config.identity.owner
            )
            || claim.capability != crate::service::CapabilityId::named(required_capability)
            || claim.operation != request.commitment()
            || matches!(
                request,
                LifecycleRequest::Inspect { .. }
                    | LifecycleRequest::AcknowledgeInvocation { .. }
                    | LifecycleRequest::Authorized { .. }
            )
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if matches!(
            &request,
            LifecycleRequest::Create(config)
                if config
                    .system_authority_genesis
                    .as_ref()
                    .is_some_and(|genesis| genesis.initial_sequence() != claim.sequence)
        ) {
            return Err(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidGenesis,
            ));
        }

        let claim_hash = claim.signing_message();

        if let Some(disposition) = self
            .authority_dispositions
            .iter()
            .find(|disposition| disposition.sequence == claim.sequence)
        {
            if disposition.credential != claim.credential
                || disposition.claim != claim_hash
                || disposition.operation != claim.operation
            {
                return Err(LifecycleError::AuthoritySequenceConflict);
            }
            self.authority_slot_high_water = Some(
                self.authority_slot_high_water
                    .map_or(admission.observed_slot, |current| {
                        current.max(admission.observed_slot)
                    }),
            );
            return disposition.result.clone();
        }

        if self
            .authority_sequence_high_water
            .is_some_and(|high_water| claim.sequence <= high_water)
        {
            return Err(LifecycleError::AuthoritySequenceRegressed);
        }
        if admission.observed_slot < claim.valid_from || admission.observed_slot > claim.valid_until
        {
            return Err(LifecycleError::InvalidRequest);
        }
        if self
            .logical_slot_high_water()
            .is_some_and(|high_water| admission.observed_slot < high_water)
        {
            return Err(LifecycleError::AuthoritySlotRegressed);
        }

        // Lifecycle implementations promise atomic rejection. Preserve that
        // property defensively while still consuming the signed sequence and
        // recording its exact deterministic refusal.
        let install_generation = match &request {
            LifecycleRequest::Install(install) => Some(derive_state_generation(
                claim_hash,
                claim.sequence,
                claim.operation,
                install.entry.actor,
            )),
            _ => None,
        };
        let before = self.clone();
        let result = match (request, install_generation) {
            (LifecycleRequest::Install(install), Some(generation)) => {
                self.install(install, generation)
            }
            (LifecycleRequest::Install(_), None) => Err(LifecycleError::InvalidRequest),
            (request, None) => self.apply_mutation(request),
            (_, Some(_)) => unreachable!("only install requests derive an actor generation"),
        };
        if result.is_err() {
            *self = before.clone();
        }

        // Before Create there is no canonical Agent state in which to retain
        // a disposition. Preserve the semantic refusal verbatim; only a
        // successful Create whose exact Created disposition exceeds its own
        // signed ceiling is translated to `ResourceLimit` below.
        if before.config.is_none() && result.is_err() {
            *self = before;
            return result;
        }

        // The signed state ceiling owns the exact final image for every
        // authorized outcome, including authority high-water and the retained
        // disposition itself. Successful Create/UpgradeRuntime naturally use
        // the newly installed contract here; every other transition uses the
        // current contract.
        let mut prospective = self.clone();
        prospective.record_authority_disposition(
            claim.credential,
            claim.sequence,
            claim_hash,
            claim.operation,
            admission.observed_slot,
            &result,
        );
        if prospective.validate_signed_state_resource().is_ok() {
            *self = prospective;
            return result;
        }

        // Roll back application semantics and retain a deterministic capacity
        // refusal under the pre-transition contract. An established Agent has
        // at least its Create disposition available as bounded eviction
        // headroom. `ResourceLimit` is smaller than every successful reply and
        // no larger than a fixed lifecycle error, so replacing the oldest
        // entry cannot grow a previously valid image.
        let limited = Err(LifecycleError::ResourceLimit);
        let mut fallback = before.clone();
        if fallback.config.is_none() {
            *self = before;
            return limited;
        }
        if !fallback.authority_dispositions.is_empty() {
            fallback.authority_dispositions.remove(0);
        }
        fallback.record_authority_disposition(
            claim.credential,
            claim.sequence,
            claim_hash,
            claim.operation,
            admission.observed_slot,
            &limited,
        );
        if fallback.validate_signed_state_resource().is_ok() {
            *self = fallback;
        } else {
            // A non-production state created without an authorized Create can
            // have no eviction headroom. Fail closed without making that
            // malformed baseline larger.
            *self = before;
        }
        limited
    }

    fn live_system_authority(
        &self,
    ) -> Result<&super::system_authority::SystemAuthorityState, LifecycleError> {
        let config = self.created()?;
        let genesis =
            config
                .system_authority_genesis
                .as_ref()
                .ok_or(LifecycleError::SystemAuthority(
                    super::system_authority::SystemAuthorityError::WrongSystemAgent,
                ))?;
        let state = self
            .system_authority
            .as_ref()
            .ok_or(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidState,
            ))?;
        state
            .validate_against_genesis(config.identity.agent, genesis)
            .map_err(LifecycleError::SystemAuthority)?;
        Ok(state)
    }

    /// Apply a management input whose raw journal context has independently
    /// been authenticated by replay. The opaque scope is the capability; the
    /// wire context is exact-compared to it before any transition or write
    /// plan can be produced.
    pub(crate) fn apply_scoped(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        request: LifecycleRequest,
    ) -> StandardScopedApply {
        if !context.matches_system_authority_scope(trusted_scope) {
            return StandardScopedApply {
                result: Err(LifecycleError::SystemAuthority(
                    super::system_authority::SystemAuthorityError::InvalidScope,
                )),
                system_authority_write: None,
            };
        }
        match request {
            LifecycleRequest::FinalizeSystemAuthority(finalize) => {
                self.apply_system_authority_finalize(trusted_scope, finalize)
            }
            LifecycleRequest::RotateSystemAuthority(rotation) => {
                self.apply_system_authority_rotation(trusted_scope, rotation)
            }
            LifecycleRequest::FinalizeCatalog(finalize) => {
                self.apply_catalog_finalize(trusted_scope, finalize)
            }
            request => StandardScopedApply {
                result: self.apply(request),
                system_authority_write: None,
            },
        }
    }

    /// Guest/data-only application. Raw context bytes select deterministic
    /// state and reply bytes, but the primitive strips every admitted fact,
    /// committee record, and history plan from this path.
    pub(crate) fn apply_guest(
        &mut self,
        context: Option<super::wire::RuntimeJournalContext>,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        match request {
            LifecycleRequest::FinalizeSystemAuthority(finalize) => match context {
                Some(context) => self.simulate_system_authority_finalize(context, finalize),
                None => self.apply(LifecycleRequest::FinalizeSystemAuthority(finalize)),
            },
            LifecycleRequest::RotateSystemAuthority(rotation) => match context {
                Some(context) => self.simulate_system_authority_rotation(context, rotation),
                None => self.apply(LifecycleRequest::RotateSystemAuthority(rotation)),
            },
            LifecycleRequest::FinalizeCatalog(finalize) => match context {
                Some(context) => self.simulate_catalog_finalize(context, finalize),
                None => self.apply(LifecycleRequest::FinalizeCatalog(finalize)),
            },
            request => self.apply(request),
        }
    }

    fn apply_system_authority_finalize(
        &mut self,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        finalize: super::system_authority::SystemAuthorityFinalize,
    ) -> StandardScopedApply {
        let transition = match self.live_system_authority().and_then(|state| {
            state
                .apply_finalize(trusted_scope, &finalize)
                .map_err(LifecycleError::SystemAuthority)
        }) {
            Ok(transition) => transition,
            Err(error) => {
                return StandardScopedApply {
                    result: Err(error),
                    system_authority_write: None,
                };
            }
        };
        let before = self.system_authority.clone();
        self.system_authority = Some(transition.state().clone());
        let result = Ok(LifecycleReply::SystemAuthorityFinalized(
            transition.outcome(),
        ));
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return StandardScopedApply {
                result: Err(LifecycleError::ResourceLimit),
                system_authority_write: None,
            };
        }
        StandardScopedApply {
            result,
            system_authority_write: Some(StandardSystemAuthorityWrite::Finalize {
                admitted_fact: transition.admitted_fact().cloned(),
                history: transition.history().clone(),
            }),
        }
    }

    fn apply_system_authority_rotation(
        &mut self,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        rotation: super::system_authority::SystemAuthorityRotation,
    ) -> StandardScopedApply {
        let transition = match self.live_system_authority().and_then(|state| {
            state
                .apply_rotation(trusted_scope, &rotation)
                .map_err(LifecycleError::SystemAuthority)
        }) {
            Ok(transition) => transition,
            Err(error) => {
                return StandardScopedApply {
                    result: Err(error),
                    system_authority_write: None,
                };
            }
        };
        let before = self.system_authority.clone();
        self.system_authority = Some(transition.state().clone());
        let result = Ok(LifecycleReply::SystemAuthorityRotated {
            rotation: transition.record().id(),
            epoch: transition.record().new_epoch(),
            exact_retry: transition.exact_retry(),
        });
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return StandardScopedApply {
                result: Err(LifecycleError::ResourceLimit),
                system_authority_write: None,
            };
        }
        StandardScopedApply {
            result,
            system_authority_write: Some(StandardSystemAuthorityWrite::Rotation {
                record: transition.record().clone(),
                history: transition.history().clone(),
            }),
        }
    }

    fn apply_catalog_finalize(
        &mut self,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
        finalize: super::system_authority::SystemAuthorityCatalogFinalize,
    ) -> StandardScopedApply {
        let transition = match self.live_system_authority().and_then(|state| {
            state
                .apply_catalog_finalize(trusted_scope, &finalize)
                .map_err(LifecycleError::SystemAuthority)
        }) {
            Ok(transition) => transition,
            Err(error) => {
                return StandardScopedApply {
                    result: Err(error),
                    system_authority_write: None,
                };
            }
        };
        let before = self.system_authority.clone();
        self.system_authority = Some(transition.state().clone());
        let result = Ok(LifecycleReply::CatalogFinalized(transition.outcome()));
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return StandardScopedApply {
                result: Err(LifecycleError::ResourceLimit),
                system_authority_write: None,
            };
        }
        StandardScopedApply {
            result,
            system_authority_write: Some(StandardSystemAuthorityWrite::Catalog {
                record: transition.record().cloned(),
                history: transition.history().clone(),
            }),
        }
    }

    fn simulate_system_authority_finalize(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        finalize: super::system_authority::SystemAuthorityFinalize,
    ) -> Result<LifecycleReply, LifecycleError> {
        let (state, outcome) = self
            .live_system_authority()?
            .simulate_finalize_untrusted(context.genesis(), context.agent_admission(), &finalize)
            .map_err(LifecycleError::SystemAuthority)?;
        let before = self.system_authority.replace(state);
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return Err(LifecycleError::ResourceLimit);
        }
        Ok(LifecycleReply::SystemAuthorityFinalized(outcome))
    }

    fn simulate_system_authority_rotation(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        rotation: super::system_authority::SystemAuthorityRotation,
    ) -> Result<LifecycleReply, LifecycleError> {
        let (state, rotation, epoch, exact_retry) = self
            .live_system_authority()?
            .simulate_rotation_untrusted(context.genesis(), context.agent_admission(), &rotation)
            .map_err(LifecycleError::SystemAuthority)?;
        let before = self.system_authority.replace(state);
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return Err(LifecycleError::ResourceLimit);
        }
        Ok(LifecycleReply::SystemAuthorityRotated {
            rotation,
            epoch,
            exact_retry,
        })
    }

    fn simulate_catalog_finalize(
        &mut self,
        context: super::wire::RuntimeJournalContext,
        finalize: super::system_authority::SystemAuthorityCatalogFinalize,
    ) -> Result<LifecycleReply, LifecycleError> {
        let (state, outcome) = self
            .live_system_authority()?
            .simulate_catalog_finalize_untrusted(
                context.genesis(),
                context.agent_admission(),
                &finalize,
            )
            .map_err(LifecycleError::SystemAuthority)?;
        let before = self.system_authority.replace(state);
        if self.validate_signed_state_resource().is_err() {
            self.system_authority = before;
            return Err(LifecycleError::ResourceLimit);
        }
        Ok(LifecycleReply::CatalogFinalized(outcome))
    }

    fn apply_mutation(
        &mut self,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        match request {
            LifecycleRequest::Create(config) => {
                if self.config.is_some() {
                    return Err(LifecycleError::AlreadyCreated);
                }
                config.validate().map_err(|error| match error {
                    AgentConfigError::UnsupportedLane => LifecycleError::UnsupportedLane,
                    _ => LifecycleError::InvalidRequest,
                })?;
                let intrinsic = super::RuntimeCapabilities::standard();
                if config.capabilities.max_actors > intrinsic.max_actors
                    || config.capabilities.lanes.bits() & !intrinsic.lanes.bits() != 0
                    || (config.capabilities.scheduling && !intrinsic.scheduling)
                    || (config.capabilities.proofs && !intrinsic.proofs)
                {
                    return Err(LifecycleError::UnsupportedRuntime);
                }
                validate_artifact_resources(
                    config.runtime_contract.resources,
                    core::iter::once(&config.runtime_package),
                )?;
                let identity = config.identity.clone();
                let system_authority = config
                    .system_authority_genesis
                    .as_ref()
                    .map(|genesis| {
                        super::system_authority::SystemAuthorityState::from_genesis(
                            config.identity.agent,
                            genesis,
                        )
                    })
                    .transpose()
                    .map_err(LifecycleError::SystemAuthority)?;
                self.config = Some(config);
                self.system_authority = system_authority;
                Ok(LifecycleReply::Created(identity))
            }
            LifecycleRequest::Install(_) => Err(LifecycleError::InvalidRequest),
            LifecycleRequest::UpgradeActor(upgrade) => self.upgrade_actor(upgrade),
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            } => self.set_suspended(actor, expected_deployment, true),
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            } => self.set_suspended(actor, expected_deployment, false),
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => self.remove_leaf(actor, expected_deployment),
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment,
                to_program,
                producer,
                package,
                contract,
                capabilities,
            } => self.upgrade_runtime(
                from_deployment,
                to_deployment,
                to_program,
                producer,
                package,
                contract,
                capabilities,
                false,
            ),
            LifecycleRequest::Inspect { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
            | LifecycleRequest::Authorized { .. } => Err(LifecycleError::InvalidRequest),
        }
    }
}

impl StandardLaneState {
    fn select(&self, lane: StateLane) -> &[StandardLaneEntry] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    fn select_mut(&mut self, lane: StateLane) -> &mut Vec<StandardLaneEntry> {
        match lane {
            StateLane::Linear => &mut self.linear,
            StateLane::Merge => &mut self.merge,
            StateLane::Local => &mut self.local,
        }
    }

    fn lanes(&self) -> [(StateLane, &[StandardLaneEntry]); 3] {
        [
            (StateLane::Linear, &self.linear),
            (StateLane::Merge, &self.merge),
            (StateLane::Local, &self.local),
        ]
    }

    fn lookup(
        &self,
        lane: StateLane,
        actor: ActorId,
        state_generation: Hash,
    ) -> Option<&StandardLaneEntry> {
        self.select(lane)
            .binary_search_by_key(&(actor, state_generation), |entry| {
                (entry.actor, entry.state_generation)
            })
            .ok()
            .and_then(|index| self.select(lane).get(index))
    }

    #[cfg(feature = "pvm")]
    fn upsert(
        &mut self,
        lane: StateLane,
        actor: ActorId,
        state_generation: Hash,
        value: Vec<u8>,
    ) -> Result<(), super::execution::ActorExecutionError> {
        use super::execution::ActorExecutionError;

        let entries = self.select_mut(lane);
        match entries.binary_search_by_key(&(actor, state_generation), |entry| {
            (entry.actor, entry.state_generation)
        }) {
            Ok(index) if value.is_empty() && entries[index].rows.is_empty() => {
                entries.remove(index);
            }
            Ok(index) => entries[index].value = value,
            Err(_) if value.is_empty() => {}
            Err(index) => {
                if entries.len() >= MAX_LANE_STATE_ENTRIES {
                    return Err(ActorExecutionError::ResultCapacity);
                }
                entries.insert(
                    index,
                    StandardLaneEntry {
                        actor,
                        state_generation,
                        value,
                        rows: BTreeMap::new(),
                    },
                );
            }
        }
        Ok(())
    }

    fn is_canonical(&self) -> bool {
        self.lanes().into_iter().all(|(_, entries)| {
            entries.len() <= MAX_LANE_STATE_ENTRIES
                && entries.iter().all(|entry| {
                    entry.actor != ActorId::ZERO
                        && entry.state_generation != Hash::ZERO
                        && !(entry.value.is_empty() && entry.rows.is_empty())
                        && super::actor_storage::ActorLaneImage::encoded_parts_len(
                            &entry.value,
                            &entry.rows,
                        )
                        .is_some()
                })
                && entries.windows(2).all(|pair| {
                    (pair[0].actor, pair[0].state_generation)
                        < (pair[1].actor, pair[1].state_generation)
                })
        })
    }
}

impl AgentRuntime for StandardAgentRuntime {
    fn capabilities(&self) -> super::RuntimeCapabilities {
        self.config
            .as_ref()
            .map(|config| config.capabilities)
            .unwrap_or_else(super::RuntimeCapabilities::standard)
    }

    fn apply(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, LifecycleError> {
        match request {
            LifecycleRequest::Inspect { after, limit } => self.directory_page(after, limit),
            LifecycleRequest::AcknowledgeInvocation {
                scope,
                invocation,
                request,
                authority,
            } => self.acknowledge_invocation(scope, invocation, request, *authority),
            LifecycleRequest::Authorized { admission, request } => {
                self.apply_authorized(admission, *request)
            }
            LifecycleRequest::Create(_)
            | LifecycleRequest::Install(_)
            | LifecycleRequest::UpgradeActor(_)
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::UpgradeRuntime { .. } => Err(LifecycleError::InvalidRequest),
            LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_) => Err(LifecycleError::SystemAuthority(
                super::system_authority::SystemAuthorityError::InvalidScope,
            )),
        }
    }

    fn lifecycle_debt(&self, actor: ActorId) -> Result<ActorLifecycleDebt, LifecycleError> {
        let managed = self.actors.get(&actor).ok_or(LifecycleError::NotFound)?;
        let mut debt = managed.debt;
        debt.children = u32::try_from(
            self.actors
                .values()
                .filter(|candidate| candidate.record.entry.parent == Some(actor))
                .count(),
        )
        .unwrap_or(u32::MAX);
        debt.lifecycle_operations = debt.lifecycle_operations.saturating_add(
            u32::try_from(
                self.invocation_results
                    .values()
                    .filter(|result| result.reply.actor == actor)
                    .count(),
            )
            .unwrap_or(u32::MAX),
        );
        debt.lifecycle_operations = debt.lifecycle_operations.saturating_add(
            u32::try_from(
                self.clean_invocation_errors
                    .values()
                    .filter(|record| record.binding.accepted.actor.0 == actor.0)
                    .count(),
            )
            .unwrap_or(u32::MAX),
        );
        debt.continuations = debt.continuations.saturating_add(
            u32::try_from(
                self.machine_continuations
                    .iter()
                    .filter(|continuation| continuation.actor == actor)
                    .count(),
            )
            .unwrap_or(u32::MAX),
        );
        Ok(debt)
    }
}

fn quiescent(mut debt: ActorLifecycleDebt) -> bool {
    debt.children = 0;
    debt.is_clear()
}

fn derive_state_generation(claim: Hash, sequence: u64, operation: Hash, actor: ActorId) -> Hash {
    let mut generation = Hash::digest(
        b"vos/agent/actor-state-generation/v1",
        &[&claim.0, &sequence.to_le_bytes(), &operation.0, &actor.0],
    );
    // State generation is an identity sentinel as well as a commitment. Make
    // nonzero structural rather than probabilistic while retaining all digest
    // bits except this dedicated marker bit.
    generation.0[0] |= 0x80;
    generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::authority::{
        AgentAuthorityClaim, AgentAuthorityReceipt, CAPABILITY_AGENT_CREATE_SHARED,
        ED25519_SIGNATURE_BYTES,
    };
    use crate::agent::catalog_finality::{
        CatalogBinding, CatalogMutation, CatalogMutationDisposition, CatalogMutationIntent,
        CatalogMutationKind, CatalogMutationResult, FinalizedCatalogMutationFact,
        FinalizedCatalogMutationReceipt,
    };
    use crate::agent::committee::{
        AuthorityClaimCommitment, AuthorityCommittee, AuthorityCommitteeMember,
        AuthorityMemberRole, AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId,
        RootAnchorConfigCommitment, RootAnchorId,
    };
    use crate::agent::genesis::{
        AgentGenesisClaim, AgentGenesisDecision, AgentGenesisEvidence, AgentGenesisExpectations,
        AgentGenesisLocator, AgentGenesisProposal, AgentReplicaCommittee, AgentReplicaMember,
        derive_replica_raft_slot,
    };
    use crate::agent::journal::{
        AgentJournalGenesisId, ReplayInput, ReplayOperation, RuntimeBinding,
        system_genesis_artifact_closure_commitment,
    };
    use crate::agent::system_authority::{
        SystemAuthorityCatalogFinalize, SystemAuthorityCatalogProof, SystemAuthorityDecisionProof,
        SystemAuthorityFinalize, SystemAuthorityGenesis, SystemAuthorityJournalScope,
        SystemAuthorityRotation, SystemAuthorityRotationCertificate, SystemAuthorityRotationClaim,
        SystemAuthorityRotationProof,
    };
    use crate::agent::{
        AgentIdentity, AgentProfile, AgentReplica, InstallActor, LaneSet,
        LifecycleAuthorityAdmission, ReplicaRole, RuntimeCapabilities, StateLane, UpgradeActor,
    };
    use crate::service::AgentId;
    use crate::service::wire::ServiceWire;
    use crate::service::{
        BlobRef, CapabilityId, CredentialId, Hash, NodeId, OperationId, PrincipalId, ProducerId,
        SpaceId,
    };
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use ed25519_dalek::{Signer as _, SigningKey};

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[cfg(feature = "pvm")]
    fn clean_authority_receipt(
        config: &AgentConfig,
        work: &crate::agent_sdk::InvocationWork,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
            AuthorityReceipt, AuthorityReceiptSelector,
        };

        let public_key = authority_key().verifying_key().to_bytes();
        let binding = &config.authority;
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: crate::agent_sdk::Hash([0x31; 32]),
                issuer: AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId(config.identity.owner.0),
                    actor: crate::agent_sdk::ActorId(binding.actor.0),
                    deployment: crate::agent_sdk::DeploymentId(binding.deployment.0),
                    program: crate::agent_sdk::ProgramId(binding.program.0),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                space: crate::agent_sdk::SpaceId(config.identity.space.0),
                agent: crate::agent_sdk::AgentId(config.identity.agent.0),
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: crate::agent_sdk::DeploymentId(
                    config.identity.runtime_deployment.0,
                ),
                actor: Some(work.actor),
                actor_deployment: Some(work.deployment),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x32; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: 2,
                request: work.commitment(),
            },
            public_key,
            signature: [1; 64],
        };
        receipt.signature = authority_key().sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn config(max_actors: u32) -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x15; 32]);
        let agent = AgentId::derive(space, owner, &creation_nonce.0);
        let authority_public = crate::agent::authority::ed25519_public_key_wire(
            authority_key().verifying_key().to_bytes(),
        );
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([17; 32]),
                transition_producer: ProducerId([18; 32]),
            },
            creation_nonce,
            authority: crate::agent::authority::AgentAuthorityBinding {
                agent: AgentId([18; 32]),
                actor: ActorId([19; 32]),
                deployment: DeploymentId([21; 32]),
                program: ProgramId([22; 32]),
                producer: ProducerId::of_public_key(&authority_public),
                public_key: authority_public,
            },
            system_authority_genesis: None,
            capabilities: RuntimeCapabilities {
                max_actors,
                ..RuntimeCapabilities::standard()
            },
            runtime_package: BlobRef {
                hash: Hash([20; 32]),
                len: 100,
            },
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            replicas: vec![AgentReplica {
                node: NodeId([6; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn private_config(max_actors: u32) -> AgentConfig {
        let mut config = config(max_actors);
        config.identity.profile = AgentProfile::Private;
        config.capabilities.lanes =
            LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        config.replicas[0].role = ReplicaRole::Observer;
        config
    }

    const TEST_PEER_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

    fn committee_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn authority_committee(
        config: &AgentConfig,
        epoch: u64,
        previous: Option<Hash>,
        keys: &[SigningKey],
    ) -> AuthorityCommittee {
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(0x80 + index as u8).wrapping_add(key.to_bytes()[0]); 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            config.identity.space,
            config.authority.commitment(),
            epoch,
            previous,
            members,
        )
        .unwrap()
    }

    fn authority_certificate(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        keys: &[SigningKey],
    ) -> AuthorityQuorumCertificate {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let mut signatures = keys
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        AuthorityQuorumCertificate::new(committee, claim, signatures).unwrap()
    }

    fn system_config() -> (AgentConfig, AuthorityCommittee, Vec<SigningKey>) {
        system_config_with_limits(
            64,
            crate::agent::contract::RuntimeResourceLimits::standard().max_runtime_state_bytes,
        )
    }

    fn system_config_with_limits(
        decision_limit: u32,
        max_runtime_state_bytes: u32,
    ) -> (AgentConfig, AuthorityCommittee, Vec<SigningKey>) {
        let mut config = config(64);
        config.authority.agent = config.identity.agent;
        config.runtime_contract.resources.max_runtime_state_bytes = max_runtime_state_bytes;
        let keys = vec![committee_key(0x51)];
        let committee = authority_committee(&config, 1, None, &keys);
        config.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                RootAnchorId::from_bytes([0x71; 32]),
                1,
                RootAnchorConfigCommitment::from_bytes([0x72; 32]),
                committee.clone(),
                1,
                Hash([0x75; 32]),
                Hash([0x76; 32]),
                decision_limit,
                16,
                64,
            )
            .unwrap(),
        );
        config.validate().unwrap();
        (config, committee, keys)
    }

    fn journal_scope(byte: u8) -> SystemAuthorityJournalScope {
        SystemAuthorityJournalScope::for_test(
            AgentJournalGenesisId::new([byte; 32]),
            crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([byte.wrapping_add(1); 32]),
        )
        .unwrap()
    }

    fn journal_context(
        scope: SystemAuthorityJournalScope,
    ) -> crate::agent::wire::RuntimeJournalContext {
        crate::agent::wire::RuntimeCall::scoped_system_authority(
            crate::agent::wire::RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
            scope,
        )
        .journal_context()
        .unwrap()
    }

    fn replica_member(byte: u8) -> AgentReplicaMember {
        let raw = [byte; 32];
        let mut peer_id = Vec::from(TEST_PEER_PREFIX);
        peer_id.extend_from_slice(&raw);
        AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer_id),
                principal: PrincipalId::of_public_key(&raw),
                role: ReplicaRole::Voter,
            },
            peer_id.clone(),
            raw,
            Some(derive_replica_raft_slot(&peer_id)),
        )
        .unwrap()
    }

    fn finalize_command(
        system: &AgentConfig,
        committee: &AuthorityCommittee,
        keys: &[SigningKey],
        scope: SystemAuthorityJournalScope,
        sequence: u64,
    ) -> SystemAuthorityFinalize {
        let member = replica_member(0x31);
        let owner = PrincipalId([0x12; 32]);
        let nonce = Hash([0x10_u8.wrapping_add(sequence as u8); 32]);
        let agent = AgentId::derive(system.identity.space, owner, nonce.as_bytes());
        let target = AgentConfig {
            identity: AgentIdentity {
                space: system.identity.space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x21; 32]),
                runtime_program: ProgramId([0x22; 32]),
                runtime_producer: ProducerId([0x23; 32]),
                transition_producer: ProducerId([0x24; 32]),
            },
            creation_nonce: nonce,
            authority: system.authority.clone(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"ordinary-standard-runtime"),
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![member.replica()],
        };
        target.validate().unwrap();
        let inner = LifecycleRequest::Create(target.clone());
        let create = ReplayInput {
            runtime: RuntimeBinding {
                space: target.identity.space,
                agent,
                deployment: target.identity.runtime_deployment,
                program: target.identity.runtime_program,
                producer: target.identity.runtime_producer,
                package: target.runtime_package.clone(),
                runtime_abi: super::super::RUNTIME_ABI_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            },
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim: AgentAuthorityClaim {
                                authority: target.authority.clone(),
                                space: target.identity.space,
                                agent,
                                principal: owner,
                                credential: CredentialId([0x24; 32]),
                                capability: CapabilityId::named(CAPABILITY_AGENT_CREATE_SHARED),
                                operation: inner.commitment(),
                                sequence,
                                valid_from: 10,
                                valid_until: 40,
                            },
                            signature: vec![0x25; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 20,
                    },
                    request: Box::new(inner.clone()),
                },
            },
        };
        let catalog = vec![target.runtime_package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            inner.commitment(),
            Hash([0x26; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            sequence,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space: target.identity.space,
                agent,
            },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas = AgentReplicaCommittee::new(
            target.identity.space,
            agent,
            AgentProfile::Shared,
            vec![member],
        )
        .unwrap();
        let claim = AgentGenesisClaim::new(
            system.identity.agent,
            scope.system_genesis(),
            scope.agent_admission(),
            &proposal,
            &replicas,
        )
        .unwrap();
        let evidence = AgentGenesisEvidence::new(
            claim.clone(),
            authority_certificate(committee, claim.authority_claim(), keys),
        )
        .unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        SystemAuthorityFinalize::new(
            decision,
            evidence,
            SystemAuthorityDecisionProof::vacant(agent, vec![]).unwrap(),
        )
        .unwrap()
    }

    fn rotation_command(
        state: &crate::agent::system_authority::SystemAuthorityState,
        scope: SystemAuthorityJournalScope,
        old: &AuthorityCommittee,
        old_keys: &[SigningKey],
        new: &AuthorityCommittee,
        new_keys: &[SigningKey],
    ) -> SystemAuthorityRotation {
        let claim = SystemAuthorityRotationClaim::new(
            state.root_anchor(),
            state.root_anchor_config_version(),
            state.root_anchor_config(),
            scope.commitment(state.root_anchor()).unwrap(),
            old,
            new,
            3,
            4,
        )
        .unwrap();
        let authority_claim = claim.authority_claim();
        let certificate = SystemAuthorityRotationCertificate::new(
            claim,
            authority_certificate(old, authority_claim, old_keys),
            authority_certificate(new, authority_claim, new_keys),
        )
        .unwrap();
        SystemAuthorityRotation::new(
            new.clone(),
            certificate,
            SystemAuthorityRotationProof::vacant(2, vec![]).unwrap(),
        )
        .unwrap()
    }

    fn catalog_command(
        state: &crate::agent::system_authority::SystemAuthorityState,
        committee: &AuthorityCommittee,
        keys: &[SigningKey],
        operation: OperationId,
        sequence: u64,
        mutation_byte: u8,
    ) -> SystemAuthorityCatalogFinalize {
        let binding = CatalogBinding::new(
            state.space(),
            state.catalog_binding(),
            state.authority_binding(),
        )
        .unwrap();
        let intent = CatalogMutationIntent::new(
            binding,
            state.authority_generation(),
            state.catalog_head(),
            PrincipalId([0x81; 32]),
            CredentialId([0x82; 32]),
            CapabilityId([0x83; 32]),
            operation,
            CatalogMutation::new(CatalogMutationKind::UpdateMetadata, vec![mutation_byte; 8])
                .unwrap(),
        )
        .unwrap();
        let result = CatalogMutationResult::new(
            CatalogMutationDisposition::Applied,
            vec![mutation_byte.wrapping_add(1); 8],
        )
        .unwrap();
        let fact = FinalizedCatalogMutationFact::new(
            intent,
            state.authority_generation(),
            state.catalog_head(),
            result,
            sequence,
        )
        .unwrap();
        let receipt = FinalizedCatalogMutationReceipt::new(
            fact.clone(),
            authority_certificate(committee, fact.authority_claim(), keys),
            binding,
            committee,
        )
        .unwrap();
        SystemAuthorityCatalogFinalize::new(
            receipt,
            SystemAuthorityCatalogProof::vacant(operation, vec![]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn system_authority_seed_is_exactly_bound_to_config_and_restore() {
        let (config, _, _) = system_config();

        let mut wrong_sequence = StandardAgentRuntime::new();
        assert_eq!(
            wrong_sequence.apply(authorized_at(
                &config,
                CredentialId([0x44; 32]),
                2,
                1,
                1,
                LifecycleRequest::Create(config.clone()),
            )),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidGenesis
            ))
        );
        assert_eq!(wrong_sequence.snapshot(), StandardRuntimeState::default());

        let mut runtime = StandardAgentRuntime::new();
        assert!(matches!(
            create_authorized(&mut runtime, &config, 1),
            Ok(LifecycleReply::Created(_))
        ));
        let snapshot = runtime.snapshot();
        let seeded = snapshot.system_authority.as_ref().unwrap();
        seeded
            .validate_against_genesis(
                config.identity.agent,
                config.system_authority_genesis.as_ref().unwrap(),
            )
            .unwrap();
        let encoded = crate::agent::wire::encode_standard_runtime_state(&snapshot);
        let decoded = crate::agent::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
        assert_eq!(
            StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
            snapshot
        );

        let mut missing_state = snapshot.clone();
        missing_state.system_authority = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_state),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut missing_marker = snapshot.clone();
        missing_marker
            .config
            .as_mut()
            .unwrap()
            .system_authority_genesis = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_marker),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut high_water_tamper = snapshot.clone();
        let authority = high_water_tamper.system_authority.as_ref().unwrap();
        let mut authority_bytes = authority.encode();
        let high_water_offset = 36
            + 2
            + 32
            + 8
            + 32
            + 32
            + 32
            + 32
            + 32
            + 32
            + 32
            + 4
            + 4
            + 4
            + 1
            + 4
            + authority.current_committee().encode().len();
        authority_bytes[high_water_offset..high_water_offset + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        high_water_tamper.system_authority = Some(
            crate::agent::system_authority::SystemAuthorityState::decode(&authority_bytes).unwrap(),
        );
        assert!(matches!(
            StandardAgentRuntime::restore(high_water_tamper),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidState
            ))
        ));

        let mut changed_marker = snapshot;
        let genesis = config.system_authority_genesis.as_ref().unwrap();
        changed_marker
            .config
            .as_mut()
            .unwrap()
            .system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                genesis.root_anchor(),
                genesis.root_anchor_config_version(),
                genesis.root_anchor_config(),
                genesis.initial_committee().clone(),
                genesis.initial_sequence(),
                genesis.catalog_binding(),
                genesis.initial_catalog_commitment(),
                genesis.decision_limit() - 1,
                genesis.rotation_limit(),
                genesis.catalog_limit(),
            )
            .unwrap(),
        );
        assert!(matches!(
            StandardAgentRuntime::restore(changed_marker),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidState
            ))
        ));
    }

    #[test]
    fn scoped_finalize_matches_guest_and_only_native_yields_write_metadata() {
        let (config, committee, keys) = system_config();
        let scope = journal_scope(0x61);
        let context = journal_context(scope);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let command = finalize_command(&config, &committee, &keys, scope, 2);
        let request = LifecycleRequest::FinalizeSystemAuthority(command.clone());
        let before = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());

        let mut public = runtime.clone();
        assert_eq!(
            public.apply(request.clone()),
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidScope
            ))
        );
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&public.snapshot()),
            before
        );
        let unscoped = crate::agent::wire::apply_standard(crate::agent::wire::RuntimeCall::new(
            before.clone(),
            request.clone(),
        ))
        .unwrap();
        assert_eq!(
            unscoped.result,
            Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidScope
            ))
        );
        assert_eq!(unscoped.state, before);

        let guest_call = crate::agent::wire::RuntimeCall::scoped_system_authority(
            before,
            request.clone(),
            scope,
        );
        let guest_call = crate::agent::wire::RuntimeCall::decode(&guest_call.encode()).unwrap();
        let guest = crate::agent::wire::apply_standard(guest_call).unwrap();
        assert_eq!(
            crate::agent::wire::RuntimeReturn::decode(
                &crate::agent::wire::RuntimeReturn {
                    state: guest.state.clone(),
                    result: guest.result.clone(),
                }
                .encode(),
            )
            .unwrap(),
            guest
        );
        let mut native = runtime;
        let native_apply = native.apply_scoped(context, scope, request.clone());
        assert_eq!(native_apply.result(), &guest.result);
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&native.snapshot()),
            guest.state
        );
        let StandardSystemAuthorityWrite::Finalize {
            admitted_fact,
            history,
        } = native_apply.system_authority_write().unwrap()
        else {
            panic!("finalize must return finalize metadata")
        };
        assert!(admitted_fact.is_some());
        assert!(history.inserted());

        let accepted = crate::agent::wire::encode_standard_runtime_state(&native.snapshot());
        let stale = native.apply_scoped(context, scope, request);
        assert_eq!(
            stale.result(),
            &Err(LifecycleError::SystemAuthority(
                crate::agent::system_authority::SystemAuthorityError::InvalidDecisionProof
            ))
        );
        assert!(stale.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&native.snapshot()),
            accepted,
            "a stale sparse proof must roll back byte-identically"
        );

        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let fact = command.fact().unwrap();
        let proof = crate::agent::system_authority::prove_decision(
            native.system_authority().unwrap().decisions_root(),
            fact.target_agent(),
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        let retry = SystemAuthorityFinalize::new(
            command.decision().clone(),
            command.evidence().clone(),
            proof,
        )
        .unwrap();
        let original_request = LifecycleRequest::FinalizeSystemAuthority(command);
        let retry_request = LifecycleRequest::FinalizeSystemAuthority(retry);
        assert_eq!(original_request.commitment(), retry_request.commitment());
        assert_ne!(
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                original_request,
            )
            .encode(),
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                retry_request.clone(),
            )
            .encode(),
        );
        let retry_apply = native.apply_scoped(context, scope, retry_request);
        assert!(matches!(
            retry_apply.result(),
            Ok(LifecycleReply::SystemAuthorityFinalized(
                crate::agent::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(_)
            ))
        ));
        let StandardSystemAuthorityWrite::Finalize { history, .. } =
            retry_apply.system_authority_write().unwrap()
        else {
            panic!("retry must retain finalize metadata")
        };
        assert!(!history.inserted());
    }

    #[test]
    fn scoped_rotation_matches_guest_and_refreshes_retry_proof_without_rekeying_operation() {
        let (config, old, old_keys) = system_config();
        let scope = journal_scope(0x71);
        let context = journal_context(scope);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let finalize = finalize_command(&config, &old, &old_keys, scope, 2);
        let finalized = runtime.apply_scoped(
            context,
            scope,
            LifecycleRequest::FinalizeSystemAuthority(finalize),
        );
        assert!(finalized.result().is_ok());

        let new_keys = vec![committee_key(0x52)];
        let new = authority_committee(&config, 2, Some(old.commitment()), &new_keys);
        let rotation = rotation_command(
            runtime.system_authority().unwrap(),
            scope,
            &old,
            &old_keys,
            &new,
            &new_keys,
        );
        let request = LifecycleRequest::RotateSystemAuthority(rotation.clone());
        let before = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());
        let guest_call = crate::agent::wire::RuntimeCall::scoped_system_authority(
            before,
            request.clone(),
            scope,
        );
        let guest_call = crate::agent::wire::RuntimeCall::decode(&guest_call.encode()).unwrap();
        let guest = crate::agent::wire::apply_standard(guest_call).unwrap();
        assert_eq!(
            crate::agent::wire::RuntimeReturn::decode(
                &crate::agent::wire::RuntimeReturn {
                    state: guest.state.clone(),
                    result: guest.result.clone(),
                }
                .encode(),
            )
            .unwrap(),
            guest
        );
        let applied = runtime.apply_scoped(context, scope, request);
        assert_eq!(applied.result(), &guest.result);
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot()),
            guest.state
        );
        let StandardSystemAuthorityWrite::Rotation { record, history } =
            applied.system_authority_write().unwrap()
        else {
            panic!("rotation must return rotation metadata")
        };
        assert_eq!(record.new_epoch(), 2);
        assert!(history.inserted());

        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let lookup = crate::agent::system_authority::prove_rotation(
            runtime.system_authority().unwrap().rotations_root(),
            2,
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        assert_eq!(lookup.occupied_record(), Some(record));
        let retry = SystemAuthorityRotation::new(
            rotation.new_committee().clone(),
            rotation.certificate().clone(),
            lookup.proof().clone(),
        )
        .unwrap();
        let original = LifecycleRequest::RotateSystemAuthority(rotation);
        let refreshed = LifecycleRequest::RotateSystemAuthority(retry);
        assert_eq!(original.commitment(), refreshed.commitment());
        assert_ne!(
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                original,
            )
            .encode(),
            crate::agent::wire::RuntimeCall::new(
                crate::agent::wire::RuntimeState::default(),
                refreshed.clone(),
            )
            .encode(),
        );
        let retry = runtime.apply_scoped(context, scope, refreshed);
        assert!(matches!(
            retry.result(),
            Ok(LifecycleReply::SystemAuthorityRotated {
                epoch: 2,
                exact_retry: true,
                ..
            })
        ));
        let StandardSystemAuthorityWrite::Rotation { history, .. } =
            retry.system_authority_write().unwrap()
        else {
            panic!("rotation retry must retain rotation metadata")
        };
        assert!(!history.inserted());
    }

    #[test]
    fn scoped_catalog_finality_matches_guest_and_keeps_retry_conflict_bounded() {
        let (config, committee, keys) = system_config();
        let scope = journal_scope(0x91);
        let context = journal_context(scope);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let predecessor = runtime.system_authority().unwrap().clone();
        let operation = OperationId([0x92; 32]);
        let command = catalog_command(&predecessor, &committee, &keys, operation, 2, 0x93);
        let request = LifecycleRequest::FinalizeCatalog(command.clone());
        let before = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());

        let guest_call = crate::agent::wire::RuntimeCall::scoped_system_authority(
            before,
            request.clone(),
            scope,
        );
        let guest_call = crate::agent::wire::RuntimeCall::decode(&guest_call.encode()).unwrap();
        let guest = crate::agent::wire::apply_standard(guest_call).unwrap();
        let applied = runtime.apply_scoped(context, scope, request.clone());
        assert_eq!(applied.result(), &guest.result);
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot()),
            guest.state
        );
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(record),
            history,
        } = applied.system_authority_write().unwrap()
        else {
            panic!("fresh catalog finality must return its permanent record and history")
        };
        assert!(history.inserted());
        assert_eq!(record.receipt(), command.receipt());
        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let occupied = crate::agent::system_authority::prove_catalog(
            runtime.system_authority().unwrap().catalog_history_root(),
            operation,
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        assert_eq!(occupied.occupied_record_id(), Some(record.id()));

        let retry =
            SystemAuthorityCatalogFinalize::new(command.receipt().clone(), occupied.clone())
                .unwrap();
        let retry_request = LifecycleRequest::FinalizeCatalog(retry);
        assert_eq!(request.commitment(), retry_request.commitment());
        let stable = crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot());
        let retried = runtime.apply_scoped(context, scope, retry_request);
        assert!(matches!(
            retried.result(),
            Ok(LifecycleReply::CatalogFinalized(outcome)) if outcome.exact_retry()
        ));
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(retry_record),
            history: retry_history,
        } = retried.system_authority_write().unwrap()
        else {
            panic!("catalog retry must retain the exact permanent record identity")
        };
        assert_eq!(retry_record.id(), record.id());
        assert!(!retry_history.inserted());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot()),
            stable
        );

        let divergent = catalog_command(&predecessor, &committee, &keys, operation, 2, 0x94);
        let conflict =
            SystemAuthorityCatalogFinalize::new(divergent.receipt().clone(), occupied).unwrap();
        let conflicted =
            runtime.apply_scoped(context, scope, LifecycleRequest::FinalizeCatalog(conflict));
        assert!(matches!(
            conflicted.result(),
            Ok(LifecycleReply::CatalogFinalized(outcome))
                if outcome.operation_conflicted()
                    && outcome.occupied_record_id() == Some(record.id())
        ));
        let StandardSystemAuthorityWrite::Catalog {
            record: None,
            history: conflict_history,
        } = conflicted.system_authority_write().unwrap()
        else {
            panic!("catalog conflict must expose only the bounded occupied record ID")
        };
        assert!(!conflict_history.inserted());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&runtime.snapshot()),
            stable
        );
    }

    #[test]
    fn scoped_authority_capacity_and_resource_refusals_roll_back_byte_identically() {
        let scope = journal_scope(0x75);
        let context = journal_context(scope);

        // The signed resource ceiling is part of Config but fixed-width on
        // wire, so the exact created-state length measured here remains the
        // exact created-state length after installing that value as its cap.
        let (probe_config, _, _) = system_config();
        let mut probe = StandardAgentRuntime::new();
        create_authorized(&mut probe, &probe_config, 1).unwrap();
        let exact_created_len =
            crate::agent::wire::encode_standard_runtime_state(&probe.snapshot())
                .encoded_len()
                .unwrap();
        let (capped_config, capped_committee, capped_keys) =
            system_config_with_limits(64, u32::try_from(exact_created_len).unwrap());
        let mut capped = StandardAgentRuntime::new();
        create_authorized(&mut capped, &capped_config, 1).unwrap();
        let capped_before = crate::agent::wire::encode_standard_runtime_state(&capped.snapshot());
        assert_eq!(capped_before.encoded_len(), Some(exact_created_len));
        let capped_request = LifecycleRequest::FinalizeSystemAuthority(finalize_command(
            &capped_config,
            &capped_committee,
            &capped_keys,
            scope,
            2,
        ));

        let guest = crate::agent::wire::apply_standard(
            crate::agent::wire::RuntimeCall::scoped_system_authority(
                capped_before.clone(),
                capped_request.clone(),
                scope,
            ),
        )
        .unwrap();
        assert_eq!(guest.result, Err(LifecycleError::ResourceLimit));
        assert_eq!(guest.state, capped_before);

        let native = capped.apply_scoped(context, scope, capped_request);
        assert_eq!(native.result(), &Err(LifecycleError::ResourceLimit));
        assert!(native.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&capped.snapshot()),
            capped_before
        );

        let (capacity_config, capacity_committee, capacity_keys) = system_config_with_limits(
            1,
            crate::agent::contract::RuntimeResourceLimits::standard().max_runtime_state_bytes,
        );
        let mut capacity = StandardAgentRuntime::new();
        create_authorized(&mut capacity, &capacity_config, 1).unwrap();
        let first = capacity.apply_scoped(
            context,
            scope,
            LifecycleRequest::FinalizeSystemAuthority(finalize_command(
                &capacity_config,
                &capacity_committee,
                &capacity_keys,
                scope,
                2,
            )),
        );
        assert!(first.result().is_ok());
        let StandardSystemAuthorityWrite::Finalize { history, .. } =
            first.system_authority_write().unwrap()
        else {
            panic!("the admitted decision must return finalize history")
        };
        let nodes = history
            .nodes()
            .iter()
            .map(|node| (node.id(), node.encode()))
            .collect::<BTreeMap<_, _>>();
        let capacity_before =
            crate::agent::wire::encode_standard_runtime_state(&capacity.snapshot());
        let full = finalize_command(
            &capacity_config,
            &capacity_committee,
            &capacity_keys,
            scope,
            3,
        );
        let target = full.fact().unwrap().target_agent();
        let proof = crate::agent::system_authority::prove_decision(
            capacity.system_authority().unwrap().decisions_root(),
            target,
            |id| Ok::<_, ()>(nodes.get(&id).cloned()),
        )
        .unwrap();
        assert!(proof.occupied_fact().is_none());
        let full_request = LifecycleRequest::FinalizeSystemAuthority(
            SystemAuthorityFinalize::new(full.decision().clone(), full.evidence().clone(), proof)
                .unwrap(),
        );
        let expected = Err(LifecycleError::SystemAuthority(
            crate::agent::system_authority::SystemAuthorityError::Capacity,
        ));

        let guest = crate::agent::wire::apply_standard(
            crate::agent::wire::RuntimeCall::scoped_system_authority(
                capacity_before.clone(),
                full_request.clone(),
                scope,
            ),
        )
        .unwrap();
        assert_eq!(guest.result, expected);
        assert_eq!(guest.state, capacity_before);

        let native = capacity.apply_scoped(context, scope, full_request);
        assert_eq!(native.result(), &expected);
        assert!(native.system_authority_write().is_none());
        assert_eq!(
            crate::agent::wire::encode_standard_runtime_state(&capacity.snapshot()),
            capacity_before
        );
    }

    fn install(agent: AgentId, parent: Option<ActorId>, name: &str) -> InstallActor {
        let actor = parent.map_or_else(
            || ActorId::top_level(agent, name),
            |parent| ActorId::owned_child(parent, name),
        );
        let requirements = RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proofs: false,
        };
        let package = BlobRef {
            hash: Hash([10; 32]),
            len: 100,
        };
        let agent_schema = BlobRef {
            hash: Hash([11; 32]),
            len: 100,
        };
        let role_policies = BlobRef {
            hash: Hash([13; 32]),
            len: 100,
        };
        InstallActor {
            installation_id: InstallationId::new(actor.0),
            registry_reservation: Hash::digest(
                b"vos/test/registry-reservation",
                &[actor.as_bytes()],
            ),
            entry: ActorEntry {
                actor,
                name: name.into(),
                parent,
                deployment: DeploymentId([7; 32]),
                program: ProgramId([8; 32]),
                package: package.clone(),
                agent_schema: agent_schema.clone(),
                role_policies: role_policies.clone(),
                constructor_abi: Hash([14; 32]),
                installation_data: None,
                state_layout: Hash([12; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: ProducerId([9; 32]),
            package,
            agent_schema,
            role_policies,
            constructor_abi: Hash([14; 32]),
            installation_data: None,
            state_layout: Hash([12; 32]),
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements,
        }
    }

    fn set_install_artifacts(
        install: &mut InstallActor,
        package: BlobRef,
        agent_schema: BlobRef,
        role_policies: BlobRef,
    ) {
        install.entry.package = package.clone();
        install.entry.agent_schema = agent_schema.clone();
        install.entry.role_policies = role_policies.clone();
        install.package = package;
        install.agent_schema = agent_schema;
        install.role_policies = role_policies;
    }

    fn set_installation_data(install: &mut InstallActor, bytes: Vec<u8>) {
        let data = super::super::InstallationData {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        };
        install.entry.installation_data = Some(data.reference.clone());
        install.installation_data = Some(data);
    }

    fn suspend(actor: ActorId, expected_deployment: DeploymentId) -> LifecycleRequest {
        LifecycleRequest::Suspend {
            actor,
            expected_deployment,
        }
    }

    fn resume(actor: ActorId, expected_deployment: DeploymentId) -> LifecycleRequest {
        LifecycleRequest::Resume {
            actor,
            expected_deployment,
        }
    }

    #[cfg(feature = "pvm")]
    fn set_lane(runtime: &mut StandardAgentRuntime, actor: ActorId, lane: StateLane, value: &[u8]) {
        let generation = runtime.actors[&actor].record.state_generation;
        runtime
            .lane_state
            .upsert(lane, actor, generation, value.to_vec())
            .unwrap();
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn persisted_rows_survive_inline_updates_and_bind_merge_observation() {
        let config = config(4);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut installed = install(config.identity.agent, None, "rows");
        installed.entry.lanes = LaneSet::of(StateLane::Merge);
        installed.requirements.lanes = installed.entry.lanes;
        let actor = installed.entry.actor;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        set_lane(&mut runtime, actor, StateLane::Merge, &[1]);
        runtime.lane_state.merge[0]
            .rows
            .insert(b"s/rows/a".to_vec(), vec![7; 64 * 1024]);
        let before = runtime
            .observation(actor, super::super::MethodMode::Merge)
            .unwrap();
        runtime.lane_state.merge[0]
            .rows
            .get_mut(b"s/rows/a".as_slice())
            .unwrap()[0] = 8;
        let after = runtime
            .observation(actor, super::super::MethodMode::Merge)
            .unwrap();
        assert_ne!(
            before.merge_frontier, after.merge_frontier,
            "row bytes must bind the observed frontier"
        );
        let rows = runtime.lane_state.merge[0].rows.clone();
        set_lane(&mut runtime, actor, StateLane::Merge, &[]);
        assert!(runtime.lane_state.merge[0].value.is_empty());
        assert_eq!(
            runtime.lane_state.merge[0].rows, rows,
            "empty inline state must not erase rows"
        );
        runtime.validate_restored_lane_state().unwrap();
        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let reopened = StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&encoded).unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.lane_state, runtime.lane_state);
        assert_eq!(
            reopened
                .observation(actor, super::super::MethodMode::Merge)
                .unwrap(),
            runtime
                .observation(actor, super::super::MethodMode::Merge)
                .unwrap()
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn merge_receives_only_merge_state_and_cannot_return_hidden_linear() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth, ActorStateLanes,
        };
        use crate::service::InvocationId;

        let config = config(4);
        let mut runtime = StandardAgentRuntime::new();
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Create(config.clone()),
        )
        .unwrap();
        let mut install = install(config.identity.agent, None, "mixed");
        let shared = LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge));
        install.entry.lanes = shared;
        install.requirements.lanes = shared;
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        set_lane(&mut runtime, actor, StateLane::Linear, &[7]);

        let invocation = ActorInvocation {
            invocation: InvocationId([31; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: crate::agent::MethodMode::Merge,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        assert_eq!(before.linear.as_deref(), Some(&[7][..]));
        assert_eq!(before.merge.as_deref(), Some(&[][..]));
        assert!(before.local.is_none());
        let visible = before.visible_for(invocation.mode);
        assert!(visible.linear.is_none());
        assert_eq!(visible.merge.as_deref(), Some(&[][..]));
        assert!(visible.local.is_none());

        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: Some(StateLane::Merge),
            status: ActorExecutionStatus::Done,
            reply: Vec::new(),
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        let forged = ActorStateLanes {
            linear: Some(vec![8]),
            merge: Some(vec![1]),
            local: None,
        };
        let fresh = ActorStateLanes {
            linear: Some(Vec::new()),
            merge: Some(Vec::new()),
            local: None,
        };
        assert_eq!(
            runtime.commit_execution(&invocation, &mut reply, &fresh, forged.clone(), 1),
            Err(ActorExecutionError::InvalidActorOutput),
            "the host enforces non-owned lanes even from the fresh sentinel"
        );
        assert_eq!(
            runtime.commit_execution(&invocation, &mut reply, &before, forged, 1),
            Err(ActorExecutionError::InvalidActorOutput)
        );
    }

    fn authorized(
        config: &AgentConfig,
        credential: CredentialId,
        sequence: u64,
        claim_byte: u8,
        request: LifecycleRequest,
    ) -> LifecycleRequest {
        authorized_at(config, credential, sequence, 100, claim_byte, request)
    }

    fn authorized_at(
        config: &AgentConfig,
        credential: CredentialId,
        sequence: u64,
        observed_slot: u64,
        claim_byte: u8,
        request: LifecycleRequest,
    ) -> LifecycleRequest {
        let operation = request.commitment();
        let claim = crate::agent::authority::AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: PrincipalId([claim_byte.max(1); 32]),
            credential,
            capability: crate::service::CapabilityId::named(match &request {
                LifecycleRequest::Create(config) => match config.identity.profile {
                    AgentProfile::Local => crate::agent::authority::CAPABILITY_AGENT_CREATE_LOCAL,
                    AgentProfile::Private => {
                        crate::agent::authority::CAPABILITY_AGENT_CREATE_PRIVATE
                    }
                    AgentProfile::Shared => crate::agent::authority::CAPABILITY_AGENT_CREATE_SHARED,
                },
                LifecycleRequest::Install(_) => crate::agent::authority::CAPABILITY_ACTOR_INSTALL,
                LifecycleRequest::UpgradeActor(_) => {
                    crate::agent::authority::CAPABILITY_ACTOR_UPGRADE
                }
                LifecycleRequest::Suspend { .. }
                | LifecycleRequest::Resume { .. }
                | LifecycleRequest::RemoveLeaf { .. } => {
                    crate::agent::authority::CAPABILITY_ACTOR_LIFECYCLE
                }
                LifecycleRequest::UpgradeRuntime { .. } => {
                    crate::agent::authority::CAPABILITY_AGENT_RUNTIME_UPGRADE
                }
                _ => panic!("test helper accepts mutation requests only"),
            }),
            operation,
            sequence,
            valid_from: 0,
            valid_until: u64::MAX,
        };
        let signature = authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        LifecycleRequest::Authorized {
            admission: super::super::LifecycleAuthorityAdmission {
                receipt: crate::agent::authority::AgentAuthorityReceipt { claim, signature },
                observed_slot,
            },
            request: Box::new(request),
        }
    }

    fn apply_authorized(
        runtime: &mut StandardAgentRuntime,
        config: &AgentConfig,
        request: LifecycleRequest,
    ) -> Result<LifecycleReply, LifecycleError> {
        let sequence = runtime.authority_sequence_high_water.unwrap_or(0) + 1;
        runtime.apply(authorized(
            config,
            CredentialId([0x55; 32]),
            sequence,
            u8::try_from(sequence).unwrap_or(u8::MAX - 1),
            request,
        ))
    }

    fn create_authorized(
        runtime: &mut StandardAgentRuntime,
        config: &AgentConfig,
        observed_slot: u64,
    ) -> Result<LifecycleReply, LifecycleError> {
        runtime.apply(authorized_at(
            config,
            CredentialId([0x54; 32]),
            1,
            observed_slot,
            1,
            LifecycleRequest::Create(config.clone()),
        ))
    }

    #[cfg(feature = "pvm")]
    fn signed_invocation_receipt(
        config: &AgentConfig,
        invocation: &super::super::execution::ActorInvocation,
        valid_from: u64,
        valid_until: u64,
    ) -> super::super::authority::ActorInvocationReceipt {
        let claim = super::super::authority::ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: invocation.auth.principal,
            credential: invocation.auth.principal.map(|_| CredentialId([0x66; 32])),
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from,
            valid_until,
        };
        super::super::authority::ActorInvocationReceipt {
            signature: authority_key()
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        }
    }

    #[test]
    fn created_agent_is_valid_and_usefully_empty() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS);
        // A later credential can advance the one global sequence without
        // consuming a permanent per-credential slot.
        assert_eq!(
            runtime.apply(LifecycleRequest::Create(config.clone())),
            Err(LifecycleError::InvalidRequest),
            "raw lifecycle mutations are never an authority bypass"
        );
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Create(config.clone())
            ),
            Ok(LifecycleReply::Created(_))
        ));
        assert!(runtime.is_empty());
        assert_eq!(
            runtime.apply(LifecycleRequest::Inspect {
                after: None,
                limit: 16
            }),
            Ok(LifecycleReply::Directory(
                super::super::ActorDirectoryPage {
                    entries: vec![],
                    next: None,
                }
            ))
        );
    }

    #[test]
    fn install_identity_is_exact_idempotent_across_upgrade_suspend_and_reopen() {
        let config = config(1);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let install_request = install(config.identity.agent, None, "identity-anchor");
        let actor = install_request.entry.actor;
        let installation_id = install_request.installation_id;
        let registry_reservation = install_request.registry_reservation;
        let install_request_commitment =
            LifecycleRequest::Install(install_request.clone()).commitment();

        let mut zero_id = install_request.clone();
        zero_id.installation_id = InstallationId::ZERO;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(zero_id),),
            Err(LifecycleError::InvalidRequest)
        );
        let mut zero_reservation = install_request.clone();
        zero_reservation.registry_reservation = Hash::ZERO;
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(zero_reservation),
            ),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.actor_record(actor).is_none());

        let installed = apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(install_request.clone()),
        )
        .unwrap();
        assert_eq!(
            installed,
            LifecycleReply::Installed(install_request.entry.clone())
        );
        let generation = runtime.actor_record(actor).unwrap().state_generation;
        assert_eq!(
            runtime
                .actor_record(actor)
                .unwrap()
                .install_request_commitment,
            install_request_commitment
        );

        // A retry may carry a fresh authority sequence. The stable install
        // identity still resolves to the original successful installation
        // without creating a new incarnation.
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(install_request.clone()),
            ),
            Ok(LifecycleReply::Installed(install_request.entry.clone()))
        );
        assert_eq!(runtime.len(), 1);
        assert_eq!(
            runtime.actor_record(actor).unwrap().state_generation,
            generation
        );

        let mut mismatched_reservation = install_request.clone();
        mismatched_reservation.registry_reservation = Hash([0xee; 32]);
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(mismatched_reservation),
            ),
            Err(LifecycleError::InvalidRequest)
        );

        let mut reused_id = install(config.identity.agent, None, "different-actor");
        reused_id.installation_id = installation_id;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(reused_id),),
            Err(LifecycleError::InvalidRequest)
        );

        let upgraded_deployment = DeploymentId([0xec; 32]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: install_request.entry.deployment,
                to_deployment: upgraded_deployment,
                to_program: install_request.entry.program,
                producer: install_request.producer,
                package: install_request.package.clone(),
                agent_schema: install_request.agent_schema.clone(),
                role_policies: install_request.role_policies.clone(),
                constructor_abi: install_request.constructor_abi,
                state_layout: install_request.state_layout,
                contract: install_request.contract,
                requirements: install_request.requirements,
            }),
        )
        .unwrap();
        let upgraded = runtime.actor_record(actor).unwrap().clone();
        assert_eq!(upgraded.installation_id, installation_id);
        assert_eq!(upgraded.registry_reservation, registry_reservation);
        assert_eq!(
            upgraded.install_request_commitment,
            install_request_commitment
        );
        assert_eq!(upgraded.state_generation, generation);

        // Upgrade-mutated deployment state cannot redefine the immutable
        // creation request. The original install is still an exact retry, but
        // an InstallActor rewritten to match the current upgraded record is a
        // conflicting reuse of the same InstallationId.
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(install_request.clone()),
            ),
            Ok(LifecycleReply::Installed(install_request.entry.clone()))
        );
        assert_eq!(runtime.actor_record(actor), Some(&upgraded));
        let mut rewritten_as_upgrade = install_request.clone();
        rewritten_as_upgrade.entry.deployment = upgraded_deployment;
        assert_ne!(
            LifecycleRequest::Install(rewritten_as_upgrade.clone()).commitment(),
            install_request_commitment
        );
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(rewritten_as_upgrade),
            ),
            Err(LifecycleError::InvalidRequest)
        );
        assert_eq!(runtime.actor_record(actor), Some(&upgraded));

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Suspend {
                actor,
                expected_deployment: upgraded_deployment,
            },
        )
        .unwrap();
        let suspended = runtime.actor_record(actor).unwrap().clone();
        assert!(suspended.entry.suspended);
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(install_request.clone()),
            ),
            Ok(LifecycleReply::Installed(install_request.entry.clone()))
        );
        assert_eq!(runtime.actor_record(actor), Some(&suspended));

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        let reopened_record = reopened.actor_record(actor).unwrap();
        assert_eq!(reopened_record.installation_id, installation_id);
        assert_eq!(reopened_record.registry_reservation, registry_reservation);
        assert_eq!(
            reopened_record.install_request_commitment,
            install_request_commitment
        );
        assert_eq!(reopened_record.state_generation, generation);
        assert_eq!(reopened_record.entry.deployment, upgraded_deployment);
        assert!(reopened_record.entry.suspended);
        let reopened_record = reopened_record.clone();
        assert_eq!(
            apply_authorized(
                &mut reopened,
                &config,
                LifecycleRequest::Install(install_request.clone()),
            ),
            Ok(LifecycleReply::Installed(install_request.entry.clone()))
        );
        assert_eq!(reopened.actor_record(actor), Some(&reopened_record));
        let mut altered_after_reopen = install_request.clone();
        altered_after_reopen.entry.deployment = upgraded_deployment;
        assert_eq!(
            apply_authorized(
                &mut reopened,
                &config,
                LifecycleRequest::Install(altered_after_reopen),
            ),
            Err(LifecycleError::InvalidRequest),
            "restore must retain the original install commitment, not derive one from current state"
        );
        assert_eq!(reopened.actor_record(actor), Some(&reopened_record));

        let page = reopened
            .apply(LifecycleRequest::Inspect {
                after: None,
                limit: 8,
            })
            .unwrap();
        let LifecycleReply::Directory(page) = page else {
            panic!("inspect returned a non-directory reply");
        };
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].installation_id, installation_id);
        assert_eq!(page.entries[0].registry_reservation, registry_reservation);
        assert_eq!(page.entries[0].incarnation, generation);
    }

    #[test]
    fn immutable_installation_data_is_exact_across_retry_restore_and_upgrade() {
        let config = config(1);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let absent = install(config.identity.agent, None, "constructor-bound");
        let mut present_empty = absent.clone();
        set_installation_data(&mut present_empty, Vec::new());
        assert_ne!(
            LifecycleRequest::Install(absent.clone()).commitment(),
            LifecycleRequest::Install(present_empty.clone()).commitment(),
            "present-empty is a committed object, not absence"
        );
        let actor = present_empty.entry.actor;
        let original_reference = present_empty.entry.installation_data.clone().unwrap();
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(present_empty.clone()),
        )
        .unwrap();
        assert_eq!(
            runtime.actor_record(actor).unwrap().installation_data,
            Some(original_reference.clone())
        );

        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(absent),),
            Err(LifecycleError::InvalidRequest),
            "the same InstallationId cannot erase a present-empty object"
        );
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(present_empty.clone()),
            ),
            Ok(LifecycleReply::Installed(present_empty.entry.clone()))
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let restored_state = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut restored = StandardAgentRuntime::restore(restored_state).unwrap();
        assert_eq!(
            restored.actor_record(actor).unwrap().installation_data,
            Some(original_reference.clone())
        );

        let upgraded_deployment = DeploymentId([0xd1; 32]);
        apply_authorized(
            &mut restored,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: present_empty.entry.deployment,
                to_deployment: upgraded_deployment,
                to_program: present_empty.entry.program,
                producer: ProducerId([0xd2; 32]),
                package: BlobRef {
                    hash: Hash([0xd3; 32]),
                    len: 100,
                },
                agent_schema: BlobRef {
                    hash: Hash([0xd4; 32]),
                    len: 100,
                },
                role_policies: BlobRef {
                    hash: Hash([0xd5; 32]),
                    len: 100,
                },
                constructor_abi: present_empty.constructor_abi,
                state_layout: present_empty.state_layout,
                contract: present_empty.contract,
                requirements: present_empty.requirements,
            }),
        )
        .unwrap();
        let upgraded = restored.actor_record(actor).unwrap();
        assert_eq!(upgraded.entry.deployment, upgraded_deployment);
        assert_eq!(upgraded.installation_data, Some(original_reference));
    }

    #[test]
    fn install_rejects_corrupt_oversized_and_cross_role_installation_data() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let mut mismatch = install(config.identity.agent, None, "mismatch");
        set_installation_data(&mut mismatch, vec![1]);
        mismatch.installation_data.as_mut().unwrap().bytes[0] = 2;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatch),),
            Err(LifecycleError::InvalidRequest)
        );

        let mut oversized = install(config.identity.agent, None, "oversized");
        set_installation_data(
            &mut oversized,
            vec![0; super::super::MAX_INSTALLATION_DATA_BYTES + 1],
        );
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(oversized),),
            Err(LifecycleError::InvalidRequest)
        );

        let mut aliased = install(config.identity.agent, None, "aliased");
        set_installation_data(&mut aliased, vec![3]);
        let reference = aliased
            .installation_data
            .as_ref()
            .unwrap()
            .reference
            .clone();
        aliased.package = reference.clone();
        aliased.entry.package = reference;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(aliased),),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn actor_upgrade_preserves_the_exact_signed_constructor_abi() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let installed = install(config.identity.agent, None, "constructor-bound-upgrade");
        let actor = installed.entry.actor;
        let from_deployment = installed.entry.deployment;
        let mut incompatible = UpgradeActor {
            actor,
            from_deployment,
            to_deployment: DeploymentId([0xb1; 32]),
            to_program: installed.entry.program,
            producer: ProducerId([0xb2; 32]),
            package: BlobRef {
                hash: Hash([0xb3; 32]),
                len: 100,
            },
            agent_schema: installed.agent_schema.clone(),
            role_policies: installed.role_policies.clone(),
            constructor_abi: Hash([0xb4; 32]),
            state_layout: installed.state_layout,
            contract: installed.contract,
            requirements: installed.requirements,
        };
        let expected_abi = installed.constructor_abi;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        let before_actor = runtime.actor_record(actor).unwrap().clone();
        let before_lanes = runtime.lane_state.clone();
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(incompatible.clone()),
            ),
            Err(LifecycleError::InvalidRequest)
        );
        assert_eq!(runtime.actor_record(actor), Some(&before_actor));
        assert_eq!(runtime.lane_state, before_lanes);
        assert_eq!(runtime.snapshot().authority_dispositions.len(), 3);
        assert_eq!(
            runtime
                .snapshot()
                .authority_dispositions
                .last()
                .unwrap()
                .result,
            Err(LifecycleError::InvalidRequest)
        );

        incompatible.constructor_abi = expected_abi;
        assert!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(incompatible),
            )
            .is_ok()
        );
        assert_eq!(
            runtime.actor_record(actor).unwrap().constructor_abi,
            expected_abi
        );
    }

    #[test]
    fn present_empty_installation_data_consumes_one_closure_reference() {
        let mut config = config(1);
        config.runtime_contract.resources.max_artifact_references = 4;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 400;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut install = install(config.identity.agent, None, "empty-counts");
        set_installation_data(&mut install, Vec::new());
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install),),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn removed_installation_id_is_burned_across_reopen() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let request = install(config.identity.agent, None, "retired-install");
        let actor = request.entry.actor;
        let retired_id = request.installation_id;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let retired_generation = runtime.actor_record(actor).unwrap().state_generation;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment: request.entry.deployment,
            },
        )
        .unwrap();
        assert!(runtime.actor_record(actor).is_none());
        assert_eq!(
            runtime.snapshot().retired_installation_ids,
            vec![retired_id]
        );

        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(request.clone()),
            ),
            Err(LifecycleError::InvalidRequest),
            "a fresh-sequence retry cannot resurrect a removed installation"
        );
        assert!(runtime.actor_record(actor).is_none());

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.snapshot().retired_installation_ids,
            vec![retired_id]
        );
        assert_eq!(
            apply_authorized(
                &mut reopened,
                &config,
                LifecycleRequest::Install(request.clone()),
            ),
            Err(LifecycleError::InvalidRequest)
        );

        let mut other_actor_reuse = install(config.identity.agent, None, "other-actor");
        other_actor_reuse.installation_id = retired_id;
        assert_eq!(
            apply_authorized(
                &mut reopened,
                &config,
                LifecycleRequest::Install(other_actor_reuse),
            ),
            Err(LifecycleError::InvalidRequest)
        );

        let mut replacement = request;
        replacement.installation_id = InstallationId([0xd1; 32]);
        replacement.registry_reservation = Hash([0xd2; 32]);
        apply_authorized(
            &mut reopened,
            &config,
            LifecycleRequest::Install(replacement),
        )
        .unwrap();
        assert_ne!(
            reopened.actor_record(actor).unwrap().state_generation,
            retired_generation,
            "a genuinely new installation receives a fresh incarnation"
        );
    }

    #[test]
    fn standard_directory_physically_encodes_and_restores_its_signed_capacity() {
        let config = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        for index in 0..config.capabilities.max_actors {
            runtime
                .install(
                    install(
                        config.identity.agent,
                        None,
                        &alloc::format!("actor-{index:04}"),
                    ),
                    Hash::digest(b"vos/test/state-generation", &[&index.to_le_bytes()]),
                )
                .unwrap();
        }
        assert_eq!(runtime.len(), 4_096);
        assert_eq!(
            runtime.install(
                install(config.identity.agent, None, "actor-overflow"),
                Hash([0x99; 32]),
            ),
            Err(LifecycleError::DirectoryFull)
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        assert!(
            encoded.encoded_len().unwrap()
                <= config.runtime_contract.resources.max_runtime_state_bytes as usize,
            "the signed standard runtime capacity must fit its own image ceiling"
        );
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let restored = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(restored.len(), 4_096);
    }

    #[test]
    fn management_directory_changes_leave_all_lane_components_byte_identical() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let before_install = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());

        let mut request = install(config.identity.agent, None, "sparse");
        request.entry.lanes = LaneSet::ALL;
        request.requirements.lanes = LaneSet::ALL;
        let actor = request.entry.actor;
        let initial_deployment = request.entry.deployment;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let after_install = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(after_install.linear, before_install.linear);
        assert_eq!(after_install.merge, before_install.merge);
        assert_eq!(after_install.local, before_install.local);

        let generation = runtime.actors[&actor].record.state_generation;
        runtime.lane_state.linear.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![1],
            rows: BTreeMap::new(),
        });
        runtime.lane_state.merge.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![2],
            rows: BTreeMap::new(),
        });
        runtime.lane_state.local.push(StandardLaneEntry {
            actor,
            state_generation: generation,
            value: vec![3],
            rows: BTreeMap::new(),
        });
        let baseline = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let assert_lanes = |runtime: &StandardAgentRuntime| {
            let state = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
            assert_eq!(state.linear, baseline.linear);
            assert_eq!(state.merge, baseline.merge);
            assert_eq!(state.local, baseline.local);
        };

        apply_authorized(&mut runtime, &config, suspend(actor, initial_deployment)).unwrap();
        assert_lanes(&runtime);
        apply_authorized(&mut runtime, &config, resume(actor, initial_deployment)).unwrap();
        assert_lanes(&runtime);

        let upgraded_deployment = DeploymentId([0x71; 32]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: initial_deployment,
                to_deployment: upgraded_deployment,
                to_program: request.entry.program,
                producer: request.producer,
                package: request.package.clone(),
                agent_schema: request.agent_schema.clone(),
                role_policies: request.role_policies.clone(),
                constructor_abi: request.constructor_abi,
                state_layout: request.state_layout,
                contract: request.contract,
                requirements: request.requirements,
            }),
        )
        .unwrap();
        assert_lanes(&runtime);
        assert_eq!(runtime.actors[&actor].record.state_generation, generation);

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0x72; 32]),
                to_program: ProgramId([0x73; 32]),
                producer: ProducerId([0x74; 32]),
                package: BlobRef {
                    hash: Hash([0x75; 32]),
                    len: 101,
                },
                contract: super::super::contract::RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
            },
        )
        .unwrap();
        assert_lanes(&runtime);

        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment: upgraded_deployment,
            },
        )
        .unwrap();
        assert_lanes(&runtime);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn remove_and_reinstall_never_resurrect_historical_lane_state() {
        use crate::agent::execution::{ActorExecutionError, ActorInvocation, ActorInvocationAuth};
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let request = install(config.identity.agent, None, "reused");
        let actor = request.entry.actor;
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(request.clone()),
        )
        .unwrap();
        let old_generation = runtime.actors[&actor].record.state_generation;
        let old_invocation = ActorInvocation {
            invocation: InvocationId([0x75; 32]),
            actor,
            incarnation: old_generation,
            deployment: request.entry.deployment,
            program: request.entry.program,
            mode: super::super::MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let old_receipt = signed_invocation_receipt(&config, &old_invocation, 0, 100);
        set_lane(&mut runtime, actor, StateLane::Linear, &[0xaa]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment: request.entry.deployment,
            },
        )
        .unwrap();
        assert_eq!(runtime.lane_state.linear.len(), 1);

        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::Install(request.clone()),
            ),
            Err(LifecycleError::InvalidRequest),
            "the retired installation identity must never become a new incarnation"
        );
        let mut replacement = request.clone();
        replacement.installation_id = InstallationId([0x77; 32]);
        replacement.registry_reservation = Hash([0x78; 32]);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(replacement.clone()),
        )
        .unwrap();
        let new_generation = runtime.actors[&actor].record.state_generation;
        assert_ne!(new_generation, old_generation);
        assert_ne!(new_generation, Hash::ZERO);
        runtime
            .verify_invocation_authority(&old_invocation, &old_receipt)
            .unwrap();
        assert_eq!(
            runtime.prepare_execution_state(&old_invocation),
            Err(ActorExecutionError::StaleIncarnation),
            "a valid receipt minted for a retired install cannot reach its replacement"
        );
        assert_eq!(
            runtime.recover_execution(&old_invocation, 1),
            Err(ActorExecutionError::StaleIncarnation)
        );

        let LifecycleReply::Directory(directory) = runtime
            .apply(LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            })
            .unwrap()
        else {
            panic!("inspect must return a directory page")
        };
        let current = directory.entries.into_iter().next().unwrap();
        assert_eq!(current.entry.actor, actor);
        assert_eq!(current.incarnation, new_generation);
        assert_eq!(current.installation_id, replacement.installation_id);
        assert_eq!(
            current.registry_reservation,
            replacement.registry_reservation
        );
        let invocation = ActorInvocation {
            invocation: InvocationId([0x76; 32]),
            actor: current.entry.actor,
            incarnation: current.incarnation,
            deployment: current.entry.deployment,
            program: current.entry.program,
            mode: super::super::MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        assert_eq!(
            runtime
                .prepare_execution_state(&invocation)
                .unwrap()
                .linear
                .as_deref(),
            Some(&[][..])
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.lane_state.linear[0].state_generation,
            old_generation
        );
        assert_eq!(
            reopened
                .prepare_execution_state(&invocation)
                .unwrap()
                .linear
                .as_deref(),
            Some(&[][..])
        );

        set_lane(&mut reopened, actor, StateLane::Linear, &[0xbb]);
        reopened.compact_historical_lane_entries_for_checkpoint();
        assert_eq!(reopened.lane_state.linear.len(), 1);
        assert_eq!(
            reopened.lane_state.linear[0].state_generation,
            new_generation
        );
        assert_eq!(reopened.lane_state.linear[0].value, vec![0xbb]);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn private_profile_rejects_linearizable_queries_and_all_linear_history() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = private_config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut install = install(config.identity.agent, None, "private");
        install.entry.lanes = LaneSet::of(StateLane::Merge);
        install.requirements.lanes = LaneSet::of(StateLane::Merge);
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        let invocation = ActorInvocation {
            invocation: InvocationId([0x78; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::LinearizableQuery,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.snapshot();
        assert_eq!(
            runtime.prepare_execution_state(&invocation),
            Err(ActorExecutionError::UnsupportedResultStorage)
        );
        assert_eq!(
            runtime.snapshot(),
            before,
            "rejection must not mutate state"
        );
        assert_eq!(
            runtime.commit_exact_outcome_clock(&invocation, 2),
            Err(ActorExecutionError::UnsupportedResultStorage),
            "an exact-outcome clock cannot synthesize unsupported result storage"
        );
        assert_eq!(runtime.snapshot(), before);

        let historical_entry = StandardLaneEntry {
            actor: ActorId([0x79; 32]),
            state_generation: Hash([0x7a; 32]),
            value: vec![1],
            rows: BTreeMap::new(),
        };
        let mut with_entry = before.clone();
        with_entry.lane_state.linear.push(historical_entry);
        assert!(matches!(
            StandardAgentRuntime::restore(with_entry),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_revision = before.clone();
        with_revision.lane_revisions.linear = 1;
        assert!(matches!(
            StandardAgentRuntime::restore(with_revision),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_slot = before.clone();
        with_slot.lane_revisions.linear_authority_slot = Some(1);
        assert!(matches!(
            StandardAgentRuntime::restore(with_slot),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut with_result = before;
        with_result
            .invocation_results
            .push(StandardInvocationResult {
                scope: InvocationScope::Ordered,
                invocation: invocation.invocation,
                incarnation,
                request: invocation.commitment(),
                reply: ActorExecutionReply {
                    invocation: invocation.invocation,
                    actor,
                    incarnation,
                    deployment,
                    mode: invocation.mode,
                    lane: None,
                    status: ActorExecutionStatus::Done,
                    reply: vec![1],
                    gas_remaining: 0,
                    observation: super::super::execution::ActorObservation::default(),
                },
                storage: InvocationResultStorage::Lane(StateLane::Linear),
                clean: None,
            });
        assert!(matches!(
            StandardAgentRuntime::restore(with_result),
            Err(LifecycleError::InvalidRequest)
        ));
    }

    #[test]
    fn local_capability_downgrade_retains_unreachable_historical_lane_entries() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        runtime.lane_state.linear.push(StandardLaneEntry {
            actor: ActorId([0x7b; 32]),
            state_generation: Hash([0x7c; 32]),
            value: vec![1],
            rows: BTreeMap::new(),
        });
        runtime.lane_revisions.linear = 1;
        let mut downgraded = config.capabilities;
        downgraded.lanes = LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0x7d; 32]),
                to_program: ProgramId([0x7e; 32]),
                producer: ProducerId([0x7f; 32]),
                package: BlobRef {
                    hash: Hash([0x80; 32]),
                    len: 1,
                },
                contract: config.runtime_contract,
                capabilities: downgraded,
            },
        )
        .unwrap();

        let reopened = StandardAgentRuntime::restore(runtime.snapshot()).unwrap();
        assert_eq!(reopened.lane_state.linear.len(), 1);
        assert_eq!(reopened.lane_revisions.linear, 1);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn runtime_cannot_disable_a_lane_which_owns_a_retained_result() {
        use crate::agent::execution::{
            ActorExecutionReply, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut install = install(config.identity.agent, None, "result-owner");
        install.entry.lanes = LaneSet::NONE;
        install.requirements.lanes = LaneSet::NONE;
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        let invocation = ActorInvocation {
            invocation: InvocationId([0x81; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::LinearizableQuery,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![1],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &invocation,
                &mut reply,
                &before,
                before.visible_for(invocation.mode),
                2,
            )
            .unwrap();

        let mut downgraded = config.capabilities;
        downgraded.lanes = LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: config.identity.runtime_deployment,
                    to_deployment: DeploymentId([0x82; 32]),
                    to_program: ProgramId([0x83; 32]),
                    producer: ProducerId([0x84; 32]),
                    package: BlobRef {
                        hash: Hash([0x85; 32]),
                        len: 1,
                    },
                    contract: config.runtime_contract,
                    capabilities: downgraded,
                },
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert!(
            runtime
                .config()
                .unwrap()
                .capabilities
                .lanes
                .contains(StateLane::Linear)
        );
        assert_eq!(runtime.invocation_results.len(), 1);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn invocation_identity_is_scoped_and_acknowledgement_routes_exactly() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut request = install(config.identity.agent, None, "scoped");
        request.entry.lanes = LaneSet::ALL;
        request.requirements.lanes = LaneSet::ALL;
        let actor = request.entry.actor;
        let deployment = request.entry.deployment;
        let program = request.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(request)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;

        let raw_id = InvocationId([0x77; 32]);
        let invocation = |mode| ActorInvocation {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            program,
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![mode as u8 + 1],
            availability: Vec::new(),
            gas: 1,
        };
        let query = invocation(super::super::MethodMode::Query);
        let query_before = runtime.prepare_execution_state(&query).unwrap();
        let mut query_reply = ActorExecutionReply {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            mode: query.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![0x11],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &query,
                &mut query_reply,
                &query_before,
                query_before.visible_for(query.mode),
                10,
            )
            .unwrap();

        let merge = invocation(super::super::MethodMode::Merge);
        let merge_before = runtime.prepare_execution_state(&merge).unwrap();
        let mut merge_reply = ActorExecutionReply {
            invocation: raw_id,
            actor,
            incarnation,
            deployment,
            mode: merge.mode,
            lane: Some(StateLane::Merge),
            status: ActorExecutionStatus::Done,
            reply: vec![0x22],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(
                &merge,
                &mut merge_reply,
                &merge_before,
                merge_before.visible_for(merge.mode),
                11,
            )
            .unwrap();
        assert_eq!(runtime.invocation_results.len(), 2);
        assert_eq!(
            runtime.recover_execution(&query, 12).unwrap(),
            Some(query_reply.clone())
        );
        assert_eq!(
            runtime.recover_execution(&merge, 12).unwrap(),
            Some(merge_reply.clone())
        );

        let linear = invocation(super::super::MethodMode::Linear);
        assert_eq!(
            runtime.recover_execution(&linear, 12),
            Err(ActorExecutionError::DivergentInvocation),
            "Query and Linear share the Ordered exactly-once namespace"
        );

        let query_receipt = signed_invocation_receipt(&config, &query, 0, 100);
        assert_eq!(
            runtime.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: super::super::InvocationScope::Merge,
                invocation: raw_id,
                request: query.commitment(),
                authority: Box::new(query_receipt.clone()),
            }),
            Err(LifecycleError::InvalidRequest),
            "an explicit but wrong scope cannot retire another result"
        );
        assert_eq!(
            runtime.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: super::super::InvocationScope::Ordered,
                invocation: raw_id,
                request: query.commitment(),
                authority: Box::new(query_receipt),
            }),
            Ok(LifecycleReply::InvocationAcknowledged {
                scope: super::super::InvocationScope::Ordered,
                invocation: raw_id,
            })
        );
        assert_eq!(runtime.recover_execution(&query, 12).unwrap(), None);
        assert_eq!(
            runtime.recover_execution(&merge, 12).unwrap(),
            Some(merge_reply)
        );
        let merge_receipt = signed_invocation_receipt(&config, &merge, 0, 100);
        assert!(
            runtime
                .apply(LifecycleRequest::AcknowledgeInvocation {
                    scope: super::super::InvocationScope::Merge,
                    invocation: raw_id,
                    request: merge.commitment(),
                    authority: Box::new(merge_receipt),
                })
                .is_ok()
        );
        assert!(runtime.invocation_results.is_empty());
    }

    #[test]
    fn create_receipt_must_name_the_immutable_owner() {
        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply(authorized_at(
                &config,
                CredentialId([0x57; 32]),
                1,
                1,
                2,
                LifecycleRequest::Create(config.clone()),
            )),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.config().is_none());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn query_results_recover_exactly_and_lanes_observe_only_visible_state() {
        use crate::agent::execution::{
            ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
            ActorInvocationAuth,
        };
        use crate::service::InvocationId;

        let config = config(8);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 10).unwrap();
        let mut installed = install(config.identity.agent, None, "observed");
        installed.entry.lanes = LaneSet::ALL;
        installed.requirements.lanes = LaneSet::ALL;
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;
        set_lane(&mut runtime, actor, StateLane::Linear, &[1]);
        set_lane(&mut runtime, actor, StateLane::Merge, &[2]);
        set_lane(&mut runtime, actor, StateLane::Local, &[3]);
        runtime.lane_revisions.linear = 7;
        runtime.lane_revisions.merge = 8;
        runtime.lane_revisions.local = 9;

        let invocation = ActorInvocation {
            invocation: InvocationId([0x61; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::Query,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        let receipt = signed_invocation_receipt(&config, &invocation, 0, 130);
        runtime
            .verify_invocation_authority(&invocation, &receipt)
            .unwrap();
        runtime
            .validate_unseen_invocation_slot(&invocation, &receipt, 120)
            .unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let visible = before.visible_for(invocation.mode);
        assert_eq!(visible.linear.as_deref(), Some(&[1][..]));
        assert_eq!(visible.merge.as_deref(), Some(&[2][..]));
        assert!(visible.local.is_none());
        let mut reply = ActorExecutionReply {
            invocation: invocation.invocation,
            actor,
            incarnation,
            deployment,
            mode: invocation.mode,
            lane: None,
            status: ActorExecutionStatus::Done,
            reply: vec![0xaa],
            gas_remaining: 0,
            observation: super::super::execution::ActorObservation::default(),
        };
        runtime
            .commit_execution(&invocation, &mut reply, &before, visible, 120)
            .unwrap();
        assert_eq!(reply.observation.linear_revision, Some(7));
        assert!(reply.observation.merge_frontier.is_some());
        assert_eq!(reply.observation.local_revision, None);
        let merge_observation = runtime
            .observation(actor, super::super::MethodMode::Merge)
            .unwrap();
        assert_eq!(merge_observation.linear_revision, None);
        assert!(merge_observation.merge_frontier.is_some());
        assert_eq!(merge_observation.local_revision, None);
        let local_observation = runtime
            .observation(actor, super::super::MethodMode::LocalQuery)
            .unwrap();
        assert_eq!(local_observation.linear_revision, Some(7));
        assert!(local_observation.merge_frontier.is_some());
        assert_eq!(local_observation.local_revision, Some(9));

        // Mutation after the reply cannot change exact query recovery. The
        // result lives in the topology-neutral control component.
        set_lane(&mut runtime, actor, StateLane::Linear, &[9]);
        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        reopened
            .verify_invocation_authority(&invocation, &receipt)
            .unwrap();
        assert_eq!(
            reopened.recover_execution(&invocation, 140).unwrap(),
            Some(reply.clone()),
            "exact recovery remains valid after the receipt window closes"
        );

        let mut fresh = invocation.clone();
        fresh.invocation = InvocationId([0x62; 32]);
        let expired = signed_invocation_receipt(&config, &fresh, 0, 130);
        reopened
            .verify_invocation_authority(&fresh, &expired)
            .unwrap();
        assert_eq!(
            reopened.validate_unseen_invocation_slot(&fresh, &expired, 140),
            Err(ActorExecutionError::AuthorityExpired)
        );

        // Exact recovery at 140 advanced the global logical observation; a
        // new lifecycle receipt at an older slot cannot reopen history.
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                CredentialId([0x63; 32]),
                3,
                139,
                3,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
        reopened
            .apply(authorized_at(
                &config,
                CredentialId([0x63; 32]),
                3,
                150,
                3,
                suspend(actor, deployment),
            ))
            .unwrap();
        let mut regressed = invocation.clone();
        regressed.invocation = InvocationId([0x64; 32]);
        let regressed_receipt = signed_invocation_receipt(&config, &regressed, 0, 200);
        reopened
            .verify_invocation_authority(&regressed, &regressed_receipt)
            .unwrap();
        assert_eq!(
            reopened.validate_unseen_invocation_slot(&regressed, &regressed_receipt, 149),
            Err(ActorExecutionError::AuthoritySlotRegressed),
            "lifecycle and invocation receipts share one monotone clock"
        );
        assert_eq!(
            reopened.apply(LifecycleRequest::AcknowledgeInvocation {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
                request: invocation.commitment(),
                authority: Box::new(receipt),
            }),
            Ok(LifecycleReply::InvocationAcknowledged {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
            })
        );
        assert_eq!(reopened.recover_execution(&invocation, 151).unwrap(), None);
    }

    #[test]
    fn authority_sequences_recover_exact_dispositions_without_reapplying_history() {
        let config = config(8);
        let agent = config.identity.agent;
        let credential = CredentialId([0x44; 32]);
        let install = install(agent, None, "counter");
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let install_request = LifecycleRequest::Install(install.clone());
        let installed = runtime
            .apply(authorized(
                &config,
                credential,
                2,
                2,
                install_request.clone(),
            ))
            .unwrap();
        assert_eq!(installed, LifecycleReply::Installed(install.entry.clone()));

        let suspend_request = suspend(actor, deployment);
        let suspended = runtime
            .apply(authorized(
                &config,
                credential,
                3,
                3,
                suspend_request.clone(),
            ))
            .unwrap();
        assert!(matches!(
            &suspended,
            LifecycleReply::Suspended(entry) if entry.suspended
        ));
        runtime
            .apply(authorized(
                &config,
                credential,
                4,
                4,
                resume(actor, deployment),
            ))
            .unwrap();

        // A skipped lower sequence was never admitted and cannot become
        // valid merely because current actor state happens to permit it.
        runtime
            .apply(authorized(
                &config,
                credential,
                10,
                10,
                suspend(actor, deployment),
            ))
            .unwrap();
        assert_eq!(
            runtime.apply(authorized(
                &config,
                credential,
                9,
                9,
                resume(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySequenceRegressed)
        );

        runtime
            .apply(authorized(
                &config,
                credential,
                11,
                11,
                LifecycleRequest::RemoveLeaf {
                    actor,
                    expected_deployment: deployment,
                },
            ))
            .unwrap();

        // Exercise the exact persisted encoding used across process restart.
        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();

        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 3, 3, suspend_request,))
                .unwrap(),
            suspended,
            "Suspend(N) replay recovers its old result after Resume(N+1)"
        );
        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 2, 2, install_request,))
                .unwrap(),
            installed,
            "an old Install retry recovers without reinstalling a removed actor"
        );
        assert!(reopened.is_empty());
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential,
                3,
                0xee,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySequenceConflict)
        );
    }

    #[test]
    fn authority_slot_high_water_survives_restart_and_guards_exact_retries() {
        let config = config(8);
        let credential = CredentialId([0x54; 32]);
        let install = install(config.identity.agent, None, "counter");
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let install_request = LifecycleRequest::Install(install.clone());
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 10).unwrap();
        let installed = runtime
            .apply(authorized_at(
                &config,
                credential,
                2,
                20,
                1,
                install_request.clone(),
            ))
            .unwrap();

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded.authority_slot_high_water, Some(20));
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                credential,
                3,
                19,
                2,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
        assert_eq!(reopened.actor(actor), Some(&install.entry));

        assert_eq!(
            reopened
                .apply(authorized_at(
                    &config,
                    credential,
                    2,
                    25,
                    1,
                    install_request,
                ))
                .unwrap(),
            installed,
            "an exact retry is recovered at the provider's newer slot"
        );
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(25));
        assert_eq!(
            reopened.apply(authorized_at(
                &config,
                credential,
                3,
                24,
                2,
                suspend(actor, deployment),
            )),
            Err(LifecycleError::AuthoritySlotRegressed)
        );
    }

    #[test]
    fn authority_sequence_is_binding_global_and_journal_eviction_stays_fail_closed() {
        fn credential(sequence: u64) -> CredentialId {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&sequence.to_le_bytes());
            CredentialId(bytes)
        }

        let config = config(8);
        let target_install = install(config.identity.agent, None, "sequence-target");
        let target = target_install.entry.actor;
        let target_deployment = target_install.entry.deployment;
        let request = suspend(target, target_deployment);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let last_sequence = MAX_AUTHORITY_DISPOSITIONS as u64 + 45;
        for sequence in 2..=last_sequence {
            assert_eq!(
                runtime.apply(authorized(
                    &config,
                    credential(sequence),
                    sequence,
                    (sequence % 251) as u8 + 1,
                    request.clone(),
                )),
                Err(LifecycleError::NotFound)
            );
        }

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.authority_sequence_high_water, Some(last_sequence));
        assert_eq!(
            snapshot.authority_dispositions.len(),
            MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(snapshot.authority_dispositions[0].sequence, 46);
        assert_eq!(
            snapshot
                .authority_dispositions
                .last()
                .map(|item| item.sequence),
            Some(last_sequence)
        );

        let encoded = super::super::wire::encode_standard_runtime_state(&snapshot);
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        apply_authorized(
            &mut reopened,
            &config,
            LifecycleRequest::Install(target_install),
        )
        .unwrap();
        assert_eq!(
            reopened.apply(authorized(&config, credential(1), 1, 2, request.clone())),
            Err(LifecycleError::AuthoritySequenceRegressed),
            "an evicted sequence remains consumed by the global high-water"
        );
        assert!(!reopened.actor(target).unwrap().suspended);
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential(47),
                47,
                (47 % 251) as u8 + 1,
                request.clone(),
            )),
            Err(LifecycleError::NotFound),
            "a retained exact refusal is still recoverable"
        );
        assert!(
            !reopened.actor(target).unwrap().suspended,
            "recovering a retained refusal must not reapply a now-valid request"
        );
        assert_eq!(
            reopened.apply(authorized(
                &config,
                credential(last_sequence + 2),
                last_sequence,
                (last_sequence % 251) as u8 + 1,
                request.clone(),
            )),
            Err(LifecycleError::AuthoritySequenceConflict),
            "a different credential cannot reuse a retained global sequence"
        );
        assert!(matches!(
            reopened.apply(authorized(
                &config,
                credential(last_sequence + 2),
                last_sequence + 2,
                7,
                request,
            )),
            Ok(LifecycleReply::Suspended(entry)) if entry.actor == target
        ));
    }

    #[test]
    fn restore_requires_the_journal_tail_to_match_the_global_high_water() {
        let config = config(8);
        let request = suspend(ActorId([0xb5; 32]), DeploymentId([0xb7; 32]));
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        assert_eq!(
            runtime.apply(authorized(&config, CredentialId([0xb6; 32]), 2, 2, request,)),
            Err(LifecycleError::NotFound)
        );

        let mut snapshot = runtime.snapshot();
        snapshot.authority_sequence_high_water = Some(3);
        assert!(matches!(
            StandardAgentRuntime::restore(snapshot),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut transient = StandardAgentRuntime::new();
        transient
            .apply_mutation(LifecycleRequest::Create(config))
            .unwrap();
        assert!(
            matches!(
                StandardAgentRuntime::restore(transient.snapshot()),
                Err(LifecycleError::InvalidRequest)
            ),
            "a durable created state must retain its authorized Create tail"
        );
    }

    #[test]
    fn authorized_create_is_durable_and_exactly_retryable() {
        let config = config(8);
        let credential = CredentialId([0x64; 32]);
        let request = LifecycleRequest::Create(config.clone());
        let mut runtime = StandardAgentRuntime::new();
        let created = runtime
            .apply(authorized_at(
                &config,
                credential,
                1,
                30,
                1,
                request.clone(),
            ))
            .unwrap();
        assert_eq!(created, LifecycleReply::Created(config.identity.clone()));

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened
                .apply(authorized_at(&config, credential, 1, 31, 1, request,))
                .unwrap(),
            created
        );
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(31));
    }

    #[test]
    fn runtime_upgrade_retry_preserves_the_signed_from_deployment() {
        let config = config(8);
        let credential = CredentialId([0x74; 32]);
        let request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0x75; 32]),
            to_program: ProgramId([0x76; 32]),
            producer: ProducerId([0x77; 32]),
            package: crate::service::BlobRef {
                hash: Hash([0x78; 32]),
                len: 10,
            },
            contract: config.runtime_contract,
            capabilities: config.capabilities,
        };
        let mut reused_signer_request = request.clone();
        let LifecycleRequest::UpgradeRuntime { producer, .. } = &mut reused_signer_request else {
            unreachable!();
        };
        *producer = config.identity.transition_producer;
        let mut rejecting_runtime = StandardAgentRuntime::new();
        create_authorized(&mut rejecting_runtime, &config, 1).unwrap();
        assert_eq!(
            rejecting_runtime.apply(authorized(
                &config,
                CredentialId([0x73; 32]),
                2,
                2,
                reused_signer_request,
            )),
            Err(LifecycleError::UnsupportedRuntime),
        );

        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let upgraded = runtime
            .apply(authorized(&config, credential, 2, 2, request.clone()))
            .unwrap();
        assert!(matches!(
            &upgraded,
            LifecycleReply::RuntimeUpgraded(identity)
                if identity.runtime_deployment == DeploymentId([0x75; 32])
                    && identity.transition_producer == config.identity.transition_producer
        ));

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.config().unwrap().identity.transition_producer,
            config.identity.transition_producer,
        );
        assert_eq!(
            reopened
                .apply(authorized(&config, credential, 2, 2, request))
                .unwrap(),
            upgraded,
            "retry uses the exact signed old-to-new request, not current-to-new"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn signed_method_policy_is_authoritative_before_actor_dispatch() {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::wire::ServiceWire as _;
        use crate::service::{
            CapabilityId, MethodPolicy, Origin, PackageRolePolicies, SubjectId,
            method_authorization_policy_hash,
        };

        let config = config(4);
        let agent = config.identity.agent;
        let capability = CapabilityId::named("board.moderate");
        let policies = PackageRolePolicies {
            methods: vec![
                MethodPolicy {
                    method: "maintenance".into(),
                    schema: Hash([0x50; 32]),
                    policy: method_authorization_policy_hash(Some(capability), None, None).unwrap(),
                    public: false,
                    attested: false,
                    space_role: None,
                    capability: Some(capability),
                    actor_role: None,
                },
                MethodPolicy {
                    method: "set_title".into(),
                    schema: Hash([0x51; 32]),
                    policy: method_authorization_policy_hash(Some(capability), None, Some(7))
                        .unwrap(),
                    public: false,
                    attested: false,
                    space_role: None,
                    capability: Some(capability),
                    actor_role: Some(7),
                },
            ],
            task_dependencies: Vec::new(),
        }
        .encode();
        let policy_blob = super::super::execution::RuntimeBlob {
            reference: BlobRef::of_bytes(&policies),
            bytes: policies,
        };

        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut installed = install(agent, None, "board");
        installed.entry.role_policies = policy_blob.reference.clone();
        installed.role_policies = policy_blob.reference.clone();
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();
        let incarnation = runtime.actors[&actor].record.state_generation;

        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("set_title").encode());
        let mut invocation = super::super::execution::ActorInvocation {
            invocation: InvocationId([0x52; 32]),
            actor,
            incarnation,
            deployment,
            program,
            mode: super::super::MethodMode::Linear,
            auth: super::super::execution::ActorInvocationAuth {
                origin: Origin::Member(SubjectId([0x53; 32])),
                principal: Some(crate::service::PrincipalId([0x54; 32])),
                origin_service: None,
                space_role: None,
                actor_role: Some(7),
                capability: Some(capability),
            },
            message,
            availability: Vec::new(),
            gas: 1,
        };
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(true)
        );

        invocation.auth.capability = Some(CapabilityId::named("board.read"));
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        // Public message bytes cannot forge the private caller context: even
        // role/capability fields paired with Anonymous remain unauthorized.
        invocation.auth.origin = Origin::Anonymous;
        invocation.auth.capability = Some(capability);
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        let mut system_message = vec![TAG_DYNAMIC];
        system_message.extend_from_slice(&Msg::new("maintenance").encode());
        invocation.message = system_message;
        invocation.auth = super::super::execution::ActorInvocationAuth {
            origin: Origin::System,
            principal: None,
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: Some(capability),
        };
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(true)
        );
        invocation.auth.capability = Some(CapabilityId::named("board.read"));
        assert_eq!(
            runtime.authorize_execution(&invocation, &policy_blob),
            Ok(false)
        );

        let corrupt = b"not-a-policy-set".to_vec();
        let corrupt_blob = super::super::execution::RuntimeBlob {
            reference: BlobRef::of_bytes(&corrupt),
            bytes: corrupt,
        };
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            corrupt_blob.reference.clone();
        assert_eq!(
            runtime.authorize_execution(&invocation, &corrupt_blob),
            Err(super::super::execution::ActorExecutionError::InvalidAvailability)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_execution_artifacts_use_sdk_wires_and_hash_domains() {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::agent_sdk::method_policy::{
            ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
            AuthorizationPolicySelector, IdempotencyRequirement,
        };
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
            ParsedStorageField,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            BlobRef as CleanBlobRef, FieldPersistence, MethodMode as CleanMethodMode,
            RoleId as CleanRoleId, StateLane as CleanStateLane,
        };

        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: vec![
                ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "value".into(),
                    type_identity: "core::primitive::u8".into(),
                    persistence: FieldPersistence::State(CleanStateLane::Linear),
                }),
                ParsedField::Storage(ParsedStorageField {
                    source_index: 1,
                    name: "rows".into(),
                    type_identity: "test::StorageMap<u32,u64>".into(),
                    prefix: b"rows/".to_vec(),
                    lane: CleanStateLane::Linear,
                    committed: false,
                    leaf_domain: None,
                    node_domain: None,
                }),
            ],
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: CleanMethodMode::Linear,
                explicit: true,
            }],
        };
        let schema_bytes = schema.encode().unwrap();
        let clean_schema_ref = CleanBlobRef::of_bytes(&schema_bytes);
        let schema_blob = crate::agent_sdk::RuntimeBlob {
            reference: clean_schema_ref.clone(),
            bytes: schema_bytes,
        };
        let policy_blob = |actor_schema: &CleanBlobRef, authorization_policy| {
            let bytes = ActorMethodPolicyArtifact {
                actor_schema: actor_schema.clone(),
                methods: vec![ActorMethodPolicy {
                    name: "write".into(),
                    mode: CleanMethodMode::Linear,
                    arguments: Vec::new(),
                    return_type_identity: "core::primitive::u8".into(),
                    authorization_policy,
                    idempotency: IdempotencyRequirement::Required,
                    attestation: AttestationRequirement::None,
                }],
            }
            .encode()
            .unwrap();
            let reference = CleanBlobRef::of_bytes(&bytes);
            crate::agent_sdk::RuntimeBlob { reference, bytes }
        };
        let public_policy = policy_blob(&clean_schema_ref, AuthorizationPolicySelector::Public);

        let config = config(4);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut installed = install(config.identity.agent, None, "counter");
        installed.entry.agent_schema = clean_blob_to_legacy(&schema_blob.reference);
        installed.agent_schema = clean_blob_to_legacy(&schema_blob.reference);
        installed.entry.role_policies = clean_blob_to_legacy(&public_policy.reference);
        installed.role_policies = clean_blob_to_legacy(&public_policy.reference);
        let state_layout = Hash(schema.state_layout_hash().unwrap().0);
        installed.entry.state_layout = state_layout;
        installed.state_layout = state_layout;
        let actor = installed.entry.actor;
        let deployment = installed.entry.deployment;
        let program = installed.entry.program;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();

        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("write").encode());
        let mut work = crate::agent_sdk::InvocationWork {
            space: crate::agent_sdk::SpaceId(config.identity.space.0),
            agent: crate::agent_sdk::AgentId(config.identity.agent.0),
            runtime_deployment: crate::agent_sdk::DeploymentId(
                config.identity.runtime_deployment.0,
            ),
            invocation: crate::agent_sdk::InvocationId([0x62; 32]),
            actor: crate::agent_sdk::ActorId(actor.0),
            incarnation: crate::agent_sdk::Hash(runtime.actors[&actor].record.state_generation.0),
            deployment: crate::agent_sdk::DeploymentId(deployment.0),
            program: crate::agent_sdk::ProgramId(program.0),
            mode: CleanMethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message,
            availability: Vec::new(),
            gas: 1,
            installation_data: None,
            recovery_only: false,
        };
        assert_eq!(
            runtime.validate_clean_execution_schema(&work, &schema_blob),
            Ok(())
        );
        // The runtime-derived scope permits only the installed namespace.
        let access = runtime
            .resolve_clean_storage_access(&work, &schema_blob)
            .unwrap();
        let mut image = super::super::actor_storage::ActorLaneImage::default();
        access
            .write(
                CleanStateLane::Linear,
                &mut image,
                b"rows/one".to_vec(),
                Some(vec![7]),
            )
            .unwrap();
        assert_eq!(
            access.read(CleanStateLane::Linear, &image, b"rows/one"),
            Ok(Some(&[7][..]))
        );
        assert_eq!(
            access.write(
                CleanStateLane::Linear,
                &mut image,
                b"other/one".to_vec(),
                Some(vec![8])
            ),
            Err(super::super::actor_storage::StorageAccessError::UndeclaredNamespace)
        );
        for (field, expected) in [
            (
                0,
                super::super::execution::ActorExecutionError::StaleIncarnation,
            ),
            (
                1,
                super::super::execution::ActorExecutionError::StaleDeployment,
            ),
            (
                2,
                super::super::execution::ActorExecutionError::WrongProgram,
            ),
            (3, super::super::execution::ActorExecutionError::NotFound),
            (
                4,
                super::super::execution::ActorExecutionError::UnsupportedMethod,
            ),
        ] {
            let mut forged = work.clone();
            match field {
                0 => forged.incarnation.0[0] ^= 1,
                1 => forged.deployment.0[0] ^= 1,
                2 => forged.program.0[0] ^= 1,
                3 => forged.actor.0[0] ^= 1,
                _ => forged.mode = CleanMethodMode::Local,
            }
            assert_eq!(
                runtime
                    .resolve_clean_storage_access(&forged, &schema_blob)
                    .err(),
                Some(expected)
            );
        }
        // A self-consistent replacement blob is not the installed commitment.
        let mut substituted = schema.clone();
        let ParsedField::Storage(field) = &mut substituted.fields[1] else {
            unreachable!()
        };
        field.prefix = b"other/".to_vec();
        let bytes = substituted.encode().unwrap();
        let replacement = crate::agent_sdk::RuntimeBlob {
            reference: CleanBlobRef::of_bytes(&bytes),
            bytes,
        };
        assert!(replacement.validate());
        assert_eq!(
            runtime
                .resolve_clean_storage_access(&work, &replacement)
                .err(),
            Some(super::super::execution::ActorExecutionError::InvalidAvailability)
        );
        assert_eq!(
            runtime.validate_clean_execution_installation_data(&work, None),
            Ok(())
        );
        let public_authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 1),
        );
        assert_eq!(
            runtime.authorize_clean_execution(
                &work,
                &public_authorization,
                &schema_blob,
                &public_policy,
            ),
            Ok(true)
        );
        work.origin.principal = Some(crate::agent_sdk::PrincipalId([0x60; 32]));
        work.roles.space = Some(CleanRoleId([0x61; 32]));
        assert_eq!(
            runtime.authorize_clean_execution(
                &work,
                &public_authorization,
                &schema_blob,
                &public_policy,
            ),
            Ok(false),
            "AMP2 Public means no role or capability claim"
        );
        work.roles = crate::agent_sdk::InvocationRoleClaims::none();
        work.origin.principal = None;
        work.origin.capability = Some(crate::agent_sdk::CapabilityId([0x62; 32]));
        assert_eq!(
            runtime.authorize_clean_execution(
                &work,
                &public_authorization,
                &schema_blob,
                &public_policy,
            ),
            Ok(false),
            "AMP2 Public cannot ignore a capability claim"
        );
        work.origin.capability = None;
        let public_authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 1),
        );

        let mut tampered_schema = schema_blob.clone();
        *tampered_schema.bytes.last_mut().unwrap() ^= 1;
        assert_eq!(
            runtime.validate_clean_execution_schema(&work, &tampered_schema),
            Err(super::super::execution::ActorExecutionError::InvalidAvailability)
        );

        let mut other_schema = schema.clone();
        let ParsedField::Inline(field) = &mut other_schema.fields[0] else {
            unreachable!()
        };
        field.name = "other_value".into();
        let other_schema_ref = CleanBlobRef::of_bytes(&other_schema.encode().unwrap());
        let mismatched_policy = policy_blob(&other_schema_ref, AuthorizationPolicySelector::Public);
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            clean_blob_to_legacy(&mismatched_policy.reference);
        assert_eq!(
            runtime.authorize_clean_execution(
                &work,
                &public_authorization,
                &schema_blob,
                &mismatched_policy,
            ),
            Err(super::super::execution::ActorExecutionError::InvalidAvailability),
            "AMP2 must close over the exact supplied AAS2 preimage"
        );

        let capability = crate::agent_sdk::CapabilityId([0x63; 32]);
        let capability_policy = policy_blob(
            &clean_schema_ref,
            AuthorizationPolicySelector::Capability(capability),
        );
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            clean_blob_to_legacy(&capability_policy.reference);
        let public_authorization = crate::agent_sdk::InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(&work, 1),
        );
        assert_eq!(
            runtime.authorize_clean_execution(
                &work,
                &public_authorization,
                &schema_blob,
                &capability_policy,
            ),
            Ok(false),
            "an unsigned PublicPreflight cannot select a non-Public AMP2 method",
        );
        work.origin.capability = Some(capability);
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &capability_policy),
            Ok(true)
        );
        work.origin.capability = Some(crate::agent_sdk::CapabilityId([0x64; 32]));
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &capability_policy),
            Ok(false)
        );

        work.origin.capability = None;
        work.origin.principal = Some(crate::agent_sdk::PrincipalId([0x65; 32]));
        let space_role = CleanRoleId([0x66; 32]);
        let space_policy = policy_blob(
            &clean_schema_ref,
            AuthorizationPolicySelector::SpaceRole(space_role),
        );
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            clean_blob_to_legacy(&space_policy.reference);
        work.roles.space = Some(space_role);
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &space_policy),
            Ok(true)
        );
        work.roles.space = Some(CleanRoleId([0x67; 32]));
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &space_policy),
            Ok(false)
        );

        let actor_role = CleanRoleId([0x68; 32]);
        let actor_policy = policy_blob(
            &clean_schema_ref,
            AuthorizationPolicySelector::ActorRole(actor_role),
        );
        runtime.actors.get_mut(&actor).unwrap().record.role_policies =
            clean_blob_to_legacy(&actor_policy.reference);
        work.roles.space = None;
        work.roles.actor = Some(actor_role);
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &actor_policy),
            Ok(true)
        );
        work.roles.actor = None;
        work.roles.space = Some(actor_role);
        let signed = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &work),
        );
        assert_eq!(
            runtime.authorize_clean_execution(&work, &signed, &schema_blob, &actor_policy),
            Ok(false),
            "equal role bytes in a different scope must not authorize"
        );
    }

    #[test]
    fn install_rejects_directory_provenance_mismatch() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.agent_schema.hash = Hash([0x44; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.state_layout = Hash([0x45; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.package.hash = Hash([0x46; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );

        let mut mismatched = install(agent, None, "counter");
        mismatched.entry.role_policies.hash = Hash([0x47; 32]);
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(mismatched)),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn create_cannot_overstate_standard_runtime_capabilities() {
        let oversized = config(super::super::RuntimeCapabilities::STANDARD_MAX_ACTORS + 1);
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &oversized, 1),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());

        let mut proof_capable = config(1);
        proof_capable.capabilities.proofs = true;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &proof_capable, 1),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());
    }

    #[test]
    fn create_enforces_signed_aggregate_and_global_per_reference_artifact_limits() {
        let mut aggregate = config(1);
        aggregate
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = aggregate.runtime_package.len - 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply_mutation(LifecycleRequest::Create(aggregate)),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.config().is_none());

        let mut per_reference = config(1);
        per_reference.runtime_package.len = super::super::MAX_CATALOG_ARTIFACT_BYTES + 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            runtime.apply_mutation(LifecycleRequest::Create(per_reference)),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.config().is_none());
    }

    #[test]
    fn install_counts_unique_exact_references_and_rejects_ambiguous_lengths() {
        let mut bounded = config(8);
        bounded.runtime_contract.resources.max_artifact_references = 4;
        bounded
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 400;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &bounded, 1).unwrap();
        apply_authorized(
            &mut runtime,
            &bounded,
            LifecycleRequest::Install(install(bounded.identity.agent, None, "first")),
        )
        .unwrap();
        apply_authorized(
            &mut runtime,
            &bounded,
            LifecycleRequest::Install(install(bounded.identity.agent, None, "shared")),
        )
        .unwrap();
        assert_eq!(runtime.len(), 2, "exact cross-actor references deduplicate");

        let mut fifth = install(bounded.identity.agent, None, "fifth-ref");
        let package = BlobRef {
            hash: Hash([0x91; 32]),
            len: 100,
        };
        fifth.entry.package = package.clone();
        fifth.package = package;
        assert_eq!(
            apply_authorized(&mut runtime, &bounded, LifecycleRequest::Install(fifth)),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.len(), 2);

        let mut ambiguous_config = config(2);
        ambiguous_config
            .runtime_contract
            .resources
            .max_artifact_references = 4;
        ambiguous_config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 1_000;
        let mut ambiguous_runtime = StandardAgentRuntime::new();
        create_authorized(&mut ambiguous_runtime, &ambiguous_config, 1).unwrap();
        let mut ambiguous = install(ambiguous_config.identity.agent, None, "ambiguous");
        let package = BlobRef {
            hash: ambiguous_config.runtime_package.hash,
            len: ambiguous_config.runtime_package.len + 1,
        };
        ambiguous.entry.package = package.clone();
        ambiguous.package = package;
        assert_eq!(
            apply_authorized(
                &mut ambiguous_runtime,
                &ambiguous_config,
                LifecycleRequest::Install(ambiguous)
            ),
            Err(LifecycleError::InvalidRequest)
        );
        assert!(ambiguous_runtime.is_empty());
    }

    #[test]
    fn install_exact_duplicates_charge_once_at_the_one_reference_boundary() {
        let mut config = config(1);
        config.runtime_contract.resources.max_artifact_references = 1;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = config.runtime_package.len;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut actor = install(config.identity.agent, None, "one-blob");
        set_install_artifacts(
            &mut actor,
            config.runtime_package.clone(),
            config.runtime_package.clone(),
            config.runtime_package.clone(),
        );
        assert!(apply_authorized(&mut runtime, &config, LifecycleRequest::Install(actor)).is_ok());
        assert_eq!(runtime.len(), 1);
    }

    #[test]
    fn actor_upgrade_keeps_globally_shared_old_references_charged() {
        let mut config = config(4);
        config.runtime_contract.resources.max_artifact_references = 6;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 1_000;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let first = install(config.identity.agent, None, "first-sharer");
        let first_entry = first.entry.clone();
        let second = install(config.identity.agent, None, "second-sharer");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(first)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(second)).unwrap();

        let upgrade = UpgradeActor {
            actor: first_entry.actor,
            from_deployment: first_entry.deployment,
            to_deployment: DeploymentId([0x92; 32]),
            to_program: first_entry.program,
            producer: ProducerId([0x93; 32]),
            package: BlobRef {
                hash: Hash([0x94; 32]),
                len: 100,
            },
            agent_schema: BlobRef {
                hash: Hash([0x95; 32]),
                len: 100,
            },
            role_policies: BlobRef {
                hash: Hash([0x96; 32]),
                len: 100,
            },
            constructor_abi: first_entry.constructor_abi,
            state_layout: first_entry.state_layout,
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: first_entry.lanes,
                scheduling: false,
                proofs: false,
            },
        };
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(upgrade)
            ),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.actor(first_entry.actor), Some(&first_entry));
        assert_eq!(runtime.len(), 2);
    }

    #[test]
    fn runtime_upgrade_uses_target_artifact_and_intrinsic_capacity_limits() {
        let mut config = config(8);
        config.runtime_contract.resources.max_artifact_references = 4;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 400;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::Install(install(config.identity.agent, None, "resident")),
        )
        .unwrap();

        let mut lower = config.runtime_contract;
        lower.resources.max_artifact_referenced_bytes = 399;
        let lower_request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0xa1; 32]),
            to_program: ProgramId([0xa2; 32]),
            producer: ProducerId([0xa3; 32]),
            package: BlobRef {
                hash: Hash([0xa4; 32]),
                len: 100,
            },
            contract: lower,
            capabilities: config.capabilities,
        };
        assert_eq!(
            apply_authorized(&mut runtime, &config, lower_request),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(
            runtime.config().unwrap().identity.runtime_deployment,
            config.identity.runtime_deployment
        );

        let mut excessive_capabilities = config.capabilities;
        excessive_capabilities.max_actors = RuntimeCapabilities::STANDARD_MAX_ACTORS + 1;
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: config.identity.runtime_deployment,
                    to_deployment: DeploymentId([0xa5; 32]),
                    to_program: ProgramId([0xa6; 32]),
                    producer: ProducerId([0xa7; 32]),
                    package: BlobRef {
                        hash: Hash([0xa8; 32]),
                        len: 100,
                    },
                    contract: config.runtime_contract,
                    capabilities: excessive_capabilities,
                }
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut unbacked_proofs = config.capabilities;
        unbacked_proofs.proofs = true;
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: config.identity.runtime_deployment,
                    to_deployment: DeploymentId([0xb5; 32]),
                    to_program: ProgramId([0xb6; 32]),
                    producer: ProducerId([0xb7; 32]),
                    package: BlobRef {
                        hash: Hash([0xb8; 32]),
                        len: 100,
                    },
                    contract: config.runtime_contract,
                    capabilities: unbacked_proofs,
                },
            ),
            Err(LifecycleError::UnsupportedRuntime),
            "legacy runtime upgrades cannot mint an untyped outer proof capability",
        );

        let mut higher = config.runtime_contract;
        higher.resources.max_artifact_referenced_bytes = 500;
        let upgraded = apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeRuntime {
                from_deployment: config.identity.runtime_deployment,
                to_deployment: DeploymentId([0xa9; 32]),
                to_program: ProgramId([0xaa; 32]),
                producer: ProducerId([0xab; 32]),
                package: BlobRef {
                    hash: Hash([0xac; 32]),
                    len: 200,
                },
                contract: higher,
                capabilities: config.capabilities,
            },
        )
        .unwrap();
        assert!(matches!(
            upgraded,
            LifecycleReply::RuntimeUpgraded(identity)
                if identity.runtime_deployment == DeploymentId([0xa9; 32])
        ));
    }

    #[test]
    fn indexed_restore_preserves_forest_and_cross_actor_validation() {
        let config = config(64);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut parents = [None; 8];
        for index in 0..64 {
            let branch = index % parents.len();
            let request = install(
                config.identity.agent,
                parents[branch],
                &alloc::format!("node-{index}"),
            );
            parents[branch] = Some(request.entry.actor);
            runtime.install(request, Hash([0xb5; 32])).unwrap();
        }
        let snapshot = runtime.snapshot();
        assert!(
            snapshot.actors.iter().enumerate().any(|(index, actor)| {
                actor.record.entry.parent.is_some_and(|parent| {
                    snapshot.actors[index + 1..]
                        .iter()
                        .any(|later| later.record.entry.actor == parent)
                })
            }),
            "fixture must include children sorted before their parents"
        );
        let restored = StandardAgentRuntime::restore(snapshot.clone()).unwrap();
        assert_eq!(restored.snapshot(), snapshot);

        let mut duplicate = snapshot.clone();
        duplicate.actors[1].record.installation_id = duplicate.actors[0].record.installation_id;
        assert!(matches!(
            StandardAgentRuntime::restore(duplicate),
            Err(LifecycleError::InvalidRequest)
        ));

        // Identical references are shared by all actors. A conflicting length
        // on a later actor must still be rejected by incremental accounting.
        let mut ambiguous = snapshot.clone();
        ambiguous.actors[1].record.package.len += 1;
        ambiguous.actors[1].record.entry.package.len += 1;
        assert!(matches!(
            StandardAgentRuntime::restore(ambiguous),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut cycle = snapshot;
        let actor = cycle.actors[0].record.entry.actor;
        cycle.actors[0].record.entry.parent = Some(actor);
        assert!(matches!(
            StandardAgentRuntime::restore(cycle),
            Err(LifecycleError::InvalidRequest)
        ));
    }

    #[test]
    fn restore_recomputes_signed_artifact_closure_and_state_limits() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        runtime
            .install(
                install(config.identity.agent, None, "restored"),
                Hash([0xb1; 32]),
            )
            .unwrap();
        let snapshot = runtime.snapshot();

        let mut artifact_overflow = snapshot.clone();
        artifact_overflow
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = 399;
        assert!(matches!(
            StandardAgentRuntime::restore(artifact_overflow),
            Err(LifecycleError::ResourceLimit)
        ));

        let mut ambiguous = snapshot.clone();
        let runtime_reference = ambiguous.config.as_ref().unwrap().runtime_package.clone();
        let package = BlobRef {
            hash: runtime_reference.hash,
            len: runtime_reference.len + 1,
        };
        ambiguous.actors[0].record.entry.package = package.clone();
        ambiguous.actors[0].record.package = package;
        assert!(matches!(
            StandardAgentRuntime::restore(ambiguous),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut state_overflow = snapshot;
        let encoded_len = super::super::wire::encode_standard_runtime_state(&state_overflow)
            .encoded_len()
            .unwrap();
        state_overflow
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = u32::try_from(encoded_len - 1).unwrap();
        assert!(matches!(
            StandardAgentRuntime::restore(state_overflow),
            Err(LifecycleError::ResourceLimit)
        ));
    }

    #[test]
    fn restore_revalidates_installation_data_forest_debt_and_suspension_invariants() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let mut parent = install(config.identity.agent, None, "parent");
        set_installation_data(&mut parent, Vec::new());
        let parent_id = parent.entry.actor;
        runtime.install(parent, Hash([0xe1; 32])).unwrap();
        let child = install(config.identity.agent, Some(parent_id), "child");
        runtime.install(child, Hash([0xe2; 32])).unwrap();
        let snapshot = runtime.snapshot();
        assert!(StandardAgentRuntime::restore(snapshot.clone()).is_ok());

        let mut missing_parent = snapshot.clone();
        missing_parent
            .actors
            .retain(|actor| actor.record.entry.actor != parent_id);
        assert!(matches!(
            StandardAgentRuntime::restore(missing_parent),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut forged_children = snapshot.clone();
        forged_children
            .actors
            .iter_mut()
            .find(|actor| actor.record.entry.actor == parent_id)
            .unwrap()
            .debt
            .children += 1;
        assert!(matches!(
            StandardAgentRuntime::restore(forged_children),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut suspended_parent = snapshot.clone();
        suspended_parent
            .actors
            .iter_mut()
            .find(|actor| actor.record.entry.actor == parent_id)
            .unwrap()
            .record
            .entry
            .suspended = true;
        assert!(
            StandardAgentRuntime::restore(suspended_parent.clone()).is_ok(),
            "suspending a non-leaf actor is a legal live-runtime state"
        );
        let parent = suspended_parent
            .actors
            .iter()
            .find(|actor| actor.record.entry.actor == parent_id)
            .unwrap();
        let request = Hash([0xe3; 32]);
        suspended_parent
            .machine_continuations
            .push(StandardMachineContinuation {
                invocation: InvocationId([0xe4; 32]),
                actor: parent_id,
                incarnation: parent.record.state_generation,
                deployment: parent.record.entry.deployment,
                program: parent.record.entry.program,
                mode: super::super::MethodMode::Query,
                request,
                work: request,
                ready_sequence: 1,
                accepted: None,
                authorization: None,
                observed_slot: 1,
                continuation: super::super::execution::ActorMachineContinuation {
                    machine: super::super::execution::PortableMachineSnapshot {
                        pc: 0,
                        gas_remaining: 1,
                        registers: [0; vos_pvm_program::REGISTER_COUNT],
                        memory: Vec::new(),
                    },
                    fetch_index: 0,
                    host_budget: super::super::execution::ActorHostBudget::default(),
                },
            });
        assert!(matches!(
            StandardAgentRuntime::restore(suspended_parent),
            Err(LifecycleError::InvalidRequest)
        ));

        let mut aliased_data = snapshot;
        let parent = aliased_data
            .actors
            .iter_mut()
            .find(|actor| actor.record.entry.actor == parent_id)
            .unwrap();
        parent.record.installation_data = Some(parent.record.package.clone());
        parent.record.entry.installation_data = parent.record.installation_data.clone();
        assert!(matches!(
            StandardAgentRuntime::restore(aliased_data),
            Err(LifecycleError::InvalidRequest)
        ));
    }

    #[test]
    fn authorized_resource_refusal_is_atomic_consumed_and_exactly_retryable() {
        let mut config = config(2);
        config.runtime_contract.resources.max_artifact_references = 1;
        config
            .runtime_contract
            .resources
            .max_artifact_referenced_bytes = config.runtime_package.len;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let before_config = runtime.config().unwrap().clone();
        let request =
            LifecycleRequest::Install(install(config.identity.agent, None, "over-signed-limit"));
        let signed = authorized(&config, CredentialId([0xb2; 32]), 2, 2, request);

        assert_eq!(
            runtime.apply(signed.clone()),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.is_empty());
        assert_eq!(runtime.config(), Some(&before_config));
        assert_eq!(runtime.authority_sequence_high_water, Some(2));
        assert_eq!(runtime.authority_slot_high_water, Some(100));
        assert_eq!(
            runtime
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
        let disposition_count = runtime.authority_dispositions.len();

        let encoded = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let decoded = super::super::wire::decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(
            decoded
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            reopened.apply(signed),
            Err(LifecycleError::ResourceLimit),
            "an exact retry recovers the retained refusal without rechecking resources"
        );
        assert!(reopened.is_empty());
        assert_eq!(reopened.config(), Some(&before_config));
        assert_eq!(reopened.authority_sequence_high_water, Some(2));
        assert_eq!(reopened.authority_dispositions.len(), disposition_count);
    }

    #[test]
    fn every_authorized_outcome_reserves_its_exact_signed_state_bytes() {
        let config = config(2);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let current_bytes = super::super::wire::encode_standard_runtime_state(&runtime.snapshot())
            .encoded_len()
            .unwrap();
        runtime
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = u32::try_from(current_bytes).unwrap();

        let request = LifecycleRequest::Install(install(
            config.identity.agent,
            None,
            "state-capacity-refusal",
        ));
        let signed = authorized(&config, CredentialId([0xb7; 32]), 2, 2, request);
        assert_eq!(
            runtime.apply(signed.clone()),
            Err(LifecycleError::ResourceLimit)
        );
        assert!(runtime.is_empty(), "the actor install must roll back");
        assert_eq!(runtime.authority_sequence_high_water, Some(2));
        assert_eq!(runtime.authority_slot_high_water, Some(100));
        assert_eq!(runtime.authority_dispositions.len(), 1);
        assert_eq!(runtime.authority_dispositions[0].sequence, 2);
        assert_eq!(
            runtime.authority_dispositions[0].result,
            Err(LifecycleError::ResourceLimit),
            "the oldest disposition supplies bounded headroom for the exact refusal"
        );
        assert!(
            super::super::wire::encode_standard_runtime_state(&runtime.snapshot())
                .encoded_len()
                .unwrap()
                <= current_bytes
        );

        let mut reopened = StandardAgentRuntime::restore(runtime.snapshot()).unwrap();
        assert_eq!(reopened.apply(signed), Err(LifecycleError::ResourceLimit));
        assert_eq!(reopened.authority_dispositions.len(), 1);

        let next = authorized(
            &config,
            CredentialId([0xb8; 32]),
            3,
            3,
            LifecycleRequest::Install(install(
                config.identity.agent,
                None,
                "second-state-capacity-refusal",
            )),
        );
        assert_eq!(reopened.apply(next), Err(LifecycleError::ResourceLimit));
        assert_eq!(reopened.authority_sequence_high_water, Some(3));
        assert_eq!(reopened.authority_dispositions.len(), 1);
        assert_eq!(reopened.authority_dispositions[0].sequence, 3);
        assert_eq!(
            reopened.apply(authorized(
                &config,
                CredentialId([0xb7; 32]),
                2,
                2,
                LifecycleRequest::Install(install(
                    config.identity.agent,
                    None,
                    "state-capacity-refusal",
                )),
            )),
            Err(LifecycleError::AuthoritySequenceRegressed),
            "evicted capacity refusals retain the global anti-replay high-water"
        );
    }

    #[test]
    fn undersized_create_refuses_without_publishing_a_partial_agent() {
        let mut config = config(1);
        config.runtime_contract.resources.max_runtime_state_bytes = 1;
        let mut runtime = StandardAgentRuntime::new();
        assert_eq!(
            create_authorized(&mut runtime, &config, 1),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(runtime.snapshot(), StandardRuntimeState::default());
    }

    #[test]
    fn runtime_upgrade_reserves_target_state_bytes_for_its_exact_disposition() {
        let config = config(1);
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let package = BlobRef {
            hash: Hash([0xb3; 32]),
            len: 100,
        };
        let mut direct = runtime.clone();
        direct
            .upgrade_runtime(
                config.identity.runtime_deployment,
                DeploymentId([0xb4; 32]),
                ProgramId([0xb5; 32]),
                ProducerId([0xb6; 32]),
                package.clone(),
                config.runtime_contract,
                config.capabilities,
                false,
            )
            .unwrap();
        let direct_bytes = super::super::wire::encode_standard_runtime_state(&direct.snapshot())
            .encoded_len()
            .unwrap();
        let mut target_contract = config.runtime_contract;
        target_contract.resources.max_runtime_state_bytes = u32::try_from(direct_bytes).unwrap();
        let request = LifecycleRequest::UpgradeRuntime {
            from_deployment: config.identity.runtime_deployment,
            to_deployment: DeploymentId([0xb4; 32]),
            to_program: ProgramId([0xb5; 32]),
            producer: ProducerId([0xb6; 32]),
            package,
            contract: target_contract,
            capabilities: config.capabilities,
        };
        assert_eq!(
            apply_authorized(&mut runtime, &config, request),
            Err(LifecycleError::ResourceLimit)
        );
        assert_eq!(
            runtime.config().unwrap().identity.runtime_deployment,
            config.identity.runtime_deployment,
            "the semantic upgrade rolls back while its exact refusal is retained"
        );
        assert_eq!(
            runtime
                .authority_dispositions
                .last()
                .map(|item| &item.result),
            Some(&Err(LifecycleError::ResourceLimit))
        );
    }

    #[test]
    fn install_rejects_proof_and_scheduler_requirements_before_state_changes() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();

        let mut proof = install(agent, None, "attested");
        proof.requirements.proofs = true;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(proof)),
            Err(LifecycleError::UnsupportedRuntime)
        );

        let mut job = install(agent, None, "scheduled");
        job.requirements.scheduling = true;
        assert_eq!(
            apply_authorized(&mut runtime, &config, LifecycleRequest::Install(job)),
            Err(LifecycleError::UnsupportedRuntime)
        );
        assert!(runtime.is_empty());
    }

    #[test]
    fn actor_forest_has_no_privileged_root_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let first = install(agent, None, "first");
        let second = install(agent, None, "second");
        let child = install(agent, Some(first.entry.actor), "child");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(first)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(second)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(child)).unwrap();
        assert_eq!(runtime.len(), 3);
    }

    #[test]
    fn safe_removal_requires_a_leaf_with_no_durable_debt() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let parent = install(agent, None, "parent");
        let parent_id = parent.entry.actor;
        let deployment = parent.entry.deployment;
        let child = install(agent, Some(parent_id), "child");
        let child_id = child.entry.actor;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(parent)).unwrap();
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(child)).unwrap();
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor: parent_id,
                    expected_deployment: deployment,
                }
            ),
            Err(LifecycleError::Busy(ActorLifecycleDebt { children: 1, .. }))
        ));
        runtime
            .set_lifecycle_debt(
                child_id,
                ActorLifecycleDebt {
                    outbox: 1,
                    ..ActorLifecycleDebt::default()
                },
            )
            .unwrap();
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor: child_id,
                    expected_deployment: DeploymentId([7; 32]),
                }
            ),
            Err(LifecycleError::Busy(ActorLifecycleDebt { outbox: 1, .. }))
        ));
    }

    #[test]
    fn runtime_upgrade_checks_every_installed_actor() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let actor = install(agent, None, "counter");
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(actor)).unwrap();
        let merge_only = RuntimeCapabilities {
            lanes: LaneSet::of(StateLane::Merge),
            scheduling: false,
            proofs: false,
            max_actors: 10,
        };
        assert_eq!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeRuntime {
                    from_deployment: DeploymentId([4; 32]),
                    to_deployment: DeploymentId([11; 32]),
                    to_program: ProgramId([12; 32]),
                    producer: ProducerId([18; 32]),
                    package: BlobRef {
                        hash: Hash([13; 32]),
                        len: 100,
                    },
                    contract: config.runtime_contract,
                    capabilities: merge_only,
                }
            ),
            Err(LifecycleError::UnsupportedRuntime)
        );
    }

    #[test]
    fn actor_program_changes_require_stateless_state() {
        let config = config(10);
        let agent = config.identity.agent;

        let mut stateful = StandardAgentRuntime::new();
        create_authorized(&mut stateful, &config, 1).unwrap();
        let installed = install(agent, None, "stateful");
        let actor = installed.entry.actor;
        let requirements = installed.requirements;
        apply_authorized(&mut stateful, &config, LifecycleRequest::Install(installed)).unwrap();
        let replacement = UpgradeActor {
            actor,
            from_deployment: DeploymentId([7; 32]),
            to_deployment: DeploymentId([14; 32]),
            to_program: ProgramId([15; 32]),
            producer: ProducerId([19; 32]),
            package: BlobRef {
                hash: Hash([16; 32]),
                len: 100,
            },
            agent_schema: BlobRef {
                hash: Hash([17; 32]),
                len: 100,
            },
            role_policies: BlobRef {
                hash: Hash([18; 32]),
                len: 100,
            },
            constructor_abi: Hash([14; 32]),
            state_layout: Hash([12; 32]),
            contract: crate::agent::contract::ActorPackageContract::canonical(),
            requirements,
        };
        assert_eq!(
            apply_authorized(
                &mut stateful,
                &config,
                LifecycleRequest::UpgradeActor(replacement.clone()),
            ),
            Err(LifecycleError::UnsupportedLane)
        );

        let mut stateless = StandardAgentRuntime::new();
        create_authorized(&mut stateless, &config, 1).unwrap();
        let mut installed = install(agent, None, "stateless");
        installed.entry.lanes = LaneSet::NONE;
        installed.requirements.lanes = LaneSet::NONE;
        let actor = installed.entry.actor;
        apply_authorized(
            &mut stateless,
            &config,
            LifecycleRequest::Install(installed),
        )
        .unwrap();
        let mut replacement = replacement;
        replacement.actor = actor;
        replacement.requirements.lanes = LaneSet::NONE;
        assert!(matches!(
            apply_authorized(
                &mut stateless,
                &config,
                LifecycleRequest::UpgradeActor(replacement),
            ),
            Ok(LifecycleReply::Upgraded(entry))
                if entry.program == ProgramId([15; 32])
                    && entry.package.hash == Hash([16; 32])
                    && entry.role_policies.hash == Hash([18; 32])
        ));
    }

    #[test]
    fn suspend_and_resume_bind_the_current_actor_deployment() {
        let config = config(10);
        let agent = config.identity.agent;
        let mut runtime = StandardAgentRuntime::new();
        create_authorized(&mut runtime, &config, 1).unwrap();
        let installed = install(agent, None, "deployment-bound");
        let actor = installed.entry.actor;
        let deployment_a = installed.entry.deployment;
        let deployment_b = DeploymentId([0x6e; 32]);
        let program = installed.entry.program;
        let requirements = installed.requirements;
        let state_layout = installed.state_layout;
        let constructor_abi = installed.constructor_abi;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(installed)).unwrap();

        let stale_suspend = suspend(actor, deployment_a);
        let stale_resume = resume(actor, deployment_a);
        apply_authorized(
            &mut runtime,
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment: deployment_a,
                to_deployment: deployment_b,
                to_program: program,
                producer: ProducerId([0x6f; 32]),
                package: BlobRef {
                    hash: Hash([0x70; 32]),
                    len: 100,
                },
                agent_schema: BlobRef {
                    hash: Hash([0x71; 32]),
                    len: 100,
                },
                role_policies: BlobRef {
                    hash: Hash([0x72; 32]),
                    len: 100,
                },
                constructor_abi,
                state_layout,
                contract: crate::agent::contract::ActorPackageContract::canonical(),
                requirements,
            }),
        )
        .unwrap();

        assert_eq!(
            apply_authorized(&mut runtime, &config, stale_suspend),
            Err(LifecycleError::StaleDeployment)
        );
        assert_eq!(
            apply_authorized(&mut runtime, &config, stale_resume),
            Err(LifecycleError::StaleDeployment)
        );
        assert_eq!(
            runtime
                .actor(actor)
                .map(|entry| (entry.deployment, entry.suspended)),
            Some((deployment_b, false)),
            "stale lifecycle requests consume their authority sequence but do not mutate B"
        );

        assert!(matches!(
            apply_authorized(&mut runtime, &config, suspend(actor, deployment_b)),
            Ok(LifecycleReply::Suspended(entry))
                if entry.deployment == deployment_b && entry.suspended
        ));
        assert!(matches!(
            apply_authorized(&mut runtime, &config, resume(actor, deployment_b)),
            Ok(LifecycleReply::Resumed(entry))
                if entry.deployment == deployment_b && !entry.suspended
        ));
    }

    #[test]
    fn upgrade_actor_is_blocked_by_pending_work() {
        let mut runtime = StandardAgentRuntime::new();
        let config = config(10);
        let agent = config.identity.agent;
        create_authorized(&mut runtime, &config, 1).unwrap();
        let install = install(agent, None, "counter");
        let actor = install.entry.actor;
        apply_authorized(&mut runtime, &config, LifecycleRequest::Install(install)).unwrap();
        runtime
            .set_lifecycle_debt(
                actor,
                ActorLifecycleDebt {
                    continuations: 1,
                    ..ActorLifecycleDebt::default()
                },
            )
            .unwrap();
        let requirements = RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proofs: false,
        };
        assert!(matches!(
            apply_authorized(
                &mut runtime,
                &config,
                LifecycleRequest::UpgradeActor(UpgradeActor {
                    actor,
                    from_deployment: DeploymentId([7; 32]),
                    to_deployment: DeploymentId([14; 32]),
                    to_program: ProgramId([15; 32]),
                    producer: ProducerId([19; 32]),
                    package: BlobRef {
                        hash: Hash([16; 32]),
                        len: 100,
                    },
                    agent_schema: BlobRef {
                        hash: Hash([17; 32]),
                        len: 100,
                    },
                    role_policies: BlobRef {
                        hash: Hash([18; 32]),
                        len: 100,
                    },
                    constructor_abi: Hash([14; 32]),
                    state_layout: Hash([12; 32]),
                    contract: crate::agent::contract::ActorPackageContract::canonical(),
                    requirements,
                })
            ),
            Err(LifecycleError::Busy(ActorLifecycleDebt {
                continuations: 1,
                ..
            }))
        ));
    }
}
