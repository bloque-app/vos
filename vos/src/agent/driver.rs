//! Host driver for one durable agent-runtime instance.
//!
//! The image store persists a small descriptor and runtime-state bytes.
//! Clean Local lifecycle metadata and directory inspection use the public
//! runtime ABI. The bundled Standard implementation also receives native
//! parity checks; other admitted runtimes own their private state layout.
//! Cross-runtime actor lifecycle and lane-transition coverage remains a
//! separate release requirement from management Create/reopen support.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::Arc;

use vos_pvm::{ExitReason, Gas};

use super::local_management::{
    LocalManagementHistory, LocalReceiptHistory as CleanManagementReceiptHistory,
};
use crate::agent_sdk::wire::CanonicalWire as AgentCanonicalWire;

use super::authority::{ActorInvocationReceipt, AgentAuthorityReceipt, AuthorityError};
pub use super::execution::MAX_RUNTIME_STATE_BYTES;
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation, RuntimeBlob,
    RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::package::{Package, PackageError};
use super::runtime_pvm::{RuntimePvmExecutionError, execute_canonical_wire, execute_service_wire};
use super::wire::{RuntimeCall, RuntimeReturn, RuntimeState};
use super::{
    ActorDirectoryRecord, ActorEntry, AgentConfig, AgentConfigError, AgentIdentity, AgentProfile,
    InstallActor, LifecycleAuthorityAdmission, LifecycleError, LifecycleReply, LifecycleRequest,
    PackageKind, RUNTIME_ABI_ID,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{ActorId, BlobRef, CapabilityId, DeploymentId, Hash, ProgramId};

/// Bounded outer-runtime allowance, separate from an actor's instruction cap.
/// The bundled Authority's signed authorization path exceeds the former
/// one-billion overhead when executed through the physical runtime.
pub const DEFAULT_MANAGEMENT_GAS: Gas = 5_000_000_000;
const MAX_STORED_PACKAGE_BYTES: usize = if super::package::MAX_ENCODED_PACKAGE_BYTES
    > crate::agent_sdk::package::MAX_PACKAGE_ENCODED_BYTES
{
    super::package::MAX_ENCODED_PACKAGE_BYTES
} else {
    crate::agent_sdk::package::MAX_PACKAGE_ENCODED_BYTES
};

fn canonical_blob_matches(reference: &BlobRef, bytes: &[u8]) -> bool {
    reference.matches(bytes)
}

/// Exclusive directory cursor immediately before an ActorId in the SDK's
/// lexicographic byte ordering. Zero is not a legal cursor or actor identity.
fn actor_lookup_cursor(actor: crate::agent_sdk::ActorId) -> Option<crate::agent_sdk::ActorId> {
    let mut bytes = actor.0;
    for byte in bytes.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            return (bytes != [0; 32]).then_some(crate::agent_sdk::ActorId(bytes));
        }
        *byte = u8::MAX;
    }
    None
}

fn sdk_blob_as_legacy(reference: &crate::agent_sdk::BlobRef) -> BlobRef {
    BlobRef {
        hash: Hash(reference.hash.0),
        len: reference.len,
    }
}

fn validate_sdk_process_local_profile(
    profile: crate::agent_sdk::AgentProfile,
) -> Result<(), AgentDriverError> {
    if profile == crate::agent_sdk::AgentProfile::Local {
        Ok(())
    } else {
        Err(AgentDriverError::UnsupportedProfile(match profile {
            crate::agent_sdk::AgentProfile::Local => AgentProfile::Local,
            crate::agent_sdk::AgentProfile::Shared => AgentProfile::Shared,
            crate::agent_sdk::AgentProfile::Private => AgentProfile::Private,
        }))
    }
}

fn clean_descriptor_from_state(
    state: &RuntimeState,
) -> Result<crate::agent_sdk::AgentDescriptor, AgentDriverError> {
    let decoded = super::wire::decode_standard_runtime_state(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    decoded
        .clean_descriptor
        .ok_or(AgentDriverError::InvalidRuntime)
}

#[cfg(test)]
fn clean_management_receipt_history(
    state: &RuntimeState,
    request: &crate::agent_sdk::ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
) -> Result<CleanManagementReceiptHistory, AgentDriverError> {
    let decoded = super::wire::decode_standard_runtime_state(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    Ok(LocalManagementHistory::from_standard_fixture(&decoded).classify(request, receipt))
}

fn image_config_is_valid(image: &AgentImage) -> bool {
    match image.clean_descriptor.as_ref() {
        Some(descriptor) => {
            descriptor.validate().is_ok()
                && image.clean_management.as_ref().is_some_and(|history| {
                    history.validates_initial_epoch(descriptor.authority.initial_epoch)
                })
                && super::standard::clean_descriptor_to_legacy_config(descriptor)
                    .is_ok_and(|projected| projected == image.config)
        }
        None => image.clean_management.is_none() && image.config.validate().is_ok(),
    }
}

fn clean_image_descriptor(
    image: &AgentImage,
) -> Result<crate::agent_sdk::AgentDescriptor, AgentDriverError> {
    if !image_config_is_valid(image)
        || image.config.identity.runtime_program != image.runtime_program
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    image
        .clean_descriptor
        .clone()
        .ok_or(AgentDriverError::InvalidRuntime)
}

fn validate_clean_standard_descriptor(
    state: &crate::agent_sdk::RuntimeState,
    expected: &crate::agent_sdk::AgentDescriptor,
) -> Result<(), AgentDriverError> {
    let decoded = super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(state))
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    if decoded.clean_creation_descriptor.as_ref() == Some(expected)
        && decoded.clean_descriptor.as_ref() == Some(expected)
    {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

pub(crate) fn verify_clean_runtime_package_binding(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    package: &super::package_admission::AdmittedRuntimePackage,
) -> Result<(), AgentDriverError> {
    if descriptor.validate().is_err()
        || descriptor.runtime_package != *package.package_ref()
        || descriptor.identity.runtime_deployment != package.deployment()
        || descriptor.identity.runtime_program != package.program()
        || descriptor.identity.runtime_producer != package.producer()
        || descriptor.runtime_contract != package.manifest().contract
        || descriptor.capabilities != package.capabilities()
    {
        return Err(AgentDriverError::RuntimeProgramMismatch);
    }
    Ok(())
}

fn clean_management_operation(
    request: &crate::agent_sdk::ManagementRequest,
) -> Option<crate::agent_sdk::authority::AuthorityOperationKind> {
    use crate::agent_sdk::ManagementRequest;
    use crate::agent_sdk::authority::AuthorityOperationKind;
    match request {
        ManagementRequest::Create(_) => Some(AuthorityOperationKind::CreateAgent),
        ManagementRequest::InspectActors { .. }
        | ManagementRequest::InspectResources
        | ManagementRequest::InspectManagementHistory => None,
        ManagementRequest::Install(_) => Some(AuthorityOperationKind::InstallActor),
        ManagementRequest::UpgradeActor(_) => Some(AuthorityOperationKind::UpgradeActor),
        ManagementRequest::Suspend { .. } => Some(AuthorityOperationKind::SuspendActor),
        ManagementRequest::Resume { .. } => Some(AuthorityOperationKind::ResumeActor),
        ManagementRequest::RemoveLeaf { .. } => Some(AuthorityOperationKind::RemoveActor),
        ManagementRequest::UpgradeRuntime(_) => Some(AuthorityOperationKind::UpgradeRuntime),
        ManagementRequest::ChangeReplicas { .. } => Some(AuthorityOperationKind::ChangeReplicaSet),
        ManagementRequest::SetExecutionLimits(_) => {
            Some(AuthorityOperationKind::SetExecutionLimits)
        }
        // Private controls have their own retained authority/application
        // path and are never admitted by a generic Local/Shared driver.
        ManagementRequest::PrivateControl { .. } => None,
    }
}

fn clean_management_actor(
    request: &crate::agent_sdk::ManagementRequest,
) -> Option<(crate::agent_sdk::ActorId, crate::agent_sdk::DeploymentId)> {
    use crate::agent_sdk::ManagementRequest;
    match request {
        ManagementRequest::Install(install) => {
            Some((install.entry.actor, install.entry.deployment))
        }
        ManagementRequest::UpgradeActor(upgrade) => Some((upgrade.actor, upgrade.to_deployment)),
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        }
        | ManagementRequest::Resume {
            actor,
            expected_deployment,
        }
        | ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => Some((*actor, *expected_deployment)),
        _ => None,
    }
}

pub(crate) fn verify_clean_management_receipt(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    request: &crate::agent_sdk::ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    observed_slot: u64,
    allow_historical_runtime: bool,
) -> Result<(), AgentDriverError> {
    let runtime_deployment = match request {
        crate::agent_sdk::ManagementRequest::Create(descriptor) => {
            descriptor.identity.runtime_deployment
        }
        crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => upgrade.from_deployment,
        _ => descriptor.identity.runtime_deployment,
    };
    let selector = &receipt.selector;
    let runtime_is_request_bound = matches!(
        request,
        crate::agent_sdk::ManagementRequest::Create(_)
            | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_)
    );
    if receipt.validate_shape().is_err()
        || !selector.is_live_at(observed_slot)
        || !descriptor.authority.accepts(receipt)
        || selector.space != descriptor.identity.space
        || selector.agent != descriptor.identity.agent
        || ((!allow_historical_runtime || runtime_is_request_bound)
            && selector.runtime_deployment != runtime_deployment)
        || (!allow_historical_runtime
            && !matches!(request, crate::agent_sdk::ManagementRequest::Create(_))
            && descriptor.identity.runtime_deployment != runtime_deployment)
        || Some(selector.operation) != clean_management_operation(request)
        || selector.actor.zip(selector.actor_deployment) != clean_management_actor(request)
        || selector.request != request.commitment()
        || !super::authority::verify_raw_ed25519(
            &receipt.public_key,
            &receipt.signing_bytes(),
            &receipt.signature,
        )
    {
        return Err(AgentDriverError::SdkManagement(
            crate::agent_sdk::ManagementError::InvalidRequest,
        ));
    }
    Ok(())
}

/// Journal-only admission for an authenticated expiry fence. The caller must
/// require an ExpiredBeforeApplication outcome and a changed, durable state
/// before treating the expired input as an observed terminal. Image admission
/// deliberately continues to use the live-window verifier above.
pub(crate) fn verify_clean_management_journal_receipt(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    request: &crate::agent_sdk::ManagementRequest,
    receipt: &crate::agent_sdk::authority::AuthorityReceipt,
    observed_slot: u64,
    allow_historical_runtime: bool,
) -> Result<bool, AgentDriverError> {
    let expiry = observed_slot > receipt.selector.expires_at
        && matches!(request, crate::agent_sdk::ManagementRequest::Install(_))
        && matches!(
            descriptor.identity.profile,
            crate::agent_sdk::AgentProfile::Local | crate::agent_sdk::AgentProfile::Shared
        );
    verify_clean_management_receipt(
        descriptor,
        request,
        receipt,
        if expiry {
            receipt.selector.expires_at
        } else {
            observed_slot
        },
        allow_historical_runtime,
    )?;
    Ok(expiry)
}

pub(crate) fn validate_sdk_management_artifacts(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    request: &crate::agent_sdk::ManagementRequest,
    artifacts: SdkManagementArtifacts<'_>,
) -> Result<(), AgentDriverError> {
    use crate::agent_sdk::ManagementRequest;

    match (request, artifacts) {
        (ManagementRequest::Install(install), SdkManagementArtifacts::Actor(package)) => {
            validate_sdk_actor_install(descriptor, install, package)
        }
        (ManagementRequest::UpgradeActor(upgrade), SdkManagementArtifacts::Actor(package)) => {
            validate_sdk_actor_upgrade(descriptor, upgrade, package)
        }
        (ManagementRequest::UpgradeRuntime(upgrade), SdkManagementArtifacts::Runtime(package)) => {
            if upgrade.to_deployment != package.deployment()
                || upgrade.to_program != package.program()
                || upgrade.producer != package.producer()
                || upgrade.producer == descriptor.identity.transition_producer
                || upgrade.package != *package.package_ref()
                || upgrade.contract != package.manifest().contract
                || upgrade.capabilities != package.capabilities()
            {
                return Err(AgentDriverError::RuntimeProgramMismatch);
            }
            Ok(())
        }
        (
            ManagementRequest::Create(_)
            | ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory
            | ManagementRequest::Suspend { .. }
            | ManagementRequest::Resume { .. }
            | ManagementRequest::RemoveLeaf { .. }
            | ManagementRequest::ChangeReplicas { .. },
            SdkManagementArtifacts::None,
        ) => Ok(()),
        _ => Err(AgentDriverError::InvalidRuntime),
    }
}

fn validate_sdk_retry_artifact_shape(
    request: &crate::agent_sdk::ManagementRequest,
    artifacts: SdkManagementArtifacts<'_>,
) -> Result<(), AgentDriverError> {
    use crate::agent_sdk::ManagementRequest;

    // A retained disposition owns the result; artifacts are not restaged or
    // revalidated against the possibly upgraded current runtime. Permit the
    // original admitted sidecar shape, or no sidecar at all, while rejecting
    // cross-role ambient artifacts.
    match (request, artifacts) {
        (
            ManagementRequest::Install(_) | ManagementRequest::UpgradeActor(_),
            SdkManagementArtifacts::None | SdkManagementArtifacts::Actor(_),
        )
        | (
            ManagementRequest::UpgradeRuntime(_),
            SdkManagementArtifacts::None | SdkManagementArtifacts::Runtime(_),
        )
        | (
            ManagementRequest::Create(_)
            | ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory
            | ManagementRequest::Suspend { .. }
            | ManagementRequest::Resume { .. }
            | ManagementRequest::RemoveLeaf { .. }
            | ManagementRequest::ChangeReplicas { .. },
            SdkManagementArtifacts::None,
        ) => Ok(()),
        _ => Err(AgentDriverError::InvalidRuntime),
    }
}

fn validate_sdk_actor_install(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    install: &crate::agent_sdk::InstallActor,
    package: &super::package_admission::AdmittedActorPackage,
) -> Result<(), AgentDriverError> {
    let schema = crate::agent_sdk::schema::decode(package.state_lane_schema_bytes())
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let expected_actor = match install.entry.parent {
        Some(parent) => crate::agent_sdk::ActorId::owned_child(parent, &install.entry.name),
        None => {
            crate::agent_sdk::ActorId::top_level(descriptor.identity.agent, &install.entry.name)
        }
    };
    let data_present = install.installation_data.is_some();
    if install.entry.actor != expected_actor
        || install.entry.deployment != package.deployment()
        || install.entry.program != package.program()
        || install.entry.package != *package.package_ref()
        || install.entry.agent_schema != package.manifest().state_lane_schema
        || install.entry.method_policy != package.manifest().method_policy
        || install.producer != package.producer()
        || install.package != *package.package_ref()
        || install.agent_schema != package.manifest().state_lane_schema
        || install.method_policy != package.manifest().method_policy
        || install.contract != package.manifest().contract
        || install.requirements != package.requirements()
        || install.entry.lanes != package.requirements().lanes
        || install.constructor_abi
            != schema
                .constructor_abi()
                .map_err(|_| AgentDriverError::InvalidRuntime)?
        || install.state_layout
            != schema
                .state_layout_hash()
                .map_err(|_| AgentDriverError::InvalidRuntime)?
        || data_present != schema.requires_installation_data()
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    package
        .requirements()
        .supported_by(descriptor.identity.profile)
        .then_some(())
        .ok_or(AgentDriverError::SdkManagement(
            crate::agent_sdk::ManagementError::UnsupportedLane,
        ))?;
    if !descriptor
        .runtime_contract
        .supports(package.manifest().contract)
        || !descriptor.capabilities.satisfies(package.requirements())
    {
        return Err(AgentDriverError::SdkManagement(
            crate::agent_sdk::ManagementError::UnsupportedRuntime,
        ));
    }
    Ok(())
}

fn validate_sdk_actor_upgrade(
    descriptor: &crate::agent_sdk::AgentDescriptor,
    upgrade: &crate::agent_sdk::UpgradeActor,
    package: &super::package_admission::AdmittedActorPackage,
) -> Result<(), AgentDriverError> {
    let schema = crate::agent_sdk::schema::decode(package.state_lane_schema_bytes())
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    if upgrade.to_deployment != package.deployment()
        || upgrade.to_program != package.program()
        || upgrade.producer != package.producer()
        || upgrade.package != *package.package_ref()
        || upgrade.agent_schema != package.manifest().state_lane_schema
        || upgrade.method_policy != package.manifest().method_policy
        || upgrade.contract != package.manifest().contract
        || upgrade.requirements != package.requirements()
        || upgrade.constructor_abi
            != schema
                .constructor_abi()
                .map_err(|_| AgentDriverError::InvalidRuntime)?
        || upgrade.state_layout
            != schema
                .state_layout_hash()
                .map_err(|_| AgentDriverError::InvalidRuntime)?
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    if !upgrade
        .requirements
        .supported_by(descriptor.identity.profile)
    {
        return Err(AgentDriverError::SdkManagement(
            crate::agent_sdk::ManagementError::UnsupportedLane,
        ));
    }
    if !descriptor.runtime_contract.supports(upgrade.contract)
        || !descriptor.capabilities.satisfies(upgrade.requirements)
    {
        return Err(AgentDriverError::SdkManagement(
            crate::agent_sdk::ManagementError::UnsupportedRuntime,
        ));
    }
    Ok(())
}

fn stage_sdk_actor_artifacts<S: AgentImageStore>(
    store: &mut S,
    package: &super::package_admission::AdmittedActorPackage,
    installation_data: Option<&crate::agent_sdk::InstallationData>,
    staged: &mut StagedSdkArtifacts,
) -> Result<(), AgentDriverError> {
    let package_ref = sdk_blob_as_legacy(package.package_ref());
    let program = ProgramId(package.program().0);
    let deployment = DeploymentId(package.deployment().0);
    staged.package = Some((
        package_ref.clone(),
        store.put_package(&package_ref, package.exact_bytes())?,
    ));
    staged.program = Some((
        program,
        store.put_program(program, package.program_bytes())?,
    ));
    let schema_ref = sdk_blob_as_legacy(&package.manifest().state_lane_schema);
    staged.schema = Some((
        deployment,
        store.put_actor_schema(deployment, &schema_ref, package.state_lane_schema_bytes())?,
    ));
    let policy_ref = sdk_blob_as_legacy(&package.manifest().method_policy);
    staged.policy = Some((
        deployment,
        store.put_actor_policies(deployment, &policy_ref, package.method_policy_bytes())?,
    ));
    if let Some(data) = installation_data {
        let reference = sdk_blob_as_legacy(&data.reference);
        staged.installation_data = Some((
            reference.clone(),
            store.put_installation_data(&reference, &data.bytes)?,
        ));
    }
    Ok(())
}

fn stage_sdk_runtime_artifacts<S: AgentImageStore>(
    store: &mut S,
    package: &super::package_admission::AdmittedRuntimePackage,
    staged: &mut StagedSdkArtifacts,
) -> Result<(), AgentDriverError> {
    let package_ref = sdk_blob_as_legacy(package.package_ref());
    let program = ProgramId(package.program().0);
    staged.package = Some((
        package_ref.clone(),
        store.put_package(&package_ref, package.exact_bytes())?,
    ));
    staged.program = Some((
        program,
        store.put_program(program, package.program_bytes())?,
    ));
    Ok(())
}

pub(crate) fn sdk_management_reply_matches(
    current: &crate::agent_sdk::AgentDescriptor,
    request: &crate::agent_sdk::ManagementRequest,
    outcome: &crate::agent_sdk::RuntimeOutcome,
) -> bool {
    use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome};
    let RuntimeOutcome::Management(result) = outcome else {
        return false;
    };
    let Ok(reply) = result else {
        return true;
    };
    match (request, reply) {
        (ManagementRequest::Create(descriptor), ManagementReply::Created(identity)) => {
            *identity == descriptor.identity
        }
        (ManagementRequest::InspectActors { .. }, ManagementReply::Actors(page)) => {
            page.validate().is_ok()
        }
        (ManagementRequest::InspectResources, ManagementReply::Resources(_)) => true,
        (
            ManagementRequest::InspectManagementHistory,
            ManagementReply::ManagementHistory(commitment),
        ) => *commitment != crate::agent_sdk::Hash::ZERO,
        (ManagementRequest::Install(install), ManagementReply::Installed(entry)) => {
            *entry == install.entry
        }
        (ManagementRequest::UpgradeActor(upgrade), ManagementReply::Upgraded(entry)) => {
            entry.actor == upgrade.actor
                && entry.deployment == upgrade.to_deployment
                && entry.program == upgrade.to_program
                && entry.package == upgrade.package
                && entry.agent_schema == upgrade.agent_schema
                && entry.method_policy == upgrade.method_policy
                && entry.constructor_abi == upgrade.constructor_abi
                && entry.state_layout == upgrade.state_layout
                && entry.lanes == upgrade.requirements.lanes
        }
        (
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            },
            ManagementReply::Suspended(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && entry.suspended,
        (
            ManagementRequest::Resume {
                actor,
                expected_deployment,
            },
            ManagementReply::Resumed(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && !entry.suspended,
        (ManagementRequest::RemoveLeaf { actor, .. }, ManagementReply::Removed(removed)) => {
            actor == removed
        }
        (
            ManagementRequest::UpgradeRuntime(upgrade),
            ManagementReply::RuntimeUpgraded(identity),
        ) => {
            identity.space == current.identity.space
                && identity.agent == current.identity.agent
                && identity.owner == current.identity.owner
                && identity.profile == current.identity.profile
                && identity.runtime_deployment == upgrade.to_deployment
                && identity.runtime_program == upgrade.to_program
                && identity.runtime_producer == upgrade.producer
                && identity.transition_producer == current.identity.transition_producer
        }
        (
            ManagementRequest::ChangeReplicas { replicas, .. },
            ManagementReply::ReplicasChanged { generation },
        ) => {
            *generation
                == crate::agent_sdk::replica_set_generation(
                    &current.identity,
                    current.creation_nonce,
                    replicas,
                )
        }
        (request @ ManagementRequest::PrivateControl { .. }, reply) => {
            request.private_runtime_reply_matches(reply)
        }
        _ => false,
    }
}

/// Derive public metadata from an already authorized management transition.
/// Retained replies describe the original operation, not a new mutation of
/// today's descriptor. Guest-state validation remains a separate boundary.
fn sdk_descriptor_after_management(
    current: &crate::agent_sdk::AgentDescriptor,
    request: &crate::agent_sdk::ManagementRequest,
    outcome: &crate::agent_sdk::RuntimeOutcome,
    exact_retry: bool,
) -> Result<crate::agent_sdk::AgentDescriptor, AgentDriverError> {
    use crate::agent_sdk::{ManagementRequest, RuntimeOutcome};
    if current.validate().is_err()
        || !request.is_valid()
        || !sdk_management_reply_matches(current, request, outcome)
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    if exact_retry || matches!(outcome, RuntimeOutcome::Management(Err(_))) {
        return Ok(current.clone());
    }
    let mut next = current.clone();
    match request {
        ManagementRequest::UpgradeRuntime(upgrade) => {
            if current.identity.runtime_deployment != upgrade.from_deployment {
                return Err(AgentDriverError::InvalidRuntime);
            }
            next.identity.runtime_deployment = upgrade.to_deployment;
            next.identity.runtime_program = upgrade.to_program;
            next.identity.runtime_producer = upgrade.producer;
            next.runtime_package = upgrade.package.clone();
            next.runtime_contract = upgrade.contract;
            next.capabilities = upgrade.capabilities;
        }
        ManagementRequest::ChangeReplicas {
            expected_generation,
            replicas,
        } => {
            if *expected_generation != current.replica_generation() {
                return Err(AgentDriverError::InvalidRuntime);
            }
            next.replicas = replicas.clone();
        }
        ManagementRequest::Create(descriptor) if descriptor.as_ref() != current => {
            return Err(AgentDriverError::InvalidRuntime);
        }
        // This image-backed entry point is Local-only, not a Private control
        // host. Do not silently accept future descriptor-changing controls.
        ManagementRequest::PrivateControl { .. } => {
            return Err(AgentDriverError::InvalidRuntime);
        }
        ManagementRequest::Create(_)
        | ManagementRequest::InspectActors { .. }
        | ManagementRequest::InspectResources
        | ManagementRequest::InspectManagementHistory
        | ManagementRequest::Install(_)
        | ManagementRequest::UpgradeActor(_)
        | ManagementRequest::Suspend { .. }
        | ManagementRequest::Resume { .. }
        | ManagementRequest::RemoveLeaf { .. }
        | ManagementRequest::SetExecutionLimits(_) => {}
    }
    next.validate()
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    Ok(next)
}

fn expected_standard_sdk_management_transition(
    work: &crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, AgentDriverError> {
    require_direct_runtime_work(work)?;
    let crate::agent_sdk::RuntimeWork::Manage {
        space,
        agent,
        runtime_deployment,
        state,
        request,
        authority,
        observed_slot,
        ..
    } = work
    else {
        return Err(AgentDriverError::InvalidRuntime);
    };
    let pristine_input = state.is_empty();
    let read_only = matches!(
        request.as_ref(),
        crate::agent_sdk::ManagementRequest::InspectActors { .. }
            | crate::agent_sdk::ManagementRequest::InspectResources
            | crate::agent_sdk::ManagementRequest::InspectManagementHistory
    );
    let decoded = super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(state))
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let mut runtime = super::standard::StandardAgentRuntime::restore(decoded)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let result = runtime.apply_clean_management(
        *space,
        *agent,
        *runtime_deployment,
        request.as_ref().clone(),
        authority.as_ref().map(|receipt| receipt.as_ref().clone()),
        *observed_slot,
        pristine_input,
    );
    Ok(crate::agent_sdk::RuntimeTransition {
        state: if read_only {
            state.clone()
        } else {
            legacy_state_as_sdk(&super::wire::encode_standard_runtime_state(
                &runtime.snapshot(),
            ))
        },
        outcome: crate::agent_sdk::RuntimeOutcome::Management(result),
    })
}

fn expected_standard_sdk_acknowledgement_transition(
    work: &crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, AgentDriverError> {
    require_direct_runtime_work(work)?;
    let crate::agent_sdk::RuntimeWork::Acknowledge {
        state,
        invocation,
        authorization,
        ..
    } = work
    else {
        return Err(AgentDriverError::InvalidRuntime);
    };
    let decoded = super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(state))
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let mut runtime = super::standard::StandardAgentRuntime::restore(decoded)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    // First recover an already-retired invocation's durable positive
    // acknowledgement. When a retained terminal result still exists, retire
    // it directly: re-running method admission here would incorrectly require
    // a Direct execution proof for work originally accepted through the
    // attested path. `acknowledge_clean_retirement_with_status` authenticates the
    // retained exact work and authorization binding, matching the bundled
    // guest.
    let result = runtime
        .acknowledge_clean_retirement_with_status(invocation, authorization)
        .map(|(acknowledgement, _)| acknowledgement);
    Ok(crate::agent_sdk::RuntimeTransition {
        state: if result.is_ok() {
            legacy_state_as_sdk(&super::wire::encode_standard_runtime_state(
                &runtime.snapshot(),
            ))
        } else {
            state.clone()
        },
        outcome: crate::agent_sdk::RuntimeOutcome::Acknowledged(result),
    })
}

fn require_direct_runtime_work(
    work: &crate::agent_sdk::RuntimeWork,
) -> Result<(), AgentDriverError> {
    work.execution_context()
        .is_direct()
        .then_some(())
        .ok_or(AgentDriverError::InvalidRuntime)
}

fn validate_standard_sdk_acknowledgement_transition(
    expected: &crate::agent_sdk::RuntimeTransition,
    returned: &crate::agent_sdk::RuntimeTransition,
) -> Result<(), AgentDriverError> {
    if returned == expected
        && matches!(
            &returned.outcome,
            crate::agent_sdk::RuntimeOutcome::Acknowledged(_)
        )
    {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_sdk_acknowledgement_transition(
    runtime_program: ProgramId,
    prior: &RuntimeState,
    work: &crate::agent_sdk::RuntimeWork,
    returned: &crate::agent_sdk::RuntimeTransition,
) -> Result<(), AgentDriverError> {
    require_direct_runtime_work(work)?;
    let crate::agent_sdk::RuntimeWork::Acknowledge {
        invocation,
        authorization,
        ..
    } = work
    else {
        return Err(AgentDriverError::InvalidRuntime);
    };
    if runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID {
        let expected = expected_standard_sdk_acknowledgement_transition(work)?;
        return validate_standard_sdk_acknowledgement_transition(&expected, returned);
    }

    let next = sdk_state_as_legacy(&returned.state);
    match &returned.outcome {
        crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(acknowledgement))
            if acknowledgement.invocation == invocation.invocation
                && acknowledgement.actor == invocation.actor
                && acknowledgement.incarnation == invocation.incarnation
                && acknowledgement.deployment == invocation.deployment
                && acknowledgement.mode == invocation.mode
                && acknowledgement.work == invocation.commitment()
                && acknowledgement.authorization == authorization.commitment() =>
        {
            validate_execution_transition(prior, &next, sdk_mode_as_legacy(invocation.mode))
        }
        // A failed retirement has no durable effect. In particular, a
        // hostile custom runtime cannot smuggle an owning-lane mutation
        // behind a NotFound or authorization error.
        crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_)) if &next == prior => Ok(()),
        _ => Err(AgentDriverError::InvalidRuntime),
    }
}

fn stored_program_matches(program: ProgramId, bytes: &[u8]) -> bool {
    ProgramId::of_pvm(bytes) == program || crate::agent_sdk::ProgramId::of_pvm(bytes).0 == program.0
}

fn valid_stored_schema(bytes: &[u8]) -> bool {
    super::schema::decode(bytes).is_some() || crate::agent_sdk::schema::decode(bytes).is_ok()
}

fn valid_stored_policy(bytes: &[u8]) -> bool {
    use crate::agent_sdk::wire::CanonicalWire as _;
    crate::service::PackageRolePolicies::decode(bytes).is_ok()
        || crate::agent_sdk::method_policy::ActorMethodPolicyArtifact::decode(bytes).is_ok()
}

/// Driver-owned source of logical time and signed-package trust. Lifecycle
/// authority remains a canonical signed receipt. Invocation authorization is
/// either that guest-verified receipt or an unsigned PublicPreflight which the
/// guest admits only after resolving the exact installed Public policy.
pub trait AgentTrustProvider: Send + Sync {
    fn current_logical_slot(&self) -> Option<u64>;

    /// Immutable system-authority deployment anchored for this space. This
    /// selects trust; it does not decide individual lifecycle operations.
    fn authority_for_space(
        &self,
        space: crate::service::SpaceId,
    ) -> Option<super::authority::AgentAuthorityBinding>;

    /// Authenticate a signed package for this complete target agent.
    /// Durable APIs accept raw packages and always cross this driver-owned
    /// trust boundary themselves.
    fn verify_package(&self, agent: &AgentConfig, package: &Package) -> bool;

    /// Unit-test-only native Standard-runtime oracle. This keeps physical
    /// host/store tests independent of the separately pinned guest artifact;
    /// production builds do not expose or compile this bypass.
    #[cfg(test)]
    fn use_native_standard_runtime_for_test(&self) -> bool {
        false
    }

    /// Unit-test-only clean-ABI counterpart to the legacy Standard oracle.
    /// Existing fixtures inherit the legacy choice; a physical custom-runtime
    /// fixture can override this independently when it must stay on PVM.
    #[cfg(test)]
    fn use_native_clean_runtime_for_test(&self) -> bool {
        self.use_native_standard_runtime_for_test()
    }
}

/// Maximum canonical configuration embedded in one image. Replica and
/// authority lists are protocol-bounded independently; this outer limit keeps
/// their decoder from allocating the generic service-wire maximum first.
pub const MAX_AGENT_CONFIG_BYTES: usize = 64 * 1024;
/// Maximum complete persisted image, including the fixed envelope and
/// length-prefix overhead around the bounded config, SDK descriptor and state.
pub const MAX_AGENT_IMAGE_BYTES: usize = MAX_AGENT_CONFIG_BYTES
    + MAX_RUNTIME_STATE_BYTES
    + crate::agent_sdk::wire::MAX_AGENT_DESCRIPTOR_WIRE_BYTES
    + super::local_management::MAX_LOCAL_MANAGEMENT_HISTORY_BYTES
    + 1024;
const MAX_AGENT_IMAGE_REPLICAS: usize = 512;

/// Complete guest-owned catalog provenance for one committed agent image.
///
/// Runtime and actor artifacts are mandatory. Reopening always reconstructs
/// the runtime from this exact content-addressed closure; it never substitutes
/// a process-local default executable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCatalogReferences {
    pub runtime_package: BlobRef,
    pub runtime_program: ProgramId,
    pub actors: Vec<ActorEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeploymentArtifacts {
    package: BlobRef,
    program: ProgramId,
    schema: BlobRef,
    policies: BlobRef,
}

#[derive(Clone, Debug)]
struct CatalogKeep {
    required_packages: BTreeMap<Hash, BlobRef>,
    retained_packages: BTreeSet<Hash>,
    required_programs: BTreeSet<ProgramId>,
    retained_programs: BTreeSet<ProgramId>,
    schemas: BTreeMap<DeploymentId, BlobRef>,
    policies: BTreeMap<DeploymentId, BlobRef>,
    installation_data: BTreeMap<Hash, BlobRef>,
}

impl CatalogKeep {
    fn from_references(references: &AgentCatalogReferences) -> Result<Self, AgentStoreError> {
        if references.runtime_package.hash == Hash::ZERO
            || references.runtime_package.len == 0
            || references.runtime_program == ProgramId::ZERO
        {
            return Err(AgentStoreError::Corrupt);
        }

        let mut deployments = BTreeMap::<DeploymentId, DeploymentArtifacts>::new();
        for actor in &references.actors {
            if actor.deployment == DeploymentId::ZERO
                || actor.program == ProgramId::ZERO
                || actor.package.hash == Hash::ZERO
                || actor.package.len == 0
                || actor.agent_schema.hash == Hash::ZERO
                || actor.agent_schema.len == 0
                || actor.role_policies.hash == Hash::ZERO
                || actor.role_policies.len == 0
            {
                return Err(AgentStoreError::Corrupt);
            }
            let artifacts = DeploymentArtifacts {
                package: actor.package.clone(),
                program: actor.program,
                schema: actor.agent_schema.clone(),
                policies: actor.role_policies.clone(),
            };
            match deployments.get(&actor.deployment) {
                Some(existing) if existing != &artifacts => return Err(AgentStoreError::Corrupt),
                Some(_) => {}
                None => {
                    deployments.insert(actor.deployment, artifacts);
                }
            }
        }

        let mut required_packages = BTreeMap::<Hash, BlobRef>::new();
        required_packages.insert(
            references.runtime_package.hash,
            references.runtime_package.clone(),
        );
        let mut required_programs = BTreeSet::from([references.runtime_program]);
        let mut schemas = BTreeMap::new();
        let mut policies = BTreeMap::new();
        let mut installation_data = BTreeMap::<Hash, BlobRef>::new();
        for actor in &references.actors {
            if let Some(reference) = &actor.installation_data {
                if reference.hash == Hash::ZERO
                    || reference.len > super::MAX_INSTALLATION_DATA_BYTES as u64
                {
                    return Err(AgentStoreError::Corrupt);
                }
                match installation_data.get(&reference.hash) {
                    Some(existing) if existing != reference => {
                        return Err(AgentStoreError::Corrupt);
                    }
                    Some(_) => {}
                    None => {
                        installation_data.insert(reference.hash, reference.clone());
                    }
                }
            }
        }
        for (deployment, artifacts) in deployments {
            match required_packages.get(&artifacts.package.hash) {
                Some(existing) if existing != &artifacts.package => {
                    return Err(AgentStoreError::Corrupt);
                }
                Some(_) => {}
                None => {
                    required_packages.insert(artifacts.package.hash, artifacts.package.clone());
                }
            }
            required_programs.insert(artifacts.program);
            schemas.insert(deployment, artifacts.schema);
            policies.insert(deployment, artifacts.policies);
        }

        let retained_packages = required_packages.keys().copied().collect::<BTreeSet<_>>();
        let retained_programs = required_programs.clone();
        Ok(Self {
            required_packages,
            retained_packages,
            required_programs,
            retained_programs,
            schemas,
            policies,
            installation_data,
        })
    }
}

/// One atomically persisted agent revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentImage {
    /// Host-owned public SDK metadata. Clean images require this descriptor;
    /// legacy in-crate images use None. It is committed atomically with state.
    pub clean_descriptor: Option<crate::agent_sdk::AgentDescriptor>,
    pub clean_management: Option<LocalManagementHistory>,
    pub revision: u64,
    pub runtime_program: ProgramId,
    pub config: AgentConfig,
    pub runtime_state: RuntimeState,
}

impl ServiceWire for AgentImage {
    const MAGIC: [u8; 4] = *b"AGI3";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&RUNTIME_ABI_ID.0);
        encoder.u64(self.revision);
        encoder.fixed(&self.runtime_program.0);
        encoder.bytes(&self.config.encode());
        encoder.option(&self.clean_descriptor, |encoder, descriptor| {
            // Invalid public values remain un-decodable rather than causing
            // the infallible host envelope encoder to panic.
            encoder.bytes(&descriptor.encode().unwrap_or_default());
        });
        encoder.option(&self.clean_management, |encoder, history| {
            encoder.bytes(&history.encode())
        });
        encoder.bytes(&self.runtime_state.control);
        encoder.bytes(&self.runtime_state.linear);
        encoder.bytes(&self.runtime_state.merge);
        encoder.bytes(&self.runtime_state.local);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let revision = decoder.u64()?;
        let runtime_program = ProgramId(decoder.fixed()?);
        let config_bytes = decoder.bytes_ref()?;
        if config_bytes.len() > MAX_AGENT_CONFIG_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let clean_descriptor = decoder.option(|decoder| {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > crate::agent_sdk::wire::MAX_AGENT_DESCRIPTOR_WIRE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            crate::agent_sdk::AgentDescriptor::decode(bytes).map_err(|_| DecodeError::NonCanonical)
        })?;
        let clean_management = decoder.option(|decoder| {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::local_management::MAX_LOCAL_MANAGEMENT_HISTORY_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            LocalManagementHistory::decode(bytes)
        })?;
        // Borrow every component first and check their aggregate before any
        // potentially large Vec is allocated.
        let control = decoder.bytes_ref()?;
        let linear = decoder.bytes_ref()?;
        let merge = decoder.bytes_ref()?;
        let local = decoder.bytes_ref()?;
        let runtime_bytes = [control, linear, merge, local]
            .into_iter()
            .try_fold(0usize, |total, component| {
                total.checked_add(component.len())
            })
            .ok_or(DecodeError::LimitExceeded)?;
        if runtime_bytes > MAX_RUNTIME_STATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let runtime_state = RuntimeState {
            control: control.to_vec(),
            linear: linear.to_vec(),
            merge: merge.to_vec(),
            local: local.to_vec(),
        };
        let config = match clean_descriptor.as_ref() {
            Some(descriptor) => {
                let projected = super::standard::clean_descriptor_to_legacy_config(descriptor)
                    .map_err(|_| DecodeError::NonCanonical)?;
                if projected.encode().as_slice() != config_bytes {
                    return Err(DecodeError::NonCanonical);
                }
                projected
            }
            None => AgentConfig::decode(config_bytes)?,
        };
        let image = Self {
            clean_descriptor,
            clean_management,
            revision,
            runtime_program,
            config,
            runtime_state,
        };
        if image.revision == 0
            || image.runtime_program == ProgramId::ZERO
            || image.runtime_state.is_empty()
            || runtime_state_size(&image.runtime_state) > MAX_RUNTIME_STATE_BYTES
            || runtime_state_size(&image.runtime_state)
                > image
                    .config
                    .runtime_contract
                    .resources
                    .max_runtime_state_bytes as usize
            || image.config.replicas.len() > MAX_AGENT_IMAGE_REPLICAS
            || !image_config_is_valid(&image)
            || image.config.identity.runtime_program != image.runtime_program
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(image)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStoreError {
    Conflict,
    Corrupt,
    Unavailable,
}

impl core::fmt::Display for AgentStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent image store: {self:?}")
    }
}

impl std::error::Error for AgentStoreError {}

/// Compare-and-replace persistence used by the process-local agent driver.
///
/// Replicated profiles need a different adapter: Shared agents must order
/// control/Linear transitions through consensus and materialize Merge changes
/// through an authenticated causal DAG, while Private agents need the same
/// causal machinery with an owner-node membership gate. Feeding either
/// profile through this whole-image CAS would silently turn Merge into
/// last-writer-wins replacement.
pub trait AgentImageStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError>;
    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError>;

    /// Persist a canonical signed package before its lifecycle transition is
    /// made durable. Returns `true` when this call created the artifact.
    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError>;
    fn load_package(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, AgentStoreError>;
    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError>;

    /// Persist the signed agent schema under the deployment that selected it.
    /// Deployment-keyed lookup avoids conflating separately signed packages
    /// which happen to reuse one executable ProgramId.
    fn put_actor_schema(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError>;
    fn load_actor_schema(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError>;
    fn remove_actor_schema(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError>;

    /// Persist and resolve the exact canonical method policies selected by a
    /// signed deployment. The runtime authenticates this sidecar against its
    /// guest-owned reference before dispatching application code.
    fn put_actor_policies(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError>;
    fn load_actor_policies(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError>;
    fn remove_actor_policies(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError>;

    /// Persist exact immutable canonical constructor-argument bytes by
    /// content hash. Empty bytes are valid when their ordinary BlobRef is
    /// supplied; const fields are reconstructed by the constructor.
    fn put_installation_data(
        &mut self,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError>;
    fn load_installation_data(
        &self,
        reference: &BlobRef,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError>;
    fn remove_installation_data(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError>;

    /// Persist and resolve executable actor bytes by their exact ProgramId.
    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError>;
    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError>;
    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError>;

    /// Authenticate every artifact referenced by the committed guest
    /// directory, then retire all unreferenced catalog artifacts. The
    /// validation phase must complete before any deletion so corruption can
    /// never turn cleanup into loss of an otherwise recoverable image.
    fn reconcile_catalog(
        &mut self,
        references: &AgentCatalogReferences,
    ) -> Result<(), AgentStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryAgentStore {
    image: Option<AgentImage>,
    packages: BTreeMap<Hash, Vec<u8>>,
    schemas: BTreeMap<DeploymentId, RuntimeBlob>,
    policies: BTreeMap<DeploymentId, RuntimeBlob>,
    installation_data: BTreeMap<Hash, Vec<u8>>,
    programs: BTreeMap<ProgramId, Vec<u8>>,
}

impl MemoryAgentStore {
    pub fn image(&self) -> Option<&AgentImage> {
        self.image.as_ref()
    }
}

impl AgentImageStore for MemoryAgentStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        Ok(self.image.clone())
    }

    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError> {
        encode_valid_image(image)?;
        if self.image.as_ref().map(|image| image.revision) != expected_revision {
            return Err(AgentStoreError::Conflict);
        }
        self.image = Some(image.clone());
        Ok(())
    }

    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if bytes.len() > MAX_STORED_PACKAGE_BYTES || !canonical_blob_matches(reference, bytes) {
            return Err(AgentStoreError::Corrupt);
        }
        put_memory_artifact(&mut self.packages, reference.hash, bytes)
    }

    fn load_package(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, AgentStoreError> {
        match self.packages.get(&reference.hash) {
            Some(bytes) if canonical_blob_matches(reference, bytes) => Ok(Some(bytes.clone())),
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.packages.remove(&reference.hash);
        Ok(())
    }

    fn put_actor_schema(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if deployment == DeploymentId::ZERO
            || !canonical_blob_matches(reference, bytes)
            || !valid_stored_schema(bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        if let Some(existing) = self.schemas.get(&deployment) {
            return if existing.reference == *reference && existing.bytes == bytes {
                Ok(false)
            } else {
                Err(AgentStoreError::Corrupt)
            };
        }
        self.schemas.insert(
            deployment,
            RuntimeBlob {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(true)
    }

    fn load_actor_schema(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        Ok(self.schemas.get(&deployment).cloned())
    }

    fn remove_actor_schema(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError> {
        self.schemas.remove(&deployment);
        Ok(())
    }

    fn put_actor_policies(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if deployment == DeploymentId::ZERO
            || bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES
            || !canonical_blob_matches(reference, bytes)
            || !valid_stored_policy(bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        if let Some(existing) = self.policies.get(&deployment) {
            return if existing.reference == *reference && existing.bytes == bytes {
                Ok(false)
            } else {
                Err(AgentStoreError::Corrupt)
            };
        }
        self.policies.insert(
            deployment,
            RuntimeBlob {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(true)
    }

    fn load_actor_policies(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        Ok(self.policies.get(&deployment).cloned())
    }

    fn remove_actor_policies(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError> {
        self.policies.remove(&deployment);
        Ok(())
    }

    fn put_installation_data(
        &mut self,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES
            || !canonical_blob_matches(reference, bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        put_memory_artifact(&mut self.installation_data, reference.hash, bytes)
    }

    fn load_installation_data(
        &self,
        reference: &BlobRef,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        match self.installation_data.get(&reference.hash) {
            Some(bytes)
                if bytes.len() <= super::MAX_INSTALLATION_DATA_BYTES
                    && canonical_blob_matches(reference, bytes) =>
            {
                Ok(Some(RuntimeBlob {
                    reference: reference.clone(),
                    bytes: bytes.clone(),
                }))
            }
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_installation_data(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.installation_data.remove(&reference.hash);
        Ok(())
    }

    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if bytes.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
            || !stored_program_matches(program, bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        put_memory_artifact(&mut self.programs, program, bytes)
    }

    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError> {
        Ok(self.programs.get(&program).cloned())
    }

    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError> {
        self.programs.remove(&program);
        Ok(())
    }

    fn reconcile_catalog(
        &mut self,
        references: &AgentCatalogReferences,
    ) -> Result<(), AgentStoreError> {
        let keep = CatalogKeep::from_references(references)?;

        // Authenticate every mandatory artifact before changing any map.
        for (hash, reference) in &keep.required_packages {
            let bytes = self.packages.get(hash).ok_or(AgentStoreError::Corrupt)?;
            if !canonical_blob_matches(reference, bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for program in &keep.required_programs {
            let bytes = self.programs.get(program).ok_or(AgentStoreError::Corrupt)?;
            if !stored_program_matches(*program, bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (deployment, reference) in &keep.schemas {
            let blob = self
                .schemas
                .get(deployment)
                .ok_or(AgentStoreError::Corrupt)?;
            if blob.reference != *reference
                || !canonical_blob_matches(reference, &blob.bytes)
                || !valid_stored_schema(&blob.bytes)
            {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (deployment, reference) in &keep.policies {
            let blob = self
                .policies
                .get(deployment)
                .ok_or(AgentStoreError::Corrupt)?;
            if blob.reference != *reference
                || !canonical_blob_matches(reference, &blob.bytes)
                || blob.bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES
                || !valid_stored_policy(&blob.bytes)
            {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (hash, reference) in &keep.installation_data {
            let bytes = self
                .installation_data
                .get(hash)
                .ok_or(AgentStoreError::Corrupt)?;
            if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES
                || !canonical_blob_matches(reference, bytes)
            {
                return Err(AgentStoreError::Corrupt);
            }
        }

        self.packages
            .retain(|hash, _| keep.retained_packages.contains(hash));
        self.programs
            .retain(|program, _| keep.retained_programs.contains(program));
        self.schemas
            .retain(|deployment, _| keep.schemas.contains_key(deployment));
        self.policies
            .retain(|deployment, _| keep.policies.contains_key(deployment));
        self.installation_data
            .retain(|hash, _| keep.installation_data.contains_key(hash));
        Ok(())
    }
}

fn put_memory_artifact<K: Ord + Copy>(
    artifacts: &mut BTreeMap<K, Vec<u8>>,
    key: K,
    bytes: &[u8],
) -> Result<bool, AgentStoreError> {
    if let Some(existing) = artifacts.get(&key) {
        return if existing == bytes {
            Ok(false)
        } else {
            Err(AgentStoreError::Corrupt)
        };
    }
    artifacts.insert(key, bytes.to_vec());
    Ok(true)
}

/// Crash-durable single-image store for Local agents. Daemon-level agent
/// ownership locks serialize writers; the revision comparison catches stale
/// drivers inside that ownership domain.
#[derive(Clone, Debug)]
pub struct FileAgentStore {
    path: PathBuf,
}

impl FileAgentStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn catalog_root(&self) -> PathBuf {
        self.path.with_extension("agent-catalog")
    }

    fn read_image(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        // A crash can leave a fully synced staging image. Validate it on open
        // even though promotion remains tied to a matching future CAS; a
        // partial, oversized, special, or symlink stage must never be silently
        // truncated by the next commit.
        if let Some(staged) =
            self.read_bounded_regular(&self.path.with_extension("next"), MAX_AGENT_IMAGE_BYTES)?
        {
            AgentImage::decode(&staged).map_err(|_| AgentStoreError::Corrupt)?;
        }
        let Some(bytes) = self.read_bounded_regular(&self.path, MAX_AGENT_IMAGE_BYTES)? else {
            return Ok(None);
        };
        AgentImage::decode(&bytes)
            .map(Some)
            .map_err(|_| AgentStoreError::Corrupt)
    }

    fn sync_parent(&self) -> Result<(), AgentStoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AgentStoreError::Unavailable)
    }

    fn catalog_path(&self, kind: &str, id: &[u8; 32], suffix: &str) -> PathBuf {
        self.catalog_root()
            .join(kind)
            .join(format!("{}.{suffix}", encode_hex(id)))
    }

    fn read_bounded_regular(
        &self,
        path: &Path,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, AgentStoreError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AgentStoreError::Unavailable),
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(AgentStoreError::Corrupt);
        }
        if metadata.len() > max_bytes as u64 {
            return Err(AgentStoreError::Corrupt);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AgentStoreError::Corrupt),
        };
        let opened = file.metadata().map_err(|_| AgentStoreError::Unavailable)?;
        if !opened.file_type().is_file() || opened.len() > max_bytes as u64 {
            return Err(AgentStoreError::Corrupt);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        Read::by_ref(&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| AgentStoreError::Unavailable)?;
        if bytes.len() > max_bytes {
            return Err(AgentStoreError::Corrupt);
        }
        Ok(Some(bytes))
    }

    fn read_regular_artifact(&self, path: &Path) -> Result<Option<Vec<u8>>, AgentStoreError> {
        self.read_bounded_regular(path, MAX_STORED_PACKAGE_BYTES)
    }

    fn validate_catalog_shape(&self) -> Result<(), AgentStoreError> {
        let root = self.catalog_root();
        let metadata = match std::fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(AgentStoreError::Unavailable),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(AgentStoreError::Corrupt);
        }
        let entries = std::fs::read_dir(&root).map_err(|_| AgentStoreError::Unavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| AgentStoreError::Unavailable)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Err(AgentStoreError::Corrupt);
            };
            if !matches!(
                name.as_str(),
                "packages" | "programs" | "schemas" | "policies" | "installation-data"
            ) {
                return Err(AgentStoreError::Corrupt);
            }
            let file_type = entry
                .file_type()
                .map_err(|_| AgentStoreError::Unavailable)?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(AgentStoreError::Corrupt);
            }
        }
        Ok(())
    }

    fn reconcile_directory(
        &self,
        kind: &str,
        retained: &BTreeSet<PathBuf>,
    ) -> Result<(), AgentStoreError> {
        let directory = self.catalog_root().join(kind);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(AgentStoreError::Unavailable),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(AgentStoreError::Corrupt);
        }

        let mut changed = false;
        for entry in std::fs::read_dir(&directory).map_err(|_| AgentStoreError::Unavailable)? {
            let entry = entry.map_err(|_| AgentStoreError::Unavailable)?;
            if !retained.contains(&entry.path()) {
                std::fs::remove_file(entry.path()).map_err(|_| AgentStoreError::Unavailable)?;
                changed = true;
            }
        }
        if changed {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AgentStoreError::Unavailable)?;
        }
        Ok(())
    }

    fn validate_catalog_directory(&self, kind: &str) -> Result<(), AgentStoreError> {
        let directory = self.catalog_root().join(kind);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(AgentStoreError::Unavailable),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(AgentStoreError::Corrupt);
        }
        for entry in std::fs::read_dir(directory).map_err(|_| AgentStoreError::Unavailable)? {
            let entry = entry.map_err(|_| AgentStoreError::Unavailable)?;
            let file_type = entry
                .file_type()
                .map_err(|_| AgentStoreError::Unavailable)?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(AgentStoreError::Corrupt);
            }
        }
        Ok(())
    }

    fn put_artifact(&self, path: &Path, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if bytes.len() > MAX_STORED_PACKAGE_BYTES {
            return Err(AgentStoreError::Corrupt);
        }
        if let Some(existing) = self.read_regular_artifact(path)? {
            return if existing == bytes {
                Ok(false)
            } else {
                Err(AgentStoreError::Corrupt)
            };
        }
        let parent = path.parent().ok_or(AgentStoreError::Unavailable)?;
        let catalog_root = self.catalog_root();
        if let Ok(metadata) = std::fs::symlink_metadata(&catalog_root)
            && (!metadata.file_type().is_dir() || metadata.file_type().is_symlink())
        {
            return Err(AgentStoreError::Corrupt);
        }
        std::fs::create_dir_all(parent).map_err(|_| AgentStoreError::Unavailable)?;
        for directory in [&catalog_root, parent] {
            let metadata =
                std::fs::symlink_metadata(directory).map_err(|_| AgentStoreError::Unavailable)?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentStoreError::Corrupt);
            }
        }
        let next = path.with_extension("next");
        match self.read_regular_artifact(&next)? {
            Some(staged) if staged == bytes => {
                if self.read_regular_artifact(path)?.is_some() {
                    return Err(AgentStoreError::Conflict);
                }
                std::fs::rename(&next, path).map_err(|_| AgentStoreError::Unavailable)?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| AgentStoreError::Unavailable)?;
                return Ok(true);
            }
            Some(_) => return Err(AgentStoreError::Corrupt),
            None => {}
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&next)
            .map_err(|_| AgentStoreError::Unavailable)?;
        let result = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                if std::fs::symlink_metadata(path).is_ok() {
                    return Err(std::io::Error::new(
                        ErrorKind::AlreadyExists,
                        "agent catalog artifact appeared during staging",
                    ));
                }
                std::fs::rename(&next, path)
            })
            .and_then(|()| File::open(parent)?.sync_all());
        if result.is_err() {
            let _ = std::fs::remove_file(&next);
            return Err(AgentStoreError::Unavailable);
        }
        Ok(true)
    }

    fn remove_artifact(&self, path: &Path) -> Result<(), AgentStoreError> {
        match std::fs::remove_file(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|_| AgentStoreError::Unavailable)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AgentStoreError::Unavailable),
        }
    }
}

impl AgentImageStore for FileAgentStore {
    fn load(&self) -> Result<Option<AgentImage>, AgentStoreError> {
        self.read_image()
    }

    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        image: &AgentImage,
    ) -> Result<(), AgentStoreError> {
        let bytes = encode_valid_image(image)?;
        if self.read_image()?.as_ref().map(|image| image.revision) != expected_revision {
            return Err(AgentStoreError::Conflict);
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        if let Ok(metadata) = std::fs::symlink_metadata(parent)
            && (!metadata.file_type().is_dir() || metadata.file_type().is_symlink())
        {
            return Err(AgentStoreError::Corrupt);
        }
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| AgentStoreError::Unavailable)?;
        }
        let parent_metadata =
            std::fs::symlink_metadata(parent).map_err(|_| AgentStoreError::Unavailable)?;
        if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(AgentStoreError::Corrupt);
        }
        let next = self.path.with_extension("next");
        if let Some(staged) = self.read_bounded_regular(&next, MAX_AGENT_IMAGE_BYTES)? {
            if staged == bytes {
                if self.read_image()?.as_ref().map(|image| image.revision) != expected_revision {
                    return Err(AgentStoreError::Conflict);
                }
                std::fs::rename(&next, &self.path).map_err(|_| AgentStoreError::Unavailable)?;
                return self.sync_parent();
            }
            // A prior writer may have crashed after syncing a different,
            // otherwise canonical candidate. The current CAS still compares
            // against the durable image, so replacing this regular staging
            // file is safe. Special files and links were rejected above.
            AgentImage::decode(&staged).map_err(|_| AgentStoreError::Corrupt)?;
            std::fs::remove_file(&next).map_err(|_| AgentStoreError::Unavailable)?;
            self.sync_parent()?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&next)
            .map_err(|_| AgentStoreError::Unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| AgentStoreError::Unavailable)?;
        if self.read_image()?.as_ref().map(|image| image.revision) != expected_revision {
            let _ = std::fs::remove_file(&next);
            return Err(AgentStoreError::Conflict);
        }
        std::fs::rename(&next, &self.path).map_err(|_| AgentStoreError::Unavailable)?;
        self.sync_parent()
    }

    fn put_package(&mut self, reference: &BlobRef, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if bytes.len() > MAX_STORED_PACKAGE_BYTES || !canonical_blob_matches(reference, bytes) {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(
            &self.catalog_path("packages", &reference.hash.0, "vos"),
            bytes,
        )
    }

    fn load_package(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, AgentStoreError> {
        let path = self.catalog_path("packages", &reference.hash.0, "vos");
        match self.read_regular_artifact(&path)? {
            Some(bytes) if canonical_blob_matches(reference, &bytes) => Ok(Some(bytes)),
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_package(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("packages", &reference.hash.0, "vos"))
    }

    fn put_actor_schema(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if deployment == DeploymentId::ZERO
            || !canonical_blob_matches(reference, bytes)
            || !valid_stored_schema(bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(&self.catalog_path("schemas", &deployment.0, "agent"), bytes)
    }

    fn load_actor_schema(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        let path = self.catalog_path("schemas", &deployment.0, "agent");
        match self.read_bounded_regular(&path, super::schema::MAX_ENCODED_BYTES)? {
            Some(bytes) if valid_stored_schema(&bytes) => Ok(Some(RuntimeBlob {
                reference: BlobRef::of_bytes(&bytes),
                bytes,
            })),
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_actor_schema(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("schemas", &deployment.0, "agent"))
    }

    fn put_actor_policies(
        &mut self,
        deployment: DeploymentId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if deployment == DeploymentId::ZERO
            || bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES
            || !canonical_blob_matches(reference, bytes)
            || !valid_stored_policy(bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(
            &self.catalog_path("policies", &deployment.0, "roles"),
            bytes,
        )
    }

    fn load_actor_policies(
        &self,
        deployment: DeploymentId,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        let path = self.catalog_path("policies", &deployment.0, "roles");
        match self.read_bounded_regular(&path, super::execution::MAX_EXECUTION_POLICY_BYTES)? {
            Some(bytes)
                if bytes.len() <= super::execution::MAX_EXECUTION_POLICY_BYTES
                    && valid_stored_policy(&bytes) =>
            {
                Ok(Some(RuntimeBlob {
                    reference: BlobRef::of_bytes(&bytes),
                    bytes,
                }))
            }
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_actor_policies(&mut self, deployment: DeploymentId) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("policies", &deployment.0, "roles"))
    }

    fn put_installation_data(
        &mut self,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, AgentStoreError> {
        if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES
            || !canonical_blob_matches(reference, bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(
            &self.catalog_path("installation-data", &reference.hash.0, "args"),
            bytes,
        )
    }

    fn load_installation_data(
        &self,
        reference: &BlobRef,
    ) -> Result<Option<RuntimeBlob>, AgentStoreError> {
        let path = self.catalog_path("installation-data", &reference.hash.0, "args");
        match self.read_bounded_regular(&path, super::MAX_INSTALLATION_DATA_BYTES)? {
            Some(bytes) if canonical_blob_matches(reference, &bytes) => Ok(Some(RuntimeBlob {
                reference: reference.clone(),
                bytes,
            })),
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_installation_data(&mut self, reference: &BlobRef) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("installation-data", &reference.hash.0, "args"))
    }

    fn put_program(&mut self, program: ProgramId, bytes: &[u8]) -> Result<bool, AgentStoreError> {
        if bytes.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES
            || !stored_program_matches(program, bytes)
        {
            return Err(AgentStoreError::Corrupt);
        }
        self.put_artifact(&self.catalog_path("programs", &program.0, "pvm"), bytes)
    }

    fn load_program(&self, program: ProgramId) -> Result<Option<Vec<u8>>, AgentStoreError> {
        let path = self.catalog_path("programs", &program.0, "pvm");
        match self.read_bounded_regular(&path, super::execution::MAX_EXECUTION_PROGRAM_BYTES)? {
            Some(bytes) if stored_program_matches(program, &bytes) => Ok(Some(bytes)),
            Some(_) => Err(AgentStoreError::Corrupt),
            None => Ok(None),
        }
    }

    fn remove_program(&mut self, program: ProgramId) -> Result<(), AgentStoreError> {
        self.remove_artifact(&self.catalog_path("programs", &program.0, "pvm"))
    }

    fn reconcile_catalog(
        &mut self,
        references: &AgentCatalogReferences,
    ) -> Result<(), AgentStoreError> {
        let keep = CatalogKeep::from_references(references)?;
        self.validate_catalog_shape()?;
        for kind in [
            "packages",
            "programs",
            "schemas",
            "policies",
            "installation-data",
        ] {
            self.validate_catalog_directory(kind)?;
        }

        // Authenticate all mandatory actor artifacts before deleting any
        // unowned file. Referenced special files and symlinks fail closed.
        for (hash, reference) in &keep.required_packages {
            let path = self.catalog_path("packages", &hash.0, "vos");
            let bytes = self
                .read_regular_artifact(&path)?
                .ok_or(AgentStoreError::Corrupt)?;
            if !canonical_blob_matches(reference, &bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for program in &keep.required_programs {
            let path = self.catalog_path("programs", &program.0, "pvm");
            let bytes = self
                .read_regular_artifact(&path)?
                .ok_or(AgentStoreError::Corrupt)?;
            if !stored_program_matches(*program, &bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (deployment, reference) in &keep.schemas {
            let path = self.catalog_path("schemas", &deployment.0, "agent");
            let bytes = self
                .read_regular_artifact(&path)?
                .ok_or(AgentStoreError::Corrupt)?;
            if !canonical_blob_matches(reference, &bytes) || !valid_stored_schema(&bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (deployment, reference) in &keep.policies {
            let path = self.catalog_path("policies", &deployment.0, "roles");
            let bytes = self
                .read_regular_artifact(&path)?
                .ok_or(AgentStoreError::Corrupt)?;
            if bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES
                || !canonical_blob_matches(reference, &bytes)
                || !valid_stored_policy(&bytes)
            {
                return Err(AgentStoreError::Corrupt);
            }
        }
        for (hash, reference) in &keep.installation_data {
            let path = self.catalog_path("installation-data", &hash.0, "args");
            let bytes = self
                .read_bounded_regular(&path, super::MAX_INSTALLATION_DATA_BYTES)?
                .ok_or(AgentStoreError::Corrupt)?;
            if !canonical_blob_matches(reference, &bytes) {
                return Err(AgentStoreError::Corrupt);
            }
        }

        let retained_packages = keep
            .retained_packages
            .iter()
            .map(|hash| self.catalog_path("packages", &hash.0, "vos"))
            .collect::<BTreeSet<_>>();
        let retained_programs = keep
            .retained_programs
            .iter()
            .map(|program| self.catalog_path("programs", &program.0, "pvm"))
            .collect::<BTreeSet<_>>();
        let retained_schemas = keep
            .schemas
            .keys()
            .map(|deployment| self.catalog_path("schemas", &deployment.0, "agent"))
            .collect::<BTreeSet<_>>();
        let retained_policies = keep
            .policies
            .keys()
            .map(|deployment| self.catalog_path("policies", &deployment.0, "roles"))
            .collect::<BTreeSet<_>>();
        let retained_installation_data = keep
            .installation_data
            .keys()
            .map(|hash| self.catalog_path("installation-data", &hash.0, "args"))
            .collect::<BTreeSet<_>>();

        self.reconcile_directory("packages", &retained_packages)?;
        self.reconcile_directory("programs", &retained_programs)?;
        self.reconcile_directory("schemas", &retained_schemas)?;
        self.reconcile_directory("policies", &retained_policies)?;
        self.reconcile_directory("installation-data", &retained_installation_data)?;
        Ok(())
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDriverError {
    InvalidConfig(AgentConfigError),
    /// This process-local driver deliberately supports only Local agents.
    /// Shared and Private profiles require their replication adapters rather
    /// than whole-image compare-and-replace persistence.
    UnsupportedProfile(AgentProfile),
    RuntimeProgramMismatch,
    InvalidRuntime,
    TrustUnavailable,
    RuntimeExit {
        reason: ExitReason,
        pc: u32,
    },
    RuntimeOutput,
    /// Host compiler/memory failure, not a completed guest outcome.
    RuntimeBackend,
    RuntimeStateTooLarge,
    PackageUnavailable(Hash),
    ProgramUnavailable(ProgramId),
    SchemaUnavailable(DeploymentId),
    SchemaMismatch(DeploymentId),
    PolicyUnavailable(DeploymentId),
    PolicyMismatch(DeploymentId),
    Lifecycle(LifecycleError),
    Execution(ActorExecutionError),
    Package(PackageError),
    PackageAdmission(super::package_admission::PackageAdmissionError),
    SdkManagement(crate::agent_sdk::ManagementError),
    Authority(AuthorityError),
    Store(AgentStoreError),
}

impl core::fmt::Display for AgentDriverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent driver: {self:?}")
    }
}

impl std::error::Error for AgentDriverError {}

impl From<AgentStoreError> for AgentDriverError {
    fn from(error: AgentStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AuthorityError> for AgentDriverError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<RuntimePvmExecutionError> for AgentDriverError {
    fn from(error: RuntimePvmExecutionError) -> Self {
        match error {
            RuntimePvmExecutionError::Load => Self::InvalidRuntime,
            RuntimePvmExecutionError::Backend => Self::RuntimeBackend,
            RuntimePvmExecutionError::Exit { reason, pc } => Self::RuntimeExit { reason, pc },
            RuntimePvmExecutionError::MissingOutput | RuntimePvmExecutionError::Decode => {
                Self::RuntimeOutput
            }
        }
    }
}

fn verify_trusted_package(
    trust: &dyn AgentTrustProvider,
    config: &AgentConfig,
    package: &Package,
) -> Result<(), AgentDriverError> {
    package.validate().map_err(AgentDriverError::Package)?;
    if !trust.verify_package(config, package) {
        return Err(AgentDriverError::Package(PackageError::InvalidSignature));
    }
    Ok(())
}

fn verify_runtime_package_binding(
    trust: &dyn AgentTrustProvider,
    config: &AgentConfig,
    package: &Package,
) -> Result<(), AgentDriverError> {
    verify_trusted_package(trust, config, package)?;
    let PackageKind::AgentRuntime {
        contract,
        capabilities,
    } = package.manifest.kind
    else {
        return Err(AgentDriverError::Package(PackageError::WrongKind));
    };
    let package_bytes = package.encode();
    if !contract.is_valid()
        || config.identity.runtime_deployment != package.deployment_id()
        || config.identity.runtime_program != package.manifest.program
        || config.identity.runtime_producer != package.deployment_signature.producer
        || config.runtime_package != BlobRef::of_bytes(&package_bytes)
        || config.runtime_contract != contract
        || config.capabilities != capabilities
    {
        return Err(AgentDriverError::RuntimeProgramMismatch);
    }
    Ok(())
}

fn verify_authority_anchor(
    trust: &dyn AgentTrustProvider,
    config: &AgentConfig,
) -> Result<(), AgentDriverError> {
    let anchored = trust
        .authority_for_space(config.identity.space)
        .ok_or(AgentDriverError::TrustUnavailable)?;
    if anchored != config.authority {
        return Err(AgentDriverError::Authority(AuthorityError::WrongAuthority));
    }
    Ok(())
}

fn verify_authority_admission(
    trust: &dyn AgentTrustProvider,
    receipt: &AgentAuthorityReceipt,
    config: &AgentConfig,
    request: &LifecycleRequest,
) -> Result<LifecycleAuthorityAdmission, AgentDriverError> {
    let current_slot = trust
        .current_logical_slot()
        .ok_or(AgentDriverError::TrustUnavailable)?;
    receipt.verify_guest_signature(&config.authority)?;
    let claim = &receipt.claim;
    if claim.space != config.identity.space {
        return Err(AgentDriverError::Authority(AuthorityError::WrongSpace));
    }
    if claim.agent != config.identity.agent {
        return Err(AgentDriverError::Authority(AuthorityError::WrongAgent));
    }
    if matches!(request, LifecycleRequest::Create(_)) && claim.principal != config.identity.owner {
        return Err(AgentDriverError::Authority(AuthorityError::WrongOperation));
    }
    let capability = request
        .required_capability()
        .ok_or(AgentDriverError::InvalidRuntime)?;
    if claim.capability != CapabilityId::named(capability) {
        return Err(AgentDriverError::Authority(AuthorityError::WrongCapability));
    }
    if claim.operation != request.commitment() {
        return Err(AgentDriverError::Authority(AuthorityError::WrongOperation));
    }
    Ok(LifecycleAuthorityAdmission {
        receipt: receipt.clone(),
        observed_slot: current_slot,
    })
}

#[cfg(test)]
std::thread_local! {
    static DIRECTORY_EXECUTIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn directory_execution_count() -> usize {
    DIRECTORY_EXECUTIONS.with(core::cell::Cell::get)
}

/// Physically verified records borrowed from one immutable driver generation.
pub(crate) struct PhysicalAuthorityDirectory<'a, S> {
    driver: &'a AgentDriver<S>,
    records: Vec<crate::agent_sdk::ActorDirectoryRecord>,
}

impl<S: AgentImageStore> PhysicalAuthorityDirectory<'_, S> {
    pub(crate) fn records(&self) -> &[crate::agent_sdk::ActorDirectoryRecord] {
        &self.records
    }

    pub(crate) fn material(
        &self,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentDriverError> {
        let index = self
            .records
            .binary_search_by_key(&actor, |record| record.entry.actor)
            .map_err(|_| {
                AgentDriverError::SdkManagement(crate::agent_sdk::ManagementError::NotFound)
            })?;
        self.driver
            .physical_material_from_record(self.records[index].clone(), false)
    }
}

/// One loaded process-local agent. Calls are serialized by mutable access.
///
/// The driver is intentionally restricted to [`AgentProfile::Local`]. A
/// replicated adapter cannot safely wrap this type after the fact because a
/// committed image contains independently governed control, Linear, Merge,
/// and Local components. See [`AgentImageStore`] for the required split.
pub struct AgentDriver<S> {
    runtime_pvm: Vec<u8>,
    image: AgentImage,
    store: S,
    management_gas: Gas,
    catalog_cleanup_pending: bool,
    trust: Arc<dyn AgentTrustProvider>,
}

/// Host-admitted artifact carried beside a clean management request.
/// Requests which do not select a package must use `None`; this prevents an
/// uncommitted sidecar from being mistaken for guest-owned catalog state.
#[derive(Clone, Copy, Debug, Default)]
pub enum SdkManagementArtifacts<'a> {
    #[default]
    None,
    Actor(&'a super::package_admission::AdmittedActorPackage),
    Runtime(&'a super::package_admission::AdmittedRuntimePackage),
}

#[derive(Default)]
struct StagedSdkArtifacts {
    package: Option<(BlobRef, bool)>,
    program: Option<(ProgramId, bool)>,
    schema: Option<(DeploymentId, bool)>,
    policy: Option<(DeploymentId, bool)>,
    installation_data: Option<(BlobRef, bool)>,
}

impl StagedSdkArtifacts {
    fn rollback<S: AgentImageStore>(&self, store: &mut S) {
        if let Some((reference, true)) = &self.installation_data {
            let _ = store.remove_installation_data(reference);
        }
        if let Some((deployment, true)) = self.policy {
            let _ = store.remove_actor_policies(deployment);
        }
        if let Some((deployment, true)) = self.schema {
            let _ = store.remove_actor_schema(deployment);
        }
        if let Some((program, true)) = self.program {
            let _ = store.remove_program(program);
        }
        if let Some((reference, true)) = &self.package {
            let _ = store.remove_package(reference);
        }
    }
}

impl<S: AgentImageStore> AgentDriver<S> {
    /// Create one process-local Agent through the canonical AWRK management
    /// entry using an already signature/PVM-admitted VOS3 runtime package.
    pub fn create_sdk(
        runtime_package: super::package_admission::AdmittedRuntimePackage,
        descriptor: crate::agent_sdk::AgentDescriptor,
        mut store: S,
        trust: Arc<dyn AgentTrustProvider>,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
    ) -> Result<Self, AgentDriverError> {
        validate_sdk_process_local_profile(descriptor.identity.profile)?;
        verify_clean_runtime_package_binding(&descriptor, &runtime_package)?;
        if store.load()?.is_some() {
            return Err(AgentDriverError::Store(AgentStoreError::Conflict));
        }
        let observed_slot = trust
            .current_logical_slot()
            .ok_or(AgentDriverError::TrustUnavailable)?;
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        verify_clean_management_receipt(&descriptor, &request, &authority, observed_slot, false)?;
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(request),
            authority: Some(Box::new(authority)),
            observed_slot,
        };
        let encoded = work
            .encode()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let expected = (runtime_package.program().0 == super::STANDARD_RUNTIME_PROGRAM_ID.0)
            .then(|| expected_standard_sdk_management_transition(&work))
            .transpose()?;
        let transition: crate::agent_sdk::RuntimeTransition = execute_runtime_canonical(
            runtime_package.program_bytes(),
            DEFAULT_MANAGEMENT_GAS,
            &encoded,
        )?;
        if expected
            .as_ref()
            .is_some_and(|expected| transition != *expected)
            || transition.outcome
                != crate::agent_sdk::RuntimeOutcome::Management(Ok(
                    crate::agent_sdk::ManagementReply::Created(descriptor.identity.clone()),
                ))
            || transition.state.is_empty()
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        if expected.is_some() {
            validate_clean_standard_descriptor(&transition.state, &descriptor)?;
        }
        let config = super::standard::clean_descriptor_to_legacy_config(&descriptor)
            .map_err(AgentDriverError::Lifecycle)?;
        let runtime_state = sdk_state_as_legacy(&transition.state);
        validate_state_size(&runtime_state, &config.runtime_contract)?;
        let runtime_program = ProgramId(runtime_package.program().0);
        let image = AgentImage {
            clean_descriptor: Some(descriptor.clone()),
            clean_management: Some(
                LocalManagementHistory::default()
                    .after_validated_transition(&work, &transition)
                    .map_err(|_| AgentDriverError::InvalidRuntime)?,
            ),
            revision: 1,
            runtime_program,
            config,
            runtime_state,
        };
        if !Self::inspect_sdk_actor_directory_image(
            runtime_package.program_bytes(),
            DEFAULT_MANAGEMENT_GAS,
            &image,
            &descriptor,
            observed_slot,
        )?
        .is_empty()
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let package_reference = sdk_blob_as_legacy(runtime_package.package_ref());
        let created_package =
            store.put_package(&package_reference, runtime_package.exact_bytes())?;
        if let Err(error) = store.put_program(runtime_program, runtime_package.program_bytes()) {
            if created_package {
                let _ = store.remove_package(&package_reference);
            }
            return Err(error.into());
        }
        store.commit(None, &image)?;
        let mut driver = Self {
            runtime_pvm: runtime_package.program_bytes().to_vec(),
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust,
        };
        driver.reconcile_catalog_after_commit();
        Ok(driver)
    }

    /// Open a clean-generation image. VOS3 admission is repeated from the
    /// exact persisted package; no process-local default or VOSK decoder is
    /// consulted.
    pub fn open_sdk(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, AgentDriverError> {
        let image = store.load()?.ok_or(AgentStoreError::Unavailable)?;
        let descriptor = clean_image_descriptor(&image)?;
        // The bundled implementation has an additional native parity check.
        // Other admitted runtimes own their private layout; the persisted
        // public envelope and exact package closure remain mandatory.
        if image.runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID {
            if clean_descriptor_from_state(&image.runtime_state)? != descriptor {
                return Err(AgentDriverError::InvalidRuntime);
            }
            let standard = super::wire::decode_standard_runtime_state(&image.runtime_state)
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
            if !image
                .clean_management
                .as_ref()
                .is_some_and(|history| history.matches_standard_state(&standard))
            {
                return Err(AgentDriverError::InvalidRuntime);
            }
        }
        validate_sdk_process_local_profile(descriptor.identity.profile)?;
        let projected = super::standard::clean_descriptor_to_legacy_config(&descriptor)
            .map_err(AgentDriverError::Lifecycle)?;
        if image.config != projected
            || image.runtime_program.0 != descriptor.identity.runtime_program.0
        {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        let package_reference = sdk_blob_as_legacy(&descriptor.runtime_package);
        let package_bytes = store
            .load_package(&package_reference)?
            .ok_or(AgentDriverError::PackageUnavailable(package_reference.hash))?;
        let runtime_package = super::package_admission::admit_runtime_package(&package_bytes)
            .map_err(AgentDriverError::PackageAdmission)?;
        verify_clean_runtime_package_binding(&descriptor, &runtime_package)?;
        let runtime_pvm = store
            .load_program(image.runtime_program)?
            .ok_or(AgentDriverError::ProgramUnavailable(image.runtime_program))?;
        if runtime_pvm != runtime_package.program_bytes() {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        // Recovered host history is a semantic projection, not an authority on
        // the guest's private state. Require agreement from the admitted PVM
        // for every runtime, with no program-ID exception or native fallback.
        let recovery_work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: legacy_state_as_sdk(&image.runtime_state),
            request: Box::new(crate::agent_sdk::ManagementRequest::InspectManagementHistory),
            authority: None,
            observed_slot: 0,
        };
        let recovery_input = recovery_work
            .encode()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let recovery: crate::agent_sdk::RuntimeTransition =
            execute_runtime_canonical(&runtime_pvm, DEFAULT_MANAGEMENT_GAS, &recovery_input)?;
        let expected_history = image
            .clean_management
            .as_ref()
            .ok_or(AgentDriverError::InvalidRuntime)?
            .recovery_commitment()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        if !crate::agent_sdk::recovery::management_history_reply_matches(
            &legacy_state_as_sdk(&image.runtime_state),
            expected_history,
            &recovery,
        ) {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let mut driver = Self {
            runtime_pvm,
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust,
        };
        driver.reconcile_catalog()?;
        Ok(driver)
    }

    /// Construct and validate the exact creation operation an authority must
    /// approve before any image or catalog artifact is written.
    pub(crate) fn create_request(
        config: &AgentConfig,
        runtime_package: &Package,
        trust: &dyn AgentTrustProvider,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        config.validate().map_err(AgentDriverError::InvalidConfig)?;
        validate_process_local_profile(config.identity.profile)?;
        verify_authority_anchor(trust, config)?;
        verify_runtime_package_binding(trust, config, runtime_package)?;
        Ok(LifecycleRequest::Create(config.clone()))
    }

    /// Create a new agent and durably consume its signed creation sequence
    /// before exposing the image.
    pub fn create(
        runtime_package: Package,
        config: AgentConfig,
        mut store: S,
        trust: Arc<dyn AgentTrustProvider>,
        authority: &AgentAuthorityReceipt,
    ) -> Result<Self, AgentDriverError> {
        let request = Self::create_request(&config, &runtime_package, trust.as_ref())?;
        let runtime_pvm = runtime_package.pvm.clone();
        let runtime_program = runtime_package.manifest.program;
        if store.load()?.is_some() {
            return Err(AgentDriverError::Store(AgentStoreError::Conflict));
        }
        let admission = verify_authority_admission(trust.as_ref(), authority, &config, &request)?;
        let output = execute_runtime(
            &runtime_pvm,
            DEFAULT_MANAGEMENT_GAS,
            RuntimeCall::new(
                RuntimeState::default(),
                LifecycleRequest::Authorized {
                    admission,
                    request: Box::new(request),
                },
            ),
        )?;
        if output.result != Ok(LifecycleReply::Created(config.identity.clone())) {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state, &config.runtime_contract)?;
        let image = AgentImage {
            clean_descriptor: None,
            clean_management: None,
            revision: 1,
            runtime_program,
            config,
            runtime_state: output.state,
        };
        let package_bytes = runtime_package.encode();
        let package_reference = image.config.runtime_package.clone();
        let created_package = store.put_package(&package_reference, &package_bytes)?;
        if let Err(error) = store.put_program(runtime_program, &runtime_pvm) {
            if created_package {
                let _ = store.remove_package(&package_reference);
            }
            return Err(error.into());
        }
        store.commit(None, &image)?;
        let mut driver = Self {
            runtime_pvm,
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust,
        };
        // The image is already durable. Catalog pruning is cleanup debt and
        // must never turn a successful Create into a caller-visible failure.
        driver.reconcile_catalog_after_commit();
        Ok(driver)
    }

    /// Open an existing agent. Creation is intentionally separate so an
    /// absent image can never be initialized without a durable authority
    /// disposition.
    pub fn open(store: S, trust: Arc<dyn AgentTrustProvider>) -> Result<Self, AgentDriverError> {
        let image = store.load()?.ok_or(AgentStoreError::Unavailable)?;
        image
            .config
            .validate()
            .map_err(AgentDriverError::InvalidConfig)?;
        validate_process_local_profile(image.config.identity.profile)?;
        verify_authority_anchor(trust.as_ref(), &image.config)?;
        let package_bytes = store.load_package(&image.config.runtime_package)?.ok_or(
            AgentDriverError::PackageUnavailable(image.config.runtime_package.hash),
        )?;
        let runtime_package = Package::decode(&package_bytes)
            .map_err(|_| AgentDriverError::Package(PackageError::InvalidRuntimeArtifacts))?;
        verify_runtime_package_binding(trust.as_ref(), &image.config, &runtime_package)?;
        let runtime_pvm = store
            .load_program(image.runtime_program)?
            .ok_or(AgentDriverError::ProgramUnavailable(image.runtime_program))?;
        if runtime_pvm != runtime_package.pvm
            || image.runtime_program != runtime_package.manifest.program
        {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        let mut driver = Self {
            runtime_pvm,
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust,
        };
        driver.reconcile_catalog()?;
        Ok(driver)
    }

    pub fn image(&self) -> &AgentImage {
        &self.image
    }

    /// Read the complete portable actor directory from one immutable image.
    /// No native runtime-state decoder participates in this query. Every
    /// page must preserve all state lanes and advance a bounded SDK cursor.
    pub(crate) fn inspect_sdk_actor_directory(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
    ) -> Result<Vec<crate::agent_sdk::ActorDirectoryRecord>, AgentDriverError> {
        Self::inspect_sdk_actor_directory_image(
            &self.runtime_pvm,
            self.management_gas,
            &self.image,
            descriptor,
            self.trust
                .current_logical_slot()
                .ok_or(AgentDriverError::TrustUnavailable)?,
        )
    }

    fn inspect_sdk_actor_directory_image(
        runtime_pvm: &[u8],
        management_gas: Gas,
        image: &AgentImage,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        observed_slot: u64,
    ) -> Result<Vec<crate::agent_sdk::ActorDirectoryRecord>, AgentDriverError> {
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork};
        if descriptor.validate().is_err()
            || image.clean_descriptor.as_ref() != Some(descriptor)
            || descriptor.identity.runtime_program.0 != image.runtime_program.0
            || super::standard::clean_descriptor_to_legacy_config(descriptor)
                .map_err(AgentDriverError::Lifecycle)?
                != image.config
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let limit = crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16;
        let maximum = descriptor.capabilities.max_actors as usize;
        let mut actors = Vec::new();
        let mut after = None;
        for _ in 0..maximum.div_ceil(usize::from(limit)).saturating_add(1) {
            let work = RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: legacy_state_as_sdk(&image.runtime_state),
                request: Box::new(ManagementRequest::InspectActors { after, limit }),
                authority: None,
                observed_slot,
            };
            let encoded = work
                .encode()
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
            let returned: crate::agent_sdk::RuntimeTransition = {
                #[cfg(test)]
                DIRECTORY_EXECUTIONS.with(|count| count.set(count.get() + 1));
                execute_runtime_canonical(runtime_pvm, management_gas, &encoded)?
            };
            if returned.state != legacy_state_as_sdk(&image.runtime_state) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = returned.outcome
            else {
                return Err(AgentDriverError::InvalidRuntime);
            };
            if page.validate().is_err()
                || page.entries.len() > usize::from(limit)
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
                return Err(AgentDriverError::InvalidRuntime);
            }
            actors.extend(page.entries);
            let Some(next) = page.next else {
                return Ok(actors);
            };
            if after == Some(next) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            after = Some(next);
        }
        Err(AgentDriverError::InvalidRuntime)
    }

    /// Resolve one invocation's complete immutable input closure from this
    /// driver's live image and catalog. The caller receives no store handle:
    /// every byte is copied only after the signed package, current runtime
    /// directory, and content references agree.
    pub(crate) fn physical_invocation_material(
        &self,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentDriverError> {
        self.physical_material(actor, true)
    }

    /// Authority reconciliation uses the same authenticated physical closure
    /// as invocation preparation, but must also inspect suspended actors so an
    /// omitted or altered non-routable installation cannot escape the audit.
    #[cfg(test)]
    pub(crate) fn physical_authority_material(
        &self,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentDriverError> {
        self.physical_material(actor, false)
    }

    /// A single physically executed directory, bound by borrowing to this
    /// immutable driver image. Records cannot be supplied or replaced by the
    /// caller; mutable lifecycle/execution access cannot coexist with the view.
    pub(crate) fn physical_authority_directory(
        &self,
    ) -> Result<PhysicalAuthorityDirectory<'_, S>, AgentDriverError> {
        let descriptor = clean_image_descriptor(&self.image)?;
        self.verify_physical_runtime(&descriptor)?;
        Ok(PhysicalAuthorityDirectory {
            driver: self,
            records: self.inspect_sdk_actor_directory(&descriptor)?,
        })
    }

    fn physical_material(
        &self,
        actor: crate::agent_sdk::ActorId,
        require_ready: bool,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentDriverError> {
        let descriptor = clean_image_descriptor(&self.image)?;
        self.verify_physical_runtime(&descriptor)?;
        let record = self.inspect_sdk_actor(&descriptor, actor)?;
        self.physical_material_from_record(record, require_ready)
    }

    /// Use the public sorted-directory cursor contract for an exact lookup:
    /// one runtime execution and at most one returned record, independent of
    /// directory page count. This does not eliminate whole-state VM input.
    fn inspect_sdk_actor(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<crate::agent_sdk::ActorDirectoryRecord, AgentDriverError> {
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork};
        let not_found =
            || AgentDriverError::SdkManagement(crate::agent_sdk::ManagementError::NotFound);
        if actor == crate::agent_sdk::ActorId::ZERO {
            return Err(not_found());
        }
        if descriptor.validate().is_err()
            || self.image.clean_descriptor.as_ref() != Some(descriptor)
            || descriptor.identity.runtime_program.0 != self.image.runtime_program.0
            || super::standard::clean_descriptor_to_legacy_config(descriptor)
                .map_err(AgentDriverError::Lifecycle)?
                != self.image.config
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let after = actor_lookup_cursor(actor);
        let state = legacy_state_as_sdk(&self.image.runtime_state);
        let work = RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: state.clone(),
            request: Box::new(ManagementRequest::InspectActors { after, limit: 1 }),
            authority: None,
            observed_slot: self
                .trust
                .current_logical_slot()
                .ok_or(AgentDriverError::TrustUnavailable)?,
        };
        let encoded = work
            .encode()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        #[cfg(test)]
        DIRECTORY_EXECUTIONS.with(|count| count.set(count.get() + 1));
        let returned: crate::agent_sdk::RuntimeTransition =
            execute_runtime_canonical(&self.runtime_pvm, self.management_gas, &encoded)?;
        if returned.state != state {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = returned.outcome else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        if page.validate().is_err()
            || page.entries.len() > 1
            || page
                .entries
                .first()
                .is_some_and(|record| record.entry.actor < actor)
            || page.entries.len() > descriptor.capabilities.max_actors as usize
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        page.entries
            .into_iter()
            .next()
            .filter(|record| record.entry.actor == actor)
            .ok_or_else(not_found)
    }

    /// Authenticate process bytes before asking the runtime for directory data.
    /// A borrowed directory view needs this once, not once per returned actor.
    fn verify_physical_runtime(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
    ) -> Result<(), AgentDriverError> {
        validate_sdk_process_local_profile(descriptor.identity.profile)?;
        let projected = super::standard::clean_descriptor_to_legacy_config(descriptor)
            .map_err(AgentDriverError::Lifecycle)?;
        if self.image.config != projected
            || self.image.runtime_program.0 != descriptor.identity.runtime_program.0
        {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        let runtime_package_reference = sdk_blob_as_legacy(&descriptor.runtime_package);
        let runtime_package_bytes = self.store.load_package(&runtime_package_reference)?.ok_or(
            AgentDriverError::PackageUnavailable(runtime_package_reference.hash),
        )?;
        let runtime_package =
            super::package_admission::admit_runtime_package(&runtime_package_bytes)
                .map_err(AgentDriverError::PackageAdmission)?;
        verify_clean_runtime_package_binding(descriptor, &runtime_package)?;
        let runtime_pvm = self.store.load_program(self.image.runtime_program)?.ok_or(
            AgentDriverError::ProgramUnavailable(self.image.runtime_program),
        )?;
        if runtime_pvm != runtime_package.program_bytes() || runtime_pvm != self.runtime_pvm {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        Ok(())
    }

    /// Callers hold an immutable driver borrow and have authenticated its
    /// runtime before obtaining this directory record.
    fn physical_material_from_record(
        &self,
        record: crate::agent_sdk::ActorDirectoryRecord,
        require_ready: bool,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentDriverError> {
        let descriptor = clean_image_descriptor(&self.image)?;
        if require_ready && record.entry.suspended {
            return Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest,
            ));
        }
        validate_loaded_clean_actor(&self.store, &descriptor, &record.entry)?;

        let actor_package_reference = sdk_blob_as_legacy(&record.entry.package);
        let actor_package_bytes = self.store.load_package(&actor_package_reference)?.ok_or(
            AgentDriverError::PackageUnavailable(actor_package_reference.hash),
        )?;
        let actor_package = super::package_admission::admit_actor_package(&actor_package_bytes)
            .map_err(AgentDriverError::PackageAdmission)?;
        if record.install_request == crate::agent_sdk::Hash::ZERO
            || actor_package.package_ref() != &record.entry.package
        {
            return Err(AgentDriverError::InvalidRuntime);
        }

        let program = self
            .store
            .load_program(ProgramId(record.entry.program.0))?
            .ok_or(AgentDriverError::ProgramUnavailable(ProgramId(
                record.entry.program.0,
            )))?;
        let schema = self
            .store
            .load_actor_schema(DeploymentId(record.entry.deployment.0))?
            .ok_or(AgentDriverError::SchemaUnavailable(DeploymentId(
                record.entry.deployment.0,
            )))?;
        let policies = self
            .store
            .load_actor_policies(DeploymentId(record.entry.deployment.0))?
            .ok_or(AgentDriverError::PolicyUnavailable(DeploymentId(
                record.entry.deployment.0,
            )))?;
        let installation_data = match record.entry.installation_data.as_ref() {
            Some(reference) => Some(
                self.store
                    .load_installation_data(&sdk_blob_as_legacy(reference))?
                    .ok_or(AgentDriverError::PackageUnavailable(Hash(reference.hash.0)))?,
            ),
            None => None,
        };
        let portable_blob = |blob: RuntimeBlob| crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef {
                hash: crate::agent_sdk::Hash(blob.reference.hash.0),
                len: blob.reference.len,
            },
            bytes: blob.bytes,
        };
        let observed_slot = self
            .trust
            .current_logical_slot()
            .ok_or(AgentDriverError::TrustUnavailable)?;
        Ok(super::invocation_preparation::PhysicalInvocationMaterial {
            descriptor,
            install_request: record.install_request,
            actor: record,
            producer: actor_package.producer(),
            contract: actor_package.manifest().contract,
            requirements: actor_package.requirements(),
            root_provenance: false,
            observed_slot,
            program: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&program),
                bytes: program,
            },
            schema: portable_blob(schema),
            policies: portable_blob(policies),
            installation_data: installation_data.map(portable_blob),
        })
    }

    pub fn set_management_gas(&mut self, gas: Gas) {
        self.management_gas = gas;
    }

    /// Whether a post-commit catalog cleanup needs to be retried. Cleanup
    /// failure never rewrites an already committed lifecycle disposition;
    /// callers can surface this as a health condition and retry explicitly.
    pub const fn catalog_cleanup_pending(&self) -> bool {
        self.catalog_cleanup_pending
    }

    /// Authenticate the committed directory's complete artifact closure and
    /// prune every unreferenced catalog entry.
    pub fn reconcile_catalog(&mut self) -> Result<(), AgentDriverError> {
        let references = self.catalog_references()?;
        self.store.reconcile_catalog(&references)?;
        self.catalog_cleanup_pending = false;
        Ok(())
    }

    fn reconcile_catalog_after_commit(&mut self) {
        if self.reconcile_catalog().is_err() {
            self.catalog_cleanup_pending = true;
        }
    }

    fn lifecycle(&mut self, request: LifecycleRequest) -> Result<LifecycleReply, AgentDriverError> {
        if matches!(request, LifecycleRequest::Create(_)) {
            return Err(AgentDriverError::Lifecycle(LifecycleError::AlreadyCreated));
        }
        if matches!(
            request,
            LifecycleRequest::UpgradeRuntime { .. }
                | LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
        ) {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        let read_only = matches!(request, LifecycleRequest::Inspect { .. });
        let authorized = matches!(request, LifecycleRequest::Authorized { .. });
        let output = execute_runtime(
            &self.runtime_pvm,
            self.management_gas,
            RuntimeCall::new(self.image.runtime_state.clone(), request),
        )?;
        match output.result {
            Err(error) => {
                if output.state != self.image.runtime_state {
                    if !authorized {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                    validate_state_size(&output.state, &self.image.config.runtime_contract)?;
                    self.commit_runtime_state(output.state)?;
                    self.reconcile_catalog_after_commit();
                }
                Err(AgentDriverError::Lifecycle(error))
            }
            Ok(reply) => {
                validate_state_size(&output.state, &self.image.config.runtime_contract)?;
                if read_only {
                    if output.state != self.image.runtime_state {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                    return Ok(reply);
                }
                if authorized && output.state == self.image.runtime_state {
                    return Ok(reply);
                }
                self.commit_runtime_state(output.state)?;
                self.reconcile_catalog_after_commit();
                Ok(reply)
            }
        }
    }

    fn commit_runtime_state(
        &mut self,
        runtime_state: RuntimeState,
    ) -> Result<(), AgentDriverError> {
        let next_revision = self
            .image
            .revision
            .checked_add(1)
            .ok_or(AgentDriverError::InvalidRuntime)?;
        let next = AgentImage {
            clean_descriptor: self.image.clean_descriptor.clone(),
            clean_management: self.image.clean_management.clone(),
            revision: next_revision,
            runtime_program: self.image.runtime_program,
            config: self.image.config.clone(),
            runtime_state,
        };
        self.store.commit(Some(self.image.revision), &next)?;
        self.image = next;
        Ok(())
    }

    /// Recover the exact durable creation disposition after response loss.
    pub fn retry_create(
        &mut self,
        config: &AgentConfig,
        runtime_package: &Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentDriverError> {
        if config != &self.image.config {
            return Err(AgentDriverError::RuntimeProgramMismatch);
        }
        let request = Self::create_request(config, runtime_package, self.trust.as_ref())?;
        let admission = self.authorize(authority, &request)?;
        match self.lifecycle(LifecycleRequest::Authorized {
            admission,
            request: Box::new(request),
        })? {
            LifecycleReply::Created(identity) if identity == config.identity => Ok(identity),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    pub fn inspect(
        &mut self,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<super::ActorDirectoryPage, AgentDriverError> {
        match self.lifecycle(LifecycleRequest::Inspect { after, limit })? {
            LifecycleReply::Directory(page) => Ok(page),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    /// Construct the exact lifecycle operation an authority must approve for
    /// this signed package and target location.
    pub fn actor_install_request(
        &self,
        installation_id: crate::service::InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        if installation_id == crate::service::InstallationId::ZERO
            || registry_reservation == Hash::ZERO
            || name.is_empty()
            || name.len() > crate::service::MAX_ACTOR_NAME_BYTES
            || parent == Some(ActorId::ZERO)
        {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        verify_trusted_package(self.trust.as_ref(), &self.image.config, package)?;
        if installation_data
            .as_ref()
            .is_some_and(|bytes| bytes.len() > super::MAX_INSTALLATION_DATA_BYTES)
            || !package
                .accepts_installation_data(installation_data.as_deref())
                .map_err(AgentDriverError::Package)?
        {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(AgentDriverError::Package(PackageError::WrongKind));
        };
        if !self.image.config.runtime_contract.supports(contract) {
            return Err(AgentDriverError::Package(PackageError::InvalidActorAbi));
        }
        let actor = match parent {
            Some(parent) => ActorId::owned_child(parent, &name),
            None => ActorId::top_level(self.image.config.identity.agent, &name),
        };
        let agent_schema = super::schema::decode(&package.agent_schema).ok_or(
            AgentDriverError::Package(PackageError::InvalidActorArtifacts),
        )?;
        let installation_data = installation_data.map(|bytes| super::InstallationData {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        let installation_reference = installation_data
            .as_ref()
            .map(|data| data.reference.clone());
        let package_reference = BlobRef::of_bytes(&package.encode());
        let schema_reference = BlobRef::of_bytes(&package.agent_schema);
        let policy_reference = BlobRef::of_bytes(&package.role_policies);
        let constructor_abi = package
            .constructor_abi()
            .map_err(AgentDriverError::Package)?;
        if installation_reference.as_ref().is_some_and(|data| {
            [&package_reference, &schema_reference, &policy_reference]
                .into_iter()
                .any(|artifact| artifact.hash == data.hash)
        }) {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        Ok(LifecycleRequest::Install(InstallActor {
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
                role_policies: policy_reference.clone(),
                constructor_abi,
                installation_data: installation_reference,
                state_layout: agent_schema.state_layout_hash(),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: package.deployment_signature.producer,
            package: package_reference,
            agent_schema: schema_reference,
            role_policies: policy_reference,
            constructor_abi,
            installation_data,
            state_layout: agent_schema.state_layout_hash(),
            contract,
            requirements,
        }))
    }

    pub fn install_actor(
        &mut self,
        authority: &AgentAuthorityReceipt,
        installation_id: crate::service::InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<ActorEntry, AgentDriverError> {
        let request = self.actor_install_request(
            installation_id,
            registry_reservation,
            name,
            parent,
            installation_data,
            package,
        )?;
        let admission = self.authorize(authority, &request)?;
        let LifecycleRequest::Install(install) = request else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        let entry = install.entry.clone();
        let package_reference = install.package.clone();
        let schema_reference = install.agent_schema.clone();
        let policy_reference = install.role_policies.clone();
        let installation_data = install.installation_data.clone();
        let deployment = install.entry.deployment;
        let package_bytes = package.encode();
        let created_package = self.store.put_package(&package_reference, &package_bytes)?;
        let created_program = match self
            .store
            .put_program(package.manifest.program, &package.pvm)
        {
            Ok(created) => created,
            Err(error) => {
                if created_package {
                    let _ = self.store.remove_package(&package_reference);
                }
                return Err(error.into());
            }
        };
        let created_schema =
            match self
                .store
                .put_actor_schema(deployment, &schema_reference, &package.agent_schema)
            {
                Ok(created) => created,
                Err(error) => {
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                    return Err(error.into());
                }
            };
        let created_policies = match self.store.put_actor_policies(
            deployment,
            &policy_reference,
            &package.role_policies,
        ) {
            Ok(created) => created,
            Err(error) => {
                if created_schema {
                    let _ = self.store.remove_actor_schema(deployment);
                }
                if created_program {
                    let _ = self.store.remove_program(package.manifest.program);
                }
                if created_package {
                    let _ = self.store.remove_package(&package_reference);
                }
                return Err(error.into());
            }
        };
        let created_installation_data = match installation_data.as_ref() {
            Some(data) => match self
                .store
                .put_installation_data(&data.reference, &data.bytes)
            {
                Ok(created) => created,
                Err(error) => {
                    if created_policies {
                        let _ = self.store.remove_actor_policies(deployment);
                    }
                    if created_schema {
                        let _ = self.store.remove_actor_schema(deployment);
                    }
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                    return Err(error.into());
                }
            },
            None => false,
        };
        let reply = self.lifecycle(LifecycleRequest::Authorized {
            admission,
            request: Box::new(LifecycleRequest::Install(install)),
        });
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                // A typed runtime refusal happened before image persistence,
                // so newly staged artifacts are unowned and may be removed.
                // Store failures are intentionally retained: a rename may
                // have reached durable storage before a directory sync error,
                // and deleting its program would make that image unusable.
                if matches!(error, AgentDriverError::Lifecycle(_)) {
                    if created_installation_data && let Some(data) = &installation_data {
                        let _ = self.store.remove_installation_data(&data.reference);
                    }
                    if created_policies {
                        let _ = self.store.remove_actor_policies(deployment);
                    }
                    if created_schema {
                        let _ = self.store.remove_actor_schema(deployment);
                    }
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                }
                return Err(error);
            }
        };
        // Exact receipt recovery may return a historical Install disposition
        // without committing current directory state. Retire any artifacts
        // staged only to reconstruct that request.
        self.reconcile_catalog_after_commit();
        match reply {
            LifecycleReply::Installed(installed) if installed == entry => Ok(installed),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    pub fn actor_upgrade_request(
        &self,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        if actor == ActorId::ZERO || from_deployment == DeploymentId::ZERO {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        verify_trusted_package(self.trust.as_ref(), &self.image.config, package)?;
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(AgentDriverError::Package(PackageError::WrongKind));
        };
        let constructor_abi = package
            .constructor_abi()
            .map_err(AgentDriverError::Package)?;
        match self.inspect_actor(actor) {
            Ok(record) if record.entry.deployment == from_deployment => {
                if !package
                    .accepts_installation_data_reference(record.entry.installation_data.as_ref())
                    .map_err(AgentDriverError::Package)?
                {
                    return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
                }
                if record.entry.constructor_abi != constructor_abi {
                    return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
                }
            }
            Ok(_) | Err(AgentDriverError::Lifecycle(LifecycleError::NotFound)) => {}
            Err(error) => return Err(error),
        }
        if !self.image.config.runtime_contract.supports(contract) {
            return Err(AgentDriverError::Package(PackageError::InvalidActorAbi));
        }
        let agent_schema = super::schema::decode(&package.agent_schema).ok_or(
            AgentDriverError::Package(PackageError::InvalidActorArtifacts),
        )?;
        Ok(LifecycleRequest::UpgradeActor(super::UpgradeActor {
            actor,
            from_deployment,
            to_deployment: package.deployment_id(),
            to_program: package.manifest.program,
            producer: package.deployment_signature.producer,
            package: BlobRef::of_bytes(&package.encode()),
            agent_schema: BlobRef::of_bytes(&package.agent_schema),
            role_policies: BlobRef::of_bytes(&package.role_policies),
            constructor_abi,
            state_layout: agent_schema.state_layout_hash(),
            contract,
            requirements,
        }))
    }

    pub fn upgrade_actor(
        &mut self,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<ActorEntry, AgentDriverError> {
        let request = self.actor_upgrade_request(actor, from_deployment, package)?;
        let admission = self.authorize(authority, &request)?;
        let LifecycleRequest::UpgradeActor(upgrade) = request else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        let package_bytes = package.encode();
        let package_reference = upgrade.package.clone();
        let schema_reference = upgrade.agent_schema.clone();
        let policy_reference = upgrade.role_policies.clone();
        let deployment = upgrade.to_deployment;
        let created_package = self.store.put_package(&package_reference, &package_bytes)?;
        let created_program = match self
            .store
            .put_program(package.manifest.program, &package.pvm)
        {
            Ok(created) => created,
            Err(error) => {
                if created_package {
                    let _ = self.store.remove_package(&package_reference);
                }
                return Err(error.into());
            }
        };
        let created_schema =
            match self
                .store
                .put_actor_schema(deployment, &schema_reference, &package.agent_schema)
            {
                Ok(created) => created,
                Err(error) => {
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                    return Err(error.into());
                }
            };
        let created_policies = match self.store.put_actor_policies(
            deployment,
            &policy_reference,
            &package.role_policies,
        ) {
            Ok(created) => created,
            Err(error) => {
                if created_schema {
                    let _ = self.store.remove_actor_schema(deployment);
                }
                if created_program {
                    let _ = self.store.remove_program(package.manifest.program);
                }
                if created_package {
                    let _ = self.store.remove_package(&package_reference);
                }
                return Err(error.into());
            }
        };
        let reply = self.lifecycle(LifecycleRequest::Authorized {
            admission,
            request: Box::new(LifecycleRequest::UpgradeActor(upgrade)),
        });
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                if matches!(error, AgentDriverError::Lifecycle(_)) {
                    if created_policies {
                        let _ = self.store.remove_actor_policies(deployment);
                    }
                    if created_schema {
                        let _ = self.store.remove_actor_schema(deployment);
                    }
                    if created_program {
                        let _ = self.store.remove_program(package.manifest.program);
                    }
                    if created_package {
                        let _ = self.store.remove_package(&package_reference);
                    }
                }
                return Err(error);
            }
        };
        self.reconcile_catalog_after_commit();
        match reply {
            LifecycleReply::Upgraded(entry)
                if entry.actor == actor && entry.deployment == package.deployment_id() =>
            {
                Ok(entry)
            }
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    pub fn suspend_actor(
        &mut self,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentDriverError> {
        let request = self.actor_suspend_request(actor)?;
        self.authorized_actor_lifecycle(authority, request)
    }

    pub fn resume_actor(
        &mut self,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentDriverError> {
        let request = self.actor_resume_request(actor)?;
        self.authorized_actor_lifecycle(authority, request)
    }

    pub fn actor_suspend_request(
        &self,
        actor: ActorId,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        Ok(LifecycleRequest::Suspend {
            actor,
            expected_deployment: self.inspect_actor(actor)?.entry.deployment,
        })
    }

    pub fn actor_resume_request(
        &self,
        actor: ActorId,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        Ok(LifecycleRequest::Resume {
            actor,
            expected_deployment: self.inspect_actor(actor)?.entry.deployment,
        })
    }

    /// Resolve one actor and its immutable install incarnation through the
    /// runtime-owned directory.
    ///
    /// Callers use this record to construct [`ActorInvocation`] values; the
    /// generation is guest-derived and must never be guessed from catalog
    /// sidecars or deployment metadata. Inspection is read-only and every
    /// page must preserve the exact runtime state.
    pub fn inspect_actor(&self, actor: ActorId) -> Result<ActorDirectoryRecord, AgentDriverError> {
        if actor == ActorId::ZERO {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        let page_limit = usize::from(super::standard::MAX_DIRECTORY_PAGE);
        let max_actors = usize::try_from(self.image.config.capabilities.max_actors)
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let max_pages = max_actors.div_ceil(page_limit).saturating_add(1);
        let mut after = None;
        let mut seen = 0usize;
        for _ in 0..max_pages {
            let output = execute_runtime(
                &self.runtime_pvm,
                self.management_gas,
                RuntimeCall::new(
                    self.image.runtime_state.clone(),
                    LifecycleRequest::Inspect {
                        after,
                        limit: super::standard::MAX_DIRECTORY_PAGE,
                    },
                ),
            )?;
            if output.state != self.image.runtime_state {
                return Err(AgentDriverError::InvalidRuntime);
            }
            let page = match output.result {
                Ok(LifecycleReply::Directory(page)) => page,
                Ok(_) => return Err(AgentDriverError::InvalidRuntime),
                Err(error) => return Err(AgentDriverError::Lifecycle(error)),
            };
            seen = validate_actor_directory_page(after, &page, page_limit, seen, max_actors)?;
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
                return Err(AgentDriverError::Lifecycle(LifecycleError::NotFound));
            }
            let Some(next) = page.next else {
                return Err(AgentDriverError::Lifecycle(LifecycleError::NotFound));
            };
            if after == Some(next) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            after = Some(next);
        }
        Err(AgentDriverError::InvalidRuntime)
    }

    fn validate_invocation_directory(
        &self,
        invocation: &ActorInvocation,
    ) -> Result<ActorDirectoryRecord, AgentDriverError> {
        let directory = match self.inspect_actor(invocation.actor) {
            Ok(record) => record,
            Err(AgentDriverError::Lifecycle(LifecycleError::NotFound)) => {
                return Err(AgentDriverError::Execution(ActorExecutionError::NotFound));
            }
            Err(error) => return Err(error),
        };
        if directory.incarnation != invocation.incarnation {
            return Err(AgentDriverError::Execution(
                ActorExecutionError::StaleIncarnation,
            ));
        }
        if directory.entry.deployment != invocation.deployment {
            return Err(AgentDriverError::Execution(
                ActorExecutionError::StaleDeployment,
            ));
        }
        if directory.entry.program != invocation.program {
            return Err(AgentDriverError::Execution(
                ActorExecutionError::WrongProgram,
            ));
        }
        Ok(directory)
    }

    fn authorized_actor_lifecycle(
        &mut self,
        authority: &AgentAuthorityReceipt,
        request: LifecycleRequest,
    ) -> Result<ActorEntry, AgentDriverError> {
        let expected = match &request {
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            } => (*actor, *expected_deployment, true),
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            } => (*actor, *expected_deployment, false),
            _ => return Err(AgentDriverError::InvalidRuntime),
        };
        let admission = self.authorize(authority, &request)?;
        let reply = self.lifecycle(LifecycleRequest::Authorized {
            admission,
            request: Box::new(request),
        })?;
        validate_actor_lifecycle_reply(expected, reply)
    }

    pub fn remove_actor(
        &mut self,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentDriverError> {
        let request = Self::actor_remove_request(actor, expected_deployment)?;
        let admission = self.authorize(authority, &request)?;
        match self.lifecycle(LifecycleRequest::Authorized {
            admission,
            request: Box::new(request),
        })? {
            LifecycleReply::Removed(removed) if removed == actor => Ok(()),
            _ => Err(AgentDriverError::InvalidRuntime),
        }
    }

    pub fn actor_remove_request(
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        if actor == ActorId::ZERO || expected_deployment == DeploymentId::ZERO {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        Ok(LifecycleRequest::RemoveLeaf {
            actor,
            expected_deployment,
        })
    }

    fn authorize(
        &self,
        authority: &AgentAuthorityReceipt,
        request: &LifecycleRequest,
    ) -> Result<LifecycleAuthorityAdmission, AgentDriverError> {
        verify_authority_admission(self.trust.as_ref(), authority, &self.image.config, request)
    }

    /// Execute one authenticated actor invocation through this agent's
    /// runtime. Exact terminal outcomes commit only their owning result
    /// clock; nondurable admission failures remain byte-identical driver
    /// errors.
    pub fn invoke(
        &mut self,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentDriverError> {
        invocation.validate().map_err(AgentDriverError::Execution)?;
        authority
            .validate_for(
                &self.image.config.authority,
                self.image.config.identity.space,
                self.image.config.identity.agent,
                &invocation,
            )
            .map_err(AgentDriverError::Authority)?;
        let observed_slot = self
            .trust
            .current_logical_slot()
            .ok_or(AgentDriverError::TrustUnavailable)?;
        self.invoke_raw(invocation, authority.clone(), observed_slot)
    }

    /// Execute one clean-generation management request. Package-bearing
    /// mutations accept only opaque values returned by VOS3 host admission;
    /// all other requests reject ambient artifacts.
    pub fn manage_sdk(
        &mut self,
        request: crate::agent_sdk::ManagementRequest,
        authority: Option<crate::agent_sdk::authority::AuthorityReceipt>,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        let current = clean_image_descriptor(&self.image)?;
        let read_only = matches!(
            &request,
            crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::InspectManagementHistory
        );
        let receipt_history = match authority.as_ref() {
            Some(receipt) => self
                .image
                .clean_management
                .as_ref()
                .ok_or(AgentDriverError::InvalidRuntime)?
                .classify(&request, receipt),
            None => CleanManagementReceiptHistory::Unseen,
        };
        let exact_retry = matches!(
            receipt_history,
            CleanManagementReceiptHistory::Retained { .. }
        );
        let allow_historical_runtime = matches!(
            receipt_history,
            CleanManagementReceiptHistory::Retained { .. }
                | CleanManagementReceiptHistory::Consumed
        );
        let skip_artifact_staging = receipt_history != CleanManagementReceiptHistory::Unseen;
        let observed_slot = match self.trust.current_logical_slot() {
            Some(slot) => slot,
            None if read_only || skip_artifact_staging => 0,
            None => return Err(AgentDriverError::TrustUnavailable),
        };
        match (&request, authority.as_ref()) {
            (
                crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::InspectManagementHistory,
                None,
            ) => {}
            (_, Some(receipt)) => {
                // An exact durable retry recovers an already accepted result;
                // its signed window is checked at that acceptance, not now.
                // Other receipts still require a live current observation.
                let authorization_slot = match receipt_history {
                    CleanManagementReceiptHistory::Retained { observed_slot } => observed_slot,
                    _ => observed_slot,
                };
                verify_clean_management_receipt(
                    &current,
                    &request,
                    receipt,
                    authorization_slot,
                    allow_historical_runtime,
                )?;
            }
            _ => return Err(AgentDriverError::InvalidRuntime),
        }
        let staged = if skip_artifact_staging {
            validate_sdk_retry_artifact_shape(&request, artifacts)?;
            StagedSdkArtifacts::default()
        } else {
            validate_sdk_management_artifacts(&current, &request, artifacts)?;
            self.stage_sdk_management_artifacts(&request, artifacts)?
        };
        let runtime_deployment = match authority.as_ref() {
            Some(receipt) => receipt.selector.runtime_deployment,
            None => current.identity.runtime_deployment,
        };
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: current.identity.space,
            agent: current.identity.agent,
            runtime_deployment,
            state: legacy_state_as_sdk(&self.image.runtime_state),
            request: Box::new(request.clone()),
            authority: authority.map(Box::new),
            observed_slot,
        };
        let encoded = match work.encode() {
            Ok(encoded) => encoded,
            Err(_) => {
                staged.rollback(&mut self.store);
                return Err(AgentDriverError::InvalidRuntime);
            }
        };
        let expected = match (self.image.runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID)
            .then(|| expected_standard_sdk_management_transition(&work))
            .transpose()
        {
            Ok(expected) => expected,
            Err(error) => {
                staged.rollback(&mut self.store);
                return Err(error);
            }
        };
        let returned: crate::agent_sdk::RuntimeTransition =
            match execute_runtime_canonical(&self.runtime_pvm, self.management_gas, &encoded) {
                Ok(returned) => returned,
                Err(error) => {
                    staged.rollback(&mut self.store);
                    return Err(error);
                }
            };
        if expected
            .as_ref()
            .is_some_and(|expected| returned != *expected)
            || !matches!(
                &returned.outcome,
                crate::agent_sdk::RuntimeOutcome::Management(_)
            )
            || !sdk_management_reply_matches(&current, &request, &returned.outcome)
            || !super::wire::clean_management_lane_changes_allowed(
                &request,
                &self.image.runtime_state,
                &sdk_state_as_legacy(&returned.state),
                matches!(
                    returned.outcome,
                    crate::agent_sdk::RuntimeOutcome::Management(Ok(_))
                ),
            )
        {
            staged.rollback(&mut self.store);
            return Err(AgentDriverError::InvalidRuntime);
        }

        let next_state = sdk_state_as_legacy(&returned.state);
        let next_management = match self
            .image
            .clean_management
            .as_ref()
            .ok_or(DecodeError::NonCanonical)
            .and_then(|history| history.after_validated_transition(&work, &returned))
        {
            Ok(history) => history,
            Err(_) => {
                staged.rollback(&mut self.store);
                return Err(AgentDriverError::InvalidRuntime);
            }
        };
        let next_descriptor = match sdk_descriptor_after_management(
            &current,
            &request,
            &returned.outcome,
            exact_retry,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                staged.rollback(&mut self.store);
                return Err(error);
            }
        };
        let success = matches!(
            &returned.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(_))
        );
        let runtime_upgrade = match (&request, success, exact_retry, artifacts) {
            (
                crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade),
                true,
                false,
                SdkManagementArtifacts::Runtime(package),
            ) => Some((upgrade.as_ref(), package)),
            _ => None,
        };
        let next_config = match super::standard::clean_descriptor_to_legacy_config(&next_descriptor)
            .map_err(AgentDriverError::Lifecycle)
        {
            Ok(config) => config,
            Err(error) => {
                staged.rollback(&mut self.store);
                return Err(error);
            }
        };
        if let Err(error) = validate_state_size(&next_state, &next_config.runtime_contract) {
            staged.rollback(&mut self.store);
            return Err(error);
        }
        let next_program = runtime_upgrade.map_or(self.image.runtime_program, |(upgrade, _)| {
            ProgramId(upgrade.to_program.0)
        });
        if next_descriptor.identity.runtime_program.0 != next_program.0 {
            staged.rollback(&mut self.store);
            return Err(AgentDriverError::InvalidRuntime);
        }
        let changed = next_state != self.image.runtime_state
            || self.image.clean_management.as_ref() != Some(&next_management)
            || self.image.clean_descriptor.as_ref() != Some(&next_descriptor)
            || next_config != self.image.config
            || next_program != self.image.runtime_program;
        if changed {
            let revision = match self.image.revision.checked_add(1) {
                Some(revision) => revision,
                None => {
                    staged.rollback(&mut self.store);
                    return Err(AgentDriverError::InvalidRuntime);
                }
            };
            let next = AgentImage {
                clean_descriptor: Some(next_descriptor.clone()),
                clean_management: Some(next_management),
                revision,
                runtime_program: next_program,
                config: next_config,
                runtime_state: next_state,
            };
            if let Some((_, package)) = runtime_upgrade {
                // The old runtime's successful reply is not evidence that the
                // admitted target can interpret the migrated state. Execute the
                // target's public, state-preserving directory query before the
                // atomic cutover and require the exact existing installations.
                let migration = (|| {
                    let before = Self::inspect_sdk_actor_directory_image(
                        &self.runtime_pvm,
                        self.management_gas,
                        &self.image,
                        &current,
                        observed_slot,
                    )?;
                    let after = Self::inspect_sdk_actor_directory_image(
                        package.program_bytes(),
                        self.management_gas,
                        &next,
                        &next_descriptor,
                        observed_slot,
                    )?;
                    if before != after {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                    Ok(())
                })();
                if let Err(error) = migration {
                    staged.rollback(&mut self.store);
                    return Err(error);
                }
            }
            // A failed commit may have become durable before returning an I/O
            // error; staged artifacts are therefore intentionally retained.
            self.store.commit(Some(self.image.revision), &next)?;
            self.image = next;
            if let Some((_, package)) = runtime_upgrade {
                self.runtime_pvm = package.program_bytes().to_vec();
            }
        }
        self.reconcile_catalog_after_commit();
        Ok(returned.outcome)
    }

    fn stage_sdk_management_artifacts(
        &mut self,
        request: &crate::agent_sdk::ManagementRequest,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<StagedSdkArtifacts, AgentDriverError> {
        let mut staged = StagedSdkArtifacts::default();
        let result = match (request, artifacts) {
            (
                crate::agent_sdk::ManagementRequest::Install(install),
                SdkManagementArtifacts::Actor(package),
            ) => stage_sdk_actor_artifacts(
                &mut self.store,
                package,
                install.installation_data.as_ref(),
                &mut staged,
            ),
            (
                crate::agent_sdk::ManagementRequest::UpgradeActor(_),
                SdkManagementArtifacts::Actor(package),
            ) => stage_sdk_actor_artifacts(&mut self.store, package, None, &mut staged),
            (
                crate::agent_sdk::ManagementRequest::UpgradeRuntime(_),
                SdkManagementArtifacts::Runtime(package),
            ) => stage_sdk_runtime_artifacts(&mut self.store, package, &mut staged),
            (_, SdkManagementArtifacts::None) => Ok(()),
            _ => Err(AgentDriverError::InvalidRuntime),
        };
        if let Err(error) = result {
            staged.rollback(&mut self.store);
            return Err(error);
        }
        Ok(staged)
    }

    /// Execute one clean-generation invocation. A Yielded outcome is an
    /// atomically persisted intermediate revision and is returned to the
    /// scheduler; it is never converted into a terminal actor result.
    pub fn invoke_sdk(
        &mut self,
        invocation: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        if !invocation.validate() {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let observed_slot = self
            .trust
            .current_logical_slot()
            .ok_or(AgentDriverError::TrustUnavailable)?;
        if self.image.runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID {
            validate_standard_sdk_invoke_preflight(
                &self.image.runtime_state,
                &invocation,
                &authorization,
                observed_slot,
            )?;
        }
        let gas = self
            .management_gas
            .checked_add(invocation.gas)
            .ok_or(AgentDriverError::InvalidRuntime)?;
        self.apply_sdk_work(
            crate::agent_sdk::RuntimeWork::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: legacy_state_as_sdk(&self.image.runtime_state),
                invocation: Box::new(invocation),
                authorization: Box::new(authorization),
                observed_slot,
            },
            gas,
        )
    }

    /// Resume one previously persisted clean continuation. Immutable
    /// availability is supplied again by exact reference; the guest checks
    /// the FIFO sequence and continuation commitment before restoring it.
    pub fn resume_sdk(
        &mut self,
        resume: crate::agent_sdk::ResumeWork,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        if !resume.validate() {
            return Err(AgentDriverError::InvalidRuntime);
        }
        if resume.input.is_some() {
            return Err(AgentDriverError::InvalidRuntime);
        }
        if self.image.runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID {
            validate_standard_sdk_resume_preflight(&self.image.runtime_state, &resume)?;
        }
        self.apply_sdk_work(
            crate::agent_sdk::RuntimeWork::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: legacy_state_as_sdk(&self.image.runtime_state),
                resume: Box::new(resume),
            },
            self.management_gas
                .saturating_add(super::execution::MAX_INVOCATION_GAS_CEILING),
        )
    }

    /// Resume from an exact delivered Yielded record while deriving every
    /// executable field from durable guest state and the originally accepted
    /// work/authorization pair. A retry after the resume committed recovers
    /// the successor Yielded/terminal state and never allocates a fresh
    /// invocation slot.
    pub fn resume_sdk_exact(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        if !work.validate()
            || !authorization.matches_work(&work)
            || !yielded.validate()
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
            return Err(AgentDriverError::InvalidRuntime);
        }
        let observed_slot = self
            .trust
            .current_logical_slot()
            .ok_or(AgentDriverError::TrustUnavailable)?;
        let resume = |yielded: crate::agent_sdk::YieldedInvocation| crate::agent_sdk::ResumeWork {
            invocation: yielded.invocation,
            actor: yielded.actor,
            incarnation: yielded.incarnation,
            deployment: yielded.deployment,
            program: yielded.program,
            mode: yielded.mode,
            continuation: yielded.continuation,
            ready_sequence: yielded.ready_sequence,
            installation_data: yielded.installation_data,
            availability: work.availability.clone(),
            input: None,
        };
        if self.image.runtime_program != super::STANDARD_RUNTIME_PROGRAM_ID {
            let resume = resume(yielded);
            let runtime_work = crate::agent_sdk::RuntimeWork::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: legacy_state_as_sdk(&self.image.runtime_state),
                resume: Box::new(resume),
            };
            return self.apply_sdk_work_with_exact(
                runtime_work,
                self.management_gas
                    .saturating_add(super::execution::MAX_INVOCATION_GAS_CEILING),
                Some(&work),
            );
        }
        let state = super::wire::decode_standard_runtime_state(&self.image.runtime_state)
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let mut runtime = super::standard::StandardAgentRuntime::restore(state)
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        match runtime
            .recover_clean_yield(&work, &authorization, observed_slot)
            .map_err(|_| AgentDriverError::InvalidRuntime)?
        {
            Some(current) if current == yielded => {
                let resume = resume(current);
                let runtime_work = crate::agent_sdk::RuntimeWork::Resume {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    state: legacy_state_as_sdk(&self.image.runtime_state),
                    resume: Box::new(resume),
                };
                self.apply_sdk_work_with_exact(
                    runtime_work,
                    self.management_gas
                        .saturating_add(super::execution::MAX_INVOCATION_GAS_CEILING),
                    Some(&work),
                )
            }
            Some(current) if current.ready_sequence > yielded.ready_sequence => {
                Ok(crate::agent_sdk::RuntimeOutcome::Yielded(current))
            }
            Some(_) => Err(AgentDriverError::InvalidRuntime),
            None => {
                if runtime
                    .recover_clean_execution(&work, &authorization, observed_slot)
                    .map_err(|_| AgentDriverError::InvalidRuntime)?
                    .is_none()
                {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                self.invoke_sdk(work, authorization)
            }
        }
    }

    /// Retire one delivered clean terminal result. The original canonical
    /// work and exact typed authorization are replayed to the guest; no
    /// host-derived legacy receipt or invocation shorthand is accepted.
    pub fn acknowledge_sdk(
        &mut self,
        invocation: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        if !invocation.validate() || !authorization.matches_acknowledgement(&invocation) {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let gas = self
            .management_gas
            .checked_add(invocation.gas)
            .ok_or(AgentDriverError::InvalidRuntime)?;
        let work = crate::agent_sdk::RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: legacy_state_as_sdk(&self.image.runtime_state),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization: Box::new(authorization),
        };
        let encoded = work
            .encode()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let returned: crate::agent_sdk::RuntimeTransition =
            execute_runtime_canonical(&self.runtime_pvm, gas, &encoded)?;
        validate_sdk_acknowledgement_transition(
            self.image.runtime_program,
            &self.image.runtime_state,
            &work,
            &returned,
        )?;
        let next = sdk_state_as_legacy(&returned.state);
        validate_state_size(&next, &self.image.config.runtime_contract)?;
        if next != self.image.runtime_state {
            self.commit_runtime_state(next)?;
        }
        Ok(returned.outcome)
    }

    fn apply_sdk_work(
        &mut self,
        work: crate::agent_sdk::RuntimeWork,
        gas: Gas,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        self.apply_sdk_work_with_exact(work, gas, None)
    }

    fn apply_sdk_work_with_exact(
        &mut self,
        work: crate::agent_sdk::RuntimeWork,
        gas: Gas,
        exact_work: Option<&crate::agent_sdk::InvocationWork>,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, AgentDriverError> {
        require_direct_runtime_work(&work)?;
        let (expected, mode) = match &work {
            crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => (
                (
                    invocation.invocation,
                    invocation.actor,
                    invocation.incarnation,
                    invocation.deployment,
                    invocation.program,
                ),
                invocation.mode,
            ),
            crate::agent_sdk::RuntimeWork::Resume { resume, .. } => (
                (
                    resume.invocation,
                    resume.actor,
                    resume.incarnation,
                    resume.deployment,
                    resume.program,
                ),
                resume.mode,
            ),
            crate::agent_sdk::RuntimeWork::Manage { .. } => {
                return Err(AgentDriverError::InvalidRuntime);
            }
            crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
                return Err(AgentDriverError::InvalidRuntime);
            }
            #[cfg(feature = "experimental-state-blocks")]
            crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => {
                return Err(AgentDriverError::InvalidRuntime);
            }
        };
        let encoded = work
            .encode()
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        let returned: crate::agent_sdk::RuntimeTransition =
            execute_runtime_canonical(&self.runtime_pvm, gas, &encoded)?;
        let next = sdk_state_as_legacy(&returned.state);
        validate_state_size(&next, &self.image.config.runtime_contract)?;
        match &returned.outcome {
            crate::agent_sdk::RuntimeOutcome::Yielded(yielded) => {
                if (
                    yielded.invocation,
                    yielded.actor,
                    yielded.incarnation,
                    yielded.deployment,
                    yielded.program,
                ) != expected
                    || yielded.mode != mode
                {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                let (installation_data, availability) = match &work {
                    crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => {
                        (&invocation.installation_data, &invocation.availability)
                    }
                    crate::agent_sdk::RuntimeWork::Resume { resume, .. } => {
                        // Ordinary resume does not carry a second copy of the
                        // original invocation. The guest checks its supplied
                        // availability against the persisted continuation;
                        // Standard also performs that check in preflight.
                        (&resume.installation_data, &resume.availability)
                    }
                    crate::agent_sdk::RuntimeWork::Manage { .. }
                    | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                    #[cfg(feature = "experimental-state-blocks")]
                    crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => {
                        return Err(AgentDriverError::InvalidRuntime);
                    }
                };
                if &yielded.installation_data != installation_data
                    || yielded.required
                        != availability
                            .iter()
                            .map(|blob| blob.reference.clone())
                            .collect::<Vec<_>>()
                    || matches!(
                        &work,
                        crate::agent_sdk::RuntimeWork::Resume { resume, .. }
                            if yielded.ready_sequence <= resume.ready_sequence
                    )
                {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                if self.image.runtime_program == super::STANDARD_RUNTIME_PROGRAM_ID {
                    validate_standard_sdk_yielded_transition(&next, &work, yielded)?;
                }
            }
            crate::agent_sdk::RuntimeOutcome::Completed(Ok(reply)) => {
                if (
                    reply.invocation,
                    reply.actor,
                    reply.incarnation,
                    reply.deployment,
                ) != (expected.0, expected.1, expected.2, expected.3)
                    || reply.mode != mode
                    || match &work {
                        crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => {
                            reply.gas_remaining > invocation.gas
                        }
                        crate::agent_sdk::RuntimeWork::Resume { .. } => {
                            exact_work.is_some_and(|work| reply.gas_remaining > work.gas)
                        }
                        crate::agent_sdk::RuntimeWork::Manage { .. }
                        | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => true,
                        #[cfg(feature = "experimental-state-blocks")]
                        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => true,
                    }
                {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                if reply.status != crate::agent_sdk::InvocationStatus::Done {
                    validate_sdk_failed_reply_transition(
                        self.image.runtime_program,
                        &self.image.runtime_state,
                        &next,
                        &work,
                        reply,
                    )?;
                }
            }
            crate::agent_sdk::RuntimeOutcome::Completed(Err(error)) => {
                validate_sdk_error_transition(
                    self.image.runtime_program,
                    &self.image.runtime_state,
                    &next,
                    &work,
                    *error,
                )?;
            }
            crate::agent_sdk::RuntimeOutcome::Management(_) => {
                return Err(AgentDriverError::InvalidRuntime);
            }
            crate::agent_sdk::RuntimeOutcome::Acknowledged(_) => {
                return Err(AgentDriverError::InvalidRuntime);
            }
        }
        validate_execution_transition(&self.image.runtime_state, &next, sdk_mode_as_legacy(mode))?;
        if next != self.image.runtime_state {
            self.commit_runtime_state(next)?;
        }
        Ok(returned.outcome)
    }

    /// Execute the raw runtime invocation after the public verification seam
    /// has sealed it. Replicated host adapters in this crate may reuse this
    /// deterministic path only after independently verifying their ordered
    /// authorization sidecar.
    pub(crate) fn invoke_raw(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
        observed_slot: u64,
    ) -> Result<ActorExecutionReply, AgentDriverError> {
        if self.catalog_cleanup_pending {
            let _ = self.reconcile_catalog();
        }
        // Validate at the trusted host boundary before resolving artifacts or
        // adding caller-selected gas to the outer runtime budget. The guest
        // repeats this check when decoding the execution wire.
        invocation.validate().map_err(AgentDriverError::Execution)?;
        let directory = self.validate_invocation_directory(&invocation)?;
        let expected_invocation = invocation.invocation;
        let expected_actor = invocation.actor;
        let expected_incarnation = invocation.incarnation;
        let expected_deployment = invocation.deployment;
        let mode = invocation.mode;
        let outer_gas = self.management_gas.saturating_add(invocation.gas);
        let actor_pvm = self.store.load_program(invocation.program)?;
        let actor_schema = self.store.load_actor_schema(invocation.deployment)?;
        let actor_policies = self.store.load_actor_policies(invocation.deployment)?;
        let installation_data = match directory.entry.installation_data.as_ref() {
            Some(reference) => self.store.load_installation_data(reference)?,
            None => None,
        };
        let installation_missing =
            directory.entry.installation_data.is_some() && installation_data.is_none();
        let recovery_only = actor_pvm.is_none()
            || actor_schema.is_none()
            || actor_policies.is_none()
            || installation_missing;
        let empty_blob = || RuntimeBlob {
            reference: BlobRef {
                hash: Hash::ZERO,
                len: 0,
            },
            bytes: Vec::new(),
        };
        let (actor_pvm, actor_schema, actor_policies, installation_data) = if recovery_only {
            (Vec::new(), empty_blob(), empty_blob(), None)
        } else {
            (
                actor_pvm.expect("checked above"),
                actor_schema.expect("checked above"),
                actor_policies.expect("checked above"),
                installation_data,
            )
        };
        let output: RuntimeExecutionReturn = execute_runtime_wire(
            &self.runtime_pvm,
            outer_gas,
            &RuntimeExecutionCall {
                state: self.image.runtime_state.clone(),
                invocation: invocation.clone(),
                authority,
                observed_slot,
                recovery_only,
                actor_pvm,
                actor_schema,
                actor_policies,
                installation_data,
            }
            .encode(),
        )?;
        let reply = match output.result {
            Ok(reply) => reply,
            Err(error) => {
                if error.is_durable_exact_outcome() {
                    validate_state_size(&output.state, &self.image.config.runtime_contract)?;
                    validate_exact_execution_transition(
                        self.image.runtime_program,
                        &self.image.runtime_state,
                        &output.state,
                        &invocation,
                        observed_slot,
                    )?;
                    if output.state != self.image.runtime_state {
                        self.commit_runtime_state(output.state)?;
                    }
                } else if output.state != self.image.runtime_state {
                    return Err(AgentDriverError::InvalidRuntime);
                }
                return Err(AgentDriverError::Execution(error));
            }
        };
        if reply.invocation != expected_invocation
            || reply.actor != expected_actor
            || reply.incarnation != expected_incarnation
            || reply.deployment != expected_deployment
            || reply.mode != mode
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state, &self.image.config.runtime_contract)?;
        if reply.status != ActorExecutionStatus::Done {
            validate_exact_execution_transition(
                self.image.runtime_program,
                &self.image.runtime_state,
                &output.state,
                &invocation,
                observed_slot,
            )?;
            if output.state != self.image.runtime_state {
                self.commit_runtime_state(output.state)?;
            }
            return Ok(reply);
        }
        validate_execution_transition(&self.image.runtime_state, &output.state, mode)?;
        if output.state == self.image.runtime_state {
            // The runtime recovered an exact durable invocation result. A
            // retry is observationally successful but is not a new agent
            // revision.
            return Ok(reply);
        }

        self.commit_runtime_state(output.state)?;
        Ok(reply)
    }

    /// Retire a durable exact-result record after its response has reached
    /// the caller. Until this explicit acknowledgement, retries remain
    /// recoverable across process restart.
    pub fn acknowledge_invocation(
        &mut self,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<(), AgentDriverError> {
        invocation.validate().map_err(AgentDriverError::Execution)?;
        authority
            .validate_for(
                &self.image.config.authority,
                self.image.config.identity.space,
                self.image.config.identity.agent,
                &invocation,
            )
            .map_err(AgentDriverError::Authority)?;
        let _ = self.validate_invocation_directory(&invocation)?;
        let reply = self.lifecycle(LifecycleRequest::AcknowledgeInvocation {
            scope: invocation.mode.invocation_scope(),
            invocation: invocation.invocation,
            request: invocation.commitment(),
            authority: Box::new(authority.clone()),
        })?;
        if reply
            == (LifecycleReply::InvocationAcknowledged {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
            })
        {
            Ok(())
        } else {
            Err(AgentDriverError::InvalidRuntime)
        }
    }

    pub fn runtime_upgrade_request(
        &self,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LifecycleRequest, AgentDriverError> {
        self.runtime_upgrade_details(from_deployment, package)
            .map(|(request, _)| request)
    }

    fn runtime_upgrade_details(
        &self,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<(LifecycleRequest, AgentConfig), AgentDriverError> {
        if from_deployment == DeploymentId::ZERO {
            return Err(AgentDriverError::Lifecycle(LifecycleError::InvalidRequest));
        }
        // Structural validation precedes deriving the target descriptor. The
        // trust provider then authenticates the package against that complete
        // post-upgrade descriptor, not merely its producer key.
        package.validate().map_err(AgentDriverError::Package)?;
        if package.deployment_signature.producer == self.image.config.identity.transition_producer {
            return Err(AgentDriverError::Lifecycle(
                LifecycleError::UnsupportedRuntime,
            ));
        }
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = package.manifest.kind
        else {
            return Err(AgentDriverError::Package(PackageError::WrongKind));
        };
        let package_reference = BlobRef::of_bytes(&package.encode());
        let mut target = self.image.config.clone();
        target.identity.runtime_deployment = package.deployment_id();
        target.identity.runtime_program = package.manifest.program;
        target.identity.runtime_producer = package.deployment_signature.producer;
        target.runtime_package = package_reference.clone();
        target.runtime_contract = contract;
        target.capabilities = capabilities;
        target.validate().map_err(AgentDriverError::InvalidConfig)?;
        verify_runtime_package_binding(self.trust.as_ref(), &target, package)?;
        let request = LifecycleRequest::UpgradeRuntime {
            from_deployment,
            to_deployment: package.deployment_id(),
            to_program: package.manifest.program,
            producer: package.deployment_signature.producer,
            package: package_reference,
            contract,
            capabilities,
        };
        Ok((request, target))
    }

    pub fn upgrade_runtime(
        &mut self,
        authority: &AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<AgentIdentity, AgentDriverError> {
        let (request, target_config) = self.runtime_upgrade_details(from_deployment, package)?;
        let admission = self.authorize(authority, &request)?;
        let LifecycleRequest::UpgradeRuntime {
            to_deployment,
            to_program,
            producer,
            package: package_reference,
            capabilities,
            ..
        } = request.clone()
        else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        let new_runtime_pvm = package.pvm.clone();
        let output = execute_runtime(
            &self.runtime_pvm,
            self.management_gas,
            RuntimeCall::new(
                self.image.runtime_state.clone(),
                LifecycleRequest::Authorized {
                    admission,
                    request: Box::new(request),
                },
            ),
        )?;
        let reply = match output.result {
            Ok(reply) => reply,
            Err(error) => {
                if output.state != self.image.runtime_state {
                    validate_state_size(&output.state, &self.image.config.runtime_contract)?;
                    self.commit_runtime_state(output.state)?;
                    self.reconcile_catalog_after_commit();
                }
                return Err(AgentDriverError::Lifecycle(error));
            }
        };
        let LifecycleReply::RuntimeUpgraded(identity) = &reply else {
            return Err(AgentDriverError::InvalidRuntime);
        };
        if identity.agent != self.image.config.identity.agent
            || identity.runtime_deployment != to_deployment
            || identity.runtime_program != to_program
            || identity.runtime_producer != producer
            || identity.transition_producer != target_config.identity.transition_producer
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        validate_state_size(&output.state, &target_config.runtime_contract)?;
        let probe = execute_runtime(
            &new_runtime_pvm,
            self.management_gas,
            RuntimeCall::new(
                output.state.clone(),
                LifecycleRequest::Inspect {
                    after: None,
                    limit: 1,
                },
            ),
        )?;
        if !matches!(probe.result, Ok(LifecycleReply::Directory(_))) || probe.state != output.state
        {
            return Err(AgentDriverError::InvalidRuntime);
        }

        if self.image.config == target_config && output.state == self.image.runtime_state {
            // Exact response-loss recovery of an already committed upgrade.
            // The current image and mandatory catalog closure already name
            // these bytes, so no second revision is created.
            return Ok(identity.clone());
        }
        if output.state == self.image.runtime_state {
            return Err(AgentDriverError::InvalidRuntime);
        }

        let package_bytes = package.encode();
        let created_package = self.store.put_package(&package_reference, &package_bytes)?;
        if let Err(error) = self.store.put_program(to_program, &new_runtime_pvm) {
            if created_package {
                let _ = self.store.remove_package(&package_reference);
            }
            return Err(error.into());
        }

        if target_config.identity != *identity
            || target_config.runtime_package != package_reference
            || target_config.capabilities != capabilities
        {
            return Err(AgentDriverError::InvalidRuntime);
        }
        let next = AgentImage {
            clean_descriptor: self.image.clean_descriptor.clone(),
            clean_management: self.image.clean_management.clone(),
            revision: self
                .image
                .revision
                .checked_add(1)
                .ok_or(AgentDriverError::InvalidRuntime)?,
            runtime_program: to_program,
            config: target_config,
            runtime_state: output.state,
        };
        self.store.commit(Some(self.image.revision), &next)?;
        self.runtime_pvm = new_runtime_pvm;
        self.image = next;
        self.reconcile_catalog_after_commit();
        Ok(identity.clone())
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn catalog_references(&self) -> Result<AgentCatalogReferences, AgentDriverError> {
        validate_state_size(
            &self.image.runtime_state,
            &self.image.config.runtime_contract,
        )?;
        if let Some(descriptor) = self.image.clean_descriptor.clone() {
            return self.clean_catalog_references(&descriptor);
        }
        let mut actors = Vec::new();
        let mut after = None;
        loop {
            let output = execute_runtime(
                &self.runtime_pvm,
                self.management_gas,
                RuntimeCall::new(
                    self.image.runtime_state.clone(),
                    LifecycleRequest::Inspect {
                        after,
                        limit: super::standard::MAX_DIRECTORY_PAGE,
                    },
                ),
            )?;
            let Ok(LifecycleReply::Directory(page)) = output.result else {
                return Err(AgentDriverError::InvalidRuntime);
            };
            if output.state != self.image.runtime_state {
                return Err(AgentDriverError::InvalidRuntime);
            }
            for record in &page.entries {
                validate_loaded_actor(
                    &self.store,
                    self.trust.as_ref(),
                    &self.image.config,
                    &record.entry,
                )?;
            }
            actors.extend(page.entries.into_iter().map(|record| record.entry));
            let Some(next) = page.next else {
                break;
            };
            after = Some(next);
        }
        Ok(AgentCatalogReferences {
            runtime_package: self.image.config.runtime_package.clone(),
            runtime_program: self.image.runtime_program,
            actors,
        })
    }

    fn clean_catalog_references(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
    ) -> Result<AgentCatalogReferences, AgentDriverError> {
        let mut actors = Vec::new();
        let mut after = None;
        let page_limit = crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16;
        let max_pages = usize::try_from(descriptor.capabilities.max_actors)
            .map_err(|_| AgentDriverError::InvalidRuntime)?
            .div_ceil(usize::from(page_limit))
            .saturating_add(1);
        for _ in 0..max_pages {
            let request = crate::agent_sdk::ManagementRequest::InspectActors {
                after,
                limit: page_limit,
            };
            let work = crate::agent_sdk::RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: legacy_state_as_sdk(&self.image.runtime_state),
                request: Box::new(request),
                authority: None,
                observed_slot: self.trust.current_logical_slot().unwrap_or(0),
            };
            let encoded = work
                .encode()
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
            let returned: crate::agent_sdk::RuntimeTransition =
                execute_runtime_canonical(&self.runtime_pvm, self.management_gas, &encoded)?;
            if returned.state != legacy_state_as_sdk(&self.image.runtime_state) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            let crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Actors(page),
            )) = returned.outcome
            else {
                return Err(AgentDriverError::InvalidRuntime);
            };
            page.validate()
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
            if after.is_some_and(|cursor| {
                page.entries
                    .first()
                    .is_some_and(|record| record.entry.actor <= cursor)
            }) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            for record in page.entries {
                validate_loaded_clean_actor(&self.store, descriptor, &record.entry)?;
                actors.push(ActorEntry {
                    actor: ActorId(record.entry.actor.0),
                    name: record.entry.name,
                    parent: record.entry.parent.map(|value| ActorId(value.0)),
                    deployment: DeploymentId(record.entry.deployment.0),
                    program: ProgramId(record.entry.program.0),
                    package: sdk_blob_as_legacy(&record.entry.package),
                    agent_schema: sdk_blob_as_legacy(&record.entry.agent_schema),
                    role_policies: sdk_blob_as_legacy(&record.entry.method_policy),
                    constructor_abi: Hash(record.entry.constructor_abi.0),
                    installation_data: record
                        .entry
                        .installation_data
                        .as_ref()
                        .map(sdk_blob_as_legacy),
                    state_layout: Hash(record.entry.state_layout.0),
                    lanes: super::LaneSet::from_bits(record.entry.lanes.bits())
                        .ok_or(AgentDriverError::InvalidRuntime)?,
                    suspended: record.entry.suspended,
                });
            }
            let Some(next) = page.next else {
                return Ok(AgentCatalogReferences {
                    runtime_package: sdk_blob_as_legacy(&descriptor.runtime_package),
                    runtime_program: ProgramId(descriptor.identity.runtime_program.0),
                    actors,
                });
            };
            if after == Some(next) {
                return Err(AgentDriverError::InvalidRuntime);
            }
            after = Some(next);
        }
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_loaded_clean_actor<S: AgentImageStore>(
    store: &S,
    descriptor: &crate::agent_sdk::AgentDescriptor,
    actor: &crate::agent_sdk::ActorEntry,
) -> Result<(), AgentDriverError> {
    let package_reference = sdk_blob_as_legacy(&actor.package);
    let package_bytes = store
        .load_package(&package_reference)?
        .ok_or(AgentDriverError::PackageUnavailable(package_reference.hash))?;
    let package = super::package_admission::admit_actor_package(&package_bytes)
        .map_err(AgentDriverError::PackageAdmission)?;
    let program = ProgramId(actor.program.0);
    let program_bytes = store
        .load_program(program)?
        .ok_or(AgentDriverError::ProgramUnavailable(program))?;
    let deployment = DeploymentId(actor.deployment.0);
    let schema = store
        .load_actor_schema(deployment)?
        .ok_or(AgentDriverError::SchemaUnavailable(deployment))?;
    let policy = store
        .load_actor_policies(deployment)?
        .ok_or(AgentDriverError::PolicyUnavailable(deployment))?;
    let parsed = crate::agent_sdk::schema::decode(&schema.bytes)
        .map_err(|_| AgentDriverError::SchemaMismatch(deployment))?;
    let installation_data = match actor.installation_data.as_ref() {
        Some(reference) => Some(
            store
                .load_installation_data(&sdk_blob_as_legacy(reference))?
                .ok_or(AgentDriverError::PackageUnavailable(Hash(reference.hash.0)))?,
        ),
        None => None,
    };
    if package.deployment() != actor.deployment
        || package.program() != actor.program
        || *package.package_ref() != actor.package
        || package.manifest().state_lane_schema != actor.agent_schema
        || package.manifest().method_policy != actor.method_policy
        || package.program_bytes() != program_bytes
        || package.state_lane_schema_bytes() != schema.bytes
        || package.method_policy_bytes() != policy.bytes
        || parsed
            .constructor_abi()
            .map_err(|_| AgentDriverError::SchemaMismatch(deployment))?
            != actor.constructor_abi
        || parsed
            .state_layout_hash()
            .map_err(|_| AgentDriverError::SchemaMismatch(deployment))?
            != actor.state_layout
        || parsed.lanes() != actor.lanes
        || installation_data
            .as_ref()
            .map(|blob| crate::agent_sdk::BlobRef::of_bytes(&blob.bytes))
            != actor.installation_data
        || parsed.requires_installation_data() != actor.installation_data.is_some()
        || !package
            .requirements()
            .supported_by(descriptor.identity.profile)
        || !descriptor
            .runtime_contract
            .supports(package.manifest().contract)
        || !descriptor.capabilities.satisfies(package.requirements())
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    Ok(())
}

fn validate_loaded_actor<S: AgentImageStore>(
    store: &S,
    trust: &dyn AgentTrustProvider,
    config: &AgentConfig,
    actor: &ActorEntry,
) -> Result<(), AgentDriverError> {
    let package_bytes = store
        .load_package(&actor.package)?
        .ok_or(AgentDriverError::PackageUnavailable(actor.package.hash))?;
    let package = Package::decode(&package_bytes)
        .map_err(|_| AgentDriverError::Package(PackageError::InvalidActorArtifacts))?;
    verify_trusted_package(trust, config, &package)?;
    let PackageKind::Actor {
        contract,
        requirements,
    } = package.manifest.kind
    else {
        return Err(AgentDriverError::Package(PackageError::WrongKind));
    };
    if !config.runtime_contract.supports(contract) {
        return Err(AgentDriverError::Package(PackageError::InvalidActorAbi));
    }
    if !config.capabilities.satisfies(requirements) {
        return Err(AgentDriverError::Package(
            PackageError::InvalidActorArtifacts,
        ));
    }

    let artifacts = load_actor_artifacts(store, actor)?;
    if package.deployment_id() != actor.deployment
        || package.manifest.program != actor.program
        || package.pvm != artifacts.program
        || BlobRef::of_bytes(&package.agent_schema) != actor.agent_schema
        || BlobRef::of_bytes(&package.role_policies) != actor.role_policies
        || artifacts.schema.bytes != package.agent_schema
        || artifacts.policies.bytes != package.role_policies
        || package
            .constructor_abi()
            .map_err(AgentDriverError::Package)?
            != actor.constructor_abi
        || artifacts
            .installation_data
            .as_ref()
            .map(|data| &data.reference)
            != actor.installation_data.as_ref()
        || !package
            .accepts_installation_data_reference(actor.installation_data.as_ref())
            .map_err(AgentDriverError::Package)?
        || requirements.lanes != actor.lanes
    {
        return Err(AgentDriverError::Package(
            PackageError::InvalidActorArtifacts,
        ));
    }
    Ok(())
}

struct LoadedActorArtifacts {
    program: Vec<u8>,
    schema: RuntimeBlob,
    policies: RuntimeBlob,
    installation_data: Option<RuntimeBlob>,
}

fn load_actor_artifacts<S: AgentImageStore>(
    store: &S,
    actor: &ActorEntry,
) -> Result<LoadedActorArtifacts, AgentDriverError> {
    let program = store
        .load_program(actor.program)?
        .ok_or(AgentDriverError::ProgramUnavailable(actor.program))?;
    let schema_blob = store
        .load_actor_schema(actor.deployment)?
        .ok_or(AgentDriverError::SchemaUnavailable(actor.deployment))?;
    let schema = super::schema::decode(&schema_blob.bytes)
        .ok_or(AgentDriverError::SchemaMismatch(actor.deployment))?;
    let policy_blob = store
        .load_actor_policies(actor.deployment)?
        .ok_or(AgentDriverError::PolicyUnavailable(actor.deployment))?;
    if schema_blob.reference != actor.agent_schema
        || !actor.agent_schema.matches(&schema_blob.bytes)
        || schema.state_layout_hash() != actor.state_layout
        || schema.lanes() != actor.lanes
    {
        return Err(AgentDriverError::SchemaMismatch(actor.deployment));
    }
    if policy_blob.reference != actor.role_policies
        || !actor.role_policies.matches(&policy_blob.bytes)
        || crate::service::PackageRolePolicies::decode(&policy_blob.bytes).is_err()
    {
        return Err(AgentDriverError::PolicyMismatch(actor.deployment));
    }
    let installation_data = match actor.installation_data.as_ref() {
        Some(reference) => Some(
            store
                .load_installation_data(reference)?
                .ok_or(AgentDriverError::PackageUnavailable(reference.hash))?,
        ),
        None => None,
    };
    Ok(LoadedActorArtifacts {
        program,
        schema: schema_blob,
        policies: policy_blob,
        installation_data,
    })
}

fn validate_process_local_profile(profile: AgentProfile) -> Result<(), AgentDriverError> {
    if profile == AgentProfile::Local {
        Ok(())
    } else {
        Err(AgentDriverError::UnsupportedProfile(profile))
    }
}

fn runtime_state_size(state: &RuntimeState) -> usize {
    state
        .control
        .len()
        .saturating_add(state.linear.len())
        .saturating_add(state.merge.len())
        .saturating_add(state.local.len())
}

fn encode_valid_image(image: &AgentImage) -> Result<Vec<u8>, AgentStoreError> {
    if image.revision == 0
        || image.runtime_program == ProgramId::ZERO
        || image.config.replicas.len() > MAX_AGENT_IMAGE_REPLICAS
        || !image_config_is_valid(image)
        || image.config.identity.runtime_program != image.runtime_program
        || image.runtime_state.is_empty()
        || image
            .runtime_state
            .encoded_len()
            .is_none_or(|bytes| bytes > MAX_RUNTIME_STATE_BYTES)
        || runtime_state_size(&image.runtime_state)
            > image
                .config
                .runtime_contract
                .resources
                .max_runtime_state_bytes as usize
    {
        return Err(AgentStoreError::Corrupt);
    }
    if image.config.encode().len() > MAX_AGENT_CONFIG_BYTES {
        return Err(AgentStoreError::Corrupt);
    }
    let bytes = image.encode();
    if bytes.len() > MAX_AGENT_IMAGE_BYTES || AgentImage::decode(&bytes).is_err() {
        return Err(AgentStoreError::Corrupt);
    }
    Ok(bytes)
}

fn validate_state_size(
    state: &RuntimeState,
    contract: &super::contract::RuntimePackageContract,
) -> Result<(), AgentDriverError> {
    if state.is_empty()
        || !contract.is_valid()
        || runtime_state_size(state) > MAX_RUNTIME_STATE_BYTES
        || runtime_state_size(state) > contract.resources.max_runtime_state_bytes as usize
    {
        Err(AgentDriverError::RuntimeStateTooLarge)
    } else {
        Ok(())
    }
}

fn validate_execution_transition(
    prior: &RuntimeState,
    next: &RuntimeState,
    mode: super::MethodMode,
) -> Result<(), AgentDriverError> {
    let storage = mode.result_storage();
    if (storage != super::InvocationResultStorage::Control && next.control != prior.control)
        || [
            super::StateLane::Linear,
            super::StateLane::Merge,
            super::StateLane::Local,
        ]
        .into_iter()
        .any(|lane| {
            storage != super::InvocationResultStorage::Lane(lane)
                && next.component(lane) != prior.component(lane)
        })
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    Ok(())
}

fn validate_standard_sdk_invoke_preflight(
    prior: &RuntimeState,
    invocation: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
) -> Result<(), AgentDriverError> {
    if !invocation.validate() {
        return Err(AgentDriverError::InvalidRuntime);
    }
    let state = super::wire::decode_standard_runtime_state(prior)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let runtime = super::standard::StandardAgentRuntime::restore(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    if matches!(authorization, crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt)
        if observed_slot > receipt.selector.expires_at)
    {
        // Non-execution does not require executable artifact availability.
        // Authenticate the exact receipt before allowing it to reach the guest;
        // only the guest's independently verified successor can retain a fence.
        runtime
            .verify_clean_invocation_authorization(invocation, authorization, observed_slot)
            .map_err(|_| AgentDriverError::InvalidRuntime)?;
        return Ok(());
    }
    match runtime.resolve_clean_invocation(invocation) {
        Ok(_) => Ok(()),
        Err(
            crate::agent_sdk::InvocationError::InvalidAvailability
            | crate::agent_sdk::InvocationError::InvalidInput,
        ) => Err(AgentDriverError::InvalidRuntime),
        // Authenticated target errors are exact guest outcomes; they must
        // still cross the runtime so its owning clock advances.
        Err(_) => Ok(()),
    }
}

fn validate_standard_sdk_resume_preflight(
    prior: &RuntimeState,
    resume: &crate::agent_sdk::ResumeWork,
) -> Result<(), AgentDriverError> {
    let state = super::wire::decode_standard_runtime_state(prior)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let runtime = super::standard::StandardAgentRuntime::restore(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let (_, accepted) = runtime
        .resolve_clean_resume(resume)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    runtime
        .resolve_clean_invocation(&accepted)
        .map(|_| ())
        .map_err(|_| AgentDriverError::InvalidRuntime)
}

fn validate_standard_sdk_yielded_transition(
    next: &RuntimeState,
    work: &crate::agent_sdk::RuntimeWork,
    yielded: &crate::agent_sdk::YieldedInvocation,
) -> Result<(), AgentDriverError> {
    let availability = match work {
        crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => &invocation.availability,
        crate::agent_sdk::RuntimeWork::Resume { resume, .. } => &resume.availability,
        crate::agent_sdk::RuntimeWork::Manage { .. }
        | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
            return Err(AgentDriverError::InvalidRuntime);
        }
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => {
            return Err(AgentDriverError::InvalidRuntime);
        }
    };
    let state = super::wire::decode_standard_runtime_state(next)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let runtime = super::standard::StandardAgentRuntime::restore(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let resume = crate::agent_sdk::ResumeWork {
        invocation: yielded.invocation,
        actor: yielded.actor,
        incarnation: yielded.incarnation,
        deployment: yielded.deployment,
        program: yielded.program,
        mode: yielded.mode,
        continuation: yielded.continuation.clone(),
        ready_sequence: yielded.ready_sequence,
        installation_data: yielded.installation_data.clone(),
        availability: availability.clone(),
        input: None,
    };
    let (record, accepted) = runtime
        .resolve_clean_resume(&resume)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    if let crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } = work
        && accepted != **invocation
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    if record
        .yielded()
        .map_err(|_| AgentDriverError::InvalidRuntime)?
        == *yielded
    {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_exact_execution_transition(
    runtime_program: ProgramId,
    prior: &RuntimeState,
    next: &RuntimeState,
    invocation: &ActorInvocation,
    observed_slot: u64,
) -> Result<(), AgentDriverError> {
    if runtime_program != super::STANDARD_RUNTIME_PROGRAM_ID {
        return validate_execution_transition(prior, next, invocation.mode);
    }
    let state = super::wire::decode_standard_runtime_state(prior)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let mut runtime = super::standard::StandardAgentRuntime::restore(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    runtime
        .commit_exact_outcome_clock(invocation, observed_slot)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let expected = super::wire::encode_standard_runtime_state(&runtime.snapshot());
    if next == &expected {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_sdk_failed_reply_transition(
    runtime_program: ProgramId,
    prior: &RuntimeState,
    next: &RuntimeState,
    work: &crate::agent_sdk::RuntimeWork,
    reply: &crate::agent_sdk::InvocationReply,
) -> Result<(), AgentDriverError> {
    use crate::agent_sdk::{InvocationStatus, RuntimeWork};

    if !matches!(
        reply.status,
        InvocationStatus::Forbidden | InvocationStatus::Panicked | InvocationStatus::OutOfGas
    ) {
        return Err(AgentDriverError::InvalidRuntime);
    }
    if runtime_program != super::STANDARD_RUNTIME_PROGRAM_ID {
        return validate_execution_transition(prior, next, sdk_mode_as_legacy(reply.mode));
    }
    fn invalid<T>(_: T) -> AgentDriverError {
        AgentDriverError::InvalidRuntime
    }
    let state = super::wire::decode_standard_runtime_state(prior).map_err(invalid)?;
    let mut runtime = super::standard::StandardAgentRuntime::restore(state).map_err(invalid)?;
    let (accepted, authorization, observed_slot, terminal_continuation) = match work {
        RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } => {
            if let Some(retained) = runtime
                .recover_clean_execution(invocation, authorization, *observed_slot)
                .map_err(invalid)?
            {
                let expected = super::wire::encode_standard_runtime_state(&runtime.snapshot());
                return if super::wire::clean_reply(retained) == *reply && expected == *next {
                    Ok(())
                } else {
                    Err(AgentDriverError::InvalidRuntime)
                };
            }
            runtime
                .validate_clean_unseen_invocation_slot(authorization, *observed_slot)
                .map_err(invalid)?;
            (
                (**invocation).clone(),
                (**authorization).clone(),
                *observed_slot,
                None,
            )
        }
        RuntimeWork::Resume { resume, .. } => {
            let (record, accepted) = runtime.resolve_clean_resume(resume).map_err(invalid)?;
            let authorization = record
                .authorization
                .clone()
                .ok_or(AgentDriverError::InvalidRuntime)?;
            (
                accepted,
                authorization,
                record.observed_slot,
                Some(record.ready_sequence),
            )
        }
        _ => return Err(AgentDriverError::InvalidRuntime),
    };
    let (invocation, ..) = runtime
        .resolve_clean_invocation(&accepted)
        .map_err(invalid)?;
    // Read only the claimed reply from the successor. The authenticated binding,
    // clock, continuation consumption and every other byte are independently
    // derived from the prior state below, never accepted from this snapshot.
    let claimed = super::wire::decode_standard_runtime_state(next).map_err(invalid)?;
    let retained = claimed
        .invocation_results
        .iter()
        .find(|result| {
            result.invocation == invocation.invocation
                && result.scope == invocation.mode.invocation_scope()
        })
        .ok_or(AgentDriverError::InvalidRuntime)?;
    if retained.reply.status == ActorExecutionStatus::Yielded
        || super::wire::clean_reply(retained.reply.clone()) != *reply
    {
        return Err(AgentDriverError::InvalidRuntime);
    }
    runtime
        .retain_clean_terminal_failure(
            &accepted,
            &authorization,
            &invocation,
            &retained.reply,
            observed_slot,
            terminal_continuation,
        )
        .map_err(invalid)?;
    let expected = super::wire::encode_standard_runtime_state(&runtime.snapshot());
    if expected == *next {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_sdk_exact_execution_transition(
    runtime_program: ProgramId,
    prior: &RuntimeState,
    next: &RuntimeState,
    work: &crate::agent_sdk::RuntimeWork,
    error: crate::agent_sdk::InvocationError,
) -> Result<(), AgentDriverError> {
    let mode = match work {
        crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => invocation.mode,
        crate::agent_sdk::RuntimeWork::Resume { resume, .. } => resume.mode,
        crate::agent_sdk::RuntimeWork::Manage { .. }
        | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
            return Err(AgentDriverError::InvalidRuntime);
        }
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => {
            return Err(AgentDriverError::InvalidRuntime);
        }
    };
    if runtime_program != super::STANDARD_RUNTIME_PROGRAM_ID {
        return validate_execution_transition(prior, next, sdk_mode_as_legacy(mode));
    }

    let state = super::wire::decode_standard_runtime_state(prior)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    let mut runtime = super::standard::StandardAgentRuntime::restore(state)
        .map_err(|_| AgentDriverError::InvalidRuntime)?;
    match work {
        crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } => {
            match runtime
                .recover_clean_invocation_error(invocation, authorization, *observed_slot)
                .map_err(|_| AgentDriverError::InvalidRuntime)?
            {
                Some(retained) if retained == error => {}
                Some(_) => return Err(AgentDriverError::InvalidRuntime),
                None => {
                    if error != crate::agent_sdk::InvocationError::ExpiredBeforeExecution {
                        runtime
                            .validate_clean_unseen_invocation_slot(authorization, *observed_slot)
                            .map_err(|_| AgentDriverError::InvalidRuntime)?;
                    }
                    // Expiry has its own strict post-expiry/non-regression
                    // checks in retention; reconstruct the full fence below.
                    runtime
                        .retain_clean_invocation_error(
                            invocation,
                            authorization,
                            error,
                            *observed_slot,
                            None,
                        )
                        .map_err(|_| AgentDriverError::InvalidRuntime)?;
                }
            }
        }
        crate::agent_sdk::RuntimeWork::Resume { resume, .. } => {
            let (record, accepted) = runtime
                .resolve_clean_resume(resume)
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
            let authorization = record
                .authorization
                .as_ref()
                .ok_or(AgentDriverError::InvalidRuntime)?;
            runtime
                .retain_clean_invocation_error(
                    &accepted,
                    authorization,
                    error,
                    record.observed_slot,
                    Some(record.ready_sequence),
                )
                .map_err(|_| AgentDriverError::InvalidRuntime)?;
        }
        crate::agent_sdk::RuntimeWork::Manage { .. }
        | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
            unreachable!("rejected above")
        }
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => unreachable!("rejected above"),
    }
    let expected = super::wire::encode_standard_runtime_state(&runtime.snapshot());
    if next == &expected {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_sdk_error_transition(
    runtime_program: ProgramId,
    prior: &RuntimeState,
    next: &RuntimeState,
    work: &crate::agent_sdk::RuntimeWork,
    error: crate::agent_sdk::InvocationError,
) -> Result<(), AgentDriverError> {
    if runtime_program != super::STANDARD_RUNTIME_PROGRAM_ID {
        let mode = match work {
            crate::agent_sdk::RuntimeWork::Invoke { invocation, .. } => invocation.mode,
            crate::agent_sdk::RuntimeWork::Resume { resume, .. } => resume.mode,
            crate::agent_sdk::RuntimeWork::Manage { .. }
            | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => {
                return Err(AgentDriverError::InvalidRuntime);
            }
            #[cfg(feature = "experimental-state-blocks")]
            crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => {
                return Err(AgentDriverError::InvalidRuntime);
            }
        };
        return validate_execution_transition(prior, next, sdk_mode_as_legacy(mode));
    }
    if error.is_durable_exact_outcome() {
        validate_sdk_exact_execution_transition(runtime_program, prior, next, work, error)
    } else if next == prior {
        Ok(())
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn execute_runtime(
    runtime_pvm: &[u8],
    gas: Gas,
    call: RuntimeCall,
) -> Result<RuntimeReturn, AgentDriverError> {
    execute_runtime_wire(runtime_pvm, gas, &call.encode())
}

fn validate_actor_directory_page(
    after: Option<ActorId>,
    page: &super::ActorDirectoryPage,
    page_limit: usize,
    seen: usize,
    max_actors: usize,
) -> Result<usize, AgentDriverError> {
    let page_size_is_valid = page.entries.len() <= page_limit;
    let ordered = !page
        .entries
        .windows(2)
        .any(|pair| pair[0].entry.actor >= pair[1].entry.actor);
    let starts_after_cursor = after.is_none_or(|cursor| {
        page.entries
            .first()
            .is_none_or(|record| record.entry.actor > cursor)
    });
    let next_is_canonical = match page.next {
        Some(next) => {
            page.entries.len() == page_limit
                && page
                    .entries
                    .last()
                    .is_some_and(|record| record.entry.actor == next)
                && after.is_none_or(|cursor| next > cursor)
        }
        None => true,
    };
    let seen = seen
        .checked_add(page.entries.len())
        .ok_or(AgentDriverError::InvalidRuntime)?;
    let incarnations_are_valid = page.entries.iter().all(|record| {
        record.incarnation != Hash::ZERO
            && record.installation_id != crate::service::InstallationId::ZERO
            && record.registry_reservation != Hash::ZERO
    });
    if page_size_is_valid
        && ordered
        && starts_after_cursor
        && next_is_canonical
        && incarnations_are_valid
        && seen <= max_actors
    {
        Ok(seen)
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn validate_actor_lifecycle_reply(
    expected: (ActorId, DeploymentId, bool),
    reply: LifecycleReply,
) -> Result<ActorEntry, AgentDriverError> {
    let (expected_actor, expected_deployment, expected_suspended) = expected;
    let entry = match (expected_suspended, reply) {
        (true, LifecycleReply::Suspended(entry)) | (false, LifecycleReply::Resumed(entry)) => entry,
        _ => return Err(AgentDriverError::InvalidRuntime),
    };
    if entry.actor == expected_actor
        && entry.deployment == expected_deployment
        && entry.suspended == expected_suspended
    {
        Ok(entry)
    } else {
        Err(AgentDriverError::InvalidRuntime)
    }
}

fn execute_runtime_wire<T: ServiceWire>(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<T, AgentDriverError> {
    execute_service_wire(runtime_pvm, gas, input).map_err(Into::into)
}

fn execute_runtime_canonical<T: AgentCanonicalWire>(
    runtime_pvm: &[u8],
    gas: Gas,
    input: &[u8],
) -> Result<T, AgentDriverError> {
    execute_canonical_wire(runtime_pvm, gas, input).map_err(Into::into)
}

fn legacy_state_as_sdk(state: &RuntimeState) -> crate::agent_sdk::RuntimeState {
    crate::agent_sdk::RuntimeState {
        control: state.control.clone(),
        linear: state.linear.clone(),
        merge: state.merge.clone(),
        local: state.local.clone(),
    }
}

fn sdk_state_as_legacy(state: &crate::agent_sdk::RuntimeState) -> RuntimeState {
    RuntimeState {
        control: state.control.clone(),
        linear: state.linear.clone(),
        merge: state.merge.clone(),
        local: state.local.clone(),
    }
}

const fn sdk_mode_as_legacy(mode: crate::agent_sdk::MethodMode) -> super::MethodMode {
    match mode {
        crate::agent_sdk::MethodMode::Query => super::MethodMode::Query,
        crate::agent_sdk::MethodMode::LinearizableQuery => super::MethodMode::LinearizableQuery,
        crate::agent_sdk::MethodMode::LocalQuery => super::MethodMode::LocalQuery,
        crate::agent_sdk::MethodMode::Linear => super::MethodMode::Linear,
        crate::agent_sdk::MethodMode::Merge => super::MethodMode::Merge,
        crate::agent_sdk::MethodMode::Local => super::MethodMode::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn targeted_actor_lookup_cursor_handles_lexicographic_boundaries() {
        use crate::agent_sdk::ActorId;
        assert_eq!(actor_lookup_cursor(ActorId::ZERO), None);
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(actor_lookup_cursor(ActorId(one)), None);
        for index in 0..32 {
            let mut id = [0; 32];
            id[index] = 1;
            let mut predecessor = [0; 32];
            predecessor[index + 1..].fill(255);
            assert_eq!(
                actor_lookup_cursor(ActorId(id)),
                (predecessor != [0; 32]).then_some(ActorId(predecessor))
            );
        }
        let mut max_predecessor = [255; 32];
        max_predecessor[31] = 254;
        assert_eq!(
            actor_lookup_cursor(ActorId([255; 32])),
            Some(ActorId(max_predecessor))
        );
    }

    #[test]
    fn runtime_pvm_failures_preserve_the_driver_error_contract() {
        assert_eq!(
            AgentDriverError::from(RuntimePvmExecutionError::Backend),
            AgentDriverError::RuntimeBackend
        );
        assert_eq!(
            AgentDriverError::from(RuntimePvmExecutionError::Load),
            AgentDriverError::InvalidRuntime
        );
        assert_eq!(
            AgentDriverError::from(RuntimePvmExecutionError::Exit {
                reason: ExitReason::OutOfGas,
                pc: 41,
            }),
            AgentDriverError::RuntimeExit {
                reason: ExitReason::OutOfGas,
                pc: 41,
            }
        );
        for error in [
            RuntimePvmExecutionError::MissingOutput,
            RuntimePvmExecutionError::Decode,
        ] {
            assert_eq!(
                AgentDriverError::from(error),
                AgentDriverError::RuntimeOutput
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn physical_invocation_material_uses_only_authenticated_image_and_catalog_state() {
        use crate::agent_sdk::authority::{
            AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
            AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use ed25519_dalek::{Signer as _, SigningKey};

        struct ClockTrust(Arc<AtomicU64>);

        impl AgentTrustProvider for ClockTrust {
            fn current_logical_slot(&self) -> Option<u64> {
                Some(self.0.load(Ordering::SeqCst))
            }

            fn authority_for_space(
                &self,
                _space: crate::service::SpaceId,
            ) -> Option<super::super::authority::AgentAuthorityBinding> {
                None
            }

            fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
                false
            }
        }

        let authority_key = SigningKey::from_bytes(&[0x51; 32]);
        let authority_public_key = authority_key.verifying_key().to_bytes();
        let runtime_package = super::super::package_admission::admitted_standard_runtime_for_test(
            "physical-runtime",
            0x52,
        );
        let space = crate::agent_sdk::SpaceId([0x53; 32]);
        let owner = crate::agent_sdk::PrincipalId([0x54; 32]);
        let creation_nonce = crate::agent_sdk::Hash([0x55; 32]);
        let agent = crate::agent_sdk::AgentId::derive(space, owner, creation_nonce.as_bytes());
        let descriptor = crate::agent_sdk::AgentDescriptor {
            identity: crate::agent_sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: crate::agent_sdk::AgentProfile::Local,
                runtime_deployment: runtime_package.deployment(),
                runtime_program: runtime_package.program(),
                runtime_producer: runtime_package.producer(),
                transition_producer: crate::agent_sdk::ProducerId([0x75; 32]),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: crate::agent_sdk::Hash([0x58; 32]),
                issuer: AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId([0x59; 32]),
                    actor: crate::agent_sdk::ActorId([0x5a; 32]),
                    deployment: crate::agent_sdk::DeploymentId([0x5b; 32]),
                    program: crate::agent_sdk::ProgramId([0x5c; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&authority_public_key),
                },
                public_key: authority_public_key,
                initial_epoch: 1,
            },
            private_recovery: None,
            runtime_package: runtime_package.package_ref().clone(),
            runtime_contract: runtime_package.manifest().contract,
            capabilities: runtime_package.capabilities(),
            replicas: vec![crate::agent_sdk::AgentReplica {
                node: crate::agent_sdk::NodeId([0x5d; 32]),
                principal: owner,
                role: crate::agent_sdk::ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();

        let package = super::super::package_admission::admitted_standard_actor_for_test(
            "physical-worker",
            crate::agent_sdk::StateLane::Linear,
            0x5e,
        );
        let schema = crate::agent_sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let actor = crate::agent_sdk::ActorId::top_level(agent, "physical-worker");
        let entry = crate::agent_sdk::ActorEntry {
            actor,
            name: "physical-worker".into(),
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
        let install = crate::agent_sdk::ManagementRequest::Install(Box::new(
            crate::agent_sdk::InstallActor {
                installation_id: crate::agent_sdk::InstallationId([0x5f; 32]),
                registry_reservation: crate::agent_sdk::Hash([0x60; 32]),
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
            },
        ));
        let create = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let signed_receipt = |request: &crate::agent_sdk::ManagementRequest,
                              decision_sequence: u64| {
            let (operation, actor, actor_deployment) = match request {
                crate::agent_sdk::ManagementRequest::Create(_) => {
                    (AuthorityOperationKind::CreateAgent, None, None)
                }
                crate::agent_sdk::ManagementRequest::Install(install) => (
                    AuthorityOperationKind::InstallActor,
                    Some(install.entry.actor),
                    Some(install.entry.deployment),
                ),
                _ => unreachable!("physical fixture uses Create and Install only"),
            };
            let mut receipt = AuthorityReceipt {
                selector: AuthorityReceiptSelector {
                    policy: descriptor.authority.policy,
                    issuer: descriptor.authority.issuer,
                    space,
                    agent,
                    operation,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    actor,
                    actor_deployment,
                    evidence: AuthorityEvidence {
                        package: None,
                        proof: None,
                        commitment: crate::agent_sdk::Hash([0x61; 32]),
                    },
                    lane_roots: AuthorityLaneRoots::default(),
                    epoch: 1,
                    decision_sequence,
                    acknowledged_through: 0,
                    valid_from: 1,
                    expires_at: 100,
                    request: request.commitment(),
                },
                public_key: authority_public_key,
                signature: [0; crate::agent_sdk::authority::AUTHORITY_SIGNATURE_BYTES],
            };
            receipt.signature = authority_key.sign(&receipt.signing_bytes()).to_bytes();
            receipt
        };
        let mut runtime = super::super::standard::StandardAgentRuntime::new();
        runtime
            .apply_clean_management(
                space,
                agent,
                descriptor.identity.runtime_deployment,
                create.clone(),
                Some(signed_receipt(&create, 1)),
                1,
                true,
            )
            .unwrap();
        runtime
            .apply_clean_management(
                space,
                agent,
                descriptor.identity.runtime_deployment,
                install.clone(),
                Some(signed_receipt(&install, 2)),
                2,
                false,
            )
            .unwrap();

        let legacy_reference = |reference: &crate::agent_sdk::BlobRef| BlobRef {
            hash: Hash(reference.hash.0),
            len: reference.len,
        };
        let deployment = DeploymentId(package.deployment().0);
        let mut store = MemoryAgentStore::default();
        store
            .put_package(
                &legacy_reference(runtime_package.package_ref()),
                runtime_package.exact_bytes(),
            )
            .unwrap();
        store
            .put_program(
                ProgramId(runtime_package.program().0),
                runtime_package.program_bytes(),
            )
            .unwrap();
        store
            .put_package(
                &legacy_reference(package.package_ref()),
                package.exact_bytes(),
            )
            .unwrap();
        store
            .put_program(ProgramId(package.program().0), package.program_bytes())
            .unwrap();
        store
            .put_actor_schema(
                deployment,
                &legacy_reference(&package.manifest().state_lane_schema),
                package.state_lane_schema_bytes(),
            )
            .unwrap();
        store
            .put_actor_policies(
                deployment,
                &legacy_reference(&package.manifest().method_policy),
                package.method_policy_bytes(),
            )
            .unwrap();
        let clock = Arc::new(AtomicU64::new(7));
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(ClockTrust(clock.clone()));
        let mut driver = AgentDriver {
            runtime_pvm: runtime_package.program_bytes().to_vec(),
            image: AgentImage {
                clean_descriptor: Some(descriptor.clone()),
                revision: 2,
                clean_management: Some(LocalManagementHistory::from_standard_fixture(
                    &runtime.snapshot(),
                )),
                runtime_program: ProgramId(descriptor.identity.runtime_program.0),
                config: super::super::standard::clean_descriptor_to_legacy_config(&descriptor)
                    .unwrap(),
                runtime_state: super::super::wire::encode_standard_runtime_state(
                    &runtime.snapshot(),
                ),
            },
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust: trust.clone(),
        };

        let prepared = driver.physical_invocation_material(actor).unwrap();
        assert_eq!(prepared.descriptor, descriptor);
        let crate::agent_sdk::ManagementRequest::Install(original_install) = &install else {
            unreachable!()
        };
        assert_eq!(
            prepared.install_request,
            original_install.lineage_commitment()
        );
        assert_eq!(prepared.actor.install_request, prepared.install_request);
        assert_eq!(
            prepared.actor.installation_id,
            original_install.installation_id
        );
        assert_eq!(
            prepared.actor.registry_reservation,
            original_install.registry_reservation
        );
        assert_eq!(prepared.producer, package.producer());
        assert_eq!(prepared.observed_slot, 7);
        assert_eq!(prepared.actor.entry.actor, actor);
        assert_eq!(prepared.actor.entry.deployment, package.deployment());
        assert_eq!(prepared.actor.entry.program, package.program());
        assert_eq!(prepared.program.bytes, package.program_bytes());
        assert_eq!(prepared.schema.bytes, package.state_lane_schema_bytes());
        assert_eq!(prepared.policies.bytes, package.method_policy_bytes());
        assert!(prepared.installation_data.is_none());

        driver.store.commit(None, &driver.image).unwrap();
        let reopened_store = driver.store.clone();
        let reopened_image = reopened_store.load().unwrap().unwrap();
        let reopened_runtime = reopened_store
            .load_program(reopened_image.runtime_program)
            .unwrap()
            .unwrap();
        let reopened = AgentDriver {
            runtime_pvm: reopened_runtime,
            image: reopened_image,
            store: reopened_store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust: trust.clone(),
        };
        assert_eq!(
            reopened.physical_invocation_material(actor).unwrap().actor,
            prepared.actor,
            "a reopened driver repeats runtime-package admission before preparation"
        );

        driver
            .store
            .packages
            .remove(&Hash(descriptor.runtime_package.hash.0));
        assert_eq!(
            driver.physical_invocation_material(actor),
            Err(AgentDriverError::PackageUnavailable(Hash(
                descriptor.runtime_package.hash.0
            )))
        );
        driver
            .store
            .put_package(
                &legacy_reference(runtime_package.package_ref()),
                runtime_package.exact_bytes(),
            )
            .unwrap();

        driver.runtime_pvm = b"substituted-process-runtime".to_vec();
        let executions = DIRECTORY_EXECUTIONS.with(|count| count.get());
        assert_eq!(
            driver.physical_invocation_material(actor),
            Err(AgentDriverError::RuntimeProgramMismatch)
        );
        assert_eq!(
            driver.physical_authority_directory().err(),
            Some(AgentDriverError::RuntimeProgramMismatch)
        );
        assert_eq!(
            DIRECTORY_EXECUTIONS.with(|count| count.get()),
            executions,
            "reject substituted runtime bytes before directory execution"
        );
        driver.runtime_pvm = runtime_package.program_bytes().to_vec();

        driver
            .store
            .programs
            .remove(&ProgramId(descriptor.identity.runtime_program.0));
        assert_eq!(
            driver.physical_invocation_material(actor),
            Err(AgentDriverError::ProgramUnavailable(ProgramId(
                descriptor.identity.runtime_program.0
            )))
        );
        driver
            .store
            .put_program(
                ProgramId(runtime_package.program().0),
                runtime_package.program_bytes(),
            )
            .unwrap();

        clock.store(8, Ordering::SeqCst);
        assert_eq!(
            driver
                .physical_invocation_material(actor)
                .unwrap()
                .observed_slot,
            8,
            "preparation reads the current trusted slot, not a persisted projection"
        );

        let substituted = crate::agent_sdk::method_policy::ActorMethodPolicyArtifact {
            actor_schema: crate::agent_sdk::BlobRef::of_bytes(b"substituted-schema"),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        driver.store.policies.insert(
            deployment,
            RuntimeBlob {
                reference: BlobRef::of_bytes(&substituted),
                bytes: substituted,
            },
        );
        assert_eq!(
            driver.physical_invocation_material(actor),
            Err(AgentDriverError::InvalidRuntime)
        );

        driver.store.policies.remove(&deployment);
        assert_eq!(
            driver.physical_invocation_material(actor),
            Err(AgentDriverError::PolicyUnavailable(deployment))
        );
    }

    struct AnchorTrust {
        space: crate::service::SpaceId,
        authority: super::super::authority::AgentAuthorityBinding,
    }

    impl AgentTrustProvider for AnchorTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(1)
        }

        fn authority_for_space(
            &self,
            space: crate::service::SpaceId,
        ) -> Option<super::super::authority::AgentAuthorityBinding> {
            (space == self.space).then(|| self.authority.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }
    }

    struct CatalogFixture {
        entry: ActorEntry,
        package_bytes: Vec<u8>,
        program_bytes: Vec<u8>,
        schema_bytes: Vec<u8>,
        policy_bytes: Vec<u8>,
    }

    impl CatalogFixture {
        fn new(seed: u8, actor: ActorId) -> Self {
            let (schema_bytes, schema_len) =
                super::super::schema::encode::<512>(&super::super::schema::SchemaMeta {
                    uses_storage: false,
                    fields: &[super::super::schema::FieldMeta {
                        name: "value",
                        codec: "u64",
                        persistence: super::super::FieldPersistence::State(
                            super::super::StateLane::Linear,
                        ),
                    }],
                    methods: &[super::super::schema::MethodMeta {
                        name: "increment",
                        mode: super::super::MethodMode::Linear,
                        explicit: true,
                    }],
                });
            let schema_bytes = schema_bytes[..schema_len].to_vec();
            let schema = super::super::schema::decode(&schema_bytes).unwrap();
            let policy_bytes = crate::service::PackageRolePolicies {
                methods: Vec::new(),
                task_dependencies: Vec::new(),
            }
            .encode();
            let package_bytes = vec![b'V', b'O', b'S', seed];
            let program_bytes = vec![seed; 16];
            let deployment = DeploymentId([seed; 32]);
            Self {
                entry: ActorEntry {
                    actor,
                    name: format!("actor-{seed}"),
                    parent: None,
                    deployment,
                    program: ProgramId::of_pvm(&program_bytes),
                    package: BlobRef::of_bytes(&package_bytes),
                    agent_schema: BlobRef::of_bytes(&schema_bytes),
                    role_policies: BlobRef::of_bytes(&policy_bytes),
                    constructor_abi: Hash([seed.wrapping_add(1); 32]),
                    installation_data: None,
                    state_layout: schema.state_layout_hash(),
                    lanes: schema.lanes(),
                    suspended: false,
                },
                package_bytes,
                program_bytes,
                schema_bytes,
                policy_bytes,
            }
        }

        fn put<S: AgentImageStore>(&self, store: &mut S) {
            store
                .put_package(&self.entry.package, &self.package_bytes)
                .unwrap();
            store
                .put_program(self.entry.program, &self.program_bytes)
                .unwrap();
            store
                .put_actor_schema(
                    self.entry.deployment,
                    &self.entry.agent_schema,
                    &self.schema_bytes,
                )
                .unwrap();
            store
                .put_actor_policies(
                    self.entry.deployment,
                    &self.entry.role_policies,
                    &self.policy_bytes,
                )
                .unwrap();
        }
    }

    #[test]
    fn actor_deployment_pagination_rejects_noncanonical_runtime_pages() {
        let first = CatalogFixture::new(0x31, ActorId([0x41; 32])).entry;
        let second = CatalogFixture::new(0x32, ActorId([0x42; 32])).entry;
        let record = |entry: ActorEntry, seed| super::super::ActorDirectoryRecord {
            entry,
            incarnation: Hash([seed; 32]),
            installation_id: crate::service::InstallationId([seed.wrapping_add(1); 32]),
            registry_reservation: Hash([seed.wrapping_add(2); 32]),
        };

        let backwards = super::super::ActorDirectoryPage {
            entries: vec![record(first.clone(), 1)],
            next: None,
        };
        assert_eq!(
            validate_actor_directory_page(Some(second.actor), &backwards, 2, 0, 2),
            Err(AgentDriverError::InvalidRuntime)
        );

        let unordered = super::super::ActorDirectoryPage {
            entries: vec![record(second.clone(), 2), record(first.clone(), 1)],
            next: None,
        };
        assert_eq!(
            validate_actor_directory_page(None, &unordered, 2, 0, 2),
            Err(AgentDriverError::InvalidRuntime)
        );

        let underfull_continuation = super::super::ActorDirectoryPage {
            entries: vec![record(first.clone(), 1)],
            next: Some(first.actor),
        };
        assert_eq!(
            validate_actor_directory_page(None, &underfull_continuation, 2, 0, 2),
            Err(AgentDriverError::InvalidRuntime)
        );

        let oversized = super::super::ActorDirectoryPage {
            entries: vec![record(first.clone(), 1), record(second.clone(), 2)],
            next: None,
        };
        assert_eq!(
            validate_actor_directory_page(None, &oversized, 1, 0, 2),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut zero_installation = record(first.clone(), 1);
        zero_installation.installation_id = crate::service::InstallationId::ZERO;
        assert_eq!(
            validate_actor_directory_page(
                None,
                &super::super::ActorDirectoryPage {
                    entries: vec![zero_installation],
                    next: None,
                },
                2,
                0,
                2,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut zero_reservation = record(first.clone(), 1);
        zero_reservation.registry_reservation = Hash::ZERO;
        assert_eq!(
            validate_actor_directory_page(
                None,
                &super::super::ActorDirectoryPage {
                    entries: vec![zero_reservation],
                    next: None,
                },
                2,
                0,
                2,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let over_capacity = super::super::ActorDirectoryPage {
            entries: vec![record(first, 1), record(second, 2)],
            next: None,
        };
        assert_eq!(
            validate_actor_directory_page(None, &over_capacity, 2, 1, 2),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[test]
    fn actor_lifecycle_reply_must_match_the_sealed_request() {
        let entry = CatalogFixture::new(0x51, ActorId([0x61; 32])).entry;
        let suspend = (entry.actor, entry.deployment, true);
        let resume = (entry.actor, entry.deployment, false);
        let mut suspended = entry.clone();
        suspended.suspended = true;

        assert_eq!(
            validate_actor_lifecycle_reply(suspend, LifecycleReply::Suspended(suspended.clone())),
            Ok(suspended.clone())
        );
        assert_eq!(
            validate_actor_lifecycle_reply(suspend, LifecycleReply::Resumed(suspended.clone())),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_actor_lifecycle_reply(resume, LifecycleReply::Suspended(suspended.clone())),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut wrong_actor = suspended.clone();
        wrong_actor.actor = ActorId([0x62; 32]);
        assert_eq!(
            validate_actor_lifecycle_reply(suspend, LifecycleReply::Suspended(wrong_actor)),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut wrong_deployment = suspended.clone();
        wrong_deployment.deployment = DeploymentId([0x63; 32]);
        assert_eq!(
            validate_actor_lifecycle_reply(suspend, LifecycleReply::Suspended(wrong_deployment)),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_actor_lifecycle_reply(suspend, LifecycleReply::Suspended(entry.clone())),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_actor_lifecycle_reply(resume, LifecycleReply::Resumed(entry.clone())),
            Ok(entry)
        );
    }

    fn catalog_references(actors: Vec<ActorEntry>) -> AgentCatalogReferences {
        AgentCatalogReferences {
            runtime_package: BlobRef::of_bytes(b"host-supplied-runtime-package"),
            runtime_program: ProgramId::of_pvm(b"host-supplied-runtime-program"),
            actors,
        }
    }

    fn put_runtime_catalog<S: AgentImageStore>(store: &mut S) {
        let package = b"host-supplied-runtime-package";
        let program = b"host-supplied-runtime-program";
        store
            .put_package(&BlobRef::of_bytes(package), package)
            .unwrap();
        store
            .put_program(ProgramId::of_pvm(program), program)
            .unwrap();
    }

    #[test]
    fn whole_image_driver_fails_closed_for_replicated_profiles() {
        assert_eq!(
            validate_process_local_profile(super::super::AgentProfile::Local),
            Ok(())
        );
        for profile in [
            super::super::AgentProfile::Shared,
            super::super::AgentProfile::Private,
        ] {
            assert_eq!(
                validate_process_local_profile(profile),
                Err(AgentDriverError::UnsupportedProfile(profile))
            );
        }

        let mut shared = invalid_config();
        shared.identity.profile = super::super::AgentProfile::Shared;
        shared.replicas = vec![super::super::AgentReplica {
            node: crate::service::NodeId([11; 32]),
            principal: crate::service::PrincipalId([12; 32]),
            role: super::super::ReplicaRole::Voter,
        }];
        assert_eq!(shared.validate(), Ok(()));
        assert_eq!(
            validate_process_local_profile(shared.identity.profile),
            Err(AgentDriverError::UnsupportedProfile(
                super::super::AgentProfile::Shared
            ))
        );
    }

    #[test]
    fn clean_host_preflight_distinguishes_retained_historical_from_unseen_stale_receipts() {
        use crate::agent_sdk::authority::{
            AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
            AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
        };
        use ed25519_dalek::{Signer as _, SigningKey};

        let signing = SigningKey::from_bytes(&[0x61; 32]);
        let public_key = signing.verifying_key().to_bytes();
        let space = crate::agent_sdk::SpaceId([0x62; 32]);
        let owner = crate::agent_sdk::PrincipalId([0x63; 32]);
        let nonce = crate::agent_sdk::Hash([0x64; 32]);
        let agent = crate::agent_sdk::AgentId::derive(space, owner, nonce.as_bytes());
        let historical_runtime = crate::agent_sdk::DeploymentId([0x65; 32]);
        let current_runtime = crate::agent_sdk::DeploymentId([0x66; 32]);
        let authority = AgentAuthorityBinding {
            policy: crate::agent_sdk::Hash([0x67; 32]),
            issuer: AuthorityIssuer {
                principal: owner,
                actor: crate::agent_sdk::ActorId([0x68; 32]),
                deployment: crate::agent_sdk::DeploymentId([0x69; 32]),
                program: crate::agent_sdk::ProgramId([0x6a; 32]),
                producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 1,
        };
        let descriptor = crate::agent_sdk::AgentDescriptor {
            identity: crate::agent_sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile: crate::agent_sdk::AgentProfile::Local,
                runtime_deployment: current_runtime,
                runtime_program: crate::agent_sdk::ProgramId([0x6b; 32]),
                runtime_producer: crate::agent_sdk::ProducerId([0x6c; 32]),
                transition_producer: crate::agent_sdk::ProducerId([0x6d; 32]),
            },
            creation_nonce: nonce,
            authority,
            private_recovery: None,
            runtime_package: crate::agent_sdk::BlobRef {
                hash: crate::agent_sdk::Hash([0x6d; 32]),
                len: 1,
            },
            runtime_contract: crate::agent_sdk::contract::RuntimePackageContract::canonical(),
            capabilities: crate::agent_sdk::RuntimeCapabilities::standard(),
            replicas: vec![crate::agent_sdk::AgentReplica {
                node: crate::agent_sdk::NodeId([0x6e; 32]),
                principal: owner,
                role: crate::agent_sdk::ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();

        let request = crate::agent_sdk::ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0x6f; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0x70; 32]),
        };
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: descriptor.authority.policy,
                issuer: descriptor.authority.issuer,
                space,
                agent,
                operation: AuthorityOperationKind::SuspendActor,
                runtime_deployment: historical_runtime,
                actor: match &request {
                    crate::agent_sdk::ManagementRequest::Suspend { actor, .. } => Some(*actor),
                    _ => unreachable!(),
                },
                actor_deployment: match &request {
                    crate::agent_sdk::ManagementRequest::Suspend {
                        expected_deployment,
                        ..
                    } => Some(*expected_deployment),
                    _ => unreachable!(),
                },
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x71; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 2,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: 200,
                request: request.commitment(),
            },
            public_key,
            signature: [0; 64],
        };
        receipt.signature = signing.sign(&receipt.signing_bytes()).to_bytes();

        // Journal expiry admission is narrower than ordinary authentication:
        // only Local/Shared Install can enter the non-execution path, and the
        // unchanged receipt still needs a valid signature and exact binding.
        let install = super::super::wire::tests::clean_install_request(
            &descriptor,
            "expiry-admission",
            None,
            0x76,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
        );
        let install_request = crate::agent_sdk::ManagementRequest::Install(Box::new(install));
        let mut install_receipt = receipt.clone();
        install_receipt.selector.operation = AuthorityOperationKind::InstallActor;
        install_receipt.selector.runtime_deployment = current_runtime;
        let (actor, deployment) = clean_management_actor(&install_request).unwrap();
        install_receipt.selector.actor = Some(actor);
        install_receipt.selector.actor_deployment = Some(deployment);
        install_receipt.selector.request = install_request.commitment();
        install_receipt.signature = signing.sign(&install_receipt.signing_bytes()).to_bytes();
        for profile in [
            crate::agent_sdk::AgentProfile::Local,
            crate::agent_sdk::AgentProfile::Shared,
        ] {
            let mut target = descriptor.clone();
            target.identity.profile = profile;
            for (slot, expected) in [(1, false), (200, false), (201, true)] {
                assert_eq!(
                    verify_clean_management_journal_receipt(
                        &target,
                        &install_request,
                        &install_receipt,
                        slot,
                        false
                    ),
                    Ok(expected)
                );
            }
            assert!(
                verify_clean_management_journal_receipt(
                    &target,
                    &install_request,
                    &install_receipt,
                    0,
                    false
                )
                .is_err()
            );
            assert!(
                verify_clean_management_receipt(
                    &target,
                    &install_request,
                    &install_receipt,
                    201,
                    false
                )
                .is_err()
            );
            let mut forged = install_receipt.clone();
            forged.signature[0] ^= 1;
            assert!(
                verify_clean_management_journal_receipt(
                    &target,
                    &install_request,
                    &forged,
                    201,
                    false
                )
                .is_err()
            );
            assert!(
                verify_clean_management_journal_receipt(&target, &request, &receipt, 201, true)
                    .is_err()
            );
        }
        let mut private = descriptor.clone();
        private.identity.profile = crate::agent_sdk::AgentProfile::Private;
        assert!(
            verify_clean_management_journal_receipt(
                &private,
                &install_request,
                &install_receipt,
                201,
                false
            )
            .is_err()
        );

        let runtime_state = super::super::wire::encode_standard_runtime_state(
            &super::super::standard::StandardRuntimeState {
                config: Some(
                    super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap(),
                ),
                clean_creation_descriptor: Some(descriptor.clone()),
                clean_descriptor: Some(descriptor.clone()),
                clean_actor_packages: Some(Vec::new()),
                clean_actor_installations: Some(Vec::new()),
                clean_authority_epoch_high_water: Some(1),
                clean_decision_sequence_high_water: Some(2),
                clean_acknowledged_through: 0,
                clean_management_dispositions: vec![
                    super::super::standard::StandardCleanManagementDisposition {
                        authority: crate::agent_sdk::Hash([0x72; 32]),
                        request: crate::agent_sdk::Hash([0x73; 32]),
                        epoch: 1,
                        sequence: 1,
                        observed_slot: 1,
                        result: Ok(crate::agent_sdk::ManagementReply::Created(
                            descriptor.identity.clone(),
                        )),
                    },
                    super::super::standard::StandardCleanManagementDisposition {
                        authority: receipt.commitment(),
                        request: request.replay_commitment(),
                        epoch: receipt.selector.epoch,
                        sequence: receipt.selector.decision_sequence,
                        observed_slot: 2,
                        result: Err(crate::agent_sdk::ManagementError::NotFound),
                    },
                ],
                active_resource_policy: Some(descriptor.initial_resource_policy()),
                authority_slot_high_water: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(
            clean_management_receipt_history(&runtime_state, &request, &receipt),
            Ok(CleanManagementReceiptHistory::Retained { observed_slot: 2 })
        );
        assert_eq!(request.replay_commitment(), request.commitment());
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &receipt, 100, true),
            Ok(()),
            "a retained receipt is authenticated without rebinding it to the current runtime"
        );
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &receipt, 100, false),
            Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest
            ))
        );

        let mut not_yet_live = receipt.clone();
        not_yet_live.selector.valid_from = 101;
        not_yet_live.signature = signing.sign(&not_yet_live.signing_bytes()).to_bytes();
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &not_yet_live, 100, true),
            Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest
            ))
        );
        let mut expired = receipt.clone();
        expired.selector.expires_at = 99;
        expired.signature = signing.sign(&expired.signing_bytes()).to_bytes();
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &expired, 100, true),
            Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest
            ))
        );

        let mut consumed = receipt.clone();
        consumed.selector.decision_sequence = 1;
        consumed.signature = signing.sign(&consumed.signing_bytes()).to_bytes();
        assert_eq!(
            clean_management_receipt_history(&runtime_state, &request, &consumed),
            Ok(CleanManagementReceiptHistory::Consumed),
            "a pruned or otherwise consumed sequence reaches the guest without staging artifacts"
        );
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &consumed, 100, true),
            Ok(())
        );
        let mut forged_consumed = consumed;
        forged_consumed.signature[0] ^= 1;
        assert_eq!(
            clean_management_receipt_history(&runtime_state, &request, &forged_consumed),
            Ok(CleanManagementReceiptHistory::Consumed)
        );
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &forged_consumed, 100, true,),
            Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest
            )),
            "history classification never bypasses immutable authentication"
        );

        let mut unseen = receipt;
        unseen.selector.decision_sequence = 3;
        unseen.selector.valid_from = 100;
        unseen.selector.expires_at = 110;
        unseen.signature = signing.sign(&unseen.signing_bytes()).to_bytes();
        assert_eq!(
            clean_management_receipt_history(&runtime_state, &request, &unseen),
            Ok(CleanManagementReceiptHistory::Unseen)
        );
        assert_eq!(
            verify_clean_management_receipt(&descriptor, &request, &unseen, 100, false),
            Err(AgentDriverError::SdkManagement(
                crate::agent_sdk::ManagementError::InvalidRequest
            )),
            "an unseen receipt cannot select a retired runtime"
        );

        let mut impossible_ack = unseen;
        impossible_ack.selector.decision_sequence = 4;
        impossible_ack.selector.acknowledged_through = 3;
        impossible_ack.signature = signing.sign(&impossible_ack.signing_bytes()).to_bytes();
        assert_eq!(
            clean_management_receipt_history(&runtime_state, &request, &impossible_ack),
            Ok(CleanManagementReceiptHistory::RejectedUnseen)
        );
    }

    #[test]
    fn creation_authority_is_selected_by_the_space_anchor_not_the_caller() {
        let mut config = invalid_config();
        let anchored = config.authority.clone();
        let trust = AnchorTrust {
            space: config.identity.space,
            authority: anchored.clone(),
        };
        assert_eq!(verify_authority_anchor(&trust, &config), Ok(()));

        let attacker_key = super::super::authority::ed25519_public_key_wire([0x52; 32]);
        config.authority.public_key = attacker_key.clone();
        config.authority.producer = crate::service::ProducerId::of_public_key(&attacker_key);
        assert_eq!(
            verify_authority_anchor(&trust, &config),
            Err(AgentDriverError::Authority(AuthorityError::WrongAuthority))
        );
    }

    // The completed clean-runtime fixture commits a PVM execution result.
    #[cfg(feature = "pvm")]
    #[test]
    fn public_descriptor_transitions_preserve_current_metadata_on_historical_retry() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };
        let (state, _, _) = super::super::wire::tests::completed_clean_policy_fixture(
            crate::agent_sdk::Hash([0xe7; 32]),
        );
        let current = clean_descriptor_from_state(&sdk_state_as_legacy(&state)).unwrap();
        let mut expected = current.clone();
        expected.identity.runtime_deployment = crate::agent_sdk::DeploymentId([0xe1; 32]);
        expected.identity.runtime_program = crate::agent_sdk::ProgramId([0xe2; 32]);
        expected.identity.runtime_producer = crate::agent_sdk::ProducerId([0xe3; 32]);
        expected.runtime_package = crate::agent_sdk::BlobRef::of_bytes(b"new-runtime-package");
        expected.capabilities.max_actors -= 1;
        expected.validate().unwrap();
        let request =
            ManagementRequest::UpgradeRuntime(Box::new(crate::agent_sdk::RuntimeUpgrade {
                from_deployment: current.identity.runtime_deployment,
                to_deployment: expected.identity.runtime_deployment,
                to_program: expected.identity.runtime_program,
                producer: expected.identity.runtime_producer,
                package: expected.runtime_package.clone(),
                contract: expected.runtime_contract,
                capabilities: expected.capabilities,
            }));
        let outcome = RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(
            expected.identity.clone(),
        )));
        assert_eq!(
            sdk_descriptor_after_management(&current, &request, &outcome, false),
            Ok(expected.clone())
        );
        assert_eq!(
            sdk_descriptor_after_management(
                &current,
                &request,
                &RuntimeOutcome::Management(Err(ManagementError::ResourceLimit)),
                false
            ),
            Ok(current.clone())
        );

        // The same retained successful reply can arrive after a later upgrade.
        // Recovering it must neither roll back metadata nor check its old
        // predecessor as though this were an unseen operation.
        let mut later = expected.clone();
        later.identity.runtime_deployment = crate::agent_sdk::DeploymentId([0xe4; 32]);
        later.identity.runtime_program = crate::agent_sdk::ProgramId([0xe5; 32]);
        later.runtime_package = crate::agent_sdk::BlobRef::of_bytes(b"later-runtime-package");
        assert_eq!(
            sdk_descriptor_after_management(&later, &request, &outcome, true),
            Ok(later.clone())
        );
        assert_eq!(
            sdk_descriptor_after_management(&later, &request, &outcome, false),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut wrong_identity = expected.identity.clone();
        wrong_identity.owner = crate::agent_sdk::PrincipalId([0xe6; 32]);
        assert_eq!(
            sdk_descriptor_after_management(
                &current,
                &request,
                &RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(wrong_identity))),
                false
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut replicas = current.replicas.clone();
        replicas.last_mut().unwrap().node = crate::agent_sdk::NodeId([0xe8; 32]);
        let replica_request = ManagementRequest::ChangeReplicas {
            expected_generation: current.replica_generation(),
            replicas: replicas.clone(),
        };
        let mut changed = current.clone();
        changed.replicas = replicas;
        let replica_reply = RuntimeOutcome::Management(Ok(ManagementReply::ReplicasChanged {
            generation: changed.replica_generation(),
        }));
        assert_eq!(
            sdk_descriptor_after_management(&current, &replica_request, &replica_reply, false),
            Ok(changed.clone())
        );
        assert_eq!(
            sdk_descriptor_after_management(&changed, &replica_request, &replica_reply, false),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut later_roster = changed.clone();
        later_roster.replicas.last_mut().unwrap().node = crate::agent_sdk::NodeId([0xe9; 32]);
        assert_eq!(
            sdk_descriptor_after_management(&later_roster, &replica_request, &replica_reply, true),
            Ok(later_roster)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_image_descriptor_roundtrips_without_decoding_opaque_state() {
        let (state, _, _) = super::super::wire::tests::completed_clean_policy_fixture(
            crate::agent_sdk::Hash([0xe7; 32]),
        );
        let descriptor = clean_descriptor_from_state(&sdk_state_as_legacy(&state)).unwrap();
        let config =
            super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap();
        let image = AgentImage {
            clean_descriptor: Some(descriptor.clone()),
            revision: 1,
            runtime_program: config.identity.runtime_program,
            clean_management: Some(LocalManagementHistory::from_standard_fixture(
                &super::super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(&state))
                    .unwrap(),
            )),
            config,
            runtime_state: RuntimeState {
                control: b"opaque-image-control".to_vec(),
                linear: vec![1],
                merge: vec![2],
                local: vec![3],
            },
        };
        assert!(clean_descriptor_from_state(&image.runtime_state).is_err());
        assert_eq!(AgentImage::decode(&image.encode()).unwrap(), image);
        assert_eq!(clean_image_descriptor(&image).unwrap(), descriptor);
        let mut store = MemoryAgentStore::default();
        store.commit(None, &image).unwrap();
        assert_eq!(store.load().unwrap(), Some(image.clone()));

        let mut absent = image.clone();
        absent.clean_descriptor = None;
        assert!(AgentImage::decode(&absent.encode()).is_err());
        let mut missing_history = image.clone();
        missing_history.clean_management = None;
        assert!(AgentImage::decode(&missing_history.encode()).is_err());
        missing_history.clean_management = Some(LocalManagementHistory::default());
        assert!(AgentImage::decode(&missing_history.encode()).is_err());
        let mut substituted = image.clone();
        substituted.config.identity.owner = crate::service::PrincipalId([0xef; 32]);
        assert!(AgentImage::decode(&substituted.encode()).is_err());
        let mut wrong_runtime = image.clone();
        wrong_runtime.runtime_program = ProgramId([0xee; 32]);
        assert!(AgentImage::decode(&wrong_runtime.encode()).is_err());
        assert_eq!(
            clean_image_descriptor(&wrong_runtime),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut predecessor = image.encode();
        predecessor[..4].copy_from_slice(b"AGI2");
        assert_eq!(
            AgentImage::decode(&predecessor),
            Err(DecodeError::InvalidTag)
        );
        predecessor[..4].copy_from_slice(b"AGIM");
        assert_eq!(
            AgentImage::decode(&predecessor),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn image_wire_rejects_empty_runtime_state() {
        let bytes = AgentImage {
            clean_descriptor: None,
            clean_management: None,
            revision: 1,
            runtime_program: ProgramId([1; 32]),
            config: invalid_config(),
            runtime_state: RuntimeState::default(),
        }
        .encode();
        assert!(AgentImage::decode(&bytes).is_err());
    }

    #[test]
    fn signed_runtime_resource_limit_is_stricter_than_the_global_decoder_cap() {
        let mut contract = super::super::contract::RuntimePackageContract::canonical();
        contract.resources.max_runtime_state_bytes = 3;
        assert!(contract.is_valid());
        assert_eq!(
            validate_state_size(
                &RuntimeState {
                    control: vec![1, 2],
                    linear: vec![3, 4],
                    merge: Vec::new(),
                    local: Vec::new(),
                },
                &contract,
            ),
            Err(AgentDriverError::RuntimeStateTooLarge)
        );
        assert_eq!(
            validate_state_size(
                &RuntimeState {
                    control: vec![1],
                    linear: vec![2],
                    merge: vec![3],
                    local: Vec::new(),
                },
                &contract,
            ),
            Ok(())
        );
    }

    fn standard_exact_transition_fixture(
        observed_slot: u64,
    ) -> (RuntimeState, RuntimeState, ActorInvocation) {
        let mut config = invalid_config();
        config.replicas = vec![super::super::AgentReplica {
            node: crate::service::NodeId([0x21; 32]),
            principal: config.identity.owner,
            role: super::super::ReplicaRole::Voter,
        }];
        assert_eq!(config.validate(), Ok(()));
        let base = super::super::standard::StandardRuntimeState {
            config: Some(config.clone()),
            authority_slot_high_water: Some(1),
            authority_sequence_high_water: Some(1),
            authority_dispositions: vec![super::super::standard::StandardAuthorityDisposition {
                credential: crate::service::CredentialId([0x22; 32]),
                sequence: 1,
                claim: Hash([0x23; 32]),
                operation: Hash([0x24; 32]),
                result: Ok(LifecycleReply::Created(config.identity.clone())),
            }],
            ..Default::default()
        };
        let prior = super::super::wire::encode_standard_runtime_state(&base);
        let mut successor = base;
        successor.lane_revisions.linear_authority_slot = Some(observed_slot);
        let next = super::super::wire::encode_standard_runtime_state(&successor);
        let invocation = ActorInvocation {
            invocation: crate::service::InvocationId([0x25; 32]),
            actor: ActorId([0x26; 32]),
            incarnation: Hash([0x27; 32]),
            deployment: DeploymentId([0x28; 32]),
            program: ProgramId([0x29; 32]),
            mode: super::super::MethodMode::Linear,
            auth: super::super::execution::ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        };
        (prior, next, invocation)
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_typed_error_resume_consumes_continuation_and_retires_after_restore() {
        use crate::agent_sdk::{
            InvocationError, RuntimeExecutionContext, RuntimeOutcome, RuntimeWork,
        };
        let work = super::super::wire::tests::clean_failing_resume_fixture_with_status(Some(0xff));
        let RuntimeWork::Resume { state, resume, .. } = &work else {
            unreachable!()
        };
        let prior = sdk_state_as_legacy(state);
        let runtime = super::super::standard::StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&prior).unwrap(),
        )
        .unwrap();
        let (record, accepted) = runtime.resolve_clean_resume(resume).unwrap();
        let transition = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidActorOutput))
        );
        let next = sdk_state_as_legacy(&transition.state);
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &next,
                &work,
                InvocationError::InvalidActorOutput
            ),
            Ok(())
        );
        let restored = super::super::standard::StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&next).unwrap(),
        )
        .unwrap();
        assert!(restored.snapshot().machine_continuations.is_empty());
        assert_eq!(
            restored.snapshot().lane_state,
            runtime.snapshot().lane_state
        );
        let ack = super::super::wire::apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: transition.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&accepted)),
            authorization: Box::new(record.authorization.unwrap()),
        })
        .unwrap();
        assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_expiry_preflight_authenticates_non_executable_work_without_mutation() {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, RuntimeOutcome, RuntimeWork,
        };
        let RuntimeWork::Invoke {
            state,
            mut invocation,
            ..
        } = super::super::wire::tests::clean_failing_actor_fixture(None)
        else {
            unreachable!()
        };
        let prior = sdk_state_as_legacy(&state);
        let runtime = super::super::standard::StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&prior).unwrap(),
        )
        .unwrap();
        invocation.availability.clear();
        assert!(invocation.validate());
        let authorization = InvocationAuthorization::AuthorityReceipt(
            super::super::wire::tests::clean_authority_receipt(
                runtime.config().unwrap(),
                &invocation,
            ),
        );
        assert_eq!(
            validate_standard_sdk_invoke_preflight(&prior, &invocation, &authorization, 1),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_standard_sdk_invoke_preflight(&prior, &invocation, &authorization, 3),
            Ok(())
        );
        let mut forged = authorization.clone();
        let InvocationAuthorization::AuthorityReceipt(receipt) = &mut forged else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;
        assert_eq!(
            validate_standard_sdk_invoke_preflight(&prior, &invocation, &forged, 3),
            Err(AgentDriverError::InvalidRuntime)
        );
        let work = RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state,
            invocation,
            authorization: Box::new(authorization),
            observed_slot: 3,
        };
        let transition = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::ExpiredBeforeExecution))
        );
        let next = sdk_state_as_legacy(&transition.state);
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &next,
                &work,
                InvocationError::ExpiredBeforeExecution
            ),
            Ok(())
        );
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &prior,
                &work,
                InvocationError::ExpiredBeforeExecution
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            prior,
            super::super::wire::encode_standard_runtime_state(&runtime.snapshot())
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_expiry_fence_requires_exact_non_execution_successor() {
        use crate::agent_sdk::{InvocationError, RuntimeWork};
        let mut work = super::super::wire::tests::clean_failing_actor_fixture(Some(0xff));
        let RuntimeWork::Invoke { observed_slot, .. } = &mut work else {
            unreachable!()
        };
        *observed_slot = 99;
        let RuntimeWork::Invoke {
            state,
            invocation,
            authorization,
            observed_slot,
            ..
        } = &work
        else {
            unreachable!()
        };
        let prior = sdk_state_as_legacy(state);
        let mut runtime = super::super::standard::StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&prior).unwrap(),
        )
        .unwrap();
        let error = InvocationError::ExpiredBeforeExecution;
        runtime
            .retain_clean_invocation_error(invocation, authorization, error, *observed_slot, None)
            .unwrap();
        let next = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        let validate = |next: &RuntimeState, error| {
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                next,
                &work,
                error,
            )
        };
        assert_eq!(validate(&next, error), Ok(()));
        assert_eq!(
            validate(&prior, error),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate(&next, InvocationError::AuthorityExpired),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate(&next, InvocationError::InvalidActorOutput),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut corrupt = next;
        corrupt.linear.push(0xff);
        assert_eq!(
            validate(&corrupt, error),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_typed_error_successor_requires_exact_retention_and_recovery() {
        use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeWork};
        let mut work = super::super::wire::tests::clean_failing_actor_fixture(Some(0xff));
        for retry in [false, true] {
            let RuntimeWork::Invoke {
                state,
                invocation,
                observed_slot,
                ..
            } = &work
            else {
                unreachable!()
            };
            let prior = sdk_state_as_legacy(state);
            let transition = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
            assert_eq!(
                transition.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::InvalidActorOutput))
            );
            let next = sdk_state_as_legacy(&transition.state);
            let validate = |next: &RuntimeState, error| {
                validate_sdk_error_transition(
                    super::super::STANDARD_RUNTIME_PROGRAM_ID,
                    &prior,
                    next,
                    &work,
                    error,
                )
            };
            assert_eq!(validate(&next, InvocationError::InvalidActorOutput), Ok(()));
            assert_eq!(
                validate(&next, InvocationError::InvalidInput),
                Err(AgentDriverError::InvalidRuntime)
            );
            let mut runtime = super::super::standard::StandardAgentRuntime::restore(
                super::super::wire::decode_standard_runtime_state(&prior).unwrap(),
            )
            .unwrap();
            runtime
                .commit_clean_exact_outcome_clock(invocation.mode, *observed_slot)
                .unwrap();
            if !retry {
                let clock_only =
                    super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
                assert_eq!(
                    validate(&clock_only, InvocationError::InvalidActorOutput),
                    Err(AgentDriverError::InvalidRuntime)
                );
            }
            let mut altered = next.clone();
            altered.linear.push(0xff);
            assert_eq!(
                validate(&altered, InvocationError::InvalidActorOutput),
                Err(AgentDriverError::InvalidRuntime)
            );
            let RuntimeWork::Invoke {
                state,
                observed_slot,
                ..
            } = &mut work
            else {
                unreachable!()
            };
            *state = transition.state;
            *observed_slot = 99;
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_terminal_failure_successor_requires_the_exact_retained_reply() {
        use crate::agent_sdk::{RuntimeOutcome, RuntimeWork};
        let work = super::super::wire::tests::clean_failing_actor_fixture(None);
        let RuntimeWork::Invoke {
            state,
            invocation,
            observed_slot,
            ..
        } = &work
        else {
            unreachable!()
        };
        let prior = sdk_state_as_legacy(state);
        let transition = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
        let next = sdk_state_as_legacy(&transition.state);
        let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
            panic!("expected failure reply")
        };
        let validate = |next: &RuntimeState, reply: &crate::agent_sdk::InvocationReply| {
            validate_sdk_failed_reply_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                next,
                &work,
                reply,
            )
        };
        assert_eq!(validate(&next, reply), Ok(()));
        let mut wrong_reply = reply.clone();
        wrong_reply.reply.push(0xaa);
        assert_eq!(
            validate(&next, &wrong_reply),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut runtime = super::super::standard::StandardAgentRuntime::restore(
            super::super::wire::decode_standard_runtime_state(&prior).unwrap(),
        )
        .unwrap();
        runtime
            .commit_clean_exact_outcome_clock(invocation.mode, *observed_slot)
            .unwrap();
        let clock_only = super::super::wire::encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(
            validate(&clock_only, reply),
            Err(AgentDriverError::InvalidRuntime)
        );
        let mut altered = super::super::wire::decode_standard_runtime_state(&next).unwrap();
        altered.invocation_results[0].clean.as_mut().unwrap().work =
            crate::agent_sdk::Hash([0xff; 32]);
        assert_eq!(
            validate(
                &super::super::wire::encode_standard_runtime_state(&altered),
                reply
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            ..
        } = work
        else {
            unreachable!()
        };
        let retry_work = RuntimeWork::Invoke {
            context,
            state: transition.state,
            invocation,
            authorization,
            observed_slot: 99,
        };
        let retry = super::super::wire::apply_standard_runtime_work(retry_work.clone()).unwrap();
        assert_eq!(retry.outcome, transition.outcome);
        assert_eq!(
            validate_sdk_failed_reply_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &next,
                &sdk_state_as_legacy(&retry.state),
                &retry_work,
                reply,
            ),
            Ok(())
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_terminal_failure_resume_successor_requires_continuation_consumption() {
        use crate::agent_sdk::{RuntimeOutcome, RuntimeWork};
        let work = super::super::wire::tests::clean_failing_resume_fixture();
        let RuntimeWork::Resume { state, .. } = &work else {
            unreachable!()
        };
        let prior = sdk_state_as_legacy(state);
        let transition = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
        let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
            panic!("expected resumed failure")
        };
        let next = sdk_state_as_legacy(&transition.state);
        let validate = |next: &RuntimeState| {
            validate_sdk_failed_reply_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                next,
                &work,
                reply,
            )
        };
        assert_eq!(validate(&next), Ok(()));
        let before = super::super::wire::decode_standard_runtime_state(&prior).unwrap();
        let mut altered = super::super::wire::decode_standard_runtime_state(&next).unwrap();
        altered.machine_continuations = before.machine_continuations;
        assert_eq!(
            validate(&super::super::wire::encode_standard_runtime_state(&altered)),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[test]
    fn bundled_runtime_exact_outcome_accepts_only_the_canonical_clock_successor() {
        let observed_slot = 9;
        let (prior, next, invocation) = standard_exact_transition_fixture(observed_slot);
        assert_eq!(
            validate_exact_execution_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &next,
                &invocation,
                observed_slot,
            ),
            Ok(())
        );

        let mut actor_bytes = next.clone();
        actor_bytes.linear.push(0xff);
        assert_eq!(
            validate_exact_execution_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &actor_bytes,
                &invocation,
                observed_slot,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let mut wrong_component = next.clone();
        wrong_component.merge.push(0xee);
        assert_eq!(
            validate_exact_execution_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &wrong_component,
                &invocation,
                observed_slot,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let (_, wrong_clock, _) = standard_exact_transition_fixture(observed_slot + 1);
        assert_eq!(
            validate_exact_execution_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &wrong_clock,
                &invocation,
                observed_slot,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[test]
    fn custom_runtime_exact_outcome_preserves_opaque_owning_component_isolation() {
        let prior = RuntimeState {
            control: vec![1],
            linear: vec![2],
            merge: vec![3],
            local: vec![4],
        };
        let mut next = prior.clone();
        next.linear.push(5);
        let (_, _, invocation) = standard_exact_transition_fixture(9);
        let custom_runtime = ProgramId([0x2a; 32]);
        assert_ne!(custom_runtime, super::super::STANDARD_RUNTIME_PROGRAM_ID);
        assert_eq!(
            validate_exact_execution_transition(custom_runtime, &prior, &next, &invocation, 9,),
            Ok(())
        );

        let mut wrong_component = next;
        wrong_component.merge.push(6);
        assert_eq!(
            validate_exact_execution_transition(
                custom_runtime,
                &prior,
                &wrong_component,
                &invocation,
                9,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    fn sdk_exact_invoke_work(
        prior: &RuntimeState,
        invocation: &ActorInvocation,
        observed_slot: u64,
    ) -> crate::agent_sdk::RuntimeWork {
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
            AuthorityReceipt, AuthorityReceiptSelector,
        };

        let decoded = super::super::wire::decode_standard_runtime_state(prior).unwrap();
        let config = decoded.config.unwrap();
        let clean = crate::agent_sdk::InvocationWork {
            space: crate::agent_sdk::SpaceId(config.identity.space.0),
            agent: crate::agent_sdk::AgentId(config.identity.agent.0),
            runtime_deployment: crate::agent_sdk::DeploymentId(
                config.identity.runtime_deployment.0,
            ),
            invocation: crate::agent_sdk::InvocationId(invocation.invocation.0),
            actor: crate::agent_sdk::ActorId(invocation.actor.0),
            incarnation: crate::agent_sdk::Hash(invocation.incarnation.0),
            deployment: crate::agent_sdk::DeploymentId(invocation.deployment.0),
            program: crate::agent_sdk::ProgramId(invocation.program.0),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: invocation.message.clone(),
            installation_data: None,
            availability: Vec::new(),
            gas: invocation.gas,
            recovery_only: false,
        };
        let public_key = [0x31; 32];
        let authority = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: crate::agent_sdk::Hash([0x32; 32]),
                issuer: AuthorityIssuer {
                    principal: crate::agent_sdk::PrincipalId(config.identity.owner.0),
                    actor: crate::agent_sdk::ActorId(config.authority.actor.0),
                    deployment: crate::agent_sdk::DeploymentId(config.authority.deployment.0),
                    program: crate::agent_sdk::ProgramId(config.authority.program.0),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                space: clean.space,
                agent: clean.agent,
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: clean.runtime_deployment,
                actor: Some(clean.actor),
                actor_deployment: Some(clean.deployment),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: crate::agent_sdk::Hash([0x33; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 1,
                expires_at: observed_slot,
                request: clean.commitment(),
            },
            public_key,
            signature: [0x34; 64],
        };
        crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: crate::agent_sdk::RuntimeState {
                control: prior.control.clone(),
                linear: prior.linear.clone(),
                merge: prior.merge.clone(),
                local: prior.local.clone(),
            },
            invocation: Box::new(clean),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority,
            )),
            observed_slot,
        }
    }

    #[test]
    fn sdk_acknowledgement_rejects_impossible_error_and_mutated_successor() {
        use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeWork};

        let observed_slot = 9;
        let (prior, _, invocation) = standard_exact_transition_fixture(observed_slot);
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = sdk_exact_invoke_work(&prior, &invocation, observed_slot)
        else {
            unreachable!()
        };
        let work = RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: legacy_state_as_sdk(&prior),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization,
        };
        let expected = expected_standard_sdk_acknowledgement_transition(&work).unwrap();
        assert_eq!(
            expected.outcome,
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotCreated))
        );

        let mut hostile = expected.clone();
        hostile.state.linear.push(0xff);
        hostile.outcome = RuntimeOutcome::Acknowledged(Err(InvocationError::AuthorityExpired));
        assert_eq!(
            validate_standard_sdk_acknowledgement_transition(&expected, &hostile),
            Err(AgentDriverError::InvalidRuntime),
            "the driver requires both the exact acknowledgement result and exact successor"
        );

        let RuntimeWork::Acknowledge {
            invocation,
            authorization,
            ..
        } = &work
        else {
            unreachable!()
        };
        let custom_runtime = ProgramId([0x35; 32]);
        assert_ne!(custom_runtime, super::super::STANDARD_RUNTIME_PROGRAM_ID);
        let mut custom_next = prior.clone();
        custom_next.linear.push(0x36);
        let acknowledgement = crate::agent_sdk::InvocationAcknowledgement {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            work: invocation.commitment(),
            authorization: authorization.commitment(),
        };
        let custom_success = crate::agent_sdk::RuntimeTransition {
            state: legacy_state_as_sdk(&custom_next),
            outcome: RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
        };
        assert_eq!(
            validate_sdk_acknowledgement_transition(custom_runtime, &prior, &work, &custom_success,),
            Ok(())
        );

        let mut substituted = acknowledgement;
        substituted.authorization = crate::agent_sdk::Hash([0x37; 32]);
        let mut hostile_success = custom_success.clone();
        hostile_success.outcome = RuntimeOutcome::Acknowledged(Ok(substituted));
        assert_eq!(
            validate_sdk_acknowledgement_transition(
                custom_runtime,
                &prior,
                &work,
                &hostile_success,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let custom_failure = crate::agent_sdk::RuntimeTransition {
            state: legacy_state_as_sdk(&prior),
            outcome: RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound)),
        };
        assert_eq!(
            validate_sdk_acknowledgement_transition(custom_runtime, &prior, &work, &custom_failure,),
            Ok(())
        );
        let mut mutating_failure = custom_failure;
        mutating_failure.state.linear.push(0x38);
        assert_eq!(
            validate_sdk_acknowledgement_transition(
                custom_runtime,
                &prior,
                &work,
                &mutating_failure,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn sdk_driver_directly_acknowledges_a_retained_required_attestation_result() {
        use super::super::package_admission::{
            ScriptedRuntimeCase, admitted_scripted_runtime_for_test,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{RuntimeExecutionContext, RuntimeOutcome, RuntimeWork};

        let proof_system = crate::agent_sdk::Hash([0xe7; 32]);
        let (retained, invocation, authorization) =
            super::super::wire::tests::completed_clean_policy_fixture(proof_system);
        let work = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: retained.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization: Box::new(authorization.clone()),
        };
        let expected = super::super::wire::apply_standard_runtime_work(work.clone()).unwrap();
        assert!(matches!(
            expected.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));

        let runtime_package = admitted_scripted_runtime_for_test(
            "driver-required-acknowledgement",
            0xe8,
            vec![ScriptedRuntimeCase {
                input: work.encode().unwrap(),
                output: expected.encode().unwrap(),
                copies: Vec::new(),
            }],
        );
        let runtime_state = sdk_state_as_legacy(&retained);
        let descriptor = super::super::wire::decode_standard_runtime_state(&runtime_state)
            .unwrap()
            .clean_descriptor
            .unwrap();
        let config =
            super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap();
        // Production construction authenticates program bytes. This unit
        // fixture substitutes a physical scripted PVM solely to exercise the
        // post-construction execution and Standard-oracle comparison path
        // without repinning the bundled blob.
        let runtime_program = config.identity.runtime_program;
        let image = AgentImage {
            clean_descriptor: Some(descriptor.clone()),
            revision: 1,
            runtime_program,
            config: config.clone(),
            clean_management: Some(LocalManagementHistory::from_standard_fixture(
                &super::super::wire::decode_standard_runtime_state(&runtime_state).unwrap(),
            )),
            runtime_state,
        };
        let mut store = MemoryAgentStore::default();
        store.commit(None, &image).unwrap();
        let trust = Arc::new(AnchorTrust {
            space: config.identity.space,
            authority: config.authority.clone(),
        });
        let mut driver = AgentDriver {
            runtime_pvm: runtime_package.program_bytes().to_vec(),
            image,
            store,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            catalog_cleanup_pending: false,
            trust,
        };

        let outcome = driver.acknowledge_sdk(invocation, authorization).unwrap();
        assert_eq!(outcome, expected.outcome);
        assert_eq!(
            driver.image().runtime_state,
            sdk_state_as_legacy(&expected.state),
            "the production driver commits the guest's exact retirement successor",
        );
        assert_eq!(driver.image().revision, 2);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn public_directory_query_accepts_opaque_state_and_rejects_mutating_replies() {
        use super::super::package_admission::{
            ScriptedRuntimeCase, admitted_scripted_runtime_for_test,
        };
        use crate::agent_sdk::{ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork};
        let (retained, _, _) = super::super::wire::tests::completed_clean_policy_fixture(
            crate::agent_sdk::Hash([0xe7; 32]),
        );
        let template = clean_descriptor_from_state(&sdk_state_as_legacy(&retained)).unwrap();
        let opaque = crate::agent_sdk::RuntimeState {
            control: b"opaque-local-directory-control".to_vec(),
            linear: vec![1],
            merge: vec![2],
            local: vec![3],
        };
        assert!(
            super::super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(&opaque))
                .is_err()
        );
        for mutation in 0..6 {
            let mut returned = crate::agent_sdk::RuntimeTransition {
                state: opaque.clone(),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Actors(
                    crate::agent_sdk::ActorDirectoryPage {
                        entries: Vec::new(),
                        next: None,
                    },
                ))),
            };
            match mutation {
                0 => {}
                1 => returned.state.control.push(9),
                2 => returned.state.linear.push(9),
                3 => returned.state.merge.push(9),
                4 => returned.state.local.push(9),
                _ => {
                    returned.outcome =
                        RuntimeOutcome::Management(Err(crate::agent_sdk::ManagementError::NotFound))
                }
            }
            let work = RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: template.identity.space,
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: opaque.clone(),
                request: Box::new(ManagementRequest::InspectActors {
                    after: None,
                    limit: crate::agent_sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
                }),
                authority: None,
                observed_slot: 1,
            };
            let package = admitted_scripted_runtime_for_test(
                "opaque-local-directory",
                0xb1 + mutation,
                vec![ScriptedRuntimeCase {
                    input: work.encode().unwrap(),
                    output: returned.encode().unwrap(),
                    copies: Vec::new(),
                }],
            );
            let mut descriptor = template.clone();
            descriptor.identity.runtime_deployment = package.deployment();
            descriptor.identity.runtime_program = package.program();
            descriptor.identity.runtime_producer = package.producer();
            descriptor.runtime_package = package.package_ref().clone();
            descriptor.runtime_contract = package.manifest().contract;
            descriptor.capabilities = package.capabilities();
            let config =
                super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap();
            let trust = Arc::new(AnchorTrust {
                space: config.identity.space,
                authority: config.authority.clone(),
            });
            // Exercise the post-construction query only. Production custom
            // Create/reopen is a separate, still-unfinished boundary.
            let driver = AgentDriver {
                runtime_pvm: package.program_bytes().to_vec(),
                image: AgentImage {
                    clean_descriptor: Some(descriptor.clone()),
                    clean_management: Some(LocalManagementHistory::from_standard_fixture(
                        &super::super::wire::decode_standard_runtime_state(&sdk_state_as_legacy(
                            &retained,
                        ))
                        .unwrap(),
                    )),
                    revision: 1,
                    runtime_program: config.identity.runtime_program,
                    config,
                    runtime_state: sdk_state_as_legacy(&opaque),
                },
                store: MemoryAgentStore::default(),
                management_gas: DEFAULT_MANAGEMENT_GAS,
                catalog_cleanup_pending: false,
                trust,
            };
            let result = driver.inspect_sdk_actor_directory(&descriptor);
            if mutation == 0 {
                assert_eq!(result, Ok(Vec::new()));
                let mut driver = driver;
                driver.image.clean_descriptor = None;
                assert_eq!(
                    driver.inspect_sdk_actor_directory(&descriptor),
                    Err(AgentDriverError::InvalidRuntime)
                );
                assert_eq!(driver.image.runtime_state, sdk_state_as_legacy(&opaque));
                continue;
            } else {
                assert_eq!(
                    result,
                    Err(AgentDriverError::InvalidRuntime),
                    "mutation {mutation}"
                );
            }
            assert_eq!(driver.image.runtime_state, sdk_state_as_legacy(&opaque));
        }
    }

    #[test]
    fn current_driver_gate_rejects_attested_runtime_work() {
        let observed_slot = 9;
        let (prior, _, invocation) = standard_exact_transition_fixture(observed_slot);
        let mut work = sdk_exact_invoke_work(&prior, &invocation, observed_slot);
        let crate::agent_sdk::RuntimeWork::Invoke { context, .. } = &mut work else {
            unreachable!()
        };
        *context = crate::agent_sdk::RuntimeExecutionContext::Attested {
            proof_system: crate::agent_sdk::Hash([0xa8; 32]),
        };
        assert_eq!(
            require_direct_runtime_work(&work),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    #[test]
    fn sdk_error_transitions_reject_hostile_standard_and_custom_state() {
        use crate::agent_sdk::InvocationError;

        let observed_slot = 9;
        let (prior, exact, invocation) = standard_exact_transition_fixture(observed_slot);
        let work = sdk_exact_invoke_work(&prior, &invocation, observed_slot);
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation: clean,
            authorization,
            ..
        } = &work
        else {
            unreachable!()
        };
        let mut actor_origin = (**clean).clone();
        actor_origin.origin.actor = Some(crate::agent_sdk::ActorId([0x38; 32]));
        assert!(actor_origin.validate());
        assert_eq!(
            validate_standard_sdk_invoke_preflight(
                &prior,
                &actor_origin,
                authorization,
                observed_slot
            ),
            Ok(()),
            "actor provenance is a valid independently authenticated origin field"
        );

        let mut malformed_origin = (**clean).clone();
        malformed_origin.origin.principal = None;
        malformed_origin.origin.credential = Some(crate::agent_sdk::CredentialId([0x39; 32]));
        assert!(!malformed_origin.validate());
        let unchanged = prior.clone();
        assert_eq!(
            validate_standard_sdk_invoke_preflight(
                &prior,
                &malformed_origin,
                authorization,
                observed_slot
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_standard_sdk_invoke_preflight(
                &prior,
                &malformed_origin,
                authorization,
                observed_slot
            ),
            Err(AgentDriverError::InvalidRuntime),
            "an exact retry is the same nonterminal host rejection"
        );
        assert_eq!(prior, unchanged);
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &exact,
                &work,
                InvocationError::InvalidActorOutput,
            ),
            Err(AgentDriverError::InvalidRuntime),
            "clock-only errors are not retained exact outcomes"
        );
        let mut forged_exact = exact.clone();
        forged_exact.linear.push(0xff);
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &forged_exact,
                &work,
                InvocationError::InvalidActorOutput,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &prior,
                &work,
                InvocationError::InvalidInput,
            ),
            Err(AgentDriverError::InvalidRuntime),
            "a runtime cannot turn a host-admission failure into an unclocked terminal result"
        );
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &prior,
                &work,
                InvocationError::InvalidAvailability,
            ),
            Ok(())
        );
        assert_eq!(
            validate_sdk_error_transition(
                super::super::STANDARD_RUNTIME_PROGRAM_ID,
                &prior,
                &exact,
                &work,
                InvocationError::InvalidAvailability,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );

        let custom = ProgramId([0x35; 32]);
        let mut owned = prior.clone();
        owned.linear.push(0x36);
        assert_eq!(
            validate_sdk_error_transition(
                custom,
                &prior,
                &owned,
                &work,
                InvocationError::InvalidAvailability,
            ),
            Ok(())
        );
        owned.merge.push(0x37);
        assert_eq!(
            validate_sdk_error_transition(
                custom,
                &prior,
                &owned,
                &work,
                InvocationError::InvalidAvailability,
            ),
            Err(AgentDriverError::InvalidRuntime)
        );
    }

    fn valid_image(revision: u64) -> AgentImage {
        let mut config = invalid_config();
        config.replicas = vec![super::super::AgentReplica {
            node: crate::service::NodeId([0x21; 32]),
            principal: config.identity.owner,
            role: super::super::ReplicaRole::Voter,
        }];
        assert_eq!(config.validate(), Ok(()));
        AgentImage {
            clean_descriptor: None,
            clean_management: None,
            revision,
            runtime_program: config.identity.runtime_program,
            config,
            runtime_state: RuntimeState {
                control: vec![1],
                linear: vec![2],
                merge: vec![3],
                local: vec![4],
            },
        }
    }

    #[test]
    fn image_wire_checks_lane_aggregate_before_accepting_it() {
        let mut image = valid_image(1);
        image.runtime_state.control = vec![1; MAX_RUNTIME_STATE_BYTES / 2];
        image.runtime_state.linear = vec![2; MAX_RUNTIME_STATE_BYTES / 2 + 1];
        assert_eq!(
            AgentImage::decode(&image.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn file_image_store_resumes_only_an_exact_regular_stage() {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vos-agent-image-resume-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.image");
        let mut store = FileAgentStore::new(&path);
        let first = valid_image(1);
        store.commit(None, &first).unwrap();

        let second = valid_image(2);
        std::fs::write(path.with_extension("next"), second.encode()).unwrap();
        store.commit(Some(1), &second).unwrap();
        assert_eq!(store.load().unwrap(), Some(second.clone()));

        std::fs::write(path.with_extension("next"), valid_image(3).encode()).unwrap();
        let fourth = valid_image(4);
        store
            .commit(Some(2), &fourth)
            .expect("a different canonical crash stage is replaceable");
        assert_eq!(store.load().unwrap(), Some(fourth));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_staging_never_follows_preseeded_symlinks() {
        use std::os::unix::fs::symlink;

        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vos-agent-image-symlink-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.image");
        let external = directory.join("external");
        std::fs::write(&external, b"must remain unchanged").unwrap();
        let mut store = FileAgentStore::new(&path);
        let first = valid_image(1);
        store.commit(None, &first).unwrap();

        let next = path.with_extension("next");
        symlink(&external, &next).unwrap();
        assert_eq!(
            store.commit(Some(1), &valid_image(2)),
            Err(AgentStoreError::Corrupt)
        );
        assert_eq!(std::fs::read(&external).unwrap(), b"must remain unchanged");
        std::fs::remove_file(&next).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));

        let package = b"signed package";
        let reference = BlobRef::of_bytes(package);
        let artifact = store.catalog_path("packages", &reference.hash.0, "vos");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        symlink(&external, artifact.with_extension("next")).unwrap();
        assert_eq!(
            store.put_package(&reference, package),
            Err(AgentStoreError::Corrupt)
        );
        assert_eq!(std::fs::read(&external).unwrap(), b"must remain unchanged");

        std::fs::remove_file(artifact.with_extension("next")).unwrap();
        symlink(&external, &artifact).unwrap();
        assert_eq!(
            store.put_package(&reference, package),
            Err(AgentStoreError::Corrupt)
        );
        assert_eq!(std::fs::read(&external).unwrap(), b"must remain unchanged");

        std::fs::remove_file(&path).unwrap();
        symlink(&external, &path).unwrap();
        assert_eq!(store.load(), Err(AgentStoreError::Corrupt));
        assert_eq!(std::fs::read(&external).unwrap(), b"must remain unchanged");

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_image_store_rejects_nonregular_and_oversized_images() {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vos-agent-image-shape-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let special = directory.join("special.image");
        std::fs::create_dir(&special).unwrap();
        assert_eq!(
            FileAgentStore::new(&special).load(),
            Err(AgentStoreError::Corrupt)
        );

        let oversized = directory.join("oversized.image");
        let file = File::create(&oversized).unwrap();
        file.set_len((MAX_AGENT_IMAGE_BYTES + 1) as u64).unwrap();
        assert_eq!(
            FileAgentStore::new(&oversized).load(),
            Err(AgentStoreError::Corrupt)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn loaded_actor_requires_exact_schema_sidecar_provenance() {
        let (schema_bytes, schema_len) =
            super::super::schema::encode::<512>(&super::super::schema::SchemaMeta {
                uses_storage: false,
                fields: &[super::super::schema::FieldMeta {
                    name: "value",
                    codec: "u64",
                    persistence: super::super::FieldPersistence::State(
                        super::super::StateLane::Linear,
                    ),
                }],
                methods: &[super::super::schema::MethodMeta {
                    name: "increment",
                    mode: super::super::MethodMode::Linear,
                    explicit: true,
                }],
            });
        let schema_bytes = &schema_bytes[..schema_len];
        let schema = super::super::schema::decode(schema_bytes).unwrap();
        let schema_reference = BlobRef::of_bytes(schema_bytes);
        let policy_bytes = crate::service::PackageRolePolicies {
            methods: Vec::new(),
            task_dependencies: Vec::new(),
        }
        .encode();
        let policy_reference = BlobRef::of_bytes(&policy_bytes);
        let package_reference = BlobRef::of_bytes(b"signed-package");
        let deployment = DeploymentId([0x31; 32]);
        let program_bytes = b"actor-pvm";
        let program = ProgramId::of_pvm(program_bytes);
        let actor = ActorEntry {
            actor: ActorId([0x32; 32]),
            name: "counter".into(),
            parent: None,
            deployment,
            program,
            package: package_reference,
            agent_schema: schema_reference.clone(),
            role_policies: policy_reference.clone(),
            constructor_abi: Hash([0x33; 32]),
            installation_data: None,
            state_layout: schema.state_layout_hash(),
            lanes: schema.lanes(),
            suspended: false,
        };
        let mut store = MemoryAgentStore::default();
        store.put_program(program, program_bytes).unwrap();
        store
            .put_actor_schema(deployment, &schema_reference, schema_bytes)
            .unwrap();
        store
            .put_actor_policies(deployment, &policy_reference, &policy_bytes)
            .unwrap();
        assert_eq!(load_actor_artifacts(&store, &actor).map(|_| ()), Ok(()));

        let mut missing_policy = store.clone();
        missing_policy.policies.remove(&deployment);
        assert_eq!(
            load_actor_artifacts(&missing_policy, &actor).map(|_| ()),
            Err(AgentDriverError::PolicyUnavailable(deployment))
        );

        let corrupt_policy = b"not-canonical-role-policies".to_vec();
        let corrupt_reference = BlobRef::of_bytes(&corrupt_policy);
        let mut corrupt_store = store.clone();
        corrupt_store.policies.insert(
            deployment,
            RuntimeBlob {
                reference: corrupt_reference.clone(),
                bytes: corrupt_policy,
            },
        );
        let mut corrupt_actor = actor.clone();
        corrupt_actor.role_policies = corrupt_reference;
        assert_eq!(
            load_actor_artifacts(&corrupt_store, &corrupt_actor).map(|_| ()),
            Err(AgentDriverError::PolicyMismatch(deployment))
        );

        let mut wrong_reference = actor.clone();
        wrong_reference.agent_schema.hash = Hash([0x33; 32]);
        assert_eq!(
            load_actor_artifacts(&store, &wrong_reference).map(|_| ()),
            Err(AgentDriverError::SchemaMismatch(deployment))
        );

        let mut wrong_layout = actor;
        wrong_layout.state_layout = Hash([0x34; 32]);
        assert_eq!(
            load_actor_artifacts(&store, &wrong_layout).map(|_| ()),
            Err(AgentDriverError::SchemaMismatch(deployment))
        );
    }

    #[test]
    fn memory_catalog_reconciles_failed_staging_upgrade_and_shared_removal() {
        let old_a = CatalogFixture::new(0x41, ActorId([0x51; 32]));
        let mut old_b = CatalogFixture::new(0x41, ActorId([0x52; 32]));
        old_b.entry.name = "second-shared-actor".into();
        let new_a = CatalogFixture::new(0x42, old_a.entry.actor);
        let mut new_b = CatalogFixture::new(0x42, old_b.entry.actor);
        new_b.entry.name = old_b.entry.name.clone();
        let failed_stage = CatalogFixture::new(0x43, ActorId([0x53; 32]));
        let mut store = MemoryAgentStore::default();
        put_runtime_catalog(&mut store);

        old_a.put(&mut store);
        failed_stage.put(&mut store);
        store
            .reconcile_catalog(&catalog_references(vec![
                old_a.entry.clone(),
                old_b.entry.clone(),
            ]))
            .unwrap();
        assert_eq!(store.packages.len(), 2, "failed package staging is pruned");
        assert_eq!(store.programs.len(), 2, "failed program staging is pruned");
        assert_eq!(store.schemas.len(), 1, "failed schema staging is pruned");
        assert_eq!(store.policies.len(), 1, "failed policy staging is pruned");

        new_a.put(&mut store);
        store
            .reconcile_catalog(&catalog_references(vec![
                new_a.entry.clone(),
                old_b.entry.clone(),
            ]))
            .unwrap();
        assert_eq!(store.packages.len(), 3);
        assert_eq!(store.programs.len(), 3);

        store
            .reconcile_catalog(&catalog_references(vec![
                new_a.entry.clone(),
                new_b.entry.clone(),
            ]))
            .unwrap();
        assert_eq!(store.packages.len(), 2, "last old deployment was upgraded");
        assert_eq!(store.programs.len(), 2);
        assert_eq!(store.schemas.len(), 1);
        assert_eq!(store.policies.len(), 1);

        store
            .reconcile_catalog(&catalog_references(vec![new_a.entry.clone()]))
            .unwrap();
        assert_eq!(
            store.packages.len(),
            2,
            "one shared actor still owns artifacts"
        );
        store
            .reconcile_catalog(&catalog_references(Vec::new()))
            .unwrap();
        assert_eq!(store.packages.len(), 1, "runtime package remains owned");
        assert_eq!(store.programs.len(), 1, "runtime program remains owned");
        assert!(store.schemas.is_empty());
        assert!(store.policies.is_empty());
    }

    #[test]
    fn memory_catalog_validates_live_closure_before_pruning() {
        let live = CatalogFixture::new(0x61, ActorId([0x71; 32]));
        let orphan = CatalogFixture::new(0x62, ActorId([0x72; 32]));
        let mut store = MemoryAgentStore::default();
        put_runtime_catalog(&mut store);
        live.put(&mut store);
        orphan.put(&mut store);
        store
            .packages
            .insert(live.entry.package.hash, b"corrupt".to_vec());

        assert_eq!(
            store.reconcile_catalog(&catalog_references(vec![live.entry.clone()])),
            Err(AgentStoreError::Corrupt)
        );
        assert!(
            store.packages.contains_key(&orphan.entry.package.hash),
            "validation failure must not start pruning unrelated recovery data"
        );
        assert!(store.programs.contains_key(&orphan.entry.program));
        assert!(store.schemas.contains_key(&orphan.entry.deployment));
        assert!(store.policies.contains_key(&orphan.entry.deployment));
    }

    #[test]
    fn installation_data_sidecars_preserve_present_empty_and_reject_hostile_content() {
        let empty_reference = BlobRef::of_bytes(&[]);
        let bytes = b"immutable constructor args";
        let reference = BlobRef::of_bytes(bytes);

        let mut memory = MemoryAgentStore::default();
        assert_eq!(memory.load_installation_data(&empty_reference), Ok(None));
        assert_eq!(
            memory.put_installation_data(&empty_reference, &[]),
            Ok(true)
        );
        assert_eq!(
            memory.load_installation_data(&empty_reference),
            Ok(Some(RuntimeBlob {
                reference: empty_reference.clone(),
                bytes: Vec::new(),
            }))
        );
        assert_eq!(memory.put_installation_data(&reference, bytes), Ok(true));
        assert_eq!(
            memory.put_installation_data(&empty_reference, bytes),
            Err(AgentStoreError::Corrupt)
        );
        let oversized = vec![0; super::super::MAX_INSTALLATION_DATA_BYTES + 1];
        assert_eq!(
            memory.put_installation_data(&BlobRef::of_bytes(&oversized), &oversized),
            Err(AgentStoreError::Corrupt)
        );

        put_runtime_catalog(&mut memory);
        let mut actor = CatalogFixture::new(0x73, ActorId([0x74; 32]));
        actor.entry.installation_data = Some(reference.clone());
        actor.put(&mut memory);
        memory
            .reconcile_catalog(&catalog_references(vec![actor.entry.clone()]))
            .unwrap();
        assert_eq!(
            memory
                .load_installation_data(&reference)
                .unwrap()
                .unwrap()
                .bytes,
            bytes
        );
        memory
            .reconcile_catalog(&catalog_references(Vec::new()))
            .unwrap();
        assert_eq!(memory.load_installation_data(&reference), Ok(None));
    }

    #[test]
    fn physical_installation_data_sidecar_reopens_exactly_and_is_pruned_with_its_actor() {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vos-agent-installation-data-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let image = directory.join("agent.image");
        let bytes = b"restart-stable constructor args";
        let reference = BlobRef::of_bytes(bytes);
        let mut actor = CatalogFixture::new(0x75, ActorId([0x76; 32]));
        actor.entry.installation_data = Some(reference.clone());

        {
            let mut store = FileAgentStore::new(&image);
            put_runtime_catalog(&mut store);
            actor.put(&mut store);
            store.put_installation_data(&reference, bytes).unwrap();
            store
                .reconcile_catalog(&catalog_references(vec![actor.entry.clone()]))
                .unwrap();
        }
        let mut reopened = FileAgentStore::new(&image);
        assert_eq!(
            reopened.load_installation_data(&reference),
            Ok(Some(RuntimeBlob {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            }))
        );
        reopened
            .reconcile_catalog(&catalog_references(Vec::new()))
            .unwrap();
        assert_eq!(reopened.load_installation_data(&reference), Ok(None));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn physical_file_catalog_reconciles_crash_staging_and_shared_ownership() {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "vos-agent-catalog-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let image = directory.join("agent.image");
        let mut store = FileAgentStore::new(&image);
        put_runtime_catalog(&mut store);
        let shared_a = CatalogFixture::new(0x81, ActorId([0x91; 32]));
        let mut shared_b = CatalogFixture::new(0x81, ActorId([0x92; 32]));
        shared_b.entry.name = "second-shared-actor".into();
        let orphan = CatalogFixture::new(0x82, ActorId([0x93; 32]));
        shared_a.put(&mut store);
        orphan.put(&mut store);

        let interrupted = store
            .catalog_path("packages", &[0xa1; 32], "vos")
            .with_extension("next");
        std::fs::create_dir_all(interrupted.parent().unwrap()).unwrap();
        std::fs::write(&interrupted, b"partial failed stage").unwrap();

        store
            .reconcile_catalog(&catalog_references(vec![
                shared_a.entry.clone(),
                shared_b.entry.clone(),
            ]))
            .unwrap();
        assert!(!interrupted.exists(), "crash-left staging file is retired");
        assert!(
            store
                .load_program(shared_a.entry.program)
                .unwrap()
                .is_some()
        );
        assert!(store.load_program(orphan.entry.program).unwrap().is_none());
        assert!(
            store
                .load_actor_schema(orphan.entry.deployment)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_actor_policies(orphan.entry.deployment)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .read_regular_artifact(&store.catalog_path(
                    "packages",
                    &orphan.entry.package.hash.0,
                    "vos"
                ))
                .unwrap()
                .is_none()
        );

        store
            .reconcile_catalog(&catalog_references(vec![shared_a.entry.clone()]))
            .unwrap();
        assert!(
            store
                .load_program(shared_a.entry.program)
                .unwrap()
                .is_some()
        );
        store
            .reconcile_catalog(&catalog_references(Vec::new()))
            .unwrap();
        assert!(
            store
                .load_program(shared_a.entry.program)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_actor_schema(shared_a.entry.deployment)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .load_actor_policies(shared_a.entry.deployment)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .read_regular_artifact(&store.catalog_path(
                    "packages",
                    &shared_a.entry.package.hash.0,
                    "vos"
                ))
                .unwrap()
                .is_none()
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    fn invalid_config() -> AgentConfig {
        use crate::agent::{AgentIdentity, AgentProfile, RuntimeCapabilities};
        use crate::service::{AgentId, BlobRef, DeploymentId, PrincipalId, ProducerId, SpaceId};
        let authority_key = crate::agent::authority::ed25519_public_key_wire([0x41; 32]);
        let space = SpaceId([1; 32]);
        let owner = PrincipalId([3; 32]);
        let creation_nonce = Hash([0x15; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &creation_nonce.0),
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([1; 32]),
                runtime_producer: ProducerId([5; 32]),
                transition_producer: ProducerId([6; 32]),
            },
            creation_nonce,
            authority: crate::agent::authority::AgentAuthorityBinding {
                agent: AgentId([7; 32]),
                actor: ActorId([8; 32]),
                deployment: DeploymentId([9; 32]),
                program: ProgramId([10; 32]),
                producer: ProducerId::of_public_key(&authority_key),
                public_key: authority_key,
            },
            system_authority_genesis: None,
            runtime_package: BlobRef {
                hash: Hash([6; 32]),
                len: 1,
            },
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: Vec::new(),
        }
    }
}
