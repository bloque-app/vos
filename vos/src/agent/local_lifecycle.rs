//! Native ownership boundary for signed Local Agent lifecycle operations.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use super::clean_authority_issuer::{
    CleanManagementIssuerStore, CleanManagementReceiptSigner, SignedManagementTerminal,
};
use super::clean_bootstrap::{CleanSystemAgentBootstrapOwner, CleanSystemAgentBootstrapStore};
use super::local_sdk_host::LocalAgentHost;
use super::package_admission::AdmittedRuntimePackage;
use super::sdk::authority::{AuthorityCredentialCall, ManagementApplicationAck};
use super::sdk::{AgentDescriptor, AgentId, AgentProfile, ManagementRequest, SpaceId};
use super::shared_host::SharedAgentHostError;
use super::supervisor_adapters::{AgentRouteAdapterError, AgentRouteHostAttachment};

pub const LOCAL_LIFECYCLE_QUEUE_CAPACITY: usize = 4;

#[path = "operation_submission.rs"]
mod operation_submission;
pub use operation_submission::AuthorityOperationSubmission;
#[path = "shared_submission.rs"]
mod shared_submission;
pub use shared_submission::{SharedCreateSubmission, SharedInstallSubmission};

pub type AuthorityOperationResult =
    Result<super::clean_bootstrap::NativeAuthorityOperationDecision, SharedAgentHostError>;
pub type AuthorityOperationPreparationResult =
    Result<AuthorityOperationSubmission, SharedAgentHostError>;
pub type AuthorityAdminPreparationResult =
    Result<super::clean_bootstrap::NativeAuthorityAdminPreparation, SharedAgentHostError>;
pub type AuthorityAdminSubmissionResult =
    Result<super::clean_bootstrap::NativeAuthorityAdminCompletion, SharedAgentHostError>;

/// Canonical signed Create submission: LCQ1 followed by length-prefixed AMRQ,
/// ACC3 and an exact admitted VOS3 runtime package. This is untrusted request
/// data, not an Authority approval or a genesis-finality proof.
pub struct LocalCreateSubmission {
    descriptor: AgentDescriptor,
    call: AuthorityCredentialCall,
    runtime: AdmittedRuntimePackage,
}

/// Distinct LCQ2 request for the experimental external-state Local runtime.
/// It has the same signed Create claim as LCQ1, but its runtime package is
/// admitted against the state-execution ABI. This envelope alone grants no
/// lifecycle, journal or route authority. The opt-in HTTP path may queue it,
/// but only the selected external controller can execute it.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
#[derive(Clone)]
pub struct LocalStateCreateSubmission {
    descriptor: AgentDescriptor,
    call: AuthorityCredentialCall,
    runtime: super::package_admission::AdmittedStateRuntimePackage,
}

/// LIQ1 carries an exact signed Install and admitted actor package. Admission
/// authenticates request bytes, not Authority approval or target availability.
pub struct LocalInstallSubmission {
    install: super::sdk::InstallActor,
    call: AuthorityCredentialCall,
    package: super::package_admission::AdmittedActorPackage,
}

impl LocalInstallSubmission {
    pub const MAX_BYTES: usize = LocalCreateSubmission::MAX_BYTES;

    pub(crate) fn install(&self) -> &super::sdk::InstallActor {
        &self.install
    }

    pub(crate) fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    pub(crate) fn package(&self) -> &super::package_admission::AdmittedActorPackage {
        &self.package
    }

    pub(crate) fn has_transport_node_claim(&self) -> bool {
        self.call.authenticated_node.is_some()
    }

    pub fn new(
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: super::package_admission::AdmittedActorPackage,
    ) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::service::wire::DecodeError;
        if call.managed.profile != AgentProfile::Local
            || install.package != *package.package_ref()
            || install.entry.deployment != package.deployment()
            || install.entry.program != package.program()
            || install.producer != package.producer()
        {
            return Err(DecodeError::NonCanonical);
        }
        install
            .validate_for_profile(AgentProfile::Local)
            .map_err(|_| DecodeError::NonCanonical)?;
        super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Install(Box::new(install.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            install,
            call,
            package,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        use super::sdk::wire::CanonicalWire as _;
        let mut bytes = b"LIQ1".to_vec();
        let mut encoder = crate::service::wire::Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Install(Box::new(self.install.clone()))
                .encode()
                .expect("validated Install"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.package.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::service::wire::DecodeError> {
        use super::sdk::wire::CanonicalWire as _;
        use crate::service::wire::{DecodeError, Decoder};
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"LIQ1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Install(install) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        let package = super::package_admission::admit_actor_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*install, call, package)
    }

    pub fn into_parts(
        self,
    ) -> (
        super::sdk::InstallActor,
        AuthorityCredentialCall,
        super::package_admission::AdmittedActorPackage,
    ) {
        (self.install, self.call, self.package)
    }
}

/// A signed server-side retirement of one exact denied Create. This is not an
/// application acknowledgement, policy approval, or evidence of a live route.
/// Construct only by verifying against an independently retained submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCreateDenial {
    bytes: Vec<u8>,
}

/// Authenticated retirement of one exact refused Shared Install. This is not
/// an application failure, receipt, or proof that the actor is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedInstallDenial {
    bytes: Vec<u8>,
}

impl SharedInstallDenial {
    pub const MAX_BYTES: usize = super::clean_management_intent::MAX_INTENT_BYTES;

    /// Verify against the caller's independently retained signed request and
    /// Authority pins, never a request supplied by the response itself.
    pub fn verify(
        install: &super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
        bytes: &[u8],
    ) -> Result<Self, crate::service::wire::DecodeError> {
        if call.managed.profile != AgentProfile::Shared {
            return Err(crate::service::wire::DecodeError::NonCanonical);
        }
        super::clean_management_intent::verify_denial_record(
            bytes,
            &ManagementRequest::Install(Box::new(install.clone())),
            call,
        )?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl LocalCreateDenial {
    pub const MAX_BYTES: usize = super::clean_management_intent::MAX_INTENT_BYTES;

    pub fn exact_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl LocalCreateSubmission {
    /// The caller must establish this submission's Space, operator and Authority
    /// from its own retained request/pins before treating denial as completion.
    /// No runtime replay or access to the server's stores is needed here.
    pub fn verify_denial(
        &self,
        bytes: &[u8],
    ) -> Result<LocalCreateDenial, crate::service::wire::DecodeError> {
        super::clean_management_intent::verify_denial_record(
            bytes,
            &ManagementRequest::Create(Box::new(self.descriptor.clone())),
            &self.call,
        )?;
        Ok(LocalCreateDenial {
            bytes: bytes.to_vec(),
        })
    }

    pub const MAX_BYTES: usize = 16
        + super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
        + super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
        + super::sdk::package::MAX_PACKAGE_ENCODED_BYTES;

    pub fn new(
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::service::wire::DecodeError;
        if descriptor.identity.profile != AgentProfile::Local {
            return Err(DecodeError::NonCanonical);
        }
        super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| DecodeError::NonCanonical)?;
        super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            descriptor,
            call,
            runtime,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        use super::sdk::wire::CanonicalWire as _;
        let mut bytes = b"LCQ1".to_vec();
        let mut encoder = crate::service::wire::Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Create(Box::new(self.descriptor.clone()))
                .encode()
                .expect("validated Create"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.runtime.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::service::wire::DecodeError> {
        use super::sdk::wire::CanonicalWire as _;
        use crate::service::wire::{DecodeError, Decoder};
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"LCQ1") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Create(descriptor) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        let runtime = super::package_admission::admit_runtime_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*descriptor, call, runtime)
    }

    pub fn into_parts(
        self,
    ) -> (
        AgentDescriptor,
        AuthorityCredentialCall,
        AdmittedRuntimePackage,
    ) {
        (self.descriptor, self.call, self.runtime)
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl LocalStateCreateSubmission {
    pub const MAX_BYTES: usize = LocalCreateSubmission::MAX_BYTES;

    /// Verify a terminal signed denial against this exact retained request.
    pub fn verify_denial(
        &self,
        bytes: &[u8],
    ) -> Result<LocalCreateDenial, crate::service::wire::DecodeError> {
        super::clean_management_intent::verify_denial_record(
            bytes,
            &ManagementRequest::Create(Box::new(self.descriptor.clone())),
            &self.call,
        )?;
        Ok(LocalCreateDenial {
            bytes: bytes.to_vec(),
        })
    }

    pub fn new(
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime_package: &[u8],
    ) -> Result<Self, crate::service::wire::DecodeError> {
        use crate::service::wire::DecodeError;
        let runtime = super::package_admission::admit_state_runtime_package(runtime_package)
            .map_err(|_| DecodeError::NonCanonical)?;
        if !super::external_local_executor::state_runtime_matches_descriptor(&descriptor, &runtime)
        {
            return Err(DecodeError::NonCanonical);
        }
        super::clean_management_intent::CleanManagementIntent::new(
            call.authority,
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Ok(Self {
            descriptor,
            call,
            runtime,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        use super::sdk::wire::CanonicalWire as _;
        let mut bytes = b"LCQ2".to_vec();
        let mut encoder = crate::service::wire::Encoder(&mut bytes);
        encoder.bytes(
            &ManagementRequest::Create(Box::new(self.descriptor.clone()))
                .encode()
                .expect("validated external Create"),
        );
        encoder.bytes(&self.call.encode().expect("validated credential call"));
        encoder.bytes(self.runtime.exact_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::service::wire::DecodeError> {
        use super::sdk::wire::CanonicalWire as _;
        use crate::service::wire::{DecodeError, Decoder};
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if bytes.get(..4) != Some(b"LCQ2") {
            return Err(DecodeError::InvalidTag);
        }
        let mut decoder = Decoder::new(&bytes[4..]);
        let request = decoder.bytes_ref()?;
        let call = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        if request.len() > super::sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            || call.len() > super::sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
            || package.len() > super::sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let ManagementRequest::Create(descriptor) =
            ManagementRequest::decode(request).map_err(|_| DecodeError::NonCanonical)?
        else {
            return Err(DecodeError::NonCanonical);
        };
        let call = AuthorityCredentialCall::decode(call).map_err(|_| DecodeError::NonCanonical)?;
        Self::new(*descriptor, call, package)
    }

    pub fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }

    pub fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AgentDescriptor,
        AuthorityCredentialCall,
        super::package_admission::AdmittedStateRuntimePackage,
    ) {
        (self.descriptor, self.call, self.runtime)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalLifecycleIngressError {
    Unavailable,
    Busy,
    Invalid,
}

impl std::fmt::Display for LocalLifecycleIngressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Local lifecycle ingress: {self:?}")
    }
}

impl std::error::Error for LocalLifecycleIngressError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalCreateDisposition {
    Created(AgentId, ManagementApplicationAck),
    Denied(LocalCreateDenial),
}

pub type LocalCreateResult =
    Result<LocalCreateDisposition, super::production_owner::AgentProductionOwnerError>;

pub(crate) struct PendingLocalCreate {
    pub descriptor: AgentDescriptor,
    pub call: AuthorityCredentialCall,
    pub runtime: AdmittedRuntimePackage,
    pub reply: mpsc::SyncSender<LocalCreateResult>,
}

pub type LocalInstallResult =
    Result<ManagementApplicationAck, super::production_owner::AgentProductionOwnerError>;

/// Terminal outcome of one exact ordinary Shared Install. A denial carries
/// the signed certificate for the caller's retained request; it is not an
/// application failure and installs nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharedInstallDisposition {
    Installed(ManagementApplicationAck),
    Denied(SharedInstallDenial),
}

pub type SharedCreateResult =
    Result<ManagementApplicationAck, super::production_owner::AgentProductionOwnerError>;
pub type SharedInstallResult =
    Result<SharedInstallDisposition, super::production_owner::AgentProductionOwnerError>;

pub(crate) enum PendingLocalLifecycle {
    PrepareAdmin {
        draft: super::sdk::authority::AuthorityAdminCall,
        reply: mpsc::SyncSender<AuthorityAdminPreparationResult>,
    },
    SubmitAdmin {
        call: super::sdk::authority::AuthorityAdminCall,
        preparation: super::clean_bootstrap::NativeAuthorityAdminPreparation,
        reply: mpsc::SyncSender<AuthorityAdminSubmissionResult>,
    },
    PrepareOperation {
        call: super::sdk::authority_operation::AuthorityOperationCall,
        reply: mpsc::SyncSender<AuthorityOperationPreparationResult>,
    },
    AuthorizeOperation {
        submission: AuthorityOperationSubmission,
        reply: mpsc::SyncSender<AuthorityOperationResult>,
    },
    Create(PendingLocalCreate),
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    CreateExternal {
        submission: LocalStateCreateSubmission,
        reply: mpsc::SyncSender<LocalCreateResult>,
    },
    Install {
        submission: LocalInstallSubmission,
        reply: mpsc::SyncSender<LocalInstallResult>,
    },
    CreateShared {
        submission: SharedCreateSubmission,
        reply: mpsc::SyncSender<SharedCreateResult>,
    },
    InstallShared {
        submission: SharedInstallSubmission,
        reply: mpsc::SyncSender<SharedInstallResult>,
    },
}

impl PendingLocalLifecycle {
    pub(crate) fn reject(self) {
        let error = super::production_owner::AgentProductionOwnerError::InvalidConfiguration;
        match self {
            Self::PrepareAdmin { reply, .. } => {
                let _ = reply.try_send(Err(SharedAgentHostError::Unavailable));
            }
            Self::SubmitAdmin { reply, .. } => {
                let _ = reply.try_send(Err(SharedAgentHostError::Unavailable));
            }
            Self::PrepareOperation { reply, .. } => {
                let _ = reply.try_send(Err(SharedAgentHostError::Unavailable));
            }
            Self::AuthorizeOperation { reply, .. } => {
                let _ = reply.try_send(Err(SharedAgentHostError::Unavailable));
            }
            Self::Create(request) => {
                let _ = request.reply.try_send(Err(error));
            }
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            Self::CreateExternal { reply, .. } => {
                let _ = reply.try_send(Err(error));
            }
            Self::Install { reply, .. } => {
                let _ = reply.try_send(Err(error));
            }
            Self::CreateShared { reply, .. } => {
                let _ = reply.try_send(Err(error));
            }
            Self::InstallShared { reply, .. } => {
                let _ = reply.try_send(Err(error));
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct LocalLifecycleQueue {
    channel: Mutex<
        Option<(
            mpsc::SyncSender<PendingLocalLifecycle>,
            mpsc::Receiver<PendingLocalLifecycle>,
        )>,
    >,
}

impl LocalLifecycleQueue {
    pub(crate) fn prepare_admin(
        &self,
        draft: super::sdk::authority::AuthorityAdminCall,
    ) -> Result<mpsc::Receiver<AuthorityAdminPreparationResult>, LocalLifecycleIngressError> {
        if draft.observed_slot != 0
            || draft
                .verify_with(&super::clean_bootstrap::RawCredentialVerifier)
                .is_err()
        {
            return Err(LocalLifecycleIngressError::Invalid);
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        self.enqueue_admin(PendingLocalLifecycle::PrepareAdmin { draft, reply })?;
        Ok(receiver)
    }

    pub(crate) fn submit_admin(
        &self,
        call: super::sdk::authority::AuthorityAdminCall,
        preparation: super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<mpsc::Receiver<AuthorityAdminSubmissionResult>, LocalLifecycleIngressError> {
        if !preparation.matches_call(&call) {
            return Err(LocalLifecycleIngressError::Invalid);
        }
        let (reply, receiver) = mpsc::sync_channel(1);
        self.enqueue_admin(PendingLocalLifecycle::SubmitAdmin {
            call,
            preparation,
            reply,
        })?;
        Ok(receiver)
    }

    fn enqueue_admin(
        &self,
        request: PendingLocalLifecycle,
    ) -> Result<(), LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        sender.try_send(request).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
            mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
        })
    }

    pub(crate) fn prepare_operation(
        &self,
        call: super::sdk::authority_operation::AuthorityOperationCall,
    ) -> Result<mpsc::Receiver<AuthorityOperationPreparationResult>, LocalLifecycleIngressError>
    {
        if call.authenticated_node().is_some()
            || call
                .verify_api_with(&super::authority_operation_coordinator::RawEd25519Verifier)
                .is_err()
        {
            return Err(LocalLifecycleIngressError::Invalid);
        }
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalLifecycle::PrepareOperation { call, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    pub(crate) fn submit_operation(
        &self,
        submission: AuthorityOperationSubmission,
    ) -> Result<mpsc::Receiver<AuthorityOperationResult>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalLifecycle::AuthorizeOperation { submission, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    pub(crate) fn open(&self) -> Result<(), LocalLifecycleIngressError> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        if channel.is_some() {
            return Err(LocalLifecycleIngressError::Busy);
        }
        *channel = Some(mpsc::sync_channel(LOCAL_LIFECYCLE_QUEUE_CAPACITY));
        Ok(())
    }

    pub(crate) fn submit(
        &self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<mpsc::Receiver<LocalCreateResult>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalLifecycle::Create(PendingLocalCreate {
                descriptor,
                call,
                runtime,
                reply,
            }))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn submit_external(
        &self,
        submission: LocalStateCreateSubmission,
    ) -> Result<mpsc::Receiver<LocalCreateResult>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalLifecycle::CreateExternal { submission, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    pub(crate) fn submit_install(
        &self,
        submission: LocalInstallSubmission,
    ) -> Result<mpsc::Receiver<LocalInstallResult>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let (sender, _) = channel
            .as_ref()
            .ok_or(LocalLifecycleIngressError::Unavailable)?;
        let (reply, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PendingLocalLifecycle::Install { submission, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => LocalLifecycleIngressError::Busy,
                mpsc::TrySendError::Disconnected(_) => LocalLifecycleIngressError::Unavailable,
            })?;
        Ok(receiver)
    }

    pub(crate) fn submit_shared_create(
        &self,
        submission: SharedCreateSubmission,
    ) -> Result<mpsc::Receiver<SharedCreateResult>, LocalLifecycleIngressError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.enqueue_admin(PendingLocalLifecycle::CreateShared { submission, reply })?;
        Ok(receiver)
    }

    pub(crate) fn submit_shared_install(
        &self,
        submission: SharedInstallSubmission,
    ) -> Result<mpsc::Receiver<SharedInstallResult>, LocalLifecycleIngressError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.enqueue_admin(PendingLocalLifecycle::InstallShared { submission, reply })?;
        Ok(receiver)
    }

    pub(crate) fn pop(&self) -> Result<Option<PendingLocalLifecycle>, LocalLifecycleIngressError> {
        let channel = self
            .channel
            .lock()
            .map_err(|_| LocalLifecycleIngressError::Unavailable)?;
        let Some((_, receiver)) = channel.as_ref() else {
            return Ok(None);
        };
        match receiver.try_recv() {
            Ok(request) => Ok(Some(request)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(LocalLifecycleIngressError::Unavailable),
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(mut channel) = self.channel.lock() {
            if let Some((_, receiver)) = channel.take() {
                for pending in receiver.try_iter() {
                    pending.reject();
                }
            }
        }
    }
}

/// Open the independent intent/issuer images and retained Create runtime under
/// the same exclusive lifecycle lease on every retry. Implementors derive paths
/// from the configured Space and Agent, never caller path strings.
pub trait LocalLifecycleStoreFactory {
    type Intent: super::clean_authority_issuer::CleanManagementRuntimeStore
        + super::clean_authority_issuer::CleanManagementActorStore;
    type Issuer: CleanManagementIssuerStore;
    type Error;

    /// Discover existing per-Agent store candidates for startup or admission
    /// capacity checks. Return a sorted, unique, bounded list; never truncate.
    /// Existing stores may remain leased: discovery must not open their
    /// images, acquire their leases or create new candidates.
    /// Names are not authority or evidence of pending work. The caller must
    /// open and independently verify every candidate's intent/issuer images.
    fn discover(&mut self, space: SpaceId, maximum: usize) -> Result<Vec<AgentId>, Self::Error>;

    /// Open a discovered store without recreating a missing Agent directory.
    /// Normal exclusive leasing and staged-image reconciliation still apply.
    fn open_existing(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error>;

    fn open(
        &mut self,
        space: SpaceId,
        agent: AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error>;
}

/// Verified request/storage scope retained before startup publishes routes.
/// Pending entries are not approvals or proof of physical application. Keeping
/// both stores alive preserves their exclusive leases through recovery setup.
pub struct LocalLifecycleRecovery<I: CleanManagementIssuerStore, J: CleanManagementIssuerStore> {
    authority: super::sdk::authority::AuthorityActorTarget,
    pub(crate) entries: Vec<LocalLifecycleRecoveryEntry<I, J>>,
}

/// Startup admission derived only from verified, still-leased lifecycle stores.
/// Covers completed work, issued receipts, and saved Create/Install
/// authorization. Issuer eligibility is not approval, and application must be
/// independently observed from the Local image before acknowledgement signing.
pub struct LocalLifecycleStartupAdmission {
    pub(crate) authority: super::sdk::authority::AuthorityActorTarget,
    order: Vec<usize>,
    pub(crate) retirements: Vec<[super::sdk::RuntimeWork; 2]>,
    pub(crate) pending: Vec<
        Vec<(
            super::clean_management_intent::ManagementJournalAnchor,
            super::sdk::RuntimeWork,
        )>,
    >,
}

impl LocalLifecycleStartupAdmission {
    pub(crate) fn is_empty(&self) -> bool {
        self.retirements.is_empty() && self.pending.is_empty()
    }
}

pub(crate) struct LocalLifecycleRecoveryEntry<
    I: CleanManagementIssuerStore,
    J: CleanManagementIssuerStore,
> {
    pub(crate) agent: AgentId,
    pub(crate) intent: super::clean_management_intent::CleanManagementIntentSlot<I>,
    pub(crate) issuer: super::clean_authority_issuer::DurableCleanManagementIssuer<J>,
    pub(crate) finalized: Option<SignedManagementTerminal>,
    pub(crate) observed: Option<SignedManagementTerminal>,
    pub(crate) issued: Option<super::sdk::authority::AuthorityReceipt>,
    pub(crate) unissued_authorization: bool,
}

impl<I: CleanManagementIssuerStore, J: CleanManagementIssuerStore> LocalLifecycleRecovery<I, J> {
    /// A fresh external root can contain a directory created just before a
    /// crash, or an exact state package durably staged before its signed
    /// Create intent. Neither state is an Agent. Retain all pledged entries;
    /// the later physical inventory still rejects any slot without one.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub fn discard_unpledged_external_staging(&mut self) -> Result<(), SharedAgentHostError>
    where
        I: super::clean_authority_issuer::CleanManagementRuntimeStore
            + super::clean_authority_issuer::CleanManagementActorStore
            + super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        for entry in &mut self.entries {
            if entry.intent.intent().is_some() {
                continue;
            }
            if entry.issuer.sequence_high_water() != 0
                || entry.issuer.acknowledged_through() != 0
                || entry.issuer.has_pending_decision()
                || entry.issuer.retained_decisions() != 0
                || entry.finalized.is_some()
                || entry.observed.is_some()
                || entry.issued.is_some()
                || entry.unissued_authorization
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            entry
                .intent
                .verify_unpledged_external_staging()
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        }
        self.entries.retain(|entry| entry.intent.intent().is_some());
        Ok(())
    }

    /// Match bounded external slot names to independently verified lifecycle
    /// stores before any startup route can be published. This is only candidate
    /// selection; each matched slot still needs its exact signed-intent lock,
    /// journal replay and physical application checks during recovery.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn external_slot_candidates(
        &self,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        node: super::sdk::NodeId,
        maximum: usize,
    ) -> Result<Vec<AgentId>, SharedAgentHostError> {
        if directory.space() != crate::service::SpaceId(self.authority.space.0)
            || directory.node() != crate::service::NodeId(node.0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        directory
            .discover_slots(maximum)
            .map_err(|error| match error {
                super::journal_store::JournalStoreError::LimitExceeded => {
                    SharedAgentHostError::CapacityExhausted
                }
                _ => SharedAgentHostError::Unavailable,
            })?
            .into_iter()
            .map(|agent| {
                let agent = AgentId(agent.0);
                let index = self
                    .entries
                    .binary_search_by_key(&agent, |entry| entry.agent)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if self.entries[index].intent.intent().is_none() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Ok(agent)
            })
            .collect()
    }

    /// Fail closed over the complete fresh external root before route
    /// publication. A saved authorization already owns a stable lock; a
    /// finalized Create or any later Install also needs its immutable Create
    /// archive. This is candidate admission only, not physical replay or
    /// proof that the selected Authority finalized the archived operation.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn external_startup_inventory(
        &mut self,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        node: super::sdk::NodeId,
        maximum: usize,
    ) -> Result<Vec<AgentId>, SharedAgentHostError>
    where
        I: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        use super::external_local_executor::ExternalLocalCreateArchive;
        if self.entries.len() > maximum {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let physical = self.external_slot_candidates(directory, node, maximum)?;
        for entry in &mut self.entries {
            let has_slot = physical.binary_search(&entry.agent).is_ok();
            let retired = entry
                .intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let denied = entry
                .intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let archived = entry
                .intent
                .load_external_create_archive()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let current = entry
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?
                .clone();
            if let Some(pending) = entry
                .intent
                .load_external_pending_install()
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            {
                let future = external_pending_install_intent(&pending, self.authority)?;
                if future.call().managed != current.call().managed
                    || future.call().managed.agent != entry.agent
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                if future.request() != current.request() || future.call() != current.call() {
                    if !retired
                        || !entry
                            .issuer
                            .can_resume_install(
                                self.authority,
                                future.call().managed,
                                future.request(),
                                future.call(),
                                &super::clean_bootstrap::RawCredentialVerifier,
                            )
                            .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                    {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                } else if !matches!(current.request(), ManagementRequest::Install(_)) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            match current.request() {
                ManagementRequest::Create(_) => {
                    let authorized = entry
                        .intent
                        .authorization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some();
                    if authorized && !has_slot {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    // Issuer finality precedes archive persistence. An
                    // unretired Create must reach authenticated recovery,
                    // which reopens its original generation and rebuilds the
                    // archive before retirement or route attachment.
                    if retired && !denied && archived.is_none() {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                }
                ManagementRequest::Install(_) => {
                    if !has_slot || archived.is_none() || denied {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                }
                _ => return Err(SharedAgentHostError::ScopeMismatch),
            }
            if let Some(bytes) = archived {
                if denied || !has_slot {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let archive = ExternalLocalCreateArchive::decode(&bytes)
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                if !archive.matches_current_scope(&current, self.authority, node) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        Ok(physical)
    }

    /// Reopen all archived, physically finalized external generations under
    /// their original stable locks. Pending Creates without an archive remain
    /// in the retained lifecycle set for normal authorization/application
    /// recovery. The returned owners are deliberately not route attachments:
    /// the caller must still authenticate system finality and complete every
    /// pending lifecycle operation before admitting any external route.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn open_external_finalized_owners(
        &mut self,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        node: super::sdk::NodeId,
        maximum: usize,
        budget: &mut super::sdk::state_blocks::ReadBudget,
    ) -> Result<
        BTreeMap<AgentId, super::external_local_executor::ExternalLocalJournalOwner>,
        SharedAgentHostError,
    >
    where
        I: super::clean_authority_issuer::CleanManagementRuntimeStore
            + super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        use super::external_local_executor::ExternalLocalCreateArchive;
        self.external_startup_inventory(directory, node, maximum)?;
        let mut owners = BTreeMap::new();
        for entry in &mut self.entries {
            let Some(archive_bytes) = entry
                .intent
                .load_external_create_archive()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                continue;
            };
            let archive = ExternalLocalCreateArchive::decode(&archive_bytes)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            if !archive.matches_current_scope(
                entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?,
                self.authority,
                node,
            ) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let runtime = entry
                .intent
                .load_runtime()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::Unavailable)?;
            let owner = archive.open_existing(runtime, self.authority, node, directory, budget)?;
            if owner.descriptor().identity.agent != entry.agent
                || owners.insert(entry.agent, owner).is_some()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        Ok(owners)
    }

    /// Return serving candidates only when every external lifecycle entry is
    /// already terminal and its signed issuer finality matches the physical
    /// file generation. This is a fail-closed checkpoint for explicit fresh-
    /// root startup, not recovery of an interrupted lifecycle: pending work
    /// must be completed under startup admission before this gate can pass.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn external_finalized_startup_owners(
        &mut self,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        node: super::sdk::NodeId,
        maximum: usize,
        budget: &mut super::sdk::state_blocks::ReadBudget,
    ) -> Result<
        BTreeMap<AgentId, super::external_local_executor::ExternalLocalJournalOwner>,
        SharedAgentHostError,
    >
    where
        I: super::clean_authority_issuer::CleanManagementRuntimeStore
            + super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        let owners = self.open_external_finalized_owners(directory, node, maximum, budget)?;
        for entry in &self.entries {
            if entry
                .intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                if owners.contains_key(&entry.agent) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let intent = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                if !matches!(intent.request(), ManagementRequest::Create(_)) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let slot = directory
                    .acquire_existing(
                        crate::service::AgentId(entry.agent.0),
                        super::external_local_executor::external_local_create_intent_hash(intent),
                    )
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                slot.verify_absent()
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                continue;
            }
            if entry.unissued_authorization
                || !entry
                    .intent
                    .retirement_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                return Err(SharedAgentHostError::Conflict);
            }
            let intent = entry
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let (receipt, terminal) = entry
                .issuer
                .recover_finalized_terminal(
                    self.authority,
                    intent.call().managed,
                    intent.request(),
                    intent.call(),
                    &super::clean_bootstrap::RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                .ok_or(SharedAgentHostError::Conflict)?;
            if entry.finalized.as_ref() != Some(&terminal)
                || entry
                    .observed
                    .as_ref()
                    .is_some_and(|observed| observed != &terminal)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let owner = owners
                .get(&entry.agent)
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let physical = match (intent.request(), &terminal) {
                (
                    ManagementRequest::Create(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Applied(ack),
                ) => owner.verify_finalized_create_ack(ack),
                (
                    ManagementRequest::Install(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Applied(ack),
                ) => owner.verify_finalized_install_ack(intent.request(), &receipt, ack),
                (
                    ManagementRequest::Install(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Rejected(failure),
                ) => owner.verify_finalized_install_failure(intent.request(), &receipt, failure),
                _ => return Err(SharedAgentHostError::ScopeMismatch),
            };
            physical.map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        }
        Ok(owners)
    }

    /// Complete the retained external Local lifecycle set before any route
    /// attachment. The system owner must already have been opened with this
    /// recovery set's startup admission, preserving all pending journal
    /// anchors. Each operation uses its original signed request, package
    /// sidecar and stable file slot. A failed/ambiguous phase leaves leases
    /// with this recovery object; the caller must drop it and rediscover from
    /// durable stores rather than continuing on possibly poisoned handles.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_external_pending<P, R, K, S>(
        &mut self,
        system: &mut CleanSystemAgentBootstrapOwner<P, R, K>,
        directory: &super::journal_store::ExternalLocalJournalDirectory,
        node: super::sdk::NodeId,
        maximum: usize,
        budget: &mut super::sdk::state_blocks::ReadBudget,
        signer: &mut S,
    ) -> Result<
        BTreeMap<AgentId, super::external_local_executor::ExternalLocalJournalOwner>,
        SharedAgentHostError,
    >
    where
        P: CleanSystemAgentBootstrapStore,
        R: CleanSystemAgentBootstrapStore,
        K: CleanManagementIssuerStore,
        I: super::clean_authority_issuer::CleanManagementRuntimeStore
            + super::clean_authority_issuer::CleanManagementActorStore
            + super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
        S: CleanManagementReceiptSigner,
    {
        use super::external_local_executor::{
            ExternalLocalCreateArchive, external_local_create_intent_hash,
        };

        if self.authority != system.authority_target()
            || directory.space() != crate::service::SpaceId(self.authority.space.0)
            || directory.node() != crate::service::NodeId(node.0)
            || system.pins().node() != node
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.external_startup_inventory(directory, node, maximum)?;
        self.startup_admission()?;
        let mut order = (0..self.entries.len()).collect::<Vec<_>>();
        order.sort_unstable_by_key(|index| {
            let call = self.entries[*index]
                .intent
                .intent()
                .expect("verified lifecycle entry has a signed intent")
                .call();
            (call.credential, call.request_sequence.get())
        });
        for index in order {
            let entry = &mut self.entries[index];
            if entry
                .intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            let intent = entry
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?
                .clone();
            match intent.request() {
                ManagementRequest::Create(_) => {
                    let existing_required = entry
                        .intent
                        .authorization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .is_some()
                        || entry
                            .intent
                            .retirement_complete()
                            .map_err(|_| SharedAgentHostError::Unavailable)?;
                    let physical = if existing_required {
                        directory.acquire_existing(
                            crate::service::AgentId(entry.agent.0),
                            external_local_create_intent_hash(&intent),
                        )
                    } else {
                        directory.acquire(
                            crate::service::AgentId(entry.agent.0),
                            external_local_create_intent_hash(&intent),
                        )
                    }
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                    if system.finish_denied_external_local_intent(
                        &mut entry.intent,
                        &entry.issuer,
                        &physical,
                        signer,
                    )? {
                        entry.unissued_authorization = false;
                        continue;
                    }
                    drop(physical);
                    let bytes = entry
                        .intent
                        .load_runtime()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::Unavailable)?;
                    let runtime = super::package_admission::admit_state_runtime_package(&bytes)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                    let (agent, acknowledgement, owner) = system
                        .create_external_local_agent_on_slots(
                            &mut entry.intent,
                            &mut entry.issuer,
                            intent,
                            runtime,
                            directory,
                            budget,
                            signer,
                        )?;
                    if agent != entry.agent || entry.finalized.as_ref().is_some_and(|saved| {
                        saved
                            != &super::clean_authority_issuer::SignedManagementTerminal::Applied(
                                acknowledgement.clone(),
                            )
                    }) {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    entry.issued = Some(acknowledgement.receipt.clone());
                    entry.observed = Some(
                        super::clean_authority_issuer::SignedManagementTerminal::Applied(
                            acknowledgement.clone(),
                        ),
                    );
                    entry.finalized = Some(
                        super::clean_authority_issuer::SignedManagementTerminal::Applied(
                            acknowledgement,
                        ),
                    );
                    entry.unissued_authorization = false;
                    drop(owner);
                }
                ManagementRequest::Install(_) => {
                    let archive = entry
                        .intent
                        .load_external_create_archive()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)
                        .and_then(|bytes| {
                            ExternalLocalCreateArchive::decode(&bytes)
                                .map_err(|_| SharedAgentHostError::ScopeMismatch)
                        })?;
                    let runtime = entry
                        .intent
                        .load_runtime()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::Unavailable)?;
                    let mut owner =
                        archive.open_existing(runtime, self.authority, node, directory, budget)?;
                    if let Some(pending) = entry
                        .intent
                        .load_external_pending_install()
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                    {
                        let staged = external_pending_install_intent(&pending, self.authority)?;
                        if staged.request() == intent.request() && staged.call() == intent.call() {
                            // This is the only recoverable pre-sidecar window:
                            // no authorization can precede the actor commit.
                            entry
                                .intent
                                .retain_actor(pending.package())
                                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                        }
                    }
                    let package = entry
                        .intent
                        .load_actor()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::Unavailable)?;
                    let terminal = system.install_external_local_on_slots(
                        &mut entry.intent,
                        &mut entry.issuer,
                        &mut owner,
                        &package,
                        budget,
                        signer,
                    )?;
                    if entry
                        .finalized
                        .as_ref()
                        .is_some_and(|saved| saved != &terminal)
                    {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    }
                    if entry.finalized.is_none() {
                        match &terminal {
                            super::clean_authority_issuer::SignedManagementTerminal::Applied(
                                ack,
                            ) => {
                                system.finalize_management_intent_with_admission(
                                    &mut entry.intent,
                                    intent.call().managed,
                                    ack,
                                    &mut entry.issuer,
                                    true,
                                )?;
                            }
                            super::clean_authority_issuer::SignedManagementTerminal::Rejected(
                                failure,
                            ) => {
                                system.finalize_failed_install_with_admission(
                                    &mut entry.intent,
                                    intent.call().managed,
                                    failure,
                                    &mut entry.issuer,
                                    true,
                                )?;
                            }
                        }
                    }
                    match &terminal {
                        super::clean_authority_issuer::SignedManagementTerminal::Applied(ack) => {
                            system.finish_live_management_intent(
                                &mut entry.intent,
                                intent.call().managed,
                                ack,
                                &entry.issuer,
                            )?;
                        }
                        super::clean_authority_issuer::SignedManagementTerminal::Rejected(
                            failure,
                        ) => {
                            system.finish_live_failed_install(
                                &mut entry.intent,
                                intent.call().managed,
                                failure,
                                &entry.issuer,
                            )?;
                        }
                    }
                    entry.issued = Some(terminal.receipt().clone());
                    entry.observed = Some(terminal.clone());
                    entry.finalized = Some(terminal);
                    entry.unissued_authorization = false;
                }
                _ => return Err(SharedAgentHostError::ScopeMismatch),
            }
        }
        // Reopen every file generation after the last lifecycle mutation;
        // route readiness cannot inherit an in-memory candidate cursor.
        self.external_finalized_startup_owners(directory, node, maximum, budget)
    }

    pub fn startup_admission(
        &self,
    ) -> Result<LocalLifecycleStartupAdmission, SharedAgentHostError> {
        let mut retirements = Vec::new();
        let mut pending = Vec::new();
        let mut credentials = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry
                .intent
                .denial_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            let retired = entry
                .intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if let Some(intent) = entry.intent.intent() {
                credentials.push(RecoveryOrderEntry {
                    index,
                    credential: intent.call().credential,
                    sequence: intent.call().request_sequence.get(),
                    needs_authorization: entry.unissued_authorization,
                    needs_finalization_preparation: !retired
                        && entry
                            .intent
                            .finalization_work()
                            .map_err(|_| SharedAgentHostError::Unavailable)?
                            .is_none(),
                    ready: retired || entry.issued.is_some() || entry.unissued_authorization,
                });
            }
            if retired {
                continue;
            }
            let authorization = entry
                .intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let finalization = entry
                .intent
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            match (authorization, finalization, &entry.finalized) {
                (None, None, None)
                    if !entry.issuer.has_pending_decision()
                        && entry.issuer.retained_decisions() == 0
                        && ((entry.issuer.sequence_high_water() == 0
                            && entry.intent.intent().is_none_or(|intent| {
                                matches!(intent.request(), ManagementRequest::Create(_))
                            }))
                            || {
                                let intent = entry
                                    .intent
                                    .intent()
                                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                                entry
                                    .issuer
                                    .can_resume_install(
                                        self.authority,
                                        intent.call().managed,
                                        intent.request(),
                                        intent.call(),
                                        &super::clean_bootstrap::RawCredentialVerifier,
                                    )
                                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                            }) => {}
                (Some(authorization), Some(finalization), Some(_)) => {
                    retirements.push([authorization.clone(), finalization.clone()]);
                }
                (Some(authorization), finalization, None)
                    if entry.issued.is_some() || entry.unissued_authorization =>
                {
                    let authorization_anchor = entry
                        .intent
                        .authorization_anchor()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    let mut group = vec![(authorization_anchor.clone(), authorization.clone())];
                    if let Some(finalization) = finalization {
                        let finalization_anchor = entry
                            .intent
                            .finalization_anchor()
                            .map_err(|_| SharedAgentHostError::Unavailable)?
                            .ok_or(SharedAgentHostError::ScopeMismatch)?;
                        group.push((finalization_anchor.clone(), finalization.clone()));
                    }
                    pending.push(group);
                }
                // Earlier phases still need protected phase extension; never
                // expose traffic or checkpoint away their retained anchors.
                _ => return Err(SharedAgentHostError::Conflict),
            }
        }
        let mut order = ordered_authorization_recovery(credentials)?;
        let successors: BTreeMap<_, _> = self
            .entries
            .iter()
            .filter(|entry| entry.unissued_authorization)
            .map(|entry| {
                let call = entry
                    .intent
                    .intent()
                    .expect("validated unissued intent")
                    .call();
                (call.credential, call.request_sequence.get())
            })
            .collect();
        // Only already-issued predecessors need early retirement. Independent
        // unissued calls retain the existing all-authorizations-first pipeline.
        order.retain(|index| {
            let entry = &self.entries[*index];
            let call = entry.intent.intent().expect("ordered intent").call();
            entry.issued.is_some()
                && !entry.intent.retirement_complete().unwrap_or(false)
                && successors
                    .get(&call.credential)
                    .is_some_and(|sequence| call.request_sequence.get() < *sequence)
        });
        let saved_slot = |index: usize, finalization: bool| -> Result<u64, SharedAgentHostError> {
            let slot = &self.entries[index].intent;
            let work = if finalization {
                slot.finalization_work()
            } else {
                slot.authorization_work()
            }
            .map_err(|_| SharedAgentHostError::Unavailable)?;
            match work {
                Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) => Ok(*observed_slot),
                _ => Err(SharedAgentHostError::ScopeMismatch),
            }
        };
        let mut predecessors = order
            .into_iter()
            .map(|index| Ok((saved_slot(index, true)?, index)))
            .collect::<Result<Vec<_>, SharedAgentHostError>>()?;
        // Stable ties preserve the per-credential order validated above.
        predecessors.sort_by_key(|(slot, _)| *slot);
        let earliest_authorization = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.unissued_authorization)
            .map(|(index, _)| saved_slot(index, false))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min();
        if predecessors
            .last()
            .zip(earliest_authorization)
            .is_some_and(|((slot, _), authorization)| *slot > authorization)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let order = predecessors.into_iter().map(|(_, index)| index).collect();
        Ok(LocalLifecycleStartupAdmission {
            authority: self.authority,
            order,
            retirements,
            pending,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct RecoveryOrderEntry {
    index: usize,
    credential: super::sdk::CredentialId,
    sequence: u64,
    needs_authorization: bool,
    needs_finalization_preparation: bool,
    ready: bool,
}

/// Sort by signed credential sequence, never by the Agent directory name.
/// Ambiguous sequence reuse and overtaking a known client-only predecessor
/// reject before attachment. Authority replay remains the approval boundary.
fn ordered_authorization_recovery(
    mut calls: Vec<RecoveryOrderEntry>,
) -> Result<Vec<usize>, SharedAgentHostError> {
    calls.sort_unstable_by_key(|call| (call.credential, call.sequence));
    let mut previous = None;
    let mut waiting_for_client = false;
    let mut needs_fresh_clock = false;
    let mut order = Vec::with_capacity(calls.len());
    for call in calls {
        if call.sequence == 0 || previous == Some((call.credential, call.sequence)) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if previous.is_none_or(|(credential, _)| credential != call.credential) {
            waiting_for_client = false;
            needs_fresh_clock = false;
        }
        // A fresh predecessor finalization can advance the runtime clock past
        // its successor's immutable authorization envelope. Until live capture
        // prevents that overlap, reject this set before executing either call.
        if (waiting_for_client || needs_fresh_clock) && call.needs_authorization {
            return Err(SharedAgentHostError::Conflict);
        }
        waiting_for_client |= !call.ready;
        needs_fresh_clock |= call.needs_finalization_preparation;
        previous = Some((call.credential, call.sequence));
        order.push(call.index);
    }
    Ok(order)
}

#[test]
fn unissued_recovery_orders_credentials_and_rejects_ambiguous_predecessors() {
    let a = super::sdk::CredentialId([1; 32]);
    let b = super::sdk::CredentialId([2; 32]);
    let call = |index, credential, sequence, ready| RecoveryOrderEntry {
        index,
        credential,
        sequence,
        needs_authorization: ready,
        needs_finalization_preparation: false,
        ready,
    };
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, a, 2, true), call(1, a, 1, true)]).unwrap(),
        vec![1, 0]
    );
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, b, 1, true), call(1, a, 1, true)]).unwrap(),
        vec![1, 0]
    );
    assert!(matches!(
        ordered_authorization_recovery(vec![call(0, a, 1, true), call(1, a, 1, true)]),
        Err(SharedAgentHostError::ScopeMismatch)
    ));
    assert!(matches!(
        ordered_authorization_recovery(vec![call(0, a, 2, true), call(1, a, 1, false)]),
        Err(SharedAgentHostError::Conflict)
    ));
    assert_eq!(
        ordered_authorization_recovery(vec![call(0, a, 1, true), call(1, a, 2, false)]).unwrap(),
        vec![0, 1]
    );
    let mut predecessor = call(0, a, 1, true);
    predecessor.needs_finalization_preparation = true;
    assert!(matches!(
        ordered_authorization_recovery(vec![predecessor, call(1, a, 2, true)]),
        Err(SharedAgentHostError::Conflict)
    ));
}

/// Load every discovered candidate through existing-only stores before ingress
/// starts. The Authority target must come from independently selected bootstrap
/// pins, not from a candidate's own signed request. This function never invokes
/// policy, signs receipts, retires results, or publishes a route.
pub fn discover_local_lifecycle_recovery<F: LocalLifecycleStoreFactory>(
    factory: &mut F,
    authority: super::sdk::authority::AuthorityActorTarget,
    maximum: usize,
) -> Result<LocalLifecycleRecovery<F::Intent, F::Issuer>, SharedAgentHostError> {
    use super::clean_authority_issuer::DurableCleanManagementIssuer;
    use super::clean_bootstrap::RawCredentialVerifier;
    use super::clean_management_intent::CleanManagementIntentSlot;
    if !authority.is_valid() {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let candidates = factory
        .discover(authority.space, maximum)
        .map_err(|_| SharedAgentHostError::Unavailable)?;
    if candidates.len() > maximum
        || candidates.iter().any(|agent| *agent == AgentId::ZERO)
        || candidates.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut entries = Vec::with_capacity(candidates.len());
    for agent in candidates {
        let (intent_store, issuer_store) = factory
            .open_existing(authority.space, agent)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let intent = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some(request) = intent.intent() {
            let managed = request.call().managed;
            if managed.space != authority.space
                || managed.agent != agent
                || managed.profile != AgentProfile::Local
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            request
                .verify(authority, managed, &RawCredentialVerifier)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        }
        let issuer = DurableCleanManagementIssuer::open(
            issuer_store,
            authority.binding,
            authority.space,
            agent,
        )
        .map_err(|_| SharedAgentHostError::Unavailable)?;
        let finalized = if let Some(request) = intent.intent() {
            let recovered = issuer
                .recover_finalized_terminal(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let final_work = intent
                .finalization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if final_work.is_some() && issuer.sequence_high_water() == 0 {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if let Some((_, terminal)) = recovered {
                // A different outstanding issuance cannot be hidden behind
                // the previous finalized acknowledgement during startup.
                if issuer.has_pending_decision()
                    || issuer.retained_decisions() != 0
                    || issuer.sequence_high_water() != issuer.acknowledged_through()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                let Some(super::sdk::RuntimeWork::Invoke { invocation, .. }) = final_work else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) = intent
                    .authorization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                if terminal.applied_at() < *observed_slot
                    || invocation.message != terminal.finalization_message()
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                Some(terminal)
            } else {
                if intent
                    .retirement_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                None
            }
        } else {
            if issuer.sequence_high_water() != 0
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            None
        };
        let observed = if let Some(request) = intent.intent() {
            issuer
                .recover_observed_terminal(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                .map(|(_, terminal)| terminal)
        } else {
            None
        };
        if observed.is_some()
            && (issuer.has_pending_decision()
                || issuer.retained_decisions() != 0
                || issuer.sequence_high_water() != issuer.acknowledged_through())
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(super::sdk::RuntimeWork::Invoke { invocation, .. }) = intent
            .finalization_work()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            let terminal = observed
                .as_ref()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let Some(super::sdk::RuntimeWork::Invoke { observed_slot, .. }) = intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if terminal.applied_at() < *observed_slot
                || invocation.message != terminal.finalization_message()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let issued = if let Some(request) = intent.intent() {
            issuer
                .recover_issued_application(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
        } else {
            None
        };
        if observed.is_some() && issued.is_none() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let denied = intent
            .denial_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if denied
            && (issuer.sequence_high_water() != 0
                || issuer.has_pending_decision()
                || issuer.retained_decisions() != 0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let unissued_authorization = if !denied
            && issued.is_none()
            && intent
                .authorization_work()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .is_some()
        {
            let request = intent.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            let eligible = if matches!(request.request(), ManagementRequest::Install(_)) {
                issuer.can_resume_install(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
            } else {
                issuer.can_resume_initial_creation(
                    authority,
                    request.call().managed,
                    request.request(),
                    request.call(),
                    &RawCredentialVerifier,
                )
            };
            eligible.map_err(|_| SharedAgentHostError::ScopeMismatch)?
        } else {
            false
        };
        entries.push(LocalLifecycleRecoveryEntry {
            agent,
            intent,
            issuer,
            finalized,
            observed,
            issued,
            unissued_authorization,
        });
    }
    Ok(LocalLifecycleRecovery { authority, entries })
}

fn load_create_runtime<B: super::clean_authority_issuer::CleanManagementRuntimeStore>(
    intent: &mut super::clean_management_intent::CleanManagementIntentSlot<B>,
) -> Result<AdmittedRuntimePackage, SharedAgentHostError> {
    let bytes = intent
        .load_runtime()
        .map_err(|_| SharedAgentHostError::Unavailable)?
        .ok_or(SharedAgentHostError::Unavailable)?;
    let runtime = super::package_admission::admit_runtime_package(&bytes)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    let ManagementRequest::Create(descriptor) = intent
        .intent()
        .ok_or(SharedAgentHostError::ScopeMismatch)?
        .request()
    else {
        return Err(SharedAgentHostError::ScopeMismatch);
    };
    super::driver::verify_clean_runtime_package_binding(descriptor, &runtime)
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
    Ok(runtime)
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
fn external_pending_install_intent(
    submission: &LocalInstallSubmission,
    authority: super::sdk::authority::AuthorityActorTarget,
) -> Result<super::clean_management_intent::CleanManagementIntent, SharedAgentHostError> {
    let call = submission.call();
    super::clean_management_intent::CleanManagementIntent::new(
        authority,
        call.managed,
        ManagementRequest::Install(Box::new(submission.install().clone())),
        call.clone(),
        &super::clean_bootstrap::RawCredentialVerifier,
    )
    .map_err(|_| SharedAgentHostError::ScopeMismatch)
}

/// Type-erased, node-owned lifecycle access. It is deliberately not an ingress
/// trait: only the production owner may coordinate creation and publication.
pub(crate) trait NativeLocalLifecycle: Send {
    fn prepare_admin(
        &mut self,
        _draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> AuthorityAdminPreparationResult {
        Err(SharedAgentHostError::Unavailable)
    }
    fn submit_admin(
        &mut self,
        _call: &super::sdk::authority::AuthorityAdminCall,
        _preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> AuthorityAdminSubmissionResult {
        Err(SharedAgentHostError::Unavailable)
    }
    fn retains_admin(
        &mut self,
        _call: &super::sdk::authority::AuthorityAdminCall,
        _preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<bool, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn retains_operation(
        &mut self,
        _call: &super::sdk::authority_operation::AuthorityOperationCall,
        _context: Option<&super::sdk::InvocationContext>,
    ) -> Result<bool, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn management_admission_held(&self) -> Result<bool, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn prepare_operation(
        &mut self,
        _call: &super::sdk::authority_operation::AuthorityOperationCall,
    ) -> AuthorityOperationPreparationResult {
        Err(SharedAgentHostError::Unavailable)
    }
    fn authorize_operation(
        &mut self,
        _call: &super::sdk::authority_operation::AuthorityOperationCall,
        _context: super::sdk::InvocationContext,
        _issued_at: u64,
    ) -> Result<super::clean_bootstrap::NativeAuthorityOperationDecision, SharedAgentHostError>
    {
        Err(SharedAgentHostError::Unavailable)
    }
    /// Only a retained, signed completion may turn a failed Create into a
    /// terminal denial. Other implementations conservatively retain the error.
    fn retained_denial(
        &mut self,
        _submission: &LocalCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        Ok(None)
    }
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn retained_state_denial(
        &mut self,
        _submission: &LocalStateCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        Ok(None)
    }
    fn node(&self) -> Result<super::sdk::NodeId, SharedAgentHostError>;
    fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>;
    fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>;
    fn local_agents(&self) -> Result<Option<Vec<AgentId>>, AgentRouteAdapterError> {
        Ok(None)
    }
    fn shared_generations(
        &self,
    ) -> Result<
        Option<Vec<crate::network::shared_agent::SharedAgentRouteHandle>>,
        SharedAgentHostError,
    > {
        Ok(None)
    }
    fn local_attachment_for_agent(
        &self,
        _agent: AgentId,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        Err(AgentRouteAdapterError::NoReadyRoutes)
    }
    fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError>;
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn create_external(
        &mut self,
        _submission: LocalStateCreateSubmission,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn install(
        &mut self,
        _install: super::sdk::InstallActor,
        _call: AuthorityCredentialCall,
        _package: super::package_admission::AdmittedActorPackage,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn create_shared(
        &mut self,
        _submission: SharedCreateSubmission,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
    fn install_shared(
        &mut self,
        _submission: SharedInstallSubmission,
    ) -> Result<SharedInstallDisposition, SharedAgentHostError> {
        Err(SharedAgentHostError::Unavailable)
    }
}

/// Signs one prepared ordinary Shared genesis candidate with credentials this
/// node is configured to hold, retaining each signature durably before it is
/// returned. Endorsement is not publication, finality or route permission;
/// the owner still selects quorum evidence and verifies its publication.
pub trait SharedGenesisEndorser: Send {
    fn endorse(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        prepared: &super::clean_bootstrap::PreparedSharedGenesisEndorsement,
    ) -> Result<Vec<super::committee::AuthoritySignature>, SharedAgentHostError>;
}

impl<F> SharedGenesisEndorser for F
where
    F: FnMut(
            super::genesis::AgentGenesisLocator,
            &super::clean_bootstrap::PreparedSharedGenesisEndorsement,
        ) -> Result<Vec<super::committee::AuthoritySignature>, SharedAgentHostError>
        + Send,
{
    fn endorse(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        prepared: &super::clean_bootstrap::PreparedSharedGenesisEndorsement,
    ) -> Result<Vec<super::committee::AuthoritySignature>, SharedAgentHostError> {
        self(locator, prepared)
    }
}

// Image-only builds do not inherit a storage-format requirement from the
// opt-in external method. Feature-on lifecycle factories must retain the
// immutable Create archive if their controller is type-erased for production.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
pub trait NativeExternalIntentStore:
    super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
{
}
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl<T: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore>
    NativeExternalIntentStore for T
{
}
#[cfg(not(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
)))]
pub trait NativeExternalIntentStore {}
#[cfg(not(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
)))]
impl<T> NativeExternalIntentStore for T {}

impl<P, R, I, F, S> NativeLocalLifecycle for LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    F: LocalLifecycleStoreFactory + Send,
    F::Intent: Send + NativeExternalIntentStore,
    F::Issuer: Send,
    S: CleanManagementReceiptSigner + Send,
{
    fn prepare_admin(
        &mut self,
        draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> AuthorityAdminPreparationResult {
        LocalLifecycleController::prepare_admin(self, draft)
    }
    fn submit_admin(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> AuthorityAdminSubmissionResult {
        LocalLifecycleController::submit_admin(self, call, preparation)
    }
    fn retains_admin(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<bool, SharedAgentHostError> {
        self.admins
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?
            .retains(call, preparation)
    }
    fn authorize_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: super::sdk::InvocationContext,
        issued_at: u64,
    ) -> Result<super::clean_bootstrap::NativeAuthorityOperationDecision, SharedAgentHostError>
    {
        LocalLifecycleController::authorize_operation(self, call, context, issued_at)
    }
    fn prepare_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
    ) -> AuthorityOperationPreparationResult {
        LocalLifecycleController::prepare_operation(self, call)
    }
    fn retains_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: Option<&super::sdk::InvocationContext>,
    ) -> Result<bool, SharedAgentHostError> {
        self.operations
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?
            .retains_call(call, context)
    }
    fn management_admission_held(&self) -> Result<bool, SharedAgentHostError> {
        self.system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .management_admission_held()
    }
    fn node(&self) -> Result<super::sdk::NodeId, SharedAgentHostError> {
        Ok(self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .pins()
            .node())
    }
    fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        LocalLifecycleController::system_attachment(self, capacity)
    }
    fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        LocalLifecycleController::local_attachment(self, capacity)
    }
    fn local_agents(&self) -> Result<Option<Vec<AgentId>>, AgentRouteAdapterError> {
        match &self.local {
            LocalBacking::Image(local) => local
                .lock()
                .map_err(|_| {
                    AgentRouteAdapterError::Route(super::supervisor::AgentRouteError::Unavailable)
                })?
                .list()
                .map(Some)
                .map_err(|_| {
                    AgentRouteAdapterError::Route(super::supervisor::AgentRouteError::Unavailable)
                }),
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { owners, .. } => Ok(Some(owners.keys().copied().collect())),
        }
    }
    fn local_attachment_for_agent(
        &self,
        agent: AgentId,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        match &self.local {
            LocalBacking::Image(local) => {
                super::supervisor_adapters::local_agent_supervisor_attachment_for_agent(
                    local.clone(),
                    agent,
                )
            }
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { owners, clock, .. } => {
                super::supervisor_adapters::external_local_agent_supervisor_attachment_for_agent(
                    owners
                        .get(&agent)
                        .ok_or(AgentRouteAdapterError::NoReadyRoutes)?
                        .clone(),
                    clock.clone(),
                )
            }
        }
    }

    fn shared_generations(
        &self,
    ) -> Result<
        Option<Vec<crate::network::shared_agent::SharedAgentRouteHandle>>,
        SharedAgentHostError,
    > {
        self.system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ordinary_supervisor_generations()
            .map(Some)
    }
    fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        LocalLifecycleController::create(self, descriptor, call, runtime)
    }

    fn create_shared(
        &mut self,
        submission: SharedCreateSubmission,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        LocalLifecycleController::create_shared(self, submission)
    }

    fn install_shared(
        &mut self,
        submission: SharedInstallSubmission,
    ) -> Result<SharedInstallDisposition, SharedAgentHostError> {
        LocalLifecycleController::install_shared(self, submission)
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn create_external(
        &mut self,
        submission: LocalStateCreateSubmission,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        LocalLifecycleController::create_external(
            self,
            submission,
            &mut super::sdk::state_blocks::ReadBudget::new(1_000_000, 1_000_000_000),
        )
    }

    fn install(
        &mut self,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: super::package_admission::AdmittedActorPackage,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        LocalLifecycleController::install(self, install, call, package)
    }

    fn retained_denial(
        &mut self,
        submission: &LocalCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        let system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if submission.call.authority != system.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let Some((intent, _)) = self
            .retained_stores
            .get_mut(&submission.descriptor.identity.agent)
        else {
            return Ok(None);
        };
        let Some(bytes) = intent
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if !bytes.starts_with(b"CND1") {
            return Ok(None);
        }
        submission
            .verify_denial(&bytes)
            .map(Some)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn retained_state_denial(
        &mut self,
        submission: &LocalStateCreateSubmission,
    ) -> Result<Option<LocalCreateDenial>, SharedAgentHostError> {
        let system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if submission.call().authority != system.authority_target() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let Some((intent, _)) = self
            .retained_stores
            .get_mut(&submission.descriptor().identity.agent)
        else {
            return Ok(None);
        };
        let Some(bytes) = intent
            .load()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        else {
            return Ok(None);
        };
        if !bytes.starts_with(b"CND1") {
            return Ok(None);
        }
        submission
            .verify_denial(&bytes)
            .map(Some)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)
    }
}

/// Type-erased admin storage/signing retained with the native owner.
trait NativeAuthorityAdminAccess<P, R, I>: Send
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    fn retains(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<bool, SharedAgentHostError>;
    fn prepare(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<super::clean_bootstrap::NativeAuthorityAdminPreparation, SharedAgentHostError>;
    fn submit(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> AuthorityAdminSubmissionResult;
    fn coordinate(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<Option<super::sdk::authority::AuthorityAdminResult>, SharedAgentHostError>;
}

impl<P, R, I, J, T, S> NativeAuthorityAdminAccess<P, R, I>
    for (
        super::clean_bootstrap::NativeAuthorityAdminController<J, T>,
        S,
    )
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    J: super::clean_bootstrap::NativeAuthorityAdminJournalStore + Send,
    T: super::clean_bootstrap::NativeAuthorityAdminTerminalStore + Send,
    S: super::clean_bootstrap::NativeAuthorityAdminTerminalSigner
        + super::clean_bootstrap::NativeAuthorityAdminPreparationSigner
        + Send,
{
    fn retains(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> Result<bool, SharedAgentHostError> {
        self.0.retains_submission(call, preparation)
    }
    fn prepare(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<super::clean_bootstrap::NativeAuthorityAdminPreparation, SharedAgentHostError> {
        owner.prepare_authority_admin(draft, &mut self.1)
    }
    fn submit(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> AuthorityAdminSubmissionResult {
        self.0
            .submit_with_completion(owner, call, preparation, &mut self.1)
    }
    fn coordinate(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<Option<super::sdk::authority::AuthorityAdminResult>, SharedAgentHostError> {
        self.0.coordinate_and_retire(owner, call, &mut self.1)
    }
}

/// Type-erased operation storage/signing retained with the native owner.
pub(crate) trait NativeAuthorityOperationAccess<P, R, I>: Send
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    fn retains_call(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: Option<&super::sdk::InvocationContext>,
    ) -> Result<bool, SharedAgentHostError>;
    fn prepare(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
    ) -> Result<super::sdk::InvocationContext, SharedAgentHostError>;
    fn coordinate(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: super::sdk::InvocationContext,
        issued_at: u64,
    ) -> Result<super::clean_bootstrap::NativeAuthorityOperationDecision, SharedAgentHostError>;
}

/// Type erasure preserves the recovery operation and its owned leases, rather
/// than accepting an arbitrary keepalive payload from startup.
trait NativeSharedGenesisAccess<P, R, I, S>: Send
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
{
    fn recover(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>;

    fn publish_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signatures: Vec<super::committee::AuthoritySignature>,
        signer: &mut S,
    ) -> Result<super::genesis::AgentGenesisArchiveRecord, SharedAgentHostError>;

    fn prepare_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<super::clean_bootstrap::PreparedSharedGenesisEndorsement, SharedAgentHostError>;

    fn complete_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError>;

    fn initialize_management(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>;

    fn prepare_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError>;

    fn complete_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError>;

    fn install_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        install: &super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<SharedInstallDenial>, SharedAgentHostError>;

    fn reserve_create(
        &mut self,
        _: &AgentDescriptor,
        _: &AuthorityCredentialCall,
        _: &AdmittedRuntimePackage,
        _: &super::genesis::AgentReplicaCommittee,
    ) -> Result<super::genesis::AgentGenesisLocator, SharedAgentHostError> {
        Err(SharedAgentHostError::Conflict)
    }
}

impl<P, R, I, S, B, J, Q, Reply, W, PubReply, A, F> NativeSharedGenesisAccess<P, R, I, S>
    for (
        super::clean_bootstrap::NativeSharedGenesisController<B, J, Q, Reply, W, PubReply, A>,
        F,
    )
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    S: CleanManagementReceiptSigner,
    B: super::clean_authority_issuer::CleanSharedManagementIntentStore + Send,
    J: super::clean_authority_issuer::CleanSharedManagementIssuerStore + Send,
    Q: super::clean_authority_issuer::CleanSharedGenesisReplicaStore + Send,
    Reply: CleanManagementIssuerStore + Send,
    W: CleanManagementIssuerStore + Send,
    PubReply: CleanManagementIssuerStore + Send,
    A: super::genesis_archive::AgentGenesisArchiveStore,
    F: FnMut(
            &AgentDescriptor,
            &AuthorityCredentialCall,
            &AdmittedRuntimePackage,
            &super::genesis::AgentReplicaCommittee,
        ) -> Result<
            (
                super::clean_bootstrap::NativeSharedGenesisRecovery<B, J, Q, Reply, W, PubReply>,
                Option<A>,
            ),
            SharedAgentHostError,
        > + Send,
{
    fn recover(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        self.0.recover(owner, signer)
    }

    fn publish_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signatures: Vec<super::committee::AuthoritySignature>,
        signer: &mut S,
    ) -> Result<super::genesis::AgentGenesisArchiveRecord, SharedAgentHostError> {
        self.0
            .publish_pending_create(owner, locator, signatures, signer)
    }

    fn prepare_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<super::clean_bootstrap::PreparedSharedGenesisEndorsement, SharedAgentHostError>
    {
        self.0.prepare_pending_create(owner, locator, signer)
    }

    fn complete_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        self.0.complete_pending_create(owner, locator, signer)
    }

    fn initialize_management(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        self.0.initialize_management(owner, locator, signer)
    }

    fn prepare_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        self.0
            .prepare_install(owner, install, call, package, signer)
    }

    fn complete_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError> {
        self.0.complete_install(owner, locator, signer)
    }

    fn install_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        install: &super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<SharedInstallDenial>, SharedAgentHostError> {
        self.0.install_denial(locator, install, call)
    }

    fn reserve_create(
        &mut self,
        descriptor: &AgentDescriptor,
        call: &AuthorityCredentialCall,
        runtime: &AdmittedRuntimePackage,
        replicas: &super::genesis::AgentReplicaCommittee,
    ) -> Result<super::genesis::AgentGenesisLocator, SharedAgentHostError> {
        let (controller, reserve) = self;
        controller.reserve_create_with(descriptor, call, runtime, replicas, || {
            reserve(descriptor, call, runtime, replicas)
        })
    }
}

impl<P, R, I, S, B, J, Q, Reply, W, PubReply, A> NativeSharedGenesisAccess<P, R, I, S>
    for super::clean_bootstrap::NativeSharedGenesisController<B, J, Q, Reply, W, PubReply, A>
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    S: CleanManagementReceiptSigner,
    B: super::clean_authority_issuer::CleanSharedManagementIntentStore + Send,
    J: super::clean_authority_issuer::CleanSharedManagementIssuerStore + Send,
    Q: super::clean_authority_issuer::CleanSharedGenesisReplicaStore + Send,
    Reply: CleanManagementIssuerStore + Send,
    W: CleanManagementIssuerStore + Send,
    PubReply: CleanManagementIssuerStore + Send,
    A: super::genesis_archive::AgentGenesisArchiveStore,
{
    fn recover(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        super::clean_bootstrap::NativeSharedGenesisController::recover(self, owner, signer)
    }

    fn publish_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signatures: Vec<super::committee::AuthoritySignature>,
        signer: &mut S,
    ) -> Result<super::genesis::AgentGenesisArchiveRecord, SharedAgentHostError> {
        self.publish_pending_create(owner, locator, signatures, signer)
    }

    fn prepare_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<super::clean_bootstrap::PreparedSharedGenesisEndorsement, SharedAgentHostError>
    {
        self.prepare_pending_create(owner, locator, signer)
    }

    fn complete_create(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        self.complete_pending_create(owner, locator, signer)
    }

    fn initialize_management(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        super::clean_bootstrap::NativeSharedGenesisController::initialize_management(
            self, owner, locator, signer,
        )
    }

    fn prepare_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
        signer: &mut S,
    ) -> Result<(), SharedAgentHostError> {
        super::clean_bootstrap::NativeSharedGenesisController::prepare_install(
            self, owner, install, call, package, signer,
        )
    }

    fn complete_install(
        &mut self,
        owner: &mut CleanSystemAgentBootstrapOwner<P, R, I>,
        locator: super::genesis::AgentGenesisLocator,
        signer: &mut S,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError> {
        super::clean_bootstrap::NativeSharedGenesisController::complete_install(
            self, owner, locator, signer,
        )
    }

    fn install_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        install: &super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<SharedInstallDenial>, SharedAgentHostError> {
        super::clean_bootstrap::NativeSharedGenesisController::install_denial(
            self, locator, install, call,
        )
    }
}

/// Retains one system owner and one selected physical Local backing across route-worker
/// retirement. Lifecycle calls lock system then Local; route workers lock only
/// their own host. Never call route-worker methods while either guard is held.
/// Native shutdown must stop lifecycle callers and retire/join route workers
/// before dropping this controller's final owner references and operation leases.
enum LocalBacking {
    Image(Arc<Mutex<LocalAgentHost>>),
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    External {
        // The pinned directory and every locked owner outlive route workers.
        _directory: super::journal_store::ExternalLocalJournalDirectory,
        maximum: usize,
        owners: BTreeMap<
            AgentId,
            Arc<Mutex<super::external_local_executor::ExternalLocalJournalOwner>>,
        >,
        clock: Arc<dyn super::driver::AgentTrustProvider>,
    },
}

pub struct LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore,
    R: CleanSystemAgentBootstrapStore,
    I: CleanManagementIssuerStore,
    F: LocalLifecycleStoreFactory,
{
    system: Arc<Mutex<CleanSystemAgentBootstrapOwner<P, R, I>>>,
    local: LocalBacking,
    stores: F,
    // Retain exclusive handles across retries, including ambiguous commits.
    // Parsed protocol state is reopened from these handles for every call.
    retained_stores: BTreeMap<AgentId, (F::Intent, F::Issuer)>,
    signer: S,
    operations: Option<Box<dyn NativeAuthorityOperationAccess<P, R, I>>>,
    admins: Option<Box<dyn NativeAuthorityAdminAccess<P, R, I>>>,
    shared_genesis: Option<Box<dyn NativeSharedGenesisAccess<P, R, I, S>>>,
    shared_endorser: Option<Box<dyn SharedGenesisEndorser>>,
}

impl<P, R, I, F, S> LocalLifecycleController<P, R, I, F, S>
where
    P: CleanSystemAgentBootstrapStore + Send + 'static,
    R: CleanSystemAgentBootstrapStore + Send + 'static,
    I: CleanManagementIssuerStore + Send + 'static,
    F: LocalLifecycleStoreFactory,
    S: CleanManagementReceiptSigner,
{
    pub fn new(
        system: CleanSystemAgentBootstrapOwner<P, R, I>,
        local: LocalAgentHost,
        stores: F,
        signer: S,
    ) -> Result<Self, SharedAgentHostError> {
        if local.space() != system.pins().space() || local.node() != system.pins().node() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Self {
            system: Arc::new(Mutex::new(system)),
            local: LocalBacking::Image(Arc::new(Mutex::new(local))),
            stores,
            retained_stores: BTreeMap::new(),
            signer,
            operations: None,
            admins: None,
            shared_genesis: None,
            shared_endorser: None,
        })
    }

    /// Explicit fresh-root external selection. Complete signed lifecycle
    /// recovery and physical finality before constructing any route worker.
    /// This selects an external owner before any opt-in LCQ2 admission; the
    /// default binary and image-backed path remain unchanged.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn with_external_recovery(
        mut system: CleanSystemAgentBootstrapOwner<P, R, I>,
        directory: super::journal_store::ExternalLocalJournalDirectory,
        stores: F,
        mut signer: S,
        mut recovery: LocalLifecycleRecovery<F::Intent, F::Issuer>,
        clock: Arc<dyn super::driver::AgentTrustProvider>,
        maximum: usize,
        budget: &mut super::sdk::state_blocks::ReadBudget,
    ) -> Result<Self, SharedAgentHostError>
    where
        F::Intent: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        let node = system.pins().node();
        if directory.space() != crate::service::SpaceId(system.pins().space().0)
            || directory.node() != crate::service::NodeId(node.0)
            || recovery.authority != system.authority_target()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let owners = recovery
            .recover_external_pending(&mut system, &directory, node, maximum, budget, &mut signer)?
            .into_iter()
            .map(|(agent, owner)| (agent, Arc::new(Mutex::new(owner))))
            .collect();
        let mut controller = Self {
            system: Arc::new(Mutex::new(system)),
            local: LocalBacking::External {
                _directory: directory,
                maximum,
                owners,
                clock,
            },
            stores,
            retained_stores: BTreeMap::new(),
            signer,
            operations: None,
            admins: None,
            shared_genesis: None,
            shared_endorser: None,
        };
        for entry in recovery.entries {
            if controller
                .retained_stores
                .insert(
                    entry.agent,
                    (entry.intent.into_store(), entry.issuer.into_store()),
                )
                .is_some()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        Ok(controller)
    }

    /// Drive an opt-in external Create under retained lifecycle leases. An
    /// exact retry of an already-serving generation verifies its immutable
    /// Create archive against the same locked owner; it must not reacquire
    /// the stable lock or publish a second physical head. The opt-in queue
    /// retains this type separately from image LCQ1.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub fn create_external(
        &mut self,
        submission: LocalStateCreateSubmission,
        budget: &mut super::sdk::state_blocks::ReadBudget,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError>
    where
        F::Intent: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore,
    {
        use super::clean_authority_issuer::DurableCleanManagementIssuer;
        use super::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
        use super::external_local_executor::ExternalLocalCreateArchive;

        let LocalBacking::External {
            _directory: directory,
            maximum,
            owners,
            ..
        } = &mut self.local
        else {
            return Err(SharedAgentHostError::Unavailable);
        };
        let (descriptor, call, runtime) = submission.into_parts();
        let agent = descriptor.identity.agent;
        let request = ManagementRequest::Create(Box::new(descriptor));
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let target = system.authority_target();
        let node = system.pins().node();
        let intent = CleanManagementIntent::new(
            target,
            call.managed,
            request,
            call,
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let ManagementRequest::Create(created_descriptor) = intent.request() else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if intent.call().managed.agent != agent
            || created_descriptor.identity.profile != AgentProfile::Local
            || created_descriptor.identity.space != system.pins().space()
            || created_descriptor.authority != target.binding
            || created_descriptor.replicas.len() != 1
            || created_descriptor.replicas[0].node != node
            || created_descriptor.replicas[0].role != super::sdk::ReplicaRole::Voter
            || !super::external_local_executor::state_runtime_matches_descriptor(
                created_descriptor,
                &runtime,
            )
            || directory.space() != crate::service::SpaceId(target.space.0)
            || directory.node() != crate::service::NodeId(node.0)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (intent_store, issuer_store) = match self.retained_stores.entry(agent) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                if owners.contains_key(&agent) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                // Startup bounds every durable lifecycle directory, including
                // denied attempts and unpledged staging discarded from the
                // recovery worklist. Use that same inventory before creating
                // another store; existing staged requests can still retry at
                // capacity. This scan is confined to lifecycle admission.
                let discovered = self
                    .stores
                    .discover(target.space, *maximum)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                if discovered.len() > *maximum
                    || discovered.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                if !discovered.contains(&agent) && discovered.len() >= *maximum {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                let stores = self
                    .stores
                    .open(target.space, agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                entry.insert(stores)
            }
        };
        let mut slot = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut issuer =
            DurableCleanManagementIssuer::open(issuer_store, target.binding, target.space, agent)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        if let Some(owner) = owners.get(&agent) {
            let archive = slot
                .load_external_create_archive()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::ScopeMismatch)
                .and_then(|bytes| {
                    ExternalLocalCreateArchive::decode(&bytes)
                        .map_err(|_| SharedAgentHostError::ScopeMismatch)
                })?;
            let runtime_bytes = slot
                .load_runtime()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let current = slot.intent().ok_or(SharedAgentHostError::ScopeMismatch)?;
            let owner = owner
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if archive.intent().request() != intent.request()
                || archive.intent().call() != intent.call()
                || runtime_bytes != runtime.exact_bytes()
                || !archive.matches_owner(current, target, node, &owner)
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if matches!(current.request(), ManagementRequest::Create(_)) {
                let finalized = issuer
                    .recover_finalized_application(
                        target,
                        intent.call().managed,
                        intent.request(),
                        intent.call(),
                        &super::clean_bootstrap::RawCredentialVerifier,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                    .ok_or(SharedAgentHostError::Conflict)?;
                if finalized.1 != *archive.acknowledgement() {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
            return Ok((agent, archive.acknowledgement().clone()));
        }
        if owners.len() >= *maximum {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let (created, acknowledgement, owner) = system.create_external_local_agent_on_slots(
            &mut slot,
            &mut issuer,
            intent,
            runtime,
            directory,
            budget,
            &mut self.signer,
        )?;
        if created != agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        match owners.entry(agent) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::new(Mutex::new(owner)));
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        Ok((created, acknowledgement))
    }

    /// Recover the complete Shared set before this controller can be handed to
    /// the node. Keep all reservation/archive leases until workers are retired
    /// and the production lifecycle owner is dropped. No archive-only verifier
    /// is installed, and failed recovery never returns a serving controller.
    pub fn with_shared_genesis<B, J, Q, Reply, W, PubReply, A>(
        self,
        shared: super::clean_bootstrap::NativeSharedGenesisController<
            B,
            J,
            Q,
            Reply,
            W,
            PubReply,
            A,
        >,
    ) -> Result<Self, SharedAgentHostError>
    where
        B: super::clean_authority_issuer::CleanSharedManagementIntentStore + Send + 'static,
        J: super::clean_authority_issuer::CleanSharedManagementIssuerStore + Send + 'static,
        Q: super::clean_authority_issuer::CleanSharedGenesisReplicaStore + Send + 'static,
        Reply: CleanManagementIssuerStore + Send + 'static,
        W: CleanManagementIssuerStore + Send + 'static,
        PubReply: CleanManagementIssuerStore + Send + 'static,
        A: super::genesis_archive::AgentGenesisArchiveStore + 'static,
    {
        self.with_shared_access(Box::new(shared))
    }

    /// Retain the configured reservation factory with the recovered Shared
    /// controller. The factory reserves signed inputs only; it must not execute
    /// Authority, provision a generation or publish routes. It may open its
    /// control roots lazily on first admission, preserving noncreating startup.
    pub fn with_shared_genesis_admission<B, J, Q, Reply, W, PubReply, A, Factory>(
        self,
        shared: super::clean_bootstrap::NativeSharedGenesisController<
            B,
            J,
            Q,
            Reply,
            W,
            PubReply,
            A,
        >,
        reserve: Factory,
    ) -> Result<Self, SharedAgentHostError>
    where
        B: super::clean_authority_issuer::CleanSharedManagementIntentStore + Send + 'static,
        J: super::clean_authority_issuer::CleanSharedManagementIssuerStore + Send + 'static,
        Q: super::clean_authority_issuer::CleanSharedGenesisReplicaStore + Send + 'static,
        Reply: CleanManagementIssuerStore + Send + 'static,
        W: CleanManagementIssuerStore + Send + 'static,
        PubReply: CleanManagementIssuerStore + Send + 'static,
        A: super::genesis_archive::AgentGenesisArchiveStore + 'static,
        Factory: FnMut(
                &AgentDescriptor,
                &AuthorityCredentialCall,
                &AdmittedRuntimePackage,
                &super::genesis::AgentReplicaCommittee,
            ) -> Result<
                (
                    super::clean_bootstrap::NativeSharedGenesisRecovery<
                        B,
                        J,
                        Q,
                        Reply,
                        W,
                        PubReply,
                    >,
                    Option<A>,
                ),
                SharedAgentHostError,
            > + Send
            + 'static,
    {
        self.with_shared_access(Box::new((shared, reserve)))
    }

    fn with_shared_access(
        mut self,
        mut shared: Box<dyn NativeSharedGenesisAccess<P, R, I, S>>,
    ) -> Result<Self, SharedAgentHostError> {
        if self.shared_genesis.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        {
            let mut system = self
                .system
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            shared.recover(&mut system, &mut self.signer)?;
        }
        self.shared_genesis = Some(shared);
        Ok(self)
    }

    /// Reserve exact Shared Create inputs under the lifecycle owner's ordering
    /// lock. This is an internal preparation boundary, not a completed Create
    /// response; no route or physical generation is produced here.
    pub fn reserve_shared_create(
        &mut self,
        descriptor: &AgentDescriptor,
        call: &AuthorityCredentialCall,
        runtime: &AdmittedRuntimePackage,
        replicas: &super::genesis::AgentReplicaCommittee,
    ) -> Result<super::genesis::AgentGenesisLocator, SharedAgentHostError> {
        let _system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .reserve_create(descriptor, call, runtime, replicas)
    }

    /// Reauthenticate retained Create inputs and query their Authority committee.
    /// The sealed candidate can obtain durable endorsements; it grants neither
    /// publication nor finality. A caller cannot supply a replacement committee.
    pub fn prepare_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<super::clean_bootstrap::PreparedSharedGenesisEndorsement, SharedAgentHostError>
    {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .prepare_create(&mut system, locator, &mut self.signer)
    }

    /// Publish collected Shared genesis evidence through the retained owner.
    /// This returns an authenticated archive, not a completed Create ACK or
    /// permission to expose an ordinary route. Application/retirement follow.
    pub fn publish_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        signatures: Vec<super::committee::AuthoritySignature>,
    ) -> Result<super::genesis::AgentGenesisArchiveRecord, SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .publish_create(&mut system, locator, signatures, &mut self.signer)
    }

    /// Finish a published Shared Create before allowing its generation to serve.
    /// Repeated completion returns the original signed application ACK.
    pub fn complete_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .complete_create(&mut system, locator, &mut self.signer)
    }

    /// Retain the continuing management issuer after a fresh completed-Create
    /// check. This internal seam admits no Install and publishes no new route.
    pub fn initialize_shared_management(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<(), SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .initialize_management(&mut system, locator, &mut self.signer)
    }

    /// Retain signed Shared Install inputs without executing Authority or the
    /// actor. Success is preparation, not an installation acknowledgement.
    pub fn prepare_shared_install(
        &mut self,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
    ) -> Result<(), SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .prepare_install(&mut system, install, call, package, &mut self.signer)
    }

    /// Complete a retained Shared Install through application, signed finality,
    /// and retirement. This orchestration seam does not enable public ingress.
    /// Exact retries return the original signed success or rejection.
    pub fn complete_shared_install(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<SignedManagementTerminal, SharedAgentHostError> {
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .complete_install(&mut system, locator, &mut self.signer)
    }

    /// Return a signed policy-denial certificate for this exact request, not
    /// for whichever request currently occupies the Agent's management slot.
    /// This read neither executes policy nor releases a reservation. One prior
    /// denial may remain available in the bounded successor handoff; older
    /// history is not promised. Public ingress remains separately gated.
    /// `None` means no retained certificate; it is not a success or denial.
    pub fn shared_install_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        install: &super::sdk::InstallActor,
        call: &AuthorityCredentialCall,
    ) -> Result<Option<SharedInstallDenial>, SharedAgentHostError> {
        self.shared_genesis
            .as_mut()
            .ok_or(SharedAgentHostError::Conflict)?
            .install_denial(locator, install, call)
    }

    /// Retain the node's genesis endorser for the controller's lifetime. Only
    /// `create_shared` consults it; recovery never signs a new endorsement.
    pub fn with_shared_genesis_endorser(
        mut self,
        endorser: impl SharedGenesisEndorser + 'static,
    ) -> Result<Self, SharedAgentHostError> {
        if self.shared_endorser.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        self.shared_endorser = Some(Box::new(endorser));
        Ok(self)
    }

    /// Drive one exact signed ordinary Shared Create through reservation,
    /// endorsement, publication, physical application, signed finality and
    /// retirement. Each phase keeps its own exact-retry semantics, so a retry
    /// after any failure (or restart) resumes rather than repeating work. The
    /// returned ACK is the original signed application acknowledgement.
    pub fn create_shared(
        &mut self,
        submission: SharedCreateSubmission,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        let (descriptor, call, runtime, replicas) = submission.into_parts();
        let locator = self.reserve_shared_create(&descriptor, &call, &runtime, &replicas)?;
        match self.prepare_shared_create(locator) {
            Ok(prepared) => {
                let signatures = self
                    .shared_endorser
                    .as_mut()
                    .ok_or(SharedAgentHostError::Unavailable)?
                    .endorse(locator, &prepared)?;
                self.publish_shared_create(locator, signatures)?;
            }
            // An archived or retired Create refuses fresh preparation. Its
            // completion below is independently reauthenticated by the owner.
            Err(SharedAgentHostError::Conflict) => {}
            Err(error) => return Err(error),
        }
        let acknowledgement = self.complete_shared_create(locator)?;
        if acknowledgement.credential_call != call.commitment() {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(acknowledgement)
    }

    /// Drive one exact signed Install on a retained ordinary Shared Agent to
    /// its signed terminal. A retained policy denial for this exact request is
    /// returned as such; a signed application rejection is not an install.
    pub fn install_shared(
        &mut self,
        submission: SharedInstallSubmission,
    ) -> Result<SharedInstallDisposition, SharedAgentHostError> {
        let (install, call, package) = submission.into_parts();
        let locator = super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(call.managed.space.0),
            agent: crate::service::AgentId(call.managed.agent.0),
        };
        if let Some(denial) = self.shared_install_denial(locator, &install, &call)? {
            return Ok(SharedInstallDisposition::Denied(denial));
        }
        let terminal = self
            .prepare_shared_install(install.clone(), call.clone(), &package)
            .and_then(|()| self.complete_shared_install(locator));
        match terminal {
            Ok(SignedManagementTerminal::Applied(acknowledgement))
                if acknowledgement.credential_call == call.commitment() =>
            {
                Ok(SharedInstallDisposition::Installed(acknowledgement))
            }
            Ok(SignedManagementTerminal::Applied(_)) => Err(SharedAgentHostError::Conflict),
            Ok(SignedManagementTerminal::Rejected(_)) => Err(SharedAgentHostError::ScopeMismatch),
            Err(SharedAgentHostError::ScopeMismatch) => {
                match self.shared_install_denial(locator, &install, &call)? {
                    Some(denial) => Ok(SharedInstallDisposition::Denied(denial)),
                    None => Err(SharedAgentHostError::ScopeMismatch),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Adopt the recovered admin stores for the full production-owner lifetime.
    pub fn with_admins<J, T, A>(
        mut self,
        admins: super::clean_bootstrap::NativeAuthorityAdminController<J, T>,
        signer: A,
    ) -> Result<Self, SharedAgentHostError>
    where
        J: super::clean_bootstrap::NativeAuthorityAdminJournalStore + Send + 'static,
        T: super::clean_bootstrap::NativeAuthorityAdminTerminalStore + Send + 'static,
        A: super::clean_bootstrap::NativeAuthorityAdminTerminalSigner
            + super::clean_bootstrap::NativeAuthorityAdminPreparationSigner
            + Send
            + 'static,
    {
        let target = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .authority_target();
        if self.admins.is_some()
            || admins.authority() != target
            || super::clean_bootstrap::NativeAuthorityAdminTerminalSigner::public_key(&signer)
                != target.binding.public_key
            || super::clean_bootstrap::NativeAuthorityAdminPreparationSigner::public_key(&signer)
                != target.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.admins = Some(Box::new((admins, signer)));
        Ok(self)
    }

    pub fn prepare_admin(
        &mut self,
        draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<super::clean_bootstrap::NativeAuthorityAdminPreparation, SharedAgentHostError> {
        let admins = self
            .admins
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        admins.prepare(&mut system, draft)
    }

    pub fn submit_admin(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> AuthorityAdminSubmissionResult {
        let admins = self
            .admins
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        admins.submit(&mut system, call, preparation)
    }

    /// Resume retained work only; new calls must use prepare_admin/submit_admin.
    pub fn administer(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
    ) -> Result<Option<super::sdk::authority::AuthorityAdminResult>, SharedAgentHostError> {
        let admins = self
            .admins
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        admins.coordinate(&mut system, call)
    }

    /// Adopt recovered operation stores and a signer matching the native owner.
    pub fn with_operations<C, B, J, K, T, D, O>(
        mut self,
        mut operations: super::clean_bootstrap::NativeAuthorityOperationController<
            C,
            B,
            J,
            K,
            T,
            D,
        >,
        signer: O,
    ) -> Result<Self, SharedAgentHostError>
    where
        C: super::authority_operation_coordinator::AuthorityOperationCoordinatorStore
            + Send
            + 'static,
        B: super::authority_operation_issuer::AuthorityOperationIssuerStore + Send + 'static,
        J: super::clean_bootstrap::NativeAuthorityOperationJournalStore + Send + 'static,
        K: super::clean_bootstrap::NativeAuthorityOperationCompletionStore + Send + 'static,
        T: super::clean_bootstrap::NativeAuthorityOperationRetirementStore + Send + 'static,
        D: super::clean_bootstrap::NativeAuthorityOperationDenialStore + Send + 'static,
        O: super::authority_operation_issuer::AuthorityOperationEvidenceSigner
            + super::clean_bootstrap::NativeAuthorityOperationCompletionSigner
            + super::clean_bootstrap::NativeAuthorityOperationRetirementSigner
            + super::clean_bootstrap::NativeAuthorityOperationDenialSigner
            + Send
            + 'static,
    {
        let target = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .authority_target();
        if self.operations.is_some()
            || operations.authority() != target
            || super::authority_operation_issuer::AuthorityOperationEvidenceSigner::public_key(
                &signer,
            ) != target.binding.public_key
            || super::clean_bootstrap::NativeAuthorityOperationCompletionSigner::public_key(&signer)
                != target.binding.public_key
            || super::clean_bootstrap::NativeAuthorityOperationRetirementSigner::public_key(&signer)
                != target.binding.public_key
            || super::clean_bootstrap::NativeAuthorityOperationDenialSigner::public_key(&signer)
                != target.binding.public_key
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        operations
            .validate()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.operations = Some(Box::new((operations, signer)));
        Ok(self)
    }

    /// Retain the native dispatch before returning its exact authorization
    /// context. This does not execute policy, issue a receipt or release admission.
    pub fn prepare_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
    ) -> AuthorityOperationPreparationResult {
        let operations = self
            .operations
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let context = operations.prepare(&mut system, call)?;
        let issued_at = context.observed_slot;
        AuthorityOperationSubmission::new(call.clone(), context, issued_at)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)
    }

    pub fn authorize_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: super::sdk::InvocationContext,
        issued_at: u64,
    ) -> Result<super::clean_bootstrap::NativeAuthorityOperationDecision, SharedAgentHostError>
    {
        let operations = self
            .operations
            .as_mut()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        operations.coordinate(&mut system, call, context, issued_at)
    }

    /// Adopt stores previously verified against independently selected pins.
    /// This transfers leases without opening their paths again. The caller
    /// must separately seed system-network recovery before publishing routes;
    /// this constructor then rechecks physical Local application, completes
    /// finalization under pending admission, and retires results before normal
    /// lifecycle/route access.
    pub fn with_recovery(
        mut system: CleanSystemAgentBootstrapOwner<P, R, I>,
        mut local: LocalAgentHost,
        stores: F,
        mut signer: S,
        mut recovery: LocalLifecycleRecovery<F::Intent, F::Issuer>,
    ) -> Result<Self, SharedAgentHostError> {
        if recovery.authority != system.authority_target()
            || local.space() != system.pins().space()
            || local.node() != system.pins().node()
            || recovery.entries.iter().any(|entry| {
                entry
                    .observed
                    .as_ref()
                    .is_some_and(|value| value.as_applied().is_none())
                    || entry
                        .finalized
                        .as_ref()
                        .is_some_and(|value| value.as_applied().is_none())
            })
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Validate the entire set before retiring any member. Incomplete
        // phases require their own protected recovery protocol, not omission.
        let admission = recovery.startup_admission()?;
        for entry in &mut recovery.entries {
            if ((entry.unissued_authorization
                && matches!(
                    entry.intent.intent().map(|intent| intent.request()),
                    Some(ManagementRequest::Create(_))
                ))
                || entry
                    .intent
                    .denial_complete()
                    .map_err(|_| SharedAgentHostError::Unavailable)?)
                && system.finish_denied_management_intent(
                    &mut entry.intent,
                    &entry.issuer,
                    &local,
                    &mut signer,
                )?
            {
                entry.unissued_authorization = false;
            }
        }
        let mut runtimes = BTreeMap::new();
        let mut actors = BTreeMap::new();
        for (index, entry) in recovery.entries.iter_mut().enumerate() {
            if (entry.issued.is_some() || entry.unissued_authorization)
                && matches!(
                    entry.intent.intent().map(|intent| intent.request()),
                    Some(ManagementRequest::Install(_))
                )
            {
                let package = entry
                    .intent
                    .load_actor()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::Unavailable)?;
                let descriptor = local
                    .show(entry.agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let managed = super::sdk::authority::ManagedAgentTarget {
                    space: descriptor.identity.space,
                    agent: descriptor.identity.agent,
                    owner: descriptor.identity.owner,
                    profile: descriptor.identity.profile,
                    runtime_deployment: descriptor.identity.runtime_deployment,
                    transition_producer: descriptor.identity.transition_producer,
                };
                let intent = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                if descriptor.authority != system.authority_target().binding {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                intent
                    .verify(
                        system.authority_target(),
                        managed,
                        &super::clean_bootstrap::RawCredentialVerifier,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                super::driver::validate_sdk_management_artifacts(
                    descriptor,
                    intent.request(),
                    super::driver::SdkManagementArtifacts::Actor(&package),
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
                actors.insert(index, package);
            }
            if (entry.unissued_authorization
                && matches!(
                    entry.intent.intent().map(|intent| intent.request()),
                    Some(ManagementRequest::Create(_))
                ))
                || (entry.issued.is_some()
                    && entry.observed.is_none()
                    && matches!(
                        local.show(entry.agent),
                        Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                    ))
            {
                runtimes.insert(index, load_create_runtime(&mut entry.intent)?);
            }
        }
        // Verify physical images before advancing any required predecessor.
        // Its saved finalization clock was checked against every unissued
        // authorization by startup_admission; no envelope is rewritten.
        if !admission.order.is_empty() {
            for (index, entry) in recovery.entries.iter().enumerate() {
                if let Some(receipt) = &entry.issued {
                    if entry.observed.is_none()
                        && matches!(
                            local.show(entry.agent),
                            Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                        )
                    {
                        continue;
                    }
                    let observation = local.observe_management_application(
                        entry.agent,
                        entry
                            .intent
                            .intent()
                            .ok_or(SharedAgentHostError::ScopeMismatch)?
                            .request(),
                        receipt,
                    );
                    if !matches!(observation, Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                        if entry.observed.is_none() && actors.contains_key(&index))
                    {
                        observation.map_err(|_| SharedAgentHostError::Unavailable)?;
                    }
                }
            }
        }
        for &index in &admission.order {
            let entry = &mut recovery.entries[index];
            let intent = entry
                .intent
                .intent()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let managed = intent.call().managed;
            let receipt = entry
                .issued
                .as_ref()
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            let observation = local
                .observe_management_application(entry.agent, intent.request(), receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let acknowledgement = entry
                .issuer
                .observe_local_application(&observation, &mut signer)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if entry.observed.as_ref().is_some_and(|saved| {
                saved != &SignedManagementTerminal::Applied(acknowledgement.clone())
            }) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            entry.observed = Some(SignedManagementTerminal::Applied(acknowledgement.clone()));
            if entry.finalized.is_none() {
                system.finalize_management_intent_with_admission(
                    &mut entry.intent,
                    managed,
                    &acknowledgement,
                    &mut entry.issuer,
                    true,
                )?;
                entry.finalized = Some(SignedManagementTerminal::Applied(acknowledgement.clone()));
                let authorization = entry
                    .intent
                    .authorization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                let finalization = entry
                    .intent
                    .finalization_work()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                system.handoff_recovered_management(&[[authorization, finalization]])?;
            }
            system.finish_management_intent_retirement(
                &mut entry.intent,
                managed,
                &acknowledgement,
                &entry.issuer,
            )?;
        }
        // Runtime availability is checked before executing any unissued call.
        // The issuer eligibility check does not replace durable actor replay.
        for entry in &mut recovery.entries {
            if entry.unissued_authorization {
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                entry.issued = Some(system.issue_management_intent(
                    &mut entry.intent,
                    managed,
                    &mut entry.issuer,
                    &mut signer,
                )?);
            }
        }
        let mut observations = Vec::new();
        let mut creates = Vec::new();
        let mut installs = Vec::new();
        for (index, entry) in recovery.entries.iter_mut().enumerate() {
            if let Some(receipt) = &entry.issued {
                let request = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .request()
                    .clone();
                if entry.observed.is_none()
                    && matches!(
                        local.show(entry.agent),
                        Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                    )
                {
                    let ManagementRequest::Create(descriptor) = &request else {
                        return Err(SharedAgentHostError::ScopeMismatch);
                    };
                    let runtime = runtimes
                        .remove(&index)
                        .ok_or(SharedAgentHostError::ScopeMismatch)?;
                    creates.push((index, runtime, (**descriptor).clone(), receipt.clone()));
                    continue;
                }
                // A finalized issuer cannot replace the actual Local image.
                match local.observe_management_application(entry.agent, &request, receipt) {
                    Ok(observation) => observations.push((index, observation)),
                    Err(super::local_sdk_host::LocalAgentHostError::NotFound)
                        if entry.observed.is_none() && actors.contains_key(&index) =>
                    {
                        let package = actors
                            .remove(&index)
                            .ok_or(SharedAgentHostError::ScopeMismatch)?;
                        installs.push((index, request, receipt.clone(), package));
                    }
                    Err(_) => return Err(SharedAgentHostError::Unavailable),
                }
            }
        }
        for (index, runtime, descriptor, receipt) in creates {
            let request = ManagementRequest::Create(Box::new(descriptor.clone()));
            let agent = local
                .create_agent(runtime, descriptor, receipt.clone())
                .map_err(|error| {
                    crate::log::warn!("Local lifecycle recovery Create failed: {error:?}");
                    SharedAgentHostError::Unavailable
                })?;
            let observation = local
                .observe_management_application(agent, &request, &receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            observations.push((index, observation));
        }
        for (index, request, receipt, package) in installs {
            let agent = recovery.entries[index].agent;
            local
                .manage(
                    agent,
                    request.clone(),
                    Some(receipt.clone()),
                    super::driver::SdkManagementArtifacts::Actor(&package),
                )
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let observation = local
                .observe_management_application(agent, &request, &receipt)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            observations.push((index, observation));
        }
        // Check all physical images before signing a missing acknowledgement
        // for any member. An issued receipt alone is not application proof.
        for (index, observation) in observations {
            let entry = &mut recovery.entries[index];
            let acknowledgement = entry
                .issuer
                .observe_local_application(&observation, &mut signer)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if entry.observed.as_ref().is_some_and(|saved| {
                saved != &SignedManagementTerminal::Applied(acknowledgement.clone())
            }) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            entry.observed = Some(SignedManagementTerminal::Applied(acknowledgement));
        }
        let mut recovered_pairs = Vec::new();
        for entry in &mut recovery.entries {
            if entry.finalized.is_none()
                && let Some(acknowledgement) = entry
                    .observed
                    .as_ref()
                    .and_then(SignedManagementTerminal::as_applied)
            {
                // Saved work keeps its clock. Missing finalization is reserved
                // before publication, without releasing the predecessor gate.
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                system.finalize_management_intent_with_admission(
                    &mut entry.intent,
                    managed,
                    acknowledgement,
                    &mut entry.issuer,
                    true,
                )?;
                entry.finalized = Some(SignedManagementTerminal::Applied(acknowledgement.clone()));
                recovered_pairs.push([
                    entry
                        .intent
                        .authorization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?
                        .clone(),
                    entry
                        .intent
                        .finalization_work()
                        .map_err(|_| SharedAgentHostError::Unavailable)?
                        .ok_or(SharedAgentHostError::ScopeMismatch)?
                        .clone(),
                ]);
            }
        }
        if !recovered_pairs.is_empty() {
            system.handoff_recovered_management(
                &recovered_pairs
                    .iter()
                    .map(|pair| [&pair[0], &pair[1]])
                    .collect::<Vec<_>>(),
            )?;
        }
        for entry in &mut recovery.entries {
            if entry
                .intent
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
            {
                continue;
            }
            if let Some(acknowledgement) = entry
                .finalized
                .as_ref()
                .and_then(SignedManagementTerminal::as_applied)
            {
                let managed = entry
                    .intent
                    .intent()
                    .ok_or(SharedAgentHostError::ScopeMismatch)?
                    .call()
                    .managed;
                system.finish_management_intent_retirement(
                    &mut entry.intent,
                    managed,
                    acknowledgement,
                    &entry.issuer,
                )?;
            }
        }
        let mut controller = Self::new(system, local, stores, signer)?;
        for entry in recovery.entries {
            if controller
                .retained_stores
                .insert(
                    entry.agent,
                    (entry.intent.into_store(), entry.issuer.into_store()),
                )
                .is_some()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        Ok(controller)
    }

    pub fn system_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        super::supervisor_adapters::system_agent_supervisor_attachment_shared(
            self.system.clone(),
            capacity,
        )
    }

    pub fn local_attachment(
        &self,
        capacity: usize,
    ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
        match &self.local {
            LocalBacking::Image(local) => {
                super::supervisor_adapters::local_agent_supervisor_attachment_shared(
                    local.clone(),
                    capacity,
                )
            }
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { .. } => Err(AgentRouteAdapterError::NoReadyRoutes),
        }
    }

    #[cfg(test)]
    pub(crate) fn ordered_index_for_test(&self) -> Result<u64, SharedAgentHostError> {
        self.system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .ordered_index_for_test()
    }

    #[cfg(test)]
    pub(crate) fn fail_finalization_once_for_test(&mut self, phase: u8) {
        self.system
            .lock()
            .unwrap()
            .fail_finalization_once_for_test(phase);
    }

    #[cfg(test)]
    pub(crate) fn system_for_test(
        &self,
    ) -> std::sync::MutexGuard<'_, CleanSystemAgentBootstrapOwner<P, R, I>> {
        self.system.lock().unwrap()
    }

    #[cfg(test)]
    pub(crate) fn into_parts_for_test(
        self,
    ) -> (
        CleanSystemAgentBootstrapOwner<P, R, I>,
        LocalAgentHost,
        F,
        S,
    ) {
        let Self {
            system,
            local,
            stores,
            retained_stores,
            signer,
            operations,
            admins,
            shared_genesis,
            shared_endorser: _,
        } = self;
        assert!(
            shared_genesis.is_none(),
            "test extraction must preserve Shared genesis leases"
        );
        assert!(
            admins.is_none(),
            "test extraction must preserve admin leases"
        );
        assert!(
            operations.is_none(),
            "test extraction must preserve operation leases"
        );
        drop(retained_stores);
        let system = Arc::try_unwrap(system)
            .ok()
            .expect("retire system route workers first")
            .into_inner()
            .unwrap();
        let local = match local {
            LocalBacking::Image(local) => local,
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { .. } => {
                panic!("image test extraction requires an image Local backing")
            }
        };
        let local = Arc::try_unwrap(local)
            .ok()
            .expect("retire local route workers first")
            .into_inner()
            .unwrap();
        (system, local, stores, signer)
    }

    #[cfg(all(
        test,
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn into_external_parts_for_test(
        self,
    ) -> (
        CleanSystemAgentBootstrapOwner<P, R, I>,
        super::journal_store::ExternalLocalJournalDirectory,
        F,
        S,
    ) {
        let Self {
            system,
            local,
            stores,
            retained_stores,
            signer,
            operations,
            admins,
            shared_genesis,
            shared_endorser: _,
        } = self;
        assert!(operations.is_none() && admins.is_none() && shared_genesis.is_none());
        drop(retained_stores);
        let LocalBacking::External {
            _directory: directory,
            owners,
            ..
        } = local
        else {
            panic!("external test extraction requires an external Local backing");
        };
        drop(owners);
        let system = Arc::try_unwrap(system)
            .ok()
            .expect("retire system route workers first")
            .into_inner()
            .unwrap();
        (system, directory, stores, signer)
    }

    /// Drive an external Install only under an already-finalized locked owner.
    /// The signed LIQ1 is staged before replacing the retired intent; public
    /// ingress stays closed until permanent guest rejection has terminal
    /// finality rather than stranding an approved operation.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub fn install_external(
        &mut self,
        submission: LocalInstallSubmission,
        budget: &mut super::sdk::state_blocks::ReadBudget,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError>
    where
        F::Intent: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        use super::clean_authority_issuer::DurableCleanManagementIssuer;
        use super::clean_bootstrap::RawCredentialVerifier;
        use super::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
        use super::driver::SdkManagementArtifacts;

        let LocalBacking::External { owners, .. } = &mut self.local else {
            return Err(SharedAgentHostError::Unavailable);
        };
        let agent = submission.call().managed.agent;
        let external = owners
            .get(&agent)
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let target = system.authority_target();
        let managed = submission.call().managed;
        let request = ManagementRequest::Install(Box::new(submission.install().clone()));
        let next = CleanManagementIntent::new(
            target,
            managed,
            request.clone(),
            submission.call().clone(),
            &RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let mut external = external
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let descriptor = external.descriptor();
        let physical_managed = super::sdk::authority::ManagedAgentTarget {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            owner: descriptor.identity.owner,
            profile: descriptor.identity.profile,
            runtime_deployment: descriptor.identity.runtime_deployment,
            transition_producer: descriptor.identity.transition_producer,
        };
        if managed != physical_managed
            || descriptor.authority != target.binding
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != system.pins().node()
            || super::driver::validate_sdk_management_artifacts(
                descriptor,
                &request,
                SdkManagementArtifacts::Actor(submission.package()),
            )
            .is_err()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let (intent_store, issuer_store) = match self.retained_stores.entry(agent) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let stores = self
                    .stores
                    .open_existing(managed.space, agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                entry.insert(stores)
            }
        };
        let mut slot = CleanManagementIntentSlot::open(intent_store)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut issuer =
            DurableCleanManagementIssuer::open(issuer_store, target.binding, managed.space, agent)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        let previous = slot
            .intent()
            .ok_or(SharedAgentHostError::ScopeMismatch)?
            .clone();
        if previous.request() != next.request() || previous.call() != next.call() {
            if !slot
                .retirement_complete()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                || !issuer
                    .can_resume_install(
                        target,
                        managed,
                        &request,
                        next.call(),
                        &RawCredentialVerifier,
                    )
                    .map_err(|_| SharedAgentHostError::ScopeMismatch)?
            {
                return Err(SharedAgentHostError::Conflict);
            }
            previous
                .verify(target, managed, &RawCredentialVerifier)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            let (receipt, terminal) = issuer
                .recover_finalized_terminal(
                    target,
                    managed,
                    previous.request(),
                    previous.call(),
                    &RawCredentialVerifier,
                )
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?
                .ok_or(SharedAgentHostError::ScopeMismatch)?;
            match (previous.request(), &terminal) {
                (
                    ManagementRequest::Create(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Applied(ack),
                ) => external.verify_finalized_create_ack(ack),
                (
                    ManagementRequest::Install(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Applied(ack),
                ) => external.verify_finalized_install_ack(previous.request(), &receipt, ack),
                (
                    ManagementRequest::Install(_),
                    super::clean_authority_issuer::SignedManagementTerminal::Rejected(failure),
                ) => {
                    external.verify_finalized_install_failure(previous.request(), &receipt, failure)
                }
                _ => return Err(SharedAgentHostError::ScopeMismatch),
            }
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
            slot.stage_external_pending_install(&previous, &next, &submission)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            slot.handoff_retired(&previous, next, &RawCredentialVerifier)
                .map_err(|_| SharedAgentHostError::Unavailable)?;
        } else {
            slot.stage_external_pending_install(&previous, &next, &submission)
                .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        }
        let terminal = system.install_external_local_on_slots(
            &mut slot,
            &mut issuer,
            &mut external,
            submission.package(),
            budget,
            &mut self.signer,
        )?;
        if !slot
            .retirement_complete()
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            match &terminal {
                super::clean_authority_issuer::SignedManagementTerminal::Applied(ack) => {
                    system.finalize_management_intent_with_admission(
                        &mut slot,
                        managed,
                        ack,
                        &mut issuer,
                        true,
                    )?;
                    system.finish_live_management_intent(&mut slot, managed, ack, &issuer)?;
                }
                super::clean_authority_issuer::SignedManagementTerminal::Rejected(failure) => {
                    system.finalize_failed_install_with_admission(
                        &mut slot,
                        managed,
                        failure,
                        &mut issuer,
                        true,
                    )?;
                    system.finish_live_failed_install(&mut slot, managed, failure, &issuer)?;
                }
            }
        }
        match terminal {
            super::clean_authority_issuer::SignedManagementTerminal::Applied(ack) => Ok(ack),
            super::clean_authority_issuer::SignedManagementTerminal::Rejected(_) => {
                Err(SharedAgentHostError::Conflict)
            }
        }
    }

    /// Install into an existing Local Agent, retaining the same exclusive
    /// lifecycle handles on errors. The production owner must publish routes
    /// before treating the returned acknowledgement as an ingress response.
    pub fn install(
        &mut self,
        install: super::sdk::InstallActor,
        call: AuthorityCredentialCall,
        package: super::package_admission::AdmittedActorPackage,
    ) -> Result<ManagementApplicationAck, SharedAgentHostError> {
        let local = match &self.local {
            LocalBacking::Image(local) => local,
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { .. } => return Err(SharedAgentHostError::Unavailable),
        };
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut local = local
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let request = ManagementRequest::Install(Box::new(install));
        system.local_install_intent(&local, &request, &call, &package)?;
        let (intent, issuer) = match self.retained_stores.entry(call.managed.agent) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let stores = self
                    .stores
                    .open_existing(call.managed.space, call.managed.agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                entry.insert(stores)
            }
        };
        system.install_local_actor(
            intent,
            issuer,
            request,
            call,
            &mut local,
            &package,
            &mut self.signer,
        )
    }

    /// Complete Create/application/finalization, retaining evidence for later
    /// authenticated publication. This does not itself publish ingress routes.
    pub fn create(
        &mut self,
        descriptor: AgentDescriptor,
        call: AuthorityCredentialCall,
        runtime: AdmittedRuntimePackage,
    ) -> Result<(AgentId, ManagementApplicationAck), SharedAgentHostError> {
        let local = match &self.local {
            LocalBacking::Image(local) => local,
            #[cfg(all(
                target_os = "linux",
                feature = "storage",
                feature = "experimental-state-blocks"
            ))]
            LocalBacking::External { .. } => return Err(SharedAgentHostError::Unavailable),
        };
        let mut system = self
            .system
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut local = local
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if descriptor.identity.profile != AgentProfile::Local
            || descriptor.identity.space != local.space()
            || descriptor.replicas.len() != 1
            || descriptor.replicas[0].node != local.node()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        super::driver::verify_clean_runtime_package_binding(&descriptor, &runtime)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        // Authenticate before a filesystem factory can create a directory.
        super::clean_management_intent::CleanManagementIntent::new(
            system.authority_target(),
            call.managed,
            ManagementRequest::Create(Box::new(descriptor.clone())),
            call.clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )
        .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let entry = self.retained_stores.entry(descriptor.identity.agent);
        let (intent, issuer) = match entry {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let stores = self
                    .stores
                    .open(descriptor.identity.space, descriptor.identity.agent)
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                entry.insert(stores)
            }
        };
        system.create_local_agent(
            intent,
            issuer,
            descriptor,
            call,
            &mut local,
            runtime,
            &mut self.signer,
        )
    }
}
