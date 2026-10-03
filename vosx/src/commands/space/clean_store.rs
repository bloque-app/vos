//! Hardened whole-image stores for clean system-Agent bootstrap state.
//!
//! The directory is a dedicated, single-writer namespace. Each logical image
//! has fixed names or names derived from a validated invocation ID; callers
//! cannot supply paths. Files contain a role-bound integrity envelope, while the persistence
//! traits continue to return the caller's exact image bytes. The envelope also
//! binds a staged replacement to the exact canonical predecessor, allowing
//! restart to finish only an unambiguous publication.

#[cfg(unix)]
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use fs2::FileExt as _;
use vos::agent::authority_operation_coordinator::{
    AuthorityOperationCoordinatorStore, MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES,
};
use vos::agent::authority_operation_issuer::{
    AuthorityOperationIssuerStore, MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES,
};
use vos::agent::bootstrap::MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES;
#[cfg(feature = "experimental-state-blocks")]
use vos::agent::clean_authority_issuer::CleanExternalLocalPendingInstallStore;
use vos::agent::clean_authority_issuer::{
    CleanExternalLocalCreateArchiveStore, CleanManagementActorStore, CleanManagementIssuerStore,
    CleanManagementRuntimeStore, CleanSharedGenesisReplicaStore, CleanSharedManagementIntentStore,
    CleanSharedManagementIssuerStore, MAX_CLEAN_EXTERNAL_LOCAL_CREATE_ARCHIVE_BYTES,
    MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES, MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES,
};
use vos::agent::clean_bootstrap::{
    CleanSystemAgentBootstrapStore, MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES,
    MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES,
};
#[cfg(target_os = "linux")]
use vos::agent::clean_bootstrap::{
    MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES, NativeAuthorityOperationJournalStore,
    native_operation_record_matches,
};
use vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES;

#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

const LOCK_FILE: &str = "lock";
const PINS_FILE: &str = "system-agent.pins";
const PINS_STAGE_FILE: &str = "system-agent.pins.next";
const BOOTSTRAP_FILE: &str = "system-agent.bootstrap";
const BOOTSTRAP_STAGE_FILE: &str = "system-agent.bootstrap.next";
const ISSUER_FILE: &str = "system-agent.management-issuer";
const ISSUER_STAGE_FILE: &str = "system-agent.management-issuer.next";
const GENESIS_FILE: &str = "system-agent.genesis-archive";
const GENESIS_STAGE_FILE: &str = "system-agent.genesis-archive.next";
const INTENT_FILE: &str = "management.intent";
const INTENT_STAGE_FILE: &str = "management.intent.next";
const LIFECYCLE_ISSUER_FILE: &str = "management.issuer";
const LIFECYCLE_ISSUER_STAGE_FILE: &str = "management.issuer.next";
const LIFECYCLE_RUNTIME_FILE: &str = "management.runtime";
const LIFECYCLE_RUNTIME_STAGE_FILE: &str = "management.runtime.next";
const LIFECYCLE_ACTOR_FILE: &str = "management.actor";
const LIFECYCLE_ACTOR_STAGE_FILE: &str = "management.actor.next";
const LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_FILE: &str = "management.external-create";
const LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE: &str = "management.external-create.next";
const LIFECYCLE_PENDING_INSTALL_FILE: &str = "management.pending-install";
const LIFECYCLE_PENDING_INSTALL_STAGE_FILE: &str = "management.pending-install.next";
pub(crate) const SHARED_LIFECYCLE_DIRECTORY: &str = "shared-agent-lifecycle";
pub(crate) const SHARED_COMMITTEE_DIRECTORY: &str = "shared-agent-committee";
pub(crate) const SHARED_ARCHIVE_DIRECTORY: &str = "shared-agent-genesis";
const LOCAL_REQUEST_FILE: &str = "local-create.request";
const LOCAL_REQUEST_STAGE_FILE: &str = "local-create.request.next";
const LOCAL_REQUEST_ENTRIES: [&str; 3] = [LOCK_FILE, LOCAL_REQUEST_FILE, LOCAL_REQUEST_STAGE_FILE];
const LOCAL_ACK_FILE: &str = "local-create.acknowledgement";
const LOCAL_ACK_STAGE_FILE: &str = "local-create.acknowledgement.next";
const LOCAL_ACK_ENTRIES: [&str; 3] = [LOCK_FILE, LOCAL_ACK_FILE, LOCAL_ACK_STAGE_FILE];
const LOCAL_DENIAL_FILE: &str = "local-create.denial";
const LOCAL_DENIAL_STAGE_FILE: &str = "local-create.denial.next";
const LOCAL_DENIAL_ENTRIES: [&str; 3] = [LOCK_FILE, LOCAL_DENIAL_FILE, LOCAL_DENIAL_STAGE_FILE];
const CREDENTIAL_QUERY_FILE: &str = "credential.query";
const RESERVATION_FILE: &str = "credential.reservation";
const RESERVATION_STAGE_FILE: &str = "credential.reservation.next";
const RESERVATION_ENTRIES: [&str; 3] = [LOCK_FILE, RESERVATION_FILE, RESERVATION_STAGE_FILE];
const CREDENTIAL_QUERY_STAGE_FILE: &str = "credential.query.next";
const CREDENTIAL_QUERY_ENTRIES: [&str; 3] = [
    LOCK_FILE,
    CREDENTIAL_QUERY_FILE,
    CREDENTIAL_QUERY_STAGE_FILE,
];
const LIFECYCLE_ENTRIES: [&str; 11] = [
    LOCK_FILE,
    INTENT_FILE,
    INTENT_STAGE_FILE,
    LIFECYCLE_ISSUER_FILE,
    LIFECYCLE_ISSUER_STAGE_FILE,
    LIFECYCLE_RUNTIME_FILE,
    LIFECYCLE_RUNTIME_STAGE_FILE,
    LIFECYCLE_ACTOR_FILE,
    LIFECYCLE_ACTOR_STAGE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE,
];
const EXTERNAL_LIFECYCLE_ENTRIES: [&str; 13] = [
    LOCK_FILE,
    INTENT_FILE,
    INTENT_STAGE_FILE,
    LIFECYCLE_ISSUER_FILE,
    LIFECYCLE_ISSUER_STAGE_FILE,
    LIFECYCLE_RUNTIME_FILE,
    LIFECYCLE_RUNTIME_STAGE_FILE,
    LIFECYCLE_ACTOR_FILE,
    LIFECYCLE_ACTOR_STAGE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE,
    LIFECYCLE_PENDING_INSTALL_FILE,
    LIFECYCLE_PENDING_INSTALL_STAGE_FILE,
];

const SHARED_LIFECYCLE_ENTRIES: [&str; 21] = [
    LOCK_FILE,
    INTENT_FILE,
    INTENT_STAGE_FILE,
    LIFECYCLE_ISSUER_FILE,
    LIFECYCLE_ISSUER_STAGE_FILE,
    LIFECYCLE_RUNTIME_FILE,
    LIFECYCLE_RUNTIME_STAGE_FILE,
    LIFECYCLE_ACTOR_FILE,
    LIFECYCLE_ACTOR_STAGE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_FILE,
    LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE,
    "shared-management.issuer",
    "shared-management.issuer.next",
    "shared-management.handoff",
    "shared-management.handoff.next",
    "shared-management.intent",
    "shared-management.intent.next",
    "shared-management.actor",
    "shared-management.actor.next",
    "shared-management.install-handoff",
    "shared-management.install-handoff.next",
];

#[derive(Clone, Copy)]
enum LifecycleLayout {
    ImageLocal,
    ExternalLocal,
    Shared,
}

impl LifecycleLayout {
    fn entries(self) -> &'static [&'static str] {
        match self {
            Self::ImageLocal => &LIFECYCLE_ENTRIES,
            Self::ExternalLocal => &EXTERNAL_LIFECYCLE_ENTRIES,
            Self::Shared => &SHARED_LIFECYCLE_ENTRIES,
        }
    }
}

pub(crate) const MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES: usize =
    MAX_SYSTEM_AGENT_GENESIS_PROVISION_BYTES + MAX_PACKAGE_ENCODED_BYTES + 1024;

const STORE_MAGIC: [u8; 4] = *b"CSF1";
const STORE_VERSION: u8 = 1;
const STORE_HEADER_BYTES: usize = 80;
const NO_PREDECESSOR: [u8; 32] = [0; 32];
const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"vos/clean-system-agent/file-envelope/v1";

const ALLOWED_ENTRIES: [&str; 9] = [
    LOCK_FILE,
    PINS_FILE,
    PINS_STAGE_FILE,
    BOOTSTRAP_FILE,
    BOOTSTRAP_STAGE_FILE,
    ISSUER_FILE,
    ISSUER_STAGE_FILE,
    GENESIS_FILE,
    GENESIS_STAGE_FILE,
];

/// Failure at the physical clean-system-Agent persistence boundary.
///
/// Structural failures are kept separate from I/O failures so startup can
/// distinguish an unavailable filesystem from state that must never be
/// selected automatically.
#[derive(Debug)]
pub(crate) enum CleanFileStoreError {
    InvalidPath,
    InsecureParent,
    InsecureRoot,
    InsecurePermissions,
    Busy,
    Alias,
    HardLink,
    NonRegular,
    UnexpectedResidue,
    WrongStoreRole,
    Oversized,
    Corrupt,
    AmbiguousPublication,
    StageCollision,
    RequestConflict,
    LockPoisoned,
    Io(io::Error),
}

impl fmt::Display for CleanFileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "clean store I/O failure: {error}"),
            other => write!(formatter, "clean store rejected physical state: {other:?}"),
        }
    }
}

impl std::error::Error for CleanFileStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CleanFileStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum StoreRole {
    Pins = 1,
    Bootstrap = 2,
    ManagementIssuer = 3,
    GenesisArchive = 4,
    ManagementIntent = 5,
    LifecycleIssuer = 6,
    LocalCreateRequest = 7,
    CredentialQuery = 8,
    CredentialReservation = 9,
    LocalCreateAcknowledgement = 10,
    LifecycleRuntime = 11,
    LocalCreateDenial = 12,
    LifecycleActor = 13,
    LocalInstallRequest = 14,
    LocalInstallAcknowledgement = 15,
    InvocationRequest = 16,
    InvocationResponse = 17,
    InvocationProgress = 18,
    OperationCoordinator = 19,
    OperationIssuer = 20,
    OperationDispatch = 21,
    OperationCompletions = 22,
    OperationRetirements = 23,
    OperationDenials = 24,
    OperationRequest = 25,
    OperationResponse = 26,
    PreparationRequest = 27,
    PreparationResponse = 28,
    AuthorizationPreparationRequest = 29,
    AuthorizationPreparationResponse = 30,
    AdminDispatch = 31,
    AdminResult = 32,
    AdminRetirement = 33,
    AdminPreparationRequest = 34,
    AdminPreparationResponse = 35,
    AdminClientRequest = 36,
    AdminClientResponse = 37,
    AdminCredentialReservation = 38,
    OrdinaryGenesisArchive = 39,
    OrdinaryGenesisSignature = 40,
    OrdinaryGenesisQuery = 41,
    OrdinaryGenesisReply = 42,
    OrdinaryGenesisPublication = 43,
    OrdinaryGenesisPublicationReply = 44,
    ExternalLocalCreateArchive = 45,
    ExternalLocalPendingInstall = 46,
    OrdinaryGenesisReplicas = 47,
    SharedManagementIssuer = 48,
    SharedManagementHandoff = 49,
    SharedManagementIntent = 50,
    SharedManagementActor = 51,
    SharedInstallHandoff = 52,
}

impl StoreRole {
    const fn file(self) -> &'static str {
        match self {
            Self::Pins => PINS_FILE,
            Self::Bootstrap => BOOTSTRAP_FILE,
            Self::ManagementIssuer => ISSUER_FILE,
            Self::GenesisArchive => GENESIS_FILE,
            Self::ManagementIntent => INTENT_FILE,
            Self::LifecycleIssuer => LIFECYCLE_ISSUER_FILE,
            Self::SharedManagementIssuer => "shared-management.issuer",
            Self::SharedManagementHandoff => "shared-management.handoff",
            Self::SharedManagementIntent => "shared-management.intent",
            Self::SharedManagementActor => "shared-management.actor",
            Self::SharedInstallHandoff => "shared-management.install-handoff",
            Self::LocalCreateRequest => LOCAL_REQUEST_FILE,
            Self::CredentialQuery => CREDENTIAL_QUERY_FILE,
            Self::CredentialReservation => RESERVATION_FILE,
            Self::LocalCreateAcknowledgement => LOCAL_ACK_FILE,
            Self::LifecycleRuntime => LIFECYCLE_RUNTIME_FILE,
            Self::LocalCreateDenial => LOCAL_DENIAL_FILE,
            Self::LifecycleActor => LIFECYCLE_ACTOR_FILE,
            Self::ExternalLocalCreateArchive => LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_FILE,
            Self::ExternalLocalPendingInstall => LIFECYCLE_PENDING_INSTALL_FILE,
            Self::LocalInstallRequest => "local-install.request",
            Self::LocalInstallAcknowledgement => "local-install.acknowledgement",
            Self::InvocationRequest => "invocation.request",
            Self::InvocationResponse => "invocation.response",
            Self::InvocationProgress => "invocation.progress",
            Self::OperationCoordinator => "authority-operation.coordinator",
            Self::OperationIssuer => "authority-operation.issuer",
            Self::OperationDispatch => "authority-operation.dispatch",
            Self::OperationCompletions => "authority-operation.completions",
            Self::OperationRetirements => "authority-operation.retirements",
            Self::OperationDenials => "authority-operation.denials",
            Self::OperationRequest => "operation.request",
            Self::OperationResponse => "operation.response",
            Self::PreparationRequest => "preparation.request",
            Self::PreparationResponse => "preparation.response",
            Self::AuthorizationPreparationRequest => "authorization-preparation.request",
            Self::AuthorizationPreparationResponse => "authorization-preparation.response",
            Self::AdminDispatch => "admin.dispatch",
            Self::AdminResult => "admin.result",
            Self::AdminRetirement => "admin.retirement",
            Self::AdminPreparationRequest => "admin-preparation.request",
            Self::AdminPreparationResponse => "admin-preparation.response",
            Self::AdminClientRequest => "admin-client.request",
            Self::AdminClientResponse => "admin-client.response",
            Self::AdminCredentialReservation => "admin-credential.reservation",
            Self::OrdinaryGenesisArchive => "ordinary-agent.genesis-archive",
            Self::OrdinaryGenesisSignature => "ordinary-agent.genesis-signature",
            Self::OrdinaryGenesisQuery => "ordinary-agent.genesis-query",
            Self::OrdinaryGenesisReply => "ordinary-agent.genesis-reply",
            Self::OrdinaryGenesisPublication => "ordinary-agent.genesis-publication",
            Self::OrdinaryGenesisPublicationReply => "ordinary-agent.genesis-publication-reply",
            Self::OrdinaryGenesisReplicas => "ordinary-agent.genesis-replicas",
        }
    }

    const fn stage_file(self) -> &'static str {
        match self {
            Self::Pins => PINS_STAGE_FILE,
            Self::Bootstrap => BOOTSTRAP_STAGE_FILE,
            Self::ManagementIssuer => ISSUER_STAGE_FILE,
            Self::GenesisArchive => GENESIS_STAGE_FILE,
            Self::ManagementIntent => INTENT_STAGE_FILE,
            Self::LifecycleIssuer => LIFECYCLE_ISSUER_STAGE_FILE,
            Self::SharedManagementIssuer => "shared-management.issuer.next",
            Self::SharedManagementHandoff => "shared-management.handoff.next",
            Self::SharedManagementIntent => "shared-management.intent.next",
            Self::SharedManagementActor => "shared-management.actor.next",
            Self::SharedInstallHandoff => "shared-management.install-handoff.next",
            Self::LocalCreateRequest => LOCAL_REQUEST_STAGE_FILE,
            Self::CredentialQuery => CREDENTIAL_QUERY_STAGE_FILE,
            Self::CredentialReservation => RESERVATION_STAGE_FILE,
            Self::LocalCreateAcknowledgement => LOCAL_ACK_STAGE_FILE,
            Self::LifecycleRuntime => LIFECYCLE_RUNTIME_STAGE_FILE,
            Self::LocalCreateDenial => LOCAL_DENIAL_STAGE_FILE,
            Self::LifecycleActor => LIFECYCLE_ACTOR_STAGE_FILE,
            Self::ExternalLocalCreateArchive => LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE,
            Self::ExternalLocalPendingInstall => LIFECYCLE_PENDING_INSTALL_STAGE_FILE,
            Self::LocalInstallRequest => "local-install.request.next",
            Self::LocalInstallAcknowledgement => "local-install.acknowledgement.next",
            Self::InvocationRequest => "invocation.request.next",
            Self::InvocationResponse => "invocation.response.next",
            Self::InvocationProgress => "invocation.progress.next",
            Self::OperationCoordinator => "authority-operation.coordinator.next",
            Self::OperationIssuer => "authority-operation.issuer.next",
            Self::OperationDispatch => "authority-operation.dispatch.next",
            Self::OperationCompletions => "authority-operation.completions.next",
            Self::OperationRetirements => "authority-operation.retirements.next",
            Self::OperationDenials => "authority-operation.denials.next",
            Self::OperationRequest => "operation.request.next",
            Self::OperationResponse => "operation.response.next",
            Self::PreparationRequest => "preparation.request.next",
            Self::PreparationResponse => "preparation.response.next",
            Self::AuthorizationPreparationRequest => "authorization-preparation.request.next",
            Self::AuthorizationPreparationResponse => "authorization-preparation.response.next",
            Self::AdminDispatch => "admin.dispatch.next",
            Self::AdminResult => "admin.result.next",
            Self::AdminRetirement => "admin.retirement.next",
            Self::AdminPreparationRequest => "admin-preparation.request.next",
            Self::AdminPreparationResponse => "admin-preparation.response.next",
            Self::AdminClientRequest => "admin-client.request.next",
            Self::AdminClientResponse => "admin-client.response.next",
            Self::AdminCredentialReservation => "admin-credential.reservation.next",
            Self::OrdinaryGenesisArchive => "ordinary-agent.genesis-archive.next",
            Self::OrdinaryGenesisSignature => "ordinary-agent.genesis-signature.next",
            Self::OrdinaryGenesisQuery => "ordinary-agent.genesis-query.next",
            Self::OrdinaryGenesisReply => "ordinary-agent.genesis-reply.next",
            Self::OrdinaryGenesisPublication => "ordinary-agent.genesis-publication.next",
            Self::OrdinaryGenesisPublicationReply => {
                "ordinary-agent.genesis-publication-reply.next"
            }
            Self::OrdinaryGenesisReplicas => "ordinary-agent.genesis-replicas.next",
        }
    }

    const fn maximum_bytes(self) -> usize {
        match self {
            Self::AdminPreparationRequest
            | Self::AdminPreparationResponse
            | Self::AdminClientRequest
            | Self::AdminClientResponse => {
                #[cfg(target_os = "linux")]
                {
                    use vos::agent::clean_bootstrap::{
                        NativeAuthorityAdminCompletion, NativeAuthorityAdminPreparation,
                        NativeAuthorityAdminSubmission,
                    };
                    use vos::agent::sdk::wire::CanonicalWire as _;
                    match self {
                        Self::AdminPreparationRequest => {
                            vos::agent::sdk::authority::AuthorityAdminCall::MAX_ENCODED_BYTES
                        }
                        Self::AdminPreparationResponse => {
                            NativeAuthorityAdminPreparation::MAX_ENCODED_BYTES
                        }
                        Self::AdminClientRequest => {
                            NativeAuthorityAdminSubmission::MAX_ENCODED_BYTES
                        }
                        _ => NativeAuthorityAdminCompletion::MAX_BYTES,
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    0
                }
            }
            Self::AdminDispatch | Self::AdminResult | Self::AdminRetirement => {
                #[cfg(target_os = "linux")]
                {
                    if matches!(self, Self::AdminDispatch) {
                        vos::agent::clean_bootstrap::MAX_NATIVE_AUTHORITY_ADMIN_DISPATCH_BYTES
                    } else {
                        vos::agent::clean_bootstrap::MAX_NATIVE_AUTHORITY_ADMIN_TERMINAL_BYTES
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    0
                }
            }
            Self::Pins => MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES,
            Self::Bootstrap => MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES,
            Self::ManagementIssuer => MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES,
            Self::GenesisArchive => MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES,
            Self::OrdinaryGenesisArchive => {
                vos::agent::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES
            }
            Self::OrdinaryGenesisSignature => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_SIGNATURE_IMAGE_BYTES
            }
            Self::OrdinaryGenesisQuery => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_QUERY_IMAGE_BYTES
            }
            Self::OrdinaryGenesisReply => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_REPLY_IMAGE_BYTES
            }
            Self::OrdinaryGenesisPublication => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_IMAGE_BYTES
            }
            Self::OrdinaryGenesisPublicationReply => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_GENESIS_PUBLICATION_REPLY_IMAGE_BYTES
            }
            Self::OrdinaryGenesisReplicas => vos::agent::genesis::MAX_AGENT_REPLICA_COMMITTEE_BYTES,
            Self::ManagementIntent => MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES,
            Self::LifecycleIssuer | Self::SharedManagementIssuer => {
                MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES
            }
            Self::SharedManagementHandoff => 36,
            Self::SharedManagementIntent => MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES,
            Self::SharedManagementActor => MAX_PACKAGE_ENCODED_BYTES,
            Self::SharedInstallHandoff => {
                vos::agent::clean_authority_issuer::MAX_CLEAN_SHARED_INSTALL_HANDOFF_BYTES
            }
            // Retains LCQ1 or the strictly larger SCQ1 ordinary Shared Create.
            Self::LocalCreateRequest => {
                vos::agent::local_lifecycle::SharedCreateSubmission::MAX_BYTES
            }
            Self::LocalInstallRequest => {
                vos::agent::local_lifecycle::LocalInstallSubmission::MAX_BYTES
            }
            Self::InvocationRequest => super::local_invocation::MAX_REQUEST_BYTES,
            Self::InvocationResponse => super::local_invocation::MAX_RESPONSE_BYTES,
            Self::InvocationProgress => super::invocation_progress::MAX_PROGRESS_BYTES,
            Self::OperationCoordinator => MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES,
            Self::OperationIssuer => MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES,
            Self::OperationCompletions => 40 + 256 * (4 + 512),
            Self::OperationRetirements => 40 + 256 * (4 + 1024),
            Self::OperationDenials => 40 + 256 * (4 + 512),
            Self::AuthorizationPreparationRequest => {
                vos::agent::sdk::authority_operation::MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
            }
            Self::OperationRequest | Self::AuthorizationPreparationResponse => {
                32 + vos::agent::sdk::authority_operation::MAX_AUTHORITY_OPERATION_CALL_WIRE_BYTES
                    + vos::agent::sdk::wire::MAX_INVOCATION_CONTEXT_WIRE_BYTES
            }
            Self::PreparationRequest => super::local_invocation::MAX_REQUEST_BYTES,
            Self::PreparationResponse => {
                use vos::agent::sdk::wire::CanonicalWire as _;
                vos::agent::supervisor_adapters::AgentTargetedPreparationResponse::MAX_ENCODED_BYTES
            }
            Self::OperationResponse => {
                #[cfg(target_os = "linux")]
                {
                    vos::agent::local_lifecycle::AuthorityOperationSubmission::MAX_RESPONSE_BYTES
                }
                #[cfg(not(target_os = "linux"))]
                {
                    0
                }
            }
            Self::OperationDispatch => {
                #[cfg(target_os = "linux")]
                {
                    MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES
                }
                #[cfg(not(target_os = "linux"))]
                {
                    0
                }
            }
            Self::LifecycleRuntime => MAX_PACKAGE_ENCODED_BYTES,
            Self::LifecycleActor => MAX_PACKAGE_ENCODED_BYTES,
            Self::ExternalLocalCreateArchive => MAX_CLEAN_EXTERNAL_LOCAL_CREATE_ARCHIVE_BYTES,
            Self::ExternalLocalPendingInstall => {
                vos::agent::local_lifecycle::LocalInstallSubmission::MAX_BYTES
            }
            Self::LocalCreateDenial => vos::agent::local_lifecycle::LocalCreateDenial::MAX_BYTES,
            Self::CredentialReservation | Self::AdminCredentialReservation => 165,
            Self::LocalCreateAcknowledgement | Self::LocalInstallAcknowledgement => {
                vos::agent::sdk::wire::MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES
            }
            Self::CredentialQuery => {
                vos::agent::sdk::wire::MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES
            }
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            16 => Some(Self::InvocationRequest),
            17 => Some(Self::InvocationResponse),
            18 => Some(Self::InvocationProgress),
            19 => Some(Self::OperationCoordinator),
            20 => Some(Self::OperationIssuer),
            21 => Some(Self::OperationDispatch),
            22 => Some(Self::OperationCompletions),
            23 => Some(Self::OperationRetirements),
            24 => Some(Self::OperationDenials),
            25 => Some(Self::OperationRequest),
            26 => Some(Self::OperationResponse),
            27 => Some(Self::PreparationRequest),
            28 => Some(Self::PreparationResponse),
            29 => Some(Self::AuthorizationPreparationRequest),
            30 => Some(Self::AuthorizationPreparationResponse),
            31 => Some(Self::AdminDispatch),
            32 => Some(Self::AdminResult),
            33 => Some(Self::AdminRetirement),
            34 => Some(Self::AdminPreparationRequest),
            35 => Some(Self::AdminPreparationResponse),
            36 => Some(Self::AdminClientRequest),
            37 => Some(Self::AdminClientResponse),
            38 => Some(Self::AdminCredentialReservation),
            39 => Some(Self::OrdinaryGenesisArchive),
            40 => Some(Self::OrdinaryGenesisSignature),
            41 => Some(Self::OrdinaryGenesisQuery),
            42 => Some(Self::OrdinaryGenesisReply),
            43 => Some(Self::OrdinaryGenesisPublication),
            44 => Some(Self::OrdinaryGenesisPublicationReply),
            45 => Some(Self::ExternalLocalCreateArchive),
            46 => Some(Self::ExternalLocalPendingInstall),
            47 => Some(Self::OrdinaryGenesisReplicas),
            48 => Some(Self::SharedManagementIssuer),
            49 => Some(Self::SharedManagementHandoff),
            50 => Some(Self::SharedManagementIntent),
            51 => Some(Self::SharedManagementActor),
            52 => Some(Self::SharedInstallHandoff),
            1 => Some(Self::Pins),
            2 => Some(Self::Bootstrap),
            3 => Some(Self::ManagementIssuer),
            4 => Some(Self::GenesisArchive),
            5 => Some(Self::ManagementIntent),
            6 => Some(Self::LifecycleIssuer),
            7 => Some(Self::LocalCreateRequest),
            8 => Some(Self::CredentialQuery),
            9 => Some(Self::CredentialReservation),
            10 => Some(Self::LocalCreateAcknowledgement),
            11 => Some(Self::LifecycleRuntime),
            12 => Some(Self::LocalCreateDenial),
            13 => Some(Self::LifecycleActor),
            14 => Some(Self::LocalInstallRequest),
            15 => Some(Self::LocalInstallAcknowledgement),
            _ => None,
        }
    }
}

/// The three independently addressable files under one shared writer lease.
pub(crate) struct CleanSystemAgentFileStores {
    pins: CleanSystemAgentPinsFile,
    bootstrap: CleanSystemAgentBootstrapFile,
    issuer: CleanManagementIssuerFile,
    genesis: CleanSystemAgentGenesisFile,
}

impl CleanSystemAgentFileStores {
    /// Open or create one dedicated clean store directory.
    ///
    /// The immediate parent must already be an absolute, canonical, private
    /// directory. A missing final directory is created as `0700`; existing
    /// directories and all existing entries are verified before any image is
    /// read or changed.
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_or_create(root.as_ref())?);
        Ok(Self {
            pins: CleanSystemAgentPinsFile(ExactFileStore::new(Arc::clone(&root), StoreRole::Pins)),
            bootstrap: CleanSystemAgentBootstrapFile(ExactFileStore::new(
                Arc::clone(&root),
                StoreRole::Bootstrap,
            )),
            issuer: CleanManagementIssuerFile(ExactFileStore::new(
                Arc::clone(&root),
                StoreRole::ManagementIssuer,
            )),
            genesis: CleanSystemAgentGenesisFile(ExactFileStore::new(
                root,
                StoreRole::GenesisArchive,
            )),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CleanSystemAgentPinsFile,
        CleanSystemAgentBootstrapFile,
        CleanManagementIssuerFile,
    ) {
        (self.pins, self.bootstrap, self.issuer)
    }

    pub(crate) fn into_production_parts(
        self,
    ) -> (
        CleanSystemAgentPinsFile,
        CleanSystemAgentBootstrapFile,
        CleanManagementIssuerFile,
        CleanSystemAgentGenesisFile,
    ) {
        (self.pins, self.bootstrap, self.issuer, self.genesis)
    }
}

pub(crate) struct CleanSystemAgentPinsFile(ExactFileStore);
pub(crate) struct CleanSystemAgentBootstrapFile(ExactFileStore);
pub(crate) struct CleanManagementIssuerFile(ExactFileStore);
pub(crate) struct CleanSystemAgentGenesisFile(ExactFileStore);

/// One immutable ordinary-genesis record under a locator-derived directory
/// and exclusive writer lease. The provider validates the opaque record;
/// this backend owns physical bounds, atomicity and durability only.
pub(crate) struct CleanAgentGenesisArchiveFile {
    locator: vos::agent::genesis::AgentGenesisLocator,
    store: Mutex<ExactFileStore>,
}

impl CleanAgentGenesisArchiveFile {
    pub(crate) fn open_or_create(
        parent: &Path,
        locator: vos::agent::genesis::AgentGenesisLocator,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open(parent, locator, true)
    }

    fn open(
        parent: &Path,
        locator: vos::agent::genesis::AgentGenesisLocator,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        locator
            .validate()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let path = parent.join(format!(
            "genesis-{}-{}",
            hex::encode(locator.space.0),
            hex::encode(locator.agent.0)
        ));
        let root = Arc::new(StoreRoot::open_with_entries_mode(
            &path,
            &[
                LOCK_FILE,
                "ordinary-agent.genesis-archive",
                "ordinary-agent.genesis-archive.next",
            ],
            create,
        )?);
        Ok(Self {
            locator,
            store: Mutex::new(ExactFileStore::new(root, StoreRole::OrdinaryGenesisArchive)),
        })
    }
}

/// Non-creating archive discovery for ordinary Shared startup. The caller must
/// compare the complete discovered set with lifecycle reservations and retain
/// all opened leases. Directory membership and image integrity are not finality.
pub(crate) struct CleanAgentGenesisArchiveStoreFactory {
    parent: PathBuf,
    directory: File,
    space: vos::service::SpaceId,
}

impl CleanAgentGenesisArchiveStoreFactory {
    pub(crate) fn open_existing(
        parent: &Path,
        space: vos::service::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::service::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            directory: open_private_directory(parent, true)?,
            space,
        })
    }

    pub(crate) fn discover(
        &self,
        maximum: usize,
    ) -> Result<Vec<vos::agent::genesis::AgentGenesisLocator>, CleanFileStoreError> {
        discover_genesis_directories(
            &self.directory,
            &self.parent,
            self.space,
            "genesis",
            maximum,
        )
    }

    pub(crate) fn open_archive(
        &self,
        locator: vos::agent::genesis::AgentGenesisLocator,
    ) -> Result<CleanAgentGenesisArchiveFile, CleanFileStoreError> {
        if locator.space != self.space {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let archive = CleanAgentGenesisArchiveFile::open(&self.parent, locator, false)?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok(archive)
    }
}

fn discover_genesis_directories(
    directory: &File,
    parent: &Path,
    space: vos::service::SpaceId,
    kind: &str,
    maximum: usize,
) -> Result<Vec<vos::agent::genesis::AgentGenesisLocator>, CleanFileStoreError> {
    validate_opened_directory(directory, parent, true)?;
    #[cfg(target_os = "linux")]
    let scan = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    #[cfg(not(target_os = "linux"))]
    let scan: PathBuf = return Err(CleanFileStoreError::InvalidPath);
    let prefix = format!("{kind}-{}-", hex::encode(space.0));
    let mut found = Vec::new();
    for entry in fs::read_dir(scan)? {
        let entry = entry?;
        if found.len() == maximum {
            return Err(CleanFileStoreError::Oversized);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
        let suffix = name
            .strip_prefix(&prefix)
            .ok_or(CleanFileStoreError::UnexpectedResidue)?;
        if suffix.len() != 64
            || !suffix
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(suffix, &mut bytes)
            .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId(bytes),
        };
        locator
            .validate()
            .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
        let path = parent.join(&name);
        let child = open_child_directory(directory, &path)?;
        validate_opened_directory(&child, &path, false)?;
        found.push(locator);
    }
    validate_opened_directory(directory, parent, true)?;
    found.sort_unstable_by_key(|locator| locator.agent);
    if found.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CleanFileStoreError::Alias);
    }
    Ok(found)
}

impl vos::agent::genesis_archive::AgentGenesisArchiveStore for CleanAgentGenesisArchiveFile {
    type Error = CleanFileStoreError;

    fn load(
        &self,
        locator: vos::agent::genesis::AgentGenesisLocator,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        if locator != self.locator {
            return Err(CleanFileStoreError::Corrupt);
        }
        let mut file = self
            .store
            .lock()
            .map_err(|_| CleanFileStoreError::LockPoisoned)?;
        let image = file.load(StoreRole::OrdinaryGenesisArchive.maximum_bytes())?;
        if let Some(bytes) = &image {
            // A prior rename may have succeeded before a directory-sync error.
            // Re-establish the durability barrier before an exact retry succeeds.
            file.commit_with_replacement(bytes, false)?;
        }
        Ok(image)
    }

    fn insert_if_absent(
        &self,
        locator: vos::agent::genesis::AgentGenesisLocator,
        record: &[u8],
    ) -> Result<(), Self::Error> {
        if locator != self.locator {
            return Err(CleanFileStoreError::Corrupt);
        }
        if record.len() > StoreRole::OrdinaryGenesisArchive.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let mut file = self
            .store
            .lock()
            .map_err(|_| CleanFileStoreError::LockPoisoned)?;
        let existing = file.load(StoreRole::OrdinaryGenesisArchive.maximum_bytes())?;
        // Immutable insertion returns the existing winner, even if different;
        // the provider reloads and reports Conflict without overwriting it.
        file.commit_with_replacement(existing.as_deref().unwrap_or(record), false)
    }
}

/// Exclusively leased signature pledge/result slot for one Agent and signer.
/// The file envelope proves integrity only; the issuance protocol must verify
/// the replay-authorized candidate, trusted committee and retained signature.
pub(crate) struct CleanAgentGenesisSignatureFile(ExactFileStore);

/// Query and reply share a lifecycle lease; dropping either handle alone must
/// not admit a second writer. File integrity does not authenticate a committee.
pub(crate) struct CleanAgentGenesisCommitteeFile(ExactFileStore);

const GENESIS_COMMITTEE_ENTRIES: &[&str] = &[
    LOCK_FILE,
    "ordinary-agent.genesis-replicas",
    "ordinary-agent.genesis-replicas.next",
    "ordinary-agent.genesis-query",
    "ordinary-agent.genesis-query.next",
    "ordinary-agent.genesis-reply",
    "ordinary-agent.genesis-reply.next",
    "ordinary-agent.genesis-publication",
    "ordinary-agent.genesis-publication.next",
    "ordinary-agent.genesis-publication-reply",
    "ordinary-agent.genesis-publication-reply.next",
];

/// Descriptor-pinned, space-scoped discovery under a dedicated private parent.
/// Discovery does not open images or acquire/release their writer leases.
pub(crate) struct CleanAgentGenesisCommitteeStoreFactory {
    parent: PathBuf,
    directory: File,
    space: vos::service::SpaceId,
}

pub(crate) type CleanSharedGenesisRecovery =
    vos::agent::clean_bootstrap::NativeSharedGenesisRecovery<
        CleanManagementIntentFile,
        CleanManagementIssuerFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
    >;

pub(crate) type CleanSharedGenesisController =
    vos::agent::clean_bootstrap::NativeSharedGenesisController<
        CleanManagementIntentFile,
        CleanManagementIssuerFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisCommitteeFile,
        CleanAgentGenesisArchiveFile,
    >;

/// File-backed admission for ordinary Shared Create. The lifecycle owner must
/// serialize calls with its other management admissions. Factories pin parent
/// identities; returned entries retain the per-Agent leases until retirement
/// and shutdown. Reserving inputs neither executes Authority nor grants a route.
pub(crate) struct CleanSharedGenesisStoreFactory {
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    maximum: usize,
    lifecycle: CleanManagementLifecycleStoreFactory,
    committee: CleanAgentGenesisCommitteeStoreFactory,
    archives: CleanAgentGenesisArchiveStoreFactory,
}

/// Pins the Space directory at startup without creating Shared control roots.
/// The lifecycle owner retains this factory and serializes its first use.
pub(crate) struct CleanSharedGenesisAdmissionFiles {
    data_dir: PathBuf,
    directory: File,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    maximum: usize,
    files: Option<CleanSharedGenesisStoreFactory>,
}

impl CleanSharedGenesisAdmissionFiles {
    pub(crate) fn open(
        data_dir: &Path,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        maximum: usize,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid()
            || maximum == 0
            || maximum > vos::agent::shared_host::MAX_SHARED_HOST_AGENTS
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            directory: open_private_directory(data_dir, true)?,
            authority,
            maximum,
            files: None,
        })
    }

    pub(crate) fn reserve(
        &mut self,
        descriptor: &vos::agent::sdk::AgentDescriptor,
        call: &vos::agent::sdk::authority::AuthorityCredentialCall,
        runtime: &vos::agent::package_admission::AdmittedRuntimePackage,
        replicas: &vos::agent::genesis::AgentReplicaCommittee,
    ) -> Result<
        (
            CleanSharedGenesisRecovery,
            Option<CleanAgentGenesisArchiveFile>,
        ),
        vos::agent::shared_host::SharedAgentHostError,
    > {
        use vos::agent::shared_host::SharedAgentHostError as Error;
        validate_opened_directory(&self.directory, &self.data_dir, true)
            .map_err(|_| Error::Unavailable)?;
        if self.files.is_none() {
            self.files = Some(
                CleanSharedGenesisStoreFactory::open_or_create(
                    &self.data_dir,
                    self.authority,
                    self.maximum,
                )
                .map_err(|_| Error::Unavailable)?,
            );
        }
        validate_opened_directory(&self.directory, &self.data_dir, true)
            .map_err(|_| Error::Unavailable)?;
        let entry = self
            .files
            .as_mut()
            .ok_or(Error::Unavailable)?
            .reserve_create(
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                replicas.clone(),
            )?;
        validate_opened_directory(&self.directory, &self.data_dir, true)
            .map_err(|_| Error::Unavailable)?;
        Ok((entry.recovery, entry.archive.map(|(archive, _)| archive)))
    }
}

impl CleanSharedGenesisStoreFactory {
    pub(crate) fn open_or_create(
        data_dir: &Path,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        maximum: usize,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid()
            || maximum == 0
            || maximum > vos::agent::shared_host::MAX_SHARED_HOST_AGENTS
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        // Do not turn an incomplete namespace with retained data into an
        // apparently complete one. Only an empty partial setup is resumable.
        shared_genesis_roots_present(data_dir)?;
        let directory = open_private_directory(data_dir, true)?;
        // Establish all three empty parents before retaining any per-Agent
        // data. Startup already accepts an empty partial parent set.
        let lifecycle = CleanManagementLifecycleStoreFactory::open_or_create_format(
            &data_dir.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
            LifecycleLayout::Shared,
        )?;
        let committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &data_dir.join(SHARED_COMMITTEE_DIRECTORY),
            vos::service::SpaceId(authority.space.0),
        )?;
        let archive_path = data_dir.join(SHARED_ARCHIVE_DIRECTORY);
        ensure_private_directory(&archive_path)?;
        let archives = CleanAgentGenesisArchiveStoreFactory::open_existing(
            &archive_path,
            vos::service::SpaceId(authority.space.0),
        )?;
        validate_opened_directory(&directory, data_dir, true)?;
        Ok(Self {
            authority,
            maximum,
            lifecycle,
            committee,
            archives,
        })
    }

    pub(crate) fn reserve_create(
        &mut self,
        descriptor: vos::agent::sdk::AgentDescriptor,
        call: vos::agent::sdk::authority::AuthorityCredentialCall,
        runtime: vos::agent::package_admission::AdmittedRuntimePackage,
        replicas: vos::agent::genesis::AgentReplicaCommittee,
    ) -> Result<CleanSharedGenesisStartupEntry, vos::agent::shared_host::SharedAgentHostError> {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::shared_host::SharedAgentHostError as Error;
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId(self.authority.space.0),
            agent: vos::service::AgentId(descriptor.identity.agent.0),
        };
        // Use the core's exact validation, without exposing private lifecycle
        // representations or allocating stores for malformed inputs.
        CleanSharedGenesisRecovery::validate_create_reservation(
            self.authority,
            locator,
            &descriptor,
            &call,
            &runtime,
            &replicas,
        )?;
        let agents = self
            .lifecycle
            .discover(self.authority.space, self.maximum)
            .map_err(|_| Error::Unavailable)?;
        // Count every retained directory, including denied or merely staged
        // inputs. Existing exact retries are still admitted at capacity.
        if !agents.contains(&descriptor.identity.agent) && agents.len() >= self.maximum {
            return Err(Error::CapacityExhausted);
        }
        for found in self
            .committee
            .discover(self.maximum)
            .map_err(|_| Error::Unavailable)?
            .into_iter()
            .chain(
                self.archives
                    .discover(self.maximum)
                    .map_err(|_| Error::Unavailable)?,
            )
        {
            if !agents.contains(&vos::agent::sdk::AgentId(found.agent.0)) {
                return Err(Error::ScopeMismatch);
            }
        }
        let (intent, issuer) = self
            .lifecycle
            .open(self.authority.space, descriptor.identity.agent)
            .map_err(|_| Error::Unavailable)?;
        validate_opened_directory(&self.committee.directory, &self.committee.parent, true)
            .map_err(|_| Error::Unavailable)?;
        let (query, reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&self.committee.parent, locator)
                .map_err(|_| Error::Unavailable)?;
        validate_opened_directory(&self.committee.directory, &self.committee.parent, true)
            .map_err(|_| Error::Unavailable)?;
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        let recovery = CleanSharedGenesisRecovery::reserve_create_with_replicas(
            self.authority,
            locator,
            descriptor,
            call,
            runtime,
            replicas,
            (intent, issuer, query, reply, publication, publication_reply),
        )?;
        // Never create an archive namespace before the signed reservation:
        // discovery rightly rejects archives without an owning Create.
        validate_opened_directory(&self.archives.directory, &self.archives.parent, true)
            .map_err(|_| Error::Unavailable)?;
        let archive = CleanAgentGenesisArchiveFile::open_or_create(&self.archives.parent, locator)
            .map_err(|_| Error::Unavailable)?;
        validate_opened_directory(&self.archives.directory, &self.archives.parent, true)
            .map_err(|_| Error::Unavailable)?;
        use vos::agent::genesis_archive::AgentGenesisArchiveStore as _;
        use vos::service::ServiceWire as _;
        let record = archive
            .load(locator)
            .map_err(|_| Error::Unavailable)?
            .map(|bytes| {
                vos::agent::genesis::AgentGenesisArchiveRecord::decode(&bytes)
                    .map_err(|_| Error::ScopeMismatch)
            })
            .transpose()?;
        if record
            .as_ref()
            .is_some_and(|record| record.provision().proposal().locator() != locator)
        {
            return Err(Error::ScopeMismatch);
        }
        Ok(CleanSharedGenesisStartupEntry {
            recovery,
            archive: Some((archive, record)),
        })
    }
}

/// Discover ordinary Shared recovery before opening the physical host. Fresh
/// spaces have no Shared control directories; do not create them during reads.
/// An empty partial set is a crash during first-time namespace creation, not
/// an Agent reservation. Never create missing directories during discovery or
/// hide a partial namespace containing durable data.
pub(crate) fn discover_shared_genesis_startup(
    data_dir: &Path,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    maximum: usize,
) -> Result<Option<CleanSharedGenesisController>, CleanFileStoreError> {
    if !authority.is_valid() {
        return Err(CleanFileStoreError::InvalidPath);
    }
    if !shared_genesis_roots_present(data_dir)? {
        return Ok(None);
    }
    let directory = open_private_directory(data_dir, true)?;
    let paths = [
        data_dir.join(SHARED_LIFECYCLE_DIRECTORY),
        data_dir.join(SHARED_COMMITTEE_DIRECTORY),
        data_dir.join(SHARED_ARCHIVE_DIRECTORY),
    ];
    let space = vos::service::SpaceId(authority.space.0);
    let mut lifecycle = CleanManagementLifecycleStoreFactory::new(&paths[0], authority.space)?;
    lifecycle.layout = LifecycleLayout::Shared;
    let committee = CleanAgentGenesisCommitteeStoreFactory::open_existing_parent(&paths[1], space)?;
    let archives = CleanAgentGenesisArchiveStoreFactory::open_existing(&paths[2], space)?;
    let entries = archives.discover_recovery(&mut lifecycle, &committee, authority, maximum)?;
    validate_opened_directory(&directory, data_dir, true)?;
    CleanSharedGenesisStartupEntry::into_controller(authority, entries)
        .map(Some)
        .map_err(|_| CleanFileStoreError::Corrupt)
}

/// Shared by noncreating discovery and first-Create admission. False means
/// absent or empty partial setup; nonempty partial setup always fails closed.
fn shared_genesis_roots_present(data_dir: &Path) -> Result<bool, CleanFileStoreError> {
    let directory = open_private_directory(data_dir, true)?;
    let paths = [
        data_dir.join(SHARED_LIFECYCLE_DIRECTORY),
        data_dir.join(SHARED_COMMITTEE_DIRECTORY),
        data_dir.join(SHARED_ARCHIVE_DIRECTORY),
    ];
    let mut present_paths = Vec::new();
    for path in &paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => present_paths.push(path),
            Ok(_) => return Err(CleanFileStoreError::InvalidPath),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if present_paths.is_empty() {
        validate_opened_directory(&directory, data_dir, true)?;
        return Ok(false);
    }
    if present_paths.len() != paths.len() {
        for path in present_paths {
            let opened = open_private_directory(path, false)?;
            #[cfg(target_os = "linux")]
            let scan = PathBuf::from(format!("/proc/self/fd/{}", opened.as_raw_fd()));
            #[cfg(not(target_os = "linux"))]
            let scan = path;
            if fs::read_dir(scan)?.next().is_some() {
                return Err(CleanFileStoreError::Corrupt);
            }
            validate_opened_directory(&opened, path, false)?;
        }
        validate_opened_directory(&directory, data_dir, true)?;
        return Ok(false);
    }
    validate_opened_directory(&directory, data_dir, true)?;
    Ok(true)
}

/// One startup reservation with every acquired lease still owned. An absent
/// archive or absent record represents incomplete publication, never a route
/// eligible for admission. Even a present record requires independent replay.
pub(crate) struct CleanSharedGenesisStartupEntry {
    pub(crate) recovery: CleanSharedGenesisRecovery,
    pub(crate) archive: Option<(
        CleanAgentGenesisArchiveFile,
        Option<vos::agent::genesis::AgentGenesisArchiveRecord>,
    )>,
}

impl CleanSharedGenesisStartupEntry {
    /// Transfer every discovered lease to the lifecycle controller. Cached
    /// decoded records are discarded: recovery re-reads the owned archive.
    pub(crate) fn into_controller(
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        entries: Vec<Self>,
    ) -> Result<CleanSharedGenesisController, vos::agent::shared_host::SharedAgentHostError> {
        vos::agent::clean_bootstrap::NativeSharedGenesisController::new(
            authority,
            entries
                .into_iter()
                .map(|entry| (entry.recovery, entry.archive.map(|(archive, _)| archive)))
                .collect(),
        )
    }
}

impl CleanAgentGenesisArchiveStoreFactory {
    pub(crate) fn discover_recovery(
        &self,
        lifecycle: &mut CleanManagementLifecycleStoreFactory,
        committee: &CleanAgentGenesisCommitteeStoreFactory,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        maximum: usize,
    ) -> Result<Vec<CleanSharedGenesisStartupEntry>, CleanFileStoreError> {
        use vos::agent::genesis_archive::AgentGenesisArchiveStore as _;
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::service::ServiceWire as _;
        if !authority.is_valid()
            || authority.space.0 != self.space.0
            || committee.space != self.space
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let agents = lifecycle.discover(authority.space, maximum)?;
        let archives = self.discover(maximum)?;
        // Refuse orphan archives before recovery may establish an empty query
        // slot for a legitimate pre-query crash.
        if archives.iter().any(|locator| {
            agents
                .binary_search(&vos::agent::sdk::AgentId(locator.agent.0))
                .is_err()
        }) {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        let mut expected_committees = committee.discover(maximum)?;
        let recoveries = committee.discover_recovery(lifecycle, authority, maximum)?;
        if archives.iter().any(|locator| {
            recoveries
                .binary_search_by_key(&locator.agent, |recovery| recovery.locator().agent)
                .is_err()
        }) {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        // Signed Creates may establish a previously absent empty query slot.
        // No other directory may appear during discovery, including a racing
        // orphan that would otherwise escape the initial validation pass.
        for recovery in &recoveries {
            let locator = recovery.locator();
            if !expected_committees
                .iter()
                .any(|found| found.agent == locator.agent)
            {
                expected_committees.push(locator);
            }
        }
        expected_committees.sort_unstable_by_key(|locator| locator.agent);
        if expected_committees.len() > maximum {
            return Err(CleanFileStoreError::Oversized);
        }
        let mut entries = Vec::with_capacity(recoveries.len());
        for recovery in recoveries {
            let locator = recovery.locator();
            let archive = if archives
                .binary_search_by_key(&locator.agent, |entry| entry.agent)
                .is_ok()
            {
                let store = self.open_archive(locator)?;
                let record = store
                    .load(locator)?
                    .map(|bytes| {
                        let record = vos::agent::genesis::AgentGenesisArchiveRecord::decode(&bytes)
                            .map_err(|_| CleanFileStoreError::Corrupt)?;
                        if record.provision().proposal().locator() != locator {
                            return Err(CleanFileStoreError::Corrupt);
                        }
                        Ok(record)
                    })
                    .transpose()?;
                Some((store, record))
            } else {
                None
            };
            entries.push(CleanSharedGenesisStartupEntry { recovery, archive });
        }
        if self.discover(maximum)? != archives
            || lifecycle.discover(authority.space, maximum)? != agents
            || committee.discover(maximum)? != expected_committees
        {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        Ok(entries)
    }
}

impl CleanAgentGenesisCommitteeStoreFactory {
    pub(crate) fn open_existing_parent(
        parent: &Path,
        space: vos::service::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::service::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            directory: open_private_directory(parent, true)?,
            space,
        })
    }

    /// Discover the complete two-directory set before opening records. Returned
    /// recovery entries own both lifecycle and committee leases. The caller
    /// must retain them through admission and transfer them to its controller.
    pub(crate) fn discover_recovery(
        &self,
        lifecycle: &mut CleanManagementLifecycleStoreFactory,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        maximum: usize,
    ) -> Result<Vec<CleanSharedGenesisRecovery>, CleanFileStoreError> {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::service::ServiceWire as _;
        if !authority.is_valid() || authority.space.0 != self.space.0 {
            return Err(CleanFileStoreError::InvalidPath);
        }
        if matches!(lifecycle.layout, LifecycleLayout::ExternalLocal) {
            return Err(CleanFileStoreError::InvalidPath);
        }
        lifecycle.layout = LifecycleLayout::Shared;
        let agents = lifecycle.discover(authority.space, maximum)?;
        let committees = self.discover(maximum)?;
        // Never silently ignore a query/reply whose owning Create is absent.
        if committees.iter().any(|locator| {
            agents
                .binary_search(&vos::agent::sdk::AgentId(locator.agent.0))
                .is_err()
        }) {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        let mut recovered = Vec::with_capacity(agents.len());
        for agent in agents {
            let locator = vos::agent::genesis::AgentGenesisLocator {
                space: self.space,
                agent: vos::service::AgentId(agent.0),
            };
            let (mut intent, mut issuer) = lifecycle.open_existing(authority.space, agent)?;
            let handoff = issuer.issuance_disabled()?;
            let has_intent = intent.load()?.is_some();
            if !has_intent {
                // A crash before the signed pledge may leave an empty scoped
                // directory or exact staged inputs. It is not an Agent. Do
                // not create a missing committee/query directory while
                // inspecting it, and never hide an issuer or phase image.
                if handoff
                    || issuer.load()?.is_some()
                    || intent.load_actor()?.is_some()
                    || intent.load_external_create_archive()?.is_some()
                {
                    return Err(CleanFileStoreError::UnexpectedResidue);
                }
                if let Some(bytes) = intent.load_runtime()? {
                    vos::agent::package_admission::admit_runtime_package(&bytes)
                        .map_err(|_| CleanFileStoreError::Corrupt)?;
                }
                if committees
                    .binary_search_by_key(&locator.agent, |found| found.agent)
                    .is_ok()
                {
                    let (mut query, mut reply) = self.open_existing(locator)?;
                    let mut publication = query.publication();
                    let mut publication_reply = query.publication_reply();
                    if query.load()?.is_some()
                        || reply.load()?.is_some()
                        || publication.load()?.is_some()
                        || publication_reply.load()?.is_some()
                    {
                        return Err(CleanFileStoreError::UnexpectedResidue);
                    }
                    if let Some(bytes) = query.load_replicas()? {
                        let replicas = vos::agent::genesis::AgentReplicaCommittee::decode(&bytes)
                            .map_err(|_| CleanFileStoreError::Corrupt)?;
                        if replicas.encode() != bytes
                            || replicas.space() != locator.space
                            || replicas.agent() != locator.agent
                            || replicas.profile() != vos::agent::AgentProfile::Shared
                        {
                            return Err(CleanFileStoreError::Corrupt);
                        }
                    }
                }
                continue;
            }
            let (query, reply) = if committees
                .binary_search_by_key(&locator.agent, |found| found.agent)
                .is_ok()
            {
                self.open_existing(locator)?
            } else {
                // A crash may precede the first query reservation. Establish
                // its empty leased slots; recovery still validates the Create.
                validate_opened_directory(&self.directory, &self.parent, true)?;
                let files = CleanAgentGenesisCommitteeFile::open_pair(&self.parent, locator)?;
                validate_opened_directory(&self.directory, &self.parent, true)?;
                files
            };
            let publication = query.publication();
            let publication_reply = query.publication_reply();
            let recovery = CleanSharedGenesisRecovery::open_with_management_handoff(
                authority,
                locator,
                intent,
                issuer,
                query,
                reply,
                publication,
                publication_reply,
            )
            .map_err(|_| CleanFileStoreError::Corrupt)?;
            recovered.push(recovery);
        }
        Ok(recovered)
    }

    pub(crate) fn open_or_create(
        parent: &Path,
        space: vos::service::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::service::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            directory: ensure_private_directory(parent)?,
            space,
        })
    }

    pub(crate) fn discover(
        &self,
        maximum: usize,
    ) -> Result<Vec<vos::agent::genesis::AgentGenesisLocator>, CleanFileStoreError> {
        discover_genesis_directories(
            &self.directory,
            &self.parent,
            self.space,
            "genesis-committee",
            maximum,
        )
    }

    pub(crate) fn open_existing(
        &self,
        locator: vos::agent::genesis::AgentGenesisLocator,
    ) -> Result<
        (
            CleanAgentGenesisCommitteeFile,
            CleanAgentGenesisCommitteeFile,
        ),
        CleanFileStoreError,
    > {
        if locator.space != self.space {
            return Err(CleanFileStoreError::InvalidPath);
        }
        locator
            .validate()
            .map_err(|_| CleanFileStoreError::InvalidPath)?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let path = self.parent.join(format!(
            "genesis-committee-{}-{}",
            hex::encode(locator.space.0),
            hex::encode(locator.agent.0)
        ));
        let root = Arc::new(StoreRoot::open_with_entries_mode(
            &path,
            GENESIS_COMMITTEE_ENTRIES,
            false,
        )?);
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok((
            CleanAgentGenesisCommitteeFile(ExactFileStore::new(
                root.clone(),
                StoreRole::OrdinaryGenesisQuery,
            )),
            CleanAgentGenesisCommitteeFile(ExactFileStore::new(
                root,
                StoreRole::OrdinaryGenesisReply,
            )),
        ))
    }
}

impl CleanAgentGenesisCommitteeFile {
    /// Keep the same lifecycle lease alive for publication work retention.
    fn publication(&self) -> Self {
        Self(ExactFileStore::new(
            self.0.root.clone(),
            StoreRole::OrdinaryGenesisPublication,
        ))
    }

    fn publication_reply(&self) -> Self {
        Self(ExactFileStore::new(
            self.0.root.clone(),
            StoreRole::OrdinaryGenesisPublicationReply,
        ))
    }

    pub(crate) fn open_pair(
        parent: &Path,
        locator: vos::agent::genesis::AgentGenesisLocator,
    ) -> Result<(Self, Self), CleanFileStoreError> {
        locator
            .validate()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let path = parent.join(format!(
            "genesis-committee-{}-{}",
            hex::encode(locator.space.0),
            hex::encode(locator.agent.0)
        ));
        let root = Arc::new(StoreRoot::open_with_entries(
            &path,
            GENESIS_COMMITTEE_ENTRIES,
        )?);
        Ok((
            Self(ExactFileStore::new(
                root.clone(),
                StoreRole::OrdinaryGenesisQuery,
            )),
            Self(ExactFileStore::new(root, StoreRole::OrdinaryGenesisReply)),
        ))
    }
}

impl CleanManagementIssuerStore for CleanAgentGenesisCommitteeFile {
    type Error = CleanFileStoreError;
    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(self.0.role.maximum_bytes())
    }
    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit_with_replacement(image, false)
    }
}

impl CleanSharedGenesisReplicaStore for CleanAgentGenesisCommitteeFile {
    fn load_replicas(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut store =
            ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::OrdinaryGenesisReplicas);
        let image = store.load(StoreRole::OrdinaryGenesisReplicas.maximum_bytes())?;
        if let Some(bytes) = &image {
            // A previous rename may have succeeded before directory sync.
            store.commit_with_replacement(bytes, false)?;
        }
        Ok(image)
    }

    fn commit_replicas(&mut self, replicas: &[u8]) -> Result<(), Self::Error> {
        match self.load_replicas()? {
            Some(bytes) if bytes == replicas => Ok(()),
            Some(_) => Err(CleanFileStoreError::RequestConflict),
            None => {
                ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::OrdinaryGenesisReplicas)
                    .commit_with_replacement(replicas, false)
            }
        }
    }
}

impl CleanAgentGenesisSignatureFile {
    pub(crate) fn open_or_create(
        parent: &Path,
        locator: vos::agent::genesis::AgentGenesisLocator,
        signer: vos::agent::committee::AuthoritySignerId,
    ) -> Result<Self, CleanFileStoreError> {
        locator
            .validate()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if signer.as_bytes() == &[0; 32] {
            return Err(CleanFileStoreError::Corrupt);
        }
        let path = parent.join(format!(
            "genesis-signature-{}-{}-{}",
            hex::encode(locator.space.0),
            hex::encode(locator.agent.0),
            hex::encode(signer.as_bytes())
        ));
        let root = Arc::new(StoreRoot::open_with_entries(
            &path,
            &[
                LOCK_FILE,
                "ordinary-agent.genesis-signature",
                "ordinary-agent.genesis-signature.next",
            ],
        )?);
        Ok(Self(ExactFileStore::new(
            root,
            StoreRole::OrdinaryGenesisSignature,
        )))
    }
}

impl CleanManagementIssuerStore for CleanAgentGenesisSignatureFile {
    type Error = CleanFileStoreError;
    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0
            .load(StoreRole::OrdinaryGenesisSignature.maximum_bytes())
    }
    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

/// One per-agent lifecycle directory with a shared exclusive writer lease.
/// The coordinator must validate the signed intent and issuer binding against
/// its configured Space/Agent; the file envelope is integrity, not authority.
pub(crate) struct CleanManagementLifecycleFiles {
    intent: CleanManagementIntentFile,
    issuer: CleanManagementIssuerFile,
}

impl CleanManagementLifecycleFiles {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        Self::open(root.as_ref(), LifecycleLayout::ImageLocal, false)
    }

    fn open_existing(root: &Path) -> Result<Self, CleanFileStoreError> {
        Self::open(root, LifecycleLayout::ImageLocal, true)
    }

    fn open(
        root: &Path,
        layout: LifecycleLayout,
        existing: bool,
    ) -> Result<Self, CleanFileStoreError> {
        let entries = layout.entries();
        Ok(Self::from_root(StoreRoot::open_with_entries_mode(
            root, entries, !existing,
        )?))
    }

    fn from_root(root: StoreRoot) -> Self {
        let root = Arc::new(root);
        Self {
            intent: CleanManagementIntentFile(
                ExactFileStore::new(Arc::clone(&root), StoreRole::ManagementIntent),
                ExactFileStore::new(Arc::clone(&root), StoreRole::LifecycleRuntime),
                ExactFileStore::new(Arc::clone(&root), StoreRole::LifecycleActor),
                ExactFileStore::new(Arc::clone(&root), StoreRole::ExternalLocalCreateArchive),
                ExactFileStore::new(Arc::clone(&root), StoreRole::ExternalLocalPendingInstall),
            ),
            issuer: CleanManagementIssuerFile(ExactFileStore::new(
                root,
                StoreRole::LifecycleIssuer,
            )),
        }
    }

    pub(crate) fn into_parts(self) -> (CleanManagementIntentFile, CleanManagementIssuerFile) {
        (self.intent, self.issuer)
    }
}

pub(crate) struct CleanManagementIntentFile(
    ExactFileStore,
    ExactFileStore,
    ExactFileStore,
    ExactFileStore,
    ExactFileStore,
);

/// One Authority's operation history under a shared exclusive writer lease.
/// These are opaque durability adapters, not policy or signature verifiers.
/// The coordinator must reopen both images against the trusted Authority and
/// reconcile them before any new operation is admitted. Never open independent
/// per-invocation issuers: issuance sequencing belongs to the whole Authority.
pub(crate) struct CleanAuthorityOperationFiles {
    coordinator: CleanAuthorityOperationCoordinatorFile,
    issuer: CleanAuthorityOperationIssuerFile,
}

impl CleanAuthorityOperationFiles {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        const ENTRIES: &[&str] = &[
            LOCK_FILE,
            StoreRole::OperationCoordinator.file(),
            StoreRole::OperationCoordinator.stage_file(),
            StoreRole::OperationIssuer.file(),
            StoreRole::OperationIssuer.stage_file(),
        ];
        let root = Arc::new(StoreRoot::open_with_entries(root.as_ref(), ENTRIES)?);
        Ok(Self {
            coordinator: CleanAuthorityOperationCoordinatorFile(ExactFileStore::new(
                Arc::clone(&root),
                StoreRole::OperationCoordinator,
            )),
            issuer: CleanAuthorityOperationIssuerFile(ExactFileStore::new(
                root,
                StoreRole::OperationIssuer,
            )),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CleanAuthorityOperationCoordinatorFile,
        CleanAuthorityOperationIssuerFile,
    ) {
        (self.coordinator, self.issuer)
    }
}

/// Keyed immutable NOD1 records under one Authority-wide exclusive lease.
/// The caller independently pins the Authority; CSF1 integrity does not prove
/// that a journal anchor was admitted or that policy approved an operation.
#[cfg(target_os = "linux")]
pub(crate) struct CleanNativeAuthorityOperationJournal {
    root: Arc<StoreRoot>,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
}

#[cfg(target_os = "linux")]
impl CleanNativeAuthorityOperationJournal {
    /// Keep the complete discovery set and writer lease tied to startup.
    pub(crate) fn startup_admission(
        &mut self,
    ) -> Result<
        vos::agent::clean_bootstrap::NativeAuthorityOperationStartupAdmission<'_>,
        CleanFileStoreError,
    > {
        let invocations = self.discover(MAX_OPERATION_JOURNAL_RECORDS)?;
        let authority = self.authority;
        vos::agent::clean_bootstrap::NativeAuthorityOperationStartupAdmission::load(
            self,
            authority,
            &invocations,
        )
        .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn open_or_create(
        path: impl AsRef<Path>,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open(path.as_ref(), authority, true)
    }

    pub(crate) fn open_existing(
        path: impl AsRef<Path>,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open(path.as_ref(), authority, false)
    }

    fn open(
        path: &Path,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid() {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let mut journal = Self {
            root: Arc::new(StoreRoot::open_namespace(path, &[LOCK_FILE], create, true)?),
            authority,
        };
        for invocation in journal.discover(MAX_OPERATION_JOURNAL_RECORDS)? {
            journal
                .load(invocation)?
                .ok_or(CleanFileStoreError::Corrupt)?;
        }
        Ok(journal)
    }

    /// Include first-publication staging records so startup cannot miss an
    /// ambiguous commit. Decode/reconcile each discovered ID before admission.
    pub(crate) fn discover(
        &self,
        maximum: usize,
    ) -> Result<Vec<vos::agent::sdk::InvocationId>, CleanFileStoreError> {
        self.root.audit_entries()?;
        let scan = PathBuf::from(format!("/proc/self/fd/{}", self.root.directory.as_raw_fd()));
        let mut records = std::collections::BTreeSet::new();
        for entry in fs::read_dir(scan)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            if name == LOCK_FILE {
                continue;
            }
            let invocation =
                operation_record_name(&name).ok_or(CleanFileStoreError::UnexpectedResidue)?;
            records.insert(invocation);
            if records.len() > maximum.min(MAX_OPERATION_JOURNAL_RECORDS) {
                return Err(CleanFileStoreError::Oversized);
            }
        }
        self.root.audit_entries()?;
        Ok(records.into_iter().collect())
    }

    fn validate(
        &self,
        invocation: vos::agent::sdk::InvocationId,
        bytes: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        if bytes.len() > MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES {
            return Err(CleanFileStoreError::Oversized);
        }
        if !native_operation_record_matches(self.authority, invocation, bytes) {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl NativeAuthorityOperationJournalStore for CleanNativeAuthorityOperationJournal {
    type Error = CleanFileStoreError;

    fn load(
        &mut self,
        invocation: vos::agent::sdk::InvocationId,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let file = ExactFileStore::operation_record(Arc::clone(&self.root), invocation)?;
        let _guard = self.root.guard()?;
        self.root.audit_entries()?;
        // Validate both names before reconciliation may publish a stage.
        for name in [file.file(), file.stage_file()] {
            if let Some(image) =
                file.read_optional(name, MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES)?
            {
                self.validate(invocation, &image.payload)?;
            }
        }
        let image = file.reconcile(MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES)?;
        if let Some(image) = &image {
            self.validate(invocation, &image.payload)?;
            file.sync_named(file.file())?;
            self.root.sync()?;
        }
        Ok(image.map(|image| image.payload))
    }

    fn retain(
        &mut self,
        invocation: vos::agent::sdk::InvocationId,
        record: &[u8],
    ) -> Result<(), Self::Error> {
        self.validate(invocation, record)?;
        let existing = self.load(invocation)?;
        if existing.as_deref().is_some_and(|bytes| bytes != record) {
            return Err(CleanFileStoreError::RequestConflict);
        }
        if existing.is_none()
            && self.discover(MAX_OPERATION_JOURNAL_RECORDS)?.len() == MAX_OPERATION_JOURNAL_RECORDS
        {
            return Err(CleanFileStoreError::Oversized);
        }
        ExactFileStore::operation_record(Arc::clone(&self.root), invocation)?
            .commit_with_replacement(record, false)
    }
}

pub(crate) struct CleanAuthorityOperationCoordinatorFile(ExactFileStore);
pub(crate) struct CleanAuthorityOperationIssuerFile(ExactFileStore);

impl AuthorityOperationCoordinatorStore for CleanAuthorityOperationCoordinatorFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl AuthorityOperationIssuerStore for CleanAuthorityOperationIssuerFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

/// One immutable signed submission in its own leased private directory.
/// Keep this lease until submission finishes; ambiguous outcomes retain the
/// same request for restart. This does not allocate a credential sequence.
#[cfg(target_os = "linux")]
pub(crate) struct CleanLocalCreateRequestFile(ExactFileStore);

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialReservationStatus {
    Pending,
    Completed,
    Denied,
}

impl CredentialReservationStatus {
    fn from_tag(tag: u8) -> Self {
        match tag {
            0 => Self::Pending,
            1 => Self::Completed,
            2 => Self::Denied,
            _ => unreachable!("validated reservation tag"),
        }
    }
}

/// One local operation at a time for a Space/Credential in this configured
/// private parent. Retain the lease across discovery, preparation and sending.
/// Other machines are still serialized by Authority's exact sequence policy.
#[cfg(target_os = "linux")]
pub(crate) struct CleanCredentialReservation {
    store: ExactFileStore,
    space: vos::agent::sdk::SpaceId,
    credential: vos::agent::sdk::CredentialId,
}

#[cfg(target_os = "linux")]
impl CleanCredentialReservation {
    pub(crate) fn open_or_create(
        parent: &Path,
        space: vos::agent::sdk::SpaceId,
        credential: vos::agent::sdk::CredentialId,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_role(parent, space, credential, StoreRole::CredentialReservation)
    }

    fn open_role(
        parent: &Path,
        space: vos::agent::sdk::SpaceId,
        credential: vos::agent::sdk::CredentialId,
        role: StoreRole,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO
            || credential == vos::agent::sdk::CredentialId::ZERO
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let path = parent.join(format!(
            "{}-{}",
            hex::encode(space.0),
            hex::encode(credential.0)
        ));
        let entries: &[&str] = if role == StoreRole::AdminCredentialReservation {
            &[
                LOCK_FILE,
                "admin-credential.reservation",
                "admin-credential.reservation.next",
            ]
        } else {
            &RESERVATION_ENTRIES
        };
        let root = Arc::new(StoreRoot::open_with_entries(&path, entries)?);
        Ok(Self {
            store: ExactFileStore::new(root, role),
            space,
            credential,
        })
    }

    fn image(
        &self,
        nonce: vos::agent::sdk::Hash,
        completed: Option<(vos::agent::sdk::Hash, vos::agent::sdk::Hash)>,
    ) -> Vec<u8> {
        let mut bytes = b"CRS1".to_vec();
        bytes.extend_from_slice(self.space.as_bytes());
        bytes.extend_from_slice(self.credential.as_bytes());
        bytes.extend_from_slice(nonce.as_bytes());
        bytes.push(u8::from(completed.is_some()));
        let (request, ack) =
            completed.unwrap_or((vos::agent::sdk::Hash::ZERO, vos::agent::sdk::Hash::ZERO));
        bytes.extend_from_slice(request.as_bytes());
        bytes.extend_from_slice(ack.as_bytes());
        bytes
    }

    fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::CredentialReservation.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            if bytes.len() != 165
                || &bytes[..4] != b"CRS1"
                || bytes[4..36] != self.space.0
                || bytes[36..68] != self.credential.0
                || bytes[68..100] == [0; 32]
                || !match bytes[100] {
                    0 => bytes[101..165] == [0; 64],
                    1 | 2 => bytes[101..133] != [0; 32] && bytes[133..165] != [0; 32],
                    _ => false,
                }
            {
                return Err(CleanFileStoreError::Corrupt);
            }
            self.store.commit(bytes)?;
        }
        Ok(bytes)
    }

    pub(crate) fn current(
        &mut self,
    ) -> Result<Option<(vos::agent::sdk::Hash, CredentialReservationStatus)>, CleanFileStoreError>
    {
        self.load()?
            .map(|bytes| {
                let nonce = vos::agent::sdk::Hash(
                    bytes[68..100]
                        .try_into()
                        .map_err(|_| CleanFileStoreError::Corrupt)?,
                );
                let status = CredentialReservationStatus::from_tag(bytes[100]);
                Ok((nonce, status))
            })
            .transpose()
    }

    pub(crate) fn reserve(
        &mut self,
        nonce: vos::agent::sdk::Hash,
    ) -> Result<CredentialReservationStatus, CleanFileStoreError> {
        if nonce == vos::agent::sdk::Hash::ZERO {
            return Err(CleanFileStoreError::Corrupt);
        }
        if let Some(current) = self.load()? {
            if current[68..100] == nonce.0 {
                return Ok(CredentialReservationStatus::from_tag(current[100]));
            }
            if current[100] == 0 {
                return Err(CleanFileStoreError::RequestConflict);
            }
        }
        self.store.commit(&self.image(nonce, None))?;
        Ok(CredentialReservationStatus::Pending)
    }

    /// Only a cryptographically verified acknowledgement for the reserved
    /// Create can complete this reservation. Never interpret an HTTP error,
    /// cancellation or unsigned projection as completion.
    pub(crate) fn complete(
        &mut self,
        request: &[u8],
        acknowledgement: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::Hash;
        let ack = super::local_create::verify_acknowledgement(request, acknowledgement)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let (descriptor, call) = super::local_create::decode_retained_request(request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if descriptor.identity.space != self.space || call.credential != self.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != descriptor.creation_nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let completed = self.image(
            descriptor.creation_nonce,
            Some((
                Hash::digest(b"vos/local-create/retained-request/v1", &[request]),
                ack.commitment(),
            )),
        );
        if current[100] != 0 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)
    }

    /// Complete Install only from its durably retained request and MAA2.
    /// The reserved operation nonce is the Install's signed installation ID.
    /// This uses the same Space/Credential lease as Create, not a second lane
    /// of credential sequences. No denial or transport error completes it.
    pub(crate) fn complete_install(
        &mut self,
        delivery: &mut CleanLocalInstallFile,
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::Hash;
        let request = delivery
            .load_request()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let response = delivery
            .load_acknowledgement()?
            .ok_or(CleanFileStoreError::RequestConflict)?;
        let ack = super::local_install::verify_acknowledgement(&request, &response)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let (install, call) = super::local_install::decode_retained_install(&request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if call.managed.space != self.space || call.credential != self.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let nonce = Hash(install.installation_id.0);
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let completed = self.image(
            nonce,
            Some((
                Hash::digest(b"vos/local-install/retained-request/v1", &[&request]),
                ack.commitment(),
            )),
        );
        if current[100] != 0 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)
    }

    /// Re-verify and sync the immutable certificate under its lease before
    /// committing a distinct denied marker. Raw HTTP errors never reach here.
    pub(crate) fn deny(
        &mut self,
        denial: &mut CleanLocalCreateDenialFile,
    ) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::Hash;
        let bytes = denial.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        let (descriptor, call) = super::local_create::decode_retained_request(&denial.request)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if descriptor.identity.space != self.space || call.credential != self.credential {
            return Err(CleanFileStoreError::Corrupt);
        }
        let current = self.load()?.ok_or(CleanFileStoreError::RequestConflict)?;
        if current[68..100] != descriptor.creation_nonce.0 {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let mut completed = self.image(
            descriptor.creation_nonce,
            Some((
                Hash::digest(b"vos/local-create/retained-request/v1", &[&denial.request]),
                Hash::digest(b"vos/local-create/retained-denial/v1", &[&bytes]),
            )),
        );
        completed[100] = 2;
        if current[100] != 0 && current != completed {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.store.commit(&completed)
    }
}

/// Immutable signed discovery query, scoped to an independently chosen target
/// and credential. A valid initial stage is recoverable; no nonce replacement
/// is allowed after publication or ambiguous completion.
#[cfg(target_os = "linux")]
pub(crate) struct CleanCredentialQueryFile {
    store: ExactFileStore,
    authority: vos::agent::sdk::authority::AuthorityActorTarget,
    credential: vos::agent::sdk::CredentialId,
}

#[cfg(target_os = "linux")]
impl CleanCredentialQueryFile {
    pub(crate) fn open_or_create(
        root: impl AsRef<Path>,
        authority: vos::agent::sdk::authority::AuthorityActorTarget,
        credential: vos::agent::sdk::CredentialId,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid() || credential == vos::agent::sdk::CredentialId::ZERO {
            return Err(CleanFileStoreError::Corrupt);
        }
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &CREDENTIAL_QUERY_ENTRIES,
        )?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::CredentialQuery),
            authority,
            credential,
        })
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::CredentialQuery.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate(bytes)?;
            self.store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(bytes)?;
        self.store.commit_with_replacement(bytes, false)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        use vos::agent::sdk::authority::{AuthorityProjectionQuery, AuthorityProjectionSelector};
        use vos::agent::sdk::wire::CanonicalWire as _;
        let query =
            AuthorityProjectionQuery::decode(bytes).map_err(|_| CleanFileStoreError::Corrupt)?;
        if query.authority != self.authority
            || query.credential != self.credential
            || query.selector != AuthorityProjectionSelector::Credential
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        query
            .verify_api_with(&super::local_create::CredentialVerifier)
            .map_err(|_| CleanFileStoreError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
/// Immutable client delivery evidence, bound to the complete retained request.
/// This is not a substitute for server publication or runtime finality.
pub(crate) struct CleanLocalCreateAcknowledgementFile {
    store: ExactFileStore,
    request: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[path = "clean_admin_reservation.rs"]
mod admin_reservation;
/// Exact invocation and its first request-bound delivery under one lease.
/// A retained response may be an error or yield, not terminal actor success.
#[cfg(target_os = "linux")]
#[path = "clean_operation_client.rs"]
mod operation_client;
#[cfg(target_os = "linux")]
pub(crate) use admin_reservation::CleanAdminCredentialReservation;
#[cfg(target_os = "linux")]
pub(crate) use operation_client::CleanOperationClientFile;
#[cfg(target_os = "linux")]
pub(crate) use operation_client::CleanPreparationClientFile;

pub(crate) struct CleanInvocationFile {
    request: ExactFileStore,
    response: ExactFileStore,
    progress: ExactFileStore,
}

impl CleanInvocationFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &[
                LOCK_FILE,
                "invocation.request",
                "invocation.request.next",
                "invocation.response",
                "invocation.response.next",
                "invocation.progress",
                "invocation.progress.next",
            ],
        )?);
        Ok(Self {
            request: ExactFileStore::new(root.clone(), StoreRole::InvocationRequest),
            response: ExactFileStore::new(root.clone(), StoreRole::InvocationResponse),
            progress: ExactFileStore::new(root, StoreRole::InvocationProgress),
        })
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .request
            .load(StoreRole::InvocationRequest.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            super::local_invocation::validate_request(bytes)
                .map_err(|_| CleanFileStoreError::Corrupt)?;
            self.request.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        super::local_invocation::validate_request(bytes)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        self.load_response()?; // Never repair an orphan response from new input.
        self.load_progress()?;
        self.request.commit_with_replacement(bytes, false)
    }

    fn validate_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        super::local_invocation::verify_response(&request, bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn load_response(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .response
            .load(StoreRole::InvocationResponse.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate_response(bytes)?;
            self.response.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_response(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.load_progress()?; // Nor reconstruct a missing predecessor of progress.
        self.validate_response(bytes)?;
        self.response.commit_with_replacement(bytes, false)
    }

    fn decode_progress(
        &mut self,
        bytes: &[u8],
    ) -> Result<super::invocation_progress::Progress, CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        let response = self.load_response()?.ok_or(CleanFileStoreError::Corrupt)?;
        super::invocation_progress::Progress::decode(bytes, &request, &response)
            .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn load_progress(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .progress
            .load(StoreRole::InvocationProgress.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.decode_progress(bytes)?;
            self.progress.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish_progress(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let next = self.decode_progress(bytes)?;
        let previous = match self.load_progress()? {
            Some(bytes) => self.decode_progress(&bytes)?,
            None => super::invocation_progress::Progress::new(
                &self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?,
            )
            .map_err(|_| CleanFileStoreError::Corrupt)?,
        };
        if !next.succeeds(&previous) {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.progress.commit_with_replacement(bytes, true)
    }
}

/// Immutable Install request and verified delivery evidence under one lease.
pub(crate) struct CleanLocalInstallFile {
    request: ExactFileStore,
    acknowledgement: ExactFileStore,
}

impl CleanLocalInstallFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &[
                LOCK_FILE,
                "local-install.request",
                "local-install.request.next",
                "local-install.acknowledgement",
                "local-install.acknowledgement.next",
            ],
        )?);
        Ok(Self {
            request: ExactFileStore::new(root.clone(), StoreRole::LocalInstallRequest),
            acknowledgement: ExactFileStore::new(root, StoreRole::LocalInstallAcknowledgement),
        })
    }

    fn validate_request(bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalInstallRequest.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let (_, call) = super::local_install::decode_retained_install(bytes)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if call.authenticated_node.is_some() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn publish_request(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        Self::validate_request(bytes)?;
        // An orphaned or contradictory completion is not permission to
        // regenerate its missing request from newly supplied bytes.
        self.load_acknowledgement()?;
        self.request.commit_with_replacement(bytes, false)
    }

    pub(crate) fn load_request(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .request
            .load(StoreRole::LocalInstallRequest.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            Self::validate_request(bytes)?;
            self.request.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    fn validate_acknowledgement(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        let request = self.load_request()?.ok_or(CleanFileStoreError::Corrupt)?;
        super::local_install::verify_acknowledgement(&request, bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }

    pub(crate) fn publish_acknowledgement(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        self.validate_acknowledgement(bytes)?;
        self.acknowledgement.commit_with_replacement(bytes, false)
    }

    pub(crate) fn load_acknowledgement(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .acknowledgement
            .load(StoreRole::LocalInstallAcknowledgement.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate_acknowledgement(bytes)?;
            self.acknowledgement.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }
}

impl CleanLocalCreateAcknowledgementFile {
    pub(crate) fn open_or_create(
        root: impl AsRef<Path>,
        request: &[u8],
    ) -> Result<Self, CleanFileStoreError> {
        CleanLocalCreateRequestFile::validate(request)?;
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &LOCAL_ACK_ENTRIES,
        )?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::LocalCreateAcknowledgement),
            request: request.to_vec(),
        })
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::LocalCreateAcknowledgement.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate(bytes)?;
            self.store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(bytes)?;
        self.store.commit_with_replacement(bytes, false)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalCreateAcknowledgement.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        super::local_create::verify_acknowledgement(&self.request, bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }
}

/// Immutable independently verified CND1, retained separately from an MAA2.
pub(crate) struct CleanLocalCreateDenialFile {
    store: ExactFileStore,
    request: Vec<u8>,
}

impl CleanLocalCreateDenialFile {
    pub(crate) fn open_or_create(
        root: impl AsRef<Path>,
        request: &[u8],
    ) -> Result<Self, CleanFileStoreError> {
        CleanLocalCreateRequestFile::validate(request)?;
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &LOCAL_DENIAL_ENTRIES,
        )?);
        Ok(Self {
            store: ExactFileStore::new(root, StoreRole::LocalCreateDenial),
            request: request.to_vec(),
        })
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self
            .store
            .load(StoreRole::LocalCreateDenial.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            self.validate(bytes)?;
            self.store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(bytes)?;
        self.store.commit_with_replacement(bytes, false)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalCreateDenial.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        super::local_create::verify_denial(&self.request, bytes)
            .map(|_| ())
            .map_err(|_| CleanFileStoreError::Corrupt)
    }
}

impl CleanLocalCreateRequestFile {
    pub(crate) fn open_or_create(root: impl AsRef<Path>) -> Result<Self, CleanFileStoreError> {
        let root = Arc::new(StoreRoot::open_with_entries(
            root.as_ref(),
            &LOCAL_REQUEST_ENTRIES,
        )?);
        Ok(Self(ExactFileStore::new(
            root,
            StoreRole::LocalCreateRequest,
        )))
    }

    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let bytes = self.0.load(StoreRole::LocalCreateRequest.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            Self::validate(bytes)?;
            // A prior publication may have renamed successfully but failed
            // its directory sync. Re-establish durability before a retry sends.
            self.0.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    pub(crate) fn publish(&mut self, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        Self::validate(bytes)?;
        self.0.commit_with_replacement(bytes, false)
    }

    fn validate(bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > StoreRole::LocalCreateRequest.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let (_, call) = super::local_create::decode_retained_request(bytes)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        if call.authenticated_node.is_some() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }
}

/// A configured private directory for per-agent lifecycle images. Keeping the
/// opened directory pins its physical identity across factory calls; image
/// signatures/bindings remain the controller's responsibility.
pub(crate) struct CleanManagementLifecycleStoreFactory {
    parent: PathBuf,
    directory: File,
    space: vos::agent::sdk::SpaceId,
    layout: LifecycleLayout,
}

impl CleanManagementLifecycleStoreFactory {
    pub(crate) fn open_or_create(
        parent: impl AsRef<Path>,
        space: vos::agent::sdk::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_or_create_format(parent.as_ref(), space, LifecycleLayout::ImageLocal)
    }

    // Retained only to qualify durable lifecycle files for the external-state
    // storage workstream. Released startup never selects this Local format.
    #[cfg(all(test, feature = "experimental-state-blocks"))]
    pub(crate) fn open_or_create_external(
        parent: impl AsRef<Path>,
        space: vos::agent::sdk::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_or_create_format(parent.as_ref(), space, LifecycleLayout::ExternalLocal)
    }

    fn open_or_create_format(
        path: &Path,
        space: vos::agent::sdk::SpaceId,
        layout: LifecycleLayout,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let directory = ensure_private_directory(path)?;
        Ok(Self {
            parent: path.to_path_buf(),
            directory,
            space,
            layout,
        })
    }

    pub(crate) fn new(
        parent: impl AsRef<Path>,
        space: vos::agent::sdk::SpaceId,
    ) -> Result<Self, CleanFileStoreError> {
        if space == vos::agent::sdk::SpaceId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let parent = parent.as_ref().to_path_buf();
        let directory = open_private_directory(&parent, true)?;
        Ok(Self {
            parent,
            directory,
            space,
            layout: LifecycleLayout::ImageLocal,
        })
    }
}

/// Create one private directory under an existing validated private parent.
pub(crate) fn ensure_private_directory(path: &Path) -> Result<File, CleanFileStoreError> {
    validate_new_path(path)?;
    let ancestor =
        open_private_directory(path.parent().ok_or(CleanFileStoreError::InvalidPath)?, true)?;
    let (directory, created) = open_or_create_child_directory(&ancestor, path)?;
    if created {
        set_private_directory_permissions(&directory)?;
        directory.sync_all()?;
        ancestor.sync_all()?;
    }
    validate_opened_directory(&directory, path, false)?;
    Ok(directory)
}

impl vos::agent::local_lifecycle::LocalLifecycleStoreFactory
    for CleanManagementLifecycleStoreFactory
{
    type Intent = CleanManagementIntentFile;
    type Issuer = CleanManagementIssuerFile;
    type Error = CleanFileStoreError;

    fn discover(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        maximum: usize,
    ) -> Result<Vec<vos::agent::sdk::AgentId>, Self::Error> {
        if space != self.space {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        // Scan the pinned directory, not a pathname that can be replaced
        // between validation and read_dir. This backend already relies on
        // Linux descriptor-relative physical storage boundaries.
        #[cfg(target_os = "linux")]
        let scan = PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let scan: PathBuf = return Err(CleanFileStoreError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-pinned lifecycle discovery requires Linux",
        )));
        let mut agents = Vec::new();
        for entry in fs::read_dir(scan)? {
            let entry = entry?;
            if agents.len() == maximum {
                return Err(CleanFileStoreError::Oversized);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CleanFileStoreError::UnexpectedResidue);
            }
            let mut bytes = [0; 32];
            hex::decode_to_slice(&name, &mut bytes)
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            let agent = vos::agent::sdk::AgentId(bytes);
            if agent == vos::agent::sdk::AgentId::ZERO {
                return Err(CleanFileStoreError::UnexpectedResidue);
            }
            let path = self.parent.join(&name);
            let directory = open_child_directory(&self.directory, &path)?;
            validate_opened_directory(&directory, &path, false)?;
            agents.push(agent);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        agents.sort_unstable();
        if agents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CleanFileStoreError::Alias);
        }
        Ok(agents)
    }

    fn open_existing(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        agent: vos::agent::sdk::AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error> {
        if space != self.space || agent == vos::agent::sdk::AgentId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let stores = CleanManagementLifecycleFiles::open(
            &self.parent.join(hex::encode(agent.0)),
            self.layout,
            true,
        )?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok(stores.into_parts())
    }

    fn open(
        &mut self,
        space: vos::agent::sdk::SpaceId,
        agent: vos::agent::sdk::AgentId,
    ) -> Result<(Self::Intent, Self::Issuer), Self::Error> {
        if space != self.space || agent == vos::agent::sdk::AgentId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        validate_opened_directory(&self.directory, &self.parent, true)?;
        let stores = CleanManagementLifecycleFiles::open(
            &self.parent.join(hex::encode(agent.0)),
            self.layout,
            false,
        )?;
        validate_opened_directory(&self.directory, &self.parent, true)?;
        Ok(stores.into_parts())
    }
}

impl CleanManagementIssuerStore for CleanManagementIntentFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        if self.0.role == StoreRole::ManagementIntent
            && self.0.root.allowed_entries == SHARED_LIFECYCLE_ENTRIES
            && CleanManagementIssuerFile(ExactFileStore::new(
                Arc::clone(&self.0.root),
                StoreRole::LifecycleIssuer,
            ))
            .issuance_disabled()?
        {
            return self.0.commit_with_replacement(image, false);
        }
        self.0.commit(image)
    }
}

impl CleanSharedManagementIntentStore for CleanManagementIntentFile {
    fn load_shared_install_handoff(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        if self.0.role != StoreRole::SharedManagementIntent {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let mut store =
            ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedInstallHandoff);
        let bytes = store.load(StoreRole::SharedInstallHandoff.maximum_bytes())?;
        if let Some(bytes) = &bytes {
            store.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    fn commit_shared_install_handoff(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.0.role != StoreRole::SharedManagementIntent {
            return Err(CleanFileStoreError::InvalidPath);
        }
        ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedInstallHandoff).commit(bytes)
    }

    fn management_intent_continuation(&mut self) -> Result<Self, Self::Error> {
        if self.0.role != StoreRole::ManagementIntent
            || self.0.root.allowed_entries != SHARED_LIFECYCLE_ENTRIES
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let root = &self.0.root;
        Ok(Self(
            ExactFileStore::new(Arc::clone(root), StoreRole::SharedManagementIntent),
            ExactFileStore::new(Arc::clone(root), StoreRole::LifecycleRuntime),
            ExactFileStore::new(Arc::clone(root), StoreRole::SharedManagementActor),
            ExactFileStore::new(Arc::clone(root), StoreRole::ExternalLocalCreateArchive),
            ExactFileStore::new(Arc::clone(root), StoreRole::ExternalLocalPendingInstall),
        ))
    }
}

impl CleanManagementRuntimeStore for CleanManagementIntentFile {
    fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let image = self.1.load(MAX_PACKAGE_ENCODED_BYTES)?;
        if let Some(bytes) = &image {
            // An earlier rename may have succeeded before directory sync
            // failed. Reestablish durability before recovery uses this package.
            self.1.commit_with_replacement(bytes, false)?;
        }
        Ok(image)
    }
    fn commit_runtime(&mut self, package: &[u8]) -> Result<(), Self::Error> {
        match self.load_runtime()? {
            Some(bytes) if bytes == package => Ok(()),
            Some(_) => Err(CleanFileStoreError::RequestConflict),
            None => self.1.commit(package),
        }
    }
}

impl CleanManagementActorStore for CleanManagementIntentFile {
    fn load_actor(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.2.load(MAX_PACKAGE_ENCODED_BYTES)
    }
    fn commit_actor(&mut self, package: &[u8]) -> Result<(), Self::Error> {
        self.2.commit(package)
    }
}

impl CleanExternalLocalCreateArchiveStore for CleanManagementIntentFile {
    fn load_external_create_archive(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let image = self.3.load(MAX_CLEAN_EXTERNAL_LOCAL_CREATE_ARCHIVE_BYTES)?;
        if let Some(bytes) = &image {
            self.3.commit_with_replacement(bytes, false)?;
        }
        Ok(image)
    }

    fn commit_external_create_archive(&mut self, archive: &[u8]) -> Result<(), Self::Error> {
        self.3.commit_with_replacement(archive, false)
    }
}

#[cfg(feature = "experimental-state-blocks")]
impl CleanExternalLocalPendingInstallStore for CleanManagementIntentFile {
    fn load_pending_install(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        let image = self
            .4
            .load(StoreRole::ExternalLocalPendingInstall.maximum_bytes())?;
        if let Some(bytes) = &image {
            self.4.commit_with_replacement(bytes, false)?;
        }
        Ok(image)
    }

    fn commit_pending_install(&mut self, submission: &[u8]) -> Result<(), Self::Error> {
        self.4.commit(submission)
    }
}

impl CleanSystemAgentGenesisFile {
    pub(crate) fn load(&mut self) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        self.0.load(MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES)
    }

    pub(crate) fn commit(&mut self, image: &[u8]) -> Result<(), CleanFileStoreError> {
        self.0.commit(image)
    }
}

impl CleanSystemAgentBootstrapStore for CleanSystemAgentPinsFile {
    type Error = CleanFileStoreError;

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(maximum_bytes)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl CleanSystemAgentBootstrapStore for CleanSystemAgentBootstrapFile {
    type Error = CleanFileStoreError;

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(maximum_bytes)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.0.commit(image)
    }
}

impl CleanManagementIssuerStore for CleanManagementIssuerFile {
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES)
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        if self.issuance_disabled()? {
            return self.0.commit_with_replacement(image, false);
        }
        self.0.commit(image)
    }

    fn issuance_disabled(&mut self) -> Result<bool, Self::Error> {
        if self.0.role != StoreRole::LifecycleIssuer
            || self.0.root.allowed_entries != SHARED_LIFECYCLE_ENTRIES
        {
            return Ok(false);
        }
        Ok(self.load_management_handoff()?.is_some()
            || self.management_continuation()?.load()?.is_some()
            || ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedManagementIntent)
                .load(MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES)?
                .is_some()
            || ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedManagementActor)
                .load(MAX_PACKAGE_ENCODED_BYTES)?
                .is_some()
            || ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedInstallHandoff)
                .load(StoreRole::SharedInstallHandoff.maximum_bytes())?
                .is_some())
    }
}

impl CleanSharedManagementIssuerStore for CleanManagementIssuerFile {
    fn load_management_handoff(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.validate_shared_source()?;
        let mut marker =
            ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedManagementHandoff);
        let bytes = marker.load(36)?;
        if let Some(bytes) = &bytes {
            // A previous rename may have preceded a failed directory sync.
            marker.commit_with_replacement(bytes, false)?;
        }
        Ok(bytes)
    }

    fn commit_management_handoff(&mut self, marker: &[u8]) -> Result<(), Self::Error> {
        self.validate_shared_source()?;
        if marker.len() != 36 || &marker[..4] != b"SMH1" {
            return Err(CleanFileStoreError::Corrupt);
        }
        ExactFileStore::new(Arc::clone(&self.0.root), StoreRole::SharedManagementHandoff)
            .commit_with_replacement(marker, false)
    }

    fn management_continuation(&mut self) -> Result<Self, Self::Error> {
        self.validate_shared_source()?;
        Ok(Self(ExactFileStore::new(
            Arc::clone(&self.0.root),
            StoreRole::SharedManagementIssuer,
        )))
    }
}

impl CleanManagementIssuerFile {
    fn validate_shared_source(&self) -> Result<(), CleanFileStoreError> {
        if self.0.role != StoreRole::LifecycleIssuer
            || self.0.root.allowed_entries != SHARED_LIFECYCLE_ENTRIES
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(())
    }
}

struct StoreRoot {
    allowed_entries: &'static [&'static str],
    operation_records: bool,
    parent_path: PathBuf,
    parent: File,
    path: PathBuf,
    directory: File,
    lock: File,
    writes: Mutex<()>,
}

impl StoreRoot {
    fn open_or_create(path: &Path) -> Result<Self, CleanFileStoreError> {
        Self::open_with_entries(path, &ALLOWED_ENTRIES)
    }

    fn open_with_entries(
        path: &Path,
        allowed_entries: &'static [&'static str],
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_with_entries_mode(path, allowed_entries, true)
    }

    fn open_with_entries_mode(
        path: &Path,
        allowed_entries: &'static [&'static str],
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_namespace(path, allowed_entries, create, false)
    }

    fn open_namespace(
        path: &Path,
        allowed_entries: &'static [&'static str],
        create: bool,
        operation_records: bool,
    ) -> Result<Self, CleanFileStoreError> {
        validate_new_path(path)?;
        let parent_path = path.parent().ok_or(CleanFileStoreError::InvalidPath)?;
        let parent = open_private_directory(parent_path, true)?;
        let (directory, created) = if create {
            open_or_create_child_directory(&parent, path)?
        } else {
            (open_child_directory(&parent, path)?, false)
        };
        if created {
            set_private_directory_permissions(&directory)?;
        }
        let opened = directory.metadata()?;
        validate_private_directory_metadata(&opened, false)?;
        let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
        validate_private_directory_metadata(&named, false)?;
        same_file_identity(&opened, &named)?;
        if created {
            directory.sync_all()?;
            parent.sync_all()?;
        }
        audit_named_entries(path, allowed_entries, operation_records)?;
        let lock = open_lock(&directory, path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(CleanFileStoreError::Busy);
            }
            Err(error) => return Err(error.into()),
        }
        let root = Self {
            allowed_entries,
            operation_records,
            parent_path: parent_path.to_path_buf(),
            parent,
            path: path.to_path_buf(),
            directory,
            lock,
            writes: Mutex::new(()),
        };
        root.validate_path()?;
        root.audit_entries()?;
        Ok(root)
    }

    fn guard(&self) -> Result<MutexGuard<'_, ()>, CleanFileStoreError> {
        self.writes
            .lock()
            .map_err(|_| CleanFileStoreError::LockPoisoned)
    }

    fn validate_path(&self) -> Result<(), CleanFileStoreError> {
        self.validate_directory_path()?;
        self.validate_lock()?;
        self.validate_directory_path()
    }

    fn validate_directory_path(&self) -> Result<(), CleanFileStoreError> {
        validate_opened_directory(&self.parent, &self.parent_path, true)?;
        let named = fs::symlink_metadata(&self.path).map_err(CleanFileStoreError::Io)?;
        validate_private_directory_metadata(&named, false)?;
        let opened = self.directory.metadata()?;
        same_file_identity(&opened, &named)?;
        let entry = open_child_directory(&self.parent, &self.path)?;
        same_file_identity(&entry.metadata()?, &opened)?;
        let canonical = fs::canonicalize(&self.path).map_err(CleanFileStoreError::Io)?;
        if canonical != self.path {
            return Err(CleanFileStoreError::Alias);
        }
        Ok(())
    }

    fn validate_lock(&self) -> Result<(), CleanFileStoreError> {
        let named = named_metadata(&self.path, LOCK_FILE)?;
        validate_private_regular_metadata(&named)?;
        validate_opened_file(&self.lock, &named)?;
        if named.len() != 0 {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }

    fn audit_entries(&self) -> Result<(), CleanFileStoreError> {
        self.validate_path()?;
        audit_named_entries(&self.path, self.allowed_entries, self.operation_records)?;
        self.validate_path()
    }

    fn sync(&self) -> Result<(), CleanFileStoreError> {
        self.validate_path()?;
        self.directory.sync_all()?;
        self.validate_path()
    }
}

// Test-only, thread- and root-scoped interruption after syncing the staged file and
// before publication. Production builds have no fault configuration surface.
#[cfg(test)]
std::thread_local! {
    static SHARED_MANAGEMENT_STAGE_FAULT: std::cell::RefCell<Option<(PathBuf, StoreRole, usize)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) struct SharedManagementStageFault;

#[cfg(test)]
impl SharedManagementStageFault {
    pub(super) fn install_handoff(root: &Path) -> Self {
        Self::arm(root, StoreRole::SharedInstallHandoff, 1)
    }

    pub(super) fn actor(root: &Path) -> Self {
        Self::arm(root, StoreRole::SharedManagementActor, 1)
    }

    pub(super) fn intent(root: &Path, changed_write: usize) -> Self {
        Self::arm(root, StoreRole::SharedManagementIntent, changed_write)
    }

    pub(super) fn issuer(root: &Path, changed_write: usize) -> Self {
        Self::arm(root, StoreRole::SharedManagementIssuer, changed_write)
    }

    fn arm(root: &Path, role: StoreRole, changed_write: usize) -> Self {
        assert!(changed_write > 0);
        SHARED_MANAGEMENT_STAGE_FAULT.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some((root.to_owned(), role, changed_write));
        });
        Self
    }

    pub(super) fn fired(&self) -> bool {
        SHARED_MANAGEMENT_STAGE_FAULT.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|(_, _, remaining)| *remaining == 0)
        })
    }
}

#[cfg(test)]
impl Drop for SharedManagementStageFault {
    fn drop(&mut self) {
        SHARED_MANAGEMENT_STAGE_FAULT.with(|slot| *slot.borrow_mut() = None);
    }
}

struct ExactFileStore {
    root: Arc<StoreRoot>,
    role: StoreRole,
    names: Option<(String, String)>,
}

impl ExactFileStore {
    fn new(root: Arc<StoreRoot>, role: StoreRole) -> Self {
        Self {
            root,
            role,
            names: None,
        }
    }

    fn operation_record(
        root: Arc<StoreRoot>,
        invocation: vos::agent::sdk::InvocationId,
    ) -> Result<Self, CleanFileStoreError> {
        Self::invocation_record(root, invocation, StoreRole::OperationDispatch)
    }

    fn invocation_record(
        root: Arc<StoreRoot>,
        invocation: vos::agent::sdk::InvocationId,
        role: StoreRole,
    ) -> Result<Self, CleanFileStoreError> {
        if !root.operation_records || invocation == vos::agent::sdk::InvocationId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let name = hex::encode(invocation.0);
        let stage = format!("{name}.next");
        Ok(Self {
            root,
            role,
            names: Some((name, stage)),
        })
    }

    fn file(&self) -> &str {
        self.names
            .as_ref()
            .map_or_else(|| self.role.file(), |names| names.0.as_str())
    }

    fn stage_file(&self) -> &str {
        self.names
            .as_ref()
            .map_or_else(|| self.role.stage_file(), |names| names.1.as_str())
    }

    fn load(&mut self, maximum_bytes: usize) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let _guard = self.root.guard()?;
        let maximum_bytes = maximum_bytes.min(self.role.maximum_bytes());
        self.reconcile(maximum_bytes)
            .map(|stored| stored.map(|stored| stored.payload))
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), CleanFileStoreError> {
        self.commit_with_replacement(image, true)
    }

    fn commit_with_replacement(
        &mut self,
        image: &[u8],
        replace: bool,
    ) -> Result<(), CleanFileStoreError> {
        if image.len() > self.role.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let _guard = self.root.guard()?;
        let current = self.reconcile(self.role.maximum_bytes())?;
        if current
            .as_ref()
            .is_some_and(|current| current.payload == image)
        {
            self.sync_named(self.file())?;
            return self.root.sync();
        }
        if !replace && current.is_some() {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let predecessor = current.as_ref().map(StoredImage::commitment);
        let encoded = encode_envelope(self.role, predecessor, image)?;
        self.write_stage(&encoded)?;
        #[cfg(test)]
        if SHARED_MANAGEMENT_STAGE_FAULT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some((root, role, remaining)) = slot.as_mut() else {
                return false;
            };
            if root != &self.root.path || *role != self.role || *remaining == 0 {
                return false;
            }
            *remaining -= 1;
            *remaining == 0
        }) {
            return Err(
                std::io::Error::other("injected Shared management publication failure").into(),
            );
        }
        self.publish_stage(
            current.as_ref(),
            &decode_envelope(self.role, &encoded, image.len())?,
        )
    }

    fn reconcile(&self, maximum_bytes: usize) -> Result<Option<StoredImage>, CleanFileStoreError> {
        self.root.audit_entries()?;
        let canonical = self.read_optional(self.file(), maximum_bytes)?;
        let staged = self.read_optional(self.stage_file(), maximum_bytes)?;
        if matches!(
            self.role,
            StoreRole::LocalCreateRequest
                | StoreRole::ExternalLocalCreateArchive
                | StoreRole::OrdinaryGenesisArchive
                | StoreRole::OrdinaryGenesisQuery
                | StoreRole::OrdinaryGenesisReply
                | StoreRole::OrdinaryGenesisPublication
                | StoreRole::OrdinaryGenesisPublicationReply
                | StoreRole::OrdinaryGenesisReplicas
                | StoreRole::SharedManagementHandoff
                | StoreRole::CredentialQuery
                | StoreRole::LocalCreateAcknowledgement
                | StoreRole::LocalCreateDenial
                | StoreRole::OperationDispatch
                | StoreRole::AdminDispatch
                | StoreRole::AdminResult
                | StoreRole::AdminRetirement
                | StoreRole::AdminPreparationRequest
                | StoreRole::AdminPreparationResponse
                | StoreRole::AdminClientRequest
                | StoreRole::AdminClientResponse
                | StoreRole::OperationRequest
                | StoreRole::OperationResponse
                | StoreRole::PreparationRequest
                | StoreRole::PreparationResponse
                | StoreRole::AuthorizationPreparationRequest
                | StoreRole::AuthorizationPreparationResponse
        ) && canonical
            .iter()
            .chain(staged.iter())
            .any(|image| image.predecessor.is_some())
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        let resolved = match (canonical, staged) {
            (None, None) => None,
            (Some(canonical), None) => Some(canonical),
            (None, Some(staged)) if staged.predecessor.is_none() => {
                self.publish_stage(None, &staged)?;
                Some(staged)
            }
            (Some(canonical), Some(staged)) if canonical == staged => {
                self.unlink_stage()?;
                Some(canonical)
            }
            (Some(canonical), Some(staged))
                if staged.predecessor == Some(canonical.commitment()) =>
            {
                self.publish_stage(Some(&canonical), &staged)?;
                Some(staged)
            }
            (None, Some(_)) | (Some(_), Some(_)) => {
                return Err(CleanFileStoreError::AmbiguousPublication);
            }
        };
        self.root.audit_entries()?;
        Ok(resolved)
    }

    fn read_optional(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Option<StoredImage>, CleanFileStoreError> {
        let named = match named_metadata(&self.root.path, name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_private_regular_metadata(&named)?;
        let mut file = open_read_at(&self.root.directory, &self.root.path, name)?;
        validate_opened_file(&file, &named)?;
        let physical_maximum = STORE_HEADER_BYTES
            .checked_add(maximum_bytes)
            .ok_or(CleanFileStoreError::Oversized)?;
        let length = usize::try_from(named.len()).map_err(|_| CleanFileStoreError::Oversized)?;
        if length > physical_maximum {
            return Err(CleanFileStoreError::Oversized);
        }
        if length < STORE_HEADER_BYTES {
            return Err(CleanFileStoreError::Corrupt);
        }
        let mut header = [0_u8; STORE_HEADER_BYTES];
        read_exact_or_corrupt(&mut file, &mut header)?;
        let payload_length = decode_payload_length(self.role, &header, maximum_bytes)?;
        if STORE_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or(CleanFileStoreError::Oversized)?
            != length
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_length)
            .map_err(|_| CleanFileStoreError::Oversized)?;
        payload.resize(payload_length, 0);
        read_exact_or_corrupt(&mut file, &mut payload)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(CleanFileStoreError::Io)? != 0 {
            return Err(CleanFileStoreError::Corrupt);
        }
        let after = file.metadata()?;
        validate_opened_file(&file, &named)?;
        if after.len() != named.len() {
            return Err(CleanFileStoreError::Corrupt);
        }
        decode_envelope_parts(self.role, &header, payload).map(Some)
    }

    fn write_stage(&self, encoded: &[u8]) -> Result<(), CleanFileStoreError> {
        let name = self.stage_file();
        let mut file = match create_new_at(&self.root.directory, &self.root.path, name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(CleanFileStoreError::StageCollision);
            }
            Err(error) => return Err(error.into()),
        };
        let result = (|| -> Result<(), CleanFileStoreError> {
            set_private_file_permissions(&file)?;
            file.write_all(encoded)?;
            file.sync_all()?;
            let named = named_metadata(&self.root.path, name)?;
            validate_private_regular_metadata(&named)?;
            validate_opened_file(&file, &named)?;
            if usize::try_from(named.len()).ok() != Some(encoded.len()) {
                return Err(CleanFileStoreError::Corrupt);
            }
            Ok(())
        })();
        if result.is_err() {
            self.remove_owned_failed_stage(&file, name);
        }
        result
    }

    fn remove_owned_failed_stage(&self, file: &File, name: &str) {
        let Ok(named) = named_metadata(&self.root.path, name) else {
            return;
        };
        if validate_private_regular_metadata(&named).is_err()
            || validate_opened_file(file, &named).is_err()
        {
            return;
        }
        if unlink_at(&self.root.directory, &self.root.path, name).is_ok() {
            let _ = self.root.sync();
        }
    }

    fn publish_stage(
        &self,
        expected: Option<&StoredImage>,
        staged: &StoredImage,
    ) -> Result<(), CleanFileStoreError> {
        let observed_stage = self
            .read_optional(self.stage_file(), self.role.maximum_bytes())?
            .ok_or(CleanFileStoreError::AmbiguousPublication)?;
        if &observed_stage != staged {
            return Err(CleanFileStoreError::AmbiguousPublication);
        }
        let observed_canonical = self.read_optional(self.file(), self.role.maximum_bytes())?;
        if observed_canonical.as_ref() != expected
            || staged.predecessor != expected.map(StoredImage::commitment)
        {
            return Err(CleanFileStoreError::AmbiguousPublication);
        }
        self.sync_named(self.stage_file())?;
        rename_at(
            &self.root.directory,
            &self.root.path,
            self.stage_file(),
            self.file(),
        )?;
        self.root.sync()?;
        let published = self
            .read_optional(self.file(), self.role.maximum_bytes())?
            .ok_or(CleanFileStoreError::Corrupt)?;
        if &published != staged {
            return Err(CleanFileStoreError::Corrupt);
        }
        match named_metadata(&self.root.path, self.stage_file()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(CleanFileStoreError::Corrupt),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn unlink_stage(&self) -> Result<(), CleanFileStoreError> {
        unlink_at(&self.root.directory, &self.root.path, self.stage_file())?;
        self.root.sync()
    }

    fn sync_named(&self, name: &str) -> Result<(), CleanFileStoreError> {
        let named = named_metadata(&self.root.path, name)?;
        validate_private_regular_metadata(&named)?;
        let file = open_read_at(&self.root.directory, &self.root.path, name)?;
        validate_opened_file(&file, &named)?;
        file.sync_all()?;
        Ok(())
    }
}

fn read_exact_or_corrupt(
    reader: &mut impl Read,
    buffer: &mut [u8],
) -> Result<(), CleanFileStoreError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(CleanFileStoreError::Corrupt)
        }
        Err(error) => Err(CleanFileStoreError::Io(error)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredImage {
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: Vec<u8>,
}

impl StoredImage {
    fn commitment(&self) -> [u8; 32] {
        envelope_digest(self.role, self.predecessor, &self.payload)
    }
}

fn encode_envelope(
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: &[u8],
) -> Result<Vec<u8>, CleanFileStoreError> {
    if payload.len() > role.maximum_bytes()
        || predecessor.is_some_and(|predecessor| predecessor == NO_PREDECESSOR)
    {
        return Err(CleanFileStoreError::Corrupt);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(
            STORE_HEADER_BYTES
                .checked_add(payload.len())
                .ok_or(CleanFileStoreError::Oversized)?,
        )
        .map_err(|_| CleanFileStoreError::Oversized)?;
    encoded.extend_from_slice(&STORE_MAGIC);
    encoded.push(STORE_VERSION);
    encoded.push(role as u8);
    encoded.push(u8::from(predecessor.is_some()));
    encoded.push(0);
    encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded.extend_from_slice(&predecessor.unwrap_or(NO_PREDECESSOR));
    encoded.extend_from_slice(&envelope_digest(role, predecessor, payload));
    encoded.extend_from_slice(payload);
    debug_assert_eq!(encoded.len(), STORE_HEADER_BYTES + payload.len());
    Ok(encoded)
}

fn decode_payload_length(
    expected_role: StoreRole,
    header: &[u8; STORE_HEADER_BYTES],
    maximum_bytes: usize,
) -> Result<usize, CleanFileStoreError> {
    if header[..4] != STORE_MAGIC || header[4] != STORE_VERSION || header[7] != 0 {
        return Err(CleanFileStoreError::Corrupt);
    }
    let role = StoreRole::from_byte(header[5]).ok_or(CleanFileStoreError::Corrupt)?;
    if role != expected_role {
        return Err(CleanFileStoreError::WrongStoreRole);
    }
    let length = u64::from_le_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| CleanFileStoreError::Corrupt)?,
    );
    let length = usize::try_from(length).map_err(|_| CleanFileStoreError::Oversized)?;
    if length > maximum_bytes || length > expected_role.maximum_bytes() {
        return Err(CleanFileStoreError::Oversized);
    }
    Ok(length)
}

fn decode_envelope(
    role: StoreRole,
    encoded: &[u8],
    maximum_bytes: usize,
) -> Result<StoredImage, CleanFileStoreError> {
    if encoded.len() < STORE_HEADER_BYTES {
        return Err(CleanFileStoreError::Corrupt);
    }
    let header: &[u8; STORE_HEADER_BYTES] = encoded[..STORE_HEADER_BYTES]
        .try_into()
        .map_err(|_| CleanFileStoreError::Corrupt)?;
    let length = decode_payload_length(role, header, maximum_bytes)?;
    if encoded.len() != STORE_HEADER_BYTES + length {
        return Err(CleanFileStoreError::Corrupt);
    }
    decode_envelope_parts(role, header, encoded[STORE_HEADER_BYTES..].to_vec())
}

fn decode_envelope_parts(
    role: StoreRole,
    header: &[u8; STORE_HEADER_BYTES],
    payload: Vec<u8>,
) -> Result<StoredImage, CleanFileStoreError> {
    let length = decode_payload_length(role, header, role.maximum_bytes())?;
    let predecessor_bytes: [u8; 32] = header[16..48]
        .try_into()
        .map_err(|_| CleanFileStoreError::Corrupt)?;
    let predecessor = match header[6] {
        0 if predecessor_bytes == NO_PREDECESSOR => None,
        1 if predecessor_bytes != NO_PREDECESSOR => Some(predecessor_bytes),
        _ => return Err(CleanFileStoreError::Corrupt),
    };
    if payload.len() != length || header[48..80] != envelope_digest(role, predecessor, &payload) {
        return Err(CleanFileStoreError::Corrupt);
    }
    let stored = StoredImage {
        role,
        predecessor,
        payload,
    };
    if stored.commitment() == NO_PREDECESSOR {
        return Err(CleanFileStoreError::Corrupt);
    }
    Ok(stored)
}

fn envelope_digest(role: StoreRole, predecessor: Option<[u8; 32]>, payload: &[u8]) -> [u8; 32] {
    digest(ENVELOPE_DIGEST_DOMAIN, role, predecessor, payload)
}

fn digest(
    domain: &[u8],
    role: StoreRole,
    predecessor: Option<[u8; 32]>,
    payload: &[u8],
) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(domain);
    state.update(&[role as u8]);
    state.update(&[u8::from(predecessor.is_some())]);
    state.update(&predecessor.unwrap_or(NO_PREDECESSOR));
    state.update(&(payload.len() as u64).to_le_bytes());
    state.update(payload);
    let hash = state.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

fn validate_new_path(path: &Path) -> Result<(), CleanFileStoreError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CleanFileStoreError::InvalidPath);
    }
    let parent = path.parent().ok_or(CleanFileStoreError::InvalidPath)?;
    let canonical_parent = fs::canonicalize(parent).map_err(CleanFileStoreError::Io)?;
    if canonical_parent != parent {
        return Err(CleanFileStoreError::Alias);
    }
    let metadata = fs::symlink_metadata(parent).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&metadata, true)
}

fn open_private_directory(path: &Path, parent: bool) -> Result<File, CleanFileStoreError> {
    let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&named, parent)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    let file = options.open(path).map_err(CleanFileStoreError::Io)?;
    same_file_identity(&file.metadata()?, &named)?;
    Ok(file)
}

fn validate_opened_directory(
    file: &File,
    path: &Path,
    parent: bool,
) -> Result<(), CleanFileStoreError> {
    let named = fs::symlink_metadata(path).map_err(CleanFileStoreError::Io)?;
    validate_private_directory_metadata(&named, parent)?;
    let opened = file.metadata()?;
    validate_private_directory_metadata(&opened, parent)?;
    same_file_identity(&opened, &named)?;
    let canonical = fs::canonicalize(path).map_err(CleanFileStoreError::Io)?;
    if canonical != path {
        return Err(CleanFileStoreError::Alias);
    }
    Ok(())
}

#[cfg(unix)]
fn child_name(path: &Path) -> Result<CString, CleanFileStoreError> {
    let name = path.file_name().ok_or(CleanFileStoreError::InvalidPath)?;
    CString::new(name.as_bytes()).map_err(|_| CleanFileStoreError::InvalidPath)
}

#[cfg(unix)]
fn open_child_directory(parent: &File, path: &Path) -> Result<File, CleanFileStoreError> {
    let name = child_name(path)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_or_create_child_directory(
    parent: &File,
    path: &Path,
) -> Result<(File, bool), CleanFileStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_private_directory_metadata(&metadata, false)?;
            let directory = open_child_directory(parent, path)?;
            same_file_identity(&directory.metadata()?, &metadata)?;
            Ok((directory, false))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = child_name(path)?;
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if result != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let directory = open_child_directory(parent, path)?;
            Ok((directory, true))
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_private_directory_metadata(
    metadata: &fs::Metadata,
    parent: bool,
) -> Result<(), CleanFileStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(CleanFileStoreError::Alias);
    }
    if !metadata.is_dir() {
        return Err(if parent {
            CleanFileStoreError::InsecureParent
        } else {
            CleanFileStoreError::InsecureRoot
        });
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(if parent {
                CleanFileStoreError::InsecureParent
            } else {
                CleanFileStoreError::InsecureRoot
            });
        }
    }
    Ok(())
}

fn validate_private_regular_metadata(metadata: &fs::Metadata) -> Result<(), CleanFileStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(CleanFileStoreError::Alias);
    }
    if !metadata.is_file() {
        return Err(CleanFileStoreError::NonRegular);
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err(CleanFileStoreError::InsecurePermissions);
        }
        if metadata.nlink() == 0 {
            return Err(CleanFileStoreError::Alias);
        }
        if metadata.nlink() > 1 {
            return Err(CleanFileStoreError::HardLink);
        }
    }
    Ok(())
}

const MAX_OPERATION_JOURNAL_RECORDS: usize =
    2 * vos::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS;

fn operation_record_name(name: &str) -> Option<vos::agent::sdk::InvocationId> {
    let name = name.strip_suffix(".next").unwrap_or(name);
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(name, &mut bytes).ok()?;
    (bytes != [0; 32]).then_some(vos::agent::sdk::InvocationId(bytes))
}

fn audit_named_entries(
    root: &Path,
    allowed_entries: &[&str],
    operation_records: bool,
) -> Result<(), CleanFileStoreError> {
    let mut records = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
        if !allowed_entries.contains(&name.as_str()) {
            if !operation_records || operation_record_name(&name).is_none() {
                return Err(CleanFileStoreError::UnexpectedResidue);
            }
            records += 1;
            if records > 2 * MAX_OPERATION_JOURNAL_RECORDS {
                return Err(CleanFileStoreError::Oversized);
            }
        }
        validate_private_regular_metadata(&fs::symlink_metadata(entry.path())?)?;
    }
    Ok(())
}

fn same_file_identity(
    opened: &fs::Metadata,
    named: &fs::Metadata,
) -> Result<(), CleanFileStoreError> {
    #[cfg(unix)]
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(CleanFileStoreError::Alias);
    }
    Ok(())
}

fn validate_opened_file(file: &File, named: &fs::Metadata) -> Result<(), CleanFileStoreError> {
    let opened = file.metadata()?;
    validate_private_regular_metadata(&opened)?;
    same_file_identity(&opened, named)
}

fn named_metadata(root: &Path, name: &str) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(root.join(name))
}

fn open_lock(directory: &File, root: &Path) -> Result<File, CleanFileStoreError> {
    let (file, created) = match create_new_at(directory, root, LOCK_FILE) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let named = named_metadata(root, LOCK_FILE)?;
            validate_private_regular_metadata(&named)?;
            let file = open_write_at(directory, root, LOCK_FILE)?;
            validate_opened_file(&file, &named)?;
            (file, false)
        }
        Err(error) => return Err(error.into()),
    };
    if created {
        set_private_file_permissions(&file)?;
        file.sync_all()?;
        directory.sync_all()?;
    }
    let named = named_metadata(root, LOCK_FILE)?;
    validate_private_regular_metadata(&named)?;
    validate_opened_file(&file, &named)?;
    if named.len() != 0 {
        return Err(CleanFileStoreError::Corrupt);
    }
    Ok(file)
}

fn set_private_file_permissions(file: &File) -> Result<(), CleanFileStoreError> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_private_directory_permissions(directory: &File) -> Result<(), CleanFileStoreError> {
    let result = unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn open_at(directory: &File, name: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_read_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
}

#[cfg(unix)]
fn open_write_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
}

#[cfg(unix)]
fn create_new_at(directory: &File, _root: &Path, name: &str) -> io::Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK,
        0o600,
    )
}

#[cfg(unix)]
fn rename_at(
    directory: &File,
    _root: &Path,
    from: &str,
    to: &str,
) -> Result<(), CleanFileStoreError> {
    let from = CString::new(from).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let to = CString::new(to).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn unlink_at(directory: &File, _root: &Path, name: &str) -> Result<(), CleanFileStoreError> {
    let name = CString::new(name).map_err(|_| CleanFileStoreError::InvalidPath)?;
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "clean_operation_journal_tests.rs"]
mod operation_journal_tests;

#[cfg(target_os = "linux")]
#[path = "clean_admin_store.rs"]
pub(crate) mod admin_store;

#[cfg(target_os = "linux")]
#[path = "clean_operation_completions.rs"]
mod operation_completions;
#[cfg(target_os = "linux")]
pub(crate) use operation_completions::CleanNativeAuthorityOperationCompletions;
#[cfg(target_os = "linux")]
pub(crate) use operation_completions::CleanNativeAuthorityOperationDenials;
#[cfg(target_os = "linux")]
pub(crate) use operation_completions::CleanNativeAuthorityOperationRetirements;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn check_denial_retention(request: &[u8], certificate: &[u8]) {
        let fixture = Fixture::new("denial-retention");
        let submission =
            vos::agent::local_lifecycle::LocalCreateSubmission::decode(request).unwrap();
        let (descriptor, call, _) = submission.into_parts();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            descriptor.identity.space,
            call.credential,
        )
        .unwrap();
        reservation.reserve(descriptor.creation_nonce).unwrap();
        let mut denial =
            CleanLocalCreateDenialFile::open_or_create(&fixture.root, request).unwrap();
        assert!(reservation.deny(&mut denial).is_err());
        assert_eq!(
            reservation.current().unwrap().unwrap().1,
            CredentialReservationStatus::Pending
        );
        assert!(matches!(
            CleanLocalCreateDenialFile::open_or_create(&fixture.root, request),
            Err(CleanFileStoreError::Busy)
        ));
        denial.publish(certificate).unwrap();
        let mut corrupt = certificate.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(denial.publish(&corrupt).is_err());
        assert_eq!(denial.load().unwrap().as_deref(), Some(certificate));
        // Simulate a process ending after certificate publication but before
        // reservation completion, preserving the exact independently leased files.
        drop(denial);
        drop(reservation);
        let mut denial =
            CleanLocalCreateDenialFile::open_or_create(&fixture.root, request).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &fixture.parent,
            descriptor.identity.space,
            call.credential,
        )
        .unwrap();
        reservation.deny(&mut denial).unwrap();
        reservation.deny(&mut denial).unwrap();
        assert_eq!(
            reservation.current().unwrap().unwrap().1,
            CredentialReservationStatus::Denied
        );
        assert_eq!(
            reservation.reserve(descriptor.creation_nonce).unwrap(),
            CredentialReservationStatus::Denied
        );
        assert_eq!(
            reservation
                .reserve(vos::agent::sdk::Hash([99; 32]))
                .unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(reservation.deny(&mut denial).is_err());
        assert_eq!(denial.load().unwrap().as_deref(), Some(certificate));
    }
    use std::io::{Seek as _, SeekFrom};
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    pub(super) struct Fixture {
        pub(super) parent: PathBuf,
        pub(super) root: PathBuf,
    }

    impl Fixture {
        pub(super) fn new(label: &str) -> Self {
            let mut nonce = [0_u8; 8];
            getrandom::getrandom(&mut nonce).expect("test entropy");
            let parent = std::env::temp_dir().join(format!(
                "vosx-clean-store-{label}-{}-{}",
                std::process::id(),
                hex::encode(nonce)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&parent).expect("create private test parent");
            #[cfg(unix)]
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .expect("set private test parent mode");
            let root = parent.join("state");
            Self { parent, root }
        }

        fn stores(&self) -> CleanSystemAgentFileStores {
            CleanSystemAgentFileStores::open_or_create(&self.root).expect("open clean stores")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&self.parent, fs::Permissions::from_mode(0o700));
                if let Ok(metadata) = fs::symlink_metadata(&self.root)
                    && metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                {
                    let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    pub(super) fn write_private(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).expect("create private test file");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set private test file mode");
        file.write_all(bytes).expect("write private test file");
        file.sync_all().expect("sync private test file");
        File::open(path.parent().unwrap())
            .and_then(|directory| directory.sync_all())
            .expect("sync private test directory");
    }

    pub(super) fn stage(
        store: &ExactFileStore,
        predecessor: Option<[u8; 32]>,
        payload: &[u8],
    ) -> StoredImage {
        let encoded = encode_envelope(store.role, predecessor, payload).expect("encode stage");
        let staged = decode_envelope(store.role, &encoded, payload.len()).expect("decode stage");
        store.write_stage(&encoded).expect("write stage");
        staged
    }

    #[cfg(target_os = "linux")]
    fn local_request(sequence: u64) -> Vec<u8> {
        let (operator, authority, descriptor, runtime) =
            super::super::local_create::tests::fixture();
        super::super::local_create::prepare(
            &operator,
            authority,
            descriptor,
            runtime,
            std::num::NonZeroU64::new(sequence).unwrap(),
            10,
            30,
        )
        .unwrap()
        .encode()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_reservation_keeps_pending_operation_across_restart() {
        use vos::agent::sdk::{CredentialId, Hash, SpaceId};
        let fixture = Fixture::new("credential-reservation");
        let space = SpaceId([1; 32]);
        let credential = CredentialId([2; 32]);
        let nonce = Hash([3; 32]);
        let mut store =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        assert!(matches!(
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.reserve(Hash::ZERO).is_err());
        assert_eq!(store.current().unwrap(), None);
        assert_eq!(
            store.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        let root = store.store.root.path.clone();
        let before = fs::read(root.join(RESERVATION_FILE)).unwrap();
        assert!(matches!(
            store.reserve(Hash([4; 32])),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(store.complete(b"LCQ1", b"MAA2").is_err());
        assert_eq!(fs::read(root.join(RESERVATION_FILE)).unwrap(), before);
        drop(store);
        let mut store =
            CleanCredentialReservation::open_or_create(&fixture.parent, space, credential).unwrap();
        assert_eq!(
            store.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        assert_eq!(
            store.reserve(nonce).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(matches!(
            store.reserve(Hash([4; 32])),
            Err(CleanFileStoreError::RequestConflict)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_create_requires_resume_and_rejects_a_different_retained_target() {
        let fixture = Fixture::new("fresh-create-pending");
        let (operator, _, descriptor, _) = super::super::local_create::tests::fixture();
        let identity =
            super::super::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
        let root = fixture.parent.join("agent-client");
        let _root = ensure_private_directory(&root).unwrap();
        let claims = root.join("credentials");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation = CleanCredentialReservation::open_or_create(
            &claims,
            descriptor.identity.space,
            identity.credential(),
        )
        .unwrap();
        reservation.reserve(descriptor.creation_nonce).unwrap();
        drop(reservation);
        let node = libp2p::identity::Keypair::ed25519_from_bytes([0x64; 32]).unwrap();
        let public = node.public().try_into_ed25519().unwrap().to_bytes();
        let create = |resume| {
            super::super::local_create::create_local(
                &fixture.parent,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                descriptor.identity.space,
                public,
                resume,
            )
        };
        assert!(create(false).unwrap_err().to_string().contains("--resume"));
        let operations = root.join("operations");
        let _operations = ensure_private_directory(&operations).unwrap();
        let operation = operations.join(format!(
            "{}-{}",
            hex::encode(identity.credential().0),
            hex::encode(descriptor.creation_nonce.0)
        ));
        let _operation = ensure_private_directory(&operation).unwrap();
        let request_root = operation.join("request");
        let bytes = local_request(2);
        CleanLocalCreateRequestFile::open_or_create(&request_root)
            .unwrap()
            .publish(&bytes)
            .unwrap();
        assert!(
            create(true)
                .unwrap_err()
                .to_string()
                .contains("retained Create differs")
        );
        assert_eq!(
            CleanLocalCreateRequestFile::open_or_create(&request_root)
                .unwrap()
                .load()
                .unwrap(),
            Some(bytes)
        );
        assert_eq!(
            CleanCredentialReservation::open_or_create(
                &claims,
                descriptor.identity.space,
                identity.credential()
            )
            .unwrap()
            .current()
            .unwrap(),
            Some((
                descriptor.creation_nonce,
                CredentialReservationStatus::Pending
            ))
        );
    }

    /// Called by the signed acknowledgement fixture; keeps its large setup out
    /// of the persistence test's stack frame.
    #[cfg(target_os = "linux")]
    pub(crate) fn check_reservation_completion(request: &[u8], acknowledgement: &[u8]) {
        use vos::agent::sdk::Hash;
        let fixture = Fixture::new("reservation-completion");
        let (descriptor, call, _) =
            vos::agent::local_lifecycle::LocalCreateSubmission::decode(request)
                .unwrap()
                .into_parts();
        let open = || {
            CleanCredentialReservation::open_or_create(
                &fixture.parent,
                descriptor.identity.space,
                call.credential,
            )
            .unwrap()
        };
        let mut store = open();
        assert!(store.complete(request, acknowledgement).is_err());
        store.reserve(descriptor.creation_nonce).unwrap();
        let mut forged = acknowledgement.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(store.complete(request, &forged).is_err());
        store.complete(request, acknowledgement).unwrap();
        store.complete(request, acknowledgement).unwrap();
        drop(store);
        let mut store = open();
        assert_eq!(
            store.reserve(descriptor.creation_nonce).unwrap(),
            CredentialReservationStatus::Completed
        );
        let next = Hash([91; 32]);
        assert_eq!(
            store.reserve(next).unwrap(),
            CredentialReservationStatus::Pending
        );
        assert!(matches!(
            store.complete(request, acknowledgement),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            store.reserve(next).unwrap(),
            CredentialReservationStatus::Pending
        );
    }

    #[cfg(target_os = "linux")]
    #[inline(never)]
    pub(crate) fn check_acknowledgement_storage(request: &[u8], acknowledgement: &[u8]) {
        let fixture = Fixture::new("local-create-acknowledgement");
        let open =
            || CleanLocalCreateAcknowledgementFile::open_or_create(&fixture.root, request).unwrap();
        let mut store = open();
        assert_eq!(store.load().unwrap(), None);
        let mut forged = acknowledgement.to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(store.publish(&forged).is_err());
        assert!(!fixture.root.join(LOCAL_ACK_FILE).exists());
        store.publish(acknowledgement).unwrap();
        let original = fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap();
        store.publish(acknowledgement).unwrap();
        assert!(store.publish(&forged).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            original
        );
        drop(store);
        let mut store = open();
        assert_eq!(store.load().unwrap().as_deref(), Some(acknowledgement));
        drop(store);
        let different = local_request(u64::MAX);
        assert_ne!(different, request);
        let mut wrong_scope =
            CleanLocalCreateAcknowledgementFile::open_or_create(&fixture.root, &different).unwrap();
        assert!(wrong_scope.load().is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            original
        );
        drop(wrong_scope);

        let staged_fixture = Fixture::new("local-create-acknowledgement-stage");
        let mut staged =
            CleanLocalCreateAcknowledgementFile::open_or_create(&staged_fixture.root, request)
                .unwrap();
        stage(&staged.store, None, acknowledgement);
        drop(staged);
        staged = CleanLocalCreateAcknowledgementFile::open_or_create(&staged_fixture.root, request)
            .unwrap();
        assert_eq!(staged.load().unwrap().as_deref(), Some(acknowledgement));
        assert!(!staged_fixture.root.join(LOCAL_ACK_STAGE_FILE).exists());
        let before = fs::read(staged_fixture.root.join(LOCAL_ACK_FILE)).unwrap();
        stage(&staged.store, Some([0x31; 32]), acknowledgement);
        assert!(matches!(
            staged.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(staged_fixture.root.join(LOCAL_ACK_FILE)).unwrap(),
            before
        );
        assert!(staged_fixture.root.join(LOCAL_ACK_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    fn credential_queries() -> (
        vos::agent::sdk::authority::AuthorityActorTarget,
        vos::agent::sdk::CredentialId,
        Vec<u8>,
        Vec<u8>,
    ) {
        use vos::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;
        use vos::agent::sdk::{authority::AuthorityProjectionSelector, wire::CanonicalWire as _};
        let (operator, authority, _, _) = super::super::local_create::tests::fixture();
        let mut signer = super::super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator::new(operator).unwrap();
        let first = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        let second = signer
            .authenticate(authority, AuthorityProjectionSelector::Credential)
            .unwrap();
        (
            authority,
            first.credential,
            first.encode().unwrap(),
            second.encode().unwrap(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_query_retains_exact_nonce_and_scope_under_one_lease() {
        use vos::agent::sdk::{
            authority::{AuthorityIngressAuthentication, AuthorityProjectionQuery},
            wire::CanonicalWire as _,
        };
        let fixture = Fixture::new("credential-query");
        let (authority, credential, first, second) = credential_queries();
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert!(matches!(
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential),
            Err(CleanFileStoreError::Busy)
        ));
        let mut forged = AuthorityProjectionQuery::decode(&first).unwrap();
        let AuthorityIngressAuthentication::ApiCredentialSignature { signature, .. } =
            &mut forged.authentication
        else {
            unreachable!()
        };
        signature[0] ^= 1;
        assert!(store.publish(&forged.encode().unwrap()).is_err());
        assert!(store.load().unwrap().is_none());
        store.publish(&first).unwrap();
        store.publish(&first).unwrap();
        assert!(matches!(
            store.publish(&second),
            Err(CleanFileStoreError::RequestConflict)
        ));
        drop(store);
        let mut wrong = CleanCredentialQueryFile::open_or_create(
            &fixture.root,
            authority,
            vos::agent::sdk::CredentialId([99; 32]),
        )
        .unwrap();
        assert!(wrong.load().is_err());
        drop(wrong);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_query_recovers_initial_stage_without_accepting_replacement() {
        let fixture = Fixture::new("credential-query-stage");
        let (authority, credential, first, second) = credential_queries();
        let store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        let initial = stage(&store.store, None, &first);
        drop(store);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        let canonical = fs::read(fixture.root.join(CREDENTIAL_QUERY_FILE)).unwrap();
        stage(&store.store, Some(initial.commitment()), &second);
        drop(store);
        let mut store =
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, credential).unwrap();
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(fixture.root.join(CREDENTIAL_QUERY_FILE)).unwrap(),
            canonical
        );
        assert!(fixture.root.join(CREDENTIAL_QUERY_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn credential_discovery_reuses_published_query_across_http_retries() {
        use vos::agent::sdk::authority::*;
        use vos::agent::sdk::{Hash, wire::CanonicalWire as _};
        let fixture = Fixture::new("credential-discovery-http");
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let principal = descriptor.identity.owner;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let root = fixture.root.clone();
        let server = std::thread::spawn(move || {
            let mut original = None;
            for _ in 0..2 {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "discovery never connected"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                assert!(header.starts_with("POST /__agents/credential HTTP/1.1\r\n"));
                let len: usize = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                assert!(len <= StoreRole::CredentialQuery.maximum_bytes());
                let mut bytes = vec![0; len];
                stream.read_exact(&mut bytes).unwrap();
                if let Some(original) = &original {
                    assert_eq!(original, &bytes);
                } else {
                    original = Some(bytes.clone());
                }
                let query = AuthorityProjectionQuery::decode(&bytes).unwrap();
                assert!(root.join(CREDENTIAL_QUERY_FILE).exists());
                assert!(matches!(
                    CleanCredentialQueryFile::open_or_create(&root, authority, query.credential),
                    Err(CleanFileStoreError::Busy)
                ));
                let one = std::num::NonZeroU64::new(1).unwrap();
                let reply = AuthorityCredentialProjection {
                    query,
                    head: AuthorityProjectionHead {
                        state_revision: one,
                        epoch: one,
                        authorization_sequence: one,
                        administration_generation: one,
                        state_commitment: Hash([42; 32]),
                    },
                    principal,
                    status: AuthorityCredentialStatus::Active,
                    kind: AuthorityCredentialKind::Api,
                    builtin_role: AuthorityBuiltinRole::Admin,
                    management_request_high_water: 1,
                    operation_request_high_water: 0,
                    admin_request_high_water: 0,
                    space_roles: vec![],
                    actor_roles: vec![],
                    capabilities: vec![],
                }
                .encode()
                .unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
                stream.write_all(&reply).unwrap();
            }
            original.unwrap()
        });
        for _ in 0..2 {
            let (_, sequence) = super::super::local_create::discover_credential(
                &fixture.root,
                address,
                &operator,
                authority,
            )
            .unwrap();
            assert_eq!(sequence.get(), 2);
        }
        let bytes = server.join().unwrap();
        let query = AuthorityProjectionQuery::decode(&bytes).unwrap();
        assert_eq!(
            CleanCredentialQueryFile::open_or_create(&fixture.root, authority, query.credential)
                .unwrap()
                .load()
                .unwrap(),
            Some(bytes)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_is_immutable_durable_and_exclusively_leased() {
        let fixture = Fixture::new("local-request");
        let first = local_request(2);
        let second = local_request(3);
        assert_eq!(
            StoreRole::LocalCreateRequest.maximum_bytes(),
            vos::agent::local_lifecycle::SharedCreateSubmission::MAX_BYTES
        );
        assert_eq!(
            StoreRole::LocalInstallRequest.maximum_bytes(),
            vos::agent::local_lifecycle::LocalInstallSubmission::MAX_BYTES
        );
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert!(store.load().unwrap().is_none());
        assert!(matches!(
            CleanLocalCreateRequestFile::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(store.publish(b"LCQ1").is_err());
        assert!(store.load().unwrap().is_none());
        store.publish(&first).unwrap();
        let envelope = fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap();
        store.publish(&first).unwrap();
        assert!(matches!(
            store.publish(&second),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            envelope
        );
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        assert!(!fixture.root.join(LOCAL_REQUEST_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_recovers_first_publication_but_refuses_staged_replacement() {
        let fixture = Fixture::new("local-request-stage");
        let first = local_request(2);
        let second = local_request(3);
        let store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        let original = stage(&store.0, None, &first);
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert_eq!(store.load().unwrap(), Some(first));
        let envelope = fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap();
        stage(&store.0, Some(original.commitment()), &second);
        drop(store);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert!(store.publish(&second).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            envelope
        );
        assert!(fixture.root.join(LOCAL_REQUEST_STAGE_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_request_preserves_incomplete_or_wrong_role_evidence() {
        let fixture = Fixture::new("local-request-incomplete");
        let first = local_request(2);
        let mut store = CleanLocalCreateRequestFile::open_or_create(&fixture.root).unwrap();
        write_private(&fixture.root.join(LOCAL_REQUEST_STAGE_FILE), b"CSF1");
        assert!(store.load().is_err());
        assert!(store.publish(&first).is_err());
        assert_eq!(
            fs::read(fixture.root.join(LOCAL_REQUEST_STAGE_FILE)).unwrap(),
            b"CSF1"
        );
        assert!(!fixture.root.join(LOCAL_REQUEST_FILE).exists());

        let other = Fixture::new("local-request-wrong-role");
        let mut store = CleanLocalCreateRequestFile::open_or_create(&other.root).unwrap();
        let wrong = encode_envelope(StoreRole::ManagementIntent, None, &first).unwrap();
        write_private(&other.root.join(LOCAL_REQUEST_FILE), &wrong);
        assert!(matches!(
            store.load(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        assert!(store.publish(&first).is_err());
        assert_eq!(
            fs::read(other.root.join(LOCAL_REQUEST_FILE)).unwrap(),
            wrong
        );
    }

    #[test]
    fn lifecycle_discovery_is_sorted_bounded_and_does_not_open_images() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-discovery");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(factory.discover(space, 0).unwrap().is_empty());
        assert!(matches!(
            factory.discover(SpaceId([9; 32]), 4),
            Err(CleanFileStoreError::InvalidPath)
        ));
        let high = AgentId([3; 32]);
        let low = AgentId([2; 32]);
        // Leases remain held: discovery must not open, reconcile, or write
        // either image, even though a later recovery open must acquire them.
        let (mut high_intent, _high_issuer) = factory.open(space, high).unwrap();
        high_intent.commit(b"unverified candidate bytes").unwrap();
        let (_low_intent, _low_issuer) = factory.open(space, low).unwrap();
        let path = fixture.root.join(hex::encode(high.0)).join(INTENT_FILE);
        let before = fs::read(&path).unwrap();
        assert_eq!(factory.discover(space, 2).unwrap(), vec![low, high]);
        assert_eq!(factory.discover(space, 2).unwrap(), vec![low, high]);
        assert!(matches!(
            factory.discover(space, 1),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            factory.discover(space, 0),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn lifecycle_discovers_unpledged_runtime_staging_after_file_reopen() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-runtime-only-candidate");
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        let (mut intent, mut issuer) = factory.open(space, agent).unwrap();
        intent.commit_runtime(b"staged-package").unwrap();
        assert_eq!(intent.load().unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);
        drop((intent, issuer));

        assert_eq!(factory.discover(space, 1).unwrap(), vec![agent]);
        let (mut intent, mut issuer) = factory.open_existing(space, agent).unwrap();
        assert_eq!(intent.load().unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"staged-package".to_vec())
        );
        assert!(matches!(
            factory.open_existing(space, agent),
            Err(CleanFileStoreError::Busy)
        ));
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn external_pending_install_survives_reopen_without_entering_image_format() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("external-pending-install");
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let mut external =
            CleanManagementLifecycleStoreFactory::open_or_create_external(&fixture.root, space)
                .unwrap();
        let (mut intent, issuer) = external.open(space, agent).unwrap();
        intent.commit(b"retired-create").unwrap();
        intent.commit_actor(b"previous-actor").unwrap();
        stage(&intent.4, None, b"exact-pending-install");
        assert_eq!(intent.load().unwrap(), Some(b"retired-create".to_vec()));
        assert_eq!(
            intent.load_actor().unwrap(),
            Some(b"previous-actor".to_vec())
        );
        drop((intent, issuer));
        assert_eq!(external.discover(space, 1).unwrap(), vec![agent]);
        let (mut intent, issuer) = external.open_existing(space, agent).unwrap();
        assert_eq!(
            intent.load_pending_install().unwrap(),
            Some(b"exact-pending-install".to_vec())
        );
        assert!(
            !fixture
                .root
                .join(hex::encode(agent.0))
                .join(LIFECYCLE_PENDING_INSTALL_STAGE_FILE)
                .exists()
        );
        assert_eq!(intent.load().unwrap(), Some(b"retired-create".to_vec()));
        assert_eq!(
            intent.load_actor().unwrap(),
            Some(b"previous-actor".to_vec())
        );
        intent.commit(b"pending-install-intent").unwrap();
        drop((intent, issuer));
        let (mut intent, issuer) = external.open_existing(space, agent).unwrap();
        assert_eq!(
            intent.load().unwrap(),
            Some(b"pending-install-intent".to_vec())
        );
        assert_eq!(
            intent.load_actor().unwrap(),
            Some(b"previous-actor".to_vec())
        );
        assert_eq!(
            intent.load_pending_install().unwrap(),
            Some(b"exact-pending-install".to_vec())
        );
        intent.commit_actor(b"installed-actor").unwrap();
        assert_eq!(
            intent.load_actor().unwrap(),
            Some(b"installed-actor".to_vec())
        );
        drop((intent, issuer, external));
        let mut image =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(matches!(
            image.open_existing(space, agent),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
    }

    #[test]
    fn lifecycle_discovery_rejects_residue_and_non_directories() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::SpaceId;
        for name in ["unrecognized".to_owned(), "AB".repeat(32), "00".repeat(32)] {
            let fixture = Fixture::new("lifecycle-discovery-residue");
            let space = SpaceId([1; 32]);
            let mut factory =
                CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
            fs::create_dir(fixture.root.join(name)).unwrap();
            assert!(matches!(
                factory.discover(space, 4),
                Err(CleanFileStoreError::UnexpectedResidue)
            ));
        }
        let fixture = Fixture::new("lifecycle-discovery-file");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        fs::write(fixture.root.join("ab".repeat(32)), b"not a directory").unwrap();
        assert!(factory.discover(space, 4).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_discovery_rejects_symlinks_and_parent_replacement() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::SpaceId;
        let fixture = Fixture::new("lifecycle-discovery-symlink");
        let space = SpaceId([1; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        let alias = fixture.root.join("ab".repeat(32));
        std::os::unix::fs::symlink(&fixture.parent, &alias).unwrap();
        assert!(factory.discover(space, 4).is_err());
        fs::rename(&fixture.root, fixture.parent.join("retained-parent")).unwrap();
        let _replacement =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(matches!(
            factory.discover(space, 4),
            Err(CleanFileStoreError::Alias)
        ));
        assert!(
            fs::symlink_metadata(fixture.parent.join("retained-parent").join("ab".repeat(32)))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn lifecycle_recovery_open_never_recreates_a_missing_candidate() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-existing-only");
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let mut factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        assert!(factory.open_existing(space, agent).is_err());
        assert!(fs::read_dir(&fixture.root).unwrap().next().is_none());
        let (mut intent, issuer) = factory.open(space, agent).unwrap();
        intent.commit(b"retained intent").unwrap();
        assert!(matches!(
            factory.open_existing(space, agent),
            Err(CleanFileStoreError::Busy)
        ));
        drop((intent, issuer));
        let (mut intent, issuer) = factory.open_existing(space, agent).unwrap();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"retained intent".as_slice())
        );
        drop((intent, issuer));
        assert_eq!(factory.discover(space, 1).unwrap(), vec![agent]);
        let path = fixture.root.join(hex::encode(agent.0));
        let retained = fixture.parent.join("retained-candidate");
        fs::rename(&path, &retained).unwrap();
        assert!(factory.open_existing(space, agent).is_err());
        assert!(!path.exists());
        assert!(retained.join(INTENT_FILE).is_file());
    }

    #[test]
    fn lifecycle_factory_creates_and_reopens_its_private_parent() {
        let fixture = Fixture::new("lifecycle-parent");
        let space = vos::agent::sdk::SpaceId([1; 32]);
        let factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&fixture.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(factory);
        let factory =
            CleanManagementLifecycleStoreFactory::open_or_create(&fixture.root, space).unwrap();
        validate_opened_directory(&factory.directory, &fixture.root, false).unwrap();
    }

    #[test]
    fn lifecycle_factory_derives_agent_paths_and_rejects_wrong_space() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentId, SpaceId};
        let fixture = Fixture::new("lifecycle-factory");
        let mut factory =
            CleanManagementLifecycleStoreFactory::new(&fixture.parent, SpaceId([1; 32])).unwrap();
        let agent = AgentId([2; 32]);
        assert!(matches!(
            factory.open(SpaceId([3; 32]), agent),
            Err(CleanFileStoreError::InvalidPath)
        ));
        assert!(fs::read_dir(&fixture.parent).unwrap().next().is_none());
        let (mut intent, mut issuer) = factory.open(SpaceId([1; 32]), agent).unwrap();
        intent.commit(b"intent").unwrap();
        issuer.commit(b"issuer").unwrap();
        assert!(
            fixture
                .parent
                .join(hex::encode(agent.0))
                .join(INTENT_FILE)
                .is_file()
        );
        assert!(matches!(
            factory.open(SpaceId([1; 32]), agent),
            Err(CleanFileStoreError::Busy)
        ));
        drop((intent, issuer));
        let (mut intent, mut issuer) = factory.open(SpaceId([1; 32]), agent).unwrap();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"intent".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"issuer".as_slice())
        );
    }

    #[test]
    fn operation_files_reopen_exact_histories_under_one_lease() {
        let fixture = Fixture::new("operation-reopen");
        let (mut coordinator, mut issuer) =
            CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
        assert_eq!(coordinator.load().unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);
        // Opaque bytes deliberately test storage, not actor policy or issuance.
        coordinator
            .commit(b"retained authorization intent")
            .unwrap();
        issuer.commit(b"retained signing preimages").unwrap();
        let original = fs::read(fixture.root.join(StoreRole::OperationIssuer.file())).unwrap();
        issuer.commit(b"retained signing preimages").unwrap();
        assert_eq!(
            fs::read(fixture.root.join(StoreRole::OperationIssuer.file())).unwrap(),
            original
        );
        let prior = coordinator
            .0
            .reconcile(MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES)
            .unwrap()
            .unwrap();
        stage(
            &coordinator.0,
            Some(prior.commitment()),
            b"consumed issuance",
        );
        drop(coordinator);
        assert!(matches!(
            CleanAuthorityOperationFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        let (mut coordinator, mut issuer) =
            CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
        assert_eq!(
            coordinator.load().unwrap().as_deref(),
            Some(b"consumed issuance".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"retained signing preimages".as_slice())
        );
        assert!(
            !fixture
                .root
                .join(StoreRole::OperationCoordinator.stage_file())
                .exists()
        );
        let prior = issuer
            .0
            .reconcile(MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES)
            .unwrap()
            .unwrap();
        stage(&issuer.0, Some(prior.commitment()), b"completed signatures");
        drop(issuer);
        assert!(matches!(
            CleanAuthorityOperationFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(coordinator);
        let (mut coordinator, mut issuer) =
            CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
        assert_eq!(
            coordinator.load().unwrap().as_deref(),
            Some(b"consumed issuance".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"completed signatures".as_slice())
        );
        assert!(
            !fixture
                .root
                .join(StoreRole::OperationIssuer.stage_file())
                .exists()
        );
    }

    #[test]
    fn operation_files_enforce_independent_role_bounds_and_namespaces() {
        let fixture = Fixture::new("operation-bounds");
        let (mut coordinator, mut issuer) =
            CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
        let coordinator_image = vec![19; MAX_AUTHORITY_OPERATION_COORDINATOR_IMAGE_BYTES];
        let issuer_image = vec![20; MAX_AUTHORITY_OPERATION_ISSUER_IMAGE_BYTES];
        coordinator.commit(&coordinator_image).unwrap();
        issuer.commit(&issuer_image).unwrap();
        assert!(matches!(
            coordinator.commit(&vec![0; coordinator_image.len() + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            issuer.commit(&vec![0; issuer_image.len() + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(coordinator.load().unwrap(), Some(coordinator_image));
        assert_eq!(issuer.load().unwrap(), Some(issuer_image));
        drop((coordinator, issuer));
        // Neither bootstrap nor management recovery may mistake these for
        // one of its own journals, even though all use CSF1 envelopes.
        assert!(CleanSystemAgentFileStores::open_or_create(&fixture.root).is_err());
        assert!(CleanManagementLifecycleFiles::open_or_create(&fixture.root).is_err());
        let fixture = Fixture::new("operation-wrong-namespace");
        drop(fixture.stores());
        write_private(&fixture.root.join(PINS_FILE), b"bootstrap evidence");
        assert!(CleanAuthorityOperationFiles::open_or_create(&fixture.root).is_err());
        assert_eq!(
            fs::read(fixture.root.join(PINS_FILE)).unwrap(),
            b"bootstrap evidence"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operation_files_are_revalidated_by_the_real_coordinator_and_issuer() {
        use vos::agent::authority_operation_coordinator::{
            AuthorityOperationActorDispatch, AuthorityOperationActorDispatcher,
            AuthorityOperationActorResult, AuthorityOperationCoordinatorError,
            DurableAuthorityOperationCoordinator,
        };
        use vos::agent::authority_operation_issuer::{
            AuthorityOperationIssuerError, DurableAuthorityOperationIssuer,
        };
        struct NoDispatch;
        impl AuthorityOperationActorDispatcher for NoDispatch {
            type Error = core::convert::Infallible;

            fn dispatch(
                &mut self,
                _: &AuthorityOperationActorDispatch,
            ) -> Result<AuthorityOperationActorResult, Self::Error> {
                panic!("opening stored evidence must not dispatch an actor")
            }
        }
        let fixture = Fixture::new("operation-real-open");
        let (_, authority, _, _) = super::super::local_create::tests::fixture();
        let (coordinator, issuer) = CleanAuthorityOperationFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        let issuer = DurableAuthorityOperationIssuer::open(issuer, authority).unwrap();
        let coordinator =
            DurableAuthorityOperationCoordinator::open(coordinator, authority, NoDispatch, issuer)
                .unwrap();
        assert_eq!(coordinator.authority(), authority);
        assert_eq!(coordinator.retained_operations(), 0);
        assert!(!coordinator.has_pending_operation());
        assert!(!coordinator.is_poisoned());
        let (mut coordinator, _, issuer) = coordinator.into_parts();
        // A valid CSF1 envelope is not a valid coordinator image or approval.
        coordinator.commit(b"unsigned operation approval").unwrap();
        assert!(matches!(
            DurableAuthorityOperationCoordinator::open(coordinator, authority, NoDispatch, issuer),
            Err(AuthorityOperationCoordinatorError::InvalidState)
        ));
        let (mut coordinator, mut issuer) =
            CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
        assert_eq!(
            coordinator.load().unwrap().as_deref(),
            Some(b"unsigned operation approval".as_slice())
        );
        issuer.commit(b"unsigned receipt").unwrap();
        assert!(matches!(
            DurableAuthorityOperationIssuer::open(issuer, authority),
            Err(AuthorityOperationIssuerError::InvalidState)
        ));
        // Failed semantic admission must not delete either journal.
        assert!(
            fixture
                .root
                .join(StoreRole::OperationCoordinator.file())
                .is_file()
        );
        assert!(
            fixture
                .root
                .join(StoreRole::OperationIssuer.file())
                .is_file()
        );
    }

    #[test]
    fn operation_files_preserve_ambiguous_stages_in_both_roles() {
        for role in [StoreRole::OperationCoordinator, StoreRole::OperationIssuer] {
            let fixture = Fixture::new("operation-ambiguous-stage");
            let (coordinator, issuer) = CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
            let mut store = if role == StoreRole::OperationCoordinator {
                drop(issuer);
                coordinator.0
            } else {
                drop(coordinator);
                issuer.0
            };
            store.commit(b"exact retained history").unwrap();
            stage(&store, Some([99; 32]), b"unrelated history");
            let canonical = fs::read(fixture.root.join(role.file())).unwrap();
            let staged = fs::read(fixture.root.join(role.stage_file())).unwrap();
            assert!(matches!(
                store.load(role.maximum_bytes()),
                Err(CleanFileStoreError::AmbiguousPublication)
            ));
            assert!(matches!(
                store.commit(b"do not replace"),
                Err(CleanFileStoreError::AmbiguousPublication)
            ));
            drop(store);
            let (mut coordinator, mut issuer) =
                CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                    .unwrap()
                    .into_parts();
            let loaded = if role == StoreRole::OperationCoordinator {
                coordinator.load()
            } else {
                issuer.load()
            };
            assert!(matches!(
                loaded,
                Err(CleanFileStoreError::AmbiguousPublication)
            ));
            assert_eq!(fs::read(fixture.root.join(role.file())).unwrap(), canonical);
            assert_eq!(
                fs::read(fixture.root.join(role.stage_file())).unwrap(),
                staged
            );
        }
    }

    #[test]
    fn operation_files_recover_initial_stages_and_reject_cross_role_images() {
        for role in [StoreRole::OperationCoordinator, StoreRole::OperationIssuer] {
            let fixture = Fixture::new("operation-role-binding");
            let (coordinator, issuer) = CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                .unwrap()
                .into_parts();
            let store = if role == StoreRole::OperationCoordinator {
                drop(issuer);
                coordinator.0
            } else {
                drop(coordinator);
                issuer.0
            };
            stage(&store, None, b"initial pending evidence");
            drop(store);
            let (mut coordinator, mut issuer) =
                CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                    .unwrap()
                    .into_parts();
            let loaded = if role == StoreRole::OperationCoordinator {
                coordinator.load()
            } else {
                issuer.load()
            };
            assert_eq!(
                loaded.unwrap().as_deref(),
                Some(b"initial pending evidence".as_slice())
            );
            drop((coordinator, issuer));
            let other = if role == StoreRole::OperationCoordinator {
                StoreRole::OperationIssuer
            } else {
                StoreRole::OperationCoordinator
            };
            let encoded = fs::read(fixture.root.join(role.file())).unwrap();
            fs::rename(
                fixture.root.join(role.file()),
                fixture.root.join(other.file()),
            )
            .unwrap();
            let (mut coordinator, mut issuer) =
                CleanAuthorityOperationFiles::open_or_create(&fixture.root)
                    .unwrap()
                    .into_parts();
            let loaded = if other == StoreRole::OperationCoordinator {
                coordinator.load()
            } else {
                issuer.load()
            };
            assert!(loaded.is_err());
            assert_eq!(fs::read(fixture.root.join(other.file())).unwrap(), encoded);
        }
    }

    #[test]
    fn shared_management_intent_files_are_separate_and_keep_the_lease() {
        let fixture = Fixture::new("shared-management-intent");
        let (mut original, issuer) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, false)
                .unwrap()
                .into_parts();
        original.commit(b"retired-create").unwrap();
        let mut pending = original.management_intent_continuation().unwrap();
        assert!(pending.management_intent_continuation().is_err());
        stage(&pending.0, None, b"signed-install");
        stage(&pending.2, None, b"actor-package");
        assert_eq!(
            pending.load().unwrap().as_deref(),
            Some(b"signed-install".as_slice())
        );
        assert_eq!(
            pending.load_actor().unwrap().as_deref(),
            Some(b"actor-package".as_slice())
        );
        assert_eq!(
            original.load().unwrap().as_deref(),
            Some(b"retired-create".as_slice())
        );
        assert!(original.load_actor().unwrap().is_none());
        assert!(original.commit(b"replace-create").is_err());
        drop(original);
        drop(issuer);
        assert!(matches!(
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true),
            Err(CleanFileStoreError::Busy)
        ));
        drop(pending);
        let (mut original, _) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true)
                .unwrap()
                .into_parts();
        let mut pending = original.management_intent_continuation().unwrap();
        assert_eq!(
            pending.load().unwrap().as_deref(),
            Some(b"signed-install".as_slice())
        );
        assert_eq!(
            pending.load_actor().unwrap().as_deref(),
            Some(b"actor-package".as_slice())
        );
        // Role-bound envelopes cannot substitute the actor for signed intent.
        std::fs::rename(
            fixture.root.join(StoreRole::SharedManagementActor.file()),
            fixture.root.join(StoreRole::SharedManagementIntent.file()),
        )
        .unwrap();
        assert!(pending.load().is_err());
    }

    #[test]
    fn shared_install_handoff_stage_recovers_under_the_original_lease() {
        let fixture = Fixture::new("shared-install-handoff");
        let (mut original, mut issuer) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, false)
                .unwrap()
                .into_parts();
        assert!(original.load_shared_install_handoff().is_err());
        let mut child = original.management_intent_continuation().unwrap();
        let fault = SharedManagementStageFault::install_handoff(&fixture.root);
        assert!(
            child
                .commit_shared_install_handoff(b"exact staged successor")
                .is_err()
        );
        assert!(fault.fired());
        drop(fault);
        assert!(
            fixture
                .root
                .join(StoreRole::SharedInstallHandoff.stage_file())
                .exists()
        );
        assert_eq!(
            child.load_shared_install_handoff().unwrap().as_deref(),
            Some(b"exact staged successor".as_slice())
        );
        assert!(
            !fixture
                .root
                .join(StoreRole::SharedInstallHandoff.stage_file())
                .exists()
        );
        assert!(
            issuer.issuance_disabled().unwrap(),
            "an orphan handoff cannot unfreeze Create issuance"
        );
        drop(original);
        drop(issuer);
        assert!(matches!(
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true),
            Err(CleanFileStoreError::Busy),
        ));
        drop(child);
        assert!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root).is_err(),
            "Shared handoffs must not enter the Local layout"
        );
        let (mut original, mut issuer) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true)
                .unwrap()
                .into_parts();
        assert!(issuer.issuance_disabled().unwrap());
        assert_eq!(
            original
                .management_intent_continuation()
                .unwrap()
                .load_shared_install_handoff()
                .unwrap()
                .as_deref(),
            Some(b"exact staged successor".as_slice())
        );
    }

    #[test]
    fn shared_management_handoff_files_preserve_source_and_one_writer_lease() {
        let fixture = Fixture::new("shared-management-handoff");
        let (intent, mut source) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, false)
                .unwrap()
                .into_parts();
        source.commit(b"finalized-create").unwrap();
        let mut continuation = source.management_continuation().unwrap();
        continuation.commit(b"finalized-create").unwrap();
        let mut marker = b"SMH1".to_vec();
        marker.extend_from_slice(&[0x91; 32]);
        source.commit_management_handoff(&marker).unwrap();
        assert!(source.issuance_disabled().unwrap());
        assert!(!continuation.issuance_disabled().unwrap());
        assert!(source.commit(b"changed-create").is_err());
        source.commit(b"finalized-create").unwrap();
        let mut different = marker.clone();
        different[4] ^= 1;
        assert!(source.commit_management_handoff(&different).is_err());
        assert!(continuation.management_continuation().is_err());
        continuation.commit(b"next-management-decision").unwrap();
        drop(intent);
        drop(source);
        assert!(matches!(
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true,),
            Err(CleanFileStoreError::Busy)
        ));
        drop(continuation);
        // Shared sidecars do not silently become accepted Local state.
        assert!(CleanManagementLifecycleFiles::open_existing(&fixture.root).is_err());
        let (_intent, mut source) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true)
                .unwrap()
                .into_parts();
        assert_eq!(
            source.load().unwrap().as_deref(),
            Some(b"finalized-create".as_slice())
        );
        assert_eq!(source.load_management_handoff().unwrap(), Some(marker));
        assert!(source.issuance_disabled().unwrap());
        assert_eq!(
            source
                .management_continuation()
                .unwrap()
                .load()
                .unwrap()
                .as_deref(),
            Some(b"next-management-decision".as_slice())
        );
    }

    #[test]
    fn shared_management_handoff_recovers_staging_and_rejects_local_layout() {
        let fixture = Fixture::new("shared-management-handoff-stage");
        let (intent, mut source) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, false)
                .unwrap()
                .into_parts();
        source.commit(b"finalized-create").unwrap();
        let continuation = source.management_continuation().unwrap();
        stage(&continuation.0, None, b"finalized-create");
        let mut marker = b"SMH1".to_vec();
        marker.extend_from_slice(&[0x92; 32]);
        let marker_store = ExactFileStore::new(
            Arc::clone(&source.0.root),
            StoreRole::SharedManagementHandoff,
        );
        stage(&marker_store, None, &marker);
        drop(marker_store);
        drop(continuation);
        drop(source);
        drop(intent);
        let (_intent, mut source) =
            CleanManagementLifecycleFiles::open(&fixture.root, LifecycleLayout::Shared, true)
                .unwrap()
                .into_parts();
        assert!(source.issuance_disabled().unwrap());
        assert_eq!(source.load_management_handoff().unwrap(), Some(marker));
        assert_eq!(
            source
                .management_continuation()
                .unwrap()
                .load()
                .unwrap()
                .as_deref(),
            Some(b"finalized-create".as_slice())
        );
        assert!(
            !fixture
                .root
                .join(StoreRole::SharedManagementHandoff.stage_file())
                .exists()
        );
        assert!(
            !fixture
                .root
                .join(StoreRole::SharedManagementIssuer.stage_file())
                .exists()
        );

        let local = Fixture::new("shared-management-reject-local");
        let (_intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&local.root)
            .unwrap()
            .into_parts();
        assert!(!issuer.issuance_disabled().unwrap());
        assert!(issuer.management_continuation().is_err());
        assert!(issuer.load_management_handoff().is_err());
    }

    #[test]
    fn shared_management_handoff_is_not_silently_ignored_by_startup() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        for phase in 0..4 {
            let fixture = Fixture::new("shared-management-startup-gate");
            let (_, authority, _, _) = super::super::local_create::tests::fixture();
            let mut factory =
                CleanSharedGenesisStoreFactory::open_or_create(&fixture.parent, authority, 4)
                    .unwrap();
            let (mut intent, mut issuer) = factory
                .lifecycle
                .open(authority.space, vos::agent::sdk::AgentId([0x93; 32]))
                .unwrap();
            if phase == 0 {
                let mut marker = b"SMH1".to_vec();
                marker.extend_from_slice(&[0x94; 32]);
                issuer.commit_management_handoff(&marker).unwrap();
            } else if phase == 1 {
                let continuation = issuer.management_continuation().unwrap();
                stage(&continuation.0, None, b"unadmitted-continuation");
            } else {
                let mut continuation = intent.management_intent_continuation().unwrap();
                if phase == 2 {
                    continuation.commit(b"orphan-install").unwrap();
                } else {
                    continuation.commit_actor(b"orphan-actor").unwrap();
                }
            }
            drop(intent);
            drop(issuer);
            drop(factory);
            assert!(matches!(
                discover_shared_genesis_startup(&fixture.parent, authority, 4),
                Err(CleanFileStoreError::UnexpectedResidue)
            ));
        }
    }

    #[test]
    fn lifecycle_files_reopen_independently_and_share_the_writer_lease() {
        let fixture = Fixture::new("lifecycle-reopen");
        let stores = CleanManagementLifecycleFiles::open_or_create(&fixture.root).unwrap();
        let (mut intent, mut issuer) = stores.into_parts();
        assert_eq!(intent.load().unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);
        intent.commit(b"pending-intent").unwrap();
        issuer.commit(b"issued-receipt").unwrap();
        let predecessor = intent
            .0
            .reconcile(MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES)
            .unwrap()
            .unwrap();
        stage(
            &intent.0,
            Some(predecessor.commitment()),
            b"prepared-finalization",
        );
        drop(intent);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(b"prepared-finalization".as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(b"issued-receipt".as_slice())
        );
        assert!(!fixture.root.join(INTENT_STAGE_FILE).exists());
        assert!(matches!(
            intent.commit(&vec![0; MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            issuer.commit(&vec![0; MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
    }

    #[test]
    fn lifecycle_files_reload_staged_images_without_releasing_writer_lease() {
        fn reload<B: CleanManagementIssuerStore>(mut store: B) -> Option<Vec<u8>> {
            store.load().ok().flatten()
        }
        let fixture = Fixture::new("lifecycle-retained-lease");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"intent-before").unwrap();
        issuer.commit(b"issuer-before").unwrap();
        for (store, payload) in [
            (&intent.0, b"intent-after".as_slice()),
            (&issuer.0, b"issuer-after".as_slice()),
        ] {
            let predecessor = store
                .reconcile(store.role.maximum_bytes())
                .unwrap()
                .unwrap();
            stage(store, Some(predecessor.commitment()), payload);
        }
        assert_eq!(
            reload(&mut intent).as_deref(),
            Some(b"intent-after".as_slice())
        );
        assert_eq!(
            reload(&mut issuer).as_deref(),
            Some(b"issuer-after".as_slice())
        );
        assert!(!fixture.root.join(INTENT_STAGE_FILE).exists());
        assert!(!fixture.root.join(LIFECYCLE_ISSUER_STAGE_FILE).exists());
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(intent);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        assert!(CleanManagementLifecycleFiles::open_or_create(&fixture.root).is_ok());
    }

    #[test]
    fn lifecycle_runtime_recovers_staged_publication_and_is_immutable_under_lease() {
        let fixture = Fixture::new("lifecycle-runtime");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"intent").unwrap();
        issuer.commit(b"issuer").unwrap();
        assert_eq!(intent.load_runtime().unwrap(), None);
        stage(&intent.1, None, b"exact-runtime");
        assert_eq!(
            CleanManagementRuntimeStore::load_runtime(&mut &mut intent).unwrap(),
            Some(b"exact-runtime".to_vec())
        );
        assert!(!fixture.root.join(LIFECYCLE_RUNTIME_STAGE_FILE).exists());
        intent.commit_runtime(b"exact-runtime").unwrap();
        assert!(matches!(
            intent.commit_runtime(b"different-runtime"),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(intent.load().unwrap(), Some(b"intent".to_vec()));
        assert_eq!(issuer.load().unwrap(), Some(b"issuer".to_vec()));
        assert!(matches!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(issuer);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(intent);
        let (mut intent, _) = CleanManagementLifecycleFiles::open_existing(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"exact-runtime".to_vec())
        );
        assert_eq!(intent.1.role.maximum_bytes(), MAX_PACKAGE_ENCODED_BYTES);
    }

    #[test]
    fn lifecycle_runtime_rejects_an_issuer_envelope() {
        let fixture = Fixture::new("lifecycle-runtime-role");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        issuer.commit(b"issuer").unwrap();
        let bytes = fs::read(fixture.root.join(LIFECYCLE_ISSUER_FILE)).unwrap();
        write_private(&fixture.root.join(LIFECYCLE_RUNTIME_FILE), &bytes);
        assert!(matches!(
            intent.load_runtime(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        assert_eq!(issuer.load().unwrap(), Some(b"issuer".to_vec()));
    }

    #[test]
    fn lifecycle_external_create_archive_survives_intent_handoff() {
        let fixture = Fixture::new("lifecycle-external-create-archive");
        let (mut intent, issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"retired-create").unwrap();
        intent.commit_runtime(b"create-runtime").unwrap();
        stage(&intent.3, None, b"exact-create-archive");
        assert_eq!(
            intent.load_external_create_archive().unwrap(),
            Some(b"exact-create-archive".to_vec())
        );
        assert!(
            !fixture
                .root
                .join(LIFECYCLE_EXTERNAL_CREATE_ARCHIVE_STAGE_FILE)
                .exists()
        );
        intent.commit(b"later-install").unwrap();
        intent
            .commit_external_create_archive(b"exact-create-archive")
            .unwrap();
        assert!(matches!(
            intent.commit_external_create_archive(b"different-create"),
            Err(CleanFileStoreError::RequestConflict)
        ));
        drop(issuer);
        drop(intent);
        let (mut intent, _) = CleanManagementLifecycleFiles::open_existing(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(intent.load().unwrap(), Some(b"later-install".to_vec()));
        assert_eq!(
            intent.load_external_create_archive().unwrap(),
            Some(b"exact-create-archive".to_vec())
        );
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"create-runtime".to_vec())
        );
    }

    #[test]
    fn lifecycle_actor_recovers_bounded_replacement_without_changing_create_runtime() {
        let fixture = Fixture::new("lifecycle-actor");
        let (mut intent, issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        intent.commit(b"signed-intent").unwrap();
        intent.commit_runtime(b"immutable-create-runtime").unwrap();
        assert_eq!(intent.load_actor().unwrap(), None);
        stage(&intent.2, None, b"first-actor");
        assert_eq!(
            CleanManagementActorStore::load_actor(&mut &mut intent).unwrap(),
            Some(b"first-actor".to_vec())
        );
        let previous = intent
            .2
            .reconcile(MAX_PACKAGE_ENCODED_BYTES)
            .unwrap()
            .unwrap();
        stage(&intent.2, Some(previous.commitment()), b"next-actor");
        assert_eq!(intent.load_actor().unwrap(), Some(b"next-actor".to_vec()));
        assert!(!fixture.root.join(LIFECYCLE_ACTOR_STAGE_FILE).exists());
        CleanManagementActorStore::commit_actor(&mut &mut intent, b"next-actor").unwrap();
        assert_eq!(intent.load().unwrap(), Some(b"signed-intent".to_vec()));
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"immutable-create-runtime".to_vec())
        );
        assert_eq!(intent.2.role.maximum_bytes(), MAX_PACKAGE_ENCODED_BYTES);
        drop(issuer);
        assert!(matches!(
            CleanManagementLifecycleFiles::open_existing(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(intent);
        let (mut intent, _) = CleanManagementLifecycleFiles::open_existing(&fixture.root)
            .unwrap()
            .into_parts();
        assert_eq!(intent.load_actor().unwrap(), Some(b"next-actor".to_vec()));
        assert_eq!(
            intent.load_runtime().unwrap(),
            Some(b"immutable-create-runtime".to_vec())
        );
    }

    #[test]
    fn lifecycle_actor_rejects_cross_role_and_divergent_staged_images() {
        let fixture = Fixture::new("lifecycle-actor-role");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        issuer.commit(b"issuer").unwrap();
        let wrong = fs::read(fixture.root.join(LIFECYCLE_ISSUER_FILE)).unwrap();
        write_private(&fixture.root.join(LIFECYCLE_ACTOR_FILE), &wrong);
        assert!(matches!(
            intent.load_actor(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        fs::remove_file(fixture.root.join(LIFECYCLE_ACTOR_FILE)).unwrap();
        intent.commit_actor(b"actor").unwrap();
        stage(&intent.2, Some([0x91; 32]), b"substituted");
        assert!(intent.load_actor().is_err());
        assert!(fixture.root.join(LIFECYCLE_ACTOR_STAGE_FILE).exists());
        assert_eq!(issuer.load().unwrap(), Some(b"issuer".to_vec()));
    }

    #[test]
    fn lifecycle_files_reject_bootstrap_names_and_cross_role_envelopes() {
        let fixture = Fixture::new("lifecycle-role");
        let (mut intent, mut issuer) = CleanManagementLifecycleFiles::open_or_create(&fixture.root)
            .unwrap()
            .into_parts();
        issuer.commit(b"issuer").unwrap();
        let bytes = fs::read(fixture.root.join(LIFECYCLE_ISSUER_FILE)).unwrap();
        write_private(&fixture.root.join(INTENT_FILE), &bytes);
        assert!(matches!(
            intent.load(),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        drop(intent);
        drop(issuer);
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));

        let fixture = Fixture::new("lifecycle-bootstrap-refusal");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        drop((pins, bootstrap, issuer));
        assert!(matches!(
            CleanManagementLifecycleFiles::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
    }

    #[test]
    fn exact_reads_distinguish_truncation_from_io_failure() {
        let mut truncated = &b"short"[..];
        let mut target = [0_u8; 6];
        assert!(matches!(
            read_exact_or_corrupt(&mut truncated, &mut target),
            Err(CleanFileStoreError::Corrupt)
        ));

        struct FailedReader;

        impl Read for FailedReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected read failure",
                ))
            }
        }

        let error = read_exact_or_corrupt(&mut FailedReader, &mut target)
            .expect_err("non-truncation read failures remain I/O errors");
        assert!(matches!(
            error,
            CleanFileStoreError::Io(error)
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn missing_parent_canonicalization_preserves_io_failure() {
        let fixture = Fixture::new("missing-parent");
        let root = fixture.parent.join("absent").join("state");
        match CleanSystemAgentFileStores::open_or_create(root) {
            Err(CleanFileStoreError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            Err(error) => panic!("missing parent was misclassified: {error}"),
            Ok(_) => panic!("missing parent unexpectedly opened"),
        }
    }

    fn flip_first_predecessor_byte(path: &Path) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("open envelope for predecessor tamper");
        file.seek(SeekFrom::Start(16)).expect("seek to predecessor");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read predecessor byte");
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(16))
            .expect("rewind to predecessor");
        file.write_all(&byte).expect("tamper predecessor byte");
        file.sync_all().expect("sync predecessor tamper");
    }

    #[test]
    #[ignore = "requires exported AUTHORITY_PUBLICATION_FIXTURE with runtime-catalog"]
    fn ordinary_genesis_provider_persists_signed_fixture_and_recovers_stage() {
        use vos::agent::execution::RuntimeBlob;
        use vos::agent::genesis::{
            AgentGenesisArchiveRecord, AgentGenesisProvider, AgentGenesisProviderError,
            AgentGenesisProvision,
        };
        use vos::agent::genesis_archive::ArchivedAgentGenesisProvider;
        use vos::service::ServiceWire as _;
        let source = PathBuf::from(std::env::var("AUTHORITY_PUBLICATION_FIXTURE").unwrap());
        let provision_bytes = fs::read(source.join("provision")).unwrap();
        let provision = AgentGenesisProvision::decode(&provision_bytes).unwrap();
        let runtime = fs::read(source.join("runtime-catalog")).unwrap();
        let catalog = vec![RuntimeBlob {
            reference: vos::service::BlobRef::of_bytes(&runtime),
            bytes: runtime,
        }];
        let record = AgentGenesisArchiveRecord::new(provision.clone(), catalog.clone()).unwrap();
        let locator = provision.proposal().locator();
        for staged in [false, true] {
            let fixture = Fixture::new("ordinary-genesis-provider-integration");
            let archive_parent = fixture.parent.join("archives");
            ensure_private_directory(&archive_parent).unwrap();
            let factory =
                CleanAgentGenesisArchiveStoreFactory::open_existing(&archive_parent, locator.space)
                    .unwrap();
            let store =
                CleanAgentGenesisArchiveFile::open_or_create(&archive_parent, locator).unwrap();
            if staged {
                stage(&store.store.lock().unwrap(), None, &record.encode());
                drop(store);
            } else {
                let provider = ArchivedAgentGenesisProvider::new(locator.space, store).unwrap();
                assert_eq!(
                    provider.reproduce(locator),
                    Err(AgentGenesisProviderError::NotConfigured)
                );
                provider.publish(&record).unwrap();
                drop(provider);
            }
            assert_eq!(factory.discover(1).unwrap(), vec![locator]);
            let store = factory.open_archive(locator).unwrap();
            let provider = ArchivedAgentGenesisProvider::new(locator.space, store).unwrap();
            assert_eq!(
                provider.reproduce(locator).unwrap().encode(),
                provision_bytes
            );
            provider.publish(&record).unwrap();
            assert_eq!(
                provider.create(provision.proposal(), &catalog).unwrap(),
                provision
            );
            assert_eq!(
                provider
                    .load_catalog(locator, &catalog[0].reference)
                    .unwrap(),
                Some(catalog[0].bytes.clone())
            );
            let mut corrupt_catalog = catalog.clone();
            corrupt_catalog[0].bytes.push(0);
            assert_eq!(
                provider.create(provision.proposal(), &corrupt_catalog),
                Err(AgentGenesisProviderError::Refused)
            );
            assert_eq!(provider.reproduce(locator).unwrap(), provision);
            assert!(matches!(
                factory.open_archive(locator),
                Err(CleanFileStoreError::Busy)
            ));
            drop(provider);
            let store = factory.open_archive(locator).unwrap();
            let provider = ArchivedAgentGenesisProvider::new(locator.space, store).unwrap();
            assert_eq!(
                provider.reproduce(locator).unwrap().encode(),
                provision_bytes
            );
        }
    }

    #[test]
    fn ordinary_genesis_signature_is_leased_bounded_and_reopens() {
        use vos::agent::committee::AuthoritySignerId;
        use vos::agent::genesis::AgentGenesisLocator;
        let fixture = Fixture::new("ordinary-genesis-signature");
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let signer = AuthoritySignerId::of_raw_ed25519(&[3; 32]);
        let mut file =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
                .unwrap();
        assert!(matches!(
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer),
            Err(CleanFileStoreError::Busy)
        ));
        let other = AuthoritySignerId::of_raw_ed25519(&[4; 32]);
        let mut independent =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, other)
                .unwrap();
        assert_eq!(independent.load().unwrap(), None);
        let pledge = vec![0x11; 100];
        let signed = vec![0x22; 164];
        file.commit(&pledge).unwrap();
        file.commit(&signed).unwrap();
        assert!(matches!(
            file.commit(&vec![0; 165]),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(file.load().unwrap(), Some(signed.clone()));
        drop(file);
        let mut file =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
                .unwrap();
        assert_eq!(file.load().unwrap(), Some(signed));
        assert_eq!(independent.load().unwrap(), None);
    }

    #[test]
    fn ordinary_genesis_committee_pair_is_immutable_bounded_and_jointly_leased() {
        let fixture = Fixture::new("ordinary-genesis-committee-pair");
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let (mut query, mut reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
        let mut publication = query.publication();
        let mut publication_reply = query.publication_reply();
        for file in [
            &mut query,
            &mut reply,
            &mut publication,
            &mut publication_reply,
        ] {
            assert_eq!(file.load().unwrap(), None);
            file.commit(&[1, 2, 3]).unwrap();
            file.commit(&[1, 2, 3]).unwrap();
            assert!(matches!(
                file.commit(&[4]),
                Err(CleanFileStoreError::RequestConflict)
            ));
            assert!(matches!(
                file.commit(&vec![0; file.0.role.maximum_bytes() + 1]),
                Err(CleanFileStoreError::Oversized)
            ));
            assert_eq!(file.load().unwrap(), Some(vec![1, 2, 3]));
        }
        drop(query);
        assert!(matches!(
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(reply);
        assert!(matches!(
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(publication);
        assert!(matches!(
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(publication_reply);
        let (mut query, mut reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
        assert_eq!(query.load().unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(reply.load().unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(query.publication().load().unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(
            query.publication_reply().load().unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn ordinary_genesis_publication_recovers_stage_and_refuses_replacement() {
        for is_reply in [false, true] {
            let fixture = Fixture::new("ordinary-genesis-publication-stage");
            let locator = vos::agent::genesis::AgentGenesisLocator {
                space: vos::service::SpaceId([1; 32]),
                agent: vos::service::AgentId([2; 32]),
            };
            let pair = CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let publication = if is_reply {
                pair.0.publication_reply()
            } else {
                pair.0.publication()
            };
            stage(&publication.0, None, &[1, 2, 3]);
            drop(publication);
            drop(pair);
            let pair = CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let mut publication = if is_reply {
                pair.0.publication_reply()
            } else {
                pair.0.publication()
            };
            assert_eq!(publication.load().unwrap(), Some(vec![1, 2, 3]));
            let current = publication
                .0
                .reconcile(publication.0.role.maximum_bytes())
                .unwrap()
                .unwrap();
            stage(&publication.0, Some(current.commitment()), &[4]);
            drop(publication);
            drop(pair);
            let pair = CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let mut publication = if is_reply {
                pair.0.publication_reply()
            } else {
                pair.0.publication()
            };
            assert!(publication.load().is_err());
        }
    }

    #[test]
    fn ordinary_genesis_fresh_reservation_preserves_every_orphan_phase() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentProfile, ManagementRequest};
        let (operator, authority, mut descriptor, runtime) =
            super::super::local_create::tests::fixture();
        let (_, mut call, _) = super::super::local_create::prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            core::num::NonZeroU64::new(1).unwrap(),
            10,
            30,
        )
        .unwrap()
        .into_parts();
        descriptor.identity.profile = AgentProfile::Shared;
        call.managed.profile = AgentProfile::Shared;
        call.plan = ManagementRequest::Create(Box::new(descriptor.clone()))
            .authorization_plan()
            .unwrap();
        call.invocation = call.expected_invocation();
        call.signature = operator
            .sign(&call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId(authority.space.0),
            agent: vos::service::AgentId(descriptor.identity.agent.0),
        };
        for orphan in 0..6 {
            let fixture = Fixture::new("ordinary-genesis-orphan-phase");
            let mut lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
                fixture.parent.join("lifecycle"),
                authority.space,
            )
            .unwrap();
            let (mut intent, mut issuer) = lifecycle
                .open(authority.space, descriptor.identity.agent)
                .unwrap();
            let committee_path = fixture.parent.join("committee");
            ensure_private_directory(&committee_path).unwrap();
            let (mut query, mut reply) =
                CleanAgentGenesisCommitteeFile::open_pair(&committee_path, locator).unwrap();
            let mut publication = query.publication();
            let mut publication_reply = query.publication_reply();
            match orphan {
                0 => intent.commit_runtime(runtime.exact_bytes()).unwrap(),
                1 => issuer.commit(b"orphan issuer").unwrap(),
                2 => query.commit(b"orphan query").unwrap(),
                3 => reply.commit(b"orphan reply").unwrap(),
                4 => publication.commit(b"orphan publication").unwrap(),
                5 => publication_reply
                    .commit(b"orphan publication reply")
                    .unwrap(),
                _ => unreachable!(),
            }
            let before = [
                intent.load().unwrap(),
                intent.load_runtime().unwrap(),
                issuer.load().unwrap(),
                query.load().unwrap(),
                reply.load().unwrap(),
                publication.load().unwrap(),
                publication_reply.load().unwrap(),
            ];
            assert!(
                matches!(
                    vos::agent::clean_bootstrap::NativeSharedGenesisRecovery::reserve_create(
                        authority,
                        locator,
                        descriptor.clone(),
                        call.clone(),
                        runtime.clone(),
                        (
                            &mut intent,
                            &mut issuer,
                            &mut query,
                            &mut reply,
                            &mut publication,
                            &mut publication_reply
                        ),
                    ),
                    Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
                ),
                "orphan phase {orphan}"
            );
            let after = [
                intent.load().unwrap(),
                intent.load_runtime().unwrap(),
                issuer.load().unwrap(),
                query.load().unwrap(),
                reply.load().unwrap(),
                publication.load().unwrap(),
                publication_reply.load().unwrap(),
            ];
            assert_eq!(
                after, before,
                "orphan phase {orphan} must not be repaired or replaced"
            );
        }
    }

    #[test]
    fn ordinary_genesis_startup_discovery_tolerates_only_empty_partial_namespaces() {
        let fixture = Fixture::new("shared-startup-discovery");
        let (_, authority, _, _) = super::super::local_create::tests::fixture();
        let paths = [
            SHARED_LIFECYCLE_DIRECTORY,
            SHARED_COMMITTEE_DIRECTORY,
            SHARED_ARCHIVE_DIRECTORY,
        ];
        assert!(
            discover_shared_genesis_startup(&fixture.parent, authority, 1)
                .unwrap()
                .is_none()
        );
        for name in paths {
            assert!(!fixture.parent.join(name).exists());
        }
        for (index, name) in paths.iter().enumerate() {
            ensure_private_directory(&fixture.parent.join(name)).unwrap();
            if index < 2 {
                assert!(
                    discover_shared_genesis_startup(&fixture.parent, authority, 1)
                        .unwrap()
                        .is_none()
                );
                for missing in &paths[index + 1..] {
                    assert!(!fixture.parent.join(missing).exists());
                }
            }
        }
        let controller = discover_shared_genesis_startup(&fixture.parent, authority, 1)
            .unwrap()
            .unwrap();
        assert_eq!(controller.authority(), authority);
        assert!(!controller.is_recovered());
        for name in paths {
            assert_eq!(fs::read_dir(fixture.parent.join(name)).unwrap().count(), 0);
        }

        let incomplete = Fixture::new("shared-startup-partial-reservation");
        let lifecycle = incomplete.parent.join(SHARED_LIFECYCLE_DIRECTORY);
        ensure_private_directory(&lifecycle).unwrap();
        write_private(&lifecycle.join("unexpected"), b"retained reservation");
        assert!(matches!(
            discover_shared_genesis_startup(&incomplete.parent, authority, 1),
            Err(CleanFileStoreError::Corrupt)
        ));
        assert!(matches!(
            CleanSharedGenesisStoreFactory::open_or_create(&incomplete.parent, authority, 1),
            Err(CleanFileStoreError::Corrupt)
        ));
        assert!(!incomplete.parent.join(SHARED_COMMITTEE_DIRECTORY).exists());
        assert!(!incomplete.parent.join(SHARED_ARCHIVE_DIRECTORY).exists());
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_genesis_startup_discovery_refuses_symlink_namespace() {
        let fixture = Fixture::new("shared-startup-symlink");
        let (_, authority, _, _) = super::super::local_create::tests::fixture();
        let target = fixture.parent.join("actual");
        ensure_private_directory(&target).unwrap();
        std::os::unix::fs::symlink(&target, fixture.parent.join(SHARED_LIFECYCLE_DIRECTORY))
            .unwrap();
        assert!(matches!(
            discover_shared_genesis_startup(&fixture.parent, authority, 1),
            Err(CleanFileStoreError::InvalidPath)
        ));
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
        assert!(!fixture.parent.join(SHARED_COMMITTEE_DIRECTORY).exists());
        assert!(!fixture.parent.join(SHARED_ARCHIVE_DIRECTORY).exists());
    }

    #[test]
    fn ordinary_genesis_replicas_are_immutable_under_committee_lease() {
        let fixture = Fixture::new("ordinary-genesis-replicas");
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let (mut query, reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
        assert_eq!(query.load_replicas().unwrap(), None);
        assert!(matches!(
            query.commit_replicas(&vec![
                0;
                StoreRole::OrdinaryGenesisReplicas.maximum_bytes() + 1
            ]),
            Err(CleanFileStoreError::Oversized)
        ));
        query.commit_replicas(b"selected roster").unwrap();
        query.commit_replicas(b"selected roster").unwrap();
        assert!(matches!(
            query.commit_replicas(b"replacement roster"),
            Err(CleanFileStoreError::RequestConflict)
        ));
        assert_eq!(
            query.load_replicas().unwrap(),
            Some(b"selected roster".to_vec())
        );
        drop((query, reply));

        let (mut reopened, _reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
        assert_eq!(
            reopened.load_replicas().unwrap(),
            Some(b"selected roster".to_vec())
        );
        assert!(matches!(
            CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator),
            Err(CleanFileStoreError::Busy)
        ));
        let roster = ExactFileStore::new(
            Arc::clone(&reopened.0.root),
            StoreRole::OrdinaryGenesisReplicas,
        );
        let current = roster
            .reconcile(StoreRole::OrdinaryGenesisReplicas.maximum_bytes())
            .unwrap()
            .unwrap();
        stage(&roster, Some(current.commitment()), b"replacement roster");
        assert!(matches!(
            reopened.load_replicas(),
            Err(CleanFileStoreError::RequestConflict)
        ));
    }

    #[test]
    fn ordinary_genesis_signed_reservation_retries_and_joint_discovery_holds_leases() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::agent::sdk::{AgentProfile, ManagementRequest};
        use vos::service::ServiceWire as _;
        struct FailRuntimeCommit(CleanManagementIntentFile, bool);
        impl CleanManagementIssuerStore for FailRuntimeCommit {
            type Error = CleanFileStoreError;
            fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                self.0.load()
            }
            fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
                self.0.commit(image)
            }
        }
        impl CleanManagementRuntimeStore for FailRuntimeCommit {
            fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
                self.0.load_runtime()
            }
            fn commit_runtime(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
                if self.1 {
                    self.0.commit_runtime(bytes)?;
                }
                Err(CleanFileStoreError::Corrupt)
            }
        }
        let fixture = Fixture::new("ordinary-genesis-signed-reservation");
        let (operator, authority, mut descriptor, runtime) =
            super::super::local_create::tests::fixture();
        let submission = super::super::local_create::prepare(
            &operator,
            authority,
            descriptor.clone(),
            runtime.clone(),
            core::num::NonZeroU64::new(1).unwrap(),
            10,
            30,
        )
        .unwrap();
        let (_, mut call, _) = submission.into_parts();
        descriptor.identity.profile = AgentProfile::Shared;
        let node_key = libp2p::identity::Keypair::ed25519_from_bytes([0x46; 32]).unwrap();
        let peer = node_key.public().to_peer_id().to_bytes();
        let node_public = ed25519_dalek::SigningKey::from_bytes(&[0x46; 32])
            .verifying_key()
            .to_bytes();
        descriptor.replicas[0].node =
            vos::agent::sdk::NodeId(vos::service::NodeId::of_authenticated_peer(&peer).0);
        call.managed.profile = AgentProfile::Shared;
        call.plan = ManagementRequest::Create(Box::new(descriptor.clone()))
            .authorization_plan()
            .unwrap();
        call.invocation = call.expected_invocation();
        call.signature = operator
            .sign(&call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId(authority.space.0),
            agent: vos::service::AgentId(descriptor.identity.agent.0),
        };
        let selected_replicas = vos::agent::genesis::AgentReplicaCommittee::new(
            locator.space,
            locator.agent,
            vos::agent::AgentProfile::Shared,
            vec![
                vos::agent::genesis::AgentReplicaMember::new(
                    vos::agent::AgentReplica {
                        node: vos::service::NodeId(descriptor.replicas[0].node.0),
                        principal: vos::service::PrincipalId(descriptor.replicas[0].principal.0),
                        role: vos::agent::ReplicaRole::Voter,
                    },
                    peer.clone(),
                    node_public,
                    Some(vos::agent::genesis::derive_replica_raft_slot(&peer)),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        selected_replicas
            .validate_for_clean_descriptor(&descriptor)
            .unwrap();
        let lazy_space = fixture.parent.join("lazy-shared-space");
        ensure_private_directory(&lazy_space).unwrap();
        let mut lazy = CleanSharedGenesisAdmissionFiles::open(&lazy_space, authority, 1).unwrap();
        assert_eq!(fs::read_dir(&lazy_space).unwrap().count(), 0);
        let reserved = lazy
            .reserve(&descriptor, &call, &runtime, &selected_replicas)
            .unwrap();
        assert!(matches!(
            discover_shared_genesis_startup(&lazy_space, authority, 1),
            Err(CleanFileStoreError::Busy)
        ));
        drop(reserved);
        drop(
            discover_shared_genesis_startup(&lazy_space, authority, 1)
                .unwrap()
                .unwrap(),
        );
        let displaced_space = fixture.parent.join("lazy-displaced-space");
        fs::rename(&lazy_space, &displaced_space).unwrap();
        ensure_private_directory(&lazy_space).unwrap();
        assert!(matches!(
            lazy.reserve(&descriptor, &call, &runtime, &selected_replicas),
            Err(vos::agent::shared_host::SharedAgentHostError::Unavailable)
        ));
        assert_eq!(fs::read_dir(&lazy_space).unwrap().count(), 0);
        let never_used = fixture.parent.join("lazy-never-used");
        ensure_private_directory(&never_used).unwrap();
        let mut lazy = CleanSharedGenesisAdmissionFiles::open(&never_used, authority, 1).unwrap();
        fs::rename(
            &never_used,
            fixture.parent.join("lazy-never-used-displaced"),
        )
        .unwrap();
        ensure_private_directory(&never_used).unwrap();
        assert!(matches!(
            lazy.reserve(&descriptor, &call, &runtime, &selected_replicas),
            Err(vos::agent::shared_host::SharedAgentHostError::Unavailable)
        ));
        assert_eq!(fs::read_dir(&never_used).unwrap().count(), 0);
        let staged = Fixture::new("ordinary-genesis-staged-create");
        let staged_archives_path = staged.parent.join(SHARED_ARCHIVE_DIRECTORY);
        ensure_private_directory(&staged_archives_path).unwrap();
        let staged_archives = CleanAgentGenesisArchiveStoreFactory::open_existing(
            &staged_archives_path,
            locator.space,
        )
        .unwrap();
        let staged_committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &staged.parent.join(SHARED_COMMITTEE_DIRECTORY),
            locator.space,
        )
        .unwrap();
        let mut staged_lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            staged.parent.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
        )
        .unwrap();
        let (mut staged_intent, staged_issuer) = staged_lifecycle
            .open(authority.space, descriptor.identity.agent)
            .unwrap();
        staged_intent.commit_runtime(runtime.exact_bytes()).unwrap();
        let (mut staged_query, staged_reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&staged_committee.parent, locator).unwrap();
        staged_query
            .commit_replicas(&selected_replicas.encode())
            .unwrap();
        drop((staged_intent, staged_issuer, staged_query, staged_reply));
        assert!(
            staged_archives
                .discover_recovery(&mut staged_lifecycle, &staged_committee, authority, 1)
                .unwrap()
                .is_empty()
        );
        let (staged_intent, staged_issuer) = staged_lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        let (staged_query, staged_reply) = staged_committee.open_existing(locator).unwrap();
        let staged_publication = staged_query.publication();
        let staged_publication_reply = staged_query.publication_reply();
        let recovery = CleanSharedGenesisRecovery::reserve_create_with_replicas(
            authority,
            locator,
            descriptor.clone(),
            call.clone(),
            runtime.clone(),
            selected_replicas.clone(),
            (
                staged_intent,
                staged_issuer,
                staged_query,
                staged_reply,
                staged_publication,
                staged_publication_reply,
            ),
        )
        .unwrap();
        assert_eq!(
            recovery.runtime().unwrap().exact_bytes(),
            runtime.exact_bytes()
        );
        drop(recovery);
        let entries = staged_archives
            .discover_recovery(&mut staged_lifecycle, &staged_committee, authority, 1)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].archive.is_none());
        drop(entries);
        // Use the exact daemon startup discovery path, not only the archive
        // factory helper. A signed pre-archive Create must retain both leases
        // without minting an archive or becoming a completed generation.
        let controller = discover_shared_genesis_startup(&staged.parent, authority, 1)
            .unwrap()
            .unwrap();
        assert!(!controller.is_recovered());
        assert!(matches!(
            staged_lifecycle.open_existing(authority.space, descriptor.identity.agent),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            staged_committee.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(staged_archives.discover(1).unwrap().is_empty());
        drop(controller);
        let (staged_intent, staged_issuer) = staged_lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        let (staged_query, staged_reply) = staged_committee.open_existing(locator).unwrap();
        let staged_publication = staged_query.publication();
        let staged_publication_reply = staged_query.publication_reply();
        let mut retried = CleanSharedGenesisRecovery::reserve_create_with_replicas(
            authority,
            locator,
            descriptor.clone(),
            call.clone(),
            runtime.clone(),
            selected_replicas.clone(),
            (
                staged_intent,
                staged_issuer,
                staged_query,
                staged_reply,
                staged_publication,
                staged_publication_reply,
            ),
        )
        .unwrap();
        assert_eq!(
            retried.retained_replicas().unwrap(),
            Some(selected_replicas.clone())
        );
        drop(retried);
        let fresh = Fixture::new("ordinary-genesis-fresh-create");
        ensure_private_directory(&fresh.parent.join(SHARED_ARCHIVE_DIRECTORY)).unwrap();
        let fresh_committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &fresh.parent.join(SHARED_COMMITTEE_DIRECTORY),
            locator.space,
        )
        .unwrap();
        let mut fresh_lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            fresh.parent.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
        )
        .unwrap();
        let (fresh_intent, fresh_issuer) = fresh_lifecycle
            .open(authority.space, descriptor.identity.agent)
            .unwrap();
        let (fresh_query, fresh_reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&fresh_committee.parent, locator).unwrap();
        let fresh_publication = fresh_query.publication();
        let fresh_publication_reply = fresh_query.publication_reply();
        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        assert!(matches!(
            CleanSharedGenesisRecovery::reserve_create_with_replicas(
                authority,
                locator,
                descriptor.clone(),
                forged,
                runtime.clone(),
                selected_replicas.clone(),
                (
                    fresh_intent,
                    fresh_issuer,
                    fresh_query,
                    fresh_reply,
                    fresh_publication,
                    fresh_publication_reply,
                ),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
        ));
        let (mut fresh_intent, fresh_issuer) = fresh_lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        let (mut fresh_query, fresh_reply) = fresh_committee.open_existing(locator).unwrap();
        assert!(fresh_intent.load().unwrap().is_none());
        assert!(fresh_intent.load_runtime().unwrap().is_none());
        assert!(fresh_query.load_replicas().unwrap().is_none());
        drop((fresh_intent, fresh_issuer, fresh_query, fresh_reply));
        let mut files =
            CleanSharedGenesisStoreFactory::open_or_create(&fresh.parent, authority, 1).unwrap();
        let mut fresh_recovery = files
            .reserve_create(
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                selected_replicas.clone(),
            )
            .unwrap();
        assert_eq!(
            fresh_recovery.recovery.retained_replicas().unwrap(),
            Some(selected_replicas.clone())
        );
        assert!(fresh_recovery.archive.as_ref().unwrap().1.is_none());
        assert!(matches!(
            files.archives.open_archive(locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(fresh_recovery);
        drop(files);
        let controller = discover_shared_genesis_startup(&fresh.parent, authority, 1)
            .unwrap()
            .unwrap();
        assert!(!controller.is_recovered());
        drop(controller);
        let mut files =
            CleanSharedGenesisStoreFactory::open_or_create(&fresh.parent, authority, 1).unwrap();
        let retry = files
            .reserve_create(
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                selected_replicas.clone(),
            )
            .unwrap();
        drop(retry);
        let mut other = descriptor.clone();
        other.creation_nonce = vos::agent::sdk::Hash([0xfa; 32]);
        other.identity.agent = vos::agent::sdk::AgentId::derive(
            other.identity.space,
            other.identity.owner,
            other.creation_nonce.as_bytes(),
        );
        let mut other_call = call.clone();
        other_call.managed.agent = other.identity.agent;
        other_call.plan = ManagementRequest::Create(Box::new(other.clone()))
            .authorization_plan()
            .unwrap();
        other_call.invocation = other_call.expected_invocation();
        other_call.signature = operator
            .sign(&other_call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let other_replicas = vos::agent::genesis::AgentReplicaCommittee::new(
            locator.space,
            vos::service::AgentId(other.identity.agent.0),
            vos::agent::AgentProfile::Shared,
            selected_replicas.members().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            files.reserve_create(
                other.clone(),
                other_call.clone(),
                runtime.clone(),
                other_replicas.clone()
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::CapacityExhausted)
        ));
        assert_eq!(
            files.lifecycle.discover(authority.space, 1).unwrap(),
            vec![descriptor.identity.agent]
        );

        // Lock-only staging consumes the same bound before and after startup.
        let bounded = Fixture::new("ordinary-genesis-staged-capacity");
        let mut files =
            CleanSharedGenesisStoreFactory::open_or_create(&bounded.parent, authority, 1).unwrap();
        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        assert!(matches!(
            files.reserve_create(
                descriptor.clone(),
                forged,
                runtime.clone(),
                selected_replicas.clone()
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
        ));
        assert!(
            files
                .lifecycle
                .discover(authority.space, 1)
                .unwrap()
                .is_empty()
        );
        drop(
            files
                .lifecycle
                .open(authority.space, descriptor.identity.agent)
                .unwrap(),
        );
        drop(files);
        let controller = discover_shared_genesis_startup(&bounded.parent, authority, 1)
            .unwrap()
            .unwrap();
        drop(controller);
        let mut files =
            CleanSharedGenesisStoreFactory::open_or_create(&bounded.parent, authority, 1).unwrap();
        assert!(matches!(
            files.reserve_create(other, other_call, runtime.clone(), other_replicas),
            Err(vos::agent::shared_host::SharedAgentHostError::CapacityExhausted)
        ));
        assert!(files.committee.discover(1).unwrap().is_empty());
        assert!(files.archives.discover(1).unwrap().is_empty());
        drop(
            files
                .reserve_create(
                    descriptor.clone(),
                    call.clone(),
                    runtime.clone(),
                    selected_replicas.clone(),
                )
                .unwrap(),
        );
        let controller = discover_shared_genesis_startup(&bounded.parent, authority, 1)
            .unwrap()
            .unwrap();
        assert!(!controller.is_recovered());
        drop(controller);
        // A retained factory must not follow a replaced parent pathname when
        // an exact retry opens its stores.
        let committee_path = bounded.parent.join(SHARED_COMMITTEE_DIRECTORY);
        fs::rename(&committee_path, bounded.parent.join("displaced-committee")).unwrap();
        ensure_private_directory(&committee_path).unwrap();
        assert!(matches!(
            files.reserve_create(
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                selected_replicas.clone(),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::Unavailable)
        ));
        assert_eq!(fs::read_dir(&committee_path).unwrap().count(), 0);
        assert!(
            files
                .lifecycle
                .open_existing(authority.space, descriptor.identity.agent)
                .is_ok()
        );
        let foreign = Fixture::new("ordinary-genesis-foreign-roster");
        let mut foreign_lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            foreign.parent.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
        )
        .unwrap();
        let (foreign_intent, foreign_issuer) = foreign_lifecycle
            .open(authority.space, descriptor.identity.agent)
            .unwrap();
        ensure_private_directory(&foreign.parent.join(SHARED_COMMITTEE_DIRECTORY)).unwrap();
        let (mut foreign_query, foreign_reply) = CleanAgentGenesisCommitteeFile::open_pair(
            &foreign.parent.join(SHARED_COMMITTEE_DIRECTORY),
            locator,
        )
        .unwrap();
        let wrong_replicas = vos::agent::genesis::AgentReplicaCommittee::new(
            locator.space,
            vos::service::AgentId([0xa1; 32]),
            vos::agent::AgentProfile::Shared,
            selected_replicas.members().to_vec(),
        )
        .unwrap();
        foreign_query
            .commit_replicas(&wrong_replicas.encode())
            .unwrap();
        let foreign_publication = foreign_query.publication();
        let foreign_publication_reply = foreign_query.publication_reply();
        assert!(matches!(
            CleanSharedGenesisRecovery::reserve_create(
                authority,
                locator,
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                (
                    foreign_intent,
                    foreign_issuer,
                    foreign_query,
                    foreign_reply,
                    foreign_publication,
                    foreign_publication_reply,
                ),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
        ));
        let archives_path = fixture.parent.join(SHARED_ARCHIVE_DIRECTORY);
        ensure_private_directory(&archives_path).unwrap();
        let archives =
            CleanAgentGenesisArchiveStoreFactory::open_existing(&archives_path, locator.space)
                .unwrap();
        let committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &fixture.parent.join(SHARED_COMMITTEE_DIRECTORY),
            locator.space,
        )
        .unwrap();
        let mut lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            fixture.parent.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
        )
        .unwrap();
        let (intent, issuer) = lifecycle
            .open(authority.space, descriptor.identity.agent)
            .unwrap();
        let (query, reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&committee.parent, locator).unwrap();
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        let mut forged = call.clone();
        forged.signature[0] ^= 1;
        assert!(
            CleanSharedGenesisRecovery::reserve_create(
                authority,
                locator,
                descriptor.clone(),
                forged,
                runtime.clone(),
                (intent, issuer, query, reply, publication, publication_reply),
            )
            .is_err()
        );
        let (mut intent, issuer) = lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        assert!(intent.load().unwrap().is_none());
        assert!(intent.load_runtime().unwrap().is_none());
        let (query, reply) = committee.open_existing(locator).unwrap();
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        assert!(matches!(
            vos::agent::clean_bootstrap::NativeSharedGenesisRecovery::reserve_create(
                authority,
                locator,
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                (
                    FailRuntimeCommit(intent, false),
                    issuer,
                    query,
                    reply,
                    publication,
                    publication_reply
                ),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::Unavailable)
        ));
        let (mut intent, issuer) = lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        let retained_intent = intent.load().unwrap().unwrap();
        assert!(intent.load_runtime().unwrap().is_none());
        let (query, reply) = committee.open_existing(locator).unwrap();
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        assert!(matches!(
            vos::agent::clean_bootstrap::NativeSharedGenesisRecovery::reserve_create(
                authority,
                locator,
                descriptor.clone(),
                call.clone(),
                runtime.clone(),
                (
                    FailRuntimeCommit(intent, true),
                    issuer,
                    query,
                    reply,
                    publication,
                    publication_reply
                ),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::Unavailable)
        ));
        let (mut intent, issuer) = lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        assert_eq!(
            intent.load().unwrap().as_deref(),
            Some(retained_intent.as_slice())
        );
        assert_eq!(
            intent.load_runtime().unwrap().as_deref(),
            Some(runtime.exact_bytes())
        );
        let (query, reply) = committee.open_existing(locator).unwrap();
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        let recovery = CleanSharedGenesisRecovery::reserve_create(
            authority,
            locator,
            descriptor.clone(),
            call.clone(),
            runtime.clone(),
            (intent, issuer, query, reply, publication, publication_reply),
        )
        .unwrap();
        assert_eq!(recovery.locator(), locator);
        assert_eq!(
            recovery.runtime().unwrap().exact_bytes(),
            runtime.exact_bytes()
        );
        assert!(recovery.issued_receipt().is_none());
        let (intent, issuer, mut query, reply, publication, publication_reply) =
            recovery.into_stores();
        query.commit_replicas(&selected_replicas.encode()).unwrap();
        let mut recovery = CleanSharedGenesisRecovery::open(
            authority,
            locator,
            intent,
            issuer,
            query,
            reply,
            publication,
            publication_reply,
        )
        .unwrap();
        assert_eq!(
            recovery.retained_replicas().unwrap(),
            Some(selected_replicas.clone())
        );
        let (mut intent, issuer, query, reply, publication, publication_reply) =
            recovery.into_stores();
        assert_eq!(intent.load().unwrap(), Some(retained_intent));
        let recovery = CleanSharedGenesisRecovery::reserve_create(
            authority,
            locator,
            descriptor.clone(),
            call.clone(),
            runtime.clone(),
            (intent, issuer, query, reply, publication, publication_reply),
        )
        .unwrap();
        drop(recovery);
        let entries = archives
            .discover_recovery(&mut lifecycle, &committee, authority, 1)
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].archive.is_none());
        let mut operations = CleanNativeAuthorityOperationJournal::open_or_create(
            fixture.parent.join("operations"),
            authority,
        )
        .unwrap();
        let mut controller =
            CleanSharedGenesisStartupEntry::into_controller(authority, entries).unwrap();
        let admission = controller
            .startup_admission(operations.startup_admission().unwrap())
            .unwrap();
        assert!(matches!(
            lifecycle.open_existing(authority.space, descriptor.identity.agent),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            committee.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(admission);
        let mut foreign_authority = authority;
        foreign_authority.binding.policy.0[0] ^= 1;
        let mut foreign_operations = CleanNativeAuthorityOperationJournal::open_or_create(
            fixture.parent.join("foreign-operations"),
            foreign_authority,
        )
        .unwrap();
        assert!(matches!(
            controller.startup_admission(foreign_operations.startup_admission().unwrap()),
            Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
        ));
        assert!(!controller.is_recovered());
        assert!(matches!(
            lifecycle.open_existing(authority.space, descriptor.identity.agent),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            committee.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(controller);
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&archives_path, locator).unwrap();
        assert!(matches!(
            archives.discover_recovery(&mut lifecycle, &committee, authority, 1),
            Err(CleanFileStoreError::Busy)
        ));
        drop(archive);
        let entries = archives
            .discover_recovery(&mut lifecycle, &committee, authority, 1)
            .unwrap();
        assert!(entries[0].archive.as_ref().unwrap().1.is_none());
        let mut controller =
            CleanSharedGenesisStartupEntry::into_controller(authority, entries).unwrap();
        assert_eq!(controller.authority(), authority);
        assert!(!controller.is_recovered());
        let admission = controller
            .startup_admission(operations.startup_admission().unwrap())
            .unwrap();
        drop(admission);
        assert!(matches!(
            controller.startup_admission(foreign_operations.startup_admission().unwrap()),
            Err(vos::agent::shared_host::SharedAgentHostError::ScopeMismatch)
        ));
        assert!(matches!(
            archives.open_archive(locator),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            lifecycle.open_existing(authority.space, descriptor.identity.agent),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            committee.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(controller);
        let (intent, issuer) = lifecycle
            .open_existing(authority.space, descriptor.identity.agent)
            .unwrap();
        let (query, reply) = committee.open_existing(locator).unwrap();
        let publication = query.publication();
        let publication_reply = query.publication_reply();
        call.request_sequence = core::num::NonZeroU64::new(2).unwrap();
        call.invocation = call.expected_invocation();
        call.signature = operator
            .sign(&call.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(matches!(
            CleanSharedGenesisRecovery::reserve_create(
                authority,
                locator,
                descriptor,
                call,
                runtime,
                (intent, issuer, query, reply, publication, publication_reply),
            ),
            Err(vos::agent::shared_host::SharedAgentHostError::Conflict)
        ));
        assert_eq!(
            archives
                .discover_recovery(&mut lifecycle, &committee, authority, 1)
                .unwrap()
                .len(),
            1
        );
        let controller = discover_shared_genesis_startup(&fixture.parent, authority, 1)
            .unwrap()
            .unwrap();
        assert!(!controller.is_recovered());
        assert!(matches!(
            archives.open_archive(locator),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            committee.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        assert!(matches!(
            lifecycle.open_existing(authority.space, vos::agent::sdk::AgentId(locator.agent.0)),
            Err(CleanFileStoreError::Busy)
        ));
        drop(controller);
        assert!(archives.open_archive(locator).is_ok());
    }

    #[test]
    fn ordinary_genesis_joint_discovery_refuses_orphans_before_creating_query_slots() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        let fixture = Fixture::new("ordinary-genesis-joint-discovery");
        let (_, authority, _, _) = super::super::local_create::tests::fixture();
        let space = vos::service::SpaceId(authority.space.0);
        let parent = fixture.parent.join("archives");
        ensure_private_directory(&parent).unwrap();
        let archives = CleanAgentGenesisArchiveStoreFactory::open_existing(&parent, space).unwrap();
        let committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &fixture.parent.join("committee"),
            space,
        )
        .unwrap();
        let mut lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            fixture.parent.join("lifecycle"),
            authority.space,
        )
        .unwrap();
        assert!(
            archives
                .discover_recovery(&mut lifecycle, &committee, authority, 0)
                .unwrap()
                .is_empty()
        );
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([2; 32]),
        };
        let archive = CleanAgentGenesisArchiveFile::open_or_create(&parent, locator).unwrap();
        assert!(matches!(
            archives.discover_recovery(&mut lifecycle, &committee, authority, 4),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        assert!(committee.discover(0).unwrap().is_empty());
        assert!(lifecycle.discover(authority.space, 0).unwrap().is_empty());
        drop(archive);
        let (mut intent, issuer) = lifecycle
            .open(authority.space, vos::agent::sdk::AgentId(locator.agent.0))
            .unwrap();
        intent.commit(b"not a signed Shared Create").unwrap();
        drop((intent, issuer));
        assert!(matches!(
            archives.discover_recovery(&mut lifecycle, &committee, authority, 4),
            Err(CleanFileStoreError::Corrupt)
        ));
        // Failure releases acquired leases, without accepting the empty archive
        // as proof or replacing the malformed reservation with a new intent.
        let _archive = archives.open_archive(locator).unwrap();
        let (mut intent, _issuer) = lifecycle
            .open_existing(authority.space, vos::agent::sdk::AgentId(locator.agent.0))
            .unwrap();
        assert_eq!(
            intent.load().unwrap(),
            Some(b"not a signed Shared Create".to_vec())
        );
    }

    #[test]
    fn ordinary_genesis_discovery_keeps_unpledged_staging_inert() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        use vos::service::ServiceWire as _;

        let fixture = Fixture::new("ordinary-genesis-unpledged-staging");
        let (_, authority, _, runtime) = super::super::local_create::tests::fixture();
        let space = vos::service::SpaceId(authority.space.0);
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([2; 32]),
        };
        let archives_path = fixture.parent.join(SHARED_ARCHIVE_DIRECTORY);
        ensure_private_directory(&archives_path).unwrap();
        let archives =
            CleanAgentGenesisArchiveStoreFactory::open_existing(&archives_path, space).unwrap();
        let committee = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &fixture.parent.join(SHARED_COMMITTEE_DIRECTORY),
            space,
        )
        .unwrap();
        let mut lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            fixture.parent.join(SHARED_LIFECYCLE_DIRECTORY),
            authority.space,
        )
        .unwrap();
        let (mut intent, issuer) = lifecycle
            .open(authority.space, vos::agent::sdk::AgentId(locator.agent.0))
            .unwrap();
        drop((intent, issuer));
        assert!(
            archives
                .discover_recovery(&mut lifecycle, &committee, authority, 1)
                .unwrap()
                .is_empty()
        );
        assert!(committee.discover(0).unwrap().is_empty());

        let (mut intent, issuer) = lifecycle
            .open_existing(authority.space, vos::agent::sdk::AgentId(locator.agent.0))
            .unwrap();
        intent.commit_runtime(runtime.exact_bytes()).unwrap();
        drop((intent, issuer));
        let node_key = libp2p::identity::Keypair::ed25519_from_bytes([0x47; 32]).unwrap();
        let peer = node_key.public().to_peer_id().to_bytes();
        let public = ed25519_dalek::SigningKey::from_bytes(&[0x47; 32])
            .verifying_key()
            .to_bytes();
        let member = vos::agent::genesis::AgentReplicaMember::new(
            vos::agent::AgentReplica {
                node: vos::service::NodeId::of_authenticated_peer(&peer),
                principal: vos::service::PrincipalId::of_public_key(&public),
                role: vos::agent::ReplicaRole::Voter,
            },
            peer.clone(),
            public,
            Some(vos::agent::genesis::derive_replica_raft_slot(&peer)),
        )
        .unwrap();
        let replicas = vos::agent::genesis::AgentReplicaCommittee::new(
            space,
            locator.agent,
            vos::agent::AgentProfile::Shared,
            vec![member],
        )
        .unwrap();
        let (mut query, reply) =
            CleanAgentGenesisCommitteeFile::open_pair(&committee.parent, locator).unwrap();
        query.commit_replicas(&replicas.encode()).unwrap();
        drop((query, reply));
        assert!(
            archives
                .discover_recovery(&mut lifecycle, &committee, authority, 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(committee.discover(1).unwrap(), vec![locator]);

        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&archives_path, locator).unwrap();
        drop(archive);
        assert!(matches!(
            archives.discover_recovery(&mut lifecycle, &committee, authority, 1),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
    }

    #[test]
    fn ordinary_genesis_archive_discovery_is_noncreating_bounded_and_leased() {
        use vos::agent::genesis::AgentGenesisLocator;
        use vos::agent::genesis_archive::AgentGenesisArchiveStore;
        let fixture = Fixture::new("ordinary-genesis-archive-discovery");
        let parent = fixture.parent.join("archives");
        let space = vos::service::SpaceId([1; 32]);
        assert!(CleanAgentGenesisArchiveStoreFactory::open_existing(&parent, space).is_err());
        assert!(!parent.exists());
        ensure_private_directory(&parent).unwrap();
        let factory = CleanAgentGenesisArchiveStoreFactory::open_existing(&parent, space).unwrap();
        assert!(factory.discover(0).unwrap().is_empty());
        let low = AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([2; 32]),
        };
        let high = AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([3; 32]),
        };
        assert!(factory.open_archive(low).is_err());
        assert!(factory.discover(0).unwrap().is_empty());
        let high_file = CleanAgentGenesisArchiveFile::open_or_create(&parent, high).unwrap();
        let low_file = CleanAgentGenesisArchiveFile::open_or_create(&parent, low).unwrap();
        low_file.insert_if_absent(low, b"opaque archive").unwrap();
        assert_eq!(factory.discover(2).unwrap(), vec![low, high]);
        assert!(matches!(
            factory.discover(1),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            factory.open_archive(low),
            Err(CleanFileStoreError::Busy)
        ));
        drop(low_file);
        let reopened = factory.open_archive(low).unwrap();
        assert_eq!(
            reopened.load(low).unwrap(),
            Some(b"opaque archive".to_vec())
        );
        assert!(
            factory
                .open_archive(AgentGenesisLocator {
                    space: vos::service::SpaceId([9; 32]),
                    ..low
                })
                .is_err()
        );
        drop(high_file);
        drop(reopened);
        let moved = fixture.parent.join("moved-archives");
        fs::rename(&parent, &moved).unwrap();
        ensure_private_directory(&parent).unwrap();
        assert!(factory.discover(2).is_err());
        assert!(factory.open_archive(low).is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }

    #[test]
    fn ordinary_genesis_archive_discovery_refuses_foreign_and_symlink_entries() {
        let fixture = Fixture::new("ordinary-genesis-archive-hostile");
        let parent = fixture.parent.join("archives");
        ensure_private_directory(&parent).unwrap();
        let space = vos::service::SpaceId([1; 32]);
        let factory = CleanAgentGenesisArchiveStoreFactory::open_existing(&parent, space).unwrap();
        let foreign = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId([9; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let foreign_file = CleanAgentGenesisArchiveFile::open_or_create(&parent, foreign).unwrap();
        assert!(matches!(
            factory.discover(2),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        drop(foreign_file);
        let other = fixture.parent.join("symlinks");
        ensure_private_directory(&other).unwrap();
        let factory = CleanAgentGenesisArchiveStoreFactory::open_existing(&other, space).unwrap();
        let link = other.join(format!(
            "genesis-{}-{}",
            hex::encode(space.0),
            hex::encode([2; 32])
        ));
        std::os::unix::fs::symlink(&parent, &link).unwrap();
        assert!(factory.discover(1).is_err());
    }

    #[test]
    fn ordinary_genesis_committee_discovery_is_bounded_sorted_and_noncreating() {
        let fixture = Fixture::new("ordinary-genesis-discovery");
        let parent = fixture.parent.join("committee");
        let space = vos::service::SpaceId([1; 32]);
        let factory =
            CleanAgentGenesisCommitteeStoreFactory::open_or_create(&parent, space).unwrap();
        assert!(factory.discover(0).unwrap().is_empty());
        let low = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([2; 32]),
        };
        let high = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId([3; 32]),
        };
        assert!(factory.open_existing(low).is_err());
        assert!(factory.discover(0).unwrap().is_empty());
        let high_files = CleanAgentGenesisCommitteeFile::open_pair(&parent, high).unwrap();
        let low_files = CleanAgentGenesisCommitteeFile::open_pair(&parent, low).unwrap();
        assert_eq!(factory.discover(2).unwrap(), vec![low, high]);
        assert!(matches!(
            factory.discover(1),
            Err(CleanFileStoreError::Oversized)
        ));
        assert!(matches!(
            factory.open_existing(low),
            Err(CleanFileStoreError::Busy)
        ));
        drop(low_files);
        let mut reopened = factory.open_existing(low).unwrap();
        assert_eq!(reopened.0.load().unwrap(), None);
        assert_eq!(reopened.1.load().unwrap(), None);
        let foreign = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId([9; 32]),
            ..low
        };
        assert!(factory.open_existing(foreign).is_err());
        drop(high_files);
    }

    #[test]
    fn ordinary_genesis_recovery_discovery_rejects_orphan_and_invalid_intent() {
        use vos::agent::local_lifecycle::LocalLifecycleStoreFactory as _;
        let fixture = Fixture::new("ordinary-genesis-recovery-discovery");
        let (_, authority, _, _) = super::super::local_create::tests::fixture();
        let space = vos::service::SpaceId(authority.space.0);
        let parent = fixture.parent.join("committee");
        let factory =
            CleanAgentGenesisCommitteeStoreFactory::open_or_create(&parent, space).unwrap();
        let mut lifecycle = CleanManagementLifecycleStoreFactory::open_or_create(
            fixture.parent.join("lifecycle"),
            authority.space,
        )
        .unwrap();
        assert!(
            factory
                .discover_recovery(&mut lifecycle, authority, 0)
                .unwrap()
                .is_empty()
        );
        let agent = vos::agent::sdk::AgentId([2; 32]);
        let locator = vos::agent::genesis::AgentGenesisLocator {
            space,
            agent: vos::service::AgentId(agent.0),
        };
        let files = CleanAgentGenesisCommitteeFile::open_pair(&parent, locator).unwrap();
        assert!(matches!(
            factory.discover_recovery(&mut lifecycle, authority, 4),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        drop(files);
        let (mut intent, issuer) = lifecycle.open(authority.space, agent).unwrap();
        intent.commit(b"invalid signed intent").unwrap();
        drop((intent, issuer));
        assert!(matches!(
            factory.discover_recovery(&mut lifecycle, authority, 4),
            Err(CleanFileStoreError::Corrupt)
        ));
        let files = factory.open_existing(locator).unwrap();
        files
            .0
            .publication()
            .commit(b"retained publication phase")
            .unwrap();
        drop(files);
        assert!(matches!(
            factory.discover_recovery(&mut lifecycle, authority, 4),
            Err(CleanFileStoreError::Corrupt)
        ));
        let files = factory.open_existing(locator).unwrap();
        files
            .0
            .publication_reply()
            .commit(b"retained publication reply")
            .unwrap();
        drop(files);
        assert!(matches!(
            factory.discover_recovery(&mut lifecycle, authority, 4),
            Err(CleanFileStoreError::Corrupt)
        ));
        // A failed scan releases its acquired leases but preserves exact data.
        let (mut intent, _issuer) = lifecycle.open_existing(authority.space, agent).unwrap();
        assert_eq!(
            intent.load().unwrap(),
            Some(b"invalid signed intent".to_vec())
        );
        let _files = factory.open_existing(locator).unwrap();
    }

    #[test]
    fn ordinary_genesis_committee_discovery_refuses_foreign_space_and_symlinks() {
        let fixture = Fixture::new("ordinary-genesis-discovery-foreign");
        let parent = fixture.parent.join("committee");
        let factory = CleanAgentGenesisCommitteeStoreFactory::open_or_create(
            &parent,
            vos::service::SpaceId([1; 32]),
        )
        .unwrap();
        let foreign = vos::agent::genesis::AgentGenesisLocator {
            space: vos::service::SpaceId([9; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let _files = CleanAgentGenesisCommitteeFile::open_pair(&parent, foreign).unwrap();
        assert!(matches!(
            factory.discover(4),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        let fixture = Fixture::new("ordinary-genesis-discovery-symlink");
        let parent = fixture.parent.join("committee");
        let space = vos::service::SpaceId([1; 32]);
        let factory =
            CleanAgentGenesisCommitteeStoreFactory::open_or_create(&parent, space).unwrap();
        let name = format!(
            "genesis-committee-{}-{}",
            hex::encode(space.0),
            hex::encode([2; 32])
        );
        std::os::unix::fs::symlink(&fixture.parent, parent.join(name)).unwrap();
        assert!(factory.discover(4).is_err());
    }

    #[test]
    fn ordinary_genesis_committee_pair_recovers_stage_and_refuses_replacement() {
        for query_role in [true, false] {
            let fixture = Fixture::new("ordinary-genesis-committee-stage");
            let locator = vos::agent::genesis::AgentGenesisLocator {
                space: vos::service::SpaceId([1; 32]),
                agent: vos::service::AgentId([2; 32]),
            };
            let pair = CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let file = if query_role { &pair.0 } else { &pair.1 };
            stage(&file.0, None, &[1, 2, 3]);
            drop(pair);
            let mut pair =
                CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let file = if query_role { &mut pair.0 } else { &mut pair.1 };
            assert_eq!(file.load().unwrap(), Some(vec![1, 2, 3]));
            let current = file
                .0
                .reconcile(file.0.role.maximum_bytes())
                .unwrap()
                .unwrap();
            stage(&file.0, Some(current.commitment()), &[4]);
            drop(pair);
            let mut pair =
                CleanAgentGenesisCommitteeFile::open_pair(&fixture.parent, locator).unwrap();
            let file = if query_role { &mut pair.0 } else { &mut pair.1 };
            assert!(file.load().is_err());
        }
    }

    #[test]
    fn ordinary_genesis_signature_recovers_matching_stage_and_refuses_stale_stage() {
        use vos::agent::committee::AuthoritySignerId;
        use vos::agent::genesis::AgentGenesisLocator;
        let fixture = Fixture::new("ordinary-genesis-signature-stage");
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let signer = AuthoritySignerId::of_raw_ed25519(&[3; 32]);
        let file = CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
            .unwrap();
        let pledge = vec![0x11; 100];
        stage(&file.0, None, &pledge);
        drop(file);
        let mut file =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
                .unwrap();
        assert_eq!(file.load().unwrap(), Some(pledge));
        let current = file
            .0
            .reconcile(StoreRole::OrdinaryGenesisSignature.maximum_bytes())
            .unwrap()
            .unwrap();
        let predecessor = current.commitment();
        let signed = vec![0x22; 164];
        stage(&file.0, Some(predecessor), &signed);
        drop(file);
        let mut file =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
                .unwrap();
        assert_eq!(file.load().unwrap(), Some(signed));
        stage(&file.0, Some(predecessor), &[0x33; 100]);
        drop(file);
        let mut file =
            CleanAgentGenesisSignatureFile::open_or_create(&fixture.parent, locator, signer)
                .unwrap();
        assert!(file.load().is_err());
    }

    #[test]
    fn ordinary_genesis_archive_is_leased_immutable_and_reopens() {
        use vos::agent::genesis::AgentGenesisLocator;
        use vos::agent::genesis_archive::AgentGenesisArchiveStore;
        let fixture = Fixture::new("ordinary-genesis-immutable");
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        assert!(matches!(
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator),
            Err(CleanFileStoreError::Busy)
        ));
        assert_eq!(archive.load(locator).unwrap(), None);
        archive.insert_if_absent(locator, b"first").unwrap();
        archive.insert_if_absent(locator, b"different").unwrap();
        assert_eq!(
            archive.load(locator).unwrap().as_deref(),
            Some(b"first".as_slice())
        );
        assert!(
            archive
                .load(AgentGenesisLocator {
                    agent: vos::service::AgentId([3; 32]),
                    ..locator
                })
                .is_err()
        );
        drop(archive);
        let reopened =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        assert_eq!(
            reopened.load(locator).unwrap().as_deref(),
            Some(b"first".as_slice())
        );
    }

    #[test]
    fn ordinary_genesis_archive_recovers_initial_stage_but_refuses_replacement() {
        use vos::agent::genesis::AgentGenesisLocator;
        use vos::agent::genesis_archive::AgentGenesisArchiveStore;
        let fixture = Fixture::new("ordinary-genesis-stage");
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        stage(&archive.store.lock().unwrap(), None, b"initial");
        drop(archive);
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        assert_eq!(
            archive.load(locator).unwrap().as_deref(),
            Some(b"initial".as_slice())
        );
        {
            let file = archive.store.lock().unwrap();
            let current = file
                .reconcile(StoreRole::OrdinaryGenesisArchive.maximum_bytes())
                .unwrap()
                .unwrap();
            stage(&file, Some(current.commitment()), b"replacement");
        }
        drop(archive);
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        assert!(matches!(
            archive.load(locator),
            Err(CleanFileStoreError::RequestConflict)
        ));
    }

    #[test]
    fn ordinary_genesis_archive_racing_inserts_keep_one_winner() {
        use vos::agent::genesis::AgentGenesisLocator;
        use vos::agent::genesis_archive::AgentGenesisArchiveStore;
        let fixture = Fixture::new("ordinary-genesis-race");
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([1; 32]),
            agent: vos::service::AgentId([2; 32]),
        };
        let archive = Arc::new(
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = [b"one", b"two"]
            .into_iter()
            .map(|bytes| {
                let archive = Arc::clone(&archive);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    archive.insert_if_absent(locator, bytes).unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let winner = archive.load(locator).unwrap().unwrap();
        assert!(winner == b"one" || winner == b"two");
        drop(archive);
        let archive =
            CleanAgentGenesisArchiveFile::open_or_create(&fixture.parent, locator).unwrap();
        assert_eq!(archive.load(locator).unwrap(), Some(winner));
    }

    #[test]
    fn missing_files_create_and_reopen_with_exact_bytes() {
        let fixture = Fixture::new("roundtrip");
        let stores = fixture.stores();
        let (mut pins, mut bootstrap, mut issuer) = stores.into_parts();
        assert_eq!(pins.load(1024).unwrap(), None);
        assert_eq!(bootstrap.load(1024).unwrap(), None);
        assert_eq!(issuer.load().unwrap(), None);

        let pins_bytes = b"pins\0exact";
        let bootstrap_bytes = b"bootstrap\xffexact";
        let issuer_bytes = b"issuer\0\xffexact";
        pins.commit(pins_bytes).unwrap();
        bootstrap.commit(bootstrap_bytes).unwrap();
        issuer.commit(issuer_bytes).unwrap();
        assert_ne!(fs::read(fixture.root.join(PINS_FILE)).unwrap(), pins_bytes);
        drop((pins, bootstrap, issuer));

        let (mut pins, mut bootstrap, mut issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(1024).unwrap().as_deref(),
            Some(pins_bytes.as_slice())
        );
        assert_eq!(
            bootstrap.load(1024).unwrap().as_deref(),
            Some(bootstrap_bytes.as_slice())
        );
        assert_eq!(
            issuer.load().unwrap().as_deref(),
            Some(issuer_bytes.as_slice())
        );
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        assert!(!fixture.root.join(BOOTSTRAP_STAGE_FILE).exists());
        assert!(!fixture.root.join(ISSUER_STAGE_FILE).exists());
    }

    #[test]
    fn genesis_archive_shares_the_lease_and_has_an_independent_role() {
        let fixture = Fixture::new("genesis-archive");
        let (pins, bootstrap, issuer, mut genesis) = fixture.stores().into_production_parts();
        assert_eq!(genesis.load().unwrap(), None);
        genesis.commit(b"exact-root-provision-and-catalog").unwrap();
        assert_ne!(
            fs::read(fixture.root.join(GENESIS_FILE)).unwrap(),
            b"exact-root-provision-and-catalog",
        );
        drop((pins, bootstrap, issuer, genesis));

        let (pins, bootstrap, issuer, mut genesis) = fixture.stores().into_production_parts();
        assert_eq!(
            genesis.load().unwrap().as_deref(),
            Some(b"exact-root-provision-and-catalog".as_slice()),
        );
        assert!(!fixture.root.join(GENESIS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer, genesis));
    }

    #[test]
    fn exact_retry_preserves_the_exact_payload() {
        let fixture = Fixture::new("exact-retry");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"same-image").unwrap();
        let physical = fs::read(fixture.root.join(PINS_FILE)).unwrap();
        pins.commit(b"same-image").unwrap();
        assert_eq!(fs::read(fixture.root.join(PINS_FILE)).unwrap(), physical);
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"same-image".as_slice())
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn valid_initial_stage_is_the_only_safe_missing_target_recovery() {
        let fixture = Fixture::new("initial-stage");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        stage(&pins.0, None, b"initial");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"initial".as_slice())
        );
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn predecessor_bound_stage_completes_replacement_on_reopen() {
        let fixture = Fixture::new("replacement-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"old").unwrap();
        let current = pins
            .0
            .reconcile(StoreRole::Pins.maximum_bytes())
            .unwrap()
            .unwrap();
        stage(&pins.0, Some(current.commitment()), b"new");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(pins.load(64).unwrap().as_deref(), Some(b"new".as_slice()));
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn canonical_predecessor_tamper_is_detected() {
        let fixture = Fixture::new("canonical-predecessor-tamper");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"predecessor").unwrap();
        pins.commit(b"successor").unwrap();
        drop((pins, bootstrap, issuer));

        flip_first_predecessor_byte(&fixture.root.join(PINS_FILE));
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert!(fixture.root.join(PINS_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn staged_predecessor_tamper_is_detected() {
        let fixture = Fixture::new("staged-predecessor-tamper");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"predecessor").unwrap();
        let current = pins
            .0
            .reconcile(StoreRole::Pins.maximum_bytes())
            .unwrap()
            .unwrap();
        stage(&pins.0, Some(current.commitment()), b"successor");
        flip_first_predecessor_byte(&fixture.root.join(PINS_STAGE_FILE));
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn exact_duplicate_stage_is_retired_without_republication() {
        let fixture = Fixture::new("duplicate-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"published").unwrap();
        fs::copy(
            fixture.root.join(PINS_FILE),
            fixture.root.join(PINS_STAGE_FILE),
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            fixture.root.join(PINS_STAGE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert_eq!(
            pins.load(64).unwrap().as_deref(),
            Some(b"published".as_slice())
        );
        assert!(!fixture.root.join(PINS_STAGE_FILE).exists());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn unrelated_stage_and_target_fail_closed_without_cleanup() {
        let fixture = Fixture::new("ambiguous-stage");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"published").unwrap();
        stage(&pins.0, Some([0x55; 32]), b"unrelated");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::AmbiguousPublication)
        ));
        assert!(fixture.root.join(PINS_FILE).is_file());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn predecessor_without_a_target_is_ambiguous() {
        let fixture = Fixture::new("missing-predecessor");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        stage(&pins.0, Some([0x33; 32]), b"orphan-successor");
        drop((pins, bootstrap, issuer));

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::AmbiguousPublication)
        ));
        assert!(!fixture.root.join(PINS_FILE).exists());
        assert!(fixture.root.join(PINS_STAGE_FILE).is_file());
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn corrupt_stage_fails_closed_and_is_not_removed() {
        let fixture = Fixture::new("corrupt-stage");
        let stores = fixture.stores();
        drop(stores);
        write_private(&fixture.root.join(PINS_STAGE_FILE), b"partial");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        assert_eq!(
            fs::read(fixture.root.join(PINS_STAGE_FILE)).unwrap(),
            b"partial"
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn create_new_stage_never_overwrites_a_collision() {
        let fixture = Fixture::new("stage-collision");
        let (pins, bootstrap, issuer) = fixture.stores().into_parts();
        write_private(&fixture.root.join(PINS_STAGE_FILE), b"occupied");
        let encoded = encode_envelope(StoreRole::Pins, None, b"candidate").unwrap();
        assert!(matches!(
            pins.0.write_stage(&encoded),
            Err(CleanFileStoreError::StageCollision)
        ));
        assert_eq!(
            fs::read(fixture.root.join(PINS_STAGE_FILE)).unwrap(),
            b"occupied"
        );
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn one_lease_serializes_all_three_files() {
        let fixture = Fixture::new("lease");
        let stores = fixture.stores();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::Busy)
        ));
        drop(stores);
        assert!(CleanSystemAgentFileStores::open_or_create(&fixture.root).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_or_unlinked_named_lock_invalidates_the_held_lease() {
        let replacement_fixture = Fixture::new("lock-replacement");
        let (mut pins, mut bootstrap, issuer) = replacement_fixture.stores().into_parts();
        let lock_path = replacement_fixture.root.join(LOCK_FILE);
        fs::remove_file(&lock_path).unwrap();
        write_private(&lock_path, b"");
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Alias)));
        assert!(matches!(
            bootstrap.load(64),
            Err(CleanFileStoreError::Alias)
        ));
        drop((pins, bootstrap, issuer));

        let unlink_fixture = Fixture::new("lock-unlink");
        let (mut pins, bootstrap, issuer) = unlink_fixture.stores().into_parts();
        fs::remove_file(unlink_fixture.root.join(LOCK_FILE)).unwrap();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::Io(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        drop((pins, bootstrap, issuer));
    }

    #[cfg(unix)]
    #[test]
    fn parent_mode_and_root_inode_are_revalidated_for_existing_handles() {
        let parent_fixture = Fixture::new("live-parent-mode");
        let (mut pins, bootstrap, issuer) = parent_fixture.stores().into_parts();
        fs::set_permissions(&parent_fixture.parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::InsecureParent)
        ));
        drop((pins, bootstrap, issuer));

        let root_fixture = Fixture::new("live-root-replacement");
        let (mut pins, bootstrap, issuer) = root_fixture.stores().into_parts();
        let displaced = root_fixture.parent.join("displaced-state");
        fs::rename(&root_fixture.root, &displaced).unwrap();
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root_fixture.root).unwrap();
        fs::set_permissions(&root_fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Alias)));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn relative_dotdot_and_symlink_roots_are_rejected() {
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(Path::new("relative-clean-store")),
            Err(CleanFileStoreError::InvalidPath)
        ));

        let fixture = Fixture::new("root-alias");
        let stores = fixture.stores();
        drop(stores);
        let dotdot = fixture.root.join("..").join("state");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(dotdot),
            Err(CleanFileStoreError::InvalidPath)
        ));

        #[cfg(unix)]
        {
            let alias = fixture.parent.join("alias");
            std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
            assert!(matches!(
                CleanSystemAgentFileStores::open_or_create(alias),
                Err(CleanFileStoreError::Alias)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn parent_and_root_must_be_exact_private_directories() {
        let fixture = Fixture::new("directory-modes");
        fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::InsecureParent)
        ));
        fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(0o700)).unwrap();
        let stores = fixture.stores();
        drop(stores);
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::InsecureRoot)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_nonregular_entries_are_rejected() {
        let symlink_fixture = Fixture::new("symlink-entry");
        drop(symlink_fixture.stores());
        let outside = symlink_fixture.parent.join("outside");
        write_private(&outside, b"outside");
        std::os::unix::fs::symlink(&outside, symlink_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&symlink_fixture.root),
            Err(CleanFileStoreError::Alias)
        ));

        let hardlink_fixture = Fixture::new("hardlink-entry");
        drop(hardlink_fixture.stores());
        let outside = hardlink_fixture.parent.join("outside");
        write_private(&outside, b"outside");
        fs::hard_link(&outside, hardlink_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&hardlink_fixture.root),
            Err(CleanFileStoreError::HardLink)
        ));

        let directory_fixture = Fixture::new("directory-entry");
        drop(directory_fixture.stores());
        fs::create_dir(directory_fixture.root.join(PINS_FILE)).unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&directory_fixture.root),
            Err(CleanFileStoreError::NonRegular)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn image_and_lock_permissions_are_revalidated_on_reopen() {
        let image_fixture = Fixture::new("image-mode");
        let (mut pins, bootstrap, issuer) = image_fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        drop((pins, bootstrap, issuer));
        fs::set_permissions(
            image_fixture.root.join(PINS_FILE),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&image_fixture.root),
            Err(CleanFileStoreError::InsecurePermissions)
        ));
        assert_eq!(
            fs::symlink_metadata(image_fixture.root.join(PINS_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o640
        );

        let lock_fixture = Fixture::new("lock-mode");
        drop(lock_fixture.stores());
        fs::set_permissions(
            lock_fixture.root.join(LOCK_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&lock_fixture.root),
            Err(CleanFileStoreError::InsecurePermissions)
        ));
        assert_eq!(
            fs::symlink_metadata(lock_fixture.root.join(LOCK_FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn truncated_and_digest_corrupt_images_fail_closed() {
        let truncated_fixture = Fixture::new("truncated");
        let (mut pins, bootstrap, issuer) = truncated_fixture.stores().into_parts();
        pins.commit(b"complete").unwrap();
        drop((pins, bootstrap, issuer));
        OpenOptions::new()
            .write(true)
            .open(truncated_fixture.root.join(PINS_FILE))
            .unwrap()
            .set_len((STORE_HEADER_BYTES - 1) as u64)
            .unwrap();
        let (mut pins, bootstrap, issuer) = truncated_fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        drop((pins, bootstrap, issuer));

        let corrupt_fixture = Fixture::new("digest-corrupt");
        let (mut pins, bootstrap, issuer) = corrupt_fixture.stores().into_parts();
        pins.commit(b"complete").unwrap();
        drop((pins, bootstrap, issuer));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(corrupt_fixture.root.join(PINS_FILE))
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[0x7f]).unwrap();
        file.sync_all().unwrap();
        let (mut pins, bootstrap, issuer) = corrupt_fixture.stores().into_parts();
        assert!(matches!(pins.load(64), Err(CleanFileStoreError::Corrupt)));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn oversized_state_is_rejected_before_body_allocation() {
        let fixture = Fixture::new("oversized");
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"small").unwrap();
        drop((pins, bootstrap, issuer));
        OpenOptions::new()
            .write(true)
            .open(fixture.root.join(PINS_FILE))
            .unwrap()
            .set_len((STORE_HEADER_BYTES + MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES + 1) as u64)
            .unwrap();
        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES),
            Err(CleanFileStoreError::Oversized)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn caller_bound_and_store_bound_are_both_enforced() {
        let fixture = Fixture::new("bounds");
        let (mut pins, bootstrap, mut issuer) = fixture.stores().into_parts();
        pins.commit(b"four").unwrap();
        assert!(matches!(pins.load(3), Err(CleanFileStoreError::Oversized)));
        assert!(matches!(
            issuer.commit(&vec![0_u8; MAX_CLEAN_MANAGEMENT_ISSUER_IMAGE_BYTES + 1]),
            Err(CleanFileStoreError::Oversized)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn role_bound_envelopes_reject_cross_store_file_swaps() {
        let fixture = Fixture::new("role-swap");
        let (mut pins, mut bootstrap, issuer) = fixture.stores().into_parts();
        pins.commit(b"pins").unwrap();
        bootstrap.commit(b"bootstrap").unwrap();
        drop((pins, bootstrap, issuer));
        let temporary = fixture.parent.join("swap");
        fs::rename(fixture.root.join(PINS_FILE), &temporary).unwrap();
        fs::rename(
            fixture.root.join(BOOTSTRAP_FILE),
            fixture.root.join(PINS_FILE),
        )
        .unwrap();
        fs::rename(temporary, fixture.root.join(BOOTSTRAP_FILE)).unwrap();

        let (mut pins, bootstrap, issuer) = fixture.stores().into_parts();
        assert!(matches!(
            pins.load(64),
            Err(CleanFileStoreError::WrongStoreRole)
        ));
        drop((pins, bootstrap, issuer));
    }

    #[test]
    fn unknown_files_are_never_treated_as_store_residue() {
        let fixture = Fixture::new("unknown-residue");
        drop(fixture.stores());
        write_private(&fixture.root.join("old-generation"), b"legacy");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));

        let fresh_fixture = Fixture::new("fresh-unknown-residue");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&fresh_fixture.root).unwrap();
        fs::set_permissions(&fresh_fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&fresh_fixture.root.join("foreign"), b"foreign");
        assert!(matches!(
            CleanSystemAgentFileStores::open_or_create(&fresh_fixture.root),
            Err(CleanFileStoreError::UnexpectedResidue)
        ));
        assert!(!fresh_fixture.root.join(LOCK_FILE).exists());
    }
}
