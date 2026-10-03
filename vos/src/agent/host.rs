//! Durable Local system-Agent host.
//!
//! One internal serialized host owns a filesystem directory and the one system
//! Agent selected by independently configured root pins. The public
//! [`AgentHostControl`] retains that worker's unique ownership. The clean
//! generation is a journal rooted at `<full-agent-id>.agent`; retired
//! `.agent-image` files are rejected and are never migrated implicitly.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fs2::FileExt;

pub use super::local_journal_driver::LocalMergeAuthenticator;
#[cfg(feature = "network")]
pub use super::local_journal_driver::{
    Ed25519NodeMergeAuthenticator, Ed25519NodeMergeAuthenticatorError,
};

use super::authority::{
    ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityReceipt, AuthorityError,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::bootstrap::validate_prepared_system_agent_genesis_root;
use super::bootstrap::{
    SystemAgentGenesisBootstrapError, SystemAgentGenesisLocator, SystemAgentGenesisProposal,
    SystemAgentGenesisProvider, SystemAgentGenesisProviderError,
    seal_prepared_system_agent_genesis,
};
use super::committee::RootAnchorPins;
use super::driver::{AgentTrustProvider, SdkManagementArtifacts};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorInvocation, MAX_EXECUTION_AVAILABILITY_BYTES,
    MAX_EXECUTION_BLOBS, MAX_EXECUTION_GAS, MAX_EXECUTION_MESSAGE_BYTES,
    MAX_EXECUTION_POLICY_BYTES, MAX_EXECUTION_PROGRAM_BYTES, RuntimeBlob,
};
use super::journal::{CanonicalJournalRecord, ReplayOperation};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::journal_store::{
    AgentJournalStore, BoundFileSystemAuthorityLedgerOwner, FileAgentJournalSlot,
    FileLocalAgentJournalSlot,
};
use super::journal_store::{FileAgentJournalStore, JournalStoreError};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::local_journal_driver::LocalJournalUnexposedOpenError;
use super::local_journal_driver::{
    LocalCleanManagementResult, LocalJournalAgentDriver, LocalJournalDriverError,
    LocalLifecycleOperation, LocalReplayExecutorError, LocalSettledAcknowledgementResult,
    LocalSettledInvocationResult,
};
use super::package::{
    MAX_ENCODED_PACKAGE_BYTES, MAX_PACKAGE_DIAGNOSTICS_BYTES, MAX_PACKAGE_INTERFACES_BYTES,
    MAX_PACKAGE_SCHEMAS_BYTES, MAX_PACKAGE_TASK_BYTES, Package, PackageError,
};
use super::replay::{
    ReplayError, ReplayMaterializationSourceError, ReplaySealedGenesis, ReplaySealedLocalGenesis,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::system_authority_ledger::{SystemAuthorityLedgerError, SystemAuthorityLedgerRouteOwner};
use super::{
    ActorDirectoryPage, ActorEntry, AgentConfig, AgentConfigError, AgentIdentity, LifecycleError,
    LifecycleReply, LifecycleRequest, PackageKind,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, DeploymentId, Hash, InstallationId, InvocationId,
    NodeId, ProgramId, SpaceId,
};

const JOURNAL_SUFFIX: &str = ".agent";
const JOURNAL_LOCK_SUFFIX: &str = ".agent-lock";
const LEGACY_IMAGE_SUFFIX: &str = ".agent-image";
const LOCAL_GENESIS_INTENT_SUFFIX: &str = ".local-genesis.intent";
const LOCAL_GENESIS_INTENT_STAGE_SUFFIX: &str = ".local-genesis.intent.next";
const LOCAL_GENESIS_EXPOSURE_SUFFIX: &str = ".local-genesis.exposed";
const LOCAL_GENESIS_EXPOSURE_STAGE_SUFFIX: &str = ".local-genesis.exposed.next";
const LOCAL_GENESIS_INTENT_DOMAIN: &[u8] = b"vos/agent-host/local-genesis-intent/v1";
const MAX_LOCAL_GENESIS_INTENT_BYTES: usize =
    MAX_ENCODED_PACKAGE_BYTES + super::journal::MAX_REPLAY_INPUT_BYTES + 1024;
const SYSTEM_AUTHORITY_LEDGER_SUFFIX: &str = ".system-authority-ledger.redb";
const SYSTEM_AUTHORITY_LEDGER_STAGE_SUFFIX: &str = ".system-authority-ledger.redb.next";
const HOST_LOCK_FILE: &str = ".agent-host.lock";
const HOST_SCOPE_FILE: &str = ".agent-host.scope";
const HOST_SCOPE_TEMP_FILE: &str = ".agent-host.scope.tmp";
const HOST_SCOPE_MAGIC: &[u8; 8] = b"VOSAHST1";
const HOST_SCOPE_ENCODED_LEN: usize = HOST_SCOPE_MAGIC.len() + 32 + 32;
const HOST_LEASE_BINDING_MAGIC: &[u8; 8] = b"VOSAHBL1";
const HOST_LEASE_ARM_MAGIC: &[u8; 8] = b"VOSAHAE1";
const HOST_LEASE_RECORD_VERSION: u32 = 1;
const HOST_LEASE_BINDING_FRESH: u32 = 1;
const HOST_LEASE_BINDING_LEGACY_MIGRATION: u32 = 2;
const HOST_LEASE_BINDING_PREFIX_LEN: usize = 8 + 4 + 4 + 32 + 32 + 32;
const HOST_LEASE_BINDING_LEN: usize = HOST_LEASE_BINDING_PREFIX_LEN + 32;
const HOST_LEASE_ARM_PREFIX_LEN: usize = 8 + 4 + 32;
const HOST_LEASE_ARM_LEN: usize = HOST_LEASE_ARM_PREFIX_LEN + 32;
const HOST_LEASE_ARMED_LEN: usize = HOST_LEASE_BINDING_LEN + HOST_LEASE_ARM_LEN;
const HOST_LEASE_ROOT_DOMAIN: &[u8] = b"vos/agent-host/root-path/v1";
const HOST_LEASE_BINDING_DOMAIN: &[u8] = b"vos/agent-host/lease-binding/v1";
const HOST_LEASE_ARM_DOMAIN: &[u8] = b"vos/agent-host/lease-armed/v1";
const HOST_AUTHORITY_ROOT_DOMAIN: &[u8] = b"vos/agent-host/authority-root/v1";
const HOST_AUTHORITY_ROOT_SUFFIX: &str = ".agent-authority";

/// Maximum number of Agent-host operations waiting behind the one active
/// operation. The bounded queue is intentional: callers receive explicit
/// backpressure instead of growing daemon memory while a PVM or durable store
/// operation is in progress.
pub const DEFAULT_AGENT_HOST_QUEUE_CAPACITY: usize = 64;

/// Maximum cumulative caller-owned payload retained by active and queued
/// Agent-host operations. This complements the command-count bound: a small
/// number of otherwise valid packages must not retain unbounded daemon memory
/// while the serialized worker is busy.
pub const DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES: usize = 32 * 1024 * 1024;

const WORKER_RUNNING: u8 = 0;
const WORKER_SHUTTING_DOWN: u8 = 1;
const WORKER_STOPPED: u8 = 2;

/// Durable, exact replay input for one ordinary Local creation.  The file is
/// retained outside the replaceable journal root and therefore serves both
/// as crash-recovery material and as the exact idempotency record.  It is not
/// an admission capability: every open re-authenticates and exactly executes
/// it through the configured trust provider before replay can mint a seal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalGenesisIntent {
    create: super::journal::ReplayInput,
    runtime_package: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LocalGenerationFiles {
    journal: bool,
    lock: bool,
    intent: bool,
    intent_stage: bool,
    exposed: bool,
    exposed_stage: bool,
}

impl LocalGenesisIntent {
    fn new(
        create: super::journal::ReplayInput,
        runtime_package: &Package,
    ) -> Result<Self, AgentHostError> {
        let intent = Self {
            create,
            runtime_package: runtime_package.encode(),
        };
        intent.validate()?;
        Ok(intent)
    }

    fn config(&self) -> Result<&AgentConfig, AgentHostError> {
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &self.create.operation
        else {
            return Err(AgentHostError::InvalidRuntime);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(AgentHostError::InvalidRuntime);
        };
        Ok(config)
    }

    fn receipt(&self) -> Result<&AgentAuthorityReceipt, AgentHostError> {
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, .. },
        } = &self.create.operation
        else {
            return Err(AgentHostError::InvalidRuntime);
        };
        Ok(&admission.receipt)
    }

    fn runtime_package(&self) -> Result<Package, AgentHostError> {
        let package =
            Package::decode(&self.runtime_package).map_err(|_| AgentHostError::InvalidRuntime)?;
        if package.encode() != self.runtime_package {
            return Err(AgentHostError::InvalidRuntime);
        }
        Ok(package)
    }

    fn validate(&self) -> Result<(), AgentHostError> {
        self.create
            .validate()
            .map_err(|_| AgentHostError::InvalidRuntime)?;
        let config = self.config()?;
        config.validate().map_err(AgentHostError::InvalidConfig)?;
        if config.identity.profile != super::AgentProfile::Local
            || config.system_authority_genesis.is_some()
            || config.replicas.len() != 1
            || self.create.runtime.space != config.identity.space
            || self.create.runtime.agent != config.identity.agent
            || self.create.runtime.package != config.runtime_package
            || !config.runtime_package.matches(&self.runtime_package)
        {
            return Err(AgentHostError::InvalidRuntime);
        }
        let package = self.runtime_package()?;
        package.validate().map_err(AgentHostError::Package)?;
        if self.encode().len() > MAX_LOCAL_GENESIS_INTENT_BYTES {
            return Err(AgentHostError::InvalidRuntime);
        }
        Ok(())
    }

    fn id(&self) -> Hash {
        Hash::digest(LOCAL_GENESIS_INTENT_DOMAIN, &[&self.encode()])
    }

    fn catalog(&self) -> Vec<RuntimeBlob> {
        vec![RuntimeBlob {
            reference: BlobRef::of_bytes(&self.runtime_package),
            bytes: self.runtime_package.clone(),
        }]
    }

    fn matches_caller(
        &self,
        config: &AgentConfig,
        runtime_package: &Package,
        receipt: &AgentAuthorityReceipt,
    ) -> Result<bool, AgentHostError> {
        Ok(self.config()? == config
            && self.runtime_package == runtime_package.encode()
            && self.receipt()? == receipt)
    }
}

impl ServiceWire for LocalGenesisIntent {
    const MAGIC: [u8; 4] = *b"AGLI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.create.encode());
        encoder.bytes(&self.runtime_package);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if decoder.remaining() > MAX_LOCAL_GENESIS_INTENT_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let create = super::journal::ReplayInput::decode(&decoder.bytes()?)?;
        let runtime_package = decoder.bytes()?;
        let intent = Self {
            create,
            runtime_package,
        };
        intent.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(intent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHostError {
    Unavailable,
    InvalidScope,
    ScopeMismatch,
    InvalidScopeBinding,
    DirectoryInUse,
    InvalidQueueCapacity,
    InvalidJournalName,
    LegacyGeneration,
    DuplicateAgent,
    AgentNotFound,
    IdentityMismatch,
    Overloaded,
    ShuttingDown,
    WorkerStopped,
    WorkerPanicked,
    InvalidConfig(AgentConfigError),
    Package(PackageError),
    Lifecycle(LifecycleError),
    Execution(ActorExecutionError),
    Authority(AuthorityError),
    Journal(AgentHostJournalError),
    Bootstrap(SystemAgentGenesisBootstrapError),
    Provider(SystemAgentGenesisProviderError),
    InvalidAuthority,
    AuthorityLedger,
    AuthorityRecoveryRequired,
    TrustUnavailable,
    Conflict,
    InvalidRuntime,
    InvocationAcknowledged,
}

impl core::fmt::Display for AgentHostError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent host: {self:?}")
    }
}

impl std::error::Error for AgentHostError {}

/// Public, host-stable projection of the crate-private journal adapter errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHostJournalError {
    InvalidPath,
    ScopeMismatch,
    DirectoryInUse,
    LegacyGeneration,
    NotInitialized,
    Conflict,
    GcPending,
    InvalidClass,
    NonCanonical,
    LimitExceeded,
    Backpressure,
    MissingObject,
    Corrupt,
    Unavailable,
}

/// Stable ownership token for one configured Agent data-root slot.
///
/// `stable_lock_path` must live outside `root`. The token therefore remains
/// exclusive if a backup/restore workflow renames and replaces the complete
/// data directory. [`AgentHostControl`] additionally owns a worker which locks
/// an inode inside `root` as defense in depth. Production setup must durably create the configured
/// parent directories first; this helper syncs the immediate parent of any
/// leaf it creates, but cannot make an arbitrarily deep new ancestor chain
/// crash-durable.
pub struct AgentHostRootLease {
    root: PathBuf,
    scope: AgentHostScope,
    stable_lock_path: PathBuf,
    stable_lock_parent: File,
    stable_lock: File,
    root_parent: File,
    root_directory: File,
    authority_root: PathBuf,
    authority_directory: File,
    binding: [u8; HOST_LEASE_BINDING_LEN],
    state: AgentHostRootLeaseState,
    // A failed Arm attempt can have durably advanced the on-disk record even
    // when the caller did not observe the final sync/read.  While this bit is
    // set, validation may reconcile only the exact forward crash states and
    // initialization/repair remains disabled until Arm is re-synced.
    arm_write_uncertain: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentHostRootLeaseState {
    LegacyUnbound,
    FreshBound,
    FreshArmInterrupted,
    LegacyMigrationBound,
    FreshArmed,
    LegacyMigrationArmed,
}

impl core::fmt::Debug for AgentHostRootLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostRootLease")
            .field("root", &self.root)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl AgentHostRootLease {
    pub fn acquire(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        scope: AgentHostScope,
    ) -> Result<Self, AgentHostError> {
        let scope = scope.validate()?;
        let requested_root = absolute_agent_host_path(root.into())?;
        let requested_lock = absolute_agent_host_path(stable_lock_path.into())?;
        if requested_lock.starts_with(&requested_root) {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let (root, _) = canonical_agent_host_root_target(requested_root)?;
        let root_parent = open_agent_host_lock_parent(&root)?;
        let stable_lock_path = canonical_lock_path(requested_lock)?;
        if stable_lock_path.starts_with(&root) {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let stable_lock_parent = open_agent_host_lock_parent(&stable_lock_path)?;
        let fresh_binding =
            encode_agent_host_lease_binding(&root, scope, HOST_LEASE_BINDING_FRESH)?;
        let migration_binding =
            encode_agent_host_lease_binding(&root, scope, HOST_LEASE_BINDING_LEGACY_MIGRATION)?;
        let authority_root = agent_host_authority_root(&stable_lock_path, &root, scope)?;
        let (mut stable_lock, created) = open_agent_host_lease_file(
            &stable_lock_path,
            &stable_lock_parent,
            &fresh_binding,
            &root,
            &root_parent,
            &authority_root,
        )?;
        validate_agent_host_lock_parent_identity(&stable_lock_parent, &stable_lock_path)?;
        let state =
            read_agent_host_lease_state(&mut stable_lock, &fresh_binding, &migration_binding)?;
        validate_agent_host_lock_identity(&stable_lock, &stable_lock_path)?;
        let (binding, state) = match (created, state) {
            (true, AgentHostRootLeaseState::FreshBound) => {
                (fresh_binding, AgentHostRootLeaseState::FreshBound)
            }
            (true, _) => return Err(AgentHostError::InvalidScopeBinding),
            (false, AgentHostRootLeaseState::LegacyUnbound) => {
                (migration_binding, AgentHostRootLeaseState::LegacyUnbound)
            }
            (_, AgentHostRootLeaseState::FreshBound) => {
                (fresh_binding, AgentHostRootLeaseState::FreshBound)
            }
            (_, AgentHostRootLeaseState::FreshArmInterrupted) => {
                (fresh_binding, AgentHostRootLeaseState::FreshArmInterrupted)
            }
            (_, AgentHostRootLeaseState::LegacyMigrationBound) => (
                migration_binding,
                AgentHostRootLeaseState::LegacyMigrationBound,
            ),
            (_, AgentHostRootLeaseState::FreshArmed) => {
                (fresh_binding, AgentHostRootLeaseState::FreshArmed)
            }
            (_, AgentHostRootLeaseState::LegacyMigrationArmed) => (
                migration_binding,
                AgentHostRootLeaseState::LegacyMigrationArmed,
            ),
        };
        validate_agent_host_lock_identity(&stable_lock, &stable_lock_path)?;
        validate_agent_host_lock_parent_identity(&stable_lock_parent, &stable_lock_path)?;
        if state == AgentHostRootLeaseState::FreshBound {
            validate_fresh_bound_tree_prefix(
                &root,
                &root_parent,
                &authority_root,
                &stable_lock_parent,
            )?;
        }
        let root = match state {
            AgentHostRootLeaseState::FreshBound => {
                // Only a never-armed fresh binding may recover the crash
                // window between binding the outer lease and creating the
                // replaceable root leaf.
                ensure_agent_host_root(root, &root_parent)?
            }
            AgentHostRootLeaseState::FreshArmInterrupted
            | AgentHostRootLeaseState::LegacyUnbound
            | AgentHostRootLeaseState::LegacyMigrationBound
            | AgentHostRootLeaseState::FreshArmed
            | AgentHostRootLeaseState::LegacyMigrationArmed => {
                existing_agent_host_root(root, &root_parent)?
            }
        };
        let root_directory = open_agent_host_root_directory_at(&root_parent, &root)?;
        let authority_root = match state {
            AgentHostRootLeaseState::FreshBound => {
                ensure_agent_host_authority_root(authority_root, &stable_lock_parent)?
            }
            AgentHostRootLeaseState::FreshArmInterrupted
            | AgentHostRootLeaseState::LegacyUnbound
            | AgentHostRootLeaseState::LegacyMigrationBound
            | AgentHostRootLeaseState::FreshArmed
            | AgentHostRootLeaseState::LegacyMigrationArmed => {
                existing_agent_host_authority_root(authority_root, &stable_lock_parent)?
            }
        };
        let authority_directory =
            open_agent_host_root_directory_at(&stable_lock_parent, &authority_root)?;
        Ok(Self {
            root,
            scope,
            stable_lock_path,
            stable_lock_parent,
            stable_lock,
            root_parent,
            root_directory,
            authority_root,
            authority_directory,
            binding,
            state,
            arm_write_uncertain: false,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn scope(&self) -> AgentHostScope {
        self.scope
    }

    /// Pinned secure namespace that owns the durable per-Agent authority
    /// lock and ledger.  This deliberately differs from the replaceable
    /// journal root.
    pub(crate) fn authority_root(&self) -> Result<&Path, AgentHostError> {
        Ok(&self.authority_root)
    }

    const fn may_initialize_host_boundary(&self) -> bool {
        matches!(self.state, AgentHostRootLeaseState::FreshBound) && !self.arm_write_uncertain
    }

    pub(crate) const fn is_armed(&self) -> bool {
        matches!(self.state, AgentHostRootLeaseState::FreshArmed)
    }

    const fn requires_strict_unexposed_open(&self) -> bool {
        self.arm_write_uncertain
            || matches!(
                self.state,
                AgentHostRootLeaseState::FreshArmInterrupted | AgentHostRootLeaseState::FreshArmed
            )
    }

    pub(crate) fn clone_generation_parents(&mut self) -> Result<(File, File), AgentHostError> {
        self.validate_live()?;
        let journal_parent = self
            .root_directory
            .try_clone()
            .map_err(|_| AgentHostError::Unavailable)?;
        let authority_parent = self
            .authority_directory
            .try_clone()
            .map_err(|_| AgentHostError::Unavailable)?;
        self.validate_live()?;
        Ok((journal_parent, authority_parent))
    }

    fn rejects_generation_state(
        &self,
        generation_residue: bool,
        complete_generation: bool,
    ) -> bool {
        if self.arm_write_uncertain {
            return !generation_residue || !complete_generation;
        }
        match self.state {
            AgentHostRootLeaseState::LegacyUnbound
            | AgentHostRootLeaseState::LegacyMigrationBound
            | AgentHostRootLeaseState::LegacyMigrationArmed => true,
            AgentHostRootLeaseState::FreshBound => false,
            AgentHostRootLeaseState::FreshArmInterrupted | AgentHostRootLeaseState::FreshArmed => {
                !generation_residue || !complete_generation
            }
        }
    }

    #[cfg(not(all(feature = "storage", target_os = "linux")))]
    pub(crate) fn arm_after_agent_open(&mut self) -> Result<(), AgentHostError> {
        Err(AgentHostError::Unavailable)
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    pub(crate) fn arm_after_agent_open(&mut self) -> Result<(), AgentHostError> {
        self.validate_live()?;
        let fresh_binding =
            encode_agent_host_lease_binding(&self.root, self.scope, HOST_LEASE_BINDING_FRESH)?;
        let migration_binding = encode_agent_host_lease_binding(
            &self.root,
            self.scope,
            HOST_LEASE_BINDING_LEGACY_MIGRATION,
        )?;
        match self.state {
            AgentHostRootLeaseState::FreshBound => {
                self.arm_write_uncertain = true;
            }
            AgentHostRootLeaseState::FreshArmInterrupted => {
                self.arm_write_uncertain = true;
                recover_interrupted_agent_host_lease_arm(
                    &mut self.stable_lock,
                    &self.stable_lock_path,
                    &self.stable_lock_parent,
                    &fresh_binding,
                    &migration_binding,
                )?;
                self.state = AgentHostRootLeaseState::FreshBound;
            }
            AgentHostRootLeaseState::FreshArmed => {
                // A previous attempt may have written the complete Arm and
                // then reported a file/parent-sync or final-read failure.
                // Never treat mere bytes as durable: re-sync both boundaries
                // and re-read the exact record before permitting exposure.
                self.arm_write_uncertain = true;
                self.stable_lock
                    .sync_all()
                    .map_err(|_| AgentHostError::Unavailable)?;
                self.stable_lock_parent
                    .sync_all()
                    .map_err(|_| AgentHostError::Unavailable)?;
                validate_agent_host_lock_identity(&self.stable_lock, &self.stable_lock_path)?;
                validate_agent_host_lock_parent_identity(
                    &self.stable_lock_parent,
                    &self.stable_lock_path,
                )?;
                let observed = read_agent_host_lease_state(
                    &mut self.stable_lock,
                    &fresh_binding,
                    &migration_binding,
                )?;
                if observed != AgentHostRootLeaseState::FreshArmed {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                self.state = observed;
                self.arm_write_uncertain = false;
                return self.validate_live();
            }
            _ => return Err(AgentHostError::InvalidScopeBinding),
        }
        let arm = encode_agent_host_lease_arm(&self.binding);
        if let Err(error) = append_agent_host_lease_record(
            &mut self.stable_lock,
            &self.stable_lock_path,
            &self.stable_lock_parent,
            &arm,
            HOST_LEASE_BINDING_LEN,
        ) {
            // Preserve an exact interrupted-Arm state in memory so the same
            // Host can retry after a transient write/sync failure. Arbitrary
            // malformed tails remain fail-closed.
            if let Ok(observed) = read_agent_host_lease_state(
                &mut self.stable_lock,
                &fresh_binding,
                &migration_binding,
            ) {
                self.state = observed;
            }
            return Err(error);
        }
        let observed =
            read_agent_host_lease_state(&mut self.stable_lock, &fresh_binding, &migration_binding)?;
        let expected = AgentHostRootLeaseState::FreshArmed;
        if observed != expected {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        self.state = observed;
        self.arm_write_uncertain = false;
        self.validate_live()
    }

    pub(crate) fn validate_live(&mut self) -> Result<(), AgentHostError> {
        validate_agent_host_lock_identity(&self.stable_lock, &self.stable_lock_path)?;
        validate_agent_host_lock_parent_identity(&self.stable_lock_parent, &self.stable_lock_path)?;
        validate_agent_host_lock_parent_identity(&self.root_parent, &self.root)?;
        validate_agent_host_root_identity(&self.root_directory, &self.root)?;
        validate_agent_host_authority_root_identity(
            &self.authority_directory,
            &self.authority_root,
        )?;
        let fresh_binding =
            encode_agent_host_lease_binding(&self.root, self.scope, HOST_LEASE_BINDING_FRESH)?;
        let migration_binding = encode_agent_host_lease_binding(
            &self.root,
            self.scope,
            HOST_LEASE_BINDING_LEGACY_MIGRATION,
        )?;
        let observed =
            read_agent_host_lease_state(&mut self.stable_lock, &fresh_binding, &migration_binding)?;
        validate_agent_host_lock_identity(&self.stable_lock, &self.stable_lock_path)?;
        validate_agent_host_lock_parent_identity(&self.stable_lock_parent, &self.stable_lock_path)?;
        validate_agent_host_lock_parent_identity(&self.root_parent, &self.root)?;
        validate_agent_host_root_identity(&self.root_directory, &self.root)?;
        validate_agent_host_authority_root_identity(
            &self.authority_directory,
            &self.authority_root,
        )?;
        if observed != self.state {
            let recoverable_arm_progress = self.arm_write_uncertain
                && matches!(
                    (self.state, observed),
                    (
                        AgentHostRootLeaseState::FreshBound,
                        AgentHostRootLeaseState::FreshArmInterrupted
                            | AgentHostRootLeaseState::FreshArmed
                    ) | (
                        AgentHostRootLeaseState::FreshArmInterrupted,
                        AgentHostRootLeaseState::FreshBound | AgentHostRootLeaseState::FreshArmed
                    )
                );
            if !recoverable_arm_progress {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            self.state = observed;
        }
        Ok(())
    }
}

/// One process-local owner of a directory of durable agents.
pub(crate) struct AgentHost {
    root: PathBuf,
    scope: AgentHostScope,
    agents: BTreeMap<AgentId, HostedLocalAgent>,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    genesis: Arc<dyn SystemAgentGenesisProvider>,
    root_pins: RootAnchorPins,
    _directory_lock: File,
    _root_lease: AgentHostRootLease,
}

/// Root driver sealed together with the one pinned signer-independent
/// authority owner. Read-only driver methods are available through `Deref`;
/// there is intentionally no `DerefMut`, so every mutation must cross the
/// wrapper's single owner-held gate.
enum HostedLocalAgent {
    System {
        driver: LocalJournalAgentDriver<FileAgentJournalStore>,
        #[cfg(all(feature = "storage", target_os = "linux"))]
        authority: BoundFileSystemAuthorityLedgerOwner,
    },
    Local {
        driver: LocalJournalAgentDriver<FileAgentJournalStore>,
        intent: LocalGenesisIntent,
    },
}

impl core::ops::Deref for HostedLocalAgent {
    type Target = LocalJournalAgentDriver<FileAgentJournalStore>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::System { driver, .. } | Self::Local { driver, .. } => driver,
        }
    }
}

impl HostedLocalAgent {
    fn with_root_mutation<T>(
        &mut self,
        operation: impl FnOnce(
            &mut LocalJournalAgentDriver<FileAgentJournalStore>,
        ) -> Result<T, AgentHostError>,
    ) -> Result<T, AgentHostError> {
        #[cfg(not(all(feature = "storage", target_os = "linux")))]
        {
            let _ = operation;
            Err(AgentHostError::Unavailable)
        }
        #[cfg(all(feature = "storage", target_os = "linux"))]
        {
            match self {
                Self::System { driver, authority } => authority
                    .with_root_mutation(|| operation(driver))
                    .map_err(map_system_authority_ledger_error)?,
                Self::Local { driver, .. } => operation(driver),
            }
        }
    }

    fn intent(&self) -> Option<&LocalGenesisIntent> {
        match self {
            Self::System { .. } => None,
            Self::Local { intent, .. } => Some(intent),
        }
    }
}

/// Immutable space and exact machine boundary for one Local Agent directory.
///
/// A Local image is not portable between nodes. Binding this at the directory
/// owner prevents a copied image—or a create request for another space—from
/// being admitted merely because a caller-selected trust provider recognizes
/// its authority key. Production construction must derive `node` from the
/// full authenticated Node identity, never a compact routing prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentHostScope {
    pub space: SpaceId,
    pub node: NodeId,
}

impl AgentHostScope {
    pub fn validate(self) -> Result<Self, AgentHostError> {
        if self.space == SpaceId::ZERO || self.node == NodeId::ZERO {
            return Err(AgentHostError::InvalidScope);
        }
        Ok(self)
    }

    fn admits(self, config: &AgentConfig) -> bool {
        config.identity.space == self.space
            && config.identity.profile == super::AgentProfile::Local
            && config.replicas.len() == 1
            && config.replicas[0].node == self.node
    }
}

/// Exact lifecycle operation prepared by the serialized Agent host for an
/// authenticated authority to approve.
///
/// Private construction makes the tuple internally consistent, but does not
/// prove which [`AgentHostControl`] produced it: callers can legitimately open
/// generic hosts with their own trust providers. A production issuer must
/// prepare through its own sealed coordinator path and must never accept this
/// value from an untrusted caller as provenance. Principal, credential,
/// sequence, and validity remain authority-owned inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLifecycleRequest {
    authority: AgentAuthorityBinding,
    space: SpaceId,
    agent: AgentId,
    capability: CapabilityId,
    request: LifecycleRequest,
}

impl PreparedLifecycleRequest {
    fn new(config: &AgentConfig, request: LifecycleRequest) -> Result<Self, AgentHostError> {
        let capability = request
            .required_capability()
            .ok_or(AgentHostError::InvalidRuntime)?;
        Ok(Self {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            capability: CapabilityId::named(capability),
            request,
        })
    }

    pub fn authority(&self) -> &AgentAuthorityBinding {
        &self.authority
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn agent(&self) -> AgentId {
        self.agent
    }

    pub const fn capability(&self) -> CapabilityId {
        self.capability
    }

    pub fn request(&self) -> &LifecycleRequest {
        &self.request
    }

    pub fn operation(&self) -> Hash {
        self.request.commitment()
    }
}

type AgentHostJob = Box<dyn FnOnce(Option<&mut AgentHost>) + Send + 'static>;

enum AgentHostCommand {
    Run {
        job: AgentHostJob,
        activity: AgentHostActivity,
    },
    Wake,
}

struct AgentHostActivity {
    active_requests: Arc<AtomicUsize>,
    admitted_payload_bytes: Arc<AtomicUsize>,
    last_activity: Arc<Mutex<Instant>>,
    payload_bytes: usize,
    admitted: bool,
}

impl AgentHostActivity {
    fn reserve(handle: &AgentHostHandle, payload_bytes: usize) -> Result<Self, AgentHostError> {
        if payload_bytes > handle.payload_capacity_bytes {
            return Err(AgentHostError::Overloaded);
        }
        let mut admitted = handle.admitted_payload_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = admitted.checked_add(payload_bytes) else {
                return Err(AgentHostError::Overloaded);
            };
            if next > handle.payload_capacity_bytes {
                return Err(AgentHostError::Overloaded);
            }
            match handle.admitted_payload_bytes.compare_exchange_weak(
                admitted,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => admitted = current,
            }
        }
        handle.active_requests.fetch_add(1, Ordering::AcqRel);
        Ok(Self {
            active_requests: handle.active_requests.clone(),
            admitted_payload_bytes: handle.admitted_payload_bytes.clone(),
            last_activity: handle.last_activity.clone(),
            payload_bytes,
            admitted: true,
        })
    }

    fn cancel_admission(&mut self) {
        self.admitted = false;
    }
}

impl Drop for AgentHostActivity {
    fn drop(&mut self) {
        // Publish completion before making the active count zero. An idle
        // observer which sees zero with Acquire must therefore also see this
        // timestamp, including when a long request straddles its threshold.
        if self.admitted
            && let Ok(mut activity) = self.last_activity.lock()
        {
            *activity = Instant::now();
        }
        self.admitted_payload_bytes
            .fetch_sub(self.payload_bytes, Ordering::AcqRel);
        self.active_requests.fetch_sub(1, Ordering::Release);
    }
}

/// Cloneable, bounded command handle for one process-local Agent host.
///
/// The underlying [`AgentHost`] is never shared through a mutex. One worker
/// owns it for its complete lifetime and serializes PVM execution with durable
/// image updates. All operations retain their signed receipt parameters and
/// use full [`AgentId`] / [`ActorId`] values; this handle never projects an
/// Agent into the transitional 32-bit service routing namespace.
#[derive(Clone)]
pub(crate) struct AgentHostHandle {
    commands: SyncSender<AgentHostCommand>,
    state: Arc<AtomicU8>,
    active_requests: Arc<AtomicUsize>,
    admitted_payload_bytes: Arc<AtomicUsize>,
    payload_capacity_bytes: usize,
    last_activity: Arc<Mutex<Instant>>,
    scope: AgentHostScope,
}

impl core::fmt::Debug for AgentHostHandle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostHandle")
            .field("scope", &self.scope)
            .field("running", &self.is_running())
            .field(
                "active_requests",
                &self.active_requests.load(Ordering::Acquire),
            )
            .field(
                "admitted_payload_bytes",
                &self.admitted_payload_bytes.load(Ordering::Acquire),
            )
            .field("payload_capacity_bytes", &self.payload_capacity_bytes)
            .finish_non_exhaustive()
    }
}

impl AgentHostHandle {
    /// Whether the worker is still accepting new operations.
    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Acquire) == WORKER_RUNNING
    }

    pub fn scope(&self) -> AgentHostScope {
        self.scope
    }

    /// Time since the last admitted operation completed. An active or queued
    /// operation reports zero so a node's idle policy cannot shut the worker
    /// down underneath durable work.
    pub fn idle_for(&self) -> Duration {
        if self.active_requests.load(Ordering::Acquire) != 0 {
            return Duration::ZERO;
        }
        self.last_activity
            .lock()
            .map(|activity| activity.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    #[cfg(test)]
    pub(crate) fn crash_worker_for_test(&self) -> Result<(), AgentHostError> {
        self.request(0, |_| -> Result<(), AgentHostError> {
            panic!("intentional Agent-host worker crash")
        })
    }

    #[cfg(test)]
    pub(crate) fn block_worker_for_test(
        &self,
        active: SyncSender<()>,
        release: Receiver<()>,
    ) -> Result<(), AgentHostError> {
        self.request(0, move |_| {
            active.send(()).map_err(|_| AgentHostError::Unavailable)?;
            release.recv().map_err(|_| AgentHostError::Unavailable)?;
            Ok(())
        })
    }

    #[cfg(test)]
    fn admitted_payload_bytes_for_test(&self) -> usize {
        self.admitted_payload_bytes.load(Ordering::Acquire)
    }

    pub fn identities(&self) -> Result<Vec<AgentIdentity>, AgentHostError> {
        self.request(0, |host| host.identities())
    }

    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.request(0, move |host| host.identity(agent))
    }

    pub fn revision(&self, agent: AgentId) -> Result<Option<u64>, AgentHostError> {
        self.request(0, move |host| Ok(host.revision(agent)))
    }

    pub fn prepare_create(
        &self,
        config: AgentConfig,
        runtime_package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        validate_package_shape_before_reservation(&runtime_package)?;
        let payload_bytes = payload_sum([
            agent_config_heap_payload_bytes(&config),
            package_heap_payload_bytes(&runtime_package),
        ]);
        self.request(payload_bytes, move |host| {
            host.prepare_create(&config, &runtime_package)
        })
    }

    pub fn prepare_actor_install(
        &self,
        agent: AgentId,
        installation_id: InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_install_identity(installation_id, registry_reservation)?;
        validate_actor_name_and_parent(&name, parent)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            name.capacity(),
            installation_data.as_ref().map_or(0, Vec::capacity),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.prepare_actor_install(
                agent,
                installation_id,
                registry_reservation,
                name,
                parent,
                installation_data,
                &package,
            )
        })
    }

    pub fn prepare_actor_upgrade(
        &self,
        agent: AgentId,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor_and_deployment(actor, from_deployment)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = package_heap_payload_bytes(&package);
        self.request(payload_bytes, move |host| {
            host.prepare_actor_upgrade(agent, actor, from_deployment, &package)
        })
    }

    pub fn prepare_actor_suspend(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor(actor)?;
        self.request(0, move |host| host.prepare_actor_suspend(agent, actor))
    }

    pub fn prepare_actor_resume(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor(actor)?;
        self.request(0, move |host| host.prepare_actor_resume(agent, actor))
    }

    pub fn prepare_actor_remove(
        &self,
        agent: AgentId,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        validate_actor_and_deployment(actor, expected_deployment)?;
        self.request(0, move |host| {
            host.prepare_actor_remove(agent, actor, expected_deployment)
        })
    }

    pub fn prepare_runtime_upgrade(
        &self,
        agent: AgentId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if from_deployment == DeploymentId::ZERO {
            return Err(invalid_lifecycle_request());
        }
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = package_heap_payload_bytes(&package);
        self.request(payload_bytes, move |host| {
            host.prepare_runtime_upgrade(agent, from_deployment, &package)
        })
    }

    pub fn create(
        &self,
        config: AgentConfig,
        runtime_package: Package,
        authority: AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        validate_agent_receipt_shape(&authority)?;
        validate_package_shape_before_reservation(&runtime_package)?;
        let payload_bytes = payload_sum([
            agent_config_heap_payload_bytes(&config),
            package_heap_payload_bytes(&runtime_package),
            agent_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.create(config, runtime_package, &authority)
        })
    }

    pub fn inspect(
        &self,
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, AgentHostError> {
        if limit == 0 || limit > super::standard::MAX_DIRECTORY_PAGE {
            return Err(invalid_lifecycle_request());
        }
        self.request(0, move |host| host.inspect(agent, after, limit))
    }

    pub fn install_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        installation_id: InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: Package,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_install_identity(installation_id, registry_reservation)?;
        validate_actor_name_and_parent(&name, parent)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            name.capacity(),
            installation_data.as_ref().map_or(0, Vec::capacity),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.install_actor(
                agent,
                &authority,
                installation_id,
                registry_reservation,
                name,
                parent,
                installation_data,
                &package,
            )
        })
    }

    pub fn upgrade_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor_and_deployment(actor, from_deployment)?;
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.upgrade_actor(agent, &authority, actor, from_deployment, &package)
        })
    }

    pub fn suspend_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor(actor)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.suspend_actor(agent, &authority, actor)
        })
    }

    pub fn resume_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor(actor)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.resume_actor(agent, &authority, actor)
        })
    }

    pub fn remove_actor(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        validate_actor_and_deployment(actor, expected_deployment)?;
        let payload_bytes = agent_receipt_heap_payload_bytes(&authority);
        self.request(payload_bytes, move |host| {
            host.remove_actor(agent, &authority, actor, expected_deployment)
        })
    }

    pub fn upgrade_runtime(
        &self,
        agent: AgentId,
        authority: AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        validate_agent_receipt_shape(&authority)?;
        if from_deployment == DeploymentId::ZERO {
            return Err(invalid_lifecycle_request());
        }
        validate_package_shape_before_reservation(&package)?;
        let payload_bytes = payload_sum([
            agent_receipt_heap_payload_bytes(&authority),
            package_heap_payload_bytes(&package),
        ]);
        self.request(payload_bytes, move |host| {
            host.upgrade_runtime(agent, &authority, from_deployment, &package)
        })
    }

    pub fn invoke(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        validate_invocation_receipt_shape(&authority)?;
        validate_invocation_shape_before_reservation(&invocation)?;
        let payload_bytes = payload_sum([
            invocation_heap_payload_bytes(&invocation),
            invocation_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.invoke(agent, invocation, &authority)
        })
    }

    pub fn acknowledge_invocation(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        validate_invocation_receipt_shape(&authority)?;
        validate_invocation_shape_before_reservation(&invocation)?;
        let payload_bytes = payload_sum([
            invocation_heap_payload_bytes(&invocation),
            invocation_receipt_heap_payload_bytes(&authority),
        ]);
        self.request(payload_bytes, move |host| {
            host.acknowledge_invocation(agent, invocation, &authority)
        })
    }

    fn request<T, F>(&self, heap_payload_bytes: usize, operation: F) -> Result<T, AgentHostError>
    where
        T: Send + 'static,
        F: FnOnce(&mut AgentHost) -> Result<T, AgentHostError> + Send + 'static,
    {
        match self.state.load(Ordering::Acquire) {
            WORKER_RUNNING => {}
            WORKER_SHUTTING_DOWN => return Err(AgentHostError::ShuttingDown),
            _ => return Err(AgentHostError::WorkerStopped),
        }
        let (reply, result) = mpsc::sync_channel(1);
        let payload_bytes = heap_payload_bytes
            .checked_add(core::mem::size_of::<AgentHostCommand>())
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<F>()))
            .and_then(|bytes| {
                bytes.checked_add(core::mem::size_of::<SyncSender<Result<T, AgentHostError>>>())
            })
            .unwrap_or(usize::MAX);
        let activity = AgentHostActivity::reserve(self, payload_bytes)?;
        let command = AgentHostCommand::Run {
            job: Box::new(move |host| {
                let response = match host {
                    Some(host) => operation(host),
                    None => Err(AgentHostError::ShuttingDown),
                };
                let _ = reply.send(response);
            }),
            activity,
        };
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(mut command)) => {
                cancel_agent_host_admission(&mut command);
                return Err(AgentHostError::Overloaded);
            }
            Err(TrySendError::Disconnected(mut command)) => {
                cancel_agent_host_admission(&mut command);
                return Err(AgentHostError::WorkerStopped);
            }
        }
        result.recv().unwrap_or(Err(AgentHostError::WorkerStopped))
    }
}

fn payload_sum<const N: usize>(parts: [usize; N]) -> usize {
    parts.into_iter().fold(0, usize::saturating_add)
}

fn vector_allocation_bytes<T>(capacity: usize) -> usize {
    capacity.saturating_mul(core::mem::size_of::<T>())
}

fn authority_binding_heap_payload_bytes(binding: &AgentAuthorityBinding) -> usize {
    binding.public_key.capacity()
}

fn agent_config_heap_payload_bytes(config: &AgentConfig) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&config.authority),
        vector_allocation_bytes::<super::AgentReplica>(config.replicas.capacity()),
    ])
}

fn package_heap_payload_bytes(package: &Package) -> usize {
    let task_program_bytes = package
        .task_dependencies
        .iter()
        .fold(0usize, |total, dependency| {
            total.saturating_add(dependency.pvm.capacity())
        });
    let diagnostic_bytes = package.diagnostics.as_ref().map_or(0, |diagnostics| {
        payload_sum([
            diagnostics.elf.as_ref().map_or(0, Vec::capacity),
            diagnostics.source_map.as_ref().map_or(0, Vec::capacity),
        ])
    });
    payload_sum([
        package.manifest.name.capacity(),
        package.pvm.capacity(),
        package.generated_interfaces.capacity(),
        package.role_policies.capacity(),
        package.schemas.capacity(),
        package.agent_schema.capacity(),
        vector_allocation_bytes::<crate::service::PackageTaskDependency>(
            package.task_dependencies.capacity(),
        ),
        task_program_bytes,
        diagnostic_bytes,
        package.deployment_signature.public_key.capacity(),
        package.deployment_signature.signature.capacity(),
    ])
}

fn agent_receipt_heap_payload_bytes(receipt: &AgentAuthorityReceipt) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&receipt.claim.authority),
        receipt.signature.capacity(),
    ])
}

fn invocation_heap_payload_bytes(invocation: &ActorInvocation) -> usize {
    let blob_bytes = invocation.availability.iter().fold(0usize, |total, blob| {
        total.saturating_add(blob.bytes.capacity())
    });
    payload_sum([
        invocation.message.capacity(),
        vector_allocation_bytes::<super::execution::RuntimeBlob>(
            invocation.availability.capacity(),
        ),
        blob_bytes,
    ])
}

fn invocation_receipt_heap_payload_bytes(receipt: &ActorInvocationReceipt) -> usize {
    payload_sum([
        authority_binding_heap_payload_bytes(&receipt.claim.authority),
        receipt.signature.capacity(),
    ])
}

fn invalid_package_shape(error: PackageError) -> AgentHostError {
    AgentHostError::Package(error)
}

/// Reject unbounded package shapes before inspecting nested allocations.
///
/// Semantic package validation, including PVM parsing, artifact hashing,
/// canonical encoding, and signature checks, belongs to the serialized
/// driver operation after payload admission.
fn validate_package_shape_before_reservation(package: &Package) -> Result<(), AgentHostError> {
    if package.task_dependencies.len() > crate::service::MAX_PACKAGE_TASK_DEPENDENCIES {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    if package.manifest.name.is_empty()
        || package.manifest.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
    {
        return Err(invalid_package_shape(PackageError::EmptyName));
    }
    if package.pvm.is_empty() {
        return Err(invalid_package_shape(PackageError::EmptyProgram));
    }
    if package.pvm.len() > MAX_EXECUTION_PROGRAM_BYTES
        || package.generated_interfaces.len() > MAX_PACKAGE_INTERFACES_BYTES
        || package.schemas.len() > MAX_PACKAGE_SCHEMAS_BYTES
    {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    if package.role_policies.len() > MAX_EXECUTION_POLICY_BYTES
        || package.agent_schema.len() > super::schema::MAX_ENCODED_BYTES
    {
        return Err(invalid_package_shape(PackageError::InvalidActorArtifacts));
    }

    // The dependency count is bounded above before either traversal.
    let task_bytes = package
        .task_dependencies
        .iter()
        .try_fold(0usize, |total, dependency| {
            total.checked_add(dependency.pvm.len())
        });
    if task_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_TASK_BYTES)
        || package
            .task_dependencies
            .iter()
            .any(|dependency| dependency.pvm.len() > MAX_EXECUTION_PROGRAM_BYTES)
    {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }

    let diagnostic_bytes = package.diagnostics.as_ref().map_or(Some(0), |diagnostics| {
        diagnostics
            .elf
            .as_ref()
            .map_or(0, |bytes| bytes.len())
            .checked_add(
                diagnostics
                    .source_map
                    .as_ref()
                    .map_or(0, |bytes| bytes.len()),
            )
    });
    if diagnostic_bytes.is_none_or(|bytes| bytes > MAX_PACKAGE_DIAGNOSTICS_BYTES) {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }

    // This is only a necessary lower bound on canonical size. The driver
    // performs the exact encoding-size check after admission.
    let dynamic_bytes = [
        package.manifest.name.len(),
        package.pvm.len(),
        package.generated_interfaces.len(),
        package.role_policies.len(),
        package.schemas.len(),
        package.agent_schema.len(),
        task_bytes.unwrap_or(usize::MAX),
        diagnostic_bytes.unwrap_or(usize::MAX),
        package.deployment_signature.public_key.len(),
        package.deployment_signature.signature.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add);
    if dynamic_bytes.is_none_or(|bytes| bytes > MAX_ENCODED_PACKAGE_BYTES) {
        return Err(invalid_package_shape(PackageError::ArtifactsTooLarge));
    }
    Ok(())
}

fn invalid_invocation_shape() -> AgentHostError {
    AgentHostError::Execution(ActorExecutionError::InvalidInput)
}

/// Apply only fixed-cost and bounded length checks before payload admission.
/// Content hashes, ordering, and complete invocation validation remain owned
/// by the serialized driver operation.
fn validate_invocation_shape_before_reservation(
    invocation: &ActorInvocation,
) -> Result<(), AgentHostError> {
    if invocation.invocation == InvocationId::ZERO
        || invocation.actor == ActorId::ZERO
        || invocation.deployment == DeploymentId::ZERO
        || invocation.program == ProgramId::ZERO
        || invocation.gas == 0
        || invocation.gas > super::execution::MAX_INVOCATION_GAS_CEILING
        || !invocation.auth.validate()
        || invocation.message.is_empty()
        || invocation.message.len() > MAX_EXECUTION_MESSAGE_BYTES
        || invocation.availability.len() > MAX_EXECUTION_BLOBS
    {
        return Err(invalid_invocation_shape());
    }

    // The availability count is bounded above before this traversal. Blob
    // reference hashing and canonical ordering are intentionally deferred.
    let availability_bytes = invocation
        .availability
        .iter()
        .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()));
    if invocation
        .availability
        .iter()
        .any(|blob| blob.bytes.len() > MAX_EXECUTION_AVAILABILITY_BYTES)
        || availability_bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_AVAILABILITY_BYTES)
    {
        return Err(invalid_invocation_shape());
    }
    Ok(())
}

fn invalid_lifecycle_request() -> AgentHostError {
    AgentHostError::Lifecycle(super::LifecycleError::InvalidRequest)
}

fn validate_actor(actor: ActorId) -> Result<(), AgentHostError> {
    if actor == ActorId::ZERO {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_install_identity(
    installation_id: InstallationId,
    registry_reservation: Hash,
) -> Result<(), AgentHostError> {
    if installation_id == InstallationId::ZERO || registry_reservation == Hash::ZERO {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_actor_and_deployment(
    actor: ActorId,
    deployment: DeploymentId,
) -> Result<(), AgentHostError> {
    validate_actor(actor)?;
    if deployment == DeploymentId::ZERO {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_actor_name_and_parent(
    name: &str,
    parent: Option<ActorId>,
) -> Result<(), AgentHostError> {
    if name.is_empty()
        || name.len() > crate::service::MAX_ACTOR_NAME_BYTES
        || parent == Some(ActorId::ZERO)
    {
        return Err(invalid_lifecycle_request());
    }
    Ok(())
}

fn validate_agent_receipt_shape(receipt: &AgentAuthorityReceipt) -> Result<(), AgentHostError> {
    if receipt.signature.len() != super::authority::ED25519_SIGNATURE_BYTES
        || !receipt.claim.authority.validate()
    {
        return Err(AgentHostError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        ));
    }
    Ok(())
}

fn validate_invocation_receipt_shape(
    receipt: &ActorInvocationReceipt,
) -> Result<(), AgentHostError> {
    if receipt.signature.len() != super::authority::ED25519_SIGNATURE_BYTES
        || !receipt.claim.authority.validate()
    {
        return Err(AgentHostError::Authority(
            super::authority::AuthorityError::InvalidSignature,
        ));
    }
    Ok(())
}

fn cancel_agent_host_admission(command: &mut AgentHostCommand) {
    if let AgentHostCommand::Run { activity, .. } = command {
        activity.cancel_admission();
    }
}

/// Owning lifecycle guard for the serialized Local Agent worker.
///
/// Dropping this value requests terminal shutdown and joins the worker. A
/// restart deliberately creates a new control with [`Self::open`]; cloned old
/// internal senders remain stopped and cannot race commands into the reopened
/// image. The raw host and cloneable sender are deliberately not public API:
///
/// ```compile_fail
/// use vos::agent::host::AgentHost;
/// ```
///
/// ```compile_fail
/// use vos::agent::host::AgentHostHandle;
/// ```
///
/// Nor can callers extract the internal sender from this owner:
///
/// ```compile_fail
/// fn extract(control: &vos::agent::host::AgentHostControl) {
///     let _ = control.handle();
/// }
/// ```
pub struct AgentHostControl {
    handle: AgentHostHandle,
    worker: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for AgentHostControl {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AgentHostControl")
            .field("scope", &self.handle.scope())
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl AgentHostControl {
    pub fn open(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, AgentHostError> {
        Self::open_with_queue_capacity(
            lease,
            trust,
            merge,
            genesis,
            root_pins,
            DEFAULT_AGENT_HOST_QUEUE_CAPACITY,
        )
    }

    pub fn open_with_queue_capacity(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
        queue_capacity: usize,
    ) -> Result<Self, AgentHostError> {
        if queue_capacity == 0 {
            return Err(AgentHostError::InvalidQueueCapacity);
        }
        let scope = lease.scope();
        let host = AgentHost::open(lease, trust, merge, genesis, root_pins)?;
        let (commands, receiver) = mpsc::sync_channel(queue_capacity);
        let state = Arc::new(AtomicU8::new(WORKER_RUNNING));
        let active_requests = Arc::new(AtomicUsize::new(0));
        let admitted_payload_bytes = Arc::new(AtomicUsize::new(0));
        let last_activity = Arc::new(Mutex::new(Instant::now()));
        let worker_state = state.clone();
        let worker = thread::Builder::new()
            .name("vos-local-agent-host".into())
            .spawn(move || agent_host_worker(host, receiver, worker_state))
            .map_err(|_| AgentHostError::Unavailable)?;
        Ok(Self {
            handle: AgentHostHandle {
                commands,
                state,
                active_requests,
                admitted_payload_bytes,
                payload_capacity_bytes: DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES,
                last_activity,
                scope,
            },
            worker: Some(worker),
        })
    }

    #[cfg(test)]
    pub(crate) fn handle_for_test(&self) -> AgentHostHandle {
        self.handle.clone()
    }

    /// Time since the last admitted operation completed. Active or queued
    /// work reports zero so node idle policy cannot stop durable work.
    pub fn idle_for(&self) -> Duration {
        self.handle.idle_for()
    }

    /// List the Local Agents currently owned by this host.
    pub fn identities(&self) -> Result<Vec<AgentIdentity>, AgentHostError> {
        self.handle.identities()
    }

    /// Read one Local Agent identity without exposing the cloneable command
    /// sender which owns the worker protocol.
    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.handle.identity(agent)
    }

    /// Invoke one full-ID actor and return only its settled durable outcome.
    pub fn invoke(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        self.handle.invoke(agent, invocation, authority)
    }

    /// Durably acknowledge one full-ID actor invocation.
    pub fn acknowledge_invocation(
        &self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        self.handle
            .acknowledge_invocation(agent, invocation, authority)
    }

    /// Stop admitting operations and wake an idle worker. The operation which
    /// already owns the host, if any, is allowed to finish; queued operations
    /// are answered with [`AgentHostError::ShuttingDown`].
    pub fn request_shutdown(&self) {
        if self
            .handle
            .state
            .compare_exchange(
                WORKER_RUNNING,
                WORKER_SHUTTING_DOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // A full queue already guarantees that the worker will wake. The
            // state transition, not this best-effort message, is authoritative.
            let _ = self.handle.commands.try_send(AgentHostCommand::Wake);
        }
    }

    pub fn is_running(&self) -> bool {
        self.handle.is_running()
    }

    pub fn shutdown(mut self) -> Result<(), AgentHostError> {
        self.request_shutdown();
        self.join_worker()
    }

    fn join_worker(&mut self) -> Result<(), AgentHostError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.join().map_err(|_| AgentHostError::WorkerPanicked)
    }
}

impl Drop for AgentHostControl {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.join_worker();
    }
}

struct WorkerStateGuard(Arc<AtomicU8>);

impl Drop for WorkerStateGuard {
    fn drop(&mut self) {
        self.0.store(WORKER_STOPPED, Ordering::Release);
    }
}

fn agent_host_worker(
    mut host: AgentHost,
    receiver: Receiver<AgentHostCommand>,
    state: Arc<AtomicU8>,
) {
    let _stopped = WorkerStateGuard(state.clone());
    loop {
        if state.load(Ordering::Acquire) != WORKER_RUNNING {
            reject_queued_agent_host_jobs(&receiver);
            return;
        }
        match receiver.recv() {
            Ok(AgentHostCommand::Run { job, activity }) => {
                if state.load(Ordering::Acquire) == WORKER_RUNNING {
                    job(Some(&mut host));
                } else {
                    job(None);
                }
                drop(activity);
            }
            Ok(AgentHostCommand::Wake) => {}
            Err(_) => return,
        }
    }
}

fn reject_queued_agent_host_jobs(receiver: &Receiver<AgentHostCommand>) {
    loop {
        match receiver.try_recv() {
            Ok(AgentHostCommand::Run { job, activity }) => {
                job(None);
                drop(activity);
            }
            Ok(AgentHostCommand::Wake) => {}
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

impl AgentHost {
    #[cfg(not(all(feature = "storage", target_os = "linux")))]
    pub fn open(
        lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, AgentHostError> {
        let _ = (lease, trust, merge, genesis, root_pins);
        Err(AgentHostError::Unavailable)
    }

    /// Open the one independently pinned Local system Agent in `root`.
    ///
    /// Startup probes the configured provider locator even when no journal is
    /// present. An archived provider-first Create is therefore completed after
    /// a crash before the first destination write. Conversely, generation
    /// residue without its exact archive fails closed and is never re-minted.
    #[cfg(all(feature = "storage", target_os = "linux"))]
    pub fn open(
        mut lease: AgentHostRootLease,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        genesis: Arc<dyn SystemAgentGenesisProvider>,
        root_pins: RootAnchorPins,
    ) -> Result<Self, AgentHostError> {
        let root = lease.root().to_path_buf();
        let scope = lease.scope();
        validate_host_root_capabilities(scope, merge.as_ref(), &root_pins)?;
        lease.validate_live()?;
        let system_agent = root_pins.record().system_agent();
        let mut generations = BTreeMap::<AgentId, LocalGenerationFiles>::new();
        let mut has_host_lock = false;
        for entry in fs::read_dir(agent_host_directory_capability_path(&lease.root_directory))
            .map_err(|_| AgentHostError::Unavailable)?
        {
            let entry = entry.map_err(|_| AgentHostError::Unavailable)?;
            let file_type = entry.file_type().map_err(|_| AgentHostError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AgentHostError::InvalidJournalName)?;
            if name == HOST_LOCK_FILE {
                if has_host_lock || !file_type.is_file() || file_type.is_symlink() {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                has_host_lock = true;
                continue;
            }
            if matches!(name.as_str(), HOST_SCOPE_FILE | HOST_SCOPE_TEMP_FILE) {
                continue;
            }
            let folded_name = name.to_ascii_lowercase();
            if matches!(
                folded_name.as_str(),
                HOST_LOCK_FILE | HOST_SCOPE_FILE | HOST_SCOPE_TEMP_FILE
            ) {
                return Err(AgentHostError::InvalidJournalName);
            }
            if folded_name.ends_with(LEGACY_IMAGE_SUFFIX) {
                return Err(AgentHostError::LegacyGeneration);
            }
            if folded_name.ends_with(SYSTEM_AUTHORITY_LEDGER_STAGE_SUFFIX) {
                // Clean break: authority state is anchored beside the outer
                // lease.  An in-root sidecar is an obsolete or spliced
                // generation and is never migrated implicitly.
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if folded_name.ends_with(SYSTEM_AUTHORITY_LEDGER_SUFFIX) {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if folded_name.ends_with(JOURNAL_LOCK_SUFFIX) {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if !folded_name.ends_with(JOURNAL_SUFFIX) {
                return Err(AgentHostError::InvalidJournalName);
            }
            if !name.ends_with(JOURNAL_SUFFIX) {
                return Err(AgentHostError::InvalidJournalName);
            }
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(AgentHostError::InvalidJournalName);
            }
            let encoded = &name[..name.len() - JOURNAL_SUFFIX.len()];
            let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidJournalName)?;
            if generations.entry(agent).or_default().journal {
                return Err(AgentHostError::DuplicateAgent);
            }
            generations.get_mut(&agent).expect("inserted").journal = true;
        }
        lease.validate_live()?;
        let authority_root = lease.authority_root()?.to_path_buf();
        let ledger_name = format!(
            "{}{}",
            encode_agent_id(system_agent),
            SYSTEM_AUTHORITY_LEDGER_SUFFIX
        );
        let ledger_stage_name = format!(
            "{}{}",
            encode_agent_id(system_agent),
            SYSTEM_AUTHORITY_LEDGER_STAGE_SUFFIX
        );
        for entry in fs::read_dir(agent_host_directory_capability_path(
            &lease.authority_directory,
        ))
        .map_err(|_| AgentHostError::Unavailable)?
        {
            let entry = entry.map_err(|_| AgentHostError::Unavailable)?;
            let file_type = entry.file_type().map_err(|_| AgentHostError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| AgentHostError::InvalidJournalName)?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if name == ledger_name || name == ledger_stage_name {
                continue;
            }
            let folded = name.to_ascii_lowercase();
            let suffixes = [
                LOCAL_GENESIS_INTENT_STAGE_SUFFIX,
                LOCAL_GENESIS_EXPOSURE_STAGE_SUFFIX,
                LOCAL_GENESIS_INTENT_SUFFIX,
                LOCAL_GENESIS_EXPOSURE_SUFFIX,
                JOURNAL_LOCK_SUFFIX,
            ];
            let suffix = suffixes
                .iter()
                .find(|suffix| folded.ends_with(**suffix))
                .copied()
                .ok_or(AgentHostError::InvalidScopeBinding)?;
            if !name.ends_with(suffix) {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            let encoded = &name[..name.len() - suffix.len()];
            let agent = decode_agent_id(encoded).ok_or(AgentHostError::InvalidScopeBinding)?;
            let files = generations.entry(agent).or_default();
            let flag = match suffix {
                JOURNAL_LOCK_SUFFIX => &mut files.lock,
                LOCAL_GENESIS_INTENT_SUFFIX => &mut files.intent,
                LOCAL_GENESIS_INTENT_STAGE_SUFFIX => &mut files.intent_stage,
                LOCAL_GENESIS_EXPOSURE_SUFFIX => &mut files.exposed,
                LOCAL_GENESIS_EXPOSURE_STAGE_SUFFIX => &mut files.exposed_stage,
                _ => unreachable!("complete Local generation suffix set"),
            };
            if *flag {
                return Err(AgentHostError::DuplicateAgent);
            }
            *flag = true;
        }
        lease.validate_live()?;
        let system_files = generations.get(&system_agent).copied().unwrap_or_default();
        if system_files.intent
            || system_files.intent_stage
            || system_files.exposed
            || system_files.exposed_stage
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let has_journal = system_files.journal;
        let has_lock = system_files.lock;
        let has_ledger =
            generation_regular_file_exists_at(&lease.authority_directory, &ledger_name)?;
        let has_ledger_stage =
            generation_regular_file_exists_at(&lease.authority_directory, &ledger_stage_name)?;
        if has_journal && (!has_lock || !has_ledger)
            || has_ledger && !has_lock
            || has_lock && !has_journal && !has_ledger && !has_ledger_stage
            || has_journal && has_ledger_stage
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        for (agent, files) in &generations {
            if *agent == system_agent {
                continue;
            }
            if (!files.intent && !files.intent_stage)
                || (files.lock && !files.intent)
                || (files.journal && !files.lock)
                || ((files.exposed || files.exposed_stage)
                    && (!files.journal || !files.lock || !files.intent))
            {
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
        let system_generation_residue = has_journal || has_lock || has_ledger || has_ledger_stage;
        let complete_system_generation = has_journal && has_lock && has_ledger && !has_ledger_stage;
        if lease.rejects_generation_state(system_generation_residue, complete_system_generation) {
            // An armed lease with no recognized residue represents the
            // unavoidable crash window after the permanent arm and before
            // the first inner stage. It is deliberately fail-closed. Partial
            // recognized states continue into the inner slot recovery matrix.
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let generation_residue = system_generation_residue
            || generations.iter().any(|(agent, files)| {
                *agent != system_agent && *files != LocalGenerationFiles::default()
            });
        if (!lease.may_initialize_host_boundary() || generation_residue) && !has_host_lock {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        #[cfg(not(all(feature = "storage", target_os = "linux")))]
        if generation_residue {
            return Err(AgentHostError::Unavailable);
        }
        let directory_lock = lock_agent_host_directory(
            &root,
            &lease.root_directory,
            lease.may_initialize_host_boundary() && !generation_residue && !has_host_lock,
        )?;
        lease.validate_live()?;
        let scope_state = read_agent_host_scope(
            &root,
            &lease.root_directory,
            scope,
            lease.may_initialize_host_boundary() && !generation_residue,
        )?;
        if scope_state.scope().is_some_and(|bound| bound != scope) {
            return Err(AgentHostError::ScopeMismatch);
        }
        let cleanup_scope_stage = matches!(scope_state, AgentHostScopeState::BoundWithStage(_));
        match scope_state {
            AgentHostScopeState::Bound(_) | AgentHostScopeState::BoundWithStage(_) => {}
            AgentHostScopeState::Staged(_) if !generation_residue => {
                publish_agent_host_scope(&root, &lease.root_directory)?;
            }
            AgentHostScopeState::Absent if !generation_residue => {
                write_agent_host_scope(&root, &lease.root_directory, scope)?;
            }
            AgentHostScopeState::Staged(_) | AgentHostScopeState::Absent => {
                // Never infer or overwrite the scope of a journal or stable
                // lock left by a pre-sidecar generation.
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
        lease.validate_live()?;

        let mut agents = BTreeMap::new();
        let locator = SystemAgentGenesisLocator {
            space: scope.space,
            agent: system_agent,
            node: scope.node,
        };
        match genesis.reproduce(locator) {
            Ok(provision) => {
                let (sealed, catalog, _, _) = prepare_archived_genesis(
                    trust.clone(),
                    merge.clone(),
                    genesis.as_ref(),
                    &root_pins,
                    provision,
                )?;
                let (journal_parent, authority_parent) = lease.clone_generation_parents()?;
                let driver = open_archived_system_agent(
                    &root,
                    &authority_root,
                    &journal_parent,
                    &authority_parent,
                    &mut lease,
                    scope,
                    sealed,
                    &catalog,
                    trust.clone(),
                    merge.clone(),
                )?;
                let identity = driver.identity().map_err(map_local_driver_error)?;
                if identity.agent != system_agent || identity.space != scope.space {
                    return Err(AgentHostError::IdentityMismatch);
                }
                lease.validate_live()?;
                agents.insert(system_agent, driver);
            }
            Err(SystemAgentGenesisProviderError::NotConfigured) if !system_generation_residue => {}
            Err(error) => return Err(AgentHostError::Provider(error)),
        }
        let ordinary_agents = generations
            .keys()
            .copied()
            .filter(|agent| *agent != system_agent)
            .collect::<Vec<_>>();
        if !ordinary_agents.is_empty() && !agents.contains_key(&system_agent) {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        for agent in ordinary_agents {
            let files = generations
                .get(&agent)
                .copied()
                .ok_or(AgentHostError::InvalidScopeBinding)?;
            let intent = recover_local_genesis_intent(&lease.authority_directory, agent)?;
            validate_local_intent_target(scope, system_agent, agent, &intent, trust.as_ref())?;
            let catalog = intent.catalog();
            let sealed =
                prepare_local_intent_genesis(&intent, &catalog, trust.clone(), merge.clone())?;
            let exposed = recover_local_exposure_marker(
                &lease.authority_directory,
                agent,
                intent.id(),
                files.exposed,
                files.exposed_stage,
            )?;
            let (journal_parent, authority_parent) = lease.clone_generation_parents()?;
            let driver = open_archived_local_agent(
                &root,
                &authority_root,
                &journal_parent,
                &authority_parent,
                scope,
                sealed,
                intent.id(),
                &catalog,
                exposed,
                trust.clone(),
                merge.clone(),
            )?;
            let identity = driver.identity().map_err(map_local_driver_error)?;
            if identity.agent != agent || identity.space != scope.space {
                return Err(AgentHostError::IdentityMismatch);
            }
            if !exposed {
                publish_local_exposure_marker(&lease.authority_directory, agent, intent.id())?;
            }
            lease.validate_live()?;
            if agents
                .insert(agent, HostedLocalAgent::Local { driver, intent })
                .is_some()
            {
                return Err(AgentHostError::DuplicateAgent);
            }
        }
        lease.validate_live()?;
        if cleanup_scope_stage {
            cleanup_agent_host_scope_stage(&root, &lease.root_directory)?;
            lease.validate_live()?;
        }
        Ok(Self {
            root,
            scope,
            agents,
            trust,
            merge,
            genesis,
            root_pins,
            _directory_lock: directory_lock,
            _root_lease: lease,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scope(&self) -> AgentHostScope {
        self.scope
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Immutable Agent identities in canonical ID order.
    pub fn identities(&self) -> Result<Vec<AgentIdentity>, AgentHostError> {
        self.agents
            .values()
            .map(|driver| driver.identity().map_err(map_local_driver_error))
            .collect()
    }

    pub fn identity(&self, agent: AgentId) -> Result<Option<AgentIdentity>, AgentHostError> {
        self.agents
            .get(&agent)
            .map(|driver| driver.identity().map_err(map_local_driver_error))
            .transpose()
    }

    /// Validate a Local creation target and runtime package without writing
    /// the image or consuming an authority sequence.
    pub fn prepare_create(
        &self,
        config: &AgentConfig,
        runtime_package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        if !self.scope.admits(config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        if let Some(driver) = self.agents.get(&config.identity.agent)
            && driver.config().map_err(map_local_driver_error)? != *config
        {
            return Err(AgentHostError::DuplicateAgent);
        }
        if config.identity.agent == self.system_agent() {
            validate_system_create_target(
                self.scope,
                self.system_agent(),
                config,
                runtime_package,
                &self.root_pins,
                self.trust.as_ref(),
            )?;
        } else {
            if !self.agents.contains_key(&self.system_agent()) {
                return Err(AgentHostError::InvalidAuthority);
            }
            validate_local_create_target(
                self.scope,
                self.system_agent(),
                config,
                runtime_package,
                self.trust.as_ref(),
            )?;
        }
        let request = LifecycleRequest::Create(config.clone());
        PreparedLifecycleRequest::new(config, request)
    }

    pub fn prepare_actor_install(
        &self,
        agent: AgentId,
        installation_id: InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_install_operation(
                installation_id,
                registry_reservation,
                name,
                parent,
                installation_data,
                package,
            )
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    pub fn prepare_actor_upgrade(
        &self,
        agent: AgentId,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_upgrade_operation(actor, from_deployment, package)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    pub fn prepare_actor_suspend(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_suspend_operation(actor)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    pub fn prepare_actor_resume(
        &self,
        agent: AgentId,
        actor: ActorId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_resume_operation(actor)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    pub fn prepare_actor_remove(
        &self,
        agent: AgentId,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .actor_remove_operation(actor, expected_deployment)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    pub fn prepare_runtime_upgrade(
        &self,
        agent: AgentId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<PreparedLifecycleRequest, AgentHostError> {
        let driver = self
            .agents
            .get(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        let operation = driver
            .runtime_upgrade_operation(from_deployment, package)
            .map_err(map_local_driver_error)?;
        PreparedLifecycleRequest::new(
            &driver.config().map_err(map_local_driver_error)?,
            operation.request().clone(),
        )
    }

    /// Create a durable empty agent with its explicitly selected runtime.
    #[cfg(not(all(feature = "storage", target_os = "linux")))]
    pub fn create(
        &mut self,
        config: AgentConfig,
        runtime_package: Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        let _ = (config, runtime_package, authority);
        Err(AgentHostError::Unavailable)
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    pub fn create(
        &mut self,
        config: AgentConfig,
        runtime_package: Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        self._root_lease.validate_live()?;
        if !self.scope.admits(&config) {
            return Err(AgentHostError::ScopeMismatch);
        }
        if config.identity.agent != self.system_agent() {
            return self.create_ordinary_local(config, runtime_package, authority);
        }
        let agent = config.identity.agent;
        validate_system_create_shape(self.scope, agent, &config, &runtime_package)?;
        let locator = self.genesis_locator();
        let (sealed, catalog, archived_config, archived_receipt) =
            match self.genesis.reproduce(locator) {
                Ok(provision) => prepare_archived_genesis(
                    self.trust.clone(),
                    self.merge.clone(),
                    self.genesis.as_ref(),
                    &self.root_pins,
                    provision,
                )?,
                Err(SystemAgentGenesisProviderError::NotConfigured) => {
                    self._root_lease.validate_live()?;
                    if generation_path_exists_at(
                        &self._root_lease.root_directory,
                        self.journal_path(agent)
                            .file_name()
                            .ok_or(AgentHostError::InvalidJournalName)?,
                    )? || generation_path_exists_at(
                        &self._root_lease.authority_directory,
                        self.journal_lock_path(agent)?
                            .file_name()
                            .ok_or(AgentHostError::InvalidJournalName)?,
                    )? || generation_path_exists_at(
                        &self._root_lease.authority_directory,
                        self.authority_ledger_path(agent)?
                            .file_name()
                            .ok_or(AgentHostError::InvalidJournalName)?,
                    )? || generation_path_exists_at(
                        &self._root_lease.authority_directory,
                        self.authority_ledger_stage_path(agent)?
                            .file_name()
                            .ok_or(AgentHostError::InvalidJournalName)?,
                    )? {
                        return Err(AgentHostError::Provider(
                            SystemAgentGenesisProviderError::NotConfigured,
                        ));
                    }
                    let (create, supplied_catalog) =
                        LocalJournalAgentDriver::<FileAgentJournalStore>::system_genesis_input(
                            config.clone(),
                            &runtime_package,
                            authority.clone(),
                            &self.root_pins,
                            &self.trust,
                            &self.merge,
                        )
                        .map_err(map_local_driver_error)?;
                    let prepared =
                        LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
                            create,
                            config.replicas[0],
                            &supplied_catalog,
                            self.trust.clone(),
                            self.merge.clone(),
                        )
                        .map_err(map_local_driver_error)?;
                    validate_prepared_system_agent_genesis_root(&prepared, &self.root_pins)
                        .map_err(AgentHostError::Bootstrap)?;
                    let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared)
                        .map_err(AgentHostError::Bootstrap)?;
                    self._root_lease.validate_live()?;
                    let returned = self
                        .genesis
                        .create(&proposal, &supplied_catalog)
                        .map_err(AgentHostError::Provider)?;
                    self._root_lease.validate_live()?;
                    let reproduced = self
                        .genesis
                        .reproduce(locator)
                        .map_err(AgentHostError::Provider)?;
                    if returned != reproduced {
                        return Err(AgentHostError::Conflict);
                    }
                    let archived_catalog =
                        load_archived_catalog(self.genesis.as_ref(), reproduced.proposal())?;
                    if archived_catalog != supplied_catalog || reproduced.proposal() != &proposal {
                        return Err(AgentHostError::Conflict);
                    }
                    let sealed =
                        seal_prepared_system_agent_genesis(prepared, &self.root_pins, &reproduced)
                            .map_err(AgentHostError::Bootstrap)?;
                    (sealed, archived_catalog, config.clone(), authority.clone())
                }
                Err(error) => return Err(AgentHostError::Provider(error)),
            };
        require_exact_create_caller(
            &catalog,
            &archived_config,
            &archived_receipt,
            &config,
            &runtime_package,
            authority,
        )?;
        if let Some(driver) = self.agents.get(&agent) {
            let current = driver.config().map_err(map_local_driver_error)?;
            if current != config {
                return Err(AgentHostError::Conflict);
            }
            return Ok(current.identity);
        }
        let (journal_parent, authority_parent) = self._root_lease.clone_generation_parents()?;
        let authority_root = self._root_lease.authority_root()?.to_path_buf();
        let driver = open_archived_system_agent(
            &self.root,
            &authority_root,
            &journal_parent,
            &authority_parent,
            &mut self._root_lease,
            self.scope,
            sealed,
            &catalog,
            self.trust.clone(),
            self.merge.clone(),
        )?;
        let identity = driver.identity().map_err(map_local_driver_error)?;
        self._root_lease.validate_live()?;
        if identity != config.identity {
            return Err(AgentHostError::IdentityMismatch);
        }
        self.agents.insert(agent, driver);
        Ok(identity)
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    fn create_ordinary_local(
        &mut self,
        config: AgentConfig,
        runtime_package: Package,
        authority: &AgentAuthorityReceipt,
    ) -> Result<AgentIdentity, AgentHostError> {
        let system_agent = self.system_agent();
        if !self.agents.contains_key(&system_agent) {
            return Err(AgentHostError::InvalidAuthority);
        }
        validate_local_create_target(
            self.scope,
            system_agent,
            &config,
            &runtime_package,
            self.trust.as_ref(),
        )?;
        validate_local_create_receipt(&config, authority)?;
        let agent = config.identity.agent;
        if let Some(hosted) = self.agents.get(&agent) {
            let current = hosted.config().map_err(map_local_driver_error)?;
            let intent = hosted.intent().ok_or(AgentHostError::Conflict)?;
            if current != config || !intent.matches_caller(&config, &runtime_package, authority)? {
                return Err(AgentHostError::Conflict);
            }
            return Ok(current.identity);
        }
        self._root_lease.validate_live()?;
        let intent_name = local_genesis_intent_name(agent);
        let intent_stage_name = local_genesis_intent_stage_name(agent);
        let exposure_name = local_genesis_exposure_name(agent);
        let exposure_stage_name = local_genesis_exposure_stage_name(agent);
        let journal_path = self.journal_path(agent);
        let journal_name = journal_path
            .file_name()
            .ok_or(AgentHostError::InvalidJournalName)?;
        let lock_path = self.journal_lock_path(agent)?;
        let lock_name = lock_path
            .file_name()
            .ok_or(AgentHostError::InvalidJournalName)?;
        if generation_path_exists_at(&self._root_lease.root_directory, journal_name)?
            || generation_path_exists_at(&self._root_lease.authority_directory, lock_name)?
            || generation_path_exists_at(
                &self._root_lease.authority_directory,
                std::ffi::OsStr::new(&intent_name),
            )?
            || generation_path_exists_at(
                &self._root_lease.authority_directory,
                std::ffi::OsStr::new(&intent_stage_name),
            )?
            || generation_path_exists_at(
                &self._root_lease.authority_directory,
                std::ffi::OsStr::new(&exposure_name),
            )?
            || generation_path_exists_at(
                &self._root_lease.authority_directory,
                std::ffi::OsStr::new(&exposure_stage_name),
            )?
        {
            return Err(AgentHostError::Conflict);
        }
        let (create, catalog) =
            LocalJournalAgentDriver::<FileAgentJournalStore>::local_genesis_input(
                config.clone(),
                &runtime_package,
                authority.clone(),
                &self.trust,
                &self.merge,
            )
            .map_err(map_local_driver_error)?;
        let intent = LocalGenesisIntent::new(create.clone(), &runtime_package)?;
        let sealed = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_local_genesis(
            create,
            config.replicas[0],
            &catalog,
            self.trust.clone(),
            self.merge.clone(),
        )
        .map_err(map_local_driver_error)?;
        persist_local_genesis_intent(&self._root_lease.authority_directory, agent, &intent)?;
        self._root_lease.validate_live()?;
        let (journal_parent, authority_parent) = self._root_lease.clone_generation_parents()?;
        let driver = open_archived_local_agent(
            &self.root,
            self._root_lease.authority_root()?,
            &journal_parent,
            &authority_parent,
            self.scope,
            sealed,
            intent.id(),
            &catalog,
            false,
            self.trust.clone(),
            self.merge.clone(),
        )?;
        let identity = driver.identity().map_err(map_local_driver_error)?;
        if identity != config.identity {
            return Err(AgentHostError::IdentityMismatch);
        }
        publish_local_exposure_marker(&self._root_lease.authority_directory, agent, intent.id())?;
        self._root_lease.validate_live()?;
        self.agents
            .insert(agent, HostedLocalAgent::Local { driver, intent });
        Ok(identity)
    }

    pub fn inspect(
        &mut self,
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, AgentHostError> {
        self._root_lease.validate_live()?;
        self.agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?
            .inspect(after, limit)
            .map_err(map_local_driver_error)
    }

    /// Journal one exact clean SDK management mutation for an already
    /// clean-created Local Agent. Read-only Inspect and Create are rejected by
    /// the journal driver and never enter this mutation path.
    pub(crate) fn manage_clean(
        &mut self,
        agent: AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<LocalCleanManagementResult, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            driver
                .clean_manage(request, authority, artifacts)
                .map_err(map_local_driver_error)
        })
    }

    pub fn install_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        installation_id: InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .actor_install_operation(
                    installation_id,
                    registry_reservation,
                    name,
                    parent,
                    installation_data,
                    package,
                )
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::Installed(entry) => Ok(entry),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn upgrade_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<ActorEntry, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .actor_upgrade_operation(actor, from_deployment, package)
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::Upgraded(entry) => Ok(entry),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn suspend_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .actor_suspend_operation(actor)
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::Suspended(entry) => Ok(entry),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn resume_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
    ) -> Result<ActorEntry, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .actor_resume_operation(actor)
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::Resumed(entry) => Ok(entry),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn remove_actor(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<(), AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .actor_remove_operation(actor, expected_deployment)
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::Removed(removed) if removed == actor => Ok(()),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn upgrade_runtime(
        &mut self,
        agent: AgentId,
        authority: &AgentAuthorityReceipt,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<AgentIdentity, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            let operation = driver
                .runtime_upgrade_operation(from_deployment, package)
                .map_err(map_local_driver_error)?;
            match apply_local_lifecycle(driver, authority.clone(), operation)? {
                LifecycleReply::RuntimeUpgraded(identity) => Ok(identity),
                _ => Err(AgentHostError::InvalidRuntime),
            }
        })
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<ActorExecutionReply, AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            match driver
                .invoke_synchronous(invocation, authority.clone())
                .map_err(map_local_driver_error)?
            {
                LocalSettledInvocationResult::Final(Ok(reply)) => Ok(reply),
                LocalSettledInvocationResult::Final(Err(error)) => {
                    Err(AgentHostError::Execution(error))
                }
                LocalSettledInvocationResult::Acknowledged => {
                    Err(AgentHostError::InvocationAcknowledged)
                }
            }
        })
    }

    pub fn acknowledge_invocation(
        &mut self,
        agent: AgentId,
        invocation: ActorInvocation,
        authority: &ActorInvocationReceipt,
    ) -> Result<(), AgentHostError> {
        self._root_lease.validate_live()?;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(AgentHostError::AgentNotFound)?;
        hosted.with_root_mutation(|driver| {
            match driver
                .acknowledge_invocation_synchronous(invocation, authority.clone())
                .map_err(map_local_driver_error)?
            {
                LocalSettledAcknowledgementResult::Acknowledged => Ok(()),
                LocalSettledAcknowledgementResult::Divergent => Err(AgentHostError::Execution(
                    ActorExecutionError::DivergentInvocation,
                )),
            }
        })
    }

    pub fn revision(&self, agent: AgentId) -> Option<u64> {
        self.agents
            .get(&agent)
            .map(|hosted| hosted.publication_revision())
    }

    fn system_agent(&self) -> AgentId {
        self.root_pins.record().system_agent()
    }

    fn genesis_locator(&self) -> SystemAgentGenesisLocator {
        SystemAgentGenesisLocator {
            space: self.scope.space,
            agent: self.system_agent(),
            node: self.scope.node,
        }
    }

    fn journal_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX))
    }

    fn journal_lock_path(&self, agent: AgentId) -> Result<PathBuf, AgentHostError> {
        Ok(self._root_lease.authority_root()?.join(format!(
            "{}{}",
            encode_agent_id(agent),
            JOURNAL_LOCK_SUFFIX
        )))
    }

    fn authority_ledger_path(&self, agent: AgentId) -> Result<PathBuf, AgentHostError> {
        Ok(self._root_lease.authority_root()?.join(format!(
            "{}{}",
            encode_agent_id(agent),
            SYSTEM_AUTHORITY_LEDGER_SUFFIX
        )))
    }

    fn authority_ledger_stage_path(&self, agent: AgentId) -> Result<PathBuf, AgentHostError> {
        Ok(self._root_lease.authority_root()?.join(format!(
            "{}{}",
            encode_agent_id(agent),
            SYSTEM_AUTHORITY_LEDGER_STAGE_SUFFIX
        )))
    }
}

fn validate_host_root_capabilities(
    scope: AgentHostScope,
    merge: &dyn LocalMergeAuthenticator,
    root_pins: &RootAnchorPins,
) -> Result<(), AgentHostError> {
    root_pins.validate().map_err(|error| {
        AgentHostError::Bootstrap(SystemAgentGenesisBootstrapError::Authority(error))
    })?;
    if root_pins.record().space() != scope.space || merge.node() != scope.node {
        return Err(AgentHostError::ScopeMismatch);
    }
    Ok(())
}

fn validate_system_create_shape(
    scope: AgentHostScope,
    system_agent: AgentId,
    config: &AgentConfig,
    runtime_package: &Package,
) -> Result<(), AgentHostError> {
    if config.identity.agent != system_agent || !scope.admits(config) {
        return Err(AgentHostError::ScopeMismatch);
    }
    validate_local_runtime_shape(scope, config, runtime_package)
}

fn validate_local_runtime_shape(
    scope: AgentHostScope,
    config: &AgentConfig,
    runtime_package: &Package,
) -> Result<(), AgentHostError> {
    if !scope.admits(config) {
        return Err(AgentHostError::ScopeMismatch);
    }
    config.validate().map_err(AgentHostError::InvalidConfig)?;
    runtime_package
        .validate()
        .map_err(AgentHostError::Package)?;
    let PackageKind::AgentRuntime {
        contract,
        capabilities,
    } = runtime_package.manifest.kind
    else {
        return Err(AgentHostError::Package(PackageError::WrongKind));
    };
    if runtime_package.deployment_id() != config.identity.runtime_deployment
        || runtime_package.manifest.program != config.identity.runtime_program
        || runtime_package.deployment_signature.producer != config.identity.runtime_producer
        || BlobRef::of_bytes(&runtime_package.encode()) != config.runtime_package
        || contract != config.runtime_contract
        || capabilities != config.capabilities
    {
        return Err(AgentHostError::InvalidRuntime);
    }
    Ok(())
}

fn validate_local_create_target(
    scope: AgentHostScope,
    system_agent: AgentId,
    config: &AgentConfig,
    runtime_package: &Package,
    trust: &dyn AgentTrustProvider,
) -> Result<(), AgentHostError> {
    if config.identity.agent == system_agent || config.system_authority_genesis.is_some() {
        return Err(AgentHostError::ScopeMismatch);
    }
    validate_local_runtime_shape(scope, config, runtime_package)?;
    let anchored = trust
        .authority_for_space(config.identity.space)
        .ok_or(AgentHostError::TrustUnavailable)?;
    if anchored != config.authority {
        return Err(AgentHostError::InvalidAuthority);
    }
    if !trust.verify_package(config, runtime_package) {
        return Err(AgentHostError::Package(PackageError::InvalidSignature));
    }
    Ok(())
}

fn validate_local_create_receipt(
    config: &AgentConfig,
    receipt: &AgentAuthorityReceipt,
) -> Result<(), AgentHostError> {
    receipt
        .verify_guest_signature(&config.authority)
        .map_err(AgentHostError::Authority)?;
    let request = LifecycleRequest::Create(config.clone());
    let claim = &receipt.claim;
    if claim.space != config.identity.space
        || claim.agent != config.identity.agent
        || claim.principal != config.identity.owner
        || claim.capability != CapabilityId::named(super::authority::CAPABILITY_AGENT_CREATE_LOCAL)
        || claim.operation != request.commitment()
    {
        return Err(AgentHostError::InvalidAuthority);
    }
    Ok(())
}

fn validate_local_intent_target(
    scope: AgentHostScope,
    system_agent: AgentId,
    file_agent: AgentId,
    intent: &LocalGenesisIntent,
    trust: &dyn AgentTrustProvider,
) -> Result<(), AgentHostError> {
    intent.validate()?;
    let config = intent.config()?;
    if config.identity.agent != file_agent {
        return Err(AgentHostError::IdentityMismatch);
    }
    let package = intent.runtime_package()?;
    validate_local_create_target(scope, system_agent, config, &package, trust)?;
    validate_local_create_receipt(config, intent.receipt()?)?;
    Ok(())
}

fn validate_system_create_target(
    scope: AgentHostScope,
    system_agent: AgentId,
    config: &AgentConfig,
    runtime_package: &Package,
    root_pins: &RootAnchorPins,
    trust: &dyn AgentTrustProvider,
) -> Result<(), AgentHostError> {
    validate_system_create_shape(scope, system_agent, config, runtime_package)?;
    let marker = config
        .system_authority_genesis
        .as_ref()
        .ok_or(AgentHostError::InvalidConfig(
            AgentConfigError::InvalidSystemAuthorityGenesis,
        ))?;
    marker
        .validate_root_config(root_pins.record(), config, marker.initial_sequence())
        .map_err(|_| {
            AgentHostError::InvalidConfig(AgentConfigError::InvalidSystemAuthorityGenesis)
        })?;
    if root_pins.genesis_claim().sequence() != marker.initial_sequence() {
        return Err(AgentHostError::InvalidConfig(
            AgentConfigError::InvalidSystemAuthorityGenesis,
        ));
    }
    let anchored = trust
        .authority_for_space(config.identity.space)
        .ok_or(AgentHostError::TrustUnavailable)?;
    if anchored != config.authority {
        return Err(AgentHostError::InvalidAuthority);
    }
    if !trust.verify_package(config, runtime_package) {
        return Err(AgentHostError::Package(PackageError::InvalidSignature));
    }
    Ok(())
}

fn archived_create_parts(
    proposal: &SystemAgentGenesisProposal,
) -> Result<(AgentConfig, AgentAuthorityReceipt), AgentHostError> {
    let ReplayOperation::Management { request } = &proposal.create().operation else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    let LifecycleRequest::Authorized { admission, request } = request else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    let LifecycleRequest::Create(config) = request.as_ref() else {
        return Err(AgentHostError::Bootstrap(
            SystemAgentGenesisBootstrapError::InvalidProposal,
        ));
    };
    Ok((config.clone(), admission.receipt.clone()))
}

fn load_archived_catalog(
    provider: &dyn SystemAgentGenesisProvider,
    proposal: &SystemAgentGenesisProposal,
) -> Result<Vec<RuntimeBlob>, AgentHostError> {
    let mut catalog = Vec::new();
    catalog
        .try_reserve_exact(proposal.catalog().len())
        .map_err(|_| AgentHostError::Unavailable)?;
    for reference in proposal.catalog() {
        let bytes = provider
            .load_catalog(proposal.locator(), reference)
            .map_err(AgentHostError::Provider)?
            .ok_or(AgentHostError::Provider(
                SystemAgentGenesisProviderError::Corrupt,
            ))?;
        if !reference.matches(&bytes) {
            return Err(AgentHostError::Provider(
                SystemAgentGenesisProviderError::Corrupt,
            ));
        }
        catalog.push(RuntimeBlob {
            reference: reference.clone(),
            bytes,
        });
    }
    Ok(catalog)
}

fn prepare_archived_genesis(
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    provider: &dyn SystemAgentGenesisProvider,
    root_pins: &RootAnchorPins,
    provision: super::bootstrap::SystemAgentGenesisProvision,
) -> Result<
    (
        ReplaySealedGenesis,
        Vec<RuntimeBlob>,
        AgentConfig,
        AgentAuthorityReceipt,
    ),
    AgentHostError,
> {
    let proposal = provision.proposal();
    let (config, receipt) = archived_create_parts(proposal)?;
    let catalog = load_archived_catalog(provider, proposal)?;
    let prepared = LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_system_genesis(
        proposal.create().clone(),
        proposal.replica(),
        &catalog,
        trust,
        merge,
    )
    .map_err(map_local_driver_error)?;
    let expected = SystemAgentGenesisProposal::from_prepared(proposal.locator(), &prepared)
        .map_err(AgentHostError::Bootstrap)?;
    if expected != *proposal {
        return Err(AgentHostError::Conflict);
    }
    let sealed = seal_prepared_system_agent_genesis(prepared, root_pins, &provision)
        .map_err(AgentHostError::Bootstrap)?;
    Ok((sealed, catalog, config, receipt))
}

fn require_exact_create_caller(
    catalog: &[RuntimeBlob],
    archived_config: &AgentConfig,
    archived_receipt: &AgentAuthorityReceipt,
    supplied_config: &AgentConfig,
    supplied_package: &Package,
    supplied_receipt: &AgentAuthorityReceipt,
) -> Result<(), AgentHostError> {
    let supplied_bytes = supplied_package.encode();
    if archived_config != supplied_config
        || archived_receipt != supplied_receipt
        || catalog.len() != 1
        || catalog[0].reference != supplied_config.runtime_package
        || catalog[0].bytes != supplied_bytes
    {
        return Err(AgentHostError::Conflict);
    }
    Ok(())
}

fn open_archived_system_agent(
    root: &Path,
    authority_root: &Path,
    journal_parent: &File,
    authority_parent: &File,
    lease: &mut AgentHostRootLease,
    scope: AgentHostScope,
    sealed: ReplaySealedGenesis,
    catalog: &[RuntimeBlob],
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
) -> Result<HostedLocalAgent, AgentHostError> {
    #[cfg(not(all(feature = "storage", target_os = "linux")))]
    {
        let _ = (
            root,
            authority_root,
            journal_parent,
            authority_parent,
            lease,
            scope,
            sealed,
            catalog,
            trust,
            merge,
        );
        return Err(AgentHostError::Unavailable);
    }
    #[cfg(all(feature = "storage", target_os = "linux"))]
    {
        let agent = sealed.genesis().runtime().agent;
        let journal = root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX));
        let stable_lock =
            authority_root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX));
        let slot = FileAgentJournalSlot::acquire_with_pinned_parents(
            journal,
            stable_lock,
            scope.node,
            journal_parent,
            authority_parent,
        )
        .map_err(map_journal_error)?;
        let ledger = slot
            .open_system_authority_ledger()
            .map_err(map_journal_error)?;
        let owner = SystemAuthorityLedgerRouteOwner::open_file(ledger.into_owner_open(), &sealed)
            .map_err(map_system_authority_ledger_error)?;
        let authority = slot
            .bind_system_authority_ledger_owner(owner, &sealed)
            .map_err(map_journal_error)?;
        let outer_armed = lease.is_armed();
        let strict_unexposed = lease.requires_strict_unexposed_open();
        if authority
            .journal_exposure_is_committed()
            .map_err(map_system_authority_ledger_error)?
            && !outer_armed
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        let (store, journal_exposure_committed) = authority
            .with_startup_root_recovery(|startup| {
                let journal_exposure_committed = startup.journal_exposure_is_committed();
                if journal_exposure_committed && !outer_armed {
                    return Err(JournalStoreError::ScopeMismatch);
                }
                slot.open_reverified(&sealed, startup, strict_unexposed)
                    .map(|store| (store, journal_exposure_committed))
            })
            .map_err(map_system_authority_ledger_error)?
            .map_err(map_journal_error)?;
        let genesis = store.genesis().map_err(map_journal_error)?;
        let heads = store.heads().map_err(map_journal_error)?;
        let driver = match (journal_exposure_committed, genesis, heads) {
            (true, Some(_), Some(_)) => {
                LocalJournalAgentDriver::open_reverified_with_owner(store, trust, merge, &authority)
                    .map_err(map_local_driver_error)?
            }
            (true, _, _) => return Err(map_journal_error(JournalStoreError::Corrupt)),
            // A complete journal can precede its exposure row only when the
            // process crashed after durable initialization and before the
            // marker transaction. Reverify it exactly under the pristine
            // initialization writer, then commit the marker before return.
            (false, Some(_), Some(_)) => {
                LocalJournalAgentDriver::open_unexposed_reverified_with_owner(
                    store,
                    &sealed,
                    trust,
                    merge,
                    &authority,
                    || {
                        lease.validate_live()?;
                        lease.arm_after_agent_open()?;
                        lease.validate_live()
                    },
                )
                .map_err(map_unexposed_driver_open_error)?
            }
            // `initialize` publishes genesis before initial heads. Reusing the
            // exact root-admitted seal is the one canonical repair for a crash at
            // that boundary; both writes are immutable and conflict checked.
            (false, None, None) | (false, Some(_), None) => {
                // This store-bound preflight deliberately rechecks current root
                // and package trust before installing immutable bytes. It does
                // not re-authenticate the Create receipt or re-execute Replay;
                // those happened exactly once while preparing `sealed`.
                LocalJournalAgentDriver::create_reverified_with_owner(
                    store,
                    sealed,
                    catalog,
                    trust,
                    merge,
                    &authority,
                    || {
                        lease.validate_live()?;
                        lease.arm_after_agent_open()?;
                        lease.validate_live()
                    },
                )
                .map_err(map_unexposed_driver_open_error)?
            }
            (false, None, Some(_)) => return Err(map_journal_error(JournalStoreError::Corrupt)),
        };
        authority.verify().map_err(map_journal_error)?;
        lease.validate_live()?;
        if !lease.is_armed() {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        Ok(HostedLocalAgent::System { driver, authority })
    }
}

fn prepare_local_intent_genesis(
    intent: &LocalGenesisIntent,
    catalog: &[RuntimeBlob],
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
) -> Result<ReplaySealedLocalGenesis, AgentHostError> {
    let config = intent.config()?;
    LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_local_genesis(
        intent.create.clone(),
        config.replicas[0],
        catalog,
        trust,
        merge,
    )
    .map_err(map_local_driver_error)
}

#[cfg(all(feature = "storage", target_os = "linux"))]
fn open_archived_local_agent(
    root: &Path,
    authority_root: &Path,
    journal_parent: &File,
    authority_parent: &File,
    scope: AgentHostScope,
    sealed: ReplaySealedLocalGenesis,
    intent: Hash,
    catalog: &[RuntimeBlob],
    exposed: bool,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
) -> Result<LocalJournalAgentDriver<FileAgentJournalStore>, AgentHostError> {
    let agent = sealed.genesis().runtime().agent;
    let journal = root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX));
    let stable_lock =
        authority_root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX));
    let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
        journal,
        stable_lock,
        scope.node,
        intent,
        journal_parent,
        authority_parent,
    )
    .map_err(map_journal_error)?;
    if exposed && !slot.generation_exists() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let store = slot.open(&sealed, exposed).map_err(map_journal_error)?;
    match (
        store.genesis().map_err(map_journal_error)?,
        store.heads().map_err(map_journal_error)?,
    ) {
        (Some(_), Some(_)) => {
            LocalJournalAgentDriver::open_local(store, &sealed, intent, trust, merge)
                .map_err(map_local_driver_error)
        }
        (None, None) | (Some(_), None) => {
            LocalJournalAgentDriver::create_local(store, sealed, intent, catalog, trust, merge)
                .map_err(map_local_driver_error)
        }
        (None, Some(_)) => Err(map_journal_error(JournalStoreError::Corrupt)),
    }
}

fn local_genesis_intent_name(agent: AgentId) -> String {
    format!("{}{}", encode_agent_id(agent), LOCAL_GENESIS_INTENT_SUFFIX)
}

fn local_genesis_intent_stage_name(agent: AgentId) -> String {
    format!(
        "{}{}",
        encode_agent_id(agent),
        LOCAL_GENESIS_INTENT_STAGE_SUFFIX
    )
}

fn local_genesis_exposure_name(agent: AgentId) -> String {
    format!(
        "{}{}",
        encode_agent_id(agent),
        LOCAL_GENESIS_EXPOSURE_SUFFIX
    )
}

fn local_genesis_exposure_stage_name(agent: AgentId) -> String {
    format!(
        "{}{}",
        encode_agent_id(agent),
        LOCAL_GENESIS_EXPOSURE_STAGE_SUFFIX
    )
}

#[derive(Debug)]
struct HostGenerationRecord {
    bytes: Vec<u8>,
    metadata: fs::Metadata,
}

fn read_host_generation_record(
    parent: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<HostGenerationRecord>, AgentHostError> {
    let path = agent_host_directory_capability_path(parent).join(name);
    let named = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    if !named.file_type().is_file()
        || named.file_type().is_symlink()
        || named.len() > maximum as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let opened = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_scope_metadata(&opened, &named)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.nlink() == 0 || opened.nlink() > 2 {
            return Err(AgentHostError::InvalidScopeBinding);
        }
    }
    let length = usize::try_from(opened.len()).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    Ok(Some(HostGenerationRecord {
        bytes,
        metadata: opened,
    }))
}

fn same_host_generation_record(left: &HostGenerationRecord, right: &HostGenerationRecord) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.metadata.dev() == right.metadata.dev() && left.metadata.ino() == right.metadata.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn persist_host_generation_record(
    parent: &File,
    canonical_name: &str,
    stage_name: &str,
    expected: &[u8],
    maximum: usize,
) -> Result<(), AgentHostError> {
    if expected.is_empty() || expected.len() > maximum {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let capability = agent_host_directory_capability_path(parent);
    let canonical_path = capability.join(canonical_name);
    let stage_path = capability.join(stage_name);
    let canonical = read_host_generation_record(parent, canonical_name, maximum)?;
    let mut stage = read_host_generation_record(parent, stage_name, maximum)?;
    if let Some(canonical) = &canonical {
        if canonical.bytes != expected {
            return Err(AgentHostError::Conflict);
        }
        if let Some(staged) = &stage {
            if staged.bytes != expected || !same_host_generation_record(canonical, staged) {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            fs::remove_file(&stage_path).map_err(|_| AgentHostError::Unavailable)?;
            parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
        }
        return Ok(());
    }

    if let Some(staged) = &stage {
        if staged.bytes.len() > expected.len()
            || staged.bytes.as_slice() != &expected[..staged.bytes.len()]
        {
            return Err(AgentHostError::Conflict);
        }
        if staged.bytes.len() != expected.len() {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let mut file = options
                .open(&stage_path)
                .map_err(|_| AgentHostError::InvalidScopeBinding)?;
            file.seek(SeekFrom::Start(staged.bytes.len() as u64))
                .and_then(|_| file.write_all(&expected[staged.bytes.len()..]))
                .and_then(|_| file.sync_all())
                .map_err(|_| AgentHostError::Unavailable)?;
            parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
            stage = read_host_generation_record(parent, stage_name, maximum)?;
        }
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options
            .open(&stage_path)
            .map_err(|_| AgentHostError::InvalidScopeBinding)?;
        file.write_all(expected)
            .and_then(|_| file.sync_all())
            .map_err(|_| AgentHostError::Unavailable)?;
        parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
        stage = read_host_generation_record(parent, stage_name, maximum)?;
    }
    let staged = stage.ok_or(AgentHostError::InvalidScopeBinding)?;
    if staged.bytes != expected {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    fs::hard_link(&stage_path, &canonical_path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    let canonical = read_host_generation_record(parent, canonical_name, maximum)?
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let staged = read_host_generation_record(parent, stage_name, maximum)?
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    if canonical.bytes != expected
        || staged.bytes != expected
        || !same_host_generation_record(&canonical, &staged)
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    fs::remove_file(stage_path).map_err(|_| AgentHostError::Unavailable)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    Ok(())
}

fn persist_local_genesis_intent(
    parent: &File,
    agent: AgentId,
    intent: &LocalGenesisIntent,
) -> Result<(), AgentHostError> {
    intent.validate()?;
    persist_host_generation_record(
        parent,
        &local_genesis_intent_name(agent),
        &local_genesis_intent_stage_name(agent),
        &intent.encode(),
        MAX_LOCAL_GENESIS_INTENT_BYTES,
    )
}

fn recover_local_genesis_intent(
    parent: &File,
    agent: AgentId,
) -> Result<LocalGenesisIntent, AgentHostError> {
    let canonical_name = local_genesis_intent_name(agent);
    let stage_name = local_genesis_intent_stage_name(agent);
    let record = match (
        read_host_generation_record(parent, &canonical_name, MAX_LOCAL_GENESIS_INTENT_BYTES)?,
        read_host_generation_record(parent, &stage_name, MAX_LOCAL_GENESIS_INTENT_BYTES)?,
    ) {
        (Some(canonical), Some(staged)) => {
            if canonical.bytes != staged.bytes || !same_host_generation_record(&canonical, &staged)
            {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            fs::remove_file(agent_host_directory_capability_path(parent).join(&stage_name))
                .map_err(|_| AgentHostError::Unavailable)?;
            parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
            canonical.bytes
        }
        (Some(canonical), None) => canonical.bytes,
        (None, Some(staged)) => {
            let intent = LocalGenesisIntent::decode(&staged.bytes)
                .map_err(|_| AgentHostError::InvalidScopeBinding)?;
            if intent.encode() != staged.bytes {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            persist_host_generation_record(
                parent,
                &canonical_name,
                &stage_name,
                &staged.bytes,
                MAX_LOCAL_GENESIS_INTENT_BYTES,
            )?;
            staged.bytes
        }
        (None, None) => return Err(AgentHostError::InvalidScopeBinding),
    };
    let intent =
        LocalGenesisIntent::decode(&record).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if intent.encode() != record {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    Ok(intent)
}

fn recover_local_exposure_marker(
    parent: &File,
    agent: AgentId,
    intent: Hash,
    has_canonical: bool,
    has_stage: bool,
) -> Result<bool, AgentHostError> {
    if !has_canonical && !has_stage {
        return Ok(false);
    }
    persist_host_generation_record(
        parent,
        &local_genesis_exposure_name(agent),
        &local_genesis_exposure_stage_name(agent),
        intent.as_bytes(),
        core::mem::size_of::<Hash>(),
    )?;
    Ok(true)
}

fn publish_local_exposure_marker(
    parent: &File,
    agent: AgentId,
    intent: Hash,
) -> Result<(), AgentHostError> {
    persist_host_generation_record(
        parent,
        &local_genesis_exposure_name(agent),
        &local_genesis_exposure_stage_name(agent),
        intent.as_bytes(),
        core::mem::size_of::<Hash>(),
    )
}

#[cfg(all(feature = "storage", target_os = "linux"))]
fn map_unexposed_driver_open_error(
    error: LocalJournalUnexposedOpenError<AgentHostError>,
) -> AgentHostError {
    match error {
        LocalJournalUnexposedOpenError::Driver(error) => map_local_driver_error(error),
        LocalJournalUnexposedOpenError::BeforeExposure(error) => error,
    }
}

fn apply_local_lifecycle(
    driver: &mut LocalJournalAgentDriver<FileAgentJournalStore>,
    authority: AgentAuthorityReceipt,
    operation: LocalLifecycleOperation,
) -> Result<LifecycleReply, AgentHostError> {
    let (request, catalog) = operation.into_parts();
    driver
        .lifecycle(authority, request, &catalog)
        .map_err(map_local_driver_error)?
        .result
        .map_err(AgentHostError::Lifecycle)
}

fn generation_path_exists(path: &Path) -> Result<bool, AgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AgentHostError::Unavailable),
    }
}

fn generation_path_exists_at(
    parent: &File,
    name: &std::ffi::OsStr,
) -> Result<bool, AgentHostError> {
    generation_path_exists(&agent_host_directory_capability_path(parent).join(name))
}

fn generation_regular_file_exists_at(parent: &File, name: &str) -> Result<bool, AgentHostError> {
    generation_regular_file_exists(&agent_host_directory_capability_path(parent).join(name))
}

fn generation_regular_file_exists(path: &Path) -> Result<bool, AgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(AgentHostError::InvalidScopeBinding),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(AgentHostError::Unavailable),
    }
}

fn map_journal_error(error: JournalStoreError) -> AgentHostError {
    let projected = match error {
        JournalStoreError::InvalidPath => AgentHostJournalError::InvalidPath,
        JournalStoreError::ScopeMismatch => AgentHostJournalError::ScopeMismatch,
        JournalStoreError::DirectoryInUse => AgentHostJournalError::DirectoryInUse,
        JournalStoreError::LegacyGeneration => AgentHostJournalError::LegacyGeneration,
        JournalStoreError::NotInitialized => AgentHostJournalError::NotInitialized,
        JournalStoreError::Conflict => AgentHostJournalError::Conflict,
        JournalStoreError::GcPending => AgentHostJournalError::GcPending,
        JournalStoreError::InvalidClass => AgentHostJournalError::InvalidClass,
        JournalStoreError::NonCanonical => AgentHostJournalError::NonCanonical,
        JournalStoreError::LimitExceeded => AgentHostJournalError::LimitExceeded,
        JournalStoreError::Backpressure => AgentHostJournalError::Backpressure,
        JournalStoreError::MissingObject => AgentHostJournalError::MissingObject,
        JournalStoreError::Corrupt => AgentHostJournalError::Corrupt,
        JournalStoreError::Unavailable => AgentHostJournalError::Unavailable,
    };
    AgentHostError::Journal(projected)
}

fn map_local_executor_error(error: LocalReplayExecutorError) -> AgentHostError {
    match error {
        LocalReplayExecutorError::InvalidProfile | LocalReplayExecutorError::WrongReplica => {
            AgentHostError::ScopeMismatch
        }
        LocalReplayExecutorError::TrustUnavailable => AgentHostError::TrustUnavailable,
        LocalReplayExecutorError::InvalidAuthority => AgentHostError::InvalidAuthority,
        LocalReplayExecutorError::Package(error) => AgentHostError::Package(error),
        LocalReplayExecutorError::Store(error) => map_journal_error(error),
        LocalReplayExecutorError::RuntimeBackend => {
            AgentHostError::Journal(AgentHostJournalError::Unavailable)
        }
        LocalReplayExecutorError::InvalidState
        | LocalReplayExecutorError::InvalidRequest
        | LocalReplayExecutorError::ArtifactUnavailable(_)
        | LocalReplayExecutorError::InvalidArtifact(_)
        | LocalReplayExecutorError::RuntimeExit { .. }
        | LocalReplayExecutorError::RuntimeOutput
        | LocalReplayExecutorError::RuntimeStateTooLarge => AgentHostError::InvalidRuntime,
    }
}

fn map_local_driver_error(error: LocalJournalDriverError) -> AgentHostError {
    match error {
        LocalJournalDriverError::Store(error) => map_journal_error(error),
        LocalJournalDriverError::Executor(error) => map_local_executor_error(error),
        LocalJournalDriverError::Lifecycle(error) => AgentHostError::Lifecycle(error),
        LocalJournalDriverError::AuthorityLedger => AgentHostError::AuthorityLedger,
        LocalJournalDriverError::AuthorityRecoveryRequired => {
            AgentHostError::AuthorityRecoveryRequired
        }
        LocalJournalDriverError::Conflict => AgentHostError::Conflict,
        LocalJournalDriverError::InvalidResult => AgentHostError::InvalidRuntime,
        LocalJournalDriverError::Replay(error) => match error {
            ReplayError::Source(ReplayMaterializationSourceError::Journal(error)) => {
                map_journal_error(error)
            }
            ReplayError::Source(ReplayMaterializationSourceError::Resolver(never)) => {
                match never {}
            }
            ReplayError::Executor(error) => map_local_executor_error(error),
            ReplayError::UncommittedInvocation(error) => AgentHostError::Execution(error),
            ReplayError::MissingOrdered(_)
            | ReplayError::MissingLocal(_)
            | ReplayError::MissingMergeEvent(_)
            | ReplayError::MissingMergeFrontier(_)
            | ReplayError::MissingMergeSeal(_)
            | ReplayError::MissingLaneState(_)
            | ReplayError::MissingArtifactClosure(_)
            | ReplayError::MissingInvocationIndex(_)
            | ReplayError::MissingCheckpoint(_)
            | ReplayError::InvalidRecord
            | ReplayError::ScopeMismatch
            | ReplayError::ChainMismatch
            | ReplayError::ReplayLimit
            | ReplayError::InvalidCausalHeight
            | ReplayError::NonMinimalFrontier
            | ReplayError::StaleMergeBranch(_)
            | ReplayError::UnauthenticatedMergeEvent(_)
            | ReplayError::InvalidOrderedBase
            | ReplayError::UnavailableOrderedBase
            | ReplayError::InvalidFence
            | ReplayError::StalePreFenceEvent(_)
            | ReplayError::RuntimeMismatch
            | ReplayError::InvalidRuntimeUpgrade
            | ReplayError::InvalidManagementTransition
            | ReplayError::InvalidPosition
            | ReplayError::CrossLaneMutation
            | ReplayError::TerminalMutation
            | ReplayError::ForbiddenMergeProducts
            | ReplayError::InvocationOwnership(_) => AgentHostError::InvalidRuntime,
        },
    }
}

#[cfg(all(feature = "storage", target_os = "linux"))]
fn map_system_authority_ledger_error(error: SystemAuthorityLedgerError) -> AgentHostError {
    match error {
        SystemAuthorityLedgerError::PublicationRecoveryRequired
        | SystemAuthorityLedgerError::GcBlockedByPendingReservation => {
            AgentHostError::AuthorityRecoveryRequired
        }
        _ => AgentHostError::AuthorityLedger,
    }
}

fn canonical_agent_host_root_target(root: PathBuf) -> Result<(PathBuf, bool), AgentHostError> {
    let root = absolute_agent_host_path(root)?;
    let file_name = root
        .file_name()
        .ok_or(AgentHostError::InvalidScopeBinding)?
        .to_owned();
    let parent = root.parent().ok_or(AgentHostError::InvalidScopeBinding)?;
    // Configured parent directories are a provisioning boundary. Requiring
    // them to pre-exist lets acquire pin and validate the exact parent before
    // any outer record or child leaf is created.
    let parent = fs::canonicalize(parent).map_err(|_| AgentHostError::Unavailable)?;
    let root = parent.join(file_name);
    match fs::symlink_metadata(&root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            fs::canonicalize(root)
                .map(|root| (root, true))
                .map_err(|_| AgentHostError::Unavailable)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((root, false)),
        Err(_) => Err(AgentHostError::Unavailable),
    }
}

fn agent_host_child_capability_path(parent: &File, child: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        return PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(
            child
                .file_name()
                .expect("validated Agent Host child has a leaf"),
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = parent;
        child.to_path_buf()
    }
}

fn ensure_agent_host_root(root: PathBuf, parent: &File) -> Result<PathBuf, AgentHostError> {
    validate_agent_host_lock_parent_identity(parent, &root)?;
    let capability = agent_host_child_capability_path(parent, &root);
    match fs::symlink_metadata(&capability) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(&capability)
                .map_err(|_| AgentHostError::Unavailable)?;
        }
        Err(_) => return Err(AgentHostError::Unavailable),
    }
    let metadata = fs::symlink_metadata(&capability).map_err(|_| AgentHostError::Unavailable)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let directory = open_agent_host_root_directory_at(parent, &root)?;
    validate_agent_host_root_identity(&directory, &root)?;
    // Repeat the parent sync even when the leaf already exists. A previous
    // attempt may have completed mkdir but failed to observe this durability
    // boundary.
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lock_parent_identity(parent, &root)?;
    Ok(root)
}

fn existing_agent_host_root(root: PathBuf, parent: &File) -> Result<PathBuf, AgentHostError> {
    validate_agent_host_lock_parent_identity(parent, &root)?;
    let capability = agent_host_child_capability_path(parent, &root);
    let metadata = fs::symlink_metadata(&capability).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AgentHostError::InvalidScopeBinding
        } else {
            AgentHostError::Unavailable
        }
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    validate_agent_host_lock_parent_identity(parent, &root)?;
    Ok(root)
}

fn agent_host_authority_root(
    stable_lock_path: &Path,
    root: &Path,
    scope: AgentHostScope,
) -> Result<PathBuf, AgentHostError> {
    let parent = stable_lock_path
        .parent()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let root_bytes = stable_agent_host_path_bytes(root)?;
    let commitment = Hash::digest(
        HOST_AUTHORITY_ROOT_DOMAIN,
        &[&root_bytes, scope.space.as_bytes(), scope.node.as_bytes()],
    );
    Ok(parent.join(format!(
        ".{}{}",
        encode_agent_id(AgentId(commitment.0)),
        HOST_AUTHORITY_ROOT_SUFFIX
    )))
}

/// Derive the exact external authority namespace without creating or
/// repairing any filesystem entry. This is used by Agent-disabled startup to
/// detect residue that survives deletion of both the journal root and the
/// canonical outer lease.
pub fn agent_host_authority_root_path(
    root: &Path,
    stable_lock_path: &Path,
    scope: AgentHostScope,
) -> Result<PathBuf, AgentHostError> {
    let scope = scope.validate()?;
    let requested_root = absolute_agent_host_path(root.to_path_buf())?;
    let canonical_root = match fs::symlink_metadata(&requested_root) {
        Ok(_) => fs::canonicalize(&requested_root).map_err(|_| AgentHostError::Unavailable)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let leaf = requested_root
                .file_name()
                .ok_or(AgentHostError::InvalidScopeBinding)?;
            let parent = requested_root
                .parent()
                .ok_or(AgentHostError::InvalidScopeBinding)?;
            fs::canonicalize(parent)
                .map_err(|_| AgentHostError::Unavailable)?
                .join(leaf)
        }
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    let requested_lock = absolute_agent_host_path(stable_lock_path.to_path_buf())?;
    let lock_leaf = requested_lock
        .file_name()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let lock_parent = requested_lock
        .parent()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let canonical_lock = fs::canonicalize(lock_parent)
        .map_err(|_| AgentHostError::Unavailable)?
        .join(lock_leaf);
    if canonical_lock.starts_with(&canonical_root) {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    agent_host_authority_root(&canonical_lock, &canonical_root, scope)
}

fn ensure_agent_host_authority_root(
    authority_root: PathBuf,
    stable_lock_parent: &File,
) -> Result<PathBuf, AgentHostError> {
    validate_agent_host_lock_parent_identity(stable_lock_parent, &authority_root)?;
    let capability = agent_host_child_capability_path(stable_lock_parent, &authority_root);
    match fs::symlink_metadata(&capability) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(&capability)
                .map_err(|_| AgentHostError::Unavailable)?;
        }
        Err(_) => return Err(AgentHostError::Unavailable),
    }
    let directory = open_agent_host_root_directory_at(stable_lock_parent, &authority_root)?;
    validate_agent_host_authority_root_identity(&directory, &authority_root)?;
    // This is also a retry barrier for mkdir-success/parent-fsync-failure.
    stable_lock_parent
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lock_parent_identity(stable_lock_parent, &authority_root)?;
    Ok(authority_root)
}

fn validate_fresh_bound_tree_prefix(
    root: &Path,
    root_parent: &File,
    authority_root: &Path,
    authority_parent: &File,
) -> Result<(), AgentHostError> {
    fn state(parent: &File, path: &Path) -> Result<Option<bool>, AgentHostError> {
        validate_agent_host_lock_parent_identity(parent, path)?;
        let capability = agent_host_child_capability_path(parent, path);
        match fs::symlink_metadata(&capability) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                let directory = open_agent_host_root_directory_at(parent, path)?;
                validate_agent_host_root_identity(&directory, path)?;
                let empty = fs::read_dir(agent_host_directory_capability_path(&directory))
                    .map_err(|_| AgentHostError::Unavailable)?
                    .next()
                    .transpose()
                    .map_err(|_| AgentHostError::Unavailable)?
                    .is_none();
                validate_agent_host_root_identity(&directory, path)?;
                Ok(Some(empty))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AgentHostError::Unavailable),
        }
    }

    let root_state = state(root_parent, root)?;
    let authority_state = state(authority_parent, authority_root)?;
    match (root_state, authority_state) {
        (None, None) | (Some(true), None) | (Some(true), Some(true)) | (Some(false), Some(_)) => {
            Ok(())
        }
        // Authority creation follows root creation, and every Host sidecar
        // follows authority creation. These impossible prefixes represent a
        // deleted/restored side and are never repaired.
        (None, Some(_)) | (Some(false), None) | (Some(true), Some(false)) => {
            Err(AgentHostError::InvalidScopeBinding)
        }
    }
}

fn existing_agent_host_authority_root(
    authority_root: PathBuf,
    parent: &File,
) -> Result<PathBuf, AgentHostError> {
    validate_agent_host_lock_parent_identity(parent, &authority_root)?;
    let capability = agent_host_child_capability_path(parent, &authority_root);
    let metadata = fs::symlink_metadata(&capability).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AgentHostError::InvalidScopeBinding
        } else {
            AgentHostError::Unavailable
        }
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    validate_agent_host_lock_parent_identity(parent, &authority_root)?;
    Ok(authority_root)
}

fn agent_host_directory_capability_path(directory: &File) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        return PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        PathBuf::new()
    }
}

fn open_agent_host_root_directory_at(parent: &File, root: &Path) -> Result<File, AgentHostError> {
    validate_agent_host_lock_parent_identity(parent, root)?;
    let capability = agent_host_child_capability_path(parent, root);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    // `/proc/self/fd/<parent>/leaf` is only the descriptor-relative open
    // mechanism. Do not run ancestor validation against that synthetic path
    // (the fd component is intentionally a symlink); validate the opened
    // inode against the real canonical name and pinned parent below.
    let directory = options
        .open(capability)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_root_identity(&directory, root)?;
    validate_agent_host_lock_parent_identity(parent, root)?;
    Ok(directory)
}

fn validate_agent_host_authority_root_identity(
    directory: &File,
    authority_root: &Path,
) -> Result<(), AgentHostError> {
    validate_agent_host_root_identity(directory, authority_root)
}

fn validate_agent_host_root_identity(directory: &File, root: &Path) -> Result<(), AgentHostError> {
    let opened = directory
        .metadata()
        .map_err(|_| AgentHostError::Unavailable)?;
    let named = fs::symlink_metadata(root).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !opened.file_type().is_dir() || !named.file_type().is_dir() || named.file_type().is_symlink()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let effective_user = unsafe { libc::geteuid() };
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != effective_user
            || named.uid() != effective_user
            || opened.mode() & 0o022 != 0
            || named.mode() & 0o022 != 0
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        for ancestor in root
            .parent()
            .ok_or(AgentHostError::InvalidScopeBinding)?
            .ancestors()
        {
            let metadata =
                fs::symlink_metadata(ancestor).map_err(|_| AgentHostError::InvalidScopeBinding)?;
            let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_user || {
                #[cfg(target_os = "linux")]
                {
                    super::journal_store::uid_is_unmapped_overflow(metadata.uid())
                        .map_err(|_| AgentHostError::InvalidScopeBinding)?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            };
            let writable = metadata.mode() & 0o022 != 0;
            let protected_sticky = metadata.mode() & u32::from(libc::S_ISVTX) != 0 && trusted_owner;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || !trusted_owner
                || writable && !protected_sticky
            {
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
    }
    Ok(())
}

fn absolute_agent_host_path(path: PathBuf) -> Result<PathBuf, AgentHostError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .map_err(|_| AgentHostError::Unavailable)?
            .join(path))
    }
}

fn canonical_lock_path(path: PathBuf) -> Result<PathBuf, AgentHostError> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|_| AgentHostError::Unavailable)?
            .join(path)
    };
    let file_name = path
        .file_name()
        .ok_or(AgentHostError::InvalidScopeBinding)?
        .to_owned();
    let parent = path.parent().ok_or(AgentHostError::InvalidScopeBinding)?;
    let parent = fs::canonicalize(parent).map_err(|_| AgentHostError::Unavailable)?;
    Ok(parent.join(file_name))
}

fn encode_agent_host_lease_binding(
    root: &Path,
    scope: AgentHostScope,
    origin: u32,
) -> Result<[u8; HOST_LEASE_BINDING_LEN], AgentHostError> {
    let root_bytes = stable_agent_host_path_bytes(root)?;
    let root_commitment = Hash::digest(HOST_LEASE_ROOT_DOMAIN, &[&root_bytes]);
    let mut encoded = [0; HOST_LEASE_BINDING_LEN];
    encoded[..8].copy_from_slice(HOST_LEASE_BINDING_MAGIC);
    encoded[8..12].copy_from_slice(&HOST_LEASE_RECORD_VERSION.to_be_bytes());
    encoded[12..16].copy_from_slice(&origin.to_be_bytes());
    encoded[16..48].copy_from_slice(root_commitment.as_bytes());
    encoded[48..80].copy_from_slice(scope.space.as_bytes());
    encoded[80..112].copy_from_slice(scope.node.as_bytes());
    let commitment = Hash::digest(
        HOST_LEASE_BINDING_DOMAIN,
        &[&encoded[..HOST_LEASE_BINDING_PREFIX_LEN]],
    );
    encoded[HOST_LEASE_BINDING_PREFIX_LEN..].copy_from_slice(commitment.as_bytes());
    Ok(encoded)
}

fn stable_agent_host_path_bytes(path: &Path) -> Result<Vec<u8>, AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let mut encoded = b"unix\0".to_vec();
        encoded.extend_from_slice(path.as_os_str().as_bytes());
        return Ok(encoded);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        let mut encoded = b"windows-utf16be\0".to_vec();
        for code_unit in path.as_os_str().encode_wide() {
            encoded.extend_from_slice(&code_unit.to_be_bytes());
        }
        return Ok(encoded);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(AgentHostError::InvalidScopeBinding)
    }
}

fn encode_agent_host_lease_arm(binding: &[u8; HOST_LEASE_BINDING_LEN]) -> [u8; HOST_LEASE_ARM_LEN] {
    let mut encoded = [0; HOST_LEASE_ARM_LEN];
    encoded[..8].copy_from_slice(HOST_LEASE_ARM_MAGIC);
    encoded[8..12].copy_from_slice(&HOST_LEASE_RECORD_VERSION.to_be_bytes());
    encoded[12..HOST_LEASE_ARM_PREFIX_LEN]
        .copy_from_slice(&binding[HOST_LEASE_BINDING_PREFIX_LEN..]);
    let commitment = Hash::digest(
        HOST_LEASE_ARM_DOMAIN,
        &[&encoded[..HOST_LEASE_ARM_PREFIX_LEN]],
    );
    encoded[HOST_LEASE_ARM_PREFIX_LEN..].copy_from_slice(commitment.as_bytes());
    encoded
}

fn read_agent_host_lease_state(
    file: &mut File,
    fresh_binding: &[u8; HOST_LEASE_BINDING_LEN],
    migration_binding: &[u8; HOST_LEASE_BINDING_LEN],
) -> Result<AgentHostRootLeaseState, AgentHostError> {
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| AgentHostError::Unavailable)?
            .len(),
    )
    .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if length == 0 {
        return Ok(AgentHostRootLeaseState::LegacyUnbound);
    }
    if !(HOST_LEASE_BINDING_LEN..=HOST_LEASE_ARMED_LEN).contains(&length) {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AgentHostError::Unavailable)?;
    let mut encoded = [0; HOST_LEASE_ARMED_LEN];
    file.read_exact(&mut encoded[..length])
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?
        != 0
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let binding = &encoded[..HOST_LEASE_BINDING_LEN];
    if &binding[..8] != HOST_LEASE_BINDING_MAGIC
        || binding[8..12] != HOST_LEASE_RECORD_VERSION.to_be_bytes()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let expected_commitment = Hash::digest(
        HOST_LEASE_BINDING_DOMAIN,
        &[&binding[..HOST_LEASE_BINDING_PREFIX_LEN]],
    );
    if binding[HOST_LEASE_BINDING_PREFIX_LEN..] != expected_commitment.0 {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if binding[16..48] != fresh_binding[16..48] {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if binding[48..112] != fresh_binding[48..112] {
        return Err(AgentHostError::ScopeMismatch);
    }
    let origin = u32::from_be_bytes(
        binding[12..16]
            .try_into()
            .map_err(|_| AgentHostError::InvalidScopeBinding)?,
    );
    let (expected_binding, bound, armed) = match origin {
        HOST_LEASE_BINDING_FRESH => (
            fresh_binding,
            AgentHostRootLeaseState::FreshBound,
            AgentHostRootLeaseState::FreshArmed,
        ),
        HOST_LEASE_BINDING_LEGACY_MIGRATION => (
            migration_binding,
            AgentHostRootLeaseState::LegacyMigrationBound,
            AgentHostRootLeaseState::LegacyMigrationArmed,
        ),
        _ => return Err(AgentHostError::InvalidScopeBinding),
    };
    if binding != expected_binding {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if length == HOST_LEASE_BINDING_LEN {
        return Ok(bound);
    }
    let expected_arm = encode_agent_host_lease_arm(expected_binding);
    let arm_bytes = &encoded[HOST_LEASE_BINDING_LEN..length];
    if arm_bytes != &expected_arm[..arm_bytes.len()] {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if length == HOST_LEASE_ARMED_LEN {
        Ok(armed)
    } else if origin == HOST_LEASE_BINDING_FRESH {
        Ok(AgentHostRootLeaseState::FreshArmInterrupted)
    } else {
        // The legacy layout is a clean break and is never repaired.
        Err(AgentHostError::InvalidScopeBinding)
    }
}

fn append_agent_host_lease_record(
    file: &mut File,
    path: &Path,
    parent: &File,
    record: &[u8],
    expected_length: usize,
) -> Result<(), AgentHostError> {
    validate_agent_host_lock_identity(file, path)?;
    validate_agent_host_lock_parent_identity(parent, path)?;
    if file
        .metadata()
        .map_err(|_| AgentHostError::Unavailable)?
        .len()
        != expected_length as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let end = file
        .seek(SeekFrom::End(0))
        .map_err(|_| AgentHostError::Unavailable)?;
    if end != expected_length as u64 {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    file.write_all(record)
        .map_err(|_| AgentHostError::Unavailable)?;
    file.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lock_identity(file, path)?;
    validate_agent_host_lock_parent_identity(parent, path)
}

fn recover_interrupted_agent_host_lease_arm(
    file: &mut File,
    path: &Path,
    parent: &File,
    fresh_binding: &[u8; HOST_LEASE_BINDING_LEN],
    migration_binding: &[u8; HOST_LEASE_BINDING_LEN],
) -> Result<(), AgentHostError> {
    validate_agent_host_lock_identity(file, path)?;
    validate_agent_host_lock_parent_identity(parent, path)?;
    if read_agent_host_lease_state(file, fresh_binding, migration_binding)?
        != AgentHostRootLeaseState::FreshArmInterrupted
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    file.set_len(HOST_LEASE_BINDING_LEN as u64)
        .map_err(|_| AgentHostError::Unavailable)?;
    file.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lock_identity(file, path)?;
    validate_agent_host_lock_parent_identity(parent, path)?;
    if read_agent_host_lease_state(file, fresh_binding, migration_binding)?
        != AgentHostRootLeaseState::FreshBound
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    Ok(())
}

fn open_agent_host_lock_parent(lock_path: &Path) -> Result<File, AgentHostError> {
    let parent_path = lock_path
        .parent()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    let parent = options
        .open(parent_path)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_lock_parent_identity(&parent, lock_path)?;
    Ok(parent)
}

fn validate_agent_host_lock_parent_identity(
    parent: &File,
    lock_path: &Path,
) -> Result<(), AgentHostError> {
    let parent_path = lock_path
        .parent()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    let opened = parent.metadata().map_err(|_| AgentHostError::Unavailable)?;
    let named =
        fs::symlink_metadata(parent_path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !opened.file_type().is_dir() || !named.file_type().is_dir() || named.file_type().is_symlink()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let effective_user = unsafe { libc::geteuid() };
        let trusted_owner = opened.uid() == 0 || opened.uid() == effective_user;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != named.uid()
            || opened.mode() != named.mode()
            || !trusted_owner
            || opened.mode() & 0o022 != 0
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
        for ancestor in parent_path
            .parent()
            .ok_or(AgentHostError::InvalidScopeBinding)?
            .ancestors()
        {
            let metadata =
                fs::symlink_metadata(ancestor).map_err(|_| AgentHostError::InvalidScopeBinding)?;
            let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_user || {
                #[cfg(target_os = "linux")]
                {
                    super::journal_store::uid_is_unmapped_overflow(metadata.uid())
                        .map_err(|_| AgentHostError::InvalidScopeBinding)?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            };
            let writable = metadata.mode() & 0o022 != 0;
            let protected_sticky = metadata.mode() & u32::from(libc::S_ISVTX) != 0 && trusted_owner;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || !trusted_owner
                || writable && !protected_sticky
            {
                return Err(AgentHostError::InvalidScopeBinding);
            }
        }
    }
    Ok(())
}

/// Deterministic crash-publication stage for the permanent outer Host lease.
/// Disabled-Agent startup treats this sibling as durable Agent residue too.
pub fn agent_host_lease_stage_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".next");
    path.with_file_name(name)
}

fn preflight_new_agent_host_lease(
    root: &Path,
    root_parent: &File,
    authority_root: &Path,
    authority_parent: &File,
) -> Result<(), AgentHostError> {
    validate_agent_host_lock_parent_identity(root_parent, root)?;
    let root_capability = agent_host_child_capability_path(root_parent, root);
    match fs::symlink_metadata(&root_capability) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            let directory = open_agent_host_root_directory_at(root_parent, root)?;
            validate_agent_host_root_identity(&directory, root)?;
            if fs::read_dir(agent_host_directory_capability_path(&directory))
                .map_err(|_| AgentHostError::Unavailable)?
                .next()
                .transpose()
                .map_err(|_| AgentHostError::Unavailable)?
                .is_some()
            {
                // With no authenticated outer binding, even Host metadata is
                // ambiguous restored/deleted state. Never install a new
                // binding over it; a second attempt fails identically.
                return Err(AgentHostError::InvalidScopeBinding);
            }
            validate_agent_host_root_identity(&directory, root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(AgentHostError::Unavailable),
    }
    validate_agent_host_lock_parent_identity(authority_parent, authority_root)?;
    let authority_capability = agent_host_child_capability_path(authority_parent, authority_root);
    match fs::symlink_metadata(authority_capability) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(AgentHostError::InvalidScopeBinding),
        Err(_) => Err(AgentHostError::Unavailable),
    }
}

fn open_agent_host_lease_file(
    path: &Path,
    parent: &File,
    expected_binding: &[u8; HOST_LEASE_BINDING_LEN],
    root: &Path,
    root_parent: &File,
    authority_root: &Path,
) -> Result<(File, bool), AgentHostError> {
    let stage_path = agent_host_lease_stage_path(path);
    let canonical_capability = agent_host_child_capability_path(parent, path);
    let stage_capability = agent_host_child_capability_path(parent, &stage_path);
    validate_agent_host_lock_parent_identity(parent, path)?;
    for _ in 0..3 {
        let canonical = fs::symlink_metadata(&canonical_capability);
        let stage = fs::symlink_metadata(&stage_capability);
        let canonical_exists = match canonical {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(AgentHostError::Unavailable),
        };
        let stage_exists = match stage {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(AgentHostError::Unavailable),
        };

        match (canonical_exists, stage_exists) {
            (true, false) => {
                let file = open_existing_agent_host_lease(&canonical_capability)?;
                validate_agent_host_lock_parent_identity(parent, path)?;
                validate_agent_host_lock_identity(&file, path)?;
                return Ok((file, false));
            }
            (true, true) => {
                let canonical = open_existing_agent_host_lease_alias(&canonical_capability, 2)?;
                let stage = open_existing_agent_host_lease_alias(&stage_capability, 2)?;
                if !same_agent_host_file_identity(&canonical, &stage)? {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
                FileExt::try_lock_exclusive(&canonical).map_err(map_agent_host_lock_error)?;
                validate_agent_host_lease_binding_file(&canonical, expected_binding, false)?;
                // Canonical + stage is the exact link-before-stage-unlink
                // publication crash.  Unlike a stage-only first binding,
                // its authenticated canonical record may already have been
                // followed by any valid FreshBound Host-tree prefix.
                // Classify that prefix read-only before removing the alias.
                validate_fresh_bound_tree_prefix(root, root_parent, authority_root, parent)?;
                validate_agent_host_lock_parent_identity(parent, path)?;
                remove_agent_host_lease_stage_at(parent, path, &stage_path)?;
                parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
                validate_agent_host_lock_identity(&canonical, path)?;
                validate_agent_host_lock_parent_identity(parent, path)?;
                return Ok((canonical, false));
            }
            (false, _) => {
                // A staged publication is recoverable only while the complete
                // data/authority boundary is still pristine. This preflight
                // precedes every write, including completion of a prefix.
                preflight_new_agent_host_lease(root, root_parent, authority_root, parent)?;
                let (mut stage, newly_created) = if stage_exists {
                    let stage = open_existing_agent_host_lease_alias(&stage_capability, 1)?;
                    validate_agent_host_lock_identity(&stage, &stage_path)?;
                    (stage, false)
                } else {
                    match create_agent_host_lease_stage_at(parent, path, &stage_path) {
                        Ok(file) => (file, true),
                        Err(AgentHostError::Conflict) => continue,
                        Err(error) => return Err(error),
                    }
                };
                FileExt::try_lock_exclusive(&stage).map_err(map_agent_host_lock_error)?;
                validate_agent_host_lock_parent_identity(parent, path)?;
                complete_agent_host_lease_binding_stage(
                    &mut stage,
                    &stage_path,
                    parent,
                    expected_binding,
                )?;
                publish_agent_host_lease_stage_at(parent, path, &stage_path)?;
                parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
                validate_agent_host_lease_alias_identity(&stage, path, &stage_path, 2)?;
                remove_agent_host_lease_stage_at(parent, path, &stage_path)?;
                parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
                validate_agent_host_lock_identity(&stage, path)?;
                validate_agent_host_lock_parent_identity(parent, path)?;
                return Ok((stage, newly_created));
            }
        }
    }
    Err(AgentHostError::DirectoryInUse)
}

fn map_agent_host_lock_error(error: std::io::Error) -> AgentHostError {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        AgentHostError::DirectoryInUse
    } else {
        AgentHostError::Unavailable
    }
}

fn open_existing_agent_host_lease(path: &Path) -> Result<File, AgentHostError> {
    let file = open_existing_agent_host_lease_alias(path, 1)?;
    FileExt::try_lock_exclusive(&file).map_err(map_agent_host_lock_error)?;
    validate_agent_host_lock_identity(&file, path)?;
    Ok(file)
}

fn open_existing_agent_host_lease_alias(
    path: &Path,
    expected_links: u64,
) -> Result<File, AgentHostError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_lease_alias_identity(&file, path, path, expected_links)?;
    Ok(file)
}

fn validate_agent_host_lease_alias_identity(
    file: &File,
    canonical_path: &Path,
    named_path: &Path,
    expected_links: u64,
) -> Result<(), AgentHostError> {
    let opened = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    let named =
        fs::symlink_metadata(named_path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !opened.file_type().is_file()
        || !named.file_type().is_file()
        || named.file_type().is_symlink()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let effective_user = unsafe { libc::geteuid() };
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.nlink() != expected_links
            || named.nlink() != expected_links
            || opened.uid() != effective_user
            || named.uid() != effective_user
            || opened.mode() & 0o022 != 0
            || named.mode() & 0o022 != 0
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
    }
    let parent = canonical_path
        .parent()
        .ok_or(AgentHostError::InvalidScopeBinding)?;
    if named_path.parent() != Some(parent) {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    Ok(())
}

fn same_agent_host_file_identity(left: &File, right: &File) -> Result<bool, AgentHostError> {
    let left = left.metadata().map_err(|_| AgentHostError::Unavailable)?;
    let right = right.metadata().map_err(|_| AgentHostError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        Err(AgentHostError::Unavailable)
    }
}

fn validate_agent_host_lease_binding_file(
    file: &File,
    expected: &[u8; HOST_LEASE_BINDING_LEN],
    allow_prefix: bool,
) -> Result<usize, AgentHostError> {
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| AgentHostError::Unavailable)?
            .len(),
    )
    .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if length > expected.len() || (!allow_prefix && length != expected.len()) {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut duplicate = file.try_clone().map_err(|_| AgentHostError::Unavailable)?;
    duplicate
        .seek(SeekFrom::Start(0))
        .map_err(|_| AgentHostError::Unavailable)?;
    let mut observed = vec![0; length];
    duplicate
        .read_exact(&mut observed)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if observed != expected[..length] {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    Ok(length)
}

fn complete_agent_host_lease_binding_stage(
    file: &mut File,
    stage_path: &Path,
    parent: &File,
    expected: &[u8; HOST_LEASE_BINDING_LEN],
) -> Result<(), AgentHostError> {
    validate_agent_host_lease_alias_identity(file, stage_path, stage_path, 1)?;
    let length = validate_agent_host_lease_binding_file(file, expected, true)?;
    file.seek(SeekFrom::Start(length as u64))
        .map_err(|_| AgentHostError::Unavailable)?;
    file.write_all(&expected[length..])
        .map_err(|_| AgentHostError::Unavailable)?;
    file.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lease_alias_identity(file, stage_path, stage_path, 1)?;
    validate_agent_host_lease_binding_file(file, expected, false)?;
    Ok(())
}

#[cfg(unix)]
fn lease_leaf(path: &Path) -> Result<std::ffi::CString, AgentHostError> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(
        path.file_name()
            .ok_or(AgentHostError::InvalidScopeBinding)?
            .as_bytes(),
    )
    .map_err(|_| AgentHostError::InvalidScopeBinding)
}

fn create_agent_host_lease_stage_at(
    parent: &File,
    canonical_path: &Path,
    stage_path: &Path,
) -> Result<File, AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let name = lease_leaf(stage_path)?;
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(AgentHostError::Conflict)
            } else {
                Err(AgentHostError::Unavailable)
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        validate_agent_host_lock_parent_identity(parent, canonical_path)?;
        validate_agent_host_lease_alias_identity(&file, stage_path, stage_path, 1)?;
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, canonical_path, stage_path);
        Err(AgentHostError::Unavailable)
    }
}

fn publish_agent_host_lease_stage_at(
    parent: &File,
    canonical_path: &Path,
    stage_path: &Path,
) -> Result<(), AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let canonical = lease_leaf(canonical_path)?;
        let stage = lease_leaf(stage_path)?;
        if unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                stage.as_ptr(),
                parent.as_raw_fd(),
                canonical.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(AgentHostError::Unavailable);
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, canonical_path, stage_path);
        Err(AgentHostError::Unavailable)
    }
}

fn remove_agent_host_lease_stage_at(
    parent: &File,
    canonical_path: &Path,
    stage_path: &Path,
) -> Result<(), AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let stage = lease_leaf(stage_path)?;
        if unsafe { libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), 0) } != 0 {
            return Err(AgentHostError::Unavailable);
        }
        validate_agent_host_lock_parent_identity(parent, canonical_path)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, canonical_path, stage_path);
        Err(AgentHostError::Unavailable)
    }
}

fn open_plain_agent_host_lock_file(path: &Path) -> Result<(File, bool), AgentHostError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let (file, created) = match options.open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                fs::symlink_metadata(path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            (
                options
                    .open(path)
                    .map_err(|_| AgentHostError::Unavailable)?,
                false,
            )
        }
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    validate_agent_host_lock_identity(&file, path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            AgentHostError::DirectoryInUse
        } else {
            AgentHostError::Unavailable
        }
    })?;
    validate_agent_host_lock_identity(&file, path)?;
    Ok((file, created))
}

fn validate_agent_host_lock_identity(file: &File, path: &Path) -> Result<(), AgentHostError> {
    let opened = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !opened.file_type().is_file()
        || !named.file_type().is_file()
        || named.file_type().is_symlink()
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let effective_user = unsafe { libc::geteuid() };
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.nlink() != 1
            || named.nlink() != 1
            || opened.uid() != effective_user
            || named.uid() != effective_user
            || opened.mode() & 0o022 != 0
            || named.mode() & 0o022 != 0
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
    }
    Ok(())
}

fn lock_agent_host_directory(
    root: &Path,
    root_directory: &File,
    allow_create: bool,
) -> Result<File, AgentHostError> {
    let path = root.join(HOST_LOCK_FILE);
    let capability = agent_host_directory_capability_path(root_directory).join(HOST_LOCK_FILE);
    if allow_create {
        return open_agent_host_lock_at(&capability, &path, root_directory);
    }
    open_existing_agent_host_lock_at(&capability, &path)
}

fn open_agent_host_lock_at(
    capability: &Path,
    named: &Path,
    parent: &File,
) -> Result<File, AgentHostError> {
    let (file, _created) = open_plain_agent_host_lock_file(capability)?;
    validate_agent_host_lock_identity(&file, named)?;
    // `allow_create` also authorizes retry of a prior create whose durability
    // sync failed, so re-sync both boundaries even when the leaf now exists.
    file.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    parent.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_lock_identity(&file, named)?;
    Ok(file)
}

fn open_existing_agent_host_lock_at(
    capability: &Path,
    named: &Path,
) -> Result<File, AgentHostError> {
    let file = open_existing_agent_host_lock(capability)?;
    validate_agent_host_lock_identity(&file, named)?;
    Ok(file)
}

fn open_existing_agent_host_lock(path: &Path) -> Result<File, AgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AgentHostError::InvalidScopeBinding
        } else {
            AgentHostError::Unavailable
        }
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_lock_identity(&file, path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            AgentHostError::DirectoryInUse
        } else {
            AgentHostError::Unavailable
        }
    })?;
    validate_agent_host_lock_identity(&file, path)?;
    Ok(file)
}

#[derive(Clone, Copy)]
enum AgentHostScopeState {
    Absent,
    Bound(AgentHostScope),
    BoundWithStage(AgentHostScope),
    Staged(AgentHostScope),
}

struct AgentHostScopeFile {
    scope: AgentHostScope,
    metadata: fs::Metadata,
}

impl AgentHostScopeState {
    const fn scope(self) -> Option<AgentHostScope> {
        match self {
            Self::Absent => None,
            Self::Bound(scope) | Self::BoundWithStage(scope) | Self::Staged(scope) => Some(scope),
        }
    }
}

fn read_agent_host_scope(
    root: &Path,
    root_directory: &File,
    requested: AgentHostScope,
    allow_partial_stage_recovery: bool,
) -> Result<AgentHostScopeState, AgentHostError> {
    let capability = agent_host_directory_capability_path(root_directory);
    let path = capability.join(HOST_SCOPE_FILE);
    let temp = capability.join(HOST_SCOPE_TEMP_FILE);
    let final_scope = read_agent_host_scope_file(&path)?;
    let staged_scope = match read_agent_host_scope_file(&temp) {
        Ok(scope) => scope,
        Err(AgentHostError::InvalidScopeBinding)
            if final_scope.is_none() && allow_partial_stage_recovery =>
        {
            Some(complete_agent_host_scope_prefix(
                root,
                root_directory,
                &temp,
                requested,
            )?)
        }
        Err(error) => return Err(error),
    };
    validate_agent_host_scope_link_state(final_scope.as_ref(), staged_scope.as_ref())?;
    match (final_scope, staged_scope) {
        (Some(bound), Some(staged)) => {
            if bound.scope != staged.scope {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            if bound.scope != requested {
                return Err(AgentHostError::ScopeMismatch);
            }
            Ok(AgentHostScopeState::BoundWithStage(bound.scope))
        }
        (Some(bound), None) => Ok(AgentHostScopeState::Bound(bound.scope)),
        (None, Some(staged)) => {
            if staged.scope != requested {
                return Err(AgentHostError::ScopeMismatch);
            }
            Ok(AgentHostScopeState::Staged(staged.scope))
        }
        (None, None) => Ok(AgentHostScopeState::Absent),
    }
}

fn cleanup_agent_host_scope_stage(
    _root: &Path,
    root_directory: &File,
) -> Result<(), AgentHostError> {
    let capability = agent_host_directory_capability_path(root_directory);
    let path = capability.join(HOST_SCOPE_FILE);
    let temp = capability.join(HOST_SCOPE_TEMP_FILE);
    let bound = read_agent_host_scope_file(&path)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    let staged = read_agent_host_scope_file(&temp)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_scope_link_state(Some(&bound), Some(&staged))?;
    if bound.scope != staged.scope {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    fs::remove_file(temp).map_err(|_| AgentHostError::Unavailable)?;
    root_directory
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    let final_scope =
        read_agent_host_scope_file(&path)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_scope_link_state(Some(&final_scope), None)
}

fn read_agent_host_scope_file(path: &Path) -> Result<Option<AgentHostScopeFile>, AgentHostError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AgentHostError::Unavailable),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| AgentHostError::Unavailable)?;
    let opened_metadata = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    validate_agent_host_scope_metadata(&opened_metadata, &metadata)?;
    let mut encoded = [0; HOST_SCOPE_ENCODED_LEN];
    file.read_exact(&mut encoded)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?
        != 0
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    if &encoded[..HOST_SCOPE_MAGIC.len()] != HOST_SCOPE_MAGIC {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut space = [0; 32];
    space.copy_from_slice(&encoded[HOST_SCOPE_MAGIC.len()..HOST_SCOPE_MAGIC.len() + 32]);
    let mut node = [0; 32];
    node.copy_from_slice(&encoded[HOST_SCOPE_MAGIC.len() + 32..]);
    Ok(Some(AgentHostScopeFile {
        scope: AgentHostScope {
            space: SpaceId(space),
            node: NodeId(node),
        },
        metadata: opened_metadata,
    }))
}

fn validate_agent_host_scope_link_state(
    final_scope: Option<&AgentHostScopeFile>,
    staged_scope: Option<&AgentHostScopeFile>,
) -> Result<(), AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        match (final_scope, staged_scope) {
            (Some(final_scope), Some(staged_scope)) => {
                if final_scope.metadata.dev() != staged_scope.metadata.dev()
                    || final_scope.metadata.ino() != staged_scope.metadata.ino()
                    || final_scope.metadata.nlink() != 2
                    || staged_scope.metadata.nlink() != 2
                {
                    return Err(AgentHostError::InvalidScopeBinding);
                }
            }
            (Some(scope), None) | (None, Some(scope)) if scope.metadata.nlink() != 1 => {
                return Err(AgentHostError::InvalidScopeBinding);
            }
            _ => {}
        }
    }
    #[cfg(not(unix))]
    if final_scope.is_some() && staged_scope.is_some() {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    Ok(())
}

fn validate_agent_host_scope_single_link(metadata: &fs::Metadata) -> Result<(), AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(AgentHostError::InvalidScopeBinding);
        }
    }
    Ok(())
}

fn encoded_agent_host_scope(scope: AgentHostScope) -> [u8; HOST_SCOPE_ENCODED_LEN] {
    let mut encoded = [0; HOST_SCOPE_ENCODED_LEN];
    encoded[..HOST_SCOPE_MAGIC.len()].copy_from_slice(HOST_SCOPE_MAGIC);
    encoded[HOST_SCOPE_MAGIC.len()..HOST_SCOPE_MAGIC.len() + 32].copy_from_slice(&scope.space.0);
    encoded[HOST_SCOPE_MAGIC.len() + 32..].copy_from_slice(&scope.node.0);
    encoded
}

fn validate_agent_host_scope_metadata(
    opened: &fs::Metadata,
    named: &fs::Metadata,
) -> Result<(), AgentHostError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_user = unsafe { libc::geteuid() };
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != effective_user
            || named.uid() != effective_user
            || opened.mode() & 0o022 != 0
            || named.mode() & 0o022 != 0
        {
            return Err(AgentHostError::InvalidScopeBinding);
        }
    }
    Ok(())
}

fn complete_agent_host_scope_prefix(
    _root: &Path,
    root_directory: &File,
    temp: &Path,
    scope: AgentHostScope,
) -> Result<AgentHostScopeFile, AgentHostError> {
    let metadata = fs::symlink_metadata(temp).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() >= HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(temp)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let opened = file.metadata().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_scope_metadata(&opened, &metadata)?;
    validate_agent_host_scope_single_link(&opened)?;
    let expected = encoded_agent_host_scope(scope);
    let length = usize::try_from(opened.len()).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let mut prefix = vec![0; length];
    file.read_exact(&mut prefix)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if prefix != expected[..length] {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    file.seek(SeekFrom::Start(length as u64))
        .and_then(|_| file.write_all(&expected[length..]))
        .and_then(|_| file.sync_all())
        .map_err(|_| AgentHostError::Unavailable)?;
    root_directory
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    read_agent_host_scope_file(temp)?.ok_or(AgentHostError::InvalidScopeBinding)
}

fn write_agent_host_scope(
    _root: &Path,
    root_directory: &File,
    scope: AgentHostScope,
) -> Result<(), AgentHostError> {
    let capability = agent_host_directory_capability_path(root_directory);
    let temp = capability.join(HOST_SCOPE_TEMP_FILE);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    file.write_all(&encoded_agent_host_scope(scope))
        .and_then(|()| file.sync_all())
        .map_err(|_| AgentHostError::Unavailable)?;
    root_directory
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    publish_agent_host_scope(_root, root_directory)
}

fn publish_agent_host_scope(_root: &Path, root_directory: &File) -> Result<(), AgentHostError> {
    let capability = agent_host_directory_capability_path(root_directory);
    let temp = capability.join(HOST_SCOPE_TEMP_FILE);
    let path = capability.join(HOST_SCOPE_FILE);
    // A recovered staging inode may predate this process. Re-establish its
    // durability before making it the canonical binding, even though the
    // ordinary writer already synced it before reaching this helper.
    let staged_metadata =
        fs::symlink_metadata(&temp).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    if !staged_metadata.file_type().is_file()
        || staged_metadata.file_type().is_symlink()
        || staged_metadata.len() != HOST_SCOPE_ENCODED_LEN as u64
    {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let staged = options
        .open(&temp)
        .map_err(|_| AgentHostError::InvalidScopeBinding)?;
    let metadata = staged.metadata().map_err(|_| AgentHostError::Unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() != HOST_SCOPE_ENCODED_LEN as u64 {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    staged.sync_all().map_err(|_| AgentHostError::Unavailable)?;
    validate_agent_host_scope_metadata(&metadata, &staged_metadata)?;
    validate_agent_host_scope_single_link(&metadata)?;
    fs::hard_link(&temp, &path).map_err(|_| AgentHostError::InvalidScopeBinding)?;
    root_directory
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    let canonical =
        read_agent_host_scope_file(&path)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    let staged = read_agent_host_scope_file(&temp)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_scope_link_state(Some(&canonical), Some(&staged))?;
    if canonical.scope != staged.scope {
        return Err(AgentHostError::InvalidScopeBinding);
    }
    fs::remove_file(temp).map_err(|_| AgentHostError::Unavailable)?;
    root_directory
        .sync_all()
        .map_err(|_| AgentHostError::Unavailable)?;
    let canonical =
        read_agent_host_scope_file(&path)?.ok_or(AgentHostError::InvalidScopeBinding)?;
    validate_agent_host_scope_link_state(Some(&canonical), None)
}

fn encode_agent_id(agent: AgentId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in agent.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_agent_id(input: &str) -> Option<AgentId> {
    if input.len() != 64 || !input.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(AgentId(bytes))
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SpaceId;

    #[test]
    fn invocation_reservation_uses_caller_availability_not_inline_state_limit() {
        let bytes = vec![0x61; MAX_EXECUTION_AVAILABILITY_BYTES];
        let mut invocation = ActorInvocation {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([3; 32]),
            deployment: DeploymentId([4; 32]),
            program: ProgramId([5; 32]),
            mode: super::super::MethodMode::Linear,
            auth: super::super::execution::ActorInvocationAuth::anonymous(),
            message: vec![1],
            gas: 1,
            availability: vec![RuntimeBlob {
                reference: crate::service::BlobRef::of_bytes(&bytes),
                bytes,
            }],
        };
        assert!(validate_invocation_shape_before_reservation(&invocation).is_ok());
        assert!(invocation.validate().is_ok());
        invocation.availability[0].bytes.push(1);
        assert!(validate_invocation_shape_before_reservation(&invocation).is_err());
        invocation.availability[0].bytes.pop();
        invocation.availability.push(RuntimeBlob {
            reference: crate::service::BlobRef::of_bytes(&[2]),
            bytes: vec![2],
        });
        assert!(validate_invocation_shape_before_reservation(&invocation).is_err());
    }

    struct NoTrust;

    impl AgentTrustProvider for NoTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            None
        }

        fn authority_for_space(
            &self,
            _space: SpaceId,
        ) -> Option<super::super::authority::AgentAuthorityBinding> {
            None
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            false
        }
    }

    struct NoMerge(NodeId);

    impl LocalMergeAuthenticator for NoMerge {
        fn node(&self) -> NodeId {
            self.0
        }

        fn sign_event(&self, _event: &mut super::super::journal::MergeEvent) -> bool {
            false
        }

        fn verify_event(&self, _event: &super::super::journal::MergeEvent) -> bool {
            false
        }
    }

    struct NoGenesis;

    impl SystemAgentGenesisProvider for NoGenesis {
        fn create(
            &self,
            _proposal: &SystemAgentGenesisProposal,
            _catalog: &[RuntimeBlob],
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            Err(SystemAgentGenesisProviderError::NotConfigured)
        }

        fn reproduce(
            &self,
            _locator: SystemAgentGenesisLocator,
        ) -> Result<
            super::super::bootstrap::SystemAgentGenesisProvision,
            SystemAgentGenesisProviderError,
        > {
            Err(SystemAgentGenesisProviderError::NotConfigured)
        }

        fn load_catalog(
            &self,
            _locator: SystemAgentGenesisLocator,
            _reference: &BlobRef,
        ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
            Ok(None)
        }
    }

    fn test_system_agent() -> AgentId {
        AgentId([9; 32])
    }

    fn test_root_pins(scope: AgentHostScope) -> RootAnchorPins {
        use super::super::committee::{
            AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
            AuthorityCommitteeMember, AuthorityMemberRole, RootAnchorRecord,
        };

        let authority_binding = Hash([0x41; 32]);
        let member = AuthorityCommitteeMember::new(
            NodeId([0x42; 32]),
            [0x43; 32],
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let committee =
            AuthorityCommittee::new(scope.space, authority_binding, 1, None, vec![member]).unwrap();
        let root_record = RootAnchorRecord::new(
            1,
            scope.space,
            test_system_agent(),
            authority_binding,
            Hash([0x44; 32]),
            committee,
        )
        .unwrap();
        let claim = AuthorityClaimCommitment::from_payload_commitment(
            AuthorityClaimDomain::SystemAgentGenesis,
            1,
            Hash([0x45; 32]),
        )
        .unwrap();
        RootAnchorPins::new(
            root_record.clone(),
            root_record.config_version(),
            root_record.id(),
            root_record.config_commitment(),
            claim,
        )
        .unwrap()
    }

    fn open_empty_control(lease: AgentHostRootLease) -> Result<AgentHostControl, AgentHostError> {
        let scope = lease.scope();
        AgentHostControl::open(
            lease,
            Arc::new(NoTrust),
            Arc::new(NoMerge(scope.node)),
            Arc::new(NoGenesis),
            test_root_pins(scope),
        )
    }

    fn open_empty_control_with_capacity(
        lease: AgentHostRootLease,
        capacity: usize,
    ) -> Result<AgentHostControl, AgentHostError> {
        let scope = lease.scope();
        AgentHostControl::open_with_queue_capacity(
            lease,
            Arc::new(NoTrust),
            Arc::new(NoMerge(scope.node)),
            Arc::new(NoGenesis),
            test_root_pins(scope),
            capacity,
        )
    }

    struct RemoveOnDrop(PathBuf);

    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn empty_host_directory(test: &str) -> (PathBuf, PathBuf, RemoveOnDrop) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "vos-agent-host-{test}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        (
            base.join("data"),
            base.join("owner.lock"),
            RemoveOnDrop(base),
        )
    }

    fn scope() -> AgentHostScope {
        AgentHostScope {
            space: SpaceId([1; 32]),
            node: NodeId([2; 32]),
        }
    }

    fn lease(root: &Path, lock: &Path, scope: AgentHostScope) -> AgentHostRootLease {
        AgentHostRootLease::acquire(root, lock, scope).unwrap()
    }

    fn encoded_scope(scope: AgentHostScope) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(HOST_SCOPE_MAGIC);
        encoded.extend_from_slice(&scope.space.0);
        encoded.extend_from_slice(&scope.node.0);
        encoded
    }

    fn payload_test_runtime_package() -> Package {
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
        let generated_interfaces = b"agent-runtime-lifecycle".to_vec();
        let schemas = b"agent-runtime-schema".to_vec();
        let public_key = b"payload-test-producer".to_vec();
        let package = Package {
            manifest: super::super::package::PackageManifest {
                name: "payload-test-runtime".into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: super::super::PackageKind::AgentRuntime {
                    contract: super::super::contract::RuntimePackageContract::canonical(),
                    capabilities: super::super::RuntimeCapabilities::standard(),
                },
                program: crate::service::ProgramId::of_pvm(&pvm),
                interfaces_hash: crate::service::artifact_hash(
                    b"interfaces",
                    &generated_interfaces,
                ),
                role_policies_hash: crate::service::artifact_hash(b"role-policies", &[]),
                schemas_hash: crate::service::artifact_hash(b"schemas", &schemas),
                agent_schema_hash: crate::service::artifact_hash(b"agent-schema", &[]),
                dependencies_hash: crate::service::task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: crate::service::DeploymentSignature {
                producer: crate::service::ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![1],
            },
        };
        package.validate().unwrap();
        package
    }

    fn payload_test_authority(agent: AgentId) -> AgentAuthorityBinding {
        let public_key = super::super::authority::ed25519_public_key_wire([0x71; 32]);
        AgentAuthorityBinding {
            agent,
            actor: ActorId([0x72; 32]),
            deployment: DeploymentId([0x73; 32]),
            program: ProgramId([0x74; 32]),
            producer: crate::service::ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn payload_test_config(
        runtime_package: &Package,
        replicas: Vec<super::super::AgentReplica>,
    ) -> AgentConfig {
        let owner = crate::service::PrincipalId([0x75; 32]);
        let creation_nonce = Hash([0x76; 32]);
        let agent = AgentId::derive(scope().space, owner, &creation_nonce.0);
        AgentConfig {
            identity: AgentIdentity {
                space: scope().space,
                agent,
                owner,
                profile: super::super::AgentProfile::Local,
                runtime_deployment: DeploymentId([0x77; 32]),
                runtime_program: runtime_package.manifest.program,
                runtime_producer: runtime_package.deployment_signature.producer,
                transition_producer: crate::service::ProducerId([0x79; 32]),
            },
            creation_nonce,
            authority: payload_test_authority(agent),
            system_authority_genesis: None,
            runtime_package: crate::service::BlobRef {
                hash: Hash([0x78; 32]),
                len: 1,
            },
            runtime_contract: super::super::contract::RuntimePackageContract::canonical(),
            capabilities: super::super::RuntimeCapabilities::standard(),
            replicas,
        }
    }

    fn payload_test_invocation_receipt(agent: AgentId) -> ActorInvocationReceipt {
        ActorInvocationReceipt {
            claim: super::super::authority::ActorInvocationClaim {
                authority: payload_test_authority(agent),
                space: scope().space,
                agent,
                principal: None,
                credential: None,
                authorization: Hash([0x79; 32]),
                auth: super::super::execution::ActorInvocationAuth::anonymous(),
                valid_from: 1,
                valid_until: 2,
            },
            signature: vec![0; super::super::authority::ED25519_SIGNATURE_BYTES],
        }
    }

    fn wait_for_payload(handle: &AgentHostHandle, predicate: impl Fn(usize) -> bool) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let payload = handle.admitted_payload_bytes_for_test();
            if predicate(payload) {
                return payload;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for Agent-host payload reservation; current={payload}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn agent_journal_names_are_canonical() {
        let agent = AgentId([0xab; 32]);
        let encoded = encode_agent_id(agent);
        assert_eq!(encoded.len(), 64);
        assert_eq!(decode_agent_id(&encoded), Some(agent));
        assert_eq!(decode_agent_id(&encoded.to_uppercase()), None);
        assert_eq!(decode_agent_id("ab"), None);
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    #[test]
    fn authority_namespaces_isolate_the_same_agent_across_scopes_and_roots() {
        let (first_root, first_lock, _remove) = empty_host_directory("authority-isolation");
        let parent = first_root.parent().unwrap();
        let second_root = parent.join("second-data");
        let second_lock = parent.join("second-owner.lock");
        let second_scope = AgentHostScope {
            space: SpaceId([9; 32]),
            node: scope().node,
        };
        let first_lease = lease(&first_root, &first_lock, scope());
        let second_lease = lease(&second_root, &second_lock, second_scope);
        let first_authority = first_lease.authority_root().unwrap().to_path_buf();
        let second_authority = second_lease.authority_root().unwrap().to_path_buf();
        assert_ne!(first_authority, second_authority);

        let agent = test_system_agent();
        let leaf = format!("{}{}", encode_agent_id(agent), JOURNAL_LOCK_SUFFIX);
        let first_slot = FileAgentJournalSlot::acquire(
            first_root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX)),
            first_authority.join(&leaf),
            scope().node,
        )
        .unwrap();
        let second_slot = FileAgentJournalSlot::acquire(
            second_root.join(format!("{}{}", encode_agent_id(agent), JOURNAL_SUFFIX)),
            second_authority.join(&leaf),
            second_scope.node,
        )
        .unwrap();
        assert_ne!(first_slot.instance_id(), second_slot.instance_id());
        assert!(first_authority.join(&leaf).is_file());
        assert!(second_authority.join(&leaf).is_file());
    }

    #[cfg(all(feature = "storage", target_os = "linux"))]
    #[test]
    fn armed_lease_quarantines_missing_and_recreated_root() {
        let (directory, lock, _remove) = empty_host_directory("outer-lease-root-deletion");
        let mut initialized = lease(&directory, &lock, scope());
        initialized.arm_after_agent_open().unwrap();
        drop(initialized);

        fs::remove_dir_all(&directory).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(
            !directory.exists(),
            "acquire must not recreate an armed root"
        );

        fs::create_dir(&directory).unwrap();
        fs::write(directory.join(HOST_SCOPE_FILE), encoded_scope(scope())).unwrap();
        let error = open_empty_control(lease(&directory, &lock, scope())).unwrap_err();
        assert_eq!(error, AgentHostError::InvalidScopeBinding);
        assert!(!directory.join(HOST_LOCK_FILE).exists());
        assert_eq!(
            fs::read(directory.join(HOST_SCOPE_FILE)).unwrap(),
            encoded_scope(scope())
        );
    }

    #[test]
    fn retired_images_and_unarchived_lock_residue_fail_closed() {
        let (directory, lock, _remove) = empty_host_directory("retired-generation");
        let first = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        first.shutdown().unwrap();
        fs::write(
            directory.join(format!(
                "{}{}",
                encode_agent_id(test_system_agent()),
                LEGACY_IMAGE_SUFFIX
            )),
            b"retired image",
        )
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::LegacyGeneration)
        ));

        fs::remove_file(directory.join(format!(
            "{}{}",
            encode_agent_id(test_system_agent()),
            LEGACY_IMAGE_SUFFIX
        )))
        .unwrap();
        fs::write(
            directory.join(format!(
                "{}{}",
                encode_agent_id(test_system_agent()),
                JOURNAL_LOCK_SUFFIX
            )),
            b"orphan lock",
        )
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn generation_aliases_are_rejected_instead_of_ignored() {
        let (directory, lock, _remove) = empty_host_directory("generation-aliases");
        let first = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        first.shutdown().unwrap();
        let encoded = encode_agent_id(test_system_agent());

        let uppercase_journal = directory.join(format!("{encoded}.AGENT"));
        fs::create_dir(&uppercase_journal).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&uppercase_journal).unwrap();

        let uppercase_lock = directory.join(format!("{encoded}.AGENT-LOCK"));
        fs::write(&uppercase_lock, b"alias").unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        fs::remove_file(&uppercase_lock).unwrap();

        for suffix in [
            ".SYSTEM-AUTHORITY-LEDGER.REDB",
            ".SYSTEM-AUTHORITY-LEDGER.REDB.NEXT",
        ] {
            let uppercase_ledger = directory.join(format!("{encoded}{suffix}"));
            fs::write(&uppercase_ledger, b"authority alias").unwrap();
            assert!(matches!(
                open_empty_control(lease(&directory, &lock, scope())),
                Err(AgentHostError::InvalidScopeBinding)
            ));
            fs::remove_file(&uppercase_ledger).unwrap();
        }

        let uppercase_legacy = directory.join(format!("{encoded}.AGENT-IMAGE"));
        fs::write(&uppercase_legacy, b"retired alias").unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::LegacyGeneration)
        ));
        fs::remove_file(&uppercase_legacy).unwrap();

        let uppercase_id = directory.join(format!(
            "{}.agent",
            encode_agent_id(AgentId([0xab; 32])).to_uppercase()
        ));
        fs::create_dir(&uppercase_id).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&uppercase_id).unwrap();

        let malformed = directory.join("not-an-agent.agent");
        fs::create_dir(&malformed).unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidJournalName)
        ));
        fs::remove_dir(&malformed).unwrap();

        // The exact host lock and durable scope metadata remain admitted.
        let reopened = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        reopened.shutdown().unwrap();
    }

    #[test]
    fn worker_handle_is_bounded_and_shutdown_is_terminal() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send::<AgentHostControl>();
        assert_send_sync::<AgentHostHandle>();

        let (directory, lock, _remove) = empty_host_directory("bounded-worker");
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 1).unwrap();
        let handle = control.handle_for_test();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread = thread::spawn(move || {
            active_handle.request(0, move |_| {
                active.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        active_rx.recv().unwrap();
        assert_eq!(handle.idle_for(), Duration::ZERO);

        let (queued_reply, queued_result) = mpsc::sync_channel(1);
        handle
            .commands
            .try_send(AgentHostCommand::Run {
                job: Box::new(move |host| {
                    queued_reply
                        .send(if host.is_some() {
                            Ok(())
                        } else {
                            Err(AgentHostError::ShuttingDown)
                        })
                        .unwrap();
                }),
                activity: AgentHostActivity::reserve(&handle, 1024).unwrap(),
            })
            .map_err(|_| ())
            .unwrap();
        let admitted_before_full_send = handle.admitted_payload_bytes_for_test();
        assert_eq!(handle.identities(), Err(AgentHostError::Overloaded));
        assert_eq!(
            handle.admitted_payload_bytes_for_test(),
            admitted_before_full_send,
            "a full command channel must release the rejected reservation"
        );

        control.request_shutdown();
        assert_eq!(handle.identities(), Err(AgentHostError::ShuttingDown));
        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        assert_eq!(
            queued_result.recv().unwrap(),
            Err(AgentHostError::ShuttingDown)
        );
        control.shutdown().unwrap();
        assert_eq!(handle.admitted_payload_bytes_for_test(), 0);
        assert_eq!(handle.identities(), Err(AgentHostError::WorkerStopped));
    }

    #[test]
    fn worker_payload_budget_backpressures_and_releases_on_completion() {
        let (directory, lock, _remove) = empty_host_directory("payload-budget");
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 4).unwrap();
        let handle = control.handle_for_test();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread = thread::spawn(move || {
            active_handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, move |_| {
                active.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        active_rx.recv().unwrap();
        let admitted = handle.admitted_payload_bytes_for_test();
        assert!(admitted > DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2);
        assert_eq!(
            handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, |_| Ok(())),
            Err(AgentHostError::Overloaded)
        );
        assert_eq!(handle.admitted_payload_bytes_for_test(), admitted);

        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        wait_for_payload(&handle, |payload| payload == 0);
        assert_eq!(
            handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 2, |_| Ok(())),
            Ok(())
        );
        wait_for_payload(&handle, |payload| payload == 0);
        control.shutdown().unwrap();
    }

    #[test]
    fn nested_package_capacity_is_rejected_without_leaking_reservation() {
        let (directory, lock, _remove) = empty_host_directory("nested-payload-budget");
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        let handle = control.handle_for_test();

        let mut package = payload_test_runtime_package();
        package.diagnostics = Some(crate::service::PackageDiagnostics {
            // Length remains zero, so the package's canonical wire is small;
            // retaining its caller-selected spare capacity is what admission
            // must account for.
            elf: Some(Vec::with_capacity(
                DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES + 1,
            )),
            source_map: Some(Vec::with_capacity(1024)),
        });
        package.task_dependencies = Vec::with_capacity(256);
        assert!(package.validate().is_ok());
        assert!(package_heap_payload_bytes(&package) > DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES);

        assert_eq!(
            handle.prepare_runtime_upgrade(AgentId([3; 32]), DeploymentId([4; 32]), package,),
            Err(AgentHostError::Overloaded)
        );
        assert_eq!(handle.admitted_payload_bytes_for_test(), 0);

        // Dependency programs are nested allocations, separate from the outer
        // dependency-vector storage. Keep a direct regression assertion even
        // though runtime packages correctly reject non-empty dependencies.
        let mut nested = payload_test_runtime_package();
        let dependency_program = Vec::with_capacity(4 * 1024 * 1024);
        nested
            .task_dependencies
            .push(crate::service::PackageTaskDependency {
                binding: crate::service::TaskDependency {
                    task: Hash([5; 32]),
                    program: crate::service::ProgramId([6; 32]),
                    witness_address: 1,
                    witness_capacity: 1,
                },
                pvm: dependency_program,
            });
        assert!(
            package_heap_payload_bytes(&nested)
                >= nested.task_dependencies[0].pvm.capacity().saturating_add(
                    vector_allocation_bytes::<crate::service::PackageTaskDependency>(
                        nested.task_dependencies.capacity()
                    )
                )
        );

        control.shutdown().unwrap();
    }

    #[test]
    fn oversized_shapes_are_rejected_before_worker_or_payload_admission() {
        const SHAPE_STRESS_ITEMS: usize = 65_536;

        let runtime_package = payload_test_runtime_package();
        let replica = super::super::AgentReplica {
            node: scope().node,
            principal: crate::service::PrincipalId([0x7a; 32]),
            role: super::super::ReplicaRole::Voter,
        };
        let oversized_config =
            payload_test_config(&runtime_package, vec![replica; SHAPE_STRESS_ITEMS]);

        let mut oversized_dependencies = payload_test_runtime_package();
        let dependency = crate::service::PackageTaskDependency {
            binding: crate::service::TaskDependency {
                task: Hash([0x7b; 32]),
                program: ProgramId([0x7c; 32]),
                witness_address: 1,
                witness_capacity: 1,
            },
            pvm: Vec::new(),
        };
        oversized_dependencies.task_dependencies = vec![dependency; SHAPE_STRESS_ITEMS];

        let invocation_agent = AgentId([0x7d; 32]);
        let blob = super::super::execution::RuntimeBlob {
            reference: crate::service::BlobRef {
                hash: Hash([0x7e; 32]),
                len: 0,
            },
            bytes: Vec::new(),
        };
        let oversized_invocation = ActorInvocation {
            invocation: InvocationId([0x7f; 32]),
            actor: ActorId([0x80; 32]),
            incarnation: Hash([0x83; 32]),
            deployment: DeploymentId([0x81; 32]),
            program: ProgramId([0x82; 32]),
            mode: super::super::MethodMode::Query,
            auth: super::super::execution::ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: vec![blob; SHAPE_STRESS_ITEMS],
            gas: 1,
        };
        let invocation_receipt = payload_test_invocation_receipt(invocation_agent);

        let (directory, lock, _remove) = empty_host_directory("oversized-shapes");
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        let handle = control.handle_for_test();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let active_handle = handle.clone();
        let active_thread =
            thread::spawn(move || active_handle.block_worker_for_test(active, release_rx));
        active_rx.recv().unwrap();
        let active_payload = handle.admitted_payload_bytes_for_test();

        let (done, done_rx) = mpsc::sync_channel(1);
        let shape_handle = handle.clone();
        let shape_thread = thread::spawn(move || {
            let config_result = shape_handle.prepare_create(oversized_config, runtime_package);
            let payload_after_config = shape_handle.admitted_payload_bytes_for_test();
            let package_result = shape_handle.prepare_runtime_upgrade(
                AgentId([0x83; 32]),
                DeploymentId([0x84; 32]),
                oversized_dependencies,
            );
            let payload_after_package = shape_handle.admitted_payload_bytes_for_test();
            let invocation_result =
                shape_handle.invoke(invocation_agent, oversized_invocation, invocation_receipt);
            let payload_after_invocation = shape_handle.admitted_payload_bytes_for_test();
            done.send((
                config_result,
                payload_after_config,
                package_result,
                payload_after_package,
                invocation_result,
                payload_after_invocation,
            ))
            .unwrap();
        });

        let outcome = done_rx.recv_timeout(Duration::from_secs(5));
        if outcome.is_err() {
            let payload = handle.admitted_payload_bytes_for_test();
            release.send(()).unwrap();
            assert_eq!(active_thread.join().unwrap(), Ok(()));
            shape_thread.join().unwrap();
            control.shutdown().unwrap();
            panic!("oversized shape reached the serialized worker; admitted payload was {payload}");
        }
        let (
            config_result,
            payload_after_config,
            package_result,
            payload_after_package,
            invocation_result,
            payload_after_invocation,
        ) = outcome.unwrap();
        assert_eq!(config_result, Err(AgentHostError::ScopeMismatch));
        assert_eq!(payload_after_config, active_payload);
        assert_eq!(
            package_result,
            Err(invalid_package_shape(PackageError::ArtifactsTooLarge))
        );
        assert_eq!(payload_after_package, active_payload);
        assert_eq!(invocation_result, Err(invalid_invocation_shape()));
        assert_eq!(payload_after_invocation, active_payload);

        release.send(()).unwrap();
        assert_eq!(active_thread.join().unwrap(), Ok(()));
        shape_thread.join().unwrap();
        wait_for_payload(&handle, |payload| payload == 0);
        control.shutdown().unwrap();
    }

    #[test]
    fn worker_panic_releases_active_and_queued_payload() {
        let (directory, lock, _remove) = empty_host_directory("payload-panic");
        let control =
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 4).unwrap();
        let handle = control.handle_for_test();

        let (active, active_rx) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let crashing_handle = handle.clone();
        let crashing = thread::spawn(move || {
            crashing_handle.request(
                DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 4,
                move |_| -> Result<(), AgentHostError> {
                    active.send(()).unwrap();
                    release_rx.recv().unwrap();
                    panic!("intentional Agent-host payload cleanup crash")
                },
            )
        });
        active_rx.recv().unwrap();
        let active_payload = handle.admitted_payload_bytes_for_test();

        let queued_handle = handle.clone();
        let queued = thread::spawn(move || {
            queued_handle.request(DEFAULT_AGENT_HOST_PAYLOAD_CAPACITY_BYTES / 4, |_| Ok(()))
        });
        wait_for_payload(&handle, |payload| payload > active_payload);
        release.send(()).unwrap();

        assert_eq!(crashing.join().unwrap(), Err(AgentHostError::WorkerStopped));
        assert_eq!(queued.join().unwrap(), Err(AgentHostError::WorkerStopped));
        wait_for_payload(&handle, |payload| payload == 0);
        assert_eq!(control.shutdown(), Err(AgentHostError::WorkerPanicked));
    }

    #[test]
    fn zero_capacity_is_rejected() {
        let (directory, lock, _remove) = empty_host_directory("zero-capacity");
        assert!(matches!(
            open_empty_control_with_capacity(lease(&directory, &lock, scope()), 0),
            Err(AgentHostError::InvalidQueueCapacity)
        ));
    }

    #[test]
    fn zero_or_partial_scope_is_rejected() {
        let (directory, lock, _remove) = empty_host_directory("invalid-scope");
        assert!(matches!(
            AgentHostRootLease::acquire(
                &directory,
                &lock,
                AgentHostScope {
                    space: SpaceId::ZERO,
                    node: NodeId([2; 32]),
                },
            ),
            Err(AgentHostError::InvalidScope)
        ));
        assert!(matches!(
            AgentHostRootLease::acquire(
                directory,
                lock,
                AgentHostScope {
                    space: SpaceId([1; 32]),
                    node: NodeId::ZERO,
                },
            ),
            Err(AgentHostError::InvalidScope)
        ));
    }

    #[test]
    fn directory_scope_is_durable_and_has_one_live_owner() {
        let (directory, lock, _remove) = empty_host_directory("directory-owner");
        let control = open_empty_control(lease(&directory, &lock, scope())).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));
        let moved = directory.with_extension("live-root");
        fs::rename(&directory, &moved).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));
        assert!(
            !directory.exists(),
            "a losing lease acquisition must not recreate the live owner's renamed root"
        );
        fs::rename(&moved, &directory).unwrap();
        control.shutdown().unwrap();

        let wrong_scope = AgentHostScope {
            space: scope().space,
            node: NodeId([3; 32]),
        };
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, wrong_scope),
            Err(AgentHostError::ScopeMismatch)
        ));

        open_empty_control(lease(&directory, &lock, scope()))
            .unwrap()
            .shutdown()
            .unwrap();
    }

    #[test]
    fn stable_lease_binding_is_immutable_for_root_and_scope() {
        let (directory, lock, _remove) = empty_host_directory("lease-binding");
        drop(lease(&directory, &lock, scope()));
        assert_eq!(
            fs::metadata(&lock).unwrap().len(),
            HOST_LEASE_BINDING_LEN as u64
        );

        let other_root = directory.with_extension("other-root");
        assert!(matches!(
            AgentHostRootLease::acquire(&other_root, &lock, scope()),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!other_root.exists());

        let wrong_scope = AgentHostScope {
            space: scope().space,
            node: NodeId([3; 32]),
        };
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, wrong_scope),
            Err(AgentHostError::ScopeMismatch)
        ));
        assert_eq!(
            fs::metadata(&lock).unwrap().len(),
            HOST_LEASE_BINDING_LEN as u64
        );
    }

    #[test]
    fn lease_pins_root_inode_before_host_open() {
        let (directory, lock, _remove) = empty_host_directory("lease-root-inode");
        let root_lease = lease(&directory, &lock, scope());
        let displaced = directory.with_extension("displaced");
        fs::rename(&directory, &displaced).unwrap();
        fs::create_dir(&directory).unwrap();

        assert!(matches!(
            open_empty_control(root_lease),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn stable_lease_rejects_untrusted_writable_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let (directory, lock, _remove) = empty_host_directory("lease-parent-mode");
        let parent = directory.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!directory.exists());
        assert!(!lock.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fresh_host_files_have_private_modes_even_under_umask_zero() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD_ROOT: &str = "VOS_AGENT_HOST_UMASK_CHILD_ROOT";
        const CHILD_LOCK: &str = "VOS_AGENT_HOST_UMASK_CHILD_LOCK";
        if let (Some(root), Some(lock)) =
            (std::env::var_os(CHILD_ROOT), std::env::var_os(CHILD_LOCK))
        {
            // SAFETY: this branch runs in a dedicated child process, so the
            // process-global umask cannot race any other test.
            unsafe { libc::umask(0) };
            let root = PathBuf::from(root);
            let lock = PathBuf::from(lock);
            let root_lease = lease(&root, &lock, scope());
            let authority_root = root_lease.authority_root().unwrap().to_path_buf();
            open_empty_control(root_lease).unwrap().shutdown().unwrap();
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(authority_root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(HOST_SCOPE_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(root.join(HOST_LOCK_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            return;
        }

        let (directory, lock, _remove) = empty_host_directory("umask-zero");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("agent::host::tests::fresh_host_files_have_private_modes_even_under_umask_zero")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, &directory)
            .env(CHILD_LOCK, &lock)
            .status()
            .unwrap();
        assert!(status.success(), "umask-zero child failed: {status}");
    }

    #[test]
    fn missing_configured_parents_are_not_created() {
        let (directory, lock, _remove) = empty_host_directory("missing-configured-parent");
        let missing_root_parent = directory.parent().unwrap().join("missing-root-parent");
        let nested_root = missing_root_parent.join("data");
        assert!(matches!(
            AgentHostRootLease::acquire(&nested_root, &lock, scope()),
            Err(AgentHostError::Unavailable | AgentHostError::InvalidScopeBinding)
        ));
        assert!(!missing_root_parent.exists());
        assert!(!lock.exists());

        let missing_lock_parent = directory.parent().unwrap().join("missing-lock-parent");
        let nested_lock = missing_lock_parent.join("owner.lock");
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &nested_lock, scope()),
            Err(AgentHostError::Unavailable | AgentHostError::InvalidScopeBinding)
        ));
        assert!(!missing_lock_parent.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn malformed_and_partial_stable_lease_records_fail_closed() {
        for (label, corrupt) in [
            ("lease-partial", 0u8),
            ("lease-checksum", 1u8),
            ("lease-trailing", 2u8),
        ] {
            let (directory, lock, _remove) = empty_host_directory(label);
            drop(AgentHostRootLease::acquire(&directory, &lock, scope()).unwrap());
            let mut encoded = fs::read(&lock).unwrap();
            match corrupt {
                0 => encoded.truncate(HOST_LEASE_BINDING_LEN - 1),
                1 => encoded[HOST_LEASE_BINDING_PREFIX_LEN] ^= 1,
                2 => encoded.push(0),
                _ => unreachable!(),
            }
            fs::write(&lock, &encoded).unwrap();
            assert!(matches!(
                AgentHostRootLease::acquire(&directory, &lock, scope()),
                Err(AgentHostError::InvalidScopeBinding)
            ));
            assert_eq!(fs::read(&lock).unwrap(), encoded);
        }
    }

    #[test]
    fn atomic_lease_binding_recovers_exact_stage_prefixes_and_alias() {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        for length in [0, 1, HOST_LEASE_BINDING_LEN - 1, HOST_LEASE_BINDING_LEN] {
            let (directory, lock, _remove) =
                empty_host_directory(&format!("lease-stage-prefix-{length}"));
            let canonical_root = canonical_agent_host_root_target(directory.clone())
                .unwrap()
                .0;
            let expected =
                encode_agent_host_lease_binding(&canonical_root, scope(), HOST_LEASE_BINDING_FRESH)
                    .unwrap();
            let stage = agent_host_lease_stage_path(&lock);
            fs::write(&stage, &expected[..length]).unwrap();

            drop(lease(&directory, &lock, scope()));
            assert_eq!(fs::read(&lock).unwrap(), expected);
            assert!(!stage.exists());
        }

        let (directory, lock, _remove) = empty_host_directory("lease-stage-alias");
        drop(
            AgentHostRootLease::acquire(&directory, &lock, scope())
                .unwrap_or_else(|error| panic!("lease alias recovery: {error:?}")),
        );
        let stage = agent_host_lease_stage_path(&lock);
        fs::hard_link(&lock, &stage).unwrap();
        assert_eq!(fs::metadata(&lock).unwrap().nlink(), 2);
        drop(lease(&directory, &lock, scope()));
        assert!(!stage.exists());
        assert_eq!(fs::metadata(&lock).unwrap().nlink(), 1);
    }

    #[test]
    fn malformed_lease_binding_stage_is_never_published_or_rewritten() {
        let (directory, lock, _remove) = empty_host_directory("lease-stage-malformed");
        let canonical_root = canonical_agent_host_root_target(directory.clone())
            .unwrap()
            .0;
        let expected =
            encode_agent_host_lease_binding(&canonical_root, scope(), HOST_LEASE_BINDING_FRESH)
                .unwrap();
        let stage = agent_host_lease_stage_path(&lock);
        let mut malformed = expected[..HOST_LEASE_BINDING_LEN - 1].to_vec();
        malformed[0] ^= 1;
        fs::write(&stage, &malformed).unwrap();

        for _ in 0..2 {
            assert!(matches!(
                AgentHostRootLease::acquire(&directory, &lock, scope()),
                Err(AgentHostError::InvalidScopeBinding)
            ));
            assert!(!lock.exists());
            assert_eq!(fs::read(&stage).unwrap(), malformed);
            assert!(!directory.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn scope_publication_alias_is_recoverable_but_a_third_link_is_rejected() {
        use std::os::unix::fs::MetadataExt as _;

        let (directory, lock, _remove) = empty_host_directory("scope-link-alias");
        let root_lease = lease(&directory, &lock, scope());
        let final_path = directory.join(HOST_SCOPE_FILE);
        let stage_path = directory.join(HOST_SCOPE_TEMP_FILE);
        fs::write(&stage_path, encoded_scope(scope())).unwrap();
        fs::hard_link(&stage_path, &final_path).unwrap();
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 2);
        assert!(matches!(
            read_agent_host_scope(
                &directory,
                &root_lease.root_directory,
                scope(),
                false,
            ),
            Ok(AgentHostScopeState::BoundWithStage(bound)) if bound == scope()
        ));
        cleanup_agent_host_scope_stage(&directory, &root_lease.root_directory).unwrap();
        assert!(!stage_path.exists());
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 1);
        drop(root_lease);

        let (directory, lock, _remove) = empty_host_directory("scope-third-link");
        let root_lease = lease(&directory, &lock, scope());
        let final_path = directory.join(HOST_SCOPE_FILE);
        let stage_path = directory.join(HOST_SCOPE_TEMP_FILE);
        let third_path = directory.join("scope-third-link");
        fs::write(&stage_path, encoded_scope(scope())).unwrap();
        fs::hard_link(&stage_path, &final_path).unwrap();
        fs::hard_link(&stage_path, &third_path).unwrap();
        assert!(matches!(
            read_agent_host_scope(&directory, &root_lease.root_directory, scope(), false,),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::metadata(&stage_path).unwrap().nlink(), 3);
    }

    #[test]
    fn every_exact_scope_stage_prefix_is_completed_and_malformed_prefixes_are_unchanged() {
        let expected = encoded_scope(scope());
        for length in 0..HOST_SCOPE_ENCODED_LEN {
            let (directory, lock, _remove) =
                empty_host_directory(&format!("scope-prefix-{length}"));
            let root_lease = lease(&directory, &lock, scope());
            let stage = directory.join(HOST_SCOPE_TEMP_FILE);
            fs::write(&stage, &expected[..length]).unwrap();
            assert!(matches!(
                read_agent_host_scope(
                    &directory,
                    &root_lease.root_directory,
                    scope(),
                    true,
                ),
                Ok(AgentHostScopeState::Staged(staged)) if staged == scope()
            ));
            assert_eq!(fs::read(stage).unwrap(), expected);
        }

        let (directory, lock, _remove) = empty_host_directory("scope-prefix-malformed");
        let root_lease = lease(&directory, &lock, scope());
        let stage = directory.join(HOST_SCOPE_TEMP_FILE);
        let mut malformed = expected[..HOST_SCOPE_ENCODED_LEN - 1].to_vec();
        malformed[0] ^= 1;
        fs::write(&stage, &malformed).unwrap();
        assert!(matches!(
            read_agent_host_scope(&directory, &root_lease.root_directory, scope(), true,),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::read(stage).unwrap(), malformed);
    }

    #[test]
    fn empty_legacy_lease_cannot_claim_an_ambiguous_empty_root() {
        let (directory, lock, _remove) = empty_host_directory("legacy-empty-lease");
        open_empty_control(lease(&directory, &lock, scope()))
            .unwrap()
            .shutdown()
            .unwrap();
        fs::write(&lock, b"").unwrap();
        let mut before = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        before.sort_unstable();

        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::metadata(&lock).unwrap().len(), 0);
        let mut after = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        after.sort_unstable();
        assert_eq!(after, before);
    }

    #[test]
    fn stable_lease_is_released_after_process_crash() {
        const CHILD_ROOT: &str = "VOS_AGENT_HOST_LEASE_CHILD_ROOT";
        const CHILD_LOCK: &str = "VOS_AGENT_HOST_LEASE_CHILD_LOCK";
        const CHILD_READY: &str = "VOS_AGENT_HOST_LEASE_CHILD_READY";

        if let (Some(root), Some(lock), Some(ready)) = (
            std::env::var_os(CHILD_ROOT),
            std::env::var_os(CHILD_LOCK),
            std::env::var_os(CHILD_READY),
        ) {
            let _lease = AgentHostRootLease::acquire(root, lock, scope()).unwrap();
            fs::write(ready, b"ready").unwrap();
            loop {
                thread::park_timeout(Duration::from_secs(60));
            }
        }

        let (directory, lock, _remove) = empty_host_directory("process-crash");
        let ready = directory.parent().unwrap().join("child-ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("agent::host::tests::stable_lease_is_released_after_process_crash")
            .arg("--test-threads=1")
            .env(CHILD_ROOT, &directory)
            .env(CHILD_LOCK, &lock)
            .env(CHILD_READY, &ready)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.is_file() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("Agent-host lease child exited before acquiring the lock: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Agent-host lease child did not acquire the lock in time");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::DirectoryInUse)
        ));

        child.kill().unwrap();
        child.wait().unwrap();
        let recovered = AgentHostRootLease::acquire(&directory, &lock, scope()).unwrap();
        drop(recovered);
    }

    #[test]
    fn malformed_directory_scope_fails_closed() {
        let (directory, lock, _remove) = empty_host_directory("malformed-scope");
        let root_lease = lease(&directory, &lock, scope());
        fs::write(directory.join(HOST_SCOPE_FILE), b"truncated").unwrap();
        assert!(matches!(
            open_empty_control(root_lease),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn unbound_existing_journals_are_not_claimed_by_a_guessed_scope() {
        let (directory, lock, _remove) = empty_host_directory("unbound-journal");
        fs::create_dir_all(&directory).unwrap();
        fs::create_dir(directory.join(format!(
            "{}{}",
            encode_agent_id(test_system_agent()),
            JOURNAL_SUFFIX
        )))
        .unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!lock.exists());
        assert!(!agent_host_lease_stage_path(&lock).exists());
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        fs::write(directory.join(HOST_SCOPE_TEMP_FILE), encoded_scope(scope())).unwrap();
        assert!(matches!(
            AgentHostRootLease::acquire(&directory, &lock, scope()),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert!(!lock.exists());
        assert!(!agent_host_lease_stage_path(&lock).exists());
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        assert!(directory.join(HOST_SCOPE_TEMP_FILE).is_file());
    }

    #[test]
    fn stable_lease_must_live_outside_the_replaceable_root() {
        let (directory, _lock, _remove) = empty_host_directory("inside-lock");
        assert!(matches!(
            AgentHostRootLease::acquire(
                &directory,
                directory.join("locks").join("owner.lock"),
                scope(),
            ),
            Err(AgentHostError::InvalidScopeBinding)
        ));
    }

    #[test]
    fn matching_staged_scope_is_recovered_but_mismatched_scope_is_not_overwritten() {
        let (directory, lock, _remove) = empty_host_directory("scope-recovery");
        let first_lease = lease(&directory, &lock, scope());
        fs::write(directory.join(HOST_SCOPE_TEMP_FILE), encoded_scope(scope())).unwrap();
        open_empty_control(first_lease).unwrap().shutdown().unwrap();
        assert!(directory.join(HOST_SCOPE_FILE).is_file());
        assert!(!directory.join(HOST_SCOPE_TEMP_FILE).exists());

        fs::remove_file(directory.join(HOST_SCOPE_FILE)).unwrap();
        let wrong_scope = AgentHostScope {
            space: scope().space,
            node: NodeId([3; 32]),
        };
        fs::write(
            directory.join(HOST_SCOPE_TEMP_FILE),
            encoded_scope(wrong_scope),
        )
        .unwrap();
        assert!(matches!(
            open_empty_control(lease(&directory, &lock, scope())),
            Err(AgentHostError::ScopeMismatch)
        ));
        assert!(!directory.join(HOST_SCOPE_FILE).exists());
        assert_eq!(
            fs::read(directory.join(HOST_SCOPE_TEMP_FILE)).unwrap(),
            encoded_scope(wrong_scope)
        );
    }

    #[cfg(unix)]
    #[test]
    fn scope_binding_symlinks_fail_without_touching_their_target() {
        use std::os::unix::fs::symlink;

        let (directory, lock, _remove) = empty_host_directory("scope-symlink");
        let lease = lease(&directory, &lock, scope());
        let target = directory.parent().unwrap().join("untouched");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, directory.join(HOST_SCOPE_FILE)).unwrap();
        assert!(matches!(
            open_empty_control(lease),
            Err(AgentHostError::InvalidScopeBinding)
        ));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}
