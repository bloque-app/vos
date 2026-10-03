//! Root-scoped production host for clean-generation Local agents.
//!
//! This boundary deliberately does not reuse the transitional journal host.
//! One locked filesystem root is bound to one exact Space and full transport
//! Node identity, and every child is named by the lowercase canonical SDK
//! `AgentId`. Lifecycle admission remains serialized. Serving work checks out
//! one exclusive driver and releases the registry mutex; independent Agents
//! execute on the supervisor's bounded pool, with no per-Agent serving thread.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs2::FileExt as _;

use crate::agent_sdk::authority::AuthorityReceipt;
use crate::agent_sdk::{
    AgentDescriptor, AgentId, AgentProfile, InvocationAuthorization, InvocationWork,
    ManagementRequest, NodeId, ResumeWork, RuntimeOutcome, SpaceId,
};

use super::driver::{
    AgentDriver, AgentDriverError, AgentImageStore, AgentStoreError, AgentTrustProvider,
    FileAgentStore, SdkManagementArtifacts,
};
use super::package_admission::AdmittedRuntimePackage;

/// Clean-generation logical time required by SDK receipt verification.
///
/// The adapter below deliberately supplies no legacy authority or package
/// trust. Clean lifecycle trust is the immutable descriptor binding plus the
/// canonical signed SDK receipt, while VOS3 package admission is performed
/// before this host boundary.
pub trait CleanAgentLogicalClock: Send + Sync {
    fn current_logical_slot(&self) -> Option<u64>;
}

struct CleanAgentTrustAdapter {
    clock: Arc<dyn CleanAgentLogicalClock>,
}

impl AgentTrustProvider for CleanAgentTrustAdapter {
    fn current_logical_slot(&self) -> Option<u64> {
        self.clock.current_logical_slot()
    }

    fn authority_for_space(
        &self,
        _space: crate::service::SpaceId,
    ) -> Option<super::authority::AgentAuthorityBinding> {
        None
    }

    fn verify_package(
        &self,
        _agent: &super::AgentConfig,
        _package: &super::package::Package,
    ) -> bool {
        false
    }
}

fn clean_clock_trust(clock: Arc<dyn CleanAgentLogicalClock>) -> Arc<dyn AgentTrustProvider> {
    Arc::new(CleanAgentTrustAdapter { clock })
}

/// Hard bound on directories and loaded drivers owned by one Local host.
pub const MAX_LOCAL_HOST_AGENTS: usize = 4_096;

const SCOPE_MAGIC: &[u8; 4] = b"LAH3";
const SCOPE_VERSION: u16 = 1;
const SCOPE_FILE: &str = "scope";
const SCOPE_STAGE_FILE: &str = "scope.next";
const LOCK_FILE: &str = "lock";
const CREATING_DIRECTORY: &str = ".creating";
const IMAGE_FILE: &str = "image";
const IMAGE_STAGE_FILE: &str = "image.next";
const CATALOG_DIRECTORY: &str = "image.agent-catalog";
const CATALOG_KINDS: [&str; 5] = [
    "packages",
    "programs",
    "schemas",
    "policies",
    "installation-data",
];
const SCOPE_PREFIX_BYTES: usize = 4 + 2 + 32 + 32;
const SCOPE_BYTES: usize = SCOPE_PREFIX_BYTES + 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalAgentHostError {
    Io,
    Busy,
    AlreadyExists,
    NotFound,
    InvalidRoot,
    InvalidScope,
    InvalidDescriptor,
    UnsupportedProfile,
    Alias,
    LimitExceeded,
    Corrupt,
    Driver(AgentDriverError),
}

pub(crate) enum LocalAuthorityProjectionAudit {
    Ready(Vec<super::supervisor::AgentRouteIdentity>),
    Lag,
}

/// Exact Local application observed by rereading the private image store.
/// Only the physical host can construct this value. It proves a Local durable
/// observation, not system-Agent finality or permission to publish a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalManagementObservation {
    receipt: AuthorityReceipt,
    result: Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
    reopened_state: crate::agent_sdk::Hash,
    applied_at: u64,
}

impl LocalManagementObservation {
    pub fn receipt(&self) -> &AuthorityReceipt {
        &self.receipt
    }
    pub fn result(
        &self,
    ) -> &Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError> {
        &self.result
    }
    pub fn reopened_state(&self) -> crate::agent_sdk::Hash {
        self.reopened_state
    }
    pub fn applied_at(&self) -> u64 {
        self.applied_at
    }
}

impl fmt::Display for LocalAgentHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Local-agent host operation failed: {self:?}")
    }
}

impl core::error::Error for LocalAgentHostError {}

impl From<AgentDriverError> for LocalAgentHostError {
    fn from(error: AgentDriverError) -> Self {
        match error {
            AgentDriverError::UnsupportedProfile(_) => Self::UnsupportedProfile,
            AgentDriverError::Store(AgentStoreError::Conflict) => Self::AlreadyExists,
            AgentDriverError::Store(AgentStoreError::Corrupt) => Self::Corrupt,
            AgentDriverError::Store(AgentStoreError::Unavailable) => Self::Io,
            other => Self::Driver(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootScope {
    space: SpaceId,
    node: NodeId,
}

struct HostedLocalAgent {
    driver: AgentDriver<FileAgentStore>,
    descriptor: AgentDescriptor,
    directory: File,
}

/// Single-writer owner of every clean Local agent under one physical root.
pub struct LocalAgentHost {
    root: PathBuf,
    canonical_root: PathBuf,
    root_directory: File,
    lock: File,
    scope: RootScope,
    trust: Arc<dyn AgentTrustProvider>,
    agents: BTreeMap<AgentId, HostedLocalAgent>,
    executing: BTreeMap<AgentId, AgentDescriptor>,
    failed: bool,
    #[cfg(test)]
    execution_probe: Option<Arc<dyn Fn(AgentId) + Send + Sync>>,
}

/// Owns exactly one driver while keeping the root lease alive. The registry
/// mutex is not held during VM execution, catalog reads or durable publication.
pub(crate) struct LocalAgentExecution {
    owner: Arc<Mutex<LocalAgentHost>>,
    agent: AgentId,
    slot: PathBuf,
    scope: RootScope,
    trust: Arc<dyn AgentTrustProvider>,
    hosted: Option<HostedLocalAgent>,
    failed: bool,
}

impl LocalAgentExecution {
    pub(crate) fn route_identities(
        &self,
    ) -> Result<Vec<super::supervisor::AgentRouteIdentity>, LocalAgentHostError> {
        let hosted = self.hosted.as_ref().ok_or(LocalAgentHostError::Corrupt)?;
        let directory = hosted.driver.physical_authority_directory()?;
        super::supervisor_adapters::route_identities(
            &hosted.descriptor,
            directory.records().to_vec(),
            AgentProfile::Local,
        )
        .map_err(|_| LocalAgentHostError::Corrupt)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn audit_authority_projection(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<LocalAuthorityProjectionAudit, LocalAgentHostError> {
        use super::supervisor_adapters::{
            PhysicalAuthorityRouteProjection, physical_material_identity,
            physical_material_matches_authority, physical_projection_is_exactly_one_ack_ahead,
        };
        let hosted = self.hosted.as_ref().ok_or(LocalAgentHostError::Corrupt)?;
        let directory = hosted.driver.physical_authority_directory()?;
        let mut actors = Vec::with_capacity(directory.records().len());
        for record in directory.records() {
            let material = directory.material(record.entry.actor)?;
            if material.descriptor != hosted.descriptor
                || material.descriptor.identity.agent != self.agent
            {
                return Err(LocalAgentHostError::Corrupt);
            }
            actors.push(material);
        }
        if projected.len() == 1
            && projected[0].descriptor() == &hosted.descriptor
            && projected[0].actors().len() == actors.len()
            && actors
                .iter()
                .zip(projected[0].actors())
                .all(|(material, actor)| {
                    physical_material_matches_authority(material, &hosted.descriptor, actor)
                })
        {
            let identities = actors
                .iter()
                .filter(|material| !material.actor.entry.suspended)
                .map(physical_material_identity)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LocalAgentHostError::InvalidDescriptor)?;
            return Ok(LocalAuthorityProjectionAudit::Ready(identities));
        }
        let history = hosted
            .driver
            .image()
            .clean_management
            .as_ref()
            .ok_or(LocalAgentHostError::Corrupt)?;
        let physical = PhysicalAuthorityRouteProjection {
            descriptor: hosted.descriptor.clone(),
            actors,
            disposition: history.latest().map(|record| {
                super::standard::StandardCleanManagementDisposition {
                    authority: record.authority,
                    request: record.request,
                    epoch: record.epoch,
                    sequence: record.sequence,
                    observed_slot: record.observed_slot,
                    result: record.result.clone(),
                }
            }),
        };
        if physical_projection_is_exactly_one_ack_ahead(head, projected, &[physical]) {
            Ok(LocalAuthorityProjectionAudit::Lag)
        } else {
            Err(LocalAgentHostError::InvalidDescriptor)
        }
    }

    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: AgentId,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, LocalAgentHostError>
    {
        if agent != self.agent {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let hosted = self.hosted.as_ref().ok_or(LocalAgentHostError::Corrupt)?;
        let material = hosted.driver.physical_invocation_material(actor)?;
        if material.descriptor != hosted.descriptor {
            return Err(LocalAgentHostError::Corrupt);
        }
        Ok(material)
    }

    fn finish(
        &mut self,
        result: Result<RuntimeOutcome, AgentDriverError>,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        match result {
            Ok(outcome) => {
                let checked = (|| {
                    let hosted = self.hosted.as_mut().ok_or(LocalAgentHostError::Corrupt)?;
                    let descriptor = descriptor_from_driver(&hosted.driver)?;
                    validate_descriptor_for_scope(self.scope, &descriptor)?;
                    if descriptor.identity.agent != self.agent {
                        return Err(LocalAgentHostError::Alias);
                    }
                    hosted.descriptor = descriptor;
                    validate_same_directory(&hosted.directory, &self.slot)?;
                    validate_agent_slot(&self.slot, false)
                })();
                if checked.is_err() {
                    self.failed = true;
                }
                checked.map(|()| outcome)
            }
            Err(error) => {
                if matches!(error, AgentDriverError::Store(_)) {
                    if let Err(error) = self
                        .hosted
                        .as_ref()
                        .ok_or(LocalAgentHostError::Corrupt)
                        .and_then(|hosted| validate_same_directory(&hosted.directory, &self.slot))
                    {
                        self.failed = true;
                        return Err(error);
                    }
                    match LocalAgentHost::open_hosted_at(
                        self.scope,
                        self.trust.clone(),
                        self.agent,
                        &self.slot,
                    ) {
                        Ok(hosted) => self.hosted = Some(hosted),
                        Err(recovery) => {
                            self.failed = true;
                            return Err(recovery);
                        }
                    }
                }
                Err(error.into())
            }
        }
    }

    pub(crate) fn invoke(
        &mut self,
        agent: AgentId,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        if agent != self.agent || work.agent != agent || work.space != self.scope.space {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = self
            .hosted
            .as_mut()
            .ok_or(LocalAgentHostError::Corrupt)?
            .driver
            .invoke_sdk(work, authorization);
        self.finish(result)
    }

    pub(crate) fn resume_sdk_exact(
        &mut self,
        agent: AgentId,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        if agent != self.agent || work.agent != agent || work.space != self.scope.space {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = self
            .hosted
            .as_mut()
            .ok_or(LocalAgentHostError::Corrupt)?
            .driver
            .resume_sdk_exact(work, authorization, yielded);
        self.finish(result)
    }

    pub(crate) fn acknowledge_sdk(
        &mut self,
        agent: AgentId,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        if agent != self.agent || work.agent != agent || work.space != self.scope.space {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = self
            .hosted
            .as_mut()
            .ok_or(LocalAgentHostError::Corrupt)?
            .driver
            .acknowledge_sdk(work, authorization);
        self.finish(result)
    }
}

impl Drop for LocalAgentExecution {
    fn drop(&mut self) {
        let mut owner = self.owner.lock().unwrap_or_else(|error| error.into_inner());
        owner.failed |= self.failed || std::thread::panicking();
        if owner.executing.remove(&self.agent).is_none() {
            owner.failed = true;
        }
        if let Some(hosted) = self.hosted.take() {
            match owner.agents.entry(self.agent) {
                alloc::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(hosted);
                }
                alloc::collections::btree_map::Entry::Occupied(_) => {
                    owner.failed = true;
                }
            }
        } else {
            owner.failed = true;
        }
    }
}

impl LocalAgentHost {
    pub(crate) fn checkout(
        owner: &Arc<Mutex<Self>>,
        agent: AgentId,
    ) -> Result<LocalAgentExecution, LocalAgentHostError> {
        let mut host = owner.lock().map_err(|_| LocalAgentHostError::Corrupt)?;
        host.verify_root_identity()?;
        if host.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        let hosted = host
            .agents
            .get(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        let slot = host.agent_path(agent);
        validate_same_directory(&hosted.directory, &slot)?;
        let hosted = host
            .agents
            .remove(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        host.executing.insert(agent, hosted.descriptor.clone());
        #[cfg(test)]
        let probe = host.execution_probe.clone();
        let execution = LocalAgentExecution {
            owner: owner.clone(),
            agent,
            slot: host.agent_path(agent),
            scope: host.scope,
            trust: host.trust.clone(),
            hosted: Some(hosted),
            failed: false,
        };
        drop(host);
        // The lease excludes same-Agent work and retains the root lock while
        // catalog traversal runs without blocking unrelated Agent checkout.
        // A validation error drops the lease and restores the untouched driver.
        validate_agent_slot(&execution.slot, false)?;
        validate_same_directory(
            &execution.hosted.as_ref().unwrap().directory,
            &execution.slot,
        )?;
        #[cfg(test)]
        if let Some(probe) = probe {
            probe(agent);
        }
        Ok(execution)
    }

    pub(crate) fn create_with_clean_clock(
        root: impl AsRef<Path>,
        space: SpaceId,
        node: NodeId,
        clock: Arc<dyn CleanAgentLogicalClock>,
    ) -> Result<Self, LocalAgentHostError> {
        Self::create(root, space, node, clean_clock_trust(clock))
    }

    pub(crate) fn open_with_clean_clock(
        root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_node: NodeId,
        clock: Arc<dyn CleanAgentLogicalClock>,
    ) -> Result<Self, LocalAgentHostError> {
        Self::open(
            root,
            expected_space,
            expected_node,
            clean_clock_trust(clock),
        )
    }

    /// Create a new empty root. The supplied path and its parent must already
    /// be canonical; relative, symlinked, `.` and `..` aliases are rejected.
    pub fn create(
        root: impl AsRef<Path>,
        space: SpaceId,
        node: NodeId,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, LocalAgentHostError> {
        if space == SpaceId::ZERO || node == NodeId::ZERO {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let root = root.as_ref();
        require_new_canonical_path(root)?;
        match fs::symlink_metadata(root) {
            Ok(_) => return Err(LocalAgentHostError::AlreadyExists),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(LocalAgentHostError::Io),
        }
        create_private_directory(root)?;
        let root_directory = open_private_directory(root)?;
        let lock = open_root_lock(root, &root_directory, true)?;
        create_private_directory(&root.join(CREATING_DIRECTORY))?;
        let scope = RootScope { space, node };
        publish_scope(root, &root_directory, scope)?;
        root_directory
            .sync_all()
            .map_err(|_| LocalAgentHostError::Io)?;
        let canonical_root = fs::canonicalize(root).map_err(|_| LocalAgentHostError::Io)?;
        if canonical_root != root {
            return Err(LocalAgentHostError::InvalidRoot);
        }
        Ok(Self {
            root: root.to_path_buf(),
            canonical_root,
            root_directory,
            lock,
            scope,
            trust,
            agents: BTreeMap::new(),
            executing: BTreeMap::new(),
            failed: false,
            #[cfg(test)]
            execution_probe: None,
        })
    }

    /// Reopen and authenticate the complete root. A valid unpublished create
    /// stage is promoted; an empty unpublished stage is retired. Other
    /// partial or aliased state fails closed.
    pub fn open(
        root: impl AsRef<Path>,
        expected_space: SpaceId,
        expected_node: NodeId,
        trust: Arc<dyn AgentTrustProvider>,
    ) -> Result<Self, LocalAgentHostError> {
        if expected_space == SpaceId::ZERO || expected_node == NodeId::ZERO {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let root = root.as_ref().to_path_buf();
        require_existing_canonical_path(&root)?;
        let root_directory = open_private_directory(&root)?;
        let lock = open_root_lock(&root, &root_directory, false)?;
        let expected = RootScope {
            space: expected_space,
            node: expected_node,
        };
        recover_scope_publication(&root, &root_directory, expected)?;
        let scope = read_scope_file(&root.join(SCOPE_FILE))?;
        if scope != expected {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let creating = root.join(CREATING_DIRECTORY);
        require_private_directory(&creating)?;
        let canonical_root = fs::canonicalize(&root).map_err(|_| LocalAgentHostError::Io)?;
        let mut host = Self {
            root,
            canonical_root,
            root_directory,
            lock,
            scope,
            trust,
            agents: BTreeMap::new(),
            executing: BTreeMap::new(),
            failed: false,
            #[cfg(test)]
            execution_probe: None,
        };
        host.recover_creating()?;
        for agent in scan_root(&host.root)? {
            if host.agents.len() >= MAX_LOCAL_HOST_AGENTS {
                return Err(LocalAgentHostError::LimitExceeded);
            }
            let hosted = host.open_hosted(agent, &host.agent_path(agent))?;
            if host.agents.insert(agent, hosted).is_some() {
                return Err(LocalAgentHostError::Alias);
            }
        }
        host.verify_root_scope()?;
        Ok(host)
    }

    pub const fn space(&self) -> SpaceId {
        self.scope.space
    }

    pub const fn node(&self) -> NodeId {
        self.scope.node
    }

    /// Return the same clean logical slot that will be bound into the next
    /// invocation transition. Callers that sign a self-authenticating Public
    /// actor request use this value in both that request and PublicPreflight;
    /// it is time data, never ambient identity or authorization.
    pub fn current_logical_slot(&self) -> Result<u64, LocalAgentHostError> {
        self.verify_root_scope()?;
        self.trust
            .current_logical_slot()
            .ok_or(LocalAgentHostError::Driver(
                AgentDriverError::TrustUnavailable,
            ))
    }

    pub fn list(&self) -> Result<Vec<AgentId>, LocalAgentHostError> {
        self.verify_root_scope()?;
        let mut agents: Vec<_> = self
            .agents
            .keys()
            .chain(self.executing.keys())
            .copied()
            .collect();
        agents.sort();
        Ok(agents)
    }

    pub fn show(&self, agent: AgentId) -> Result<&AgentDescriptor, LocalAgentHostError> {
        self.verify_root_scope()?;
        self.agents
            .get(&agent)
            .map(|hosted| &hosted.descriptor)
            .or_else(|| self.executing.get(&agent))
            .ok_or(LocalAgentHostError::NotFound)
    }

    /// Read the complete invocation closure from the exact live Local image.
    /// This remains crate-private so ingress cannot bypass supervisor
    /// snapshot/generation admission.
    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: AgentId,
        actor: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, LocalAgentHostError>
    {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        if hosted.descriptor.identity.agent != agent {
            return Err(LocalAgentHostError::Alias);
        }
        let material = hosted.driver.physical_invocation_material(actor)?;
        if material.descriptor != hosted.descriptor {
            return Err(LocalAgentHostError::Corrupt);
        }
        Ok(material)
    }

    /// Authenticate one complete authority inventory against the exact Local
    /// images and content-addressed actor closures owned by this host.
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn audit_authority_projection(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<LocalAuthorityProjectionAudit, LocalAgentHostError> {
        self.verify_root_scope()?;
        if !self.executing.is_empty() {
            return Err(LocalAgentHostError::Busy);
        }
        match self.audit_authority_projection_exact(projected) {
            Ok(identities) => return Ok(LocalAuthorityProjectionAudit::Ready(identities)),
            Err(error) => {
                if self.physical_projection_is_one_ack_ahead(head, projected)? {
                    return Ok(LocalAuthorityProjectionAudit::Lag);
                }
                return Err(error);
            }
        }
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn audit_authority_projection_exact(
        &self,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<Vec<super::supervisor::AgentRouteIdentity>, LocalAgentHostError> {
        if projected.len() != self.agents.len() {
            return Err(LocalAgentHostError::InvalidDescriptor);
        }
        let mut identities = Vec::new();
        for ((agent, hosted), authority) in self.agents.iter().zip(projected) {
            if *agent != authority.descriptor().identity.agent
                || hosted.descriptor != *authority.descriptor()
                || hosted.descriptor.identity.profile != AgentProfile::Local
            {
                return Err(LocalAgentHostError::InvalidDescriptor);
            }
            let directory = hosted.driver.physical_authority_directory()?;
            if directory.records().len() != authority.actors().len() {
                return Err(LocalAgentHostError::InvalidDescriptor);
            }
            for actor in authority.actors() {
                let material = directory.material(actor.entry.actor)?;
                if !super::supervisor_adapters::physical_material_matches_authority(
                    &material,
                    authority.descriptor(),
                    actor,
                ) {
                    return Err(LocalAgentHostError::InvalidDescriptor);
                }
                if !actor.entry.suspended {
                    identities.push(
                        super::supervisor_adapters::physical_material_identity(&material)
                            .map_err(|_| LocalAgentHostError::InvalidDescriptor)?,
                    );
                }
            }
        }
        Ok(identities)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn physical_projection_is_one_ack_ahead(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[super::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<bool, LocalAgentHostError> {
        let mut physical = Vec::with_capacity(self.agents.len());
        for (agent, hosted) in &self.agents {
            let history = hosted
                .driver
                .image()
                .clean_management
                .as_ref()
                .ok_or(LocalAgentHostError::Corrupt)?;
            let directory = hosted.driver.physical_authority_directory()?;
            let mut actors = Vec::with_capacity(directory.records().len());
            for actor in directory.records() {
                let material = directory.material(actor.entry.actor)?;
                if material.descriptor != hosted.descriptor
                    || material.descriptor.identity.agent != *agent
                {
                    return Err(LocalAgentHostError::Corrupt);
                }
                actors.push(material);
            }
            physical.push(
                super::supervisor_adapters::PhysicalAuthorityRouteProjection {
                    descriptor: hosted.descriptor.clone(),
                    actors,
                    disposition: history.latest().map(|record| {
                        super::standard::StandardCleanManagementDisposition {
                            authority: record.authority,
                            request: record.request,
                            epoch: record.epoch,
                            sequence: record.sequence,
                            observed_slot: record.observed_slot,
                            result: record.result.clone(),
                        }
                    }),
                },
            );
        }
        Ok(
            super::supervisor_adapters::physical_projection_is_exactly_one_ack_ahead(
                head, projected, &physical,
            ),
        )
    }

    /// Create one exact SDK agent. The runtime value is already VOS3-admitted
    /// and the driver verifies the signed authority receipt again in guest
    /// execution before any image is published.
    pub fn create_agent(
        &mut self,
        runtime: AdmittedRuntimePackage,
        descriptor: AgentDescriptor,
        authority: AuthorityReceipt,
    ) -> Result<AgentId, LocalAgentHostError> {
        self.verify_root_scope()?;
        self.validate_descriptor(&descriptor)?;
        let agent = descriptor.identity.agent;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if self.agents.contains_key(&agent) {
            let exact = self
                .agents
                .get(&agent)
                .is_some_and(|hosted| hosted.descriptor == descriptor)
                && runtime_matches_descriptor(&runtime, &descriptor);
            if !exact {
                return Err(LocalAgentHostError::AlreadyExists);
            }
            let expected_identity = descriptor.identity.clone();
            let result = {
                let hosted = self
                    .agents
                    .get_mut(&agent)
                    .ok_or(LocalAgentHostError::NotFound)?;
                hosted.driver.manage_sdk(
                    ManagementRequest::Create(Box::new(descriptor)),
                    Some(authority),
                    SdkManagementArtifacts::None,
                )
            };
            return match self.finish_driver_operation(agent, result)? {
                RuntimeOutcome::Management(Ok(crate::agent_sdk::ManagementReply::Created(
                    identity,
                ))) if identity == expected_identity => Ok(agent),
                _ => Err(LocalAgentHostError::Corrupt),
            };
        }
        if self.agents.len() + self.executing.len() >= MAX_LOCAL_HOST_AGENTS {
            return Err(LocalAgentHostError::LimitExceeded);
        }
        let stage = self.creating_path(agent);
        let destination = self.agent_path(agent);
        if path_exists(&stage)? || path_exists(&destination)? {
            return Err(LocalAgentHostError::AlreadyExists);
        }
        create_agent_slot(&stage)?;
        let image = image_path(&stage);
        let result = AgentDriver::create_sdk(
            runtime,
            descriptor.clone(),
            FileAgentStore::new(&image),
            self.trust.clone(),
            authority,
        );
        match result {
            Ok(driver) => drop(driver),
            Err(error) => {
                // A failed durability sync may have lost only the result. If
                // the exact image and admitted closure reopen, publish that
                // committed create; otherwise retire only this unpublished
                // canonical stage.
                match AgentDriver::open_sdk(FileAgentStore::new(&image), self.trust.clone()) {
                    Ok(driver)
                        if descriptor_from_driver(&driver)? == descriptor
                            && self.descriptor_matches_scope(&descriptor) =>
                    {
                        drop(driver);
                    }
                    _ => {
                        remove_unpublished_slot(&stage)?;
                        return Err(error.into());
                    }
                }
            }
        }
        validate_agent_slot(&stage, true)?;
        sync_directory(&stage)?;
        fs::rename(&stage, &destination).map_err(|_| LocalAgentHostError::Io)?;
        let publication = self
            .root_directory
            .sync_all()
            .map_err(|_| LocalAgentHostError::Io)
            .and_then(|()| sync_directory(&self.root.join(CREATING_DIRECTORY)));
        let hosted = self.open_hosted(agent, &destination)?;
        if self.agents.insert(agent, hosted).is_some() {
            return Err(LocalAgentHostError::Alias);
        }
        publication.map(|()| agent)
    }

    pub fn manage(
        &mut self,
        agent: AgentId,
        request: ManagementRequest,
        authority: Option<AuthorityReceipt>,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if matches!(request, ManagementRequest::Create(_)) {
            return Err(LocalAgentHostError::InvalidDescriptor);
        }
        if let ManagementRequest::ChangeReplicas { replicas, .. } = &request
            && (replicas.len() != 1 || replicas[0].node != self.scope.node)
        {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = {
            let hosted = self
                .agents
                .get_mut(&agent)
                .ok_or(LocalAgentHostError::NotFound)?;
            hosted.driver.manage_sdk(request, authority, artifacts)
        };
        self.finish_driver_operation(agent, result)
    }

    /// Reopen the exact durable receipt/result before a lifecycle coordinator
    /// asks its issuer to sign application evidence. The coordinator must
    /// persist the resulting acknowledgement before admitting later work;
    /// a later image has a different state commitment, even for an old retry.
    pub fn observe_management_application(
        &self,
        agent: AgentId,
        request: &ManagementRequest,
        receipt: &AuthorityReceipt,
    ) -> Result<LocalManagementObservation, LocalAgentHostError> {
        use crate::service::wire::ServiceWire as _;
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        let hosted = self
            .agents
            .get(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        let store = FileAgentStore::new(image_path(&self.root.join(encode_agent_id(agent))));
        let image = store
            .load()
            .map_err(AgentDriverError::Store)?
            .ok_or(LocalAgentHostError::Corrupt)?;
        if &image != hosted.driver.image()
            || image.clean_descriptor.as_ref() != Some(&hosted.descriptor)
        {
            return Err(LocalAgentHostError::Corrupt);
        }
        let record = image
            .clean_management
            .as_ref()
            .and_then(|history| history.retained(request, receipt))
            .ok_or(LocalAgentHostError::NotFound)?;
        super::driver::verify_clean_management_receipt(
            &hosted.descriptor,
            request,
            receipt,
            record.observed_slot,
            true,
        )?;
        // Re-admit the persisted package/program and actor catalog as well
        // as the envelope. Reopen performs its normal catalog reconciliation;
        // this observation must not bless an image whose required artifacts
        // have disappeared since the application completed.
        let reopened = AgentDriver::open_sdk(store, self.trust.clone())?;
        if reopened.image() != &image {
            return Err(LocalAgentHostError::Corrupt);
        }
        Ok(LocalManagementObservation {
            receipt: receipt.clone(),
            result: record.result.clone(),
            reopened_state: crate::agent_sdk::Hash::digest(
                b"vos/agent/local/reopened-image/v1",
                &[&image.encode()],
            ),
            applied_at: record.observed_slot,
        })
    }

    pub fn invoke(
        &mut self,
        agent: AgentId,
        invocation: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if invocation.space != self.scope.space || invocation.agent != agent {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = {
            let hosted = self
                .agents
                .get_mut(&agent)
                .ok_or(LocalAgentHostError::NotFound)?;
            hosted.driver.invoke_sdk(invocation, authorization)
        };
        self.finish_driver_operation(agent, result)
    }

    pub fn resume(
        &mut self,
        agent: AgentId,
        resume: ResumeWork,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        let result = {
            let hosted = self
                .agents
                .get_mut(&agent)
                .ok_or(LocalAgentHostError::NotFound)?;
            hosted.driver.resume_sdk(resume)
        };
        self.finish_driver_operation(agent, result)
    }

    pub fn resume_sdk_exact(
        &mut self,
        agent: AgentId,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if work.space != self.scope.space || work.agent != agent {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = {
            let hosted = self
                .agents
                .get_mut(&agent)
                .ok_or(LocalAgentHostError::NotFound)?;
            hosted.driver.resume_sdk_exact(work, authorization, yielded)
        };
        self.finish_driver_operation(agent, result)
    }

    pub fn acknowledge_sdk(
        &mut self,
        agent: AgentId,
        invocation: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        self.verify_root_scope()?;
        if self.executing.contains_key(&agent) {
            return Err(LocalAgentHostError::Busy);
        }
        if invocation.space != self.scope.space || invocation.agent != agent {
            return Err(LocalAgentHostError::InvalidScope);
        }
        let result = {
            let hosted = self
                .agents
                .get_mut(&agent)
                .ok_or(LocalAgentHostError::NotFound)?;
            hosted.driver.acknowledge_sdk(invocation, authorization)
        };
        self.finish_driver_operation(agent, result)
    }

    fn finish_driver_operation(
        &mut self,
        agent: AgentId,
        result: Result<RuntimeOutcome, AgentDriverError>,
    ) -> Result<RuntimeOutcome, LocalAgentHostError> {
        match result {
            Ok(outcome) => {
                self.refresh_hosted(agent)?;
                Ok(outcome)
            }
            Err(error) => {
                if matches!(error, AgentDriverError::Store(_)) {
                    // Recover a commit whose durable publication may have
                    // succeeded before its final sync reported failure. The
                    // caller still receives the original error and may retry
                    // the exact signed request to recover its disposition.
                    self.reload_hosted(agent)?;
                }
                Err(error.into())
            }
        }
    }

    fn refresh_hosted(&mut self, agent: AgentId) -> Result<(), LocalAgentHostError> {
        let scope = self.scope;
        let hosted = self
            .agents
            .get_mut(&agent)
            .ok_or(LocalAgentHostError::NotFound)?;
        let descriptor = descriptor_from_driver(&hosted.driver)?;
        validate_descriptor_for_scope(scope, &descriptor)?;
        if descriptor.identity.agent != agent {
            return Err(LocalAgentHostError::Alias);
        }
        hosted.descriptor = descriptor;
        validate_agent_slot(&self.agent_path(agent), false)
    }

    fn reload_hosted(&mut self, agent: AgentId) -> Result<(), LocalAgentHostError> {
        let path = self.agent_path(agent);
        let replacement = self.open_hosted(agent, &path)?;
        self.agents.insert(agent, replacement);
        Ok(())
    }

    fn open_hosted(
        &self,
        expected_agent: AgentId,
        slot: &Path,
    ) -> Result<HostedLocalAgent, LocalAgentHostError> {
        Self::open_hosted_at(self.scope, self.trust.clone(), expected_agent, slot)
    }

    fn open_hosted_at(
        scope: RootScope,
        trust: Arc<dyn AgentTrustProvider>,
        expected_agent: AgentId,
        slot: &Path,
    ) -> Result<HostedLocalAgent, LocalAgentHostError> {
        let directory = open_private_directory(slot)?;
        validate_agent_slot(slot, true)?;
        let mut driver = AgentDriver::open_sdk(FileAgentStore::new(image_path(slot)), trust)?;
        driver.reconcile_catalog()?;
        let descriptor = descriptor_from_driver(&driver)?;
        validate_descriptor_for_scope(scope, &descriptor)?;
        if descriptor.identity.agent != expected_agent {
            return Err(LocalAgentHostError::Alias);
        }
        retire_image_stage(slot)?;
        validate_agent_slot(slot, false)?;
        validate_same_directory(&directory, slot)?;
        Ok(HostedLocalAgent {
            driver,
            descriptor,
            directory,
        })
    }

    fn validate_descriptor(&self, descriptor: &AgentDescriptor) -> Result<(), LocalAgentHostError> {
        validate_descriptor_for_scope(self.scope, descriptor)
    }

    fn descriptor_matches_scope(&self, descriptor: &AgentDescriptor) -> bool {
        validate_descriptor_for_scope(self.scope, descriptor).is_ok()
    }

    fn recover_creating(&mut self) -> Result<(), LocalAgentHostError> {
        let creating = self.root.join(CREATING_DIRECTORY);
        for entry in fs::read_dir(&creating).map_err(|_| LocalAgentHostError::Io)? {
            let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| LocalAgentHostError::InvalidRoot)?;
            let agent = decode_agent_id(&name).ok_or(LocalAgentHostError::InvalidRoot)?;
            let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(LocalAgentHostError::InvalidRoot);
            }
            let stage = entry.path();
            let destination = self.agent_path(agent);
            if path_exists(&destination)? {
                return Err(LocalAgentHostError::Alias);
            }
            match self.open_hosted(agent, &stage) {
                Ok(hosted) => {
                    drop(hosted);
                    fs::rename(&stage, &destination).map_err(|_| LocalAgentHostError::Io)?;
                    self.root_directory
                        .sync_all()
                        .map_err(|_| LocalAgentHostError::Io)?;
                    sync_directory(&creating)?;
                }
                Err(
                    LocalAgentHostError::Io
                    | LocalAgentHostError::NotFound
                    | LocalAgentHostError::Corrupt,
                ) if unpublished_slot_is_empty(&stage)? => {
                    remove_unpublished_slot(&stage)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Constant-size root ownership checks used by generation-bound execution
    /// leases. Namespace/catalog enumeration belongs to lifecycle and recovery.
    fn verify_root_identity(&self) -> Result<(), LocalAgentHostError> {
        if self.failed {
            return Err(LocalAgentHostError::Corrupt);
        }
        let canonical =
            fs::canonicalize(&self.root).map_err(|_| LocalAgentHostError::InvalidRoot)?;
        if canonical != self.canonical_root || canonical != self.root {
            return Err(LocalAgentHostError::InvalidRoot);
        }
        validate_same_directory(&self.root_directory, &self.root)
            .map_err(|_| LocalAgentHostError::InvalidRoot)?;
        require_private_directory(&self.root)?;
        validate_same_file(&self.lock, &self.root.join(LOCK_FILE))?;
        if read_scope_file(&self.root.join(SCOPE_FILE))? != self.scope {
            return Err(LocalAgentHostError::InvalidScope);
        }
        require_private_file(&self.root.join(LOCK_FILE))?;
        require_private_directory(&self.root.join(CREATING_DIRECTORY))?;
        if fs::read_dir(self.root.join(CREATING_DIRECTORY))
            .map_err(|_| LocalAgentHostError::Io)?
            .next()
            .transpose()
            .map_err(|_| LocalAgentHostError::Io)?
            .is_some()
        {
            return Err(LocalAgentHostError::Corrupt);
        }
        Ok(())
    }

    fn verify_root_scope(&self) -> Result<(), LocalAgentHostError> {
        self.verify_root_identity()?;
        let disk_agents = scan_root(&self.root)?;
        let mut owned: Vec<_> = self
            .agents
            .keys()
            .chain(self.executing.keys())
            .copied()
            .collect();
        owned.sort();
        if disk_agents.len() != owned.len()
            || !disk_agents
                .iter()
                .zip(owned.iter())
                .all(|(disk, loaded)| disk == loaded)
        {
            return Err(LocalAgentHostError::Corrupt);
        }
        for agent in disk_agents {
            // This Agent's exclusive execution lease validates its own slot
            // after publication; concurrent staging files are not corruption.
            if self.executing.contains_key(&agent) {
                continue;
            }
            let hosted = self
                .agents
                .get(&agent)
                .ok_or(LocalAgentHostError::Corrupt)?;
            validate_same_directory(&hosted.directory, &self.agent_path(agent))?;
            validate_agent_slot(&self.agent_path(agent), false)?;
        }
        Ok(())
    }

    fn agent_path(&self, agent: AgentId) -> PathBuf {
        self.root.join(encode_agent_id(agent))
    }

    fn creating_path(&self, agent: AgentId) -> PathBuf {
        self.root
            .join(CREATING_DIRECTORY)
            .join(encode_agent_id(agent))
    }
}

fn validate_descriptor_for_scope(
    scope: RootScope,
    descriptor: &AgentDescriptor,
) -> Result<(), LocalAgentHostError> {
    if descriptor.identity.profile != AgentProfile::Local {
        return Err(LocalAgentHostError::UnsupportedProfile);
    }
    descriptor
        .validate()
        .map_err(|_| LocalAgentHostError::InvalidDescriptor)?;
    if descriptor.identity.space != scope.space
        || descriptor.replicas.len() != 1
        || descriptor.replicas[0].node != scope.node
    {
        return Err(LocalAgentHostError::InvalidScope);
    }
    Ok(())
}

fn runtime_matches_descriptor(
    runtime: &AdmittedRuntimePackage,
    descriptor: &AgentDescriptor,
) -> bool {
    runtime.package_ref() == &descriptor.runtime_package
        && runtime.deployment() == descriptor.identity.runtime_deployment
        && runtime.program() == descriptor.identity.runtime_program
        && runtime.producer() == descriptor.identity.runtime_producer
        && runtime.manifest().contract == descriptor.runtime_contract
        && runtime.capabilities() == descriptor.capabilities
}

fn descriptor_from_driver(
    driver: &AgentDriver<FileAgentStore>,
) -> Result<AgentDescriptor, LocalAgentHostError> {
    driver
        .image()
        .clean_descriptor
        .clone()
        .ok_or(LocalAgentHostError::Corrupt)
}

fn image_path(slot: &Path) -> PathBuf {
    slot.join(IMAGE_FILE)
}

fn create_agent_slot(path: &Path) -> Result<(), LocalAgentHostError> {
    create_private_directory(path)?;
    let catalog = path.join(CATALOG_DIRECTORY);
    create_private_directory(&catalog)?;
    for kind in CATALOG_KINDS {
        create_private_directory(&catalog.join(kind))?;
    }
    sync_directory(&catalog)?;
    sync_directory(path)
}

#[cfg(test)]
std::thread_local! {
    static SLOT_VALIDATIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static CATALOG_VALIDATION_PROBE: core::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { core::cell::RefCell::new(None) };
}

fn validate_agent_slot(path: &Path, allow_image_stage: bool) -> Result<(), LocalAgentHostError> {
    #[cfg(test)]
    SLOT_VALIDATIONS.with(|count| count.set(count.get() + 1));
    require_private_directory(path)?;
    let mut saw_image = false;
    let mut saw_catalog = false;
    for entry in fs::read_dir(path).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let name = entry.file_name();
        let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
        if name == OsStr::new(IMAGE_FILE) {
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(LocalAgentHostError::Corrupt);
            }
            require_private_file(&entry.path())?;
            saw_image = true;
        } else if name == OsStr::new(IMAGE_STAGE_FILE) && allow_image_stage {
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(LocalAgentHostError::Corrupt);
            }
            require_private_file(&entry.path())?;
        } else if name == OsStr::new(CATALOG_DIRECTORY) {
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(LocalAgentHostError::Corrupt);
            }
            validate_catalog(&entry.path())?;
            saw_catalog = true;
        } else {
            return Err(LocalAgentHostError::InvalidRoot);
        }
    }
    if !saw_image || !saw_catalog {
        return Err(LocalAgentHostError::Corrupt);
    }
    Ok(())
}

fn validate_catalog(path: &Path) -> Result<(), LocalAgentHostError> {
    #[cfg(test)]
    CATALOG_VALIDATION_PROBE.with(|probe| {
        if let Some(probe) = probe.borrow().as_ref() {
            probe();
        }
    });
    require_private_directory(path)?;
    let mut seen = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LocalAgentHostError::InvalidRoot)?;
        if !CATALOG_KINDS.contains(&name.as_str()) || seen.contains_key(&name) {
            return Err(LocalAgentHostError::InvalidRoot);
        }
        let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(LocalAgentHostError::Corrupt);
        }
        validate_catalog_kind(&entry.path(), &name)?;
        seen.insert(name, ());
    }
    if seen.len() != CATALOG_KINDS.len() {
        return Err(LocalAgentHostError::Corrupt);
    }
    Ok(())
}

fn validate_catalog_kind(path: &Path, kind: &str) -> Result<(), LocalAgentHostError> {
    require_private_directory(path)?;
    for entry in fs::read_dir(path).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LocalAgentHostError::InvalidRoot)?;
        if !valid_catalog_leaf(&name, kind) {
            return Err(LocalAgentHostError::InvalidRoot);
        }
        let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(LocalAgentHostError::Corrupt);
        }
        require_private_file(&entry.path())?;
    }
    Ok(())
}

fn valid_catalog_leaf(name: &str, kind: &str) -> bool {
    let Some((identity, suffix)) = name.split_once('.') else {
        return false;
    };
    identity.len() == 64
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (suffix == "next"
            || matches!(
                (kind, suffix),
                ("packages", "vos")
                    | ("programs", "pvm")
                    | ("schemas", "agent")
                    | ("policies", "roles")
                    | ("installation-data", "args")
            ))
}

fn retire_image_stage(slot: &Path) -> Result<(), LocalAgentHostError> {
    let stage = slot.join(IMAGE_STAGE_FILE);
    match fs::symlink_metadata(&stage) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LocalAgentHostError::Corrupt);
            }
            require_private_file(&stage)?;
            fs::remove_file(&stage).map_err(|_| LocalAgentHostError::Io)?;
            sync_directory(slot)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalAgentHostError::Io),
    }
}

fn scan_root(root: &Path) -> Result<Vec<AgentId>, LocalAgentHostError> {
    let mut agents = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LocalAgentHostError::InvalidRoot)?;
        let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
        match name.as_str() {
            SCOPE_FILE | LOCK_FILE => {
                if file_type.is_symlink() || !file_type.is_file() {
                    return Err(LocalAgentHostError::InvalidRoot);
                }
                require_private_file(&entry.path())?;
            }
            CREATING_DIRECTORY => {
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(LocalAgentHostError::InvalidRoot);
                }
                require_private_directory(&entry.path())?;
            }
            _ => {
                let agent = decode_agent_id(&name).ok_or(LocalAgentHostError::InvalidRoot)?;
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(LocalAgentHostError::InvalidRoot);
                }
                require_private_directory(&entry.path())?;
                agents.push(agent);
            }
        }
    }
    agents.sort_unstable();
    if agents.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LocalAgentHostError::Alias);
    }
    Ok(agents)
}

fn encode_scope(scope: RootScope) -> [u8; SCOPE_BYTES] {
    let mut bytes = [0; SCOPE_BYTES];
    bytes[..4].copy_from_slice(SCOPE_MAGIC);
    bytes[4..6].copy_from_slice(&SCOPE_VERSION.to_le_bytes());
    bytes[6..38].copy_from_slice(scope.space.as_bytes());
    bytes[38..70].copy_from_slice(scope.node.as_bytes());
    let checksum = crate::agent_sdk::Hash::digest(
        b"vos/local-agent-host/root-scope/v1",
        &[&bytes[..SCOPE_PREFIX_BYTES]],
    );
    bytes[SCOPE_PREFIX_BYTES..].copy_from_slice(checksum.as_bytes());
    bytes
}

fn decode_scope(bytes: &[u8]) -> Result<RootScope, LocalAgentHostError> {
    if bytes.len() != SCOPE_BYTES || &bytes[..4] != SCOPE_MAGIC {
        return Err(LocalAgentHostError::InvalidScope);
    }
    let version = u16::from_le_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| LocalAgentHostError::InvalidScope)?,
    );
    if version != SCOPE_VERSION {
        return Err(LocalAgentHostError::InvalidScope);
    }
    let scope = RootScope {
        space: SpaceId(
            bytes[6..38]
                .try_into()
                .map_err(|_| LocalAgentHostError::InvalidScope)?,
        ),
        node: NodeId(
            bytes[38..70]
                .try_into()
                .map_err(|_| LocalAgentHostError::InvalidScope)?,
        ),
    };
    if scope.space == SpaceId::ZERO
        || scope.node == NodeId::ZERO
        || encode_scope(scope).as_slice() != bytes
    {
        return Err(LocalAgentHostError::InvalidScope);
    }
    Ok(scope)
}

fn publish_scope(
    root: &Path,
    root_directory: &File,
    scope: RootScope,
) -> Result<(), LocalAgentHostError> {
    let stage = root.join(SCOPE_STAGE_FILE);
    write_new_private_file(&stage, &encode_scope(scope))?;
    root_directory
        .sync_all()
        .map_err(|_| LocalAgentHostError::Io)?;
    fs::rename(&stage, root.join(SCOPE_FILE)).map_err(|_| LocalAgentHostError::Io)?;
    root_directory
        .sync_all()
        .map_err(|_| LocalAgentHostError::Io)
}

fn recover_scope_publication(
    root: &Path,
    root_directory: &File,
    expected: RootScope,
) -> Result<(), LocalAgentHostError> {
    let canonical = root.join(SCOPE_FILE);
    let stage = root.join(SCOPE_STAGE_FILE);
    let canonical_scope = optional_scope(&canonical)?;
    let staged_scope = optional_scope(&stage)?;
    match (canonical_scope, staged_scope) {
        (Some(scope), None) if scope == expected => Ok(()),
        (Some(scope), Some(staged)) if scope == expected && staged == scope => {
            fs::remove_file(stage).map_err(|_| LocalAgentHostError::Io)?;
            root_directory
                .sync_all()
                .map_err(|_| LocalAgentHostError::Io)
        }
        (None, Some(scope)) if scope == expected && root_without_scope_is_pristine(root)? => {
            fs::rename(stage, canonical).map_err(|_| LocalAgentHostError::Io)?;
            root_directory
                .sync_all()
                .map_err(|_| LocalAgentHostError::Io)
        }
        (Some(_), _) | (None, Some(_)) => Err(LocalAgentHostError::InvalidScope),
        (None, None) => Err(LocalAgentHostError::InvalidScope),
    }
}

fn optional_scope(path: &Path) -> Result<Option<RootScope>, LocalAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_scope_file(path).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(LocalAgentHostError::Io),
    }
}

fn read_scope_file(path: &Path) -> Result<RootScope, LocalAgentHostError> {
    require_private_file(path)?;
    let mut file = open_read_nofollow(path)?;
    let length = file.metadata().map_err(|_| LocalAgentHostError::Io)?.len();
    if length != SCOPE_BYTES as u64 {
        return Err(LocalAgentHostError::InvalidScope);
    }
    let mut bytes = [0; SCOPE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| LocalAgentHostError::InvalidScope)?;
    decode_scope(&bytes)
}

fn root_without_scope_is_pristine(root: &Path) -> Result<bool, LocalAgentHostError> {
    for entry in fs::read_dir(root).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let name = entry.file_name();
        if name != OsStr::new(LOCK_FILE)
            && name != OsStr::new(CREATING_DIRECTORY)
            && name != OsStr::new(SCOPE_STAGE_FILE)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn open_root_lock(
    root: &Path,
    root_directory: &File,
    create: bool,
) -> Result<File, LocalAgentHostError> {
    let path = root.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            LocalAgentHostError::InvalidRoot
        } else {
            LocalAgentHostError::Io
        }
    })?;
    require_private_file(&path)?;
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == ErrorKind::WouldBlock {
            LocalAgentHostError::Busy
        } else {
            LocalAgentHostError::Io
        }
    })?;
    validate_same_file(&file, &path)?;
    file.sync_all().map_err(|_| LocalAgentHostError::Io)?;
    root_directory
        .sync_all()
        .map_err(|_| LocalAgentHostError::Io)?;
    validate_same_file(&file, &path)?;
    Ok(file)
}

fn require_new_canonical_path(path: &Path) -> Result<(), LocalAgentHostError> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    let parent = path.parent().ok_or(LocalAgentHostError::InvalidRoot)?;
    require_existing_canonical_path(parent)
}

fn require_existing_canonical_path(path: &Path) -> Result<(), LocalAgentHostError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    let canonical = fs::canonicalize(path).map_err(|_| LocalAgentHostError::InvalidRoot)?;
    if canonical != path {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    require_private_directory_or_trusted_parent(path)
}

fn require_private_directory_or_trusted_parent(path: &Path) -> Result<(), LocalAgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LocalAgentHostError::InvalidRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_user = unsafe { libc::geteuid() };
        let trusted_owner = metadata.uid() == effective_user || metadata.uid() == 0;
        let sticky = metadata.mode() & u32::from(libc::S_ISVTX) != 0;
        if !trusted_owner || metadata.mode() & 0o022 != 0 && !sticky {
            return Err(LocalAgentHostError::InvalidRoot);
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), LocalAgentHostError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| LocalAgentHostError::Io)?;
    require_private_directory(path)
}

fn open_private_directory(path: &Path) -> Result<File, LocalAgentHostError> {
    require_private_directory(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    }
    let file = options
        .open(path)
        .map_err(|_| LocalAgentHostError::InvalidRoot)?;
    validate_same_directory(&file, path)?;
    Ok(file)
}

fn require_private_directory(path: &Path) -> Result<(), LocalAgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LocalAgentHostError::InvalidRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(LocalAgentHostError::InvalidRoot);
        }
    }
    Ok(())
}

fn require_private_file(path: &Path) -> Result<(), LocalAgentHostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LocalAgentHostError::Corrupt)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LocalAgentHostError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(LocalAgentHostError::Alias);
        }
    }
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), LocalAgentHostError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| LocalAgentHostError::Io)?;
    file.write_all(bytes).map_err(|_| LocalAgentHostError::Io)?;
    file.sync_all().map_err(|_| LocalAgentHostError::Io)?;
    validate_same_file(&file, path)
}

fn open_read_nofollow(path: &Path) -> Result<File, LocalAgentHostError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| LocalAgentHostError::Corrupt)?;
    validate_same_file(&file, path)?;
    Ok(file)
}

fn validate_same_file(file: &File, path: &Path) -> Result<(), LocalAgentHostError> {
    let opened = file.metadata().map_err(|_| LocalAgentHostError::Io)?;
    let named = fs::symlink_metadata(path).map_err(|_| LocalAgentHostError::Corrupt)?;
    if !opened.is_file() || !named.is_file() || named.file_type().is_symlink() {
        return Err(LocalAgentHostError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(LocalAgentHostError::Alias);
        }
    }
    Ok(())
}

fn validate_same_directory(file: &File, path: &Path) -> Result<(), LocalAgentHostError> {
    let opened = file.metadata().map_err(|_| LocalAgentHostError::Io)?;
    let named = fs::symlink_metadata(path).map_err(|_| LocalAgentHostError::InvalidRoot)?;
    if !opened.is_dir() || !named.is_dir() || named.file_type().is_symlink() {
        return Err(LocalAgentHostError::InvalidRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(LocalAgentHostError::Alias);
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), LocalAgentHostError> {
    open_private_directory(path)?
        .sync_all()
        .map_err(|_| LocalAgentHostError::Io)
}

fn path_exists(path: &Path) -> Result<bool, LocalAgentHostError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LocalAgentHostError::Io),
    }
}

fn unpublished_slot_is_empty(path: &Path) -> Result<bool, LocalAgentHostError> {
    require_private_directory(path)?;
    let image = image_path(path);
    if path_exists(&image)? || path_exists(&path.join(IMAGE_STAGE_FILE))? {
        return Ok(false);
    }
    validate_unpublished_tree(path)?;
    Ok(true)
}

fn validate_unpublished_tree(path: &Path) -> Result<(), LocalAgentHostError> {
    for entry in fs::read_dir(path).map_err(|_| LocalAgentHostError::Io)? {
        let entry = entry.map_err(|_| LocalAgentHostError::Io)?;
        let file_type = entry.file_type().map_err(|_| LocalAgentHostError::Io)?;
        if file_type.is_symlink() {
            return Err(LocalAgentHostError::Corrupt);
        }
        if file_type.is_dir() {
            require_private_directory(&entry.path())?;
            validate_unpublished_tree(&entry.path())?;
        } else if file_type.is_file() {
            require_private_file(&entry.path())?;
        } else {
            return Err(LocalAgentHostError::Corrupt);
        }
    }
    Ok(())
}

fn remove_unpublished_slot(path: &Path) -> Result<(), LocalAgentHostError> {
    validate_unpublished_tree(path)?;
    fs::remove_dir_all(path).map_err(|_| LocalAgentHostError::Io)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn encode_agent_id(agent: AgentId) -> String {
    let mut output = String::with_capacity(64);
    for byte in agent.as_bytes() {
        use core::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_agent_id(name: &str) -> Option<AgentId> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex(pair[0])? << 4) | decode_hex(pair[1])?;
    }
    let agent = AgentId(bytes);
    (agent != AgentId::ZERO && encode_agent_id(agent) == name).then_some(agent)
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
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::path::PathBuf;
    use std::sync::Arc;

    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::*;
    use crate::actors::codec::Encode as _;
    use crate::actors::value::{Msg, TAG_DYNAMIC};
    use crate::agent::authority::AgentAuthorityBinding as LegacyAuthorityBinding;
    use crate::agent::driver::AgentTrustProvider;
    use crate::agent::package::Package as LegacyPackage;
    use crate::agent::package_admission::{
        AdmittedActorPackage, admit_actor_package, admit_runtime_package,
    };
    use crate::agent_sdk as sdk;
    use crate::agent_sdk::authority::{
        AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
        AuthorityOperationKind, AuthorityReceiptSelector,
    };
    use crate::agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use crate::agent_sdk::introspection::{
        ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
    };
    use crate::agent_sdk::method_policy::{
        ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
        AuthorizationPolicySelector, IdempotencyRequirement,
    };
    use crate::agent_sdk::package::{
        ActorPackageManifest, AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope,
        PackageManifest, PackageSigning,
    };
    use crate::agent_sdk::schema::{
        ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
    };
    use crate::agent_sdk::task::TaskDependencySetArtifact;
    use crate::agent_sdk::wire::CanonicalWire as _;
    use crate::agent_sdk::{
        ActorEntry, ActorId, AgentIdentity, AgentReplica, BlobRef, Hash, InstallationId,
        InvocationId, LaneSet, ManagementReply, MethodMode, PrincipalId, ReplicaRole, RuntimeBlob,
        RuntimeCapabilities, RuntimeRequirements, StateLane,
    };
    use crate::service::SpaceId as LegacySpaceId;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
    const PACKAGE_SEED: [u8; 32] = [0x71; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x72; 32];
    const RUNTIME_PVM: &[u8] = include_bytes!("../../../vosx/blobs/agent_runtime.pvm");

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-local-sdk-host-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestTrust;

    impl AgentTrustProvider for TestTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(1)
        }

        fn authority_for_space(&self, _space: LegacySpaceId) -> Option<LegacyAuthorityBinding> {
            None
        }

        fn verify_package(
            &self,
            _agent: &super::super::AgentConfig,
            _package: &LegacyPackage,
        ) -> bool {
            false
        }
    }

    fn trust() -> Arc<dyn AgentTrustProvider> {
        Arc::new(TestTrust)
    }

    struct ClockTrust {
        slot: Arc<AtomicU64>,
    }

    impl AgentTrustProvider for ClockTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(self.slot.load(Ordering::SeqCst))
        }

        fn authority_for_space(&self, _space: LegacySpaceId) -> Option<LegacyAuthorityBinding> {
            None
        }

        fn verify_package(
            &self,
            _agent: &super::super::AgentConfig,
            _package: &LegacyPackage,
        ) -> bool {
            false
        }
    }

    fn clock_trust(initial: u64) -> (Arc<AtomicU64>, Arc<dyn AgentTrustProvider>) {
        let slot = Arc::new(AtomicU64::new(initial));
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(ClockTrust { slot: slot.clone() });
        (slot, trust)
    }

    fn space() -> SpaceId {
        SpaceId([0x11; 32])
    }

    fn node() -> NodeId {
        NodeId([0x22; 32])
    }

    fn package_signing() -> PackageSigning {
        let key = SigningKey::from_bytes(&PACKAGE_SEED);
        let public_key = key.verifying_key().to_bytes();
        PackageSigning {
            producer: sdk::ProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; sdk::package::PACKAGE_SIGNATURE_BYTES],
        }
    }

    fn sign_package(mut package: PackageEnvelope) -> PackageEnvelope {
        let bytes = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = SigningKey::from_bytes(&PACKAGE_SEED)
            .sign(&bytes)
            .to_bytes();
        package
    }

    fn artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn admitted_runtime() -> AdmittedRuntimePackage {
        // Explicit candidate qualification only; default tests retain the
        // bundled-release gate and must not silently substitute a new guest.
        let candidate = std::env::var_os("AGENT_RUNTIME_CANDIDATE_ELF").map(|path| {
            let elf = std::fs::read(&path).unwrap();
            let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
            vos_pvm::spi::validate_refine_host_calls(&program).unwrap();
            eprintln!(
                "Local host candidate runtime: {}",
                std::path::Path::new(&path).display()
            );
            program
        });
        let runtime = candidate.as_deref().unwrap_or(RUNTIME_PVM);
        let package = sign_package(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "standard-local-runtime".into(),
                external_state_limits: None,
                outer_program: BlobRef::of_bytes(runtime),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities::standard(),
                signing: package_signing(),
            }),
            artifacts: vec![artifact(runtime)],
        });
        admit_runtime_package(&package.encode().unwrap()).unwrap()
    }

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&AUTHORITY_SEED)
    }

    fn descriptor(
        runtime: &AdmittedRuntimePackage,
        discriminator: u8,
        profile: AgentProfile,
        target_space: SpaceId,
        target_node: NodeId,
    ) -> AgentDescriptor {
        let owner = PrincipalId([discriminator; 32]);
        let creation_nonce = Hash([discriminator.wrapping_add(0x30); 32]);
        let agent = AgentId::derive(target_space, owner, creation_nonce.as_bytes());
        let authority_key = authority_key();
        let public_key = authority_key.verifying_key().to_bytes();
        let role = if profile == AgentProfile::Private {
            ReplicaRole::Observer
        } else {
            ReplicaRole::Voter
        };
        let value = AgentDescriptor {
            identity: AgentIdentity {
                space: target_space,
                agent,
                owner,
                profile,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer: crate::agent_sdk::ProducerId(
                    [discriminator.wrapping_add(0x60); 32],
                ),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([0x81; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x82; 32]),
                    actor: ActorId([0x83; 32]),
                    deployment: sdk::DeploymentId([0x84; 32]),
                    program: sdk::ProgramId([0x85; 32]),
                    producer: sdk::ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
            private_recovery: (profile == AgentProfile::Private).then_some(
                crate::agent_sdk::PrivateRecoveryBinding {
                    signing_key_commitment: Hash([0x86; 32]),
                    encryption_public_key: [0x17; 32],
                },
            ),
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: vec![AgentReplica {
                node: target_node,
                principal: owner,
                role,
            }],
        };
        value.validate().unwrap();
        value
    }

    fn operation_for(
        request: &ManagementRequest,
    ) -> (
        AuthorityOperationKind,
        Option<ActorId>,
        Option<sdk::DeploymentId>,
    ) {
        match request {
            ManagementRequest::Create(_) => (AuthorityOperationKind::CreateAgent, None, None),
            ManagementRequest::Install(install) => (
                AuthorityOperationKind::InstallActor,
                Some(install.entry.actor),
                Some(install.entry.deployment),
            ),
            ManagementRequest::UpgradeActor(upgrade) => (
                AuthorityOperationKind::UpgradeActor,
                Some(upgrade.actor),
                Some(upgrade.to_deployment),
            ),
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            } => (
                AuthorityOperationKind::SuspendActor,
                Some(*actor),
                Some(*expected_deployment),
            ),
            ManagementRequest::Resume {
                actor,
                expected_deployment,
            } => (
                AuthorityOperationKind::ResumeActor,
                Some(*actor),
                Some(*expected_deployment),
            ),
            ManagementRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => (
                AuthorityOperationKind::RemoveActor,
                Some(*actor),
                Some(*expected_deployment),
            ),
            ManagementRequest::UpgradeRuntime(_) => {
                (AuthorityOperationKind::UpgradeRuntime, None, None)
            }
            ManagementRequest::ChangeReplicas { .. } => {
                (AuthorityOperationKind::ChangeReplicaSet, None, None)
            }
            ManagementRequest::SetExecutionLimits(_) => {
                (AuthorityOperationKind::SetExecutionLimits, None, None)
            }
            ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory => {
                panic!("read-only management has no receipt")
            }
            ManagementRequest::PrivateControl { .. } => {
                panic!("generic Local SDK host does not authorize Private controls")
            }
        }
    }

    fn management_receipt(
        descriptor: &AgentDescriptor,
        request: &ManagementRequest,
        decision_sequence: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> AuthorityReceipt {
        let (operation, actor, actor_deployment) = operation_for(request);
        let runtime_deployment = match request {
            ManagementRequest::Create(created) => created.identity.runtime_deployment,
            ManagementRequest::UpgradeRuntime(upgrade) => upgrade.from_deployment,
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
                    commitment: Hash([0x86; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence,
                acknowledged_through: 0,
                valid_from,
                expires_at,
                request: request.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0; sdk::authority::AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = authority_key().sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn create_receipt(descriptor: &AgentDescriptor, expires_at: u64) -> AuthorityReceipt {
        management_receipt(
            descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
            1,
            1,
            expires_at,
        )
    }

    fn static_actor_program() -> Vec<u8> {
        // Done + three lane lengths + one Linear byte + one reply byte.
        let output = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0x63];
        let mut actor = Assembler::new();
        actor
            .set_rw_data(output.clone())
            .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
            .load_imm_64(Reg::A1, output.len() as u64)
            .jump_ind(Reg::RA, 0);
        actor.build_standard()
    }

    fn admitted_actor() -> AdmittedActorPackage {
        admitted_actor_program(static_actor_program())
    }

    fn admitted_actor_program(program: Vec<u8>) -> AdmittedActorPackage {
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: vec![ParsedField::Inline(ParsedInlineField {
                source_index: 0,
                name: "value".into(),
                type_identity: "core::primitive::u8".into(),
                persistence: sdk::FieldPersistence::State(StateLane::Linear),
            })],
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: MethodMode::Linear,
                explicit: true,
            }],
        };
        let schema_bytes = schema.encode().unwrap();
        let policies = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema_bytes),
            methods: vec![ActorMethodPolicy {
                name: "write".into(),
                mode: MethodMode::Linear,
                arguments: Vec::new(),
                return_type_identity: "core::primitive::u8".into(),
                authorization_policy: AuthorizationPolicySelector::Public,
                idempotency: IdempotencyRequirement::Required,
                attestation: AttestationRequirement::None,
            }],
        };
        let policy_bytes = policies.encode().unwrap();
        let introspection = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&schema_bytes),
            method_policy: BlobRef::of_bytes(&policy_bytes),
            actor_doc: "physical Local host fixture".into(),
            methods: vec![ActorMethodIntrospection {
                name: "write".into(),
                doc: String::new(),
                cli_exposure: CliExposure::Exposed,
                timeout_ms: 0,
                dispatch: MethodDispatch::Sync,
            }],
        };
        let introspection_bytes = introspection.encode().unwrap();
        let tasks = TaskDependencySetArtifact {
            dependencies: Vec::new(),
        };
        let task_bytes = tasks.encode().unwrap();
        let mut artifacts = vec![
            artifact(&program),
            artifact(&schema_bytes),
            artifact(&policy_bytes),
            artifact(&introspection_bytes),
            artifact(&task_bytes),
        ];
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        let envelope = sign_package(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "counter".into(),
                program: BlobRef::of_bytes(&program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(&schema_bytes),
                method_policy: BlobRef::of_bytes(&policy_bytes),
                introspection: BlobRef::of_bytes(&introspection_bytes),
                task_dependencies: BlobRef::of_bytes(&task_bytes),
                scheduling: false,
                requirements: RuntimeRequirements {
                    lanes: LaneSet::of(StateLane::Linear),
                    scheduling: false,
                    proof_systems: sdk::ProofSystemSet::EMPTY,
                },
                resources: None,
                signing: package_signing(),
            }),
            artifacts,
        });
        admit_actor_package(&envelope.encode().unwrap()).unwrap()
    }

    fn yielding_actor_program() -> Vec<u8> {
        let yielded = [
            crate::actors::STATUS_YIELDED,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ];
        let done = [
            crate::actors::STATUS_DONE,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&yielded);
        data.extend_from_slice(&yielded);
        data.extend_from_slice(&done);
        let base = 2 * u64::from(vos_pvm::PVM_ZONE_SIZE);
        const FIRST_BRANCH: u32 = 5;
        const SECOND_BRANCH: u32 = 20;
        const FIRST_YIELD: u32 = 56;
        const SECOND_YIELD: u32 = 82;
        let mut actor = Assembler::new();
        actor
            .set_rw_data(data)
            .ecalli(crate::abi::hostcall::SUSPEND)
            .branch_eq_imm(Reg::A0, 0, FIRST_YIELD - FIRST_BRANCH)
            .ecalli(crate::abi::hostcall::SUSPEND)
            .branch_eq_imm(Reg::A0, 0, SECOND_YIELD - SECOND_BRANCH)
            .load_imm_64(Reg::A0, base + (yielded.len() * 2) as u64)
            .load_imm_64(Reg::A1, done.len() as u64)
            .jump_ind(Reg::RA, 0);
        actor
            .load_imm_64(Reg::A0, base)
            .load_imm_64(Reg::A1, yielded.len() as u64)
            .jump_ind(Reg::RA, 0);
        actor
            .load_imm_64(Reg::A0, base + yielded.len() as u64)
            .load_imm_64(Reg::A1, yielded.len() as u64)
            .jump_ind(Reg::RA, 0);
        actor.build_standard()
    }

    fn install_request(
        descriptor: &AgentDescriptor,
        package: &AdmittedActorPackage,
    ) -> ManagementRequest {
        let schema = sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let actor = ActorId::top_level(descriptor.identity.agent, "counter");
        let entry = ActorEntry {
            actor,
            name: "counter".into(),
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
        ManagementRequest::Install(Box::new(sdk::InstallActor {
            installation_id: InstallationId([0x91; 32]),
            registry_reservation: Hash([0x92; 32]),
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

    fn invocation_receipt(
        descriptor: &AgentDescriptor,
        invocation: &InvocationWork,
        valid_from: u64,
        expires_at: u64,
    ) -> AuthorityReceipt {
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: descriptor.authority.policy,
                issuer: descriptor.authority.issuer,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: descriptor.identity.runtime_deployment,
                actor: Some(invocation.actor),
                actor_deployment: Some(invocation.deployment),
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x93; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 1,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from,
                expires_at,
                request: invocation.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [0; sdk::authority::AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = authority_key().sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    fn availability(package: &AdmittedActorPackage) -> Vec<RuntimeBlob> {
        let mut values = vec![
            RuntimeBlob {
                reference: BlobRef::of_bytes(package.program_bytes()),
                bytes: package.program_bytes().to_vec(),
            },
            RuntimeBlob {
                reference: BlobRef::of_bytes(package.state_lane_schema_bytes()),
                bytes: package.state_lane_schema_bytes().to_vec(),
            },
            RuntimeBlob {
                reference: BlobRef::of_bytes(package.method_policy_bytes()),
                bytes: package.method_policy_bytes().to_vec(),
            },
        ];
        values.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        values
    }

    fn invocation(
        descriptor: &AgentDescriptor,
        record: &sdk::ActorDirectoryRecord,
        package: &AdmittedActorPackage,
        id: u8,
    ) -> InvocationWork {
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("write").encode());
        InvocationWork {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            invocation: InvocationId([id; 32]),
            actor: record.entry.actor,
            incarnation: record.incarnation,
            deployment: record.entry.deployment,
            program: record.entry.program,
            mode: MethodMode::Linear,
            origin: sdk::InvocationOrigin::anonymous(),
            roles: sdk::InvocationRoleClaims::none(),
            message,
            installation_data: None,
            availability: availability(package),
            gas: 10_000_000,
            recovery_only: false,
        }
    }

    #[test]
    fn shared_route_attachment_preserves_lifecycle_lease_and_serializes_access() {
        let directory = TestDirectory::new("shared-route-lease");
        let root = directory.child("agents");
        let host = Arc::new(std::sync::Mutex::new(
            LocalAgentHost::create(&root, space(), node(), trust()).unwrap(),
        ));
        let attachment =
            super::super::supervisor_adapters::local_agent_supervisor_attachment_shared(
                host.clone(),
                4,
            )
            .unwrap();
        let handle = attachment.handle();
        let guard = host.lock().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sent.send(handle.identities()).unwrap();
        });
        assert!(matches!(
            received.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(guard);
        assert!(
            received
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .unwrap()
                .is_empty()
        );
        worker.join().unwrap();
        attachment.retire().unwrap();
        assert!(host.lock().unwrap().list().unwrap().is_empty());
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::Busy)
        ));
        let attachment =
            super::super::supervisor_adapters::local_agent_supervisor_attachment_shared(
                host.clone(),
                4,
            )
            .unwrap();
        let poisoned = host.clone();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = poisoned.lock().unwrap();
                panic!("injected lifecycle failure");
            }))
            .is_err()
        );
        assert_eq!(
            attachment.handle().identities(),
            Err(super::super::supervisor::AgentRouteError::Unavailable)
        );
        attachment.retire().unwrap();
        drop(poisoned);
        drop(host);
        assert!(
            LocalAgentHost::open(&root, space(), node(), trust())
                .unwrap()
                .list()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_create_reopen_is_exactly_scoped_and_exclusively_locked() {
        let directory = TestDirectory::new("empty");
        let root = directory.child("agents");
        let host = LocalAgentHost::create(&root, space(), node(), trust()).unwrap();
        assert_eq!(host.space(), space());
        assert_eq!(host.node(), node());
        assert!(host.list().unwrap().is_empty());
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::Busy)
        ));
        drop(host);

        assert!(matches!(
            LocalAgentHost::open(&root, SpaceId([0x12; 32]), node(), trust()),
            Err(LocalAgentHostError::InvalidScope)
        ));
        assert!(matches!(
            LocalAgentHost::open(&root, space(), NodeId([0x23; 32]), trust()),
            Err(LocalAgentHostError::InvalidScope)
        ));
        let reopened = LocalAgentHost::open(&root, space(), node(), trust()).unwrap();
        assert!(reopened.list().unwrap().is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
            assert_eq!(
                fs::metadata(root.join(SCOPE_FILE)).unwrap().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(root.join(LOCK_FILE)).unwrap().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn physical_independent_local_agents_overlap_through_one_supervisor() {
        use super::super::supervisor::{
            AgentRouteKey, AgentSupervisorLimits, AgentSupervisorOwner,
        };
        use super::super::supervisor_adapters::{
            AgentInvocationRequest, dispatch_invocation,
            local_agent_supervisor_attachment_for_agent,
        };
        use std::sync::{Condvar, mpsc};
        use std::time::Duration;
        let directory = TestDirectory::new("physical-supervisor-overlap");
        let root = directory.child("agents");
        let (clock, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust).unwrap();
        let runtime = admitted_runtime();
        let package = admitted_actor();
        let mut requests = Vec::new();
        for seed in [7, 8] {
            let created_at = 1 + 2 * u64::from(seed - 7);
            clock.store(created_at, Ordering::SeqCst);
            let descriptor = descriptor(&runtime, seed, AgentProfile::Local, space(), node());
            let agent = host
                .create_agent(
                    runtime.clone(),
                    descriptor.clone(),
                    create_receipt(&descriptor, 10),
                )
                .unwrap();
            let install = install_request(&descriptor, &package);
            clock.store(created_at + 1, Ordering::SeqCst);
            let installed = host
                .manage(
                    agent,
                    install.clone(),
                    Some(management_receipt(&descriptor, &install, 2, 1, 10)),
                    SdkManagementArtifacts::Actor(&package),
                )
                .unwrap();
            assert!(
                matches!(
                    installed,
                    RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
                ),
                "fixture install failed for {seed}: {installed:?}"
            );
            let directory = host.agents[&agent]
                .driver
                .physical_authority_directory()
                .unwrap();
            let record = &directory.records()[0];
            let work = invocation(&descriptor, record, &package, seed);
            let authorization = sdk::InvocationAuthorization::AuthorityReceipt(invocation_receipt(
                &descriptor,
                &work,
                5,
                5,
            ));
            let key = AgentRouteKey::new(space(), agent, record.entry.actor).unwrap();
            requests.push((
                agent,
                key,
                AgentInvocationRequest::new(
                    sdk::RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                )
                .unwrap(),
            ));
        }
        clock.store(5, Ordering::SeqCst);
        let shared = Arc::new(Mutex::new(host));
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        {
            use super::super::supervisor_adapters::AgentAuthorityRouteProjection;
            use sdk::authority::{AuthorityActorProjection, AuthorityProjectionHead};
            let head = AuthorityProjectionHead {
                state_revision: 2.try_into().unwrap(),
                epoch: 1.try_into().unwrap(),
                authorization_sequence: 2.try_into().unwrap(),
                administration_generation: 1.try_into().unwrap(),
                state_commitment: Hash([0x31; 32]),
            };
            let leases: Vec<_> = requests
                .iter()
                .map(|(agent, _, _)| LocalAgentHost::checkout(&shared, *agent).unwrap())
                .collect();
            for lease in &leases {
                let hosted = lease.hosted.as_ref().unwrap();
                let directory = hosted.driver.physical_authority_directory().unwrap();
                let record = &directory.records()[0];
                let projection = AgentAuthorityRouteProjection::new(
                    hosted.descriptor.replica_generation(),
                    hosted.descriptor.clone(),
                    vec![AuthorityActorProjection {
                        agent: lease.agent,
                        entry: record.entry.clone(),
                        producer: package.producer(),
                        contract: package.manifest().contract,
                        requirements: package.requirements(),
                        root_provenance: false,
                        installation_id: record.installation_id,
                        registry_reservation: record.registry_reservation,
                        install_request: record.install_request,
                    }],
                )
                .unwrap();
                let before = super::super::driver::directory_execution_count();
                assert!(
                    matches!(lease.audit_authority_projection(head, &[projection]), Ok(LocalAuthorityProjectionAudit::Ready(identities)) if identities.len() == 1)
                );
                assert_eq!(
                    super::super::driver::directory_execution_count() - before,
                    1
                );
                assert!(
                    shared.try_lock().is_ok(),
                    "audit must not retain the host-wide mutex"
                );
                assert!(matches!(
                    lease.audit_authority_projection(head, &[]),
                    Err(LocalAgentHostError::InvalidDescriptor)
                ));
            }
        }
        let mut supervisor = AgentSupervisorOwner::start(AgentSupervisorLimits::default()).unwrap();
        for (agent, _, _) in &requests {
            let (attachment, _) =
                local_agent_supervisor_attachment_for_agent(shared.clone(), *agent)
                    .unwrap()
                    .into_parts();
            supervisor.attach(attachment).unwrap();
        }
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered, observed) = mpsc::channel();
        let execution_gate = gate.clone();
        shared.lock().unwrap().execution_probe = Some(Arc::new(move |agent| {
            entered.send(agent).unwrap();
            let (lock, wake) = &*execution_gate;
            let (released, _) = wake
                .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(15), |released| {
                    !*released
                })
                .unwrap();
            assert!(*released, "physical execution gate timed out");
        }));
        let mut threads = Vec::new();
        for (_, key, request) in requests {
            let handle = supervisor.handle();
            let snapshot = handle.snapshot(key).unwrap();
            threads.push(std::thread::spawn(move || {
                dispatch_invocation(&handle, snapshot, request)
            }));
        }
        // Both concrete adapters must own their real drivers before either
        // may proceed into physical VM execution. No timing-speedup claim.
        let first = observed.recv_timeout(Duration::from_secs(5));
        let second = observed.recv_timeout(Duration::from_secs(5));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_ne!(first.unwrap(), second.unwrap());
        for result in results {
            assert!(
                matches!(
                    result,
                    Ok(
                        super::super::supervisor_adapters::AgentInvocationResponse::Direct {
                            outcome: RuntimeOutcome::Completed(Ok(_)),
                            ..
                        }
                    )
                ),
                "physical dispatch failed: {result:?}"
            );
        }
        supervisor.shutdown_and_join().unwrap();
        assert!(shared.lock().unwrap().executing.is_empty());
    }

    #[test]
    fn physical_execution_leases_release_registry_and_exclude_same_agent_lifecycle() {
        let directory = TestDirectory::new("execution-leases");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let first = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let second = descriptor(&runtime, 8, AgentProfile::Local, space(), node());
        let a = host
            .create_agent(runtime.clone(), first.clone(), create_receipt(&first, 10))
            .unwrap();
        let b = host
            .create_agent(runtime, second.clone(), create_receipt(&second, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let before = SLOT_VALIDATIONS.with(|count| count.get());
        let a_lease = LocalAgentHost::checkout(&shared, a).unwrap();
        assert_eq!(
            SLOT_VALIDATIONS.with(|count| count.get()) - before,
            1,
            "checkout must inspect only its Agent, not idle neighbors"
        );
        let before = SLOT_VALIDATIONS.with(|count| count.get());
        let b_lease = LocalAgentHost::checkout(&shared, b).unwrap();
        assert_eq!(SLOT_VALIDATIONS.with(|count| count.get()) - before, 1);
        assert!(matches!(
            LocalAgentHost::checkout(&shared, a),
            Err(LocalAgentHostError::Busy)
        ));
        {
            let mut registry = shared
                .try_lock()
                .ok()
                .expect("VM leases must not hold the registry mutex");
            assert_eq!(registry.list().unwrap().len(), 2);
            assert_eq!(registry.show(a).unwrap(), &first);
            assert!(matches!(
                registry.manage(
                    a,
                    ManagementRequest::InspectActors {
                        after: None,
                        limit: 1
                    },
                    None,
                    SdkManagementArtifacts::None
                ),
                Err(LocalAgentHostError::Busy)
            ));
        }
        drop(shared);
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust.clone()),
            Err(LocalAgentHostError::Busy)
        ));
        drop(a_lease);
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust.clone()),
            Err(LocalAgentHostError::Busy)
        ));
        drop(b_lease);
        assert_eq!(
            LocalAgentHost::open(&root, space(), node(), trust)
                .unwrap()
                .list()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn physical_catalog_validation_releases_registry_and_restores_failed_checkout() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = TestDirectory::new("catalog-checkout-isolation");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust).unwrap();
        let runtime = admitted_runtime();
        let first = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let second = descriptor(&runtime, 8, AgentProfile::Local, space(), node());
        let a = host
            .create_agent(runtime.clone(), first.clone(), create_receipt(&first, 10))
            .unwrap();
        let b = host
            .create_agent(runtime, second.clone(), create_receipt(&second, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let a_owner = shared.clone();
        let a_thread = std::thread::spawn(move || {
            CATALOG_VALIDATION_PROBE.with(|probe| {
                *probe.borrow_mut() = Some(Box::new(move || {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                }));
            });
            LocalAgentHost::checkout(&a_owner, a).map(drop)
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        let (finished, result) = mpsc::channel();
        let b_owner = shared.clone();
        let b_thread = std::thread::spawn(move || {
            let same_agent_busy = matches!(
                LocalAgentHost::checkout(&b_owner, a),
                Err(LocalAgentHostError::Busy)
            );
            let independent = LocalAgentHost::checkout(&b_owner, b).map(drop);
            finished.send((same_agent_busy, independent)).unwrap();
        });
        let independent = result.recv_timeout(Duration::from_secs(5));
        // Corruption encountered after ownership transfer must still reject
        // admission and return the untouched driver, without stranding a lane.
        let invalid = root
            .join(encode_agent_id(a))
            .join(CATALOG_DIRECTORY)
            .join("unexpected");
        create_private_directory(&invalid).unwrap();
        release.send(()).unwrap();
        let rejected = a_thread.join().unwrap();
        b_thread.join().unwrap();
        let (same_agent_busy, independent) =
            independent.expect("Agent B must complete while Agent A is inside catalog validation");
        assert!(same_agent_busy);
        independent.unwrap();
        assert!(rejected.is_err());
        assert!(shared.lock().unwrap().executing.is_empty());
        assert!(LocalAgentHost::checkout(&shared, a).is_err());
        fs::remove_dir(&invalid).unwrap();
        drop(LocalAgentHost::checkout(&shared, a).unwrap());
        assert_eq!(shared.lock().unwrap().list().unwrap().len(), 2);
    }

    #[test]
    fn physical_checkout_rejects_slot_replacement_during_catalog_validation() {
        let directory = TestDirectory::new("catalog-slot-replacement");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let slot = root.join(encode_agent_id(agent));
        let original = directory.child("original-slot");
        let replacement = directory.child("replacement-slot");
        let probe_slot = slot.clone();
        let probe_original = original.clone();
        CATALOG_VALIDATION_PROBE.with(|probe| {
            *probe.borrow_mut() = Some(Box::new(move || {
                fs::rename(&probe_slot, &probe_original).unwrap();
                create_agent_slot(&probe_slot).unwrap();
                fs::copy(image_path(&probe_original), image_path(&probe_slot)).unwrap();
            }));
        });
        let result = LocalAgentHost::checkout(&shared, agent);
        CATALOG_VALIDATION_PROBE.with(|probe| *probe.borrow_mut() = None);
        assert!(
            result.is_err(),
            "post-scan ownership must still match the pinned directory"
        );
        assert!(shared.lock().unwrap().executing.is_empty());
        fs::rename(&slot, &replacement).unwrap();
        fs::rename(&original, &slot).unwrap();
        drop(LocalAgentHost::checkout(&shared, agent).unwrap());
    }

    #[test]
    fn physical_inline_retirement_releases_root_while_closed_handle_survives() {
        let directory = TestDirectory::new("inline-retirement-root");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let lifetime = Arc::downgrade(&shared);
        let attachment =
            super::super::supervisor_adapters::local_agent_supervisor_attachment_for_agent(
                shared.clone(),
                agent,
            )
            .unwrap();
        let closed = attachment.handle();
        drop(shared);
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust.clone()),
            Err(LocalAgentHostError::Busy)
        ));
        attachment.retire().unwrap();
        assert!(!closed.is_running());
        assert!(lifetime.upgrade().is_none());
        let reopened = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        assert_eq!(reopened.show(agent).unwrap(), &descriptor);
        assert!(closed.identities().is_err());
    }

    #[test]
    fn physical_checkout_pins_its_slot_and_defers_unrelated_namespace_audit() {
        let directory = TestDirectory::new("targeted-slot-validation");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let unowned = root.join(encode_agent_id(AgentId([0xee; 32])));
        create_private_directory(&unowned).unwrap();
        // Serving an owned Agent does not traverse the unrelated namespace.
        drop(LocalAgentHost::checkout(&shared, agent).unwrap());
        // The explicit lifecycle audit still rejects that namespace change.
        assert_eq!(
            shared.lock().unwrap().list(),
            Err(LocalAgentHostError::Corrupt)
        );
        fs::remove_dir(&unowned).unwrap();
        let slot = root.join(encode_agent_id(agent));
        let moved = directory.child("original-slot");
        fs::rename(&slot, &moved).unwrap();
        create_private_directory(&slot).unwrap();
        assert!(
            LocalAgentHost::checkout(&shared, agent).is_err(),
            "a path replacement must not become a new ownership generation"
        );
        fs::remove_dir(&slot).unwrap();
        fs::rename(&moved, &slot).unwrap();
        drop(LocalAgentHost::checkout(&shared, agent).unwrap());
    }

    #[test]
    fn physical_execution_lease_recovers_store_error_and_poison_fails_closed() {
        let directory = TestDirectory::new("execution-lease-failure");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let shared = Arc::new(Mutex::new(host));
        let mut lease = LocalAgentHost::checkout(&shared, agent).unwrap();
        assert_eq!(
            lease.finish(Err(AgentDriverError::Store(AgentStoreError::Unavailable))),
            Err(LocalAgentHostError::Io)
        );
        drop(lease);
        assert_eq!(shared.lock().unwrap().show(agent).unwrap(), &descriptor);

        let lease = LocalAgentHost::checkout(&shared, agent).unwrap();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _owned = lease;
            panic!("execution aborted while owning its driver");
        }));
        assert!(panicked.is_err());
        assert!(matches!(
            LocalAgentHost::checkout(&shared, agent),
            Err(LocalAgentHostError::Corrupt)
        ));
        assert!(shared.lock().unwrap().executing.is_empty());
        // No uncertain in-memory driver is reused. Recovery reauthenticates
        // the durable root only after all execution owners have gone away.
        drop(shared);
        assert_eq!(
            LocalAgentHost::open(&root, space(), node(), trust)
                .unwrap()
                .show(agent)
                .unwrap(),
            &descriptor
        );
    }

    #[test]
    fn restart_retires_only_an_empty_unpublished_create_stage() {
        let directory = TestDirectory::new("empty-stage");
        let root = directory.child("agents");
        drop(LocalAgentHost::create(&root, space(), node(), trust()).unwrap());
        let staged_agent = AgentId([0x33; 32]);
        let stage = root
            .join(CREATING_DIRECTORY)
            .join(encode_agent_id(staged_agent));
        create_agent_slot(&stage).unwrap();

        let host = LocalAgentHost::open(&root, space(), node(), trust()).unwrap();
        assert!(host.list().unwrap().is_empty());
        assert!(!stage.exists());
    }

    #[test]
    fn root_scope_tamper_and_replacement_fail_closed() {
        let directory = TestDirectory::new("replacement");
        let root = directory.child("agents");
        let host = LocalAgentHost::create(&root, space(), node(), trust()).unwrap();

        let displaced = directory.child("displaced");
        fs::rename(&root, &displaced).unwrap();
        create_private_directory(&root).unwrap();
        assert!(matches!(host.list(), Err(LocalAgentHostError::InvalidRoot)));
        drop(host);

        fs::remove_dir(&root).unwrap();
        fs::rename(&displaced, &root).unwrap();
        let scope_path = root.join(SCOPE_FILE);
        let mut bytes = fs::read(&scope_path).unwrap();
        bytes[10] ^= 1;
        fs::write(&scope_path, bytes).unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::InvalidScope)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_path_child_and_hardlink_aliases_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("aliases");
        let root = directory.child("agents");
        drop(LocalAgentHost::create(&root, space(), node(), trust()).unwrap());

        let root_alias = directory.child("root-alias");
        symlink(&root, &root_alias).unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root_alias, space(), node(), trust()),
            Err(LocalAgentHostError::InvalidRoot)
        ));

        let external = directory.child("external");
        create_private_directory(&external).unwrap();
        symlink(&external, root.join(encode_agent_id(AgentId([0x44; 32])))).unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::InvalidRoot)
        ));
        fs::remove_file(root.join(encode_agent_id(AgentId([0x44; 32])))).unwrap();

        fs::hard_link(root.join(SCOPE_FILE), root.join("scope-alias")).unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::Alias | LocalAgentHostError::InvalidRoot)
        ));
    }

    #[test]
    fn hostile_and_legacy_names_never_become_agents() {
        let directory = TestDirectory::new("names");
        let root = directory.child("agents");
        drop(LocalAgentHost::create(&root, space(), node(), trust()).unwrap());

        create_private_directory(
            &root.join("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::InvalidRoot)
        ));
        fs::remove_dir(
            root.join("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .unwrap();

        create_private_directory(&root.join("legacy-service-root")).unwrap();
        assert!(matches!(
            LocalAgentHost::open(&root, space(), node(), trust()),
            Err(LocalAgentHostError::InvalidRoot)
        ));
    }

    #[test]
    fn live_host_detects_new_unowned_disk_entries() {
        let directory = TestDirectory::new("live-injection");
        let root = directory.child("agents");
        let host = LocalAgentHost::create(&root, space(), node(), trust()).unwrap();
        create_private_directory(&root.join(encode_agent_id(AgentId([0x55; 32])))).unwrap();
        assert!(matches!(host.list(), Err(LocalAgentHostError::Corrupt)));
    }

    #[test]
    fn physical_sdk_create_two_agents_reopen_retry_and_profile_scope_refusals() {
        let directory = TestDirectory::new("physical-create");
        let root = directory.child("agents");
        let (slot, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();

        let first_runtime = admitted_runtime();
        let first = descriptor(&first_runtime, 1, AgentProfile::Local, space(), node());
        let first_receipt = create_receipt(&first, 1);
        let first_id = host
            .create_agent(first_runtime, first.clone(), first_receipt.clone())
            .unwrap();
        assert_eq!(first_id, first.identity.agent);
        assert_eq!(host.show(first_id).unwrap(), &first);

        // Model a lost successful response. The exact Create receipt remains
        // recoverable after expiry through the guest-owned disposition.
        slot.store(50, Ordering::SeqCst);
        assert_eq!(
            host.create_agent(admitted_runtime(), first.clone(), first_receipt)
                .unwrap(),
            first_id
        );

        let second_runtime = admitted_runtime();
        let second = descriptor(&second_runtime, 2, AgentProfile::Local, space(), node());
        let second_receipt = create_receipt(&second, 100);
        let second_id = host
            .create_agent(second_runtime, second.clone(), second_receipt)
            .unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(host.list().unwrap(), {
            let mut ids = vec![first_id, second_id];
            ids.sort_unstable();
            ids
        });
        assert!(root.join(encode_agent_id(first_id)).is_dir());
        assert!(root.join(encode_agent_id(second_id)).is_dir());
        assert!(!root.join("first").exists() && !root.join("second").exists());

        for profile in [AgentProfile::Shared, AgentProfile::Private] {
            let runtime = admitted_runtime();
            let unsupported = descriptor(&runtime, 3, profile, space(), node());
            assert_eq!(
                host.create_agent(
                    runtime,
                    unsupported.clone(),
                    create_receipt(&unsupported, 100),
                ),
                Err(LocalAgentHostError::UnsupportedProfile)
            );
            // Unsupported profiles must not leave durable or staged Agent
            // state behind, including when the Private host is not compiled.
            assert!(!host.agent_path(unsupported.identity.agent).exists());
            assert!(!host.creating_path(unsupported.identity.agent).exists());
            assert_eq!(host.list().unwrap().len(), 2);
        }

        let wrong_space_runtime = admitted_runtime();
        let wrong_space = descriptor(
            &wrong_space_runtime,
            4,
            AgentProfile::Local,
            SpaceId([0x12; 32]),
            node(),
        );
        assert_eq!(
            host.create_agent(
                wrong_space_runtime,
                wrong_space.clone(),
                create_receipt(&wrong_space, 100),
            ),
            Err(LocalAgentHostError::InvalidScope)
        );

        let wrong_node_runtime = admitted_runtime();
        let wrong_node = descriptor(
            &wrong_node_runtime,
            5,
            AgentProfile::Local,
            space(),
            NodeId([0x23; 32]),
        );
        assert_eq!(
            host.create_agent(
                wrong_node_runtime,
                wrong_node.clone(),
                create_receipt(&wrong_node, 100),
            ),
            Err(LocalAgentHostError::InvalidScope)
        );

        drop(host);
        let reopened = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        assert_eq!(reopened.show(first_id).unwrap(), &first);
        assert_eq!(reopened.show(second_id).unwrap(), &second);
    }

    #[test]
    fn physical_valid_staged_create_and_store_stages_reconcile_on_restart() {
        let directory = TestDirectory::new("physical-stage");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        drop(LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap());

        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 6, AgentProfile::Local, space(), node());
        let agent = descriptor.identity.agent;
        let stage = root.join(CREATING_DIRECTORY).join(encode_agent_id(agent));
        create_agent_slot(&stage).unwrap();
        drop(
            AgentDriver::create_sdk(
                runtime,
                descriptor.clone(),
                FileAgentStore::new(image_path(&stage)),
                trust.clone(),
                create_receipt(&descriptor, 10),
            )
            .unwrap(),
        );

        // Model a synced-but-unpublished image candidate and an actor-artifact
        // sidecar left by a failed stage. Opening authenticates the committed
        // image first, then retires both unowned candidates.
        write_new_private_file(
            &stage.join(IMAGE_STAGE_FILE),
            &fs::read(image_path(&stage)).unwrap(),
        )
        .unwrap();
        let artifact_stage = stage
            .join(CATALOG_DIRECTORY)
            .join("packages")
            .join(format!("{}.next", "a".repeat(64)));
        write_new_private_file(&artifact_stage, b"unpublished VOS3 stage").unwrap();

        let host = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        assert_eq!(host.show(agent).unwrap(), &descriptor);
        assert!(!stage.exists());
        let destination = root.join(encode_agent_id(agent));
        assert!(!destination.join(IMAGE_STAGE_FILE).exists());
        assert!(
            !destination
                .join(CATALOG_DIRECTORY)
                .join("packages")
                .join(format!("{}.next", "a".repeat(64)))
                .exists()
        );
    }

    #[test]
    fn physical_opaque_runtime_create_management_and_expired_retry_reopen() {
        opaque_runtime_lifecycle_with_upgrade(0);
    }

    #[test]
    fn physical_runtime_upgrade_rejects_unreadable_or_changed_target_directory() {
        for mutation in 1..=7 {
            opaque_runtime_lifecycle_with_upgrade(mutation);
        }
    }

    fn opaque_runtime_lifecycle_with_upgrade(upgrade_mutation: u8) {
        use super::super::driver::AgentImageStore as _;
        use super::super::package_admission::{
            ScriptedRuntimeCase, ScriptedRuntimeCopy, admitted_recovery_scripted_runtime_for_test,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            ActorDirectoryPage, RuntimeExecutionContext, RuntimeState, RuntimeTransition,
            RuntimeWork,
        };
        let template = descriptor(&admitted_runtime(), 9, AgentProfile::Local, space(), node());
        let actor_package = admitted_actor();
        let install_request = install_request(&template, &actor_package);
        let ManagementRequest::Install(install) = &install_request else {
            unreachable!()
        };
        let record = sdk::ActorDirectoryRecord {
            entry: install.entry.clone(),
            incarnation: Hash([0xc3; 32]),
            installation_id: install.installation_id,
            registry_reservation: install.registry_reservation,
            install_request: install.lineage_commitment(),
        };
        let create = ManagementRequest::Create(Box::new(template.clone()));
        let denied = ManagementRequest::RemoveLeaf {
            actor: ActorId::top_level(template.identity.agent, "absent"),
            expected_deployment: sdk::DeploymentId([0xc1; 32]),
        };
        let inspect = ManagementRequest::InspectActors {
            after: None,
            limit: sdk::MAX_DIRECTORY_PAGE_ENTRIES as u16,
        };
        // The opaque fixture explicitly implements both full inspection and
        // targeted inspection of its single actor, using the public cursor
        // contract rather than the standard runtime's private state layout.
        let mut predecessor = record.entry.actor.0;
        for byte in predecessor.iter_mut().rev() {
            let (value, borrow) = byte.overflowing_sub(1);
            *byte = value;
            if !borrow {
                break;
            }
        }
        let lookup = ManagementRequest::InspectActors {
            after: (predecessor != [0; 32]).then_some(ActorId(predecessor)),
            limit: 1,
        };
        let state = |tag: u8| RuntimeState {
            control: vec![tag.min(0xa3)],
            linear: if tag >= 0xa3 {
                vec![tag - 0xa3]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let mut identity = Vec::new();
        identity.extend_from_slice(template.identity.space.as_bytes());
        identity.extend_from_slice(template.identity.agent.as_bytes());
        identity.extend_from_slice(template.identity.owner.as_bytes());
        identity.push(template.identity.profile as u8);
        identity.extend_from_slice(template.identity.runtime_deployment.as_bytes());
        identity.extend_from_slice(template.identity.runtime_program.as_bytes());
        identity.extend_from_slice(template.identity.runtime_producer.as_bytes());
        identity.extend_from_slice(template.identity.transition_producer.as_bytes());
        let offset = |bytes: &[u8]| {
            bytes
                .windows(identity.len())
                .position(|part| part == identity)
                .unwrap()
        };
        let mut cases = Vec::new();
        for tag in [0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5] {
            let input = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: space(),
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: if tag == 0 {
                    RuntimeState::default()
                } else {
                    state(tag)
                },
                request: Box::new(create.clone()),
                authority: Some(Box::new(create_receipt(&template, 10))),
                observed_slot: 1,
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: state(if tag == 0 { 0xa1 } else { tag }),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Created(
                    template.identity.clone(),
                ))),
            }
            .encode()
            .unwrap();
            let copy = ScriptedRuntimeCopy {
                input_offset: offset(&input),
                output_offset: offset(&output),
                len: identity.len(),
            };
            cases.push(ScriptedRuntimeCase {
                input,
                output,
                copies: vec![copy],
            });
        }
        for tag in [0xa1, 0xa2, 0xa3, 0xa4, 0xa5] {
            for request in [&inspect, &lookup, &denied] {
                let inspection = matches!(request, ManagementRequest::InspectActors { .. });
                if !inspection && tag >= 0xa3 {
                    continue;
                }
                let input = RuntimeWork::Manage {
                    context: RuntimeExecutionContext::Direct,
                    space: space(),
                    agent: template.identity.agent,
                    runtime_deployment: template.identity.runtime_deployment,
                    state: state(tag),
                    request: Box::new(request.clone()),
                    authority: (!inspection)
                        .then(|| Box::new(management_receipt(&template, request, 2, 1, 10))),
                    observed_slot: 2,
                }
                .encode()
                .unwrap();
                let output = RuntimeTransition {
                    state: state(if inspection { tag } else { 0xa2 }),
                    outcome: RuntimeOutcome::Management(if inspection {
                        Ok(ManagementReply::Actors(ActorDirectoryPage {
                            entries: if tag >= 0xa3 {
                                vec![record.clone()]
                            } else {
                                Vec::new()
                            },
                            next: None,
                        }))
                    } else {
                        Err(sdk::ManagementError::NotFound)
                    }),
                }
                .encode()
                .unwrap();
                cases.push(ScriptedRuntimeCase {
                    input,
                    output,
                    copies: Vec::new(),
                });
            }
        }
        for tag in [0xa2, 0xa3, 0xa4, 0xa5] {
            let input = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: space(),
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: state(tag),
                request: Box::new(install_request.clone()),
                authority: Some(Box::new(management_receipt(
                    &template,
                    &install_request,
                    3,
                    51,
                    51,
                ))),
                observed_slot: 51,
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: state(tag.max(0xa3)),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Installed(
                    record.entry.clone(),
                ))),
            }
            .encode()
            .unwrap();
            cases.push(ScriptedRuntimeCase {
                input,
                output,
                copies: Vec::new(),
            });
        }
        let invocation_template = invocation(&template, &record, &actor_package, 0xc4);
        let completed = RuntimeOutcome::Completed(Ok(sdk::InvocationReply {
            invocation: invocation_template.invocation,
            actor: record.entry.actor,
            incarnation: record.incarnation,
            deployment: record.entry.deployment,
            mode: MethodMode::Linear,
            lane: Some(StateLane::Linear),
            status: sdk::InvocationStatus::Done,
            reply: vec![1],
            gas_remaining: 100,
            observation: sdk::InvocationObservation {
                linear_revision: Some(1),
                merge_frontier: None,
                local_revision: None,
            },
        }));
        let yielded = sdk::YieldedInvocation {
            invocation: invocation_template.invocation,
            actor: record.entry.actor,
            incarnation: record.incarnation,
            deployment: record.entry.deployment,
            program: record.entry.program,
            mode: MethodMode::Linear,
            continuation: BlobRef::of_bytes(b"opaque-continuation"),
            ready_sequence: 1,
            installation_data: None,
            required: invocation_template
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: sdk::YieldReason::Cooperative,
        };
        for tag in [0xa3, 0xa4, 0xa5] {
            let input = RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: state(tag),
                invocation: Box::new(invocation_template.clone()),
                authorization: Box::new(sdk::InvocationAuthorization::PublicPreflight(
                    sdk::PublicPreflight::for_work(&invocation_template, 52),
                )),
                observed_slot: 52,
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: state(tag.max(0xa4)),
                outcome: if tag == 0xa5 {
                    completed.clone()
                } else {
                    RuntimeOutcome::Yielded(yielded.clone())
                },
            }
            .encode()
            .unwrap();
            cases.push(ScriptedRuntimeCase {
                input,
                output,
                copies: Vec::new(),
            });
        }
        for tag in [0xa4, 0xa5] {
            let input = RuntimeWork::Resume {
                context: RuntimeExecutionContext::Direct,
                state: state(tag),
                resume: Box::new(sdk::ResumeWork {
                    invocation: yielded.invocation,
                    actor: yielded.actor,
                    incarnation: yielded.incarnation,
                    deployment: yielded.deployment,
                    program: yielded.program,
                    mode: yielded.mode,
                    continuation: yielded.continuation.clone(),
                    ready_sequence: yielded.ready_sequence,
                    installation_data: None,
                    availability: invocation_template.availability.clone(),
                    input: None,
                }),
            }
            .encode()
            .unwrap();
            let output = RuntimeTransition {
                state: state(0xa5),
                outcome: completed.clone(),
            }
            .encode()
            .unwrap();
            cases.push(ScriptedRuntimeCase {
                input,
                output,
                copies: Vec::new(),
            });
        }
        let mut target_reply = RuntimeTransition {
            state: state(0xa5),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Actors(ActorDirectoryPage {
                entries: vec![record.clone()],
                next: None,
            }))),
        };
        match upgrade_mutation {
            0 => {}
            1 => target_reply.state.control.push(9),
            2 => target_reply.state.linear.push(9),
            3 => target_reply.state.merge.push(9),
            4 => target_reply.state.local.push(9),
            5 => {
                target_reply.outcome =
                    RuntimeOutcome::Management(Ok(ManagementReply::Actors(ActorDirectoryPage {
                        entries: Vec::new(),
                        next: None,
                    })));
            }
            6 => {
                let mut substituted = record.clone();
                substituted.incarnation = Hash([0xd2; 32]);
                target_reply.outcome =
                    RuntimeOutcome::Management(Ok(ManagementReply::Actors(ActorDirectoryPage {
                        entries: vec![substituted],
                        next: None,
                    })));
            }
            _ => {
                target_reply.outcome =
                    RuntimeOutcome::Management(Err(sdk::ManagementError::UnsupportedRuntime));
            }
        }
        let mut target_cases = vec![ScriptedRuntimeCase {
            input: RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: space(),
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: state(0xa5),
                request: Box::new(inspect.clone()),
                authority: None,
                observed_slot: 71,
            }
            .encode()
            .unwrap(),
            output: target_reply.encode().unwrap(),
            copies: Vec::new(),
        }];
        let mut migrated_invocation = invocation_template.clone();
        migrated_invocation.invocation = InvocationId([0xc5; 32]);
        let RuntimeOutcome::Completed(Ok(mut migrated_reply)) = completed.clone() else {
            unreachable!()
        };
        migrated_reply.invocation = migrated_invocation.invocation;
        migrated_reply.reply = vec![2];
        migrated_reply.observation.linear_revision = Some(2);
        let migrated_outcome = RuntimeOutcome::Completed(Ok(migrated_reply));
        for tag in [0xa5, 0xa6] {
            target_cases.push(ScriptedRuntimeCase {
                input: RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: state(tag),
                    invocation: Box::new(migrated_invocation.clone()),
                    authorization: Box::new(sdk::InvocationAuthorization::PublicPreflight(
                        sdk::PublicPreflight::for_work(&migrated_invocation, 72),
                    )),
                    observed_slot: 72,
                }
                .encode()
                .unwrap(),
                output: RuntimeTransition {
                    state: state(0xa6),
                    outcome: migrated_outcome.clone(),
                }
                .encode()
                .unwrap(),
                copies: Vec::new(),
            });
        }
        target_cases.push(ScriptedRuntimeCase {
            input: RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: space(),
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: state(0xa6),
                request: Box::new(inspect.clone()),
                authority: None,
                observed_slot: 72,
            }
            .encode()
            .unwrap(),
            output: RuntimeTransition {
                state: state(0xa6),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Actors(
                    ActorDirectoryPage {
                        entries: vec![record.clone()],
                        next: None,
                    },
                ))),
            }
            .encode()
            .unwrap(),
            copies: Vec::new(),
        });
        // The new runtime owns retries after cutover. Copy the target identity
        // fields from the request so the scripted package need not contain its
        // own content-derived identity.
        let retry_request = ManagementRequest::UpgradeRuntime(Box::new(sdk::RuntimeUpgrade {
            from_deployment: template.identity.runtime_deployment,
            to_deployment: sdk::DeploymentId([0xd7; 32]),
            to_program: sdk::ProgramId([0xd8; 32]),
            producer: sdk::ProducerId([0xd9; 32]),
            package: template.runtime_package.clone(),
            contract: template.runtime_contract,
            capabilities: template.capabilities,
        }));
        let mut retry_identity = template.identity.clone();
        retry_identity.runtime_deployment = sdk::DeploymentId([0xd7; 32]);
        retry_identity.runtime_program = sdk::ProgramId([0xd8; 32]);
        retry_identity.runtime_producer = sdk::ProducerId([0xd9; 32]);
        let identity_fields = [vec![0xd7; 32], vec![0xd8; 32], vec![0xd9; 32]].concat();
        let input = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: space(),
            agent: template.identity.agent,
            runtime_deployment: template.identity.runtime_deployment,
            state: state(0xa6),
            request: Box::new(retry_request.clone()),
            authority: Some(Box::new(management_receipt(
                &template,
                &retry_request,
                4,
                71,
                71,
            ))),
            observed_slot: 100,
        }
        .encode()
        .unwrap();
        let output = RuntimeTransition {
            state: state(0xa6),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(
                retry_identity,
            ))),
        }
        .encode()
        .unwrap();
        let copy = ScriptedRuntimeCopy {
            input_offset: input
                .windows(identity_fields.len())
                .position(|bytes| bytes == identity_fields)
                .unwrap(),
            output_offset: output
                .windows(identity_fields.len())
                .position(|bytes| bytes == identity_fields)
                .unwrap(),
            len: identity_fields.len(),
        };
        target_cases.push(ScriptedRuntimeCase {
            input,
            output,
            copies: vec![copy],
        });
        let mut lookup_cases = Vec::new();
        for case in &target_cases {
            let mut work = RuntimeWork::decode(&case.input).unwrap();
            if let RuntimeWork::Manage { request, .. } = &mut work {
                if request.as_ref() == &inspect {
                    *request = Box::new(lookup.clone());
                    lookup_cases.push(ScriptedRuntimeCase {
                        input: work.encode().unwrap(),
                        output: case.output.clone(),
                        copies: Vec::new(),
                    });
                }
            }
        }
        target_cases.extend(lookup_cases);
        let target = admitted_recovery_scripted_runtime_for_test(
            "local-opaque-migration-target",
            0xd1,
            target_cases,
        );
        let target_descriptor = descriptor(&target, 9, AgentProfile::Local, space(), node());
        let mut upgrade_request =
            ManagementRequest::UpgradeRuntime(Box::new(sdk::RuntimeUpgrade {
                from_deployment: template.identity.runtime_deployment,
                to_deployment: target.deployment(),
                to_program: target.program(),
                producer: target.producer(),
                package: target.package_ref().clone(),
                contract: target.manifest().contract,
                capabilities: target.capabilities(),
            }));
        cases.push(ScriptedRuntimeCase {
            input: RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space: space(),
                agent: template.identity.agent,
                runtime_deployment: template.identity.runtime_deployment,
                state: state(0xa5),
                request: Box::new(upgrade_request.clone()),
                authority: Some(Box::new(management_receipt(
                    &template,
                    &upgrade_request,
                    4,
                    71,
                    71,
                ))),
                observed_slot: 71,
            }
            .encode()
            .unwrap(),
            output: RuntimeTransition {
                state: state(0xa5),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(
                    target_descriptor.identity.clone(),
                ))),
            }
            .encode()
            .unwrap(),
            copies: Vec::new(),
        });
        let runtime = admitted_recovery_scripted_runtime_for_test(
            "local-opaque-image-lifecycle",
            0xc2,
            cases,
        );
        let descriptor = descriptor(&runtime, 9, AgentProfile::Local, space(), node());
        let directory = TestDirectory::new("opaque-image-lifecycle");
        let root = directory.child("agents");
        let (slot, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let receipt = create_receipt(&descriptor, 10);
        let mut forged = receipt.clone();
        forged.signature[0] ^= 1;
        assert!(
            host.create_agent(runtime.clone(), descriptor.clone(), forged)
                .is_err()
        );
        assert!(host.list().unwrap().is_empty());
        let agent = host
            .create_agent(runtime.clone(), descriptor.clone(), receipt.clone())
            .unwrap();
        assert!(
            crate::agent::wire::decode_standard_runtime_state(
                &host
                    .agents
                    .get(&agent)
                    .unwrap()
                    .driver
                    .image()
                    .runtime_state
            )
            .is_err()
        );
        slot.store(2, Ordering::SeqCst);
        let denial_receipt = management_receipt(&descriptor, &denied, 2, 1, 10);
        let outcome = host
            .manage(
                agent,
                denied.clone(),
                Some(denial_receipt.clone()),
                SdkManagementArtifacts::None,
            )
            .unwrap();
        assert_eq!(
            outcome,
            RuntimeOutcome::Management(Err(sdk::ManagementError::NotFound))
        );
        let before = host.agents.get(&agent).unwrap().driver.image().clone();
        assert_eq!(
            before
                .clean_management
                .as_ref()
                .unwrap()
                .latest()
                .unwrap()
                .sequence,
            2
        );
        drop(host);
        slot.store(50, Ordering::SeqCst);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(
            host.manage(
                agent,
                denied,
                Some(denial_receipt),
                SdkManagementArtifacts::None
            )
            .unwrap(),
            outcome
        );
        assert_eq!(
            host.create_agent(runtime, descriptor.clone(), receipt)
                .unwrap(),
            agent
        );
        assert_eq!(host.agents.get(&agent).unwrap().driver.image(), &before);
        slot.store(51, Ordering::SeqCst);
        let install_receipt = management_receipt(&descriptor, &install_request, 3, 51, 51);
        host.manage(
            agent,
            install_request.clone(),
            Some(install_receipt.clone()),
            SdkManagementArtifacts::Actor(&actor_package),
        )
        .unwrap();
        let application = host
            .observe_management_application(agent, &install_request, &install_receipt)
            .unwrap();
        assert_eq!(application.receipt(), &install_receipt);
        assert_eq!(
            application.result(),
            &Ok(ManagementReply::Installed(record.entry.clone()))
        );
        assert_eq!(application.applied_at(), 51);
        assert_ne!(application.reopened_state(), Hash::ZERO);
        let mut forged_observation = install_receipt.clone();
        forged_observation.signature[0] ^= 1;
        assert!(
            host.observe_management_application(agent, &install_request, &forged_observation)
                .is_err()
        );
        let material = host.agents[&agent]
            .driver
            .physical_invocation_material(record.entry.actor)
            .unwrap();
        assert_eq!(material.actor, record);
        assert_eq!(material.program.bytes, actor_package.program_bytes());
        assert_eq!(material.install_request, install.lineage_commitment());
        assert_eq!(
            host.agents[&agent].driver.image().runtime_state.linear,
            vec![0]
        );
        slot.store(52, Ordering::SeqCst);
        let work = invocation(&descriptor, &record, &actor_package, 0xc4);
        let authorization = sdk::InvocationAuthorization::PublicPreflight(
            sdk::PublicPreflight::for_work(&work, 52),
        );
        assert_eq!(
            host.invoke(agent, work.clone(), authorization.clone())
                .unwrap(),
            RuntimeOutcome::Yielded(yielded.clone())
        );
        let pending = host.agents[&agent].driver.image().clone();
        drop(host);
        slot.store(60, Ordering::SeqCst);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(host.agents[&agent].driver.image(), &pending);
        let mut missing_preimage = work.clone();
        missing_preimage.availability.remove(0);
        assert!(
            host.resume_sdk_exact(
                agent,
                missing_preimage,
                authorization.clone(),
                yielded.clone()
            )
            .is_err()
        );
        assert_eq!(host.agents[&agent].driver.image(), &pending);
        assert_eq!(
            host.resume_sdk_exact(agent, work.clone(), authorization.clone(), yielded.clone())
                .unwrap(),
            completed
        );
        let terminal = host.agents[&agent].driver.image().clone();
        assert_eq!(terminal.runtime_state.linear, vec![2]);
        drop(host);
        slot.store(70, Ordering::SeqCst);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(
            host.agents[&agent]
                .driver
                .physical_invocation_material(record.entry.actor)
                .unwrap()
                .actor,
            record
        );
        assert_eq!(
            host.manage(
                agent,
                install_request.clone(),
                Some(install_receipt.clone()),
                SdkManagementArtifacts::Actor(&actor_package)
            )
            .unwrap(),
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(record.entry.clone())))
        );
        assert_eq!(
            host.invoke(agent, work.clone(), authorization.clone())
                .unwrap(),
            completed
        );
        assert_eq!(
            host.resume_sdk_exact(agent, work, authorization, yielded)
                .unwrap(),
            completed
        );
        assert_eq!(host.agents[&agent].driver.image(), &terminal);
        let late_observation = host
            .observe_management_application(agent, &install_request, &install_receipt)
            .unwrap();
        assert_eq!(late_observation.result(), application.result());
        assert_eq!(late_observation.applied_at(), 51);
        assert_ne!(
            late_observation.reopened_state(),
            application.reopened_state()
        );
        let ManagementRequest::UpgradeRuntime(upgrade) = &mut upgrade_request else {
            unreachable!()
        };
        upgrade.from_deployment = descriptor.identity.runtime_deployment;
        let upgrade_receipt = management_receipt(&descriptor, &upgrade_request, 4, 71, 71);
        slot.store(71, Ordering::SeqCst);
        let result = host.manage(
            agent,
            upgrade_request.clone(),
            Some(upgrade_receipt.clone()),
            SdkManagementArtifacts::Runtime(&target),
        );
        if upgrade_mutation == 0 {
            assert_eq!(
                result.unwrap(),
                RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(
                    target_descriptor.identity.clone()
                )))
            );
            assert_eq!(
                host.agents[&agent].driver.image().revision,
                terminal.revision + 1
            );
            assert_eq!(
                host.agents[&agent].driver.image().runtime_program.0,
                target.program().0
            );
        } else {
            assert!(result.is_err(), "target mutation {upgrade_mutation}");
            assert_eq!(host.agents[&agent].driver.image(), &terminal);
            let store = FileAgentStore::new(image_path(&root.join(encode_agent_id(agent))));
            assert_eq!(store.load().unwrap(), Some(terminal.clone()));
            assert_eq!(
                store
                    .load_program(crate::service::ProgramId(target.program().0))
                    .unwrap(),
                None
            );
            assert_eq!(
                store
                    .load_package(&crate::service::BlobRef {
                        hash: crate::service::Hash(target.package_ref().hash.0),
                        len: target.package_ref().len,
                    })
                    .unwrap(),
                None
            );
        }
        let expected_image = host.agents[&agent].driver.image().clone();
        drop(host);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(host.agents[&agent].driver.image(), &expected_image);
        assert_eq!(
            host.agents[&agent]
                .driver
                .physical_invocation_material(record.entry.actor)
                .unwrap()
                .actor,
            record
        );
        if upgrade_mutation == 0 {
            slot.store(72, Ordering::SeqCst);
            let work = invocation(&target_descriptor, &record, &actor_package, 0xc5);
            let authorization = sdk::InvocationAuthorization::PublicPreflight(
                sdk::PublicPreflight::for_work(&work, 72),
            );
            assert_eq!(
                host.invoke(agent, work.clone(), authorization.clone())
                    .unwrap(),
                migrated_outcome
            );
            let invoked = host.agents[&agent].driver.image().clone();
            assert_eq!(invoked.runtime_state.linear, vec![3]);
            assert_eq!(invoked.revision, expected_image.revision + 1);
            drop(host);
            slot.store(100, Ordering::SeqCst);
            let mut host = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
            assert_eq!(
                host.manage(
                    agent,
                    upgrade_request,
                    Some(upgrade_receipt),
                    SdkManagementArtifacts::Runtime(&target),
                )
                .unwrap(),
                RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(
                    target_descriptor.identity
                )))
            );
            assert_eq!(
                host.agents[&agent].driver.image(),
                &invoked,
                "expired upgrade retry must not roll back post-migration execution"
            );
            assert_eq!(
                host.invoke(agent, work, authorization).unwrap(),
                migrated_outcome
            );
            assert_eq!(host.agents[&agent].driver.image(), &invoked);
        }
    }

    #[test]
    fn physical_reopen_rejects_substituted_host_management_history() {
        use super::super::driver::AgentImageStore as _;
        use super::super::local_management::LocalManagementHistory;
        use crate::service::wire::ServiceWire as _;
        let directory = TestDirectory::new("management-history-binding");
        let root = directory.child("agents");
        let (_, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 8, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let original = host.agents.get(&agent).unwrap().driver.image().clone();
        drop(host);
        let reopened = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(
            reopened.agents.get(&agent).unwrap().driver.image(),
            &original
        );
        let mut substituted = original.clone();
        let mut bytes = substituted.clean_management.as_ref().unwrap().encode();
        // LMH1 header (36), acknowledgement (8), count (4), first receipt
        // commitment (32): change the first request commitment, keeping this
        // history canonical but inconsistent with the validated guest state.
        bytes[80] ^= 1;
        substituted.clean_management = Some(LocalManagementHistory::decode(&bytes).unwrap());
        substituted.revision += 1;
        let mut store = FileAgentStore::new(image_path(&root.join(encode_agent_id(agent))));
        store.commit(Some(original.revision), &substituted).unwrap();
        assert_eq!(
            reopened.observe_management_application(
                agent,
                &ManagementRequest::Create(Box::new(descriptor.clone())),
                &create_receipt(&descriptor, 10)
            ),
            Err(LocalAgentHostError::Corrupt)
        );
        drop(reopened);
        assert!(LocalAgentHost::open(&root, space(), node(), trust.clone()).is_err());

        let mut restored = original;
        restored.revision = substituted.revision + 1;
        store.commit(Some(substituted.revision), &restored).unwrap();
        let reopened = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        assert_eq!(
            reopened.agents.get(&agent).unwrap().driver.image(),
            &restored
        );
    }

    #[test]
    fn physical_manage_invoke_retry_lifecycle_and_catalog_reconciliation() {
        let directory = TestDirectory::new("physical-lifecycle");
        let root = directory.child("agents");
        let (slot, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 7, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let actor_package = admitted_actor();
        let install = install_request(&descriptor, &actor_package);
        let install_receipt = management_receipt(&descriptor, &install, 2, 1, 2);
        slot.store(2, Ordering::SeqCst);
        let installed = host
            .manage(
                agent,
                install.clone(),
                Some(install_receipt.clone()),
                SdkManagementArtifacts::Actor(&actor_package),
            )
            .unwrap();
        assert!(matches!(
            installed,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));

        // Lose the result, expire its receipt, and restart. The exact retry
        // must return the byte-identical terminal disposition.
        drop(host);
        slot.store(50, Ordering::SeqCst);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        let retried = host
            .manage(
                agent,
                install.clone(),
                Some(install_receipt),
                SdkManagementArtifacts::Actor(&actor_package),
            )
            .unwrap();
        assert_eq!(retried, installed);

        let page = host
            .manage(
                agent,
                ManagementRequest::InspectActors {
                    after: None,
                    limit: 8,
                },
                None,
                SdkManagementArtifacts::None,
            )
            .unwrap();
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = page else {
            panic!("inspect did not return the canonical directory")
        };
        let record = page.entries.first().unwrap().clone();
        let before_inspection = host.agents[&agent].driver.image().clone();
        assert_eq!(
            host.agents[&agent]
                .driver
                .inspect_sdk_actor_directory(&descriptor)
                .unwrap(),
            page.entries
        );
        assert_eq!(host.agents[&agent].driver.image(), &before_inspection);

        {
            let driver = &host.agents[&agent].driver;
            let before = super::super::driver::directory_execution_count();
            let directory = driver.physical_authority_directory().unwrap();
            assert_eq!(directory.records(), page.entries);
            let after = super::super::driver::directory_execution_count();
            assert_eq!(after - before, 1, "fixture directory requires one page");
            for _ in 0..3 {
                directory.material(record.entry.actor).unwrap();
            }
            assert_eq!(
                super::super::driver::directory_execution_count(),
                after,
                "material lookup must not execute the directory again"
            );
            assert_eq!(
                directory.material(record.entry.actor).unwrap(),
                driver
                    .physical_authority_material(record.entry.actor)
                    .unwrap(),
                "single-enumeration audit must retain the exact physical artifact closure"
            );
            assert!(directory.material(sdk::ActorId([0xee; 32])).is_err());
            let before_lookup = super::super::driver::directory_execution_count();
            assert_eq!(
                driver
                    .physical_invocation_material(record.entry.actor)
                    .unwrap(),
                directory.material(record.entry.actor).unwrap()
            );
            assert_eq!(
                super::super::driver::directory_execution_count() - before_lookup,
                1,
                "targeted lookup executes exactly one bounded directory request"
            );
            for absent in [sdk::ActorId([1; 32]), sdk::ActorId([255; 32])] {
                assert_ne!(absent, record.entry.actor);
                let before = super::super::driver::directory_execution_count();
                assert!(matches!(
                    driver.physical_invocation_material(absent),
                    Err(AgentDriverError::SdkManagement(
                        sdk::ManagementError::NotFound
                    ))
                ));
                assert_eq!(
                    super::super::driver::directory_execution_count() - before,
                    1
                );
            }
            assert_eq!(driver.image(), &before_inspection);
        }

        let work = invocation(&descriptor, &record, &actor_package, 0xa1);
        let authority = invocation_receipt(&descriptor, &work, 50, 50);
        let mut forged = authority.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            host.invoke(
                agent,
                work.clone(),
                sdk::InvocationAuthorization::AuthorityReceipt(forged),
            )
            .unwrap(),
            RuntimeOutcome::Completed(Err(sdk::InvocationError::InvalidAuthorization))
        );
        let authorization = sdk::InvocationAuthorization::AuthorityReceipt(authority.clone());
        let shared = Arc::new(Mutex::new(host));
        let mut lease = LocalAgentHost::checkout(&shared, agent).unwrap();
        assert!(
            shared.try_lock().is_ok(),
            "execution must not retain host mutex"
        );
        let completed = lease
            .invoke(agent, work.clone(), authorization.clone())
            .unwrap();
        drop(lease);
        let host = Arc::try_unwrap(shared)
            .ok()
            .unwrap()
            .into_inner()
            .ok()
            .unwrap();
        let RuntimeOutcome::Completed(Ok(reply)) = &completed else {
            panic!("physical invoke did not complete successfully: {completed:?}")
        };
        assert_eq!(reply.status, sdk::InvocationStatus::Done);
        assert_eq!(reply.reply, [0x63]);
        let persisted = crate::agent::wire::decode_standard_runtime_state(
            &host.agents[&agent].driver.image().runtime_state,
        )
        .unwrap();
        let linear = persisted
            .lane_state
            .linear
            .iter()
            .find(|entry| {
                entry.actor.0 == record.entry.actor.0
                    && entry.state_generation.0 == record.incarnation.0
            })
            .expect("the completed write commits its Linear lane");
        assert_eq!(linear.value, [0x2a]);
        drop(host);
        slot.store(100, Ordering::SeqCst);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        assert_eq!(
            host.invoke(agent, work.clone(), authorization.clone())
                .unwrap(),
            completed,
            "an expired exact retry recovers the result without re-execution"
        );
        let acknowledgement = host
            .acknowledge_sdk(agent, work.clone(), authorization.clone())
            .unwrap();
        assert_eq!(
            acknowledgement,
            RuntimeOutcome::Acknowledged(Ok(sdk::InvocationAcknowledgement {
                invocation: work.invocation,
                actor: work.actor,
                incarnation: work.incarnation,
                deployment: work.deployment,
                mode: work.mode,
                work: work.commitment(),
                authorization: authorization.commitment(),
            }))
        );
        let acknowledged_state = host.agents[&agent].driver.image().runtime_state.clone();
        drop(host);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        assert_eq!(
            host.acknowledge_sdk(agent, work, authorization).unwrap(),
            acknowledgement,
            "response loss/restart replays the exact positive acknowledgement"
        );
        assert_eq!(
            host.agents[&agent].driver.image().runtime_state,
            acknowledged_state,
            "an acknowledgement retry is byte-identical"
        );

        let actor = record.entry.actor;
        let deployment = record.entry.deployment;
        for (logical_slot, request, expected) in [
            (
                101,
                ManagementRequest::Suspend {
                    actor,
                    expected_deployment: deployment,
                },
                0u8,
            ),
            (
                102,
                ManagementRequest::Resume {
                    actor,
                    expected_deployment: deployment,
                },
                1u8,
            ),
            (
                103,
                ManagementRequest::RemoveLeaf {
                    actor,
                    expected_deployment: deployment,
                },
                2u8,
            ),
        ] {
            slot.store(logical_slot, Ordering::SeqCst);
            let receipt = management_receipt(
                &descriptor,
                &request,
                logical_slot,
                logical_slot,
                logical_slot,
            );
            let outcome = host
                .manage(agent, request, Some(receipt), SdkManagementArtifacts::None)
                .unwrap();
            assert!(matches!(
                (expected, outcome),
                (
                    0,
                    RuntimeOutcome::Management(Ok(ManagementReply::Suspended(_)))
                ) | (
                    1,
                    RuntimeOutcome::Management(Ok(ManagementReply::Resumed(_)))
                ) | (
                    2,
                    RuntimeOutcome::Management(Ok(ManagementReply::Removed(_)))
                )
            ));
        }
    }

    #[test]
    fn physical_resume_boundary_replays_persisted_fifo_continuations() {
        let directory = TestDirectory::new("physical-resume");
        let root = directory.child("agents");
        let (slot, trust) = clock_trust(1);
        let mut host = LocalAgentHost::create(&root, space(), node(), trust.clone()).unwrap();
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, 8, AgentProfile::Local, space(), node());
        let agent = host
            .create_agent(runtime, descriptor.clone(), create_receipt(&descriptor, 10))
            .unwrap();
        let actor_package = admitted_actor_program(yielding_actor_program());
        let install = install_request(&descriptor, &actor_package);
        slot.store(2, Ordering::SeqCst);
        host.manage(
            agent,
            install.clone(),
            Some(management_receipt(&descriptor, &install, 2, 2, 2)),
            SdkManagementArtifacts::Actor(&actor_package),
        )
        .unwrap();
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = host
            .manage(
                agent,
                ManagementRequest::InspectActors {
                    after: None,
                    limit: 4,
                },
                None,
                SdkManagementArtifacts::None,
            )
            .unwrap()
        else {
            panic!("inspect did not return an actor")
        };
        let work = invocation(&descriptor, &page.entries[0], &actor_package, 0xb1);
        slot.store(3, Ordering::SeqCst);
        let outcome = host
            .invoke(
                agent,
                work.clone(),
                sdk::InvocationAuthorization::AuthorityReceipt(invocation_receipt(
                    &descriptor,
                    &work,
                    3,
                    3,
                )),
            )
            .unwrap();
        let RuntimeOutcome::Yielded(first) = outcome else {
            panic!("initial execution did not yield: {outcome:?}")
        };
        assert_eq!(first.reason, sdk::YieldReason::Cooperative);
        assert_eq!(first.ready_sequence, 1);
        drop(host);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust.clone()).unwrap();
        let resume = ResumeWork {
            invocation: first.invocation,
            actor: first.actor,
            incarnation: first.incarnation,
            deployment: first.deployment,
            program: first.program,
            mode: first.mode,
            continuation: first.continuation,
            ready_sequence: first.ready_sequence,
            installation_data: first.installation_data,
            availability: work.availability.clone(),
            input: None,
        };
        let mut tampered = resume.clone();
        tampered.availability[0].bytes[0] ^= 1;
        assert!(matches!(
            host.resume(agent, tampered),
            Err(LocalAgentHostError::Driver(
                AgentDriverError::InvalidRuntime
            ))
        ));
        let outcome = host.resume(agent, resume).unwrap();
        let RuntimeOutcome::Yielded(second) = outcome else {
            panic!("first resume did not yield: {outcome:?}")
        };
        assert_eq!(second.reason, sdk::YieldReason::Cooperative);
        assert_eq!(second.ready_sequence, 2);
        drop(host);
        let mut host = LocalAgentHost::open(&root, space(), node(), trust).unwrap();
        let outcome = host
            .resume(
                agent,
                ResumeWork {
                    invocation: second.invocation,
                    actor: second.actor,
                    incarnation: second.incarnation,
                    deployment: second.deployment,
                    program: second.program,
                    mode: second.mode,
                    continuation: second.continuation,
                    ready_sequence: second.ready_sequence,
                    installation_data: second.installation_data,
                    availability: work.availability,
                    input: None,
                },
            )
            .unwrap();
        let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            panic!("second resume did not complete: {outcome:?}")
        };
        assert_eq!(reply.status, sdk::InvocationStatus::Done);
        assert_eq!(reply.reply, [2]);
    }
}
