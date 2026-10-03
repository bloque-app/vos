//! Native root-authorized system startup and leased ordinary Shared recovery.

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::identity::{KeyType, Keypair};
use zeroize::Zeroize as _;

use system_authority::{
    AuthorityBindingState, AuthorityBlobRow, AuthorityIssuerState,
    ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER, SystemAuthorityConfiguration,
};
use system_catalog::{CatalogAuthorityState, CatalogIssuerState, SystemCatalogConfiguration};
use vos::agent::Ed25519NodeMergeAuthenticator;
use vos::agent::authority::ed25519_public_key_wire;
use vos::agent::bootstrap::SystemAgentGenesisProvider;
use vos::agent::clean_bootstrap::{
    AuthorizedCleanSystemAgentBootstrap, CleanSystemAgentBootstrapError,
    CleanSystemAgentBootstrapRecord, CleanSystemAgentBootstrapStore,
    MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES, MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES,
    PendingCleanSystemAgentBootstrap, PreparedCleanSystemAgentBootstrap,
};
use vos::agent::driver::AgentTrustProvider;
use vos::agent::genesis::{
    AgentGenesisFinalityError, AgentGenesisFinalityVerifier, AgentReplicaCommittee,
    AgentReplicaMember, derive_replica_raft_slot,
};
use vos::agent::host::LocalMergeAuthenticator;
use vos::agent::package::{Ed25519PackageVerifier, Package};
use vos::agent::package_admission::AdmittedActorPackage;
use vos::agent::sdk::authority::{
    AgentAuthorityBinding, AuthorityActorTarget, AuthorityCredentialCall, AuthorityCredentialKind,
    AuthorityIssuer, ManagedAgentTarget,
};
use vos::agent::sdk::{
    ActorEntry, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CredentialId, Hash, InstallationData, InstallationId, InvocationId, ManagementRequest,
    PrincipalId, ProducerId, ReplicaRole, SpaceId,
};
use vos::agent::supervisor::AgentSupervisorLimits;
use vos::agent::{AgentConfig, AgentProfile as HostAgentProfile, ReplicaRole as HostReplicaRole};
use vos::node::VosNode;
use vos::service::{
    AgentId as HostAgentId, Hash as HostHash, NodeId as HostNodeId, PrincipalId as HostPrincipalId,
    SpaceId as HostSpaceId,
};

use super::authority_projection_authenticator::OperatorAuthorityProjectionAuthenticator;
use super::clean_genesis_archive::CleanSystemAgentGenesisArchive;
use super::clean_identity::{
    CleanOperatorIdentitySigner, OwnedCleanOperatorIdentitySigner, node_id_from_authenticated_peer,
    sign_node_encryption_enrollment,
};
use super::clean_store::{
    CleanAuthorityOperationFiles, CleanManagementLifecycleStoreFactory,
    CleanNativeAuthorityOperationCompletions, CleanNativeAuthorityOperationDenials,
    CleanNativeAuthorityOperationJournal, CleanNativeAuthorityOperationRetirements,
    CleanSystemAgentFileStores, discover_shared_genesis_startup,
};

const SYSTEM_AUTHORITY_NAME: &str = "system-authority";
const SYSTEM_CATALOG_NAME: &str = "system-catalog";
const SYSTEM_AGENT_CONTROL_DIRECTORY: &str = "system-agent";
const SHARED_AGENT_HOST_DIRECTORY: &str = "agent-host";
const LOCAL_AGENT_HOST_DIRECTORY: &str = super::local_config::IMAGE_LOCAL_HOST_DIRECTORY;
const LOCAL_LIFECYCLE_DIRECTORY: &str = super::local_config::IMAGE_LOCAL_LIFECYCLE_DIRECTORY;
const OPERATION_IMAGES_DIRECTORY: &str = "authority-operation";
const OPERATION_JOURNAL_DIRECTORY: &str = "authority-operation-journal";
const OPERATION_COMPLETIONS_DIRECTORY: &str = "authority-operation-completions";
const OPERATION_RETIREMENTS_DIRECTORY: &str = "authority-operation-retirements";
const OPERATION_DENIALS_DIRECTORY: &str = "authority-operation-denials";
const ADMIN_DISPATCH_DIRECTORY: &str = "authority-admin-dispatch";
const ADMIN_RESULTS_DIRECTORY: &str = "authority-admin-results";
const ADMIN_RETIREMENTS_DIRECTORY: &str = "authority-admin-retirements";
const PROJECTION_ROUTE_QUEUE_CAPACITY: usize = 64;
const LOCAL_LIFECYCLE_RECOVERY_LIMIT: usize = 1_024;
const PROJECTION_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
// A retry window between bounded bootstrap operations, not a hard execution
// deadline. Keep the same owner/leases while consensus work becomes available.
const SYSTEM_BOOTSTRAP_RETRY_WINDOW: Duration = Duration::from_secs(60);

/// Verified node-key possession plus the operator-selected fixed roster. This
/// is preparation input, not live Authority admission or route authority.
struct SystemBootstrapRoster {
    primary: vos::agent::sdk::private::NodeEncryptionEnrollment,
    additional: Option<[system_authority::AuthorityBootstrapNode; 2]>,
    replicas: AgentReplicaCommittee,
}

impl SystemBootstrapRoster {
    fn from_enrollments(
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        local_node: vos::agent::sdk::NodeId,
        enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    ) -> anyhow::Result<Self> {
        use vos::agent::private_crypto::StrictNodeEncryptionEnrollmentVerifier;
        anyhow::ensure!(
            matches!(enrollments.len(), 1 | 3),
            "system bootstrap requires exactly one or three nodes"
        );
        let mut nodes = enrollments.to_vec();
        nodes.sort_by_key(|node| node.node);
        anyhow::ensure!(
            nodes.windows(2).all(|pair| pair[0].node != pair[1].node),
            "duplicate bootstrap node"
        );
        for node in &nodes {
            anyhow::ensure!(
                node.space == space
                    && node.principal == owner
                    && node.verify_with(&StrictNodeEncryptionEnrollmentVerifier),
                "bootstrap enrollment has invalid scope or transport signature"
            );
        }
        let primary = *nodes
            .iter()
            .find(|node| node.node == local_node)
            .ok_or_else(|| anyhow::anyhow!("planning node is outside the bootstrap roster"))?;
        let mut members = Vec::with_capacity(nodes.len());
        for node in &nodes {
            members.push(AgentReplicaMember::new(
                vos::agent::AgentReplica {
                    node: HostNodeId(node.node.0),
                    principal: HostPrincipalId(
                        PrincipalId::of_public_key(&node.transport_public_key).0,
                    ),
                    role: HostReplicaRole::Voter,
                },
                node.transport_peer_id.to_vec(),
                node.transport_public_key,
                Some(derive_replica_raft_slot(&node.transport_peer_id)),
            )?);
        }
        let additional = if nodes.len() == 3 {
            let extra: Vec<_> = nodes
                .iter()
                .filter(|node| node.node != local_node)
                .map(|node| system_authority::AuthorityBootstrapNode {
                    transport_public_key: node.transport_public_key,
                    encryption_public_key: node.encryption_public_key,
                    transport_signature: node.transport_signature,
                })
                .collect();
            Some(
                extra
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid bootstrap roster"))?,
            )
        } else {
            None
        };
        let replicas = AgentReplicaCommittee::new(
            HostSpaceId(space.0),
            HostAgentId(agent.0),
            HostAgentProfile::Shared,
            members,
        )?;
        Ok(Self {
            primary,
            additional,
            replicas,
        })
    }

    fn descriptor_replicas(&self) -> Vec<AgentReplica> {
        self.replicas
            .members()
            .iter()
            .map(|member| AgentReplica {
                node: vos::agent::sdk::NodeId(member.replica().node.0),
                principal: PrincipalId(member.replica().principal.0),
                role: ReplicaRole::Voter,
            })
            .collect()
    }

    fn authority_configuration(
        &self,
        descriptor: &AgentDescriptor,
        operator_public: [u8; 32],
    ) -> anyhow::Result<SystemAuthorityConfiguration> {
        anyhow::ensure!(
            descriptor.identity.owner == PrincipalId::of_public_key(&operator_public)
                && descriptor.authority.public_key == operator_public
                && self.replicas.space() == HostSpaceId(descriptor.identity.space.0)
                && self.replicas.agent() == HostAgentId(descriptor.identity.agent.0),
            "bootstrap descriptor does not belong to the configured root operator"
        );
        let authority = descriptor.authority;
        let enrollment = self.primary;
        let configuration = SystemAuthorityConfiguration {
            space: descriptor.identity.space.0,
            system_agent: descriptor.identity.agent.0,
            system_runtime_deployment: descriptor.identity.runtime_deployment.0,
            system_runtime_program: descriptor.identity.runtime_program.0,
            system_runtime_producer: descriptor.identity.runtime_producer.0,
            system_transition_producer: descriptor.identity.transition_producer.0,
            system_runtime_package: AuthorityBlobRow {
                hash: descriptor.runtime_package.hash.0,
                len: descriptor.runtime_package.len,
            },
            binding: AuthorityBindingState {
                policy: authority.policy.0,
                issuer: AuthorityIssuerState {
                    principal: authority.issuer.principal.0,
                    actor: authority.issuer.actor.0,
                    deployment: authority.issuer.deployment.0,
                    program: authority.issuer.program.0,
                    producer: authority.issuer.producer.0,
                },
                public_key: authority.public_key,
                initial_epoch: authority.initial_epoch,
            },
            bootstrap_authorization_high_water: ROOT_BOOTSTRAP_AUTHORIZATION_HIGH_WATER,
            bootstrap_system_agent_creation_nonce: descriptor.creation_nonce.0,
            bootstrap_principal: descriptor.identity.owner.0,
            bootstrap_replica_principal: PrincipalId::of_public_key(
                &enrollment.transport_public_key,
            )
            .0,
            bootstrap_credential_public_key: operator_public,
            bootstrap_credential_kind: AuthorityCredentialKind::Api as u8,
            bootstrap_node: enrollment.node.0,
            bootstrap_node_transport_public_key: enrollment.transport_public_key,
            bootstrap_node_transport_peer_id: enrollment.transport_peer_id,
            bootstrap_node_encryption_public_key: enrollment.encryption_public_key,
            bootstrap_node_transport_signature: enrollment.transport_signature,
            bootstrap_additional_nodes: self.additional,
        };
        anyhow::ensure!(
            configuration.matches_system_descriptor(descriptor),
            "derived system-authority configuration does not match its system descriptor"
        );
        Ok(configuration)
    }
}

/// One material builder for live singleton startup and offline common-roster
/// preparation. Construction validates inputs but does not sign or publish.
struct SystemBootstrapMaterials {
    descriptor: AgentDescriptor,
    runtime: vos::agent::package_admission::AdmittedRuntimePackage,
    authority_package: AdmittedActorPackage,
    catalog_package: AdmittedActorPackage,
    authority_request: ManagementRequest,
    catalog_request: ManagementRequest,
    replicas: AgentReplicaCommittee,
}

impl SystemBootstrapMaterials {
    #[allow(clippy::too_many_arguments)]
    fn new(
        space: SpaceId,
        operator_public: [u8; 32],
        local_node: vos::agent::sdk::NodeId,
        runtime: vos::agent::package_admission::AdmittedRuntimePackage,
        authority_package: AdmittedActorPackage,
        catalog_package: AdmittedActorPackage,
        enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    ) -> anyhow::Result<Self> {
        authority_package.require_runtime(AgentProfile::Shared, &runtime)?;
        catalog_package.require_runtime(AgentProfile::Shared, &runtime)?;
        let (target, creation_nonce) =
            derive_system_authority_target(space, operator_public, &runtime, &authority_package)?;
        let owner = PrincipalId::of_public_key(&operator_public);
        let roster = SystemBootstrapRoster::from_enrollments(
            space,
            target.system_agent,
            owner,
            local_node,
            enrollments,
        )?;
        let transition_producer = ProducerId::of_public_key(&roster.primary.transport_public_key);
        anyhow::ensure!(
            transition_producer != ProducerId::of_public_key(&operator_public),
            "system Agent requires distinct root and node signing identities"
        );
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: target.system_agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: runtime.deployment(),
                runtime_program: runtime.program(),
                runtime_producer: runtime.producer(),
                transition_producer,
            },
            creation_nonce,
            authority: target.binding,
            private_recovery: None,
            runtime_package: runtime.package_ref().clone(),
            runtime_contract: runtime.manifest().contract,
            capabilities: runtime.capabilities(),
            replicas: roster.descriptor_replicas(),
        };
        descriptor
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid system-Agent descriptor: {error:?}"))?;
        let authority_configuration =
            roster.authority_configuration(&descriptor, operator_public)?;
        let authority = target.binding;
        let catalog_configuration = SystemCatalogConfiguration {
            space: space.0,
            system_agent: target.system_agent.0,
            system_runtime_deployment: runtime.deployment().0,
            actor: ActorId::top_level(target.system_agent, SYSTEM_CATALOG_NAME).0,
            deployment: catalog_package.deployment().0,
            program: catalog_package.program().0,
            authority: CatalogAuthorityState {
                policy: authority.policy.0,
                issuer: CatalogIssuerState {
                    principal: authority.issuer.principal.0,
                    actor: authority.issuer.actor.0,
                    deployment: authority.issuer.deployment.0,
                    program: authority.issuer.program.0,
                    producer: authority.issuer.producer.0,
                },
                public_key: authority.public_key,
                initial_epoch: authority.initial_epoch,
            },
        };
        anyhow::ensure!(
            catalog_configuration.is_valid(),
            "derived system-catalog configuration is invalid"
        );
        let authority_request = install_request(
            target.system_agent,
            &authority_package,
            authority_configuration.encode(),
            b"authority",
        )?;
        let catalog_request = install_request(
            target.system_agent,
            &catalog_package,
            catalog_configuration.encode(),
            b"catalog",
        )?;
        Ok(Self {
            descriptor,
            runtime,
            authority_package,
            catalog_package,
            authority_request,
            catalog_request,
            replicas: roster.replicas,
        })
    }

    fn authority_target(&self) -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: self.descriptor.identity.space,
            system_agent: self.descriptor.identity.agent,
            system_runtime_deployment: self.descriptor.identity.runtime_deployment,
            binding: self.descriptor.authority,
        }
    }

    fn prepare<C: vos::agent::clean_bootstrap::CleanSystemAgentRootCertifier>(
        self,
        operator: &Keypair,
        observed_slot: u64,
        certifier: &mut C,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<PreparedCleanSystemAgentBootstrap, CleanSystemAgentBootstrapError> {
        let invalid = || {
            CleanSystemAgentBootstrapError::Rejected(
                vos::agent::clean_bootstrap::CleanSystemAgentBootstrapRejection::InvalidDecision,
            )
        };
        let mut signer = CleanOperatorIdentitySigner::new(operator)
            .map_err(|_| CleanSystemAgentBootstrapError::Signer)?;
        let public = signer.raw_public_key();
        if public != self.descriptor.authority.public_key {
            return Err(CleanSystemAgentBootstrapError::Signer);
        }
        let identity = &self.descriptor.identity;
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId::ZERO,
            authority: self.authority_target(),
            managed: ManagedAgentTarget {
                space: identity.space,
                agent: identity.agent,
                owner: identity.owner,
                profile: AgentProfile::Shared,
                runtime_deployment: identity.runtime_deployment,
                transition_producer: identity.transition_producer,
            },
            principal: identity.owner,
            credential: CredentialId::of_public_key(&public),
            request_sequence: NonZeroU64::new(1).expect("one is nonzero"),
            credential_public_key: public,
            authenticated_node: Some(vos::agent::sdk::NodeId(merge.node().0)),
            requested_valid_from: observed_slot,
            requested_expires_at: u64::MAX,
            plan: self
                .catalog_request
                .authorization_plan()
                .ok_or_else(invalid)?,
            signature: [0; 64],
        };
        call.invocation = call.expected_invocation();
        call.signature = sign_exact(operator, &call.signing_bytes())
            .map_err(|_| CleanSystemAgentBootstrapError::Signer)?;
        call.validate_shape().map_err(|_| invalid())?;
        AuthorizedCleanSystemAgentBootstrap::prepare_root_authorized(
            self.descriptor,
            self.runtime.exact_bytes().to_vec(),
            self.replicas,
            observed_slot,
            self.authority_package.exact_bytes().to_vec(),
            self.authority_request,
            self.catalog_package.exact_bytes().to_vec(),
            self.catalog_request,
            call,
            vos::agent::execution::MAX_EXECUTION_GAS,
            &mut signer,
            certifier,
            trust,
            merge,
        )
    }
}

/// Shared immutable bootstrap derivation for startup and fresh CLI requests.
/// This derives an expected target, not proof of the daemon's live state.
pub(crate) fn derive_system_authority_target(
    space: SpaceId,
    operator_public: [u8; 32],
    runtime: &vos::agent::package_admission::AdmittedRuntimePackage,
    authority_package: &AdmittedActorPackage,
) -> anyhow::Result<(AuthorityActorTarget, Hash)> {
    let principal = PrincipalId::of_public_key(&operator_public);
    let producer = ProducerId::of_public_key(&operator_public);
    anyhow::ensure!(
        runtime.producer() == producer && authority_package.producer() == producer,
        "system packages must be signed by the configured root"
    );
    authority_package.require_runtime(AgentProfile::Shared, runtime)?;
    let nonce = Hash::digest(
        b"vos/system-agent/creation-nonce/v1",
        &[space.as_bytes(), &operator_public],
    );
    let agent = AgentId::derive(space, principal, nonce.as_bytes());
    let target = AuthorityActorTarget {
        space,
        system_agent: agent,
        system_runtime_deployment: runtime.deployment(),
        binding: AgentAuthorityBinding {
            policy: Hash::digest(
                b"vos/system-authority/policy-binding/v1",
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    authority_package.package_ref().hash.as_bytes(),
                ],
            ),
            issuer: AuthorityIssuer {
                principal,
                actor: ActorId::top_level(agent, SYSTEM_AUTHORITY_NAME),
                deployment: authority_package.deployment(),
                program: authority_package.program(),
                producer: authority_package.producer(),
            },
            public_key: operator_public,
            initial_epoch: 1,
        },
    };
    anyhow::ensure!(
        target.is_valid(),
        "derived system-authority target is invalid"
    );
    Ok((target, nonce))
}

/// Start or exactly reopen the native system Agent after the node network has
/// been attached. Every fresh identity is derived from the immutable Space
/// root and authenticated node key; no compatibility runtime is selectable.
pub(crate) fn start_clean_system_agent(
    node: &mut VosNode,
    data_dir: &Path,
    space_bytes: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
    local_storage: super::local_config::LocalAgentStorage,
    bootstrap_bundle: Option<&Path>,
) -> anyhow::Result<()> {
    let startup_started = std::time::Instant::now();
    let network = node
        .network()
        .ok_or_else(|| anyhow::anyhow!("clean system Agent requires an attached network"))?;
    let (clean_node, lifecycle) = open_clean_system_lifecycle(
        network,
        data_dir,
        space_bytes,
        operator,
        daemon,
        local_storage,
        &crate::paths::agent_host_lock_path(&space_bytes),
        bootstrap_bundle,
    )?;
    node.start_clean_local_agent_production(
        clean_node,
        lifecycle,
        Box::new(OperatorAuthorityProjectionAuthenticator::new(
            operator.clone(),
        )?),
        AgentSupervisorLimits::default(),
        PROJECTION_ROUTE_QUEUE_CAPACITY,
        PROJECTION_RECONCILE_INTERVAL,
    )?;
    tracing::debug!(
        phase = "production_ready",
        elapsed_ms = startup_started.elapsed().as_millis() as u64,
        "Clean system Agent startup phase complete"
    );
    Ok(())
}

type CleanProductionLifecycle = vos::agent::local_lifecycle::LocalLifecycleController<
    super::clean_store::CleanSystemAgentPinsFile,
    super::clean_store::CleanSystemAgentBootstrapFile,
    super::clean_store::CleanManagementIssuerFile,
    CleanManagementLifecycleStoreFactory,
    OwnedCleanOperatorIdentitySigner,
>;

/// Construct and recover all file owners before handing them to the node. The
/// explicit lock path also permits isolated recovery qualification without
/// changing process-global configuration or exposing a second startup mode.
fn open_clean_system_lifecycle(
    network: Arc<vos::network::Network>,
    data_dir: &Path,
    space_bytes: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
    local_storage: super::local_config::LocalAgentStorage,
    host_lock: &Path,
    bootstrap_bundle: Option<&Path>,
) -> anyhow::Result<(vos::agent::sdk::NodeId, CleanProductionLifecycle)> {
    let certified = bootstrap_bundle
        .map(|path| {
            read_certified_bootstrap_bundle(&data_dir.join(path), space_bytes, operator, daemon)
        })
        .transpose()?;
    open_clean_system_lifecycle_with_inputs(
        network,
        data_dir,
        space_bytes,
        operator,
        daemon,
        local_storage,
        host_lock,
        certified.as_ref(),
        #[cfg(test)]
        None,
    )
}

fn read_certified_bootstrap_bundle(
    path: &Path,
    space: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
) -> anyhow::Result<PreparedCleanSystemAgentBootstrap> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use vos::agent::clean_bootstrap::MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES as u64,
        "bootstrap bundle must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_CLEAN_SYSTEM_AGENT_IMPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let (plan, provision, catalog) = PreparedCleanSystemAgentBootstrap::decode_import_parts(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid bootstrap bundle encoding: {error:?}"))?;
    let node = node_id_from_authenticated_peer(&daemon.public().to_peer_id());
    anyhow::ensure!(
        plan.pins().space() == SpaceId(space)
            && plan
                .pins()
                .replicas()
                .member_by_node(HostNodeId(node.0))
                .is_some(),
        "bootstrap bundle belongs to another Space or node"
    );
    let root_key = raw_public_key(operator)?;
    let members = plan.pins().root().record().initial_committee().members();
    anyhow::ensure!(
        members.len() == 1 && members[0].public_key() == &root_key,
        "bootstrap bundle was not certified by the configured root operator"
    );
    let descriptor = plan.pins().descriptor();
    let trust = Arc::new(SystemAgentTrust::new(
        plan.pins().observed_slot(),
        HostSpaceId(space),
        host_authority_binding(descriptor.identity.agent, descriptor.authority),
    ));
    let merge = Arc::new(
        Ed25519NodeMergeAuthenticator::new(daemon.clone())
            .map_err(|error| anyhow::anyhow!("construct bootstrap verifier: {error:?}"))?,
    );
    PreparedCleanSystemAgentBootstrap::from_common_certified_parts(
        plan, provision, catalog, trust, merge,
    )
    .map_err(Into::into)
}

/// Directory, under the root node's Space data directory, that retains the
/// root's genesis certification for one prepared fixed-roster bundle.
pub(crate) const FIXED_ROSTER_CERTIFICATION_DIRECTORY: &str = "system-roster-certification";
const NODE_ENROLLMENT_MAGIC: &[u8; 4] = b"VNE1";
/// Exact size of an exported node enrollment: magic, Space, owner principal,
/// transport key, encryption key and transport signature.
pub(crate) const NODE_ENROLLMENT_FILE_BYTES: usize = 4 + 4 * 32 + 64;

/// This node's signed enrollment for the Space whose root is `operator`.
/// The joining node sends it to the root, which certifies the fixed roster.
pub(crate) fn local_node_enrollment(
    space: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
) -> anyhow::Result<vos::agent::sdk::private::NodeEncryptionEnrollment> {
    require_ed25519(operator, "space root")?;
    require_ed25519(daemon, "node transport")?;
    let space = SpaceId(space);
    let owner = PrincipalId::of_public_key(&raw_public_key(operator)?);
    let enrollment = sign_node_encryption_enrollment(
        daemon,
        space,
        owner,
        derive_node_encryption_public(daemon, space)?,
    )?;
    anyhow::ensure!(
        enrollment.node == node_id_from_authenticated_peer(&daemon.public().to_peer_id()),
        "node enrollment does not bind the authenticated transport identity"
    );
    Ok(enrollment)
}

pub(crate) fn encode_node_enrollment(
    enrollment: &vos::agent::sdk::private::NodeEncryptionEnrollment,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(NODE_ENROLLMENT_FILE_BYTES);
    bytes.extend_from_slice(NODE_ENROLLMENT_MAGIC);
    bytes.extend_from_slice(&enrollment.space.0);
    bytes.extend_from_slice(&enrollment.principal.0);
    bytes.extend_from_slice(&enrollment.transport_public_key);
    bytes.extend_from_slice(&enrollment.encryption_public_key);
    bytes.extend_from_slice(&enrollment.transport_signature);
    bytes
}

/// Strict inverse of [`encode_node_enrollment`]. Every redundant identity
/// field is re-derived from the transport key and the signature is verified
/// before the enrollment can enter a roster.
pub(crate) fn decode_node_enrollment(
    bytes: &[u8],
) -> anyhow::Result<vos::agent::sdk::private::NodeEncryptionEnrollment> {
    use vos::agent::private_crypto::StrictNodeEncryptionEnrollmentVerifier;
    anyhow::ensure!(
        bytes.len() == NODE_ENROLLMENT_FILE_BYTES && bytes.starts_with(NODE_ENROLLMENT_MAGIC),
        "node enrollment must be exactly {NODE_ENROLLMENT_FILE_BYTES} bytes of VNE1"
    );
    let field = |index: usize| -> [u8; 32] {
        let start = NODE_ENROLLMENT_MAGIC.len() + index * 32;
        bytes[start..start + 32].try_into().expect("bounded field")
    };
    let signature: [u8; 64] = bytes[NODE_ENROLLMENT_FILE_BYTES - 64..]
        .try_into()
        .expect("bounded signature");
    let enrollment = vos::agent::sdk::private::NodeEncryptionEnrollment::from_keys(
        SpaceId(field(0)),
        PrincipalId(field(1)),
        field(2),
        field(3),
        signature,
    );
    anyhow::ensure!(
        enrollment.verify_with(&StrictNodeEncryptionEnrollmentVerifier),
        "node enrollment has an invalid shape or transport signature"
    );
    Ok(enrollment)
}

/// Certify one common fixed-roster bootstrap bundle on the Space root node.
///
/// `enrollments` must hold exactly three distinct signed enrollments for this
/// Space and root, including this node's own. The root certification is kept
/// under [`FIXED_ROSTER_CERTIFICATION_DIRECTORY`], apart from the live system
/// Agent stores, so preparing the bundle does not start this node. Every
/// member (this node included) then starts once with the returned bytes as
/// its `system_bootstrap_bundle`.
pub(crate) fn prepare_fixed_roster_bundle(
    data_dir: &Path,
    space_bytes: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
    local_storage: super::local_config::LocalAgentStorage,
    enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    #[cfg(test)] test_inputs: Option<&StartupTestInputs>,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        enrollments.len() == 3,
        "a fixed roster bundle requires exactly three node enrollments"
    );
    let space = SpaceId(space_bytes);
    let local = local_node_enrollment(space_bytes, operator, daemon)?;
    anyhow::ensure!(
        enrollments.contains(&local),
        "the root node's own enrollment must be part of the roster"
    );
    let certification = data_dir.join(FIXED_ROSTER_CERTIFICATION_DIRECTORY);
    anyhow::ensure!(
        std::fs::symlink_metadata(&certification)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "a fixed roster was already certified under {}; reuse its bundle",
        certification.display()
    );
    let operator_public = raw_public_key(operator)?;
    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_storage(local_storage)?,
        SYSTEM_AUTHORITY_NAME,
        operator,
    )?;
    let catalog = crate::bundled::root_signed_actor_package(
        crate::bundled::system_catalog_package_template(),
        SYSTEM_CATALOG_NAME,
        operator,
    )?;
    #[cfg(test)]
    let (runtime, authority, catalog) =
        test_inputs.map_or((runtime, authority, catalog), |inputs| {
            (
                inputs.runtime.clone(),
                inputs.authority.clone(),
                inputs.catalog.clone(),
            )
        });
    let materials = SystemBootstrapMaterials::new(
        space,
        operator_public,
        local.node,
        runtime,
        authority,
        catalog,
        enrollments,
    )?;
    let target = materials.authority_target();
    let (_, _, _, genesis) =
        CleanSystemAgentFileStores::open_or_create(&certification)?.into_production_parts();
    let archive = CleanSystemAgentGenesisArchive::new(
        genesis,
        HostSpaceId(space_bytes),
        HostAgentId(target.system_agent.0),
        HostNodeId(local.node.0),
        HostHash(target.binding.commitment().0),
        operator.clone(),
    )?;
    let slot = system_logical_slot()?;
    let trust = Arc::new(SystemAgentTrust::new(
        slot,
        HostSpaceId(space_bytes),
        host_authority_binding(target.system_agent, target.binding),
    ));
    let merge = Arc::new(
        Ed25519NodeMergeAuthenticator::new(daemon.clone())
            .map_err(|error| anyhow::anyhow!("construct roster merge signer: {error:?}"))?,
    );
    let prepared = materials.prepare(
        operator,
        slot,
        &mut |root, proposal: &_, catalog: &_| archive.certify_fresh(root, proposal, catalog),
        trust,
        merge,
    )?;
    prepared
        .encode_import()
        .map_err(|error| anyhow::anyhow!("encode fixed roster bundle: {error:?}"))
}

#[cfg(test)]
pub(crate) struct StartupTestInputs {
    runtime: vos::agent::package_admission::AdmittedRuntimePackage,
    authority: AdmittedActorPackage,
    catalog: AdmittedActorPackage,
    clock: Arc<AtomicU64>,
}

fn open_clean_system_lifecycle_with_inputs(
    network: Arc<vos::network::Network>,
    data_dir: &Path,
    space_bytes: [u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
    local_storage: super::local_config::LocalAgentStorage,
    host_lock: &Path,
    certified_inputs: Option<&PreparedCleanSystemAgentBootstrap>,
    #[cfg(test)] test_inputs: Option<&StartupTestInputs>,
) -> anyhow::Result<(vos::agent::sdk::NodeId, CleanProductionLifecycle)> {
    // A one- or three-node roster is accepted only as a root-certified common
    // bundle (`read_certified_bootstrap_bundle`) or as the exact plan an
    // earlier certified startup persisted; no ambient roster is constructed.
    super::local_config::validate_local_storage_roots(data_dir, local_storage)?;
    let startup_started = std::time::Instant::now();
    let report_phase = |phase: &'static str| {
        tracing::debug!(
            phase,
            elapsed_ms = startup_started.elapsed().as_millis() as u64,
            "Clean system Agent startup phase complete"
        );
    };
    require_ed25519(operator, "space root")?;
    require_ed25519(daemon, "node transport")?;

    let space = SpaceId(space_bytes);
    let operator_public = raw_public_key(operator)?;
    let node_public = raw_public_key(daemon)?;
    let operator_principal = PrincipalId::of_public_key(&operator_public);
    let operator_producer = ProducerId::of_public_key(&operator_public);
    let transition_producer = ProducerId::of_public_key(&node_public);
    if transition_producer == operator_producer {
        anyhow::bail!("system Agent requires distinct root and node signing identities");
    }

    let peer = daemon.public().to_peer_id();
    let clean_node = node_id_from_authenticated_peer(&peer);

    let stores =
        CleanSystemAgentFileStores::open_or_create(data_dir.join(SYSTEM_AGENT_CONTROL_DIRECTORY))?;
    let (mut pins_store, mut record_store, issuer_store, genesis_store) =
        stores.into_production_parts();
    let stored_plan = record_store
        .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)?
        .map(|bytes| {
            CleanSystemAgentBootstrapRecord::authorized_plan(&bytes)
                .map_err(|error| anyhow::anyhow!("invalid persisted bootstrap plan: {error:?}"))
        })
        .transpose()?;

    let runtime = crate::bundled::root_signed_agent_runtime_package(operator)?;
    let authority_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template_for_storage(local_storage)?,
        SYSTEM_AUTHORITY_NAME,
        operator,
    )?;
    #[cfg(test)]
    let (runtime, authority_package) = test_inputs.map_or((runtime, authority_package), |inputs| {
        (inputs.runtime.clone(), inputs.authority.clone())
    });
    let catalog_package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_catalog_package_template(),
        SYSTEM_CATALOG_NAME,
        operator,
    )?;
    #[cfg(test)]
    let catalog_package = test_inputs.map_or(catalog_package, |inputs| inputs.catalog.clone());
    let (runtime, authority_package, catalog_package) = match certified_inputs
        .map(|inputs| inputs.plan())
        .or(stored_plan.as_ref())
    {
        Some(plan) => {
            anyhow::ensure!(
                plan.pins().space() == space && plan.pins().node() == clean_node,
                "certified bootstrap inputs belong to another Space or node"
            );
            (
                vos::agent::package_admission::admit_runtime_package(plan.runtime_package_bytes())?,
                vos::agent::package_admission::admit_actor_package(plan.authority_package_bytes())?,
                vos::agent::package_admission::admit_actor_package(plan.catalog_package_bytes())?,
            )
        }
        None => (runtime, authority_package, catalog_package),
    };
    let node_encryption_public = derive_node_encryption_public(daemon, space)?;
    let enrollment =
        sign_node_encryption_enrollment(daemon, space, operator_principal, node_encryption_public)?;
    if enrollment.node != clean_node {
        anyhow::bail!("node enrollment does not bind the authenticated transport identity");
    }

    let materials = SystemBootstrapMaterials::new(
        space,
        operator_public,
        clean_node,
        runtime,
        authority_package,
        catalog_package,
        &[enrollment],
    )?;
    let authority_target = materials.authority_target();
    let system_agent = authority_target.system_agent;
    let authority = authority_target.binding;
    report_phase("bootstrap_material");

    let archive = Arc::new(CleanSystemAgentGenesisArchive::new(
        genesis_store,
        HostSpaceId(space.0),
        HostAgentId(system_agent.0),
        HostNodeId(clean_node.0),
        HostHash(authority.commitment().0),
        operator.clone(),
    )?);
    if let Some(inputs) = certified_inputs {
        anyhow::ensure!(
            inputs.plan().pins().descriptor().authority == authority,
            "certified bootstrap authority differs from configured root packages"
        );
        let pins = pins_store.load(MAX_CLEAN_SYSTEM_AGENT_PINS_BYTES)?;
        let record = record_store.load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)?;
        match (pins, record) {
            (None, None) => {
                match std::fs::symlink_metadata(data_dir.join(SHARED_AGENT_HOST_DIRECTORY)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    _ => anyhow::bail!("cannot import bootstrap beside a preexisting Shared host"),
                }
                archive.import_certified(inputs.provision(), inputs.catalog())?;
            }
            (Some(_), Some(bytes)) => {
                let stored = CleanSystemAgentBootstrapRecord::authorized_plan(&bytes)
                    .map_err(|error| anyhow::anyhow!("invalid stored bootstrap plan: {error:?}"))?;
                anyhow::ensure!(
                    stored.commitment() == inputs.plan().commitment(),
                    "certified bootstrap differs from stored plan"
                );
                // Import is not repair permission for a missing/corrupt archive
                // after plan publication. Existing startup remains read-only.
                anyhow::ensure!(
                    archive.create(inputs.provision().proposal(), inputs.catalog())?
                        == *inputs.provision(),
                    "stored genesis evidence differs from import"
                );
            }
            _ => anyhow::bail!("cannot import bootstrap into partial plan stores"),
        }
    }
    let observed_slot = archive
        .stored_observed_slot()?
        .unwrap_or(system_logical_slot()?);
    let clock = SystemAgentTrust::new(
        observed_slot,
        HostSpaceId(space.0),
        host_authority_binding(system_agent, authority),
    );
    #[cfg(test)]
    let clock = SystemAgentTrust {
        test_clock: test_inputs.map(|inputs| inputs.clock.clone()),
        ..clock
    };
    let trust: Arc<dyn AgentTrustProvider> = Arc::new(clock);
    let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(
        Ed25519NodeMergeAuthenticator::new(daemon.clone())
            .map_err(|error| anyhow::anyhow!("construct node merge signer: {error:?}"))?,
    );
    let finality: Arc<dyn AgentGenesisFinalityVerifier> = Arc::new(UnavailableAgentFinality);
    let genesis: Arc<dyn SystemAgentGenesisProvider> = archive.clone();
    let mut owner_signer = CleanOperatorIdentitySigner::new(operator)?;
    let archive_for_certification = Arc::clone(&archive);
    let mut root_certifier = move |root, proposal: &_, catalog: &_| {
        archive_for_certification.certify_fresh(root, proposal, catalog)
    };
    let plan_trust = Arc::clone(&trust);
    let plan_merge = Arc::clone(&merge);
    let fresh_plan = move || {
        if let Some(inputs) = certified_inputs {
            return Ok(inputs.plan().clone());
        }
        materials
            .prepare(
                operator,
                observed_slot,
                &mut root_certifier,
                plan_trust,
                plan_merge,
            )
            .map(|prepared| prepared.into_parts().0)
    };
    let mut lifecycle_stores = CleanManagementLifecycleStoreFactory::open_or_create(
        data_dir.join(LOCAL_LIFECYCLE_DIRECTORY),
        space,
    )?;
    let lifecycle_recovery = vos::agent::local_lifecycle::discover_local_lifecycle_recovery(
        &mut lifecycle_stores,
        authority_target,
        LOCAL_LIFECYCLE_RECOVERY_LIMIT,
    )
    .map_err(|error| anyhow::anyhow!("verify Local lifecycle stores before startup: {error:?}"))?;
    let lifecycle_admission = lifecycle_recovery.startup_admission()
        .map_err(|error| anyhow::anyhow!("Local lifecycle requires incomplete-phase recovery before startup; preserved all stores: {error:?}"))?;
    report_phase("lifecycle_discovery");
    let discovered_shared_genesis = discover_shared_genesis_startup(
        data_dir,
        authority_target,
        vos::agent::shared_host::MAX_SHARED_HOST_AGENTS,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "verify Shared lifecycle stores before startup; preserved stores: {error:?}"
        )
    })?;
    let existing_shared_roots = discovered_shared_genesis.is_some();
    let mut shared_genesis = match discovered_shared_genesis {
        Some(controller) => controller,
        None => super::clean_store::CleanSharedGenesisStartupEntry::into_controller(
            authority_target,
            Vec::new(),
        )
        .map_err(|error| anyhow::anyhow!("initialize empty Shared owner: {error:?}"))?,
    };
    report_phase("shared_lifecycle_discovery");
    tracing::debug!(
        existing_roots = existing_shared_roots,
        "Shared lifecycle owner selected"
    );
    let operation_journal = CleanNativeAuthorityOperationJournal::open_or_create(
        data_dir.join(OPERATION_JOURNAL_DIRECTORY),
        authority_target,
    )?;
    let operation_ids = operation_journal.discover(
        2 * vos::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS,
    )?;
    let (operation_coordinator, operation_issuer) =
        CleanAuthorityOperationFiles::open_or_create(data_dir.join(OPERATION_IMAGES_DIRECTORY))?
            .into_parts();
    let operation_completions = CleanNativeAuthorityOperationCompletions::open_or_create(
        data_dir.join(OPERATION_COMPLETIONS_DIRECTORY),
        authority_target,
    )?;
    let mut operations = vos::agent::clean_bootstrap::NativeAuthorityOperationController::new(
        authority_target,
        operation_coordinator,
        operation_issuer,
        operation_journal,
    )
    .with_completions(operation_completions)
    .with_retirements(CleanNativeAuthorityOperationRetirements::open_or_create(
        data_dir.join(OPERATION_RETIREMENTS_DIRECTORY),
        authority_target,
    )?)
    .with_denials(CleanNativeAuthorityOperationDenials::open_or_create(
        data_dir.join(OPERATION_DENIALS_DIRECTORY),
        authority_target,
    )?);
    let admin_stores = super::clean_store::admin_store::CleanNativeAuthorityAdminStores::open(
        &data_dir.join(ADMIN_DISPATCH_DIRECTORY),
        &data_dir.join(ADMIN_RESULTS_DIRECTORY),
        &data_dir.join(ADMIN_RETIREMENTS_DIRECTORY),
        authority_target,
        true,
    )?;
    let admin_ids = admin_stores.journal.discover()?;
    let mut admins = vos::agent::clean_bootstrap::NativeAuthorityAdminController::new(
        authority_target,
        admin_stores.journal,
        admin_stores.terminals,
    );
    let operation_admission = operations
        .startup_admission(&operation_ids)
        .map_err(|error| {
            anyhow::anyhow!("verify operation recovery before startup; preserved stores: {error:?}")
        })?;
    let operation_admission = admins
        .startup_admission(operation_admission, &admin_ids)
        .map_err(|error| {
            anyhow::anyhow!("verify admin recovery before startup; preserved stores: {error:?}")
        })?;
    report_phase("operation_admission");
    let operation_admission = shared_genesis
        .startup_admission(operation_admission)
        .map_err(|error| {
            anyhow::anyhow!("admit Shared recovery before startup; preserved stores: {error:?}")
        })?;
    let mut pending = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
        pins_store,
        record_store,
        issuer_store,
        &mut owner_signer,
        fresh_plan,
        data_dir.join(SHARED_AGENT_HOST_DIRECTORY),
        host_lock,
        space,
        clean_node,
        Arc::clone(&trust),
        Arc::clone(&merge),
        finality,
        genesis,
        network,
        Some(&lifecycle_admission),
        Some(&operation_admission),
    )?;
    if let Some(inputs) = certified_inputs {
        anyhow::ensure!(
            pending.pins() == inputs.plan().pins(),
            "stored bootstrap differs from supplied certified inputs"
        );
    }
    let retry_started = std::time::Instant::now();
    let mut owner = loop {
        match pending.try_complete(&mut owner_signer) {
            Ok(Some(owner)) => break owner,
            Ok(None) => anyhow::bail!("system bootstrap owner was already transferred"),
            Err(CleanSystemAgentBootstrapError::Host(
                vos::agent::shared_host::SharedAgentHostError::Unavailable,
            )) if retry_started.elapsed() < SYSTEM_BOOTSTRAP_RETRY_WINDOW => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    };
    report_phase("system_owner");
    drop(operation_admission);
    let mut admin_signer = OwnedCleanOperatorIdentitySigner::new(operator.clone())?;
    admins
        .recover(&mut owner, &admin_ids, &mut admin_signer)
        .map_err(|error| {
            anyhow::anyhow!(
                "complete retained admin recovery before routes; preserved stores: {error:?}"
            )
        })?;
    report_phase("admin_recovery");
    let local_root = data_dir.join(LOCAL_AGENT_HOST_DIRECTORY);
    let local = match std::fs::symlink_metadata(&local_root) {
        Ok(_) => vos::agent::local_sdk_host::LocalAgentHost::open(
            &local_root,
            space,
            clean_node,
            Arc::clone(&trust),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            vos::agent::local_sdk_host::LocalAgentHost::create(
                &local_root,
                space,
                clean_node,
                Arc::clone(&trust),
            )?
        }
        Err(error) => return Err(error.into()),
    };
    report_phase("local_host");
    let lifecycle = vos::agent::local_lifecycle::LocalLifecycleController::with_recovery(
        owner,
        local,
        lifecycle_stores,
        OwnedCleanOperatorIdentitySigner::new(operator.clone())?,
        lifecycle_recovery,
    )?;
    let mut shared_files = super::clean_store::CleanSharedGenesisAdmissionFiles::open(
        data_dir,
        authority_target,
        vos::agent::shared_host::MAX_SHARED_HOST_AGENTS,
    )?;
    let lifecycle = lifecycle
        .with_shared_genesis_admission(
            shared_genesis,
            move |descriptor, call, runtime, replicas| {
                shared_files.reserve(descriptor, call, runtime, replicas)
            },
        )
        .map_err(|error| {
            anyhow::anyhow!("complete Shared recovery before routes; preserved stores: {error:?}")
        })?;
    report_phase("shared_lifecycle_recovery");
    let lifecycle = lifecycle
        .with_operations(
            operations,
            OwnedCleanOperatorIdentitySigner::new(operator.clone())?,
        )?
        .with_admins(admins, admin_signer)?;
    report_phase("lifecycle_controller");
    Ok((clean_node, lifecycle))
}

#[cfg(test)]
#[path = "clean_startup_tests.rs"]
mod tests;

fn install_request(
    agent: AgentId,
    package: &AdmittedActorPackage,
    bytes: Vec<u8>,
    role: &[u8],
) -> anyhow::Result<ManagementRequest> {
    let schema = vos::agent::sdk::schema::decode(package.state_lane_schema_bytes())
        .map_err(|error| anyhow::anyhow!("decode {} schema: {error:?}", package.manifest().name))?;
    let installation_data = InstallationData {
        reference: BlobRef::of_bytes(&bytes),
        bytes,
    };
    let name = package.manifest().name.clone();
    let actor = ActorId::top_level(agent, &name);
    let id = Hash::digest(
        b"vos/system-agent/root-installation/v1",
        &[agent.as_bytes(), actor.as_bytes(), role],
    );
    let reservation = Hash::digest(
        b"vos/system-agent/root-registry-reservation/v1",
        &[agent.as_bytes(), actor.as_bytes(), role],
    );
    let entry = ActorEntry {
        actor,
        name,
        parent: None,
        deployment: package.deployment(),
        program: package.program(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi: schema
            .constructor_abi()
            .map_err(|error| anyhow::anyhow!("derive actor constructor ABI: {error:?}"))?,
        installation_data: Some(installation_data.reference.clone()),
        state_layout: schema
            .state_layout_hash()
            .map_err(|error| anyhow::anyhow!("derive actor state layout: {error:?}"))?,
        lanes: package.requirements().lanes,
        suspended: false,
    };
    let request = ManagementRequest::Install(Box::new(vos::agent::sdk::InstallActor {
        installation_id: InstallationId(id.0),
        registry_reservation: reservation,
        entry,
        producer: package.producer(),
        package: package.package_ref().clone(),
        agent_schema: package.manifest().state_lane_schema.clone(),
        method_policy: package.manifest().method_policy.clone(),
        constructor_abi: schema
            .constructor_abi()
            .map_err(|error| anyhow::anyhow!("derive actor constructor ABI: {error:?}"))?,
        installation_data: Some(installation_data),
        state_layout: schema
            .state_layout_hash()
            .map_err(|error| anyhow::anyhow!("derive actor state layout: {error:?}"))?,
        contract: package.manifest().contract,
        requirements: package.requirements(),
    }));
    if !request.is_valid() {
        anyhow::bail!(
            "derived {} install request is invalid",
            package.manifest().name
        );
    }
    Ok(request)
}

fn require_ed25519(keypair: &Keypair, label: &str) -> anyhow::Result<()> {
    if keypair.key_type() != KeyType::Ed25519 {
        anyhow::bail!("{label} identity must be Ed25519");
    }
    Ok(())
}

fn raw_public_key(keypair: &Keypair) -> anyhow::Result<[u8; 32]> {
    keypair
        .public()
        .try_into_ed25519()
        .map(|public| public.to_bytes())
        .map_err(|_| anyhow::anyhow!("Ed25519 public key unavailable"))
}

fn sign_exact(keypair: &Keypair, message: &[u8]) -> anyhow::Result<[u8; 64]> {
    keypair
        .sign(message)
        .map_err(|error| anyhow::anyhow!("Ed25519 signing failed: {error}"))?
        .try_into()
        .map_err(|signature: Vec<u8>| {
            anyhow::anyhow!("Ed25519 signer returned {} bytes", signature.len())
        })
}

fn derive_node_encryption_public(daemon: &Keypair, space: SpaceId) -> anyhow::Result<[u8; 32]> {
    let mut secret_encoding = daemon
        .to_protobuf_encoding()
        .map_err(|error| anyhow::anyhow!("encode node key for X25519 derivation: {error}"))?;
    let secret = Hash::digest(
        b"vos/node/x25519-from-transport/v1",
        &[space.as_bytes(), &secret_encoding],
    );
    secret_encoding.zeroize();
    let key = vos::agent::private_crypto::PrivateNodeDecryptionKey::from_bytes(secret.0)
        .map_err(|error| anyhow::anyhow!("derive node X25519 key: {error}"))?;
    Ok(key.public_key())
}

fn system_logical_slot() -> anyhow::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("system clock precedes Unix epoch"))?
            .as_secs(),
    )
    .map_err(|_| anyhow::anyhow!("system logical clock overflow"))
}

fn host_authority_binding(
    system_agent: AgentId,
    authority: AgentAuthorityBinding,
) -> vos::agent::authority::AgentAuthorityBinding {
    let public_key = ed25519_public_key_wire(authority.public_key);
    vos::agent::authority::AgentAuthorityBinding {
        agent: HostAgentId(system_agent.0),
        actor: vos::service::ActorId(authority.issuer.actor.0),
        deployment: vos::service::DeploymentId(authority.issuer.deployment.0),
        program: vos::service::ProgramId(authority.issuer.program.0),
        producer: vos::service::ProducerId::of_public_key(&public_key),
        public_key,
    }
}

struct SystemAgentTrust {
    floor: AtomicU64,
    space: HostSpaceId,
    authority: vos::agent::authority::AgentAuthorityBinding,
    #[cfg(test)]
    test_clock: Option<Arc<AtomicU64>>,
}

impl SystemAgentTrust {
    fn new(
        floor: u64,
        space: HostSpaceId,
        authority: vos::agent::authority::AgentAuthorityBinding,
    ) -> Self {
        Self {
            floor: AtomicU64::new(floor),
            space,
            authority,
            #[cfg(test)]
            test_clock: None,
        }
    }
}

impl AgentTrustProvider for SystemAgentTrust {
    fn current_logical_slot(&self) -> Option<u64> {
        let observed = system_logical_slot().ok()?;
        #[cfg(test)]
        let observed = self.test_clock.as_ref().map_or(observed, |clock| {
            // Requests still use wall-clock valid_from slots. Slow guest
            // execution must not leave the injected clock behind them;
            // explicit forward jumps for expiry remain authoritative.
            clock.fetch_max(observed, Ordering::AcqRel);
            clock.fetch_add(1, Ordering::AcqRel)
        });
        Some(
            self.floor
                .fetch_max(observed, Ordering::AcqRel)
                .max(observed),
        )
    }

    fn authority_for_space(
        &self,
        space: HostSpaceId,
    ) -> Option<vos::agent::authority::AgentAuthorityBinding> {
        (space == self.space).then(|| self.authority.clone())
    }

    fn verify_package(&self, _agent: &AgentConfig, package: &Package) -> bool {
        package.verify_signature(&Ed25519PackageVerifier).is_ok()
    }
}

/// Root system genesis has its own pinned QC path. This fallback refuses all
/// ordinary provisions; deferred recovery replaces it only with exact proofs
/// independently replayed by the root-pinned owner, never archive-only trust.
struct UnavailableAgentFinality;

impl AgentGenesisFinalityVerifier for UnavailableAgentFinality {
    fn verify_finalized(
        &self,
        _provision: &vos::agent::genesis::AgentGenesisProvision,
    ) -> Result<(), AgentGenesisFinalityError> {
        Err(AgentGenesisFinalityError::Unavailable)
    }
}
