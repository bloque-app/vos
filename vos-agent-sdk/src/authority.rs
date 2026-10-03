//! Guest-verifiable authority receipt model.

use core::num::NonZeroU64;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::contract::{ActorPackageContract, RuntimePackageContract};
use crate::private::NodeEncryptionEnrollment;
use crate::{
    ActorEntry, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, CapabilityId, CredentialId, DeploymentId, Hash, InstallationId, InvocationContext,
    InvocationId, InvocationRoleClaims, ManagementError, ManagementReply, ManagementRequest,
    MethodMode, NodeId, PrincipalId, PrivateRecoveryBinding, ProducerId, ProgramId, ReplicaRole,
    RoleId, RuntimeCapabilities, RuntimeRequirements, RuntimeUpgrade, SpaceId, UpgradeActor,
};

pub const AUTHORITY_PUBLIC_KEY_BYTES: usize = 32;
pub const AUTHORITY_SIGNATURE_BYTES: usize = 64;
pub const CREDENTIAL_PUBLIC_KEY_BYTES: usize = 32;
pub const CREDENTIAL_SIGNATURE_BYTES: usize = 64;
/// Maximum number of records returned by one authority inventory query.
/// Encoded reply size remains an independent, stricter bound.
pub const MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES: usize = 8;
/// Leave room for the actor reply's canonical Bytes tag and u32 length.
pub const MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES: usize = crate::MAX_INVOCATION_REPLY_BYTES - 5;
/// Maximum replicas returned by one Agent-roster query. A complete maximum
/// roster is reconstructed across bounded pages sharing one projection head.
pub const MAX_AUTHORITY_REPLICA_PAGE_ENTRIES: usize = 64;
/// Combined pages preserve dense replica-roster throughput. Agent and actor
/// rows share the stricter eight-complex-row budget, plus the total byte cap.
pub const MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES: usize = MAX_AUTHORITY_REPLICA_PAGE_ENTRIES;
/// Maximum application authorization grants projected for one Principal.
pub const MAX_AUTHORITY_PRINCIPAL_GRANTS: usize = 64;
/// Bound on the lifetime of newly admitted delegated reads, in trusted slots.
/// This is not a deadline for finishing an already committed invocation.
pub const MAX_AUTHORITY_PROJECTION_RECOVERY_SLOTS: u64 = 120;

/// Exact installed system-authority route selected by a credential call.
///
/// The complete independently selected binding is carried here. An issuer
/// identity alone is not a trust anchor: policy, signing key, and initial
/// epoch must not be substituted while retaining the same actor route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityActorTarget {
    pub space: SpaceId,
    pub system_agent: AgentId,
    pub system_runtime_deployment: DeploymentId,
    pub binding: AgentAuthorityBinding,
}

impl AuthorityActorTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.system_agent != AgentId::ZERO
            && self.system_runtime_deployment != DeploymentId::ZERO
            && self.binding.is_valid()
    }
}

/// Exact Agent route whose management request is being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedAgentTarget {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub profile: AgentProfile,
    pub runtime_deployment: DeploymentId,
    pub transition_producer: ProducerId,
}

impl ManagedAgentTarget {
    pub fn is_valid(self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.owner != PrincipalId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.transition_producer != ProducerId::ZERO
    }
}

/// Replica facts retained directly by a bounded authorization plan. The
/// principal is reconstructed from the authority's exact Node enrollment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactReplicaSlot {
    pub node: NodeId,
    pub role: ReplicaRole,
}

impl CompactReplicaSlot {
    pub fn is_valid(self) -> bool {
        self.node.0 != NodeId::ZERO.0
    }
}

/// Descriptor fields other than replica principals. Create authorization
/// reconstructs those principals from enrollments and then verifies the full
/// descriptor commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactAgentDescriptor {
    pub identity: AgentIdentity,
    pub creation_nonce: Hash,
    pub authority: AgentAuthorityBinding,
    pub private_recovery: Option<PrivateRecoveryBinding>,
    pub runtime_package: BlobRef,
    pub runtime_contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
}

impl CompactAgentDescriptor {
    fn from_descriptor(descriptor: &AgentDescriptor) -> Self {
        Self {
            identity: descriptor.identity.clone(),
            creation_nonce: descriptor.creation_nonce,
            authority: descriptor.authority,
            private_recovery: descriptor.private_recovery,
            runtime_package: descriptor.runtime_package.clone(),
            runtime_contract: descriptor.runtime_contract,
            capabilities: descriptor.capabilities,
        }
    }

    pub fn with_replicas(&self, replicas: alloc::vec::Vec<crate::AgentReplica>) -> AgentDescriptor {
        AgentDescriptor {
            identity: self.identity.clone(),
            creation_nonce: self.creation_nonce,
            authority: self.authority,
            private_recovery: self.private_recovery,
            runtime_package: self.runtime_package.clone(),
            runtime_contract: self.runtime_contract,
            capabilities: self.capabilities,
            replicas,
        }
    }
}

/// Install policy facts with constructor bytes represented only by their
/// content-addressed [`BlobRef`] in `entry.installation_data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactInstallActor {
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub contract: ActorPackageContract,
    pub requirements: RuntimeRequirements,
}

impl CompactInstallActor {
    fn from_install(value: &crate::InstallActor) -> Self {
        Self {
            installation_id: value.installation_id,
            registry_reservation: value.registry_reservation,
            entry: value.entry.clone(),
            producer: value.producer,
            contract: value.contract,
            requirements: value.requirements,
        }
    }

    pub fn matches_install(&self, value: &crate::InstallActor) -> bool {
        ManagementRequest::Install(Box::new(value.clone())).is_valid()
            && self.installation_id == value.installation_id
            && self.registry_reservation == value.registry_reservation
            && self.entry == value.entry
            && self.producer == value.producer
            && self.contract == value.contract
            && self.requirements == value.requirements
    }

    pub fn is_valid(&self) -> bool {
        self.installation_id != InstallationId::ZERO
            && self.registry_reservation != Hash::ZERO
            && self.entry.validate().is_ok()
            && self.producer != ProducerId::ZERO
            && self.contract.is_valid()
            && self.requirements.lanes == self.entry.lanes
    }

    /// Immutable install-lineage commitment retained across actor upgrades.
    /// This is the exact SDK authorization-plan commitment and is therefore
    /// identical whether derived from the compact authority value or the full
    /// runtime request.
    pub fn lineage_commitment(&self) -> Hash {
        ManagementAuthorizationPlan::Install(Box::new(self.clone())).commitment()
    }
}

impl crate::InstallActor {
    /// Derive the same immutable SDK install lineage used by the authority's
    /// compact install plan without depending on transitional lifecycle wire.
    pub fn lineage_commitment(&self) -> Hash {
        CompactInstallActor::from_install(self).lineage_commitment()
    }
}

/// Bounded policy input carried by ACC3 and MAP2. A host or guest holding the
/// full management request must derive this exact plan and compare it before
/// applying the resulting receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementAuthorizationPlan {
    Create {
        descriptor: Box<CompactAgentDescriptor>,
        replicas: Vec<CompactReplicaSlot>,
        descriptor_commitment: Hash,
    },
    Install(Box<CompactInstallActor>),
    UpgradeActor(Box<UpgradeActor>),
    Suspend {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    Resume {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    RemoveLeaf {
        actor: ActorId,
        expected_deployment: DeploymentId,
    },
    UpgradeRuntime(Box<RuntimeUpgrade>),
    ChangeReplicas {
        expected_generation: Hash,
        replicas: Vec<CompactReplicaSlot>,
        replica_roster_commitment: Hash,
    },
}

impl ManagementAuthorizationPlan {
    pub fn from_request(request: &ManagementRequest) -> Option<Self> {
        if !request.is_valid() {
            return None;
        }
        Some(match request {
            ManagementRequest::Create(descriptor) => Self::Create {
                descriptor: Box::new(CompactAgentDescriptor::from_descriptor(descriptor)),
                replicas: descriptor
                    .replicas
                    .iter()
                    .map(|replica| CompactReplicaSlot {
                        node: replica.node,
                        role: replica.role,
                    })
                    .collect(),
                descriptor_commitment: descriptor.commitment(),
            },
            ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory => {
                return None;
            }
            ManagementRequest::Install(value) => {
                Self::Install(Box::new(CompactInstallActor::from_install(value)))
            }
            ManagementRequest::UpgradeActor(value) => Self::UpgradeActor(value.clone()),
            ManagementRequest::Suspend {
                actor,
                expected_deployment,
            } => Self::Suspend {
                actor: *actor,
                expected_deployment: *expected_deployment,
            },
            ManagementRequest::Resume {
                actor,
                expected_deployment,
            } => Self::Resume {
                actor: *actor,
                expected_deployment: *expected_deployment,
            },
            ManagementRequest::RemoveLeaf {
                actor,
                expected_deployment,
            } => Self::RemoveLeaf {
                actor: *actor,
                expected_deployment: *expected_deployment,
            },
            ManagementRequest::UpgradeRuntime(value) => Self::UpgradeRuntime(value.clone()),
            ManagementRequest::ChangeReplicas {
                expected_generation,
                replicas,
            } => Self::ChangeReplicas {
                expected_generation: *expected_generation,
                replicas: replicas
                    .iter()
                    .map(|replica| CompactReplicaSlot {
                        node: replica.node,
                        role: replica.role,
                    })
                    .collect(),
                replica_roster_commitment: crate::replica_roster_commitment(replicas),
            },
            // Private controls enter through retained AOC/AOP/PCA evidence,
            // never through the generic ACC3 management plan. Execution bounds
            // are authorized by a direct receipt; they have no ACC3 plan yet.
            ManagementRequest::PrivateControl { .. } | ManagementRequest::SetExecutionLimits(_) => {
                return None;
            }
        })
    }

    pub fn is_valid(&self) -> bool {
        let slots_valid = |replicas: &[CompactReplicaSlot]| {
            !replicas.is_empty()
                && replicas.len() <= crate::MAX_AGENT_REPLICAS
                && replicas.iter().all(|replica| replica.is_valid())
                && replicas.windows(2).all(|pair| pair[0].node < pair[1].node)
        };
        match self {
            Self::Create {
                descriptor,
                replicas,
                descriptor_commitment,
            } => {
                if *descriptor_commitment == Hash::ZERO || !slots_valid(replicas) {
                    return false;
                }
                let reconstructed = descriptor.with_replicas(
                    replicas
                        .iter()
                        .map(|slot| crate::AgentReplica {
                            node: slot.node,
                            principal: descriptor.identity.owner,
                            role: slot.role,
                        })
                        .collect(),
                );
                reconstructed.validate().is_ok()
            }
            Self::Install(value) => value.is_valid(),
            Self::UpgradeActor(value) => ManagementRequest::UpgradeActor(value.clone()).is_valid(),
            Self::Suspend {
                actor,
                expected_deployment,
            }
            | Self::Resume {
                actor,
                expected_deployment,
            }
            | Self::RemoveLeaf {
                actor,
                expected_deployment,
            } => *actor != ActorId::ZERO && *expected_deployment != DeploymentId::ZERO,
            Self::UpgradeRuntime(value) => {
                ManagementRequest::UpgradeRuntime(value.clone()).is_valid()
            }
            Self::ChangeReplicas {
                expected_generation,
                replicas,
                replica_roster_commitment,
            } => {
                *expected_generation != Hash::ZERO
                    && *replica_roster_commitment != Hash::ZERO
                    && slots_valid(replicas)
            }
        }
    }

    pub fn matches_request(&self, request: &ManagementRequest) -> bool {
        Self::from_request(request).as_ref() == Some(self)
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::management_authorization_plan_commitment(self)
    }

    pub const fn authority_operation(&self) -> AuthorityOperationKind {
        match self {
            Self::Create { .. } => AuthorityOperationKind::CreateAgent,
            Self::Install(_) => AuthorityOperationKind::InstallActor,
            Self::UpgradeActor(_) => AuthorityOperationKind::UpgradeActor,
            Self::Suspend { .. } => AuthorityOperationKind::SuspendActor,
            Self::Resume { .. } => AuthorityOperationKind::ResumeActor,
            Self::RemoveLeaf { .. } => AuthorityOperationKind::RemoveActor,
            Self::UpgradeRuntime(_) => AuthorityOperationKind::UpgradeRuntime,
            Self::ChangeReplicas { .. } => AuthorityOperationKind::ChangeReplicaSet,
        }
    }

    pub fn authority_actor(&self) -> Option<(ActorId, DeploymentId)> {
        match self {
            Self::Install(value) => Some((value.entry.actor, value.entry.deployment)),
            Self::UpgradeActor(value) => Some((value.actor, value.to_deployment)),
            Self::Suspend {
                actor,
                expected_deployment,
            }
            | Self::Resume {
                actor,
                expected_deployment,
            }
            | Self::RemoveLeaf {
                actor,
                expected_deployment,
            } => Some((*actor, *expected_deployment)),
            Self::Create { .. } | Self::UpgradeRuntime(_) | Self::ChangeReplicas { .. } => None,
        }
    }
}

/// Policy operation selected by an authority receipt. Tags are stable wire
/// values; unknown tags fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityOperationKind {
    CreateAgent = 0,
    InstallActor = 1,
    UpgradeActor = 2,
    SuspendActor = 3,
    ResumeActor = 4,
    RemoveActor = 5,
    UpgradeRuntime = 6,
    InvokeActor = 7,
    ChangeReplicaSet = 8,
    InvitePrivateNode = 9,
    RevokePrivateNode = 10,
    RecoverPrivateAgent = 11,
    PublishCatalog = 12,
    /// Rotate a Private Agent's owner/data epoch without changing members.
    RotatePrivateKeys = 13,
    /// Select a new content-addressed resource policy for a Private Agent.
    SetPrivateResourcePolicy = 14,
    /// Apply one owner-signed Private actor lifecycle control. The exact
    /// lifecycle request is committed by the PCTL and the actor is exposed in
    /// the receipt selector; Private controls do not expose a deployment.
    PrivateActorLifecycle = 15,
    /// Select the Agent's per-invocation execution bounds.
    SetExecutionLimits = 16,
}

impl AuthorityOperationKind {
    pub const fn requires_actor(self) -> bool {
        matches!(
            self,
            Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::InvokeActor
                | Self::PrivateActorLifecycle
        )
    }

    /// Private lifecycle controls bind an actor but deliberately keep its
    /// encrypted deployment details inside the signed PCTL request.
    pub const fn requires_actor_deployment(self) -> bool {
        matches!(
            self,
            Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::InvokeActor
        )
    }

    /// Whether this operation participates in the standard Agent management
    /// decision journal. Invocation, Private-Agent, and catalog receipts use
    /// their own replay domains and therefore carry zero in both management
    /// replay fields.
    pub const fn uses_management_decision_journal(self) -> bool {
        matches!(
            self,
            Self::CreateAgent
                | Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::UpgradeRuntime
                | Self::SetExecutionLimits
                | Self::ChangeReplicaSet
        )
    }
}

/// Exact visible authority actor which issued the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityIssuer {
    pub principal: PrincipalId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub producer: ProducerId,
}

impl AuthorityIssuer {
    pub fn is_valid(self) -> bool {
        self.principal.0 != PrincipalId::ZERO.0
            && self.actor.0 != ActorId::ZERO.0
            && self.deployment.0 != DeploymentId::ZERO.0
            && self.program.0 != ProgramId::ZERO.0
            && self.producer.0 != ProducerId::ZERO.0
    }
}

/// One directly authenticated credential request to the system authority
/// actor. The signature covers every preceding field and the complete bounded
/// canonical [`ManagementAuthorizationPlan`]; it never covers itself.
///
/// This call is deliberately self-authenticating and carries no role or
/// capability grant. It can therefore enter the authority actor through a
/// non-circular public preflight before that actor has made a policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCredentialCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    /// Monotonic sequence in this credential's management-call domain.
    /// The authority actor accepts exactly the successor of its durable
    /// per-credential high-water mark.
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub requested_valid_from: u64,
    pub requested_expires_at: u64,
    pub plan: ManagementAuthorizationPlan,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityCredentialCall {
    /// Commitment of every caller-selected field except the derived
    /// invocation and the signature. Keeping those two outputs out of this
    /// preimage avoids a circular derivation while still binding the complete
    /// management request and caller/target tuple.
    pub fn invocation_payload_commitment(&self) -> Hash {
        crate::wire::authority_credential_call_invocation_payload_commitment(self)
    }

    pub fn derive_invocation(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        payload: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-management-invocation/v3",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    credential.as_bytes(),
                    &request_sequence.get().to_le_bytes(),
                    payload.as_bytes(),
                ],
            )
            .0,
        )
    }

    pub fn expected_invocation(&self) -> InvocationId {
        Self::derive_invocation(
            self.credential,
            self.request_sequence,
            self.invocation_payload_commitment(),
        )
    }

    /// Bytes verified by the injected Ed25519 implementation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_credential_call_signing_bytes(self)
    }

    /// Commitment of the complete signed call, including its signature.
    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-credential-call/v2",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.invocation == InvocationId::ZERO
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if self.requested_valid_from > self.requested_expires_at {
            return Err(AuthorityActorProtocolError::InvalidValidity);
        }
        if !mutating_plan_matches_targets(&self.authority, &self.managed, &self.plan) {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.signature == [0; CREDENTIAL_SIGNATURE_BYTES] {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        if crate::wire::authority_credential_call_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify the credential signature without choosing a crypto provider.
    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        if !verifier.verify(
            &self.credential_public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Exact public-preflight binding to the clean actor invocation context.
    /// Signature verification remains a separate injected operation.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.principal == Some(self.principal)
            && context.origin.credential == Some(self.credential)
            && context.origin.transport_node == self.authenticated_node
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Credential ingress family retained by the system authority. Both kinds
/// use canonical Ed25519 public keys; the distinct tag prevents an API key
/// from being silently reclassified as an SSH enrollment (or vice versa).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityCredentialKind {
    Ssh = 0,
    Api = 1,
}

/// Built-in Space role assigned to one enrolled Principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityBuiltinRole {
    Member = 0,
    Developer = 1,
    Admin = 2,
}

/// One typed credential enrollment. [`CredentialId`] remains derived from
/// the exact public key and is never interchangeable with a Principal or Node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityCredentialEnrollment {
    pub credential: CredentialId,
    pub kind: AuthorityCredentialKind,
    pub public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
}

impl AuthorityCredentialEnrollment {
    pub fn from_public_key(
        kind: AuthorityCredentialKind,
        public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    ) -> Self {
        Self {
            credential: CredentialId::of_public_key(&public_key),
            kind,
            public_key,
        }
    }

    pub fn is_valid(self) -> bool {
        self.credential != CredentialId::ZERO
            && self.public_key != [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            && CredentialId::of_public_key(&self.public_key) == self.credential
    }
}

/// One Admin-only mutation of the built-in identity authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityAdminOperation {
    /// Enroll a Principal with Member role and its first active credential.
    EnrollPrincipal {
        principal: PrincipalId,
        credential: AuthorityCredentialEnrollment,
    },
    AddCredential {
        principal: PrincipalId,
        credential: AuthorityCredentialEnrollment,
    },
    RevokeCredential {
        principal: PrincipalId,
        credential: CredentialId,
    },
    /// Enroll one exact NEN1 transport/encryption identity. The enclosing
    /// Admin signature authorizes its Principal binding while NEN1's nested
    /// transport signature independently proves possession of the full
    /// Ed25519 PeerId.
    EnrollNode {
        enrollment: NodeEncryptionEnrollment,
    },
    UnbindNodeOwner {
        node: NodeId,
        owner: PrincipalId,
    },
    SetBuiltinRole {
        principal: PrincipalId,
        role: AuthorityBuiltinRole,
    },
    /// Add or remove one exact Space-scoped AMP2 role grant.
    SetSpaceRole {
        principal: PrincipalId,
        role: RoleId,
        granted: bool,
    },
    /// Add or remove one exact deployment-scoped AMP2 actor-role grant.
    SetActorRole {
        principal: PrincipalId,
        agent: AgentId,
        actor: ActorId,
        deployment: DeploymentId,
        role: RoleId,
        granted: bool,
    },
    /// Add or remove one exact deployment-scoped AMP2 capability grant.
    SetCapability {
        principal: PrincipalId,
        agent: AgentId,
        actor: ActorId,
        deployment: DeploymentId,
        capability: CapabilityId,
        granted: bool,
    },
}

impl AuthorityAdminOperation {
    pub fn validate_shape(&self) -> bool {
        match self {
            Self::EnrollPrincipal {
                principal,
                credential,
            }
            | Self::AddCredential {
                principal,
                credential,
            } => *principal != PrincipalId::ZERO && credential.is_valid(),
            Self::RevokeCredential {
                principal,
                credential,
            } => *principal != PrincipalId::ZERO && *credential != CredentialId::ZERO,
            Self::EnrollNode { enrollment } => enrollment.validate_shape(),
            Self::UnbindNodeOwner { node, owner } => {
                *node != NodeId::ZERO && *owner != PrincipalId::ZERO
            }
            Self::SetBuiltinRole { principal, .. } => *principal != PrincipalId::ZERO,
            Self::SetSpaceRole {
                principal, role, ..
            } => *principal != PrincipalId::ZERO && *role != RoleId::ZERO,
            Self::SetActorRole {
                principal,
                agent,
                actor,
                deployment,
                role,
                ..
            } => {
                *principal != PrincipalId::ZERO
                    && *agent != AgentId::ZERO
                    && *actor != ActorId::ZERO
                    && *deployment != DeploymentId::ZERO
                    && *role != RoleId::ZERO
            }
            Self::SetCapability {
                principal,
                agent,
                actor,
                deployment,
                capability,
                ..
            } => {
                *principal != PrincipalId::ZERO
                    && *agent != AgentId::ZERO
                    && *actor != ActorId::ZERO
                    && *deployment != DeploymentId::ZERO
                    && *capability != CapabilityId::ZERO
            }
        }
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::authority_admin_operation_commitment(self)
    }
}

/// Self-authenticating Admin mutation admitted through an unsigned Public
/// preflight. The credential signature covers the complete target, exact
/// Principal/Credential/transport Node tuple, logical slot, CAS generation,
/// and operation. Runtime Public admission does not authenticate these fields;
/// the authority actor verifies them against its durable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAdminCall {
    pub invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub administrator: PrincipalId,
    pub credential: CredentialId,
    /// Monotonic sequence in this credential's identity-administration
    /// domain. It is independent from the global projection generation.
    pub request_sequence: NonZeroU64,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: NodeId,
    pub observed_slot: u64,
    pub expected_generation: NonZeroU64,
    pub operation: AuthorityAdminOperation,
    pub signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
}

impl AuthorityAdminCall {
    /// Commitment of every caller-selected field except the derived
    /// invocation and signature.
    pub fn invocation_payload_commitment(&self) -> Hash {
        crate::wire::authority_admin_call_invocation_payload_commitment(self)
    }

    pub fn derive_invocation(
        credential: CredentialId,
        request_sequence: NonZeroU64,
        payload: Hash,
    ) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/authority-admin-invocation/v4",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    credential.as_bytes(),
                    &request_sequence.get().to_le_bytes(),
                    payload.as_bytes(),
                ],
            )
            .0,
        )
    }

    pub fn expected_invocation(&self) -> InvocationId {
        Self::derive_invocation(
            self.credential,
            self.request_sequence,
            self.invocation_payload_commitment(),
        )
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_admin_call_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-admin-call/v4",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn next_generation(&self) -> Option<NonZeroU64> {
        self.expected_generation
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.invocation == InvocationId::ZERO || !self.authority.is_valid() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.administrator == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == NodeId::ZERO
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if !self.operation.validate_shape() || self.next_generation().is_none() {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if self.invocation != self.expected_invocation() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.signature == [0; CREDENTIAL_SIGNATURE_BYTES] {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        if crate::wire::authority_admin_call_encoded_len(self) > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        if !verifier.verify(
            &self.credential_public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.observed_slot == self.observed_slot
            && context.origin.principal == Some(self.administrator)
            && context.origin.credential == Some(self.credential)
            && context.origin.transport_node == Some(self.authenticated_node)
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Canonical applied Admin result. Embedding the complete signed call makes
/// the deterministic `expected + 1` generation part of that signature's
/// closure without storing an authority signing secret in actor state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAdminResult {
    pub call: AuthorityAdminCall,
    pub generation: NonZeroU64,
}

impl AuthorityAdminResult {
    pub fn from_call(call: AuthorityAdminCall) -> Result<Self, AuthorityActorProtocolError> {
        call.validate_shape()?;
        let generation = call
            .next_generation()
            .ok_or(AuthorityActorProtocolError::InvalidRequest)?;
        let result = Self { call, generation };
        result.validate_shape()?;
        Ok(result)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.call.validate_shape()?;
        if self.call.next_generation() != Some(self.generation) {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_admin_result_encoded_len(self) > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        self.call.verify_with(verifier)
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::authority_admin_result_commitment(self)
    }
}

/// Authentication proof for one ingress-originated authority request.
///
/// API credentials sign the request directly. SSH credentials are already
/// proven at the transport boundary, where the client key cannot be used to
/// sign an arbitrary actor message; an enrolled ingress Node therefore signs
/// the exact request and a stable, caller-selected request binding. The Node
/// is an ingress attester, not the credential owner's identity, and need not
/// be enrolled to the same Principal.
///
/// This shape is shared by projection queries and the AOC5 general-operation
/// protocol so both ingress paths enforce one SSH authentication format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityIngressAuthentication {
    ApiCredentialSignature {
        credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
    },
    SshNodeAttestation {
        credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        node: NodeId,
        /// Nonzero fixed-width binding derived from the ingress request's
        /// stable idempotency identity, not from an ephemeral SSH connection.
        request_binding: Hash,
        signature: [u8; CREDENTIAL_SIGNATURE_BYTES],
    },
}

impl AuthorityIngressAuthentication {
    pub const fn credential_public_key(self) -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        match self {
            Self::ApiCredentialSignature {
                credential_public_key,
                ..
            }
            | Self::SshNodeAttestation {
                credential_public_key,
                ..
            } => credential_public_key,
        }
    }

    pub const fn signature(self) -> [u8; CREDENTIAL_SIGNATURE_BYTES] {
        match self {
            Self::ApiCredentialSignature { signature, .. }
            | Self::SshNodeAttestation { signature, .. } => signature,
        }
    }

    pub const fn attesting_node(self) -> Option<NodeId> {
        match self {
            Self::ApiCredentialSignature { .. } => None,
            Self::SshNodeAttestation { node, .. } => Some(node),
        }
    }

    pub fn validate_shape(self, credential: CredentialId) -> bool {
        let public_key = self.credential_public_key();
        credential != CredentialId::ZERO
            && public_key != [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            && CredentialId::of_public_key(&public_key) == credential
            && self.signature() != [0; CREDENTIAL_SIGNATURE_BYTES]
            && match self {
                Self::ApiCredentialSignature { .. } => true,
                Self::SshNodeAttestation {
                    node,
                    request_binding,
                    ..
                } => node != NodeId::ZERO && request_binding != Hash::ZERO,
            }
    }
}

/// One authenticated, read-only query against the durable system authority
/// projection. The nonce is caller-selected and response-bound; replaying a
/// query is harmless but cannot substitute a response for another request or
/// authority installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityProjectionQuery {
    pub authority: AuthorityActorTarget,
    pub credential: CredentialId,
    pub nonce: Hash,
    pub selector: AuthorityProjectionSelector,
    pub authentication: AuthorityIngressAuthentication,
    /// Explicit opt-in for committee recovery of this exact read. Absence keeps
    /// the original wire/signature format and committed-only relay semantics.
    pub recovery: Option<AuthorityProjectionRecoveryDelegation>,
}

/// Signed permission for the exact admitted committee to finish a read while
/// its ingress attester is offline. The enclosing query signature binds the
/// target, selector, nonce and original authentication as well as these fields.
///
/// `accepted_slot` fixes the PublicPreflight identity across replicas; it is
/// not evidence of fresh admission. Before proposing unseen work the host must
/// independently check the current trusted slot and exact stable route/committee.
/// A committed invocation may finish after expiry without changing its pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityProjectionRecoveryDelegation {
    /// AgentGenerationRouteKey::replication_id(): space, Agent, genesis, admission.
    pub generation: Hash,
    /// Complete admitted replica committee commitment (not just voter count).
    pub committee: Hash,
    pub accepted_slot: u64,
    /// Exclusive upper bound for admission of a previously unseen invocation.
    pub expires_at: u64,
}

impl AuthorityProjectionRecoveryDelegation {
    pub fn is_valid(self) -> bool {
        self.generation != Hash::ZERO
            && self.committee != Hash::ZERO
            && self
                .expires_at
                .checked_sub(self.accepted_slot)
                .is_some_and(|lifetime| {
                    lifetime != 0 && lifetime <= MAX_AUTHORITY_PROJECTION_RECOVERY_SLOTS
                })
    }

    pub fn admits_at(self, trusted_slot: u64) -> bool {
        self.is_valid() && self.accepted_slot <= trusted_slot && trusted_slot < self.expires_at
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityProjectionSelector {
    /// Resolve only the credential signing this query, including revocation.
    Credential,
    /// Page the authority's Agent inventory by exclusive full-ID cursor.
    Agents { after: Option<AgentId>, limit: u16 },
    /// Page one exact Agent's replica roster by exclusive full Node ID.
    AgentReplicas {
        agent: AgentId,
        after: Option<NodeId>,
        limit: u16,
    },
    /// Page one exact Agent's Actors by exclusive full-ID cursor.
    Actors {
        agent: AgentId,
        after: Option<ActorId>,
        limit: u16,
    },
    /// One ordered stream of Agent, replica and actor facts. A known head
    /// may suppress rows only on the first page, after fresh authentication.
    Inventory {
        after: Option<AuthorityInventoryCursor>,
        limit: u16,
        known_head: Option<AuthorityProjectionHead>,
    },
}

impl AuthorityProjectionSelector {
    pub fn validate_shape(self) -> bool {
        match self {
            Self::Inventory {
                after,
                limit,
                known_head,
            } => {
                after.is_none_or(|cursor| cursor.is_valid())
                    && limit != 0
                    && usize::from(limit) <= MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES
                    && known_head.is_none_or(|head| after.is_none() && head.is_valid())
            }
            Self::Credential => true,
            Self::Agents { after, limit } => {
                after != Some(AgentId::ZERO)
                    && limit != 0
                    && usize::from(limit) <= MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            }
            Self::AgentReplicas {
                agent,
                after,
                limit,
            } => {
                agent != AgentId::ZERO
                    && after != Some(NodeId::ZERO)
                    && limit != 0
                    && usize::from(limit) <= MAX_AUTHORITY_REPLICA_PAGE_ENTRIES
            }
            Self::Actors {
                agent,
                after,
                limit,
            } => {
                agent != AgentId::ZERO
                    && after != Some(ActorId::ZERO)
                    && limit != 0
                    && usize::from(limit) <= MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            }
        }
    }
}

impl AuthorityProjectionQuery {
    pub fn expected_invocation(&self) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/system-authority/projection-invocation/v2",
                &[self.commitment().as_bytes()],
            )
            .0,
        )
    }

    /// Deterministic guest-side binding only. Live generation, committee and
    /// expiry checks require the host's trusted proposal boundary, not replay
    /// time. Legacy queries keep their existing context-independent behavior.
    pub fn matches_recovery_context(&self, context: &InvocationContext) -> bool {
        let Some(recovery) = self.recovery else {
            return false;
        };
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.expected_invocation()
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Query
            && context.observed_slot == recovery.accepted_slot
            && context.origin.principal.is_none()
            && context.origin.credential.is_none()
            && context.origin.transport_node == self.attesting_node()
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_projection_query_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            if self.recovery.is_some() {
                b"vos/agent/authority-projection-query/v2"
            } else {
                b"vos/agent/authority-projection-query/v1"
            },
            &[&self.signing_bytes(), &self.authentication.signature()],
        )
    }

    pub const fn credential_public_key(&self) -> [u8; CREDENTIAL_PUBLIC_KEY_BYTES] {
        self.authentication.credential_public_key()
    }

    pub const fn attesting_node(&self) -> Option<NodeId> {
        self.authentication.attesting_node()
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if !self.authority.is_valid() {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if !self.authentication.validate_shape(self.credential) {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if self.nonce == Hash::ZERO
            || !self.selector.validate_shape()
            || self
                .recovery
                .is_some_and(|delegation| !delegation.is_valid())
        {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if crate::wire::authority_projection_query_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_api_with<V: AuthorityCredentialVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        let AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key,
            signature,
        } = self.authentication
        else {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        };
        if !verifier.verify(&credential_public_key, &self.signing_bytes(), &signature) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    pub fn verify_ssh_node_attestation_with<V: AuthorityCredentialVerifier>(
        &self,
        node_public_key: &[u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
            self.authentication
        else {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        };
        if !verifier.verify(node_public_key, &self.signing_bytes(), &signature) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }
}

/// Exact durable authority head shared by every projection response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityProjectionHead {
    /// Monotonic revision of the complete authority state image. Unlike the
    /// operation-specific counters below, this advances for every mutation.
    pub state_revision: NonZeroU64,
    pub epoch: NonZeroU64,
    pub authorization_sequence: NonZeroU64,
    pub administration_generation: NonZeroU64,
    /// Commitment of the complete validated actor state represented here.
    pub state_commitment: Hash,
}

impl AuthorityProjectionHead {
    pub fn is_valid(self) -> bool {
        self.state_commitment != Hash::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityCredentialStatus {
    Active = 0,
    Revoked = 1,
}

/// One deployment-scoped actor-role assignment for the projected Principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityActorRoleGrant {
    pub agent: AgentId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub role: RoleId,
}

impl AuthorityActorRoleGrant {
    pub fn is_valid(self) -> bool {
        self.agent != AgentId::ZERO
            && self.actor != ActorId::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.role != RoleId::ZERO
    }
}

/// One deployment-scoped capability assignment for the projected Principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityCapabilityGrant {
    pub agent: AgentId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub capability: CapabilityId,
}

impl AuthorityCapabilityGrant {
    pub fn is_valid(self) -> bool {
        self.agent != AgentId::ZERO
            && self.actor != ActorId::ZERO
            && self.deployment != DeploymentId::ZERO
            && self.capability != CapabilityId::ZERO
    }
}

/// Credential-to-Principal resolution and every typed application claim
/// currently granted to that Principal. Revoked credentials remain
/// self-queryable so ingress can distinguish revocation from malformed or
/// unknown credentials, but cannot use the inventory queries below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCredentialProjection {
    pub query: AuthorityProjectionQuery,
    pub head: AuthorityProjectionHead,
    pub principal: PrincipalId,
    pub status: AuthorityCredentialStatus,
    pub kind: AuthorityCredentialKind,
    pub builtin_role: AuthorityBuiltinRole,
    /// Highest durable request sequence consumed in each credential-local
    /// protocol domain. The next call must use the exact successor.
    pub management_request_high_water: u64,
    pub operation_request_high_water: u64,
    pub admin_request_high_water: u64,
    pub space_roles: Vec<RoleId>,
    pub actor_roles: Vec<AuthorityActorRoleGrant>,
    pub capabilities: Vec<AuthorityCapabilityGrant>,
}

impl AuthorityCredentialProjection {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.query.validate_shape()?;
        if !matches!(
            self.query.selector,
            AuthorityProjectionSelector::Credential | AuthorityProjectionSelector::Inventory { .. }
        ) || !self.head.is_valid()
            || self.principal == PrincipalId::ZERO
            || self.space_roles.len() + self.actor_roles.len() + self.capabilities.len()
                > MAX_AUTHORITY_PRINCIPAL_GRANTS
            || self.space_roles.contains(&RoleId::ZERO)
            || self.space_roles.windows(2).any(|pair| pair[0] >= pair[1])
            || self.actor_roles.iter().any(|grant| !grant.is_valid())
            || self.actor_roles.windows(2).any(|pair| pair[0] >= pair[1])
            || self.capabilities.iter().any(|grant| !grant.is_valid())
            || self.capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_credential_projection_encoded_len(self)
            > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// Exclusive cursor ordered by Agent first, then descriptor, replicas, actors.
/// Replica/actor identifiers are not interchangeable, even when bytes coincide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityInventoryCursor {
    pub agent: AgentId,
    pub position: AuthorityInventoryPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityInventoryPosition {
    Agent,
    Replica(NodeId),
    Actor(ActorId),
}

impl AuthorityInventoryCursor {
    pub fn is_valid(self) -> bool {
        self.agent != AgentId::ZERO
            && match self.position {
                AuthorityInventoryPosition::Agent => true,
                AuthorityInventoryPosition::Replica(node) => node != NodeId::ZERO,
                AuthorityInventoryPosition::Actor(actor) => actor != ActorId::ZERO,
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityInventoryEntry {
    Agent(AuthorityAgentProjection),
    Replica {
        agent: AgentId,
        replica: AgentReplica,
    },
    Actor(AuthorityActorProjection),
}

impl AuthorityInventoryEntry {
    pub fn cursor(&self) -> AuthorityInventoryCursor {
        let (agent, position) = match self {
            Self::Agent(row) => (row.identity.agent, AuthorityInventoryPosition::Agent),
            Self::Replica { agent, replica } => {
                (*agent, AuthorityInventoryPosition::Replica(replica.node))
            }
            Self::Actor(row) => (
                row.agent,
                AuthorityInventoryPosition::Actor(row.entry.actor),
            ),
        };
        AuthorityInventoryCursor { agent, position }
    }

    fn valid_for(&self, target: AuthorityActorTarget) -> bool {
        match self {
            Self::Agent(row) => {
                row.validate_shape().is_ok()
                    && row.identity.space == target.space
                    && row.authority == target.binding
                    && (row.identity.agent != target.system_agent
                        || row.identity.runtime_deployment == target.system_runtime_deployment)
            }
            Self::Replica { agent, replica } => {
                *agent != AgentId::ZERO
                    && replica.node != NodeId::ZERO
                    && replica.principal != PrincipalId::ZERO
            }
            Self::Actor(row) => row.validate_shape().is_ok(),
        }
    }
}

/// A bounded slice of one authenticated inventory revision. Credential facts
/// carry the exact signed Inventory query (not a synthetic Credential query).
/// Revoked credentials receive only their own claims; never inventory rows.
/// Consumers must reconstruct complete descriptors and verify replica counts,
/// generations, per-Agent actor limits and the same head/claims across pages.
/// `unchanged` attests only to the requested state head: cache reuse also
/// requires matching Authority, credential identity and complete fresh claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityInventoryProjectionPage {
    pub credential: AuthorityCredentialProjection,
    pub unchanged: bool,
    pub entries: Vec<AuthorityInventoryEntry>,
    pub next: Option<AuthorityInventoryCursor>,
}

impl AuthorityInventoryProjectionPage {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.credential.validate_shape()?;
        let AuthorityProjectionSelector::Inventory {
            after,
            limit,
            known_head,
        } = self.credential.query.selector
        else {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        };
        if self.entries.len() > usize::from(limit)
            || self
                .entries
                .iter()
                .filter(|entry| !matches!(entry, AuthorityInventoryEntry::Replica { .. }))
                .count()
                > MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            || self
                .entries
                .iter()
                .any(|entry| !entry.valid_for(self.credential.query.authority))
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].cursor() >= pair[1].cursor())
            || self
                .entries
                .first()
                .is_some_and(|entry| after.is_some_and(|after| entry.cursor() <= after))
            || self.next.is_some()
                && self.entries.last().map(AuthorityInventoryEntry::cursor) != self.next
            || self.unchanged
                && (after.is_some()
                    || known_head != Some(self.credential.head)
                    || !self.entries.is_empty()
                    || self.next.is_some()
                    || self.credential.status != AuthorityCredentialStatus::Active)
            || self.credential.status == AuthorityCredentialStatus::Revoked
                && (!self.entries.is_empty() || self.next.is_some())
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_inventory_projection_page_encoded_len(self)
            > MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// Complete authenticated Agent descriptor facts retained by the authority.
/// Runtime package bytes, physical readiness, and incarnation are deliberately
/// absent: the package reference and contract are authoritative, while a
/// supervisor must reconcile those host-owned availability facts separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAgentProjection {
    pub identity: AgentIdentity,
    pub creation_nonce: Hash,
    pub authority: AgentAuthorityBinding,
    pub private_recovery: Option<PrivateRecoveryBinding>,
    pub runtime_package: BlobRef,
    pub runtime_contract: RuntimePackageContract,
    pub capabilities: RuntimeCapabilities,
    /// Exact size of the separately paged replica roster.
    pub replica_count: u16,
    pub replica_generation: Hash,
}

impl AuthorityAgentProjection {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.identity.space == SpaceId::ZERO
            || self.identity.agent == AgentId::ZERO
            || self.identity.owner == PrincipalId::ZERO
            || self.identity.runtime_deployment == DeploymentId::ZERO
            || self.identity.runtime_program == ProgramId::ZERO
            || self.identity.runtime_producer == ProducerId::ZERO
            || self.identity.transition_producer == ProducerId::ZERO
            || self.identity.transition_producer == self.identity.runtime_producer
            || self.creation_nonce == Hash::ZERO
            || AgentId::derive(
                self.identity.space,
                self.identity.owner,
                self.creation_nonce.as_bytes(),
            ) != self.identity.agent
            || !self.authority.is_valid()
            || self.runtime_package.hash == Hash::ZERO
            || self.runtime_package.len == 0
            || self.runtime_package.len > crate::MAX_CATALOG_ARTIFACT_BYTES
            || !self.runtime_contract.is_valid()
            || self.capabilities.validate().is_err()
            || self.replica_count == 0
            || usize::from(self.replica_count) > crate::MAX_AGENT_REPLICAS
            || self.replica_generation == Hash::ZERO
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        match (self.identity.profile, self.private_recovery) {
            (crate::AgentProfile::Private, Some(binding)) if binding.is_valid() => {}
            (crate::AgentProfile::Private, _) | (_, Some(_)) => {
                return Err(AuthorityActorProtocolError::InvalidApplication);
            }
            _ => {}
        }
        match self.identity.profile {
            crate::AgentProfile::Local if self.replica_count != 1 => {
                return Err(AuthorityActorProtocolError::InvalidApplication);
            }
            _ => {}
        }
        Ok(())
    }

    /// Reconstruct and validate the complete authenticated descriptor after
    /// draining replica pages with the same head, count, and generation.
    pub fn reconstruct_descriptor(
        &self,
        replicas: Vec<AgentReplica>,
    ) -> Result<AgentDescriptor, AuthorityActorProtocolError> {
        self.validate_shape()?;
        if replicas.len() != usize::from(self.replica_count)
            || crate::replica_set_generation(&self.identity, self.creation_nonce, &replicas)
                != self.replica_generation
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        let descriptor = AgentDescriptor {
            identity: self.identity.clone(),
            creation_nonce: self.creation_nonce,
            authority: self.authority,
            private_recovery: self.private_recovery,
            runtime_package: self.runtime_package.clone(),
            runtime_contract: self.runtime_contract,
            capabilities: self.capabilities,
            replicas,
        };
        descriptor
            .validate()
            .map(|()| descriptor)
            .map_err(|_| AuthorityActorProtocolError::InvalidApplication)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAgentProjectionPage {
    pub query: AuthorityProjectionQuery,
    pub head: AuthorityProjectionHead,
    pub entries: Vec<AuthorityAgentProjection>,
    pub next: Option<AgentId>,
}

impl AuthorityAgentProjectionPage {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.query.validate_shape()?;
        let AuthorityProjectionSelector::Agents { after, limit } = self.query.selector else {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        };
        if !self.head.is_valid()
            || self.entries.len() > usize::from(limit)
            || self.entries.len() > MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            || self.entries.iter().any(|entry| {
                entry.validate_shape().is_err()
                    || entry.identity.space != self.query.authority.space
                    || entry.authority != self.query.authority.binding
                    || entry.identity.agent == self.query.authority.system_agent
                        && entry.identity.runtime_deployment
                            != self.query.authority.system_runtime_deployment
            })
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].identity.agent >= pair[1].identity.agent)
            || self
                .entries
                .first()
                .is_some_and(|entry| after.is_some_and(|after| entry.identity.agent <= after))
            || self.next.is_some()
                && self.entries.last().map(|entry| entry.identity.agent) != self.next
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_agent_projection_page_encoded_len(self)
            > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// One bounded slice of an Agent's exact authenticated replica roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityAgentReplicaProjectionPage {
    pub query: AuthorityProjectionQuery,
    pub head: AuthorityProjectionHead,
    pub replica_count: u16,
    pub replica_generation: Hash,
    pub entries: Vec<AgentReplica>,
    pub next: Option<NodeId>,
}

impl AuthorityAgentReplicaProjectionPage {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.query.validate_shape()?;
        let AuthorityProjectionSelector::AgentReplicas { after, limit, .. } = self.query.selector
        else {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        };
        if !self.head.is_valid()
            || self.replica_count == 0
            || usize::from(self.replica_count) > crate::MAX_AGENT_REPLICAS
            || self.replica_generation == Hash::ZERO
            || self.entries.len() > usize::from(limit)
            || self.entries.len() > usize::from(self.replica_count)
            || self.entries.len() > MAX_AUTHORITY_REPLICA_PAGE_ENTRIES
            || self
                .entries
                .iter()
                .any(|entry| entry.node == NodeId::ZERO || entry.principal == PrincipalId::ZERO)
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].node >= pair[1].node)
            || self
                .entries
                .first()
                .is_some_and(|entry| after.is_some_and(|after| entry.node <= after))
            || self.next.is_some() && self.entries.last().map(|entry| entry.node) != self.next
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_agent_replica_projection_page_encoded_len(self)
            > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Check the immutable reconstruction facts shared with the Agent row.
    pub fn matches_agent_at_head(
        &self,
        agent: &AuthorityAgentProjection,
        head: AuthorityProjectionHead,
    ) -> bool {
        self.head == head
            && matches!(
                self.query.selector,
                AuthorityProjectionSelector::AgentReplicas { agent: id, .. }
                    if id == agent.identity.agent
            )
            && self.replica_count == agent.replica_count
            && self.replica_generation == agent.replica_generation
    }
}

/// Durable actor directory/status/artifact record. The runtime-selected
/// incarnation and readiness are host-owned and intentionally not invented by
/// the policy actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityActorProjection {
    pub agent: AgentId,
    pub entry: ActorEntry,
    pub producer: ProducerId,
    pub contract: ActorPackageContract,
    pub requirements: RuntimeRequirements,
    pub root_provenance: bool,
    pub installation_id: InstallationId,
    pub registry_reservation: Hash,
    pub install_request: Hash,
}

impl AuthorityActorProjection {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.agent == AgentId::ZERO
            || self.entry.validate().is_err()
            || self.producer == ProducerId::ZERO
            || !self.contract.is_valid()
            || self.requirements.lanes != self.entry.lanes
            || self.installation_id == InstallationId::ZERO
            || self.registry_reservation == Hash::ZERO
            || self.install_request == Hash::ZERO
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityActorProjectionPage {
    pub query: AuthorityProjectionQuery,
    pub head: AuthorityProjectionHead,
    pub entries: Vec<AuthorityActorProjection>,
    pub next: Option<ActorId>,
}

impl AuthorityActorProjectionPage {
    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        self.query.validate_shape()?;
        let AuthorityProjectionSelector::Actors {
            agent,
            after,
            limit,
        } = self.query.selector
        else {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        };
        if !self.head.is_valid()
            || self.entries.len() > usize::from(limit)
            || self.entries.len() > MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
            || self
                .entries
                .iter()
                .any(|entry| entry.agent != agent || entry.validate_shape().is_err())
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
            || self
                .entries
                .first()
                .is_some_and(|entry| after.is_some_and(|after| entry.entry.actor <= after))
            || self.next.is_some()
                && self.entries.last().map(|entry| entry.entry.actor) != self.next
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::authority_actor_projection_page_encoded_len(self)
            > crate::MAX_INVOCATION_REPLY_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }
}

/// Ed25519 verification is injected by the host or guest actor. The portable
/// SDK intentionally provides no key store, host call, or crypto provider.
pub trait AuthorityCredentialVerifier {
    fn verify(
        &self,
        public_key: &[u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        message: &[u8],
        signature: &[u8; CREDENTIAL_SIGNATURE_BYTES],
    ) -> bool;
}

/// Deterministic policy output consumed by the durable management issuer.
///
/// `authorization_sequence` belongs to the authority actor and is stable
/// across exact retries. It is not the management receipt's decision
/// sequence; the durable issuer allocates and acknowledges that separate
/// replay clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementApproval {
    pub credential_call: Hash,
    pub authorization_sequence: NonZeroU64,
    /// Distinct invocation ID reserved by the authority actor for the
    /// post-durability acknowledgement before this approval is published.
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub principal: PrincipalId,
    pub credential: CredentialId,
    pub credential_public_key: [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    pub authenticated_node: Option<NodeId>,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    pub epoch: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub plan: ManagementAuthorizationPlan,
    pub plan_commitment: Hash,
}

impl ManagementApproval {
    /// Derive the acknowledgement invocation reserved alongside one exact
    /// signed credential call. The authority actor must collision-check this
    /// value against every retained authorization and acknowledgement ID
    /// before admitting the call.
    pub fn derive_acknowledgement_invocation(call: &AuthorityCredentialCall) -> InvocationId {
        InvocationId(
            Hash::digest(
                b"vos/agent/management-acknowledgement-invocation/v1",
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    call.invocation.as_bytes(),
                    call.commitment().as_bytes(),
                ],
            )
            .0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_call(
        call: &AuthorityCredentialCall,
        authorization_sequence: NonZeroU64,
        evidence: AuthorityEvidence,
        lane_roots: AuthorityLaneRoots,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> Result<Self, AuthorityActorProtocolError> {
        call.validate_shape()?;
        let value = Self {
            credential_call: call.commitment(),
            authorization_sequence,
            acknowledgement_invocation: Self::derive_acknowledgement_invocation(call),
            authority: call.authority,
            managed: call.managed,
            principal: call.principal,
            credential: call.credential,
            credential_public_key: call.credential_public_key,
            authenticated_node: call.authenticated_node,
            evidence,
            lane_roots,
            epoch,
            valid_from,
            expires_at,
            plan: call.plan.clone(),
            plan_commitment: call.plan.commitment(),
        };
        value.validate_shape()?;
        if !value.matches_call(call) {
            return Err(AuthorityActorProtocolError::MismatchedCall);
        }
        Ok(value)
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.credential_call == Hash::ZERO
            || self.acknowledgement_invocation == InvocationId::ZERO
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.principal == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.credential_public_key == [0; CREDENTIAL_PUBLIC_KEY_BYTES]
            || CredentialId::of_public_key(&self.credential_public_key) != self.credential
            || self.authenticated_node == Some(NodeId::ZERO)
        {
            return Err(AuthorityActorProtocolError::InvalidCaller);
        }
        if self.epoch == 0 || self.valid_from > self.expires_at {
            return Err(AuthorityActorProtocolError::InvalidValidity);
        }
        if !self.evidence.is_valid()
            || !self.lane_roots.is_valid()
            || !mutating_plan_matches_targets(&self.authority, &self.managed, &self.plan)
            || self.plan_commitment == Hash::ZERO
            || self.plan_commitment != self.plan.commitment()
        {
            return Err(AuthorityActorProtocolError::InvalidRequest);
        }
        if crate::wire::management_approval_encoded_len(self) > crate::MAX_INVOCATION_REPLY_BYTES {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Check the retained call preimage and ensure policy only narrows the
    /// caller-requested validity interval.
    pub fn matches_call(&self, call: &AuthorityCredentialCall) -> bool {
        self.validate_shape().is_ok()
            && call.validate_shape().is_ok()
            && self.credential_call == call.commitment()
            && self.acknowledgement_invocation == Self::derive_acknowledgement_invocation(call)
            && self.acknowledgement_invocation != call.invocation
            && self.authority == call.authority
            && self.managed == call.managed
            && self.principal == call.principal
            && self.credential == call.credential
            && self.credential_public_key == call.credential_public_key
            && self.authenticated_node == call.authenticated_node
            && self.valid_from >= call.requested_valid_from
            && self.expires_at <= call.requested_expires_at
            && self.plan == call.plan
            && self.plan_commitment == call.plan.commitment()
    }

    pub fn commitment(&self) -> Hash {
        crate::wire::management_approval_commitment(self)
    }
}

/// Authority-signed acknowledgement produced only after the managed Agent's
/// exact result has been durably reopened.
///
/// Authorization and acknowledgement are distinct actor invocations. Reusing
/// the authorization invocation identifier for a different acknowledgement
/// message would violate the runtime's exact-retry contract, so both IDs are
/// explicit and must differ. The actor retains the ACC3 and MAP2 preimages;
/// this bounded message carries their commitments rather than embedding them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementApplicationAck {
    pub authorization_invocation: InvocationId,
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub credential_call: Hash,
    pub approval: Hash,
    pub authorization_sequence: NonZeroU64,
    pub request: Hash,
    pub receipt: AuthorityReceipt,
    /// Exact typed reply durably reopened for this authorized request.
    pub application: ManagementReply,
    pub reopened_state: Hash,
    pub applied_at: u64,
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl ManagementApplicationAck {
    /// Bytes covered by the post-application authority signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::management_application_ack_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/management-application-ack/v2",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.authorization_invocation == InvocationId::ZERO
            || self.acknowledgement_invocation == InvocationId::ZERO
            || self.authorization_invocation == self.acknowledgement_invocation
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if self.credential_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.request == Hash::ZERO
            || !crate::wire::management_reply_valid(&self.application)
            || self.reopened_state == Hash::ZERO
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        let selector = &self.receipt.selector;
        if self.receipt.validate_shape().is_err()
            || !self.authority.binding.accepts(&self.receipt)
            || selector.space != self.managed.space
            || selector.agent != self.managed.agent
            || selector.runtime_deployment != self.managed.runtime_deployment
            || !selector.operation.uses_management_decision_journal()
            || selector.request != self.request
            || !selector.is_live_at(self.applied_at)
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::management_application_ack_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    /// Verify both the original receipt and the distinct post-application
    /// signature using the independently selected binding key.
    pub fn verify_with<V: AuthorityVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        self.receipt
            .verify_at(self.applied_at, verifier)
            .map_err(|_| AuthorityActorProtocolError::InvalidSignature)?;
        if !verifier.verify(
            &self.authority.binding.public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    /// Match the exact actor-retained credential call and approval preimages.
    pub fn matches_pending(
        &self,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> bool {
        self.validate_shape().is_ok()
            && approval.matches_call(call)
            && self.authorization_invocation == call.invocation
            && self.acknowledgement_invocation == approval.acknowledgement_invocation
            && self.authority == call.authority
            && self.authority == approval.authority
            && self.managed == call.managed
            && self.managed == approval.managed
            && self.credential_call == call.commitment()
            && self.credential_call == approval.credential_call
            && self.approval == approval.commitment()
            && self.authorization_sequence == approval.authorization_sequence
            && self.request == approval.plan_commitment
            && management_application_reply_shape_matches(call, &self.application)
            && receipt_matches_approval(&self.receipt, approval)
    }

    /// Bind the acknowledgement to its own Linear actor invocation. The
    /// signature, rather than caller identity, authenticates the issuer, so a
    /// client may safely relay the exact acknowledgement bytes.
    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.acknowledgement_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Distinct signed finality for a physically rejected Local or Shared Install.
///
/// The ordinary MAA2 success wire remains byte-identical. MAF1 can only
/// resolve an already-approved Install after the exact guest rejection (or
/// ordered expiry/non-execution fence) and resulting state have been durably
/// reopened. Its signature does not grant
/// permission to skip physical replay or to cancel an ambiguous publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagementApplicationFailure {
    pub authorization_invocation: InvocationId,
    pub acknowledgement_invocation: InvocationId,
    pub authority: AuthorityActorTarget,
    pub managed: ManagedAgentTarget,
    pub credential_call: Hash,
    pub approval: Hash,
    pub authorization_sequence: NonZeroU64,
    pub request: Hash,
    pub receipt: AuthorityReceipt,
    pub error: ManagementError,
    pub reopened_state: Hash,
    pub failed_at: u64,
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl ManagementApplicationFailure {
    /// Time rule for a replay-proved Install failure, not permission to execute.
    /// Receipt shape, route and signatures must be authenticated separately.
    pub fn valid_failure_slot(
        receipt: &AuthorityReceipt,
        error: ManagementError,
        slot: u64,
    ) -> bool {
        if error == ManagementError::ExpiredBeforeApplication {
            slot > receipt.selector.expires_at
        } else {
            receipt.selector.is_live_at(slot)
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::management_application_failure_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/management-application-failure/v1",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityActorProtocolError> {
        if self.authorization_invocation == InvocationId::ZERO
            || self.acknowledgement_invocation == InvocationId::ZERO
            || self.authorization_invocation == self.acknowledgement_invocation
            || !self.authority.is_valid()
            || !self.managed.is_valid()
            || self.authority.space != self.managed.space
        {
            return Err(AuthorityActorProtocolError::InvalidTarget);
        }
        if !matches!(
            self.managed.profile,
            AgentProfile::Local | AgentProfile::Shared
        ) || self.credential_call == Hash::ZERO
            || self.approval == Hash::ZERO
            || self.request == Hash::ZERO
            || self.reopened_state == Hash::ZERO
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        let selector = &self.receipt.selector;
        if self.receipt.validate_shape().is_err()
            || !self.authority.binding.accepts(&self.receipt)
            || selector.space != self.managed.space
            || selector.agent != self.managed.agent
            || selector.runtime_deployment != self.managed.runtime_deployment
            || selector.operation != AuthorityOperationKind::InstallActor
            || selector.request != self.request
            || !Self::valid_failure_slot(&self.receipt, self.error, self.failed_at)
        {
            return Err(AuthorityActorProtocolError::InvalidApplication);
        }
        if crate::wire::management_application_failure_encoded_len(self)
            > crate::MAX_INVOCATION_MESSAGE_BYTES
        {
            return Err(AuthorityActorProtocolError::LimitExceeded);
        }
        Ok(())
    }

    pub fn verify_with<V: AuthorityVerifier>(
        &self,
        verifier: &V,
    ) -> Result<(), AuthorityActorProtocolError> {
        self.validate_shape()?;
        // Expiry proves non-execution after the window, not renewed authority.
        // Authenticate the unchanged receipt at its final valid slot.
        let receipt_slot = if self.error == ManagementError::ExpiredBeforeApplication {
            self.receipt.selector.expires_at
        } else {
            self.failed_at
        };
        self.receipt
            .verify_at(receipt_slot, verifier)
            .map_err(|_| AuthorityActorProtocolError::InvalidSignature)?;
        if !verifier.verify(
            &self.authority.binding.public_key,
            &self.signing_bytes(),
            &self.signature,
        ) {
            return Err(AuthorityActorProtocolError::InvalidSignature);
        }
        Ok(())
    }

    pub fn matches_pending(
        &self,
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> bool {
        self.validate_shape().is_ok()
            && matches!(&call.plan, ManagementAuthorizationPlan::Install(_))
            && approval.matches_call(call)
            && self.authorization_invocation == call.invocation
            && self.acknowledgement_invocation == approval.acknowledgement_invocation
            && self.authority == call.authority
            && self.managed == call.managed
            && self.credential_call == call.commitment()
            && self.credential_call == approval.credential_call
            && self.approval == approval.commitment()
            && self.authorization_sequence == approval.authorization_sequence
            && self.request == approval.plan_commitment
            && receipt_matches_approval(&self.receipt, approval)
    }

    pub fn matches_invocation_context(&self, context: &InvocationContext) -> bool {
        self.validate_shape().is_ok()
            && context.validate()
            && context.invocation == self.acknowledgement_invocation
            && context.actor == self.authority.binding.issuer.actor
            && context.mode == MethodMode::Linear
            && context.origin.actor.is_none()
            && context.origin.capability.is_none()
            && context.roles == InvocationRoleClaims::none()
    }
}

/// Match application facts using only fields present in ACC3. Every variant is
/// exact against the call except `ReplicasChanged`: its generation also binds
/// the Agent creation nonce. The authority actor compares that value with the
/// generation of its exact enrollment-reconstructed target before accepting
/// MAA2; this SDK boundary only rejects zero or a reply of the wrong variant.
fn management_application_reply_shape_matches(
    call: &AuthorityCredentialCall,
    application: &ManagementReply,
) -> bool {
    match (&call.plan, application) {
        (
            ManagementAuthorizationPlan::Create { descriptor, .. },
            ManagementReply::Created(identity),
        ) => *identity == descriptor.identity,
        (ManagementAuthorizationPlan::Install(install), ManagementReply::Installed(entry)) => {
            *entry == install.entry
        }
        (ManagementAuthorizationPlan::UpgradeActor(upgrade), ManagementReply::Upgraded(entry)) => {
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
            ManagementAuthorizationPlan::Suspend {
                actor,
                expected_deployment,
            },
            ManagementReply::Suspended(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && entry.suspended,
        (
            ManagementAuthorizationPlan::Resume {
                actor,
                expected_deployment,
            },
            ManagementReply::Resumed(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && !entry.suspended,
        (
            ManagementAuthorizationPlan::RemoveLeaf { actor, .. },
            ManagementReply::Removed(removed),
        ) => actor == removed,
        (
            ManagementAuthorizationPlan::UpgradeRuntime(upgrade),
            ManagementReply::RuntimeUpgraded(identity),
        ) => {
            identity.space == call.managed.space
                && identity.agent == call.managed.agent
                && identity.owner == call.managed.owner
                && identity.profile == call.managed.profile
                && identity.runtime_deployment == upgrade.to_deployment
                && identity.runtime_program == upgrade.to_program
                && identity.runtime_producer == upgrade.producer
                && identity.transition_producer == call.managed.transition_producer
        }
        (
            ManagementAuthorizationPlan::ChangeReplicas { .. },
            ManagementReply::ReplicasChanged { generation },
        ) => *generation != Hash::ZERO,
        (_, ManagementReply::Actors(_))
        | (_, ManagementReply::Resources(_))
        | (_, ManagementReply::Created(_))
        | (_, ManagementReply::Installed(_))
        | (_, ManagementReply::Upgraded(_))
        | (_, ManagementReply::Suspended(_))
        | (_, ManagementReply::Resumed(_))
        | (_, ManagementReply::Removed(_))
        | (_, ManagementReply::RuntimeUpgraded(_))
        | (_, ManagementReply::ReplicasChanged { .. })
        | (_, ManagementReply::ResourcePolicySet(_))
        | (_, ManagementReply::ExecutionLimitsSet(_))
        | (_, ManagementReply::ManagementHistory(_)) => false,
    }
}

/// Compare receipt selectors with the exact retained management approval.
///
/// This is a binding comparison, not signature, validity-window, or policy
/// verification. Callers must validate both values and independently verify
/// the receipt and approval's retained credential call before admission.
/// The issuer's decision sequence is deliberately not compared with the
/// actor's authorization sequence: they are independently allocated clocks.
pub fn receipt_matches_approval(receipt: &AuthorityReceipt, approval: &ManagementApproval) -> bool {
    let selector = &receipt.selector;
    let actor = approval.plan.authority_actor();
    selector.policy == approval.authority.binding.policy
        && selector.issuer == approval.authority.binding.issuer
        && selector.space == approval.managed.space
        && selector.agent == approval.managed.agent
        && selector.operation == approval.plan.authority_operation()
        && selector.runtime_deployment == approval.managed.runtime_deployment
        && selector.actor == actor.map(|(actor, _)| actor)
        && selector.actor_deployment == actor.map(|(_, deployment)| deployment)
        && selector.evidence == approval.evidence
        && selector.lane_roots == approval.lane_roots
        && selector.epoch == approval.epoch
        && selector.valid_from == approval.valid_from
        && selector.expires_at == approval.expires_at
        && selector.request == approval.plan_commitment
}

fn mutating_plan_matches_targets(
    authority: &AuthorityActorTarget,
    managed: &ManagedAgentTarget,
    plan: &ManagementAuthorizationPlan,
) -> bool {
    if !plan.is_valid() {
        return false;
    }
    match plan {
        ManagementAuthorizationPlan::Create { descriptor, .. } => {
            descriptor.identity.space == managed.space
                && descriptor.identity.agent == managed.agent
                && descriptor.identity.owner == managed.owner
                && descriptor.identity.profile == managed.profile
                && descriptor.identity.runtime_deployment == managed.runtime_deployment
                && descriptor.identity.transition_producer == managed.transition_producer
                && descriptor.authority == authority.binding
        }
        ManagementAuthorizationPlan::UpgradeRuntime(upgrade) => {
            upgrade.from_deployment == managed.runtime_deployment
                && upgrade.producer != managed.transition_producer
        }
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityActorProtocolError {
    InvalidTarget,
    InvalidCaller,
    InvalidValidity,
    InvalidRequest,
    InvalidSignature,
    InvalidApplication,
    LimitExceeded,
    MismatchedCall,
}

impl core::fmt::Display for AuthorityActorProtocolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid authority actor protocol value: {self:?}"
        )
    }
}

impl core::error::Error for AuthorityActorProtocolError {}

/// Immutable trust anchor selected when an Agent is created.
///
/// A receipt is self-describing so a runtime can verify its signature, but
/// those self-described fields are not themselves a trust decision. Every
/// Agent therefore persists this independently supplied binding and requires
/// exact policy, issuer, and key equality before consuming a receipt. The
/// epoch is a floor for later authority rotations and prevents a newly
/// created Agent from accepting evidence from an already-retired epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentAuthorityBinding {
    pub policy: Hash,
    pub issuer: AuthorityIssuer,
    pub public_key: [u8; AUTHORITY_PUBLIC_KEY_BYTES],
    pub initial_epoch: u64,
}

impl AgentAuthorityBinding {
    pub fn is_valid(self) -> bool {
        self.policy != Hash::ZERO
            && self.issuer.is_valid()
            && self.public_key != [0; AUTHORITY_PUBLIC_KEY_BYTES]
            && ProducerId::of_public_key(&self.public_key) == self.issuer.producer
            && self.initial_epoch != 0
    }

    /// Whether this immutable anchor selects the signer and policy carried by
    /// `receipt`. Request, target, operation, liveness, and signature checks
    /// remain separate so callers cannot accidentally treat a trust match as
    /// complete authorization.
    pub fn accepts(self, receipt: &AuthorityReceipt) -> bool {
        self.is_valid()
            && receipt.selector.policy == self.policy
            && receipt.selector.issuer == self.issuer
            && receipt.public_key == self.public_key
            && receipt.selector.epoch >= self.initial_epoch
    }

    pub fn commitment(self) -> Hash {
        Hash::digest(
            b"vos/agent/authority-binding/v1",
            &[
                self.policy.as_bytes(),
                self.issuer.principal.as_bytes(),
                self.issuer.actor.as_bytes(),
                self.issuer.deployment.as_bytes(),
                self.issuer.program.as_bytes(),
                self.issuer.producer.as_bytes(),
                &self.public_key,
                &self.initial_epoch.to_le_bytes(),
            ],
        )
    }
}

/// Relevant lane commitments selected at authorization time. Missing lanes
/// are explicit and cannot be confused with a zero root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityLaneRoots {
    pub control: Option<Hash>,
    pub linear: Option<Hash>,
    pub merge: Option<Hash>,
    pub local: Option<Hash>,
}

impl AuthorityLaneRoots {
    pub fn is_valid(self) -> bool {
        option_hash_valid(self.control)
            && option_hash_valid(self.linear)
            && option_hash_valid(self.merge)
            && option_hash_valid(self.local)
    }
}

fn option_hash_valid(value: Option<Hash>) -> bool {
    match value {
        Some(value) => value.0 != Hash::ZERO.0,
        None => true,
    }
}

/// Optional package/proof objects plus the mandatory complete evidence
/// commitment used by the policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub package: Option<BlobRef>,
    pub proof: Option<BlobRef>,
    pub commitment: Hash,
}

impl AuthorityEvidence {
    pub fn is_valid(&self) -> bool {
        self.commitment != Hash::ZERO
            && self.package.as_ref().is_none_or(valid_reference)
            && self.proof.as_ref().is_none_or(valid_reference)
    }
}

fn valid_reference(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO
        && reference.len != 0
        && reference.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
}

/// Complete policy selector signed by the authority actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceiptSelector {
    pub policy: Hash,
    pub issuer: AuthorityIssuer,
    pub space: SpaceId,
    pub agent: AgentId,
    pub operation: AuthorityOperationKind,
    pub runtime_deployment: DeploymentId,
    pub actor: Option<ActorId>,
    pub actor_deployment: Option<DeploymentId>,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    /// Monotonic policy/committee epoch.
    pub epoch: u64,
    /// Binding-global sequence in the clean management decision journal.
    /// This is nonzero only for operations selected by
    /// [`AuthorityOperationKind::uses_management_decision_journal`].
    pub decision_sequence: u64,
    /// Inclusive clean-management sequence watermark whose older exact
    /// results the authority has durably observed and permits the Agent to
    /// discard. Unrelated operation domains carry zero here and above.
    pub acknowledged_through: u64,
    /// First logical slot at which this decision may be consumed.
    pub valid_from: u64,
    /// Last logical slot at which this decision may be consumed, inclusive.
    pub expires_at: u64,
    /// Hash of the exact canonical request bytes authorized by this receipt.
    pub request: Hash,
}

impl AuthorityReceiptSelector {
    pub fn validate(&self) -> Result<(), AuthorityReceiptError> {
        let valid_management_replay = if self.operation.uses_management_decision_journal() {
            self.decision_sequence != 0 && self.acknowledged_through < self.decision_sequence
        } else {
            self.decision_sequence == 0 && self.acknowledged_through == 0
        };
        if self.policy == Hash::ZERO
            || !self.issuer.is_valid()
            || self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.runtime_deployment == DeploymentId::ZERO
            || self.request == Hash::ZERO
            || !valid_management_replay
            || self.valid_from > self.expires_at
            || !self.evidence.is_valid()
            || !self.lane_roots.is_valid()
        {
            return Err(AuthorityReceiptError::InvalidSelector);
        }
        match (self.operation.requires_actor(), self.actor) {
            (true, Some(actor)) if actor != ActorId::ZERO => {}
            (false, None) => {}
            _ => return Err(AuthorityReceiptError::InvalidSelector),
        }
        match (
            self.operation.requires_actor_deployment(),
            self.actor_deployment,
        ) {
            (true, Some(deployment)) if deployment != DeploymentId::ZERO => {}
            (false, None) => {}
            _ => return Err(AuthorityReceiptError::InvalidSelector),
        }
        Ok(())
    }

    pub fn is_live_at(&self, logical_slot: u64) -> bool {
        logical_slot >= self.valid_from && logical_slot <= self.expires_at
    }
}

/// Signed, self-describing authority evidence. The verifier implementation is
/// supplied by the guest runtime so the SDK does not choose a cryptographic
/// provider or introduce host calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceipt {
    pub selector: AuthorityReceiptSelector,
    pub public_key: [u8; AUTHORITY_PUBLIC_KEY_BYTES],
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl AuthorityReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/authority/receipt",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityReceiptError> {
        self.selector.validate()?;
        if self.public_key == [0; AUTHORITY_PUBLIC_KEY_BYTES]
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        if ProducerId::of_public_key(&self.public_key) != self.selector.issuer.producer {
            return Err(AuthorityReceiptError::WrongSigner);
        }
        Ok(())
    }

    pub fn verify_at<V: AuthorityVerifier>(
        &self,
        logical_slot: u64,
        verifier: &V,
    ) -> Result<(), AuthorityReceiptError> {
        self.validate_shape()?;
        if !self.selector.is_live_at(logical_slot) {
            return Err(AuthorityReceiptError::Expired);
        }
        if !verifier.verify(&self.public_key, &self.signing_bytes(), &self.signature) {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        Ok(())
    }
}

pub trait AuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityReceiptError {
    InvalidSelector,
    WrongSigner,
    InvalidSignature,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signature(public_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
        let first = Hash::digest(
            b"vos/test/credential-signature/first",
            &[public_key, message],
        );
        let second = Hash::digest(
            b"vos/test/credential-signature/second",
            &[public_key, message],
        );
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        signature
    }

    struct TestCredentialVerifier;

    impl AuthorityCredentialVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    impl AuthorityVerifier for TestCredentialVerifier {
        fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            *signature == test_signature(public_key, message)
        }
    }

    fn authority_target() -> AuthorityActorTarget {
        let public_key = [28; AUTHORITY_PUBLIC_KEY_BYTES];
        AuthorityActorTarget {
            space: SpaceId([21; 32]),
            system_agent: AgentId([22; 32]),
            system_runtime_deployment: DeploymentId([23; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([20; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([24; 32]),
                    actor: ActorId([25; 32]),
                    deployment: DeploymentId([26; 32]),
                    program: ProgramId([27; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
        }
    }

    fn managed_target() -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: authority_target().space,
            agent: AgentId([29; 32]),
            owner: PrincipalId([0x29; 32]),
            profile: AgentProfile::Shared,
            runtime_deployment: DeploymentId([30; 32]),
            transition_producer: ProducerId([0x2a; 32]),
        }
    }

    fn mutating_request() -> ManagementRequest {
        ManagementRequest::Suspend {
            actor: ActorId([31; 32]),
            expected_deployment: DeploymentId([32; 32]),
        }
    }

    fn credential_call(request: ManagementRequest) -> AuthorityCredentialCall {
        let public_key = [33; CREDENTIAL_PUBLIC_KEY_BYTES];
        let plan = request.authorization_plan().unwrap();
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            managed: managed_target(),
            principal: PrincipalId([35; 32]),
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public_key,
            authenticated_node: Some(NodeId([36; 32])),
            requested_valid_from: 100,
            requested_expires_at: 120,
            plan,
            signature: [1; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&public_key, &call.signing_bytes());
        call
    }

    fn resign(call: &mut AuthorityCredentialCall) {
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&call.credential_public_key, &call.signing_bytes());
    }

    fn admin_call() -> AuthorityAdminCall {
        let public_key = [45; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut call = AuthorityAdminCall {
            invocation: InvocationId::ZERO,
            authority: authority_target(),
            administrator: PrincipalId([47; 32]),
            credential: CredentialId::of_public_key(&public_key),
            request_sequence: NonZeroU64::new(1).unwrap(),
            credential_public_key: public_key,
            authenticated_node: NodeId([48; 32]),
            observed_slot: 101,
            expected_generation: NonZeroU64::new(3).unwrap(),
            operation: AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([49; 32]),
                credential: AuthorityCredentialEnrollment::from_public_key(
                    AuthorityCredentialKind::Ssh,
                    [50; CREDENTIAL_PUBLIC_KEY_BYTES],
                ),
            },
            signature: [1; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call.signature = test_signature(&public_key, &call.signing_bytes());
        call
    }

    fn approval(call: &AuthorityCredentialCall) -> ManagementApproval {
        ManagementApproval::from_call(
            call,
            NonZeroU64::new(7).unwrap(),
            AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([37; 32]),
            },
            AuthorityLaneRoots {
                control: Some(Hash([38; 32])),
                linear: Some(Hash([39; 32])),
                merge: None,
                local: None,
            },
            3,
            101,
            119,
        )
        .unwrap()
    }

    fn application_ack(
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
    ) -> ManagementApplicationAck {
        let (actor, deployment) = match call.plan {
            ManagementAuthorizationPlan::Suspend {
                actor,
                expected_deployment,
            } => (actor, expected_deployment),
            _ => panic!("application acknowledgement fixture requires Suspend"),
        };
        let application = ManagementReply::Suspended(crate::ActorEntry {
            actor,
            name: "fixture".into(),
            parent: None,
            deployment,
            program: ProgramId([40; 32]),
            package: BlobRef::of_bytes(b"fixture-package"),
            agent_schema: BlobRef::of_bytes(b"fixture-schema"),
            method_policy: BlobRef::of_bytes(b"fixture-policy"),
            constructor_abi: Hash([41; 32]),
            installation_data: None,
            state_layout: Hash([42; 32]),
            lanes: crate::LaneSet::NONE,
            suspended: true,
        });
        application_ack_with_reply(call, approval, application)
    }

    fn application_ack_with_reply(
        call: &AuthorityCredentialCall,
        approval: &ManagementApproval,
        application: ManagementReply,
    ) -> ManagementApplicationAck {
        let actor = approval.plan.authority_actor();
        let mut receipt = AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: approval.authority.binding.policy,
                issuer: approval.authority.binding.issuer,
                space: approval.managed.space,
                agent: approval.managed.agent,
                operation: approval.plan.authority_operation(),
                runtime_deployment: approval.managed.runtime_deployment,
                actor: actor.map(|(actor, _)| actor),
                actor_deployment: actor.map(|(_, deployment)| deployment),
                evidence: approval.evidence.clone(),
                lane_roots: approval.lane_roots,
                epoch: approval.epoch,
                decision_sequence: 1,
                acknowledged_through: 0,
                valid_from: approval.valid_from,
                expires_at: approval.expires_at,
                request: approval.plan_commitment,
            },
            public_key: approval.authority.binding.public_key,
            signature: [1; AUTHORITY_SIGNATURE_BYTES],
        };
        receipt.signature = test_signature(&receipt.public_key, &receipt.signing_bytes());
        let mut ack = ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: call.authority,
            managed: call.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            application,
            receipt,
            reopened_state: Hash([44; 32]),
            applied_at: approval.valid_from,
            signature: [1; AUTHORITY_SIGNATURE_BYTES],
        };
        ack.signature = test_signature(&ack.authority.binding.public_key, &ack.signing_bytes());
        ack
    }

    fn selector(producer: ProducerId) -> AuthorityReceiptSelector {
        AuthorityReceiptSelector {
            policy: Hash([1; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([2; 32]),
                actor: ActorId([3; 32]),
                deployment: DeploymentId([4; 32]),
                program: ProgramId([5; 32]),
                producer,
            },
            space: SpaceId([6; 32]),
            agent: AgentId([7; 32]),
            operation: AuthorityOperationKind::InvokeActor,
            runtime_deployment: DeploymentId([8; 32]),
            actor: Some(ActorId([9; 32])),
            actor_deployment: Some(DeploymentId([10; 32])),
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([11; 32]),
            },
            lane_roots: AuthorityLaneRoots {
                linear: Some(Hash([12; 32])),
                ..AuthorityLaneRoots::default()
            },
            epoch: 4,
            decision_sequence: 0,
            acknowledged_through: 0,
            valid_from: 20,
            expires_at: 30,
            request: Hash([13; 32]),
        }
    }

    fn binding(public_key: [u8; 32]) -> AgentAuthorityBinding {
        let selector = selector(ProducerId::of_public_key(&public_key));
        AgentAuthorityBinding {
            policy: selector.policy,
            issuer: selector.issuer,
            public_key,
            initial_epoch: selector.epoch,
        }
    }

    #[test]
    fn projection_recovery_is_scoped_expiring_signed_and_context_bound() {
        let credential_key = [0x61; CREDENTIAL_PUBLIC_KEY_BYTES];
        let node_key = [0x62; CREDENTIAL_PUBLIC_KEY_BYTES];
        let recovery = AuthorityProjectionRecoveryDelegation {
            generation: Hash([0x63; 32]),
            committee: Hash([0x64; 32]),
            accepted_slot: 10,
            expires_at: 10 + MAX_AUTHORITY_PROJECTION_RECOVERY_SLOTS,
        };
        assert!(recovery.is_valid());
        for (slot, admitted) in [
            (9, false),
            (10, true),
            (129, true),
            (130, false),
            (u64::MAX, false),
        ] {
            assert_eq!(recovery.admits_at(slot), admitted);
        }
        for invalid in [
            AuthorityProjectionRecoveryDelegation {
                generation: Hash::ZERO,
                ..recovery
            },
            AuthorityProjectionRecoveryDelegation {
                committee: Hash::ZERO,
                ..recovery
            },
            AuthorityProjectionRecoveryDelegation {
                expires_at: 10,
                ..recovery
            },
            AuthorityProjectionRecoveryDelegation {
                expires_at: 9,
                ..recovery
            },
            AuthorityProjectionRecoveryDelegation {
                expires_at: 131,
                ..recovery
            },
            AuthorityProjectionRecoveryDelegation {
                accepted_slot: u64::MAX,
                expires_at: 1,
                ..recovery
            },
        ] {
            assert!(!invalid.is_valid());
            assert!(!invalid.admits_at(10));
        }
        for ssh in [false, true] {
            let mut query = AuthorityProjectionQuery {
                authority: authority_target(),
                credential: CredentialId::of_public_key(&credential_key),
                nonce: Hash([0x65; 32]),
                selector: AuthorityProjectionSelector::Agents {
                    after: None,
                    limit: 2,
                },
                authentication: if ssh {
                    AuthorityIngressAuthentication::SshNodeAttestation {
                        credential_public_key: credential_key,
                        node: NodeId([0x66; 32]),
                        request_binding: Hash([0x67; 32]),
                        signature: [1; CREDENTIAL_SIGNATURE_BYTES],
                    }
                } else {
                    AuthorityIngressAuthentication::ApiCredentialSignature {
                        credential_public_key: credential_key,
                        signature: [1; CREDENTIAL_SIGNATURE_BYTES],
                    }
                },
                recovery: Some(recovery),
            };
            let signature = test_signature(
                if ssh { &node_key } else { &credential_key },
                &query.signing_bytes(),
            );
            match &mut query.authentication {
                AuthorityIngressAuthentication::ApiCredentialSignature {
                    signature: field, ..
                }
                | AuthorityIngressAuthentication::SshNodeAttestation {
                    signature: field, ..
                } => *field = signature,
            }
            let verifies = |query: &AuthorityProjectionQuery| {
                if ssh {
                    query
                        .verify_ssh_node_attestation_with(&node_key, &TestCredentialVerifier)
                        .is_ok()
                } else {
                    query.verify_api_with(&TestCredentialVerifier).is_ok()
                }
            };
            assert!(verifies(&query));
            for change in 0..7 {
                let mut altered = query.clone();
                match change {
                    0 => altered.recovery = None,
                    1 => altered.recovery.as_mut().unwrap().generation.0[0] ^= 1,
                    2 => altered.recovery.as_mut().unwrap().committee.0[0] ^= 1,
                    3 => altered.recovery.as_mut().unwrap().accepted_slot += 1,
                    4 => altered.recovery.as_mut().unwrap().expires_at -= 1,
                    5 => altered.nonce.0[0] ^= 1,
                    _ => altered.selector = AuthorityProjectionSelector::Credential,
                }
                assert_ne!(query.commitment(), altered.commitment());
                assert!(!verifies(&altered), "substituted signed field {change}");
            }
            let context = InvocationContext {
                invocation: query.expected_invocation(),
                actor: query.authority.binding.issuer.actor,
                mode: MethodMode::Query,
                observed_slot: recovery.accepted_slot,
                origin: crate::InvocationOrigin {
                    principal: None,
                    credential: None,
                    transport_node: query.attesting_node(),
                    actor: None,
                    capability: None,
                },
                roles: InvocationRoleClaims::none(),
            };
            assert!(query.matches_recovery_context(&context));
            for change in 0..5 {
                let mut altered = context;
                match change {
                    0 => altered.observed_slot += 1,
                    1 => altered.invocation = InvocationId([0x68; 32]),
                    2 => altered.actor = ActorId([0x69; 32]),
                    3 => altered.mode = MethodMode::Linear,
                    _ => altered.origin.transport_node = Some(NodeId([0x70; 32])),
                }
                assert!(!query.matches_recovery_context(&altered));
            }
        }
    }

    #[test]
    fn projection_authentication_variants_bind_the_complete_query() {
        let api_key = [0x61; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut api = AuthorityProjectionQuery {
            recovery: None,
            authority: authority_target(),
            credential: CredentialId::of_public_key(&api_key),
            nonce: Hash([0x62; 32]),
            selector: AuthorityProjectionSelector::Agents {
                after: Some(AgentId([0x63; 32])),
                limit: 2,
            },
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key: api_key,
                signature: [1; CREDENTIAL_SIGNATURE_BYTES],
            },
        };
        let api_signature = test_signature(&api_key, &api.signing_bytes());
        let AuthorityIngressAuthentication::ApiCredentialSignature { signature, .. } =
            &mut api.authentication
        else {
            unreachable!();
        };
        *signature = api_signature;
        assert_eq!(api.verify_api_with(&TestCredentialVerifier), Ok(()));
        assert!(
            api.verify_ssh_node_attestation_with(&[0x64; 32], &TestCredentialVerifier)
                .is_err()
        );
        let mut substituted = api.clone();
        substituted.nonce.0[0] ^= 1;
        assert!(
            substituted
                .verify_api_with(&TestCredentialVerifier)
                .is_err()
        );

        let node_key = [0x65; CREDENTIAL_PUBLIC_KEY_BYTES];
        let ssh_key = [0x66; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut ssh = AuthorityProjectionQuery {
            recovery: None,
            authority: authority_target(),
            credential: CredentialId::of_public_key(&ssh_key),
            nonce: Hash([0x67; 32]),
            selector: AuthorityProjectionSelector::Credential,
            authentication: AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key: ssh_key,
                node: NodeId([0x68; 32]),
                request_binding: Hash([0x69; 32]),
                signature: [1; CREDENTIAL_SIGNATURE_BYTES],
            },
        };
        let node_signature = test_signature(&node_key, &ssh.signing_bytes());
        let AuthorityIngressAuthentication::SshNodeAttestation { signature, .. } =
            &mut ssh.authentication
        else {
            unreachable!();
        };
        *signature = node_signature;
        assert_eq!(
            ssh.verify_ssh_node_attestation_with(&node_key, &TestCredentialVerifier),
            Ok(())
        );
        assert!(ssh.verify_api_with(&TestCredentialVerifier).is_err());

        let mut zero_binding = ssh;
        let AuthorityIngressAuthentication::SshNodeAttestation {
            request_binding, ..
        } = &mut zero_binding.authentication
        else {
            unreachable!();
        };
        *request_binding = Hash::ZERO;
        assert_eq!(
            zero_binding.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidCaller)
        );
    }

    #[test]
    fn selector_binds_actor_and_runtime_deployments() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert_eq!(value.validate(), Ok(()));
        let mut missing_actor = value.clone();
        missing_actor.actor = None;
        assert_eq!(
            missing_actor.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
    }

    #[test]
    fn logical_expiry_is_inclusive_and_deterministic() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert!(!value.is_live_at(19));
        assert!(value.is_live_at(20));
        assert!(value.is_live_at(30));
        assert!(!value.is_live_at(31));
    }

    #[test]
    fn management_replay_fields_are_nonzero_and_scoped_away_from_invocations() {
        let key = [14; 32];
        let invocation = selector(ProducerId::of_public_key(&key));
        assert_eq!(invocation.validate(), Ok(()));

        let mut invalid_invocation = invocation.clone();
        invalid_invocation.decision_sequence = 1;
        assert_eq!(
            invalid_invocation.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );

        let mut management = invocation;
        management.operation = AuthorityOperationKind::SuspendActor;
        management.decision_sequence = 9;
        management.acknowledged_through = 8;
        assert_eq!(management.validate(), Ok(()));

        let mut zero_sequence = management.clone();
        zero_sequence.decision_sequence = 0;
        zero_sequence.acknowledged_through = 0;
        assert_eq!(
            zero_sequence.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
        management.acknowledged_through = management.decision_sequence;
        assert_eq!(
            management.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
    }

    #[test]
    fn authority_binding_is_independent_of_self_described_receipt_fields() {
        let public_key = [14; 32];
        let anchor = binding(public_key);
        let receipt = AuthorityReceipt {
            selector: selector(ProducerId::of_public_key(&public_key)),
            public_key,
            signature: [15; 64],
        };
        assert!(anchor.is_valid());
        assert!(anchor.accepts(&receipt));
        assert_ne!(anchor.commitment(), Hash::ZERO);

        let mut attacker = receipt.clone();
        attacker.selector.policy = Hash([16; 32]);
        assert!(!anchor.accepts(&attacker));
        attacker = receipt.clone();
        attacker.selector.epoch = anchor.initial_epoch - 1;
        assert!(!anchor.accepts(&attacker));
        attacker = receipt;
        attacker.public_key = [17; 32];
        assert!(!anchor.accepts(&attacker));
    }

    #[test]
    fn credential_call_uses_injected_verification_and_exact_clean_preflight() {
        let call = credential_call(mutating_request());
        assert_eq!(call.validate_shape(), Ok(()));
        assert_eq!(call.verify_with(&TestCredentialVerifier), Ok(()));
        assert_ne!(
            call.principal,
            PrincipalId::of_public_key(&call.credential_public_key),
            "a revocable credential is not the durable Principal identity"
        );

        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: Some(call.principal),
                transport_node: call.authenticated_node,
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: 99,
        };
        assert!(call.matches_invocation_context(&context));

        let mut granted = context;
        granted.roles.space = Some(crate::RoleId([40; 32]));
        assert!(!call.matches_invocation_context(&granted));
        let mut relayed = context;
        relayed.origin.actor = Some(ActorId([41; 32]));
        assert!(!call.matches_invocation_context(&relayed));
        let mut wrong_credential = context;
        wrong_credential.origin.credential = Some(CredentialId([42; 32]));
        assert!(!call.matches_invocation_context(&wrong_credential));
    }

    #[test]
    fn credential_call_rejects_zero_mismatch_and_read_only_shapes() {
        let call = credential_call(mutating_request());

        let mut zero = call.clone();
        zero.invocation = InvocationId::ZERO;
        assert_eq!(
            zero.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut wrong_credential = call.clone();
        wrong_credential.credential = CredentialId([43; 32]);
        assert_eq!(
            wrong_credential.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidCaller)
        );
        let mut wrong_space = call.clone();
        wrong_space.managed.space = SpaceId([44; 32]);
        assert_eq!(
            wrong_space.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut reverse_validity = call;
        reverse_validity.requested_valid_from = 121;
        assert_eq!(
            reverse_validity.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidValidity)
        );

        for request in [
            ManagementRequest::InspectResources,
            ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            },
        ] {
            assert!(request.authorization_plan().is_none());
        }
    }

    #[test]
    fn admin_call_and_result_bind_exact_caller_context_operation_and_generation() {
        let call = admin_call();
        assert_eq!(call.validate_shape(), Ok(()));
        assert_eq!(call.verify_with(&TestCredentialVerifier), Ok(()));
        let context = InvocationContext {
            invocation: call.invocation,
            actor: call.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: Some(call.administrator),
                transport_node: Some(call.authenticated_node),
                credential: Some(call.credential),
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: call.observed_slot,
        };
        assert!(call.matches_invocation_context(&context));

        let result = AuthorityAdminResult::from_call(call.clone()).unwrap();
        assert_eq!(result.generation.get(), call.expected_generation.get() + 1);
        assert_eq!(result.verify_with(&TestCredentialVerifier), Ok(()));

        let mut cross_node = call.clone();
        cross_node.authenticated_node = NodeId([51; 32]);
        assert_ne!(cross_node.signing_bytes(), call.signing_bytes());
        assert!(!cross_node.matches_invocation_context(&context));
        let mut stale = call.clone();
        stale.expected_generation = NonZeroU64::new(2).unwrap();
        assert_ne!(stale.signing_bytes(), call.signing_bytes());
        let mut forged = call;
        forged.signature[0] ^= 1;
        assert_eq!(
            forged.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature),
        );
    }

    #[test]
    fn approval_binds_exact_call_and_narrows_requested_validity() {
        let call = credential_call(mutating_request());
        let value = approval(&call);
        assert_eq!(value.validate_shape(), Ok(()));
        assert!(value.matches_call(&call));
        assert_eq!(
            value.acknowledgement_invocation,
            ManagementApproval::derive_acknowledgement_invocation(&call)
        );
        assert_ne!(value.acknowledgement_invocation, call.invocation);
        assert_ne!(value.commitment(), Hash::ZERO);

        let mut wider = value.clone();
        wider.valid_from = call.requested_valid_from - 1;
        assert!(!wider.matches_call(&call));
        let mut divergent = call.clone();
        divergent.signature[0] ^= 1;
        assert!(!value.matches_call(&divergent));
        let mut wrong_acknowledgement = value.clone();
        wrong_acknowledgement.acknowledgement_invocation = InvocationId([46; 32]);
        assert_eq!(wrong_acknowledgement.validate_shape(), Ok(()));
        assert!(!wrong_acknowledgement.matches_call(&call));
        let mut wrong_request = value;
        wrong_request.plan_commitment = Hash([45; 32]);
        assert_eq!(
            wrong_request.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn receipt_approval_binding_keeps_issuer_and_authorization_clocks_separate() {
        let call = credential_call(mutating_request());
        let approval = approval(&call);
        let ack = application_ack(&call, &approval);
        assert!(receipt_matches_approval(&ack.receipt, &approval));
        let mut later_issuer_sequence = ack.receipt.clone();
        later_issuer_sequence.selector.decision_sequence += 100;
        assert!(receipt_matches_approval(&later_issuer_sequence, &approval));
        // Matching does not claim that the changed receipt is signed.
        assert!(
            later_issuer_sequence
                .verify_at(ack.applied_at, &TestCredentialVerifier)
                .is_err()
        );
        let mut substituted = ack.receipt.clone();
        substituted.selector.request = Hash([0x91; 32]);
        assert!(!receipt_matches_approval(&substituted, &approval));
        substituted = ack.receipt.clone();
        substituted.selector.agent = AgentId([0x92; 32]);
        assert!(!receipt_matches_approval(&substituted, &approval));
    }

    #[test]
    fn application_ack_requires_distinct_invocation_exact_pending_preimages_and_two_signatures() {
        let call = credential_call(mutating_request());
        let approval = approval(&call);
        let ack = application_ack(&call, &approval);
        assert_eq!(ack.validate_shape(), Ok(()));
        assert!(ack.matches_pending(&call, &approval));
        assert_eq!(ack.verify_with(&TestCredentialVerifier), Ok(()));
        assert_ne!(ack.commitment(), Hash::ZERO);

        let context = InvocationContext {
            invocation: ack.acknowledgement_invocation,
            actor: ack.authority.binding.issuer.actor,
            mode: MethodMode::Linear,
            origin: crate::InvocationOrigin {
                principal: None,
                transport_node: None,
                credential: None,
                actor: None,
                capability: None,
            },
            roles: InvocationRoleClaims::none(),
            observed_slot: ack.applied_at,
        };
        assert!(ack.matches_invocation_context(&context));

        let mut reused_invocation = ack.clone();
        reused_invocation.acknowledgement_invocation = reused_invocation.authorization_invocation;
        assert_eq!(
            reused_invocation.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidTarget)
        );
        let mut wrong_approval = ack.clone();
        wrong_approval.approval = Hash([45; 32]);
        assert!(!wrong_approval.matches_pending(&call, &approval));
        let mut wrong_reserved_invocation = ack.clone();
        wrong_reserved_invocation.acknowledgement_invocation = InvocationId([46; 32]);
        wrong_reserved_invocation.signature = test_signature(
            &wrong_reserved_invocation.authority.binding.public_key,
            &wrong_reserved_invocation.signing_bytes(),
        );
        assert!(!wrong_reserved_invocation.matches_pending(&call, &approval));
        let mut expired = ack.clone();
        expired.applied_at = expired.receipt.selector.expires_at + 1;
        assert_eq!(
            expired.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        let mut forged_receipt = ack.clone();
        forged_receipt.receipt.signature[0] ^= 1;
        forged_receipt.signature = test_signature(
            &forged_receipt.authority.binding.public_key,
            &forged_receipt.signing_bytes(),
        );
        assert_eq!(
            forged_receipt.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        let mut forged_ack = ack.clone();
        forged_ack.signature[0] ^= 1;
        assert_eq!(
            forged_ack.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        let mut wrong_context = context;
        wrong_context.invocation = call.invocation;
        assert!(!ack.matches_invocation_context(&wrong_context));
    }

    #[test]
    fn application_failure_is_signed_and_bound_to_a_pending_local_install() {
        check_application_failure(AgentProfile::Local);
    }

    #[test]
    fn application_failure_is_signed_and_bound_to_a_pending_shared_install() {
        check_application_failure(AgentProfile::Shared);
    }

    fn check_application_failure(profile: AgentProfile) {
        let entry = crate::ActorEntry {
            actor: ActorId([61; 32]),
            name: "fixture".into(),
            parent: None,
            deployment: DeploymentId([62; 32]),
            program: ProgramId([63; 32]),
            package: BlobRef::of_bytes(b"failure-package"),
            agent_schema: BlobRef::of_bytes(b"failure-schema"),
            method_policy: BlobRef::of_bytes(b"failure-policy"),
            constructor_abi: Hash([64; 32]),
            installation_data: None,
            state_layout: Hash([65; 32]),
            lanes: crate::LaneSet::NONE,
            suspended: false,
        };
        let install = crate::InstallActor {
            installation_id: InstallationId([66; 32]),
            registry_reservation: Hash([67; 32]),
            producer: ProducerId([68; 32]),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: None,
            state_layout: entry.state_layout,
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements::default(),
            entry: entry.clone(),
        };
        let mut call = credential_call(ManagementRequest::Install(Box::new(install)));
        call.managed.profile = profile;
        resign(&mut call);
        let approval = approval(&call);
        let success =
            application_ack_with_reply(&call, &approval, ManagementReply::Installed(entry));
        assert!(success.matches_pending(&call, &approval));
        let mut failure = ManagementApplicationFailure {
            authorization_invocation: success.authorization_invocation,
            acknowledgement_invocation: success.acknowledgement_invocation,
            authority: success.authority,
            managed: success.managed,
            credential_call: success.credential_call,
            approval: success.approval,
            authorization_sequence: success.authorization_sequence,
            request: success.request,
            receipt: success.receipt.clone(),
            error: ManagementError::AlreadyExists,
            reopened_state: Hash([69; 32]),
            failed_at: success.applied_at,
            signature: [1; AUTHORITY_SIGNATURE_BYTES],
        };
        failure.signature = test_signature(
            &failure.authority.binding.public_key,
            &failure.signing_bytes(),
        );
        assert_eq!(failure.validate_shape(), Ok(()));
        assert!(failure.matches_pending(&call, &approval));
        assert_eq!(failure.verify_with(&TestCredentialVerifier), Ok(()));
        assert_ne!(failure.commitment(), success.commitment());

        let mut forged_error = failure.clone();
        forged_error.error = ManagementError::ExpiredBeforeApplication;
        assert_eq!(
            forged_error.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        forged_error.error = ManagementError::ResourceLimit;
        assert_eq!(
            forged_error.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        let mut wrong_request = failure.clone();
        wrong_request.request = Hash([70; 32]);
        wrong_request.signature = test_signature(
            &wrong_request.authority.binding.public_key,
            &wrong_request.signing_bytes(),
        );
        assert!(!wrong_request.matches_pending(&call, &approval));
        let mut wrong_profile = failure.clone();
        wrong_profile.managed.profile = AgentProfile::Private;
        assert_eq!(
            wrong_profile.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        let mut expired = failure;
        expired.failed_at = expired.receipt.selector.expires_at + 1;
        assert_eq!(
            expired.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        expired.error = ManagementError::ExpiredBeforeApplication;
        expired.signature = test_signature(
            &expired.authority.binding.public_key,
            &expired.signing_bytes(),
        );
        assert_eq!(expired.verify_with(&TestCredentialVerifier), Ok(()));
        assert!(expired.matches_pending(&call, &approval));
        let mut boundary = expired.clone();
        boundary.failed_at = boundary.receipt.selector.expires_at;
        assert_eq!(
            boundary.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidApplication)
        );
        let mut forged_expiry = expired.clone();
        forged_expiry.receipt.signature[0] ^= 1;
        forged_expiry.signature = test_signature(
            &forged_expiry.authority.binding.public_key,
            &forged_expiry.signing_bytes(),
        );
        assert_eq!(
            forged_expiry.verify_with(&TestCredentialVerifier),
            Err(AuthorityActorProtocolError::InvalidSignature)
        );
        for profile in [AgentProfile::Local, AgentProfile::Shared] {
            let mut terminal = expired.clone();
            terminal.managed.profile = profile;
            terminal.signature = test_signature(
                &terminal.authority.binding.public_key,
                &terminal.signing_bytes(),
            );
            assert_eq!(terminal.verify_with(&TestCredentialVerifier), Ok(()));
        }
    }

    #[test]
    fn create_and_runtime_upgrade_cross_check_exact_targets() {
        let authority_public_key = [46; AUTHORITY_PUBLIC_KEY_BYTES];
        let mut authority = authority_target();
        authority.binding.policy = Hash([52; 32]);
        authority.binding.public_key = authority_public_key;
        authority.binding.issuer.producer = ProducerId::of_public_key(&authority_public_key);
        authority.binding.initial_epoch = 2;
        let owner = PrincipalId([47; 32]);
        let creation_nonce = Hash([48; 32]);
        let agent = AgentId::derive(authority.space, owner, creation_nonce.as_bytes());
        let managed = ManagedAgentTarget {
            space: authority.space,
            agent,
            owner,
            profile: crate::AgentProfile::Local,
            runtime_deployment: DeploymentId([49; 32]),
            transition_producer: ProducerId([52; 32]),
        };
        let descriptor = crate::AgentDescriptor {
            identity: crate::AgentIdentity {
                space: managed.space,
                agent: managed.agent,
                owner,
                profile: crate::AgentProfile::Local,
                runtime_deployment: managed.runtime_deployment,
                runtime_program: ProgramId([50; 32]),
                runtime_producer: ProducerId([51; 32]),
                transition_producer: ProducerId([52; 32]),
            },
            creation_nonce,
            authority: authority.binding,
            private_recovery: None,
            runtime_package: BlobRef {
                hash: Hash([53; 32]),
                len: 1,
            },
            runtime_contract: crate::contract::RuntimePackageContract::canonical(),
            capabilities: crate::RuntimeCapabilities::standard(),
            replicas: alloc::vec![crate::AgentReplica {
                node: NodeId([54; 32]),
                principal: owner,
                role: crate::ReplicaRole::Voter,
            }],
        };
        assert!(descriptor.validate().is_ok());

        let mut create = credential_call(ManagementRequest::Create(alloc::boxed::Box::new(
            descriptor.clone(),
        )));
        create.authority = authority;
        create.managed = managed;
        resign(&mut create);
        assert_eq!(create.validate_shape(), Ok(()));

        let mut wrong_issuer = descriptor.clone();
        wrong_issuer.authority.issuer.principal = PrincipalId([55; 32]);
        let mut wrong_issuer_call = create.clone();
        wrong_issuer_call.plan = ManagementRequest::Create(alloc::boxed::Box::new(wrong_issuer))
            .authorization_plan()
            .unwrap();
        resign(&mut wrong_issuer_call);
        assert_eq!(
            wrong_issuer_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let mut wrong_issuer = descriptor.clone();
        wrong_issuer.authority.public_key = [62; AUTHORITY_PUBLIC_KEY_BYTES];
        wrong_issuer.authority.issuer.producer =
            ProducerId::of_public_key(&wrong_issuer.authority.public_key);
        assert!(wrong_issuer.validate().is_ok());
        let mut wrong_issuer_call = create.clone();
        wrong_issuer_call.plan = ManagementRequest::Create(alloc::boxed::Box::new(wrong_issuer))
            .authorization_plan()
            .unwrap();
        resign(&mut wrong_issuer_call);
        assert_eq!(
            wrong_issuer_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let mut wrong_target = create;
        wrong_target.managed.runtime_deployment = DeploymentId([56; 32]);
        resign(&mut wrong_target);
        assert_eq!(
            wrong_target.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let upgrade = crate::RuntimeUpgrade {
            from_deployment: managed.runtime_deployment,
            to_deployment: DeploymentId([57; 32]),
            to_program: ProgramId([58; 32]),
            producer: ProducerId([59; 32]),
            package: BlobRef {
                hash: Hash([60; 32]),
                len: 1,
            },
            contract: crate::contract::RuntimePackageContract::canonical(),
            capabilities: crate::RuntimeCapabilities::standard(),
        };
        let mut upgrade_call = credential_call(ManagementRequest::UpgradeRuntime(
            alloc::boxed::Box::new(upgrade.clone()),
        ));
        upgrade_call.authority = authority;
        upgrade_call.managed = managed;
        resign(&mut upgrade_call);
        assert_eq!(upgrade_call.validate_shape(), Ok(()));

        let upgrade_approval = approval(&upgrade_call);
        let upgraded_identity = crate::AgentIdentity {
            space: managed.space,
            agent: managed.agent,
            owner: managed.owner,
            profile: managed.profile,
            runtime_deployment: upgrade.to_deployment,
            runtime_program: upgrade.to_program,
            runtime_producer: upgrade.producer,
            transition_producer: managed.transition_producer,
        };
        let upgrade_ack = application_ack_with_reply(
            &upgrade_call,
            &upgrade_approval,
            ManagementReply::RuntimeUpgraded(upgraded_identity),
        );
        assert!(upgrade_ack.matches_pending(&upgrade_call, &upgrade_approval));
        for substitute in [
            |identity: &mut AgentIdentity| identity.owner = PrincipalId([0xe1; 32]),
            |identity: &mut AgentIdentity| identity.profile = AgentProfile::Private,
            |identity: &mut AgentIdentity| identity.transition_producer = ProducerId([0xe2; 32]),
        ] {
            let mut substituted = upgrade_ack.clone();
            let ManagementReply::RuntimeUpgraded(identity) = &mut substituted.application else {
                unreachable!();
            };
            substitute(identity);
            substituted.signature = test_signature(
                &substituted.authority.binding.public_key,
                &substituted.signing_bytes(),
            );
            assert_eq!(substituted.verify_with(&TestCredentialVerifier), Ok(()));
            assert!(!substituted.matches_pending(&upgrade_call, &upgrade_approval));
        }

        let mut reused_transition_signer = upgrade.clone();
        reused_transition_signer.producer = managed.transition_producer;
        let mut reused_transition_signer_call = upgrade_call.clone();
        reused_transition_signer_call.plan =
            ManagementRequest::UpgradeRuntime(alloc::boxed::Box::new(reused_transition_signer))
                .authorization_plan()
                .unwrap();
        resign(&mut reused_transition_signer_call);
        assert_eq!(
            reused_transition_signer_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );

        let mut wrong_from = upgrade;
        wrong_from.from_deployment = DeploymentId([61; 32]);
        upgrade_call.plan = ManagementRequest::UpgradeRuntime(alloc::boxed::Box::new(wrong_from))
            .authorization_plan()
            .unwrap();
        resign(&mut upgrade_call);
        assert_eq!(
            upgrade_call.validate_shape(),
            Err(AuthorityActorProtocolError::InvalidRequest)
        );
    }
}
