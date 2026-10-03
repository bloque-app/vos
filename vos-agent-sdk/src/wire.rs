//! Canonical bounded codecs for the clean agent SDK generation.
//!
//! There is exactly one accepted ABI header. This module intentionally has no
//! compatibility tags or fallback decoder.

use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::authority::{
    AUTHORITY_PUBLIC_KEY_BYTES, AUTHORITY_SIGNATURE_BYTES, AgentAuthorityBinding,
    AuthorityActorProjection, AuthorityActorProjectionPage, AuthorityActorRoleGrant,
    AuthorityActorTarget, AuthorityAdminCall, AuthorityAdminOperation, AuthorityAdminResult,
    AuthorityAgentProjection, AuthorityAgentProjectionPage, AuthorityAgentReplicaProjectionPage,
    AuthorityBuiltinRole, AuthorityCapabilityGrant, AuthorityCredentialCall,
    AuthorityCredentialEnrollment, AuthorityCredentialKind, AuthorityCredentialProjection,
    AuthorityCredentialStatus, AuthorityEvidence, AuthorityIngressAuthentication,
    AuthorityInventoryCursor, AuthorityInventoryEntry, AuthorityInventoryPosition,
    AuthorityInventoryProjectionPage, AuthorityIssuer, AuthorityLaneRoots, AuthorityOperationKind,
    AuthorityProjectionHead, AuthorityProjectionQuery, AuthorityProjectionRecoveryDelegation,
    AuthorityProjectionSelector, AuthorityReceipt, AuthorityReceiptSelector,
    CREDENTIAL_PUBLIC_KEY_BYTES, CREDENTIAL_SIGNATURE_BYTES, CompactAgentDescriptor,
    CompactInstallActor, CompactReplicaSlot, MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES,
    MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES, MAX_AUTHORITY_PRINCIPAL_GRANTS,
    MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES, MAX_AUTHORITY_REPLICA_PAGE_ENTRIES, ManagedAgentTarget,
    ManagementApplicationAck, ManagementApplicationFailure, ManagementApproval,
    ManagementAuthorizationPlan,
};
use crate::catalog::{
    CatalogActorTarget, CatalogAlias, CatalogEntry, CatalogMutationCall, CatalogMutationKind,
    CatalogMutationRequest, CatalogMutationResult, CatalogPage, CatalogPageRequest,
    CatalogPublication, MAX_CATALOG_ALIAS_BYTES, MAX_CATALOG_NAMESPACE_BYTES,
    MAX_CATALOG_PAGE_ENTRIES,
};
use crate::contract::{
    ActorAbiRange, ActorPackageContract, RuntimeMigrationPolicy, RuntimePackageContract,
    RuntimeResourceLimits, RuntimeResourcePolicy,
};
use crate::*;

const HEADER_BYTES: usize = 4 + 32;
pub const MAX_ACTOR_ENTRY_WIRE_BYTES: usize = 1_024;
pub const MAX_DIRECTORY_PAGE_WIRE_BYTES: usize =
    HEADER_BYTES + 4 + MAX_DIRECTORY_PAGE_ENTRIES * (MAX_ACTOR_ENTRY_WIRE_BYTES + 128) + 33;
pub const MAX_AUTHORITY_RECEIPT_WIRE_BYTES: usize = 1_024;
pub const MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_AUTHORITY_ADMIN_CALL_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_AUTHORITY_ADMIN_RESULT_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_AUTHORITY_CREDENTIAL_PROJECTION_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_AUTHORITY_AGENT_PROJECTION_PAGE_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_AUTHORITY_AGENT_REPLICA_PROJECTION_PAGE_WIRE_BYTES: usize =
    MAX_INVOCATION_REPLY_BYTES;
pub const MAX_AUTHORITY_ACTOR_PROJECTION_PAGE_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_MANAGEMENT_APPROVAL_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_MANAGEMENT_AUTHORIZATION_PLAN_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_CATALOG_MUTATION_REQUEST_WIRE_BYTES: usize = 2 * 1024;
pub const MAX_CATALOG_MUTATION_CALL_WIRE_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;
pub const MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES: usize = 512;
pub const MAX_CATALOG_ENTRY_WIRE_BYTES: usize = 2 * 1024;
pub const MAX_CATALOG_PAGE_REQUEST_WIRE_BYTES: usize = 1_024;
pub const MAX_CATALOG_PAGE_WIRE_BYTES: usize = MAX_INVOCATION_REPLY_BYTES;
pub const MAX_AGENT_DESCRIPTOR_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_INVOCATION_CONTEXT_WIRE_BYTES: usize = 512;
pub const MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES: usize = 2 * 1024;
pub const MAX_RUNTIME_WORK_WIRE_BYTES: usize =
    HEADER_BYTES + MAX_RUNTIME_STATE_BYTES + MAX_RUNTIME_AVAILABILITY_BYTES + 512 * 1024;
pub const MAX_RUNTIME_TRANSITION_WIRE_BYTES: usize =
    HEADER_BYTES + MAX_RUNTIME_STATE_BYTES + MAX_DIRECTORY_PAGE_WIRE_BYTES + 64 * 1024;
pub const MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES: usize = HEADER_BYTES + 4 + 4 + 4 + 8 + 8;
/// Exact largest canonical PCTL admitted by the runtime ABI. Only the fixed
/// SetResourcePolicy and ActorLifecycle shapes are admitted; the much larger
/// Invite/Recover control families never enter a guest work item.
pub const MAX_PRIVATE_RUNTIME_CONTROL_WIRE_BYTES: usize = HEADER_BYTES
    + 32 // space
    + 32 // agent
    + 8 // sequence
    + 1
    + 32 // optional previous
    + 1
    + 32
    + 1
    + 32 // largest ActorLifecycle operation
    + 1 // signer
    + 32 // signing key
    + crate::private::PRIVATE_SIGNATURE_BYTES;
/// One bounded nonrecursive Private mutation. Install is largest because it
/// may contain the canonical constructor argument preimage.
pub const MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES: usize =
    HEADER_BYTES + crate::MAX_INSTALLATION_DATA_BYTES + 4 * MAX_ACTOR_ENTRY_WIRE_BYTES;
/// One complete, nonrecursive management request. `PrivateControl` is the
/// largest admitted shape because it frames both bounded canonical PCTL and
/// private-runtime mutation values.
pub const MAX_MANAGEMENT_REQUEST_WIRE_BYTES: usize = HEADER_BYTES
    + 1
    + 4
    + MAX_PRIVATE_RUNTIME_CONTROL_WIRE_BYTES
    + 4
    + MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Decode(DecodeError),
    InvalidValue,
    LimitExceeded,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidValue => formatter.write_str("invalid canonical agent value"),
            Self::LimitExceeded => formatter.write_str("canonical agent wire limit exceeded"),
        }
    }
}

impl core::error::Error for WireError {}

impl From<DecodeError> for WireError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

/// One complete canonical SDK message. Implementations validate values before
/// encoding and after decoding; malformed values can never be normalized into
/// a second accepted representation.
pub trait CanonicalWire: Sized {
    const MAGIC: [u8; 4];
    const MAX_ENCODED_BYTES: usize;

    fn validate_wire(&self) -> bool;
    fn encode_body(&self, encoder: &mut Encoder<'_>);
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;

    fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !self.validate_wire() {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve(Self::MAX_ENCODED_BYTES.min(4096))
            .map_err(|_| WireError::LimitExceeded)?;
        bytes.extend_from_slice(&Self::MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        Self::encode_body(self, &mut Encoder(&mut bytes));
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(WireError::LimitExceeded);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let value = decode_canonical_frame::<Self>(bytes)?;
        if !value.validate_wire() {
            return Err(WireError::InvalidValue);
        }
        Ok(value)
    }
}

/// Framing only; callers must validate the returned value unless their body
/// decoder already performs complete validation. This helper is private.
fn decode_canonical_frame<T: CanonicalWire>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > T::MAX_ENCODED_BYTES {
        return Err(WireError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4)? != T::MAGIC {
        return Err(DecodeError::InvalidTag.into());
    }
    if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
        return Err(DecodeError::InvalidPlatform.into());
    }
    let value = T::decode_body(&mut decoder)?;
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes.into());
    }
    Ok(value)
}

fn encode_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_optional_blob(encoder: &mut Encoder<'_>, value: &Option<BlobRef>) {
    encoder.option(value, encode_blob);
}

fn decode_optional_blob(decoder: &mut Decoder<'_>) -> Result<Option<BlobRef>, DecodeError> {
    decoder.option(decode_blob)
}

fn encode_installation_data(encoder: &mut Encoder<'_>, value: &InstallationData) {
    encode_blob(encoder, &value.reference);
    encoder.bytes(&value.bytes);
}

fn decode_installation_data(decoder: &mut Decoder<'_>) -> Result<InstallationData, DecodeError> {
    let reference = decode_blob(decoder)?;
    // Bound the declared frame before allocating its owned representation.
    let bytes = decoder
        .bytes_ref_bounded(MAX_INSTALLATION_DATA_BYTES)?
        .to_vec();
    let value = InstallationData { reference, bytes };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_optional_hash(encoder: &mut Encoder<'_>, value: &Option<Hash>) {
    encoder.option(value, |encoder, value| encoder.fixed(value.as_bytes()));
}

fn decode_optional_hash(decoder: &mut Decoder<'_>) -> Result<Option<Hash>, DecodeError> {
    decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))
}

fn encode_lane(encoder: &mut Encoder<'_>, value: StateLane) {
    encoder.u8(value as u8);
}

fn decode_lane(decoder: &mut Decoder<'_>) -> Result<StateLane, DecodeError> {
    match decoder.u8()? {
        0 => Ok(StateLane::Linear),
        1 => Ok(StateLane::Merge),
        2 => Ok(StateLane::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_method_mode(decoder: &mut Decoder<'_>) -> Result<MethodMode, DecodeError> {
    match decoder.u8()? {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_requirements(encoder: &mut Encoder<'_>, value: RuntimeRequirements) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, value: RuntimeCapabilities) {
    encoder.u8(value.lanes.bits());
    encoder.bool(value.scheduling);
    value.proof_systems.encode_embedded(encoder);
    encoder.u32(value.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    let value = RuntimeCapabilities {
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        scheduling: decoder.bool()?,
        proof_systems: ProofSystemSet::decode_embedded(decoder)?,
        max_actors: decoder.u32()?,
    };
    if value.max_actors == 0 || value.max_actors > STANDARD_MAX_ACTORS {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_actor_contract(encoder: &mut Encoder<'_>, value: ActorPackageContract) {
    encoder.u32(value.actor_abi);
}

fn decode_actor_contract(decoder: &mut Decoder<'_>) -> Result<ActorPackageContract, DecodeError> {
    let value = ActorPackageContract {
        actor_abi: decoder.u32()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_contract(encoder: &mut Encoder<'_>, value: RuntimePackageContract) {
    encoder.fixed(value.lifecycle_abi.as_bytes());
    encoder.u32(value.actor_abis.minimum);
    encoder.u32(value.actor_abis.maximum);
    encoder.fixed(value.control_schema.as_bytes());
    encoder.u32(value.resources.max_runtime_state_bytes);
    encoder.u32(value.resources.max_artifact_references);
    encoder.u64(value.resources.max_artifact_referenced_bytes);
    encoder.u64(value.resources.max_proof_material_bytes);
    encoder.u8(value.migration as u8);
}

fn decode_runtime_contract(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimePackageContract, DecodeError> {
    let value = RuntimePackageContract {
        lifecycle_abi: Hash(decoder.fixed()?),
        actor_abis: ActorAbiRange {
            minimum: decoder.u32()?,
            maximum: decoder.u32()?,
        },
        control_schema: Hash(decoder.fixed()?),
        resources: RuntimeResourceLimits {
            max_runtime_state_bytes: decoder.u32()?,
            max_artifact_references: decoder.u32()?,
            max_artifact_referenced_bytes: decoder.u64()?,
            max_proof_material_bytes: decoder.u64()?,
        },
        migration: match decoder.u8()? {
            0 => RuntimeMigrationPolicy::None,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_resource_policy(encoder: &mut Encoder<'_>, value: RuntimeResourcePolicy) {
    encoder.u32(value.max_actors);
    encoder.u32(value.max_runtime_state_bytes);
    encoder.u32(value.max_artifact_references);
    encoder.u64(value.max_artifact_referenced_bytes);
    encoder.u64(value.max_proof_material_bytes);
}

fn decode_runtime_resource_policy(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimeResourcePolicy, DecodeError> {
    let value = RuntimeResourcePolicy {
        max_actors: decoder.u32()?,
        max_runtime_state_bytes: decoder.u32()?,
        max_artifact_references: decoder.u32()?,
        max_artifact_referenced_bytes: decoder.u64()?,
        max_proof_material_bytes: decoder.u64()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for RuntimeResourcePolicy {
    const MAGIC: [u8; 4] = *b"RRP1";
    const MAX_ENCODED_BYTES: usize = MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.is_valid()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_runtime_resource_policy(encoder, *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_runtime_resource_policy(decoder)
    }
}

fn encode_package_kind(encoder: &mut Encoder<'_>, value: PackageKind) {
    match value {
        PackageKind::Actor {
            contract,
            requirements,
        } => {
            encoder.u8(0);
            encode_actor_contract(encoder, contract);
            encode_requirements(encoder, requirements);
        }
        PackageKind::AgentRuntime {
            contract,
            capabilities,
        } => {
            encoder.u8(1);
            encode_runtime_contract(encoder, contract);
            encode_capabilities(encoder, capabilities);
        }
    }
}

fn decode_package_kind(decoder: &mut Decoder<'_>) -> Result<PackageKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PackageKind::Actor {
            contract: decode_actor_contract(decoder)?,
            requirements: decode_requirements(decoder)?,
        }),
        1 => Ok(PackageKind::AgentRuntime {
            contract: decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for PackageKind {
    const MAGIC: [u8; 4] = *b"APKG";
    const MAX_ENCODED_BYTES: usize = 256;

    fn validate_wire(&self) -> bool {
        match *self {
            Self::Actor { contract, .. } => contract.is_valid(),
            Self::AgentRuntime {
                contract,
                capabilities,
            } => {
                contract.is_valid()
                    && capabilities.max_actors != 0
                    && capabilities.max_actors <= STANDARD_MAX_ACTORS
            }
        }
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_package_kind(encoder, *self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_package_kind(decoder)
    }
}

fn encode_agent_identity(encoder: &mut Encoder<'_>, value: &AgentIdentity) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.owner.as_bytes());
    encoder.u8(value.profile as u8);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.runtime_program.as_bytes());
    encoder.fixed(value.runtime_producer.as_bytes());
    encoder.fixed(value.transition_producer.as_bytes());
}

fn decode_agent_identity(decoder: &mut Decoder<'_>) -> Result<AgentIdentity, DecodeError> {
    Ok(AgentIdentity {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_producer: ProducerId(decoder.fixed()?),
        transition_producer: ProducerId(decoder.fixed()?),
    })
}

fn encode_replica(encoder: &mut Encoder<'_>, value: &AgentReplica) {
    encoder.fixed(value.node.as_bytes());
    encoder.fixed(value.principal.as_bytes());
    encoder.u8(value.role as u8);
}

fn decode_replica(decoder: &mut Decoder<'_>) -> Result<AgentReplica, DecodeError> {
    Ok(AgentReplica {
        node: NodeId(decoder.fixed()?),
        principal: PrincipalId(decoder.fixed()?),
        role: match decoder.u8()? {
            0 => ReplicaRole::Voter,
            1 => ReplicaRole::Observer,
            _ => return Err(DecodeError::InvalidTag),
        },
    })
}

fn encode_agent_authority_binding(encoder: &mut Encoder<'_>, value: AgentAuthorityBinding) {
    encoder.fixed(value.policy.as_bytes());
    encode_authority_issuer(encoder, value.issuer);
    encoder.fixed(&value.public_key);
    encoder.u64(value.initial_epoch);
}

fn decode_agent_authority_binding(
    decoder: &mut Decoder<'_>,
) -> Result<AgentAuthorityBinding, DecodeError> {
    let value = AgentAuthorityBinding {
        policy: Hash(decoder.fixed()?),
        issuer: decode_authority_issuer(decoder)?,
        public_key: decoder.fixed()?,
        initial_epoch: decoder.u64()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_private_recovery_binding(encoder: &mut Encoder<'_>, value: &PrivateRecoveryBinding) {
    encoder.fixed(value.signing_key_commitment.as_bytes());
    encoder.fixed(&value.encryption_public_key);
}

fn decode_private_recovery_binding(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateRecoveryBinding, DecodeError> {
    let value = PrivateRecoveryBinding {
        signing_key_commitment: Hash(decoder.fixed()?),
        encryption_public_key: decoder.fixed()?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_agent_descriptor(encoder: &mut Encoder<'_>, value: &AgentDescriptor) {
    encode_agent_identity(encoder, &value.identity);
    encoder.fixed(value.creation_nonce.as_bytes());
    encode_agent_authority_binding(encoder, value.authority);
    encoder.option(&value.private_recovery, encode_private_recovery_binding);
    encode_blob(encoder, &value.runtime_package);
    encode_runtime_contract(encoder, value.runtime_contract);
    encode_capabilities(encoder, value.capabilities);
    encoder.list(&value.replicas, encode_replica);
}

pub(crate) fn agent_descriptor_commitment(value: &AgentDescriptor) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ADC1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_agent_descriptor(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/descriptor/v1", &[&bytes])
}

fn decode_agent_descriptor(decoder: &mut Decoder<'_>) -> Result<AgentDescriptor, DecodeError> {
    let value = AgentDescriptor {
        identity: decode_agent_identity(decoder)?,
        creation_nonce: Hash(decoder.fixed()?),
        authority: decode_agent_authority_binding(decoder)?,
        private_recovery: decoder.option(decode_private_recovery_binding)?,
        runtime_package: decode_blob(decoder)?,
        runtime_contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
        replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_replica)?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for AgentDescriptor {
    const MAGIC: [u8; 4] = *b"AADS";
    const MAX_ENCODED_BYTES: usize = MAX_AGENT_DESCRIPTOR_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_agent_descriptor(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_agent_descriptor(decoder)
    }
}

fn encode_compact_replica_slot(encoder: &mut Encoder<'_>, value: &CompactReplicaSlot) {
    encoder.fixed(value.node.as_bytes());
    encoder.u8(value.role as u8);
}

fn decode_compact_replica_slot(
    decoder: &mut Decoder<'_>,
) -> Result<CompactReplicaSlot, DecodeError> {
    let value = CompactReplicaSlot {
        node: NodeId(decoder.fixed()?),
        role: match decoder.u8()? {
            0 => ReplicaRole::Voter,
            1 => ReplicaRole::Observer,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_compact_agent_descriptor(encoder: &mut Encoder<'_>, value: &CompactAgentDescriptor) {
    encode_agent_identity(encoder, &value.identity);
    encoder.fixed(value.creation_nonce.as_bytes());
    encode_agent_authority_binding(encoder, value.authority);
    encoder.option(&value.private_recovery, encode_private_recovery_binding);
    encode_blob(encoder, &value.runtime_package);
    encode_runtime_contract(encoder, value.runtime_contract);
    encode_capabilities(encoder, value.capabilities);
}

fn decode_compact_agent_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<CompactAgentDescriptor, DecodeError> {
    Ok(CompactAgentDescriptor {
        identity: decode_agent_identity(decoder)?,
        creation_nonce: Hash(decoder.fixed()?),
        authority: decode_agent_authority_binding(decoder)?,
        private_recovery: decoder.option(decode_private_recovery_binding)?,
        runtime_package: decode_blob(decoder)?,
        runtime_contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
    })
}

fn encode_compact_install_actor(encoder: &mut Encoder<'_>, value: &CompactInstallActor) {
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.producer.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
}

fn decode_compact_install_actor(
    decoder: &mut Decoder<'_>,
) -> Result<CompactInstallActor, DecodeError> {
    let value = CompactInstallActor {
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
        entry: decode_actor_entry(decoder)?,
        producer: ProducerId(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_management_authorization_plan_body(
    encoder: &mut Encoder<'_>,
    value: &ManagementAuthorizationPlan,
) {
    match value {
        ManagementAuthorizationPlan::Create {
            descriptor,
            replicas,
            descriptor_commitment,
        } => {
            encoder.u8(0);
            encode_compact_agent_descriptor(encoder, descriptor);
            encoder.list(replicas, encode_compact_replica_slot);
            encoder.fixed(descriptor_commitment.as_bytes());
        }
        ManagementAuthorizationPlan::Install(value) => {
            encoder.u8(1);
            encode_compact_install_actor(encoder, value);
        }
        ManagementAuthorizationPlan::UpgradeActor(value) => {
            encoder.u8(2);
            encode_upgrade_actor(encoder, value);
        }
        ManagementAuthorizationPlan::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(3);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementAuthorizationPlan::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(4);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementAuthorizationPlan::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementAuthorizationPlan::UpgradeRuntime(value) => {
            encoder.u8(6);
            encode_runtime_upgrade(encoder, value);
        }
        ManagementAuthorizationPlan::ChangeReplicas {
            expected_generation,
            replicas,
            replica_roster_commitment,
        } => {
            encoder.u8(7);
            encoder.fixed(expected_generation.as_bytes());
            encoder.list(replicas, encode_compact_replica_slot);
            encoder.fixed(replica_roster_commitment.as_bytes());
        }
    }
}

fn decode_management_authorization_plan_body(
    decoder: &mut Decoder<'_>,
) -> Result<ManagementAuthorizationPlan, DecodeError> {
    let value = match decoder.u8()? {
        0 => ManagementAuthorizationPlan::Create {
            descriptor: alloc::boxed::Box::new(decode_compact_agent_descriptor(decoder)?),
            replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_compact_replica_slot)?,
            descriptor_commitment: Hash(decoder.fixed()?),
        },
        1 => ManagementAuthorizationPlan::Install(alloc::boxed::Box::new(
            decode_compact_install_actor(decoder)?,
        )),
        2 => ManagementAuthorizationPlan::UpgradeActor(alloc::boxed::Box::new(
            decode_upgrade_actor(decoder)?,
        )),
        3 => ManagementAuthorizationPlan::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        4 => ManagementAuthorizationPlan::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        5 => ManagementAuthorizationPlan::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        6 => ManagementAuthorizationPlan::UpgradeRuntime(alloc::boxed::Box::new(
            decode_runtime_upgrade(decoder)?,
        )),
        7 => ManagementAuthorizationPlan::ChangeReplicas {
            expected_generation: Hash(decoder.fixed()?),
            replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_compact_replica_slot)?,
            replica_roster_commitment: Hash(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ManagementAuthorizationPlan {
    const MAGIC: [u8; 4] = *b"AMP1";
    const MAX_ENCODED_BYTES: usize = MAX_MANAGEMENT_AUTHORIZATION_PLAN_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.is_valid()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_management_authorization_plan_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_management_authorization_plan_body(decoder)
    }
}

pub(crate) fn management_authorization_plan_commitment(
    value: &ManagementAuthorizationPlan,
) -> Hash {
    let Ok(encoded) = value.encode() else {
        return Hash::ZERO;
    };
    Hash::digest(b"vos/agent/management-authorization-plan/v1", &[&encoded])
}

fn encode_actor_entry(encoder: &mut Encoder<'_>, value: &ActorEntry) {
    encoder.fixed(value.actor.as_bytes());
    encoder.string(&value.name);
    encoder.option(&value.parent, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encode_optional_blob(encoder, &value.installation_data);
    encoder.fixed(value.state_layout.as_bytes());
    encoder.u8(value.lanes.bits());
    encoder.bool(value.suspended);
}

fn decode_actor_entry(decoder: &mut Decoder<'_>) -> Result<ActorEntry, DecodeError> {
    let value = ActorEntry {
        actor: ActorId(decoder.fixed()?),
        name: decoder.string_bounded(MAX_ACTOR_NAME_BYTES)?,
        parent: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        installation_data: decode_optional_blob(decoder)?,
        state_layout: Hash(decoder.fixed()?),
        lanes: LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)?,
        suspended: decoder.bool()?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ActorEntry {
    const MAGIC: [u8; 4] = *b"AACT";
    const MAX_ENCODED_BYTES: usize = MAX_ACTOR_ENTRY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_actor_entry(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_actor_entry(decoder)
    }
}

fn encode_directory_record(encoder: &mut Encoder<'_>, value: &ActorDirectoryRecord) {
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
    encoder.fixed(value.install_request.as_bytes());
}

fn decode_directory_record(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryRecord, DecodeError> {
    let value = ActorDirectoryRecord {
        entry: decode_actor_entry(decoder)?,
        incarnation: Hash(decoder.fixed()?),
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
        install_request: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_directory_page(encoder: &mut Encoder<'_>, value: &ActorDirectoryPage) {
    encoder.list(&value.entries, encode_directory_record);
    encoder.option(&value.next, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_directory_page(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryPage, DecodeError> {
    let value = ActorDirectoryPage {
        entries: decoder.list_bounded(MAX_DIRECTORY_PAGE_ENTRIES, decode_directory_record)?,
        next: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ActorDirectoryPage {
    const MAGIC: [u8; 4] = *b"AFST";
    const MAX_ENCODED_BYTES: usize = MAX_DIRECTORY_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_directory_page(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_directory_page(decoder)
    }
}

fn encode_storage_descriptor(encoder: &mut Encoder<'_>, value: &StorageFieldDescriptor) {
    encoder.fixed(value.field.as_bytes());
    encoder.u8(value.kind as u8);
    encoder.bytes(&value.prefix);
    encode_lane(encoder, value.lane);
    encoder.bool(value.committed);
    encoder.fixed(value.key_schema.as_bytes());
    encoder.fixed(value.value_schema.as_bytes());
    encoder.fixed(value.commitment_domain.as_bytes());
}

fn decode_storage_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<StorageFieldDescriptor, DecodeError> {
    let value = StorageFieldDescriptor {
        field: Hash(decoder.fixed()?),
        kind: match decoder.u8()? {
            0 => StorageKind::Value,
            1 => StorageKind::Map,
            2 => StorageKind::Set,
            3 => StorageKind::Vec,
            _ => return Err(DecodeError::InvalidTag),
        },
        prefix: decoder.bytes_bounded(MAX_STORAGE_PREFIX_BYTES)?,
        lane: decode_lane(decoder)?,
        committed: decoder.bool()?,
        key_schema: Hash(decoder.fixed()?),
        value_schema: Hash(decoder.fixed()?),
        commitment_domain: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for StorageFieldDescriptor {
    const MAGIC: [u8; 4] = *b"ASFD";
    const MAX_ENCODED_BYTES: usize = 512;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_storage_descriptor(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_storage_descriptor(decoder)
    }
}

fn encode_authority_operation(encoder: &mut Encoder<'_>, value: AuthorityOperationKind) {
    encoder.u8(value as u8);
}

fn decode_authority_operation(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityOperationKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(AuthorityOperationKind::CreateAgent),
        1 => Ok(AuthorityOperationKind::InstallActor),
        2 => Ok(AuthorityOperationKind::UpgradeActor),
        3 => Ok(AuthorityOperationKind::SuspendActor),
        4 => Ok(AuthorityOperationKind::ResumeActor),
        5 => Ok(AuthorityOperationKind::RemoveActor),
        6 => Ok(AuthorityOperationKind::UpgradeRuntime),
        7 => Ok(AuthorityOperationKind::InvokeActor),
        8 => Ok(AuthorityOperationKind::ChangeReplicaSet),
        9 => Ok(AuthorityOperationKind::InvitePrivateNode),
        10 => Ok(AuthorityOperationKind::RevokePrivateNode),
        11 => Ok(AuthorityOperationKind::RecoverPrivateAgent),
        12 => Ok(AuthorityOperationKind::PublishCatalog),
        13 => Ok(AuthorityOperationKind::RotatePrivateKeys),
        14 => Ok(AuthorityOperationKind::SetPrivateResourcePolicy),
        15 => Ok(AuthorityOperationKind::PrivateActorLifecycle),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_authority_issuer(encoder: &mut Encoder<'_>, value: AuthorityIssuer) {
    encoder.fixed(value.principal.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
}

fn decode_authority_issuer(decoder: &mut Decoder<'_>) -> Result<AuthorityIssuer, DecodeError> {
    Ok(AuthorityIssuer {
        principal: PrincipalId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
    })
}

fn encode_lane_roots(encoder: &mut Encoder<'_>, value: AuthorityLaneRoots) {
    encode_optional_hash(encoder, &value.control);
    encode_optional_hash(encoder, &value.linear);
    encode_optional_hash(encoder, &value.merge);
    encode_optional_hash(encoder, &value.local);
}

fn decode_lane_roots(decoder: &mut Decoder<'_>) -> Result<AuthorityLaneRoots, DecodeError> {
    Ok(AuthorityLaneRoots {
        control: decode_optional_hash(decoder)?,
        linear: decode_optional_hash(decoder)?,
        merge: decode_optional_hash(decoder)?,
        local: decode_optional_hash(decoder)?,
    })
}

pub(crate) fn encode_authority_selector(
    encoder: &mut Encoder<'_>,
    value: &AuthorityReceiptSelector,
) {
    encoder.fixed(value.policy.as_bytes());
    encode_authority_issuer(encoder, value.issuer);
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encode_authority_operation(encoder, value.operation);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor_deployment, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encode_optional_blob(encoder, &value.evidence.package);
    encode_optional_blob(encoder, &value.evidence.proof);
    encoder.fixed(value.evidence.commitment.as_bytes());
    encode_lane_roots(encoder, value.lane_roots);
    encoder.u64(value.epoch);
    encoder.u64(value.decision_sequence);
    encoder.u64(value.acknowledged_through);
    encoder.u64(value.valid_from);
    encoder.u64(value.expires_at);
    encoder.fixed(value.request.as_bytes());
}

pub(crate) fn decode_authority_selector(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityReceiptSelector, DecodeError> {
    let value = AuthorityReceiptSelector {
        policy: Hash(decoder.fixed()?),
        issuer: decode_authority_issuer(decoder)?,
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        operation: decode_authority_operation(decoder)?,
        runtime_deployment: DeploymentId(decoder.fixed()?),
        actor: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        actor_deployment: decoder.option(|decoder| Ok(DeploymentId(decoder.fixed()?)))?,
        evidence: AuthorityEvidence {
            package: decode_optional_blob(decoder)?,
            proof: decode_optional_blob(decoder)?,
            commitment: Hash(decoder.fixed()?),
        },
        lane_roots: decode_lane_roots(decoder)?,
        epoch: decoder.u64()?,
        decision_sequence: decoder.u64()?,
        acknowledged_through: decoder.u64()?,
        valid_from: decoder.u64()?,
        expires_at: decoder.u64()?,
        request: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_signing_bytes(value: &AuthorityReceipt) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AUSG");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encode_authority_selector(&mut encoder, &value.selector);
    encoder.0.extend_from_slice(&value.public_key);
    bytes
}

pub(crate) fn encode_authority_receipt_body(encoder: &mut Encoder<'_>, value: &AuthorityReceipt) {
    encode_authority_selector(encoder, &value.selector);
    encoder.0.extend_from_slice(&value.public_key);
    encoder.0.extend_from_slice(&value.signature);
}

pub(crate) fn decode_authority_receipt_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityReceipt, DecodeError> {
    let value = AuthorityReceipt {
        selector: decode_authority_selector(decoder)?,
        public_key: decoder
            .take(AUTHORITY_PUBLIC_KEY_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        signature: decoder
            .take(AUTHORITY_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for AuthorityReceipt {
    const MAGIC: [u8; 4] = *b"AURC";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_RECEIPT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_receipt_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_receipt_body(decoder)
    }
}

pub(crate) fn encode_authority_actor_target(
    encoder: &mut Encoder<'_>,
    value: AuthorityActorTarget,
) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.system_agent.as_bytes());
    encoder.fixed(value.system_runtime_deployment.as_bytes());
    encode_agent_authority_binding(encoder, value.binding);
}

pub(crate) fn decode_authority_actor_target(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityActorTarget, DecodeError> {
    let value = AuthorityActorTarget {
        space: SpaceId(decoder.fixed()?),
        system_agent: AgentId(decoder.fixed()?),
        system_runtime_deployment: DeploymentId(decoder.fixed()?),
        binding: decode_agent_authority_binding(decoder)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_managed_agent_target(encoder: &mut Encoder<'_>, value: ManagedAgentTarget) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.owner.as_bytes());
    encoder.u8(value.profile as u8);
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.transition_producer.as_bytes());
}

fn decode_managed_agent_target(
    decoder: &mut Decoder<'_>,
) -> Result<ManagedAgentTarget, DecodeError> {
    let value = ManagedAgentTarget {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        profile: match decoder.u8()? {
            0 => AgentProfile::Local,
            1 => AgentProfile::Shared,
            2 => AgentProfile::Private,
            _ => return Err(DecodeError::InvalidTag),
        },
        runtime_deployment: DeploymentId(decoder.fixed()?),
        transition_producer: ProducerId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_credential_caller(
    encoder: &mut Encoder<'_>,
    principal: PrincipalId,
    credential: CredentialId,
    public_key: &[u8; CREDENTIAL_PUBLIC_KEY_BYTES],
    authenticated_node: Option<NodeId>,
) {
    encoder.fixed(principal.as_bytes());
    encoder.fixed(credential.as_bytes());
    encoder.0.extend_from_slice(public_key);
    encoder.option(&authenticated_node, |encoder, node| {
        encoder.fixed(node.as_bytes())
    });
}

pub(crate) fn decode_credential_caller(
    decoder: &mut Decoder<'_>,
) -> Result<
    (
        PrincipalId,
        CredentialId,
        [u8; CREDENTIAL_PUBLIC_KEY_BYTES],
        Option<NodeId>,
    ),
    DecodeError,
> {
    Ok((
        PrincipalId(decoder.fixed()?),
        CredentialId(decoder.fixed()?),
        decoder
            .take(CREDENTIAL_PUBLIC_KEY_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
    ))
}

fn encode_canonical_management_request(value: &ManagementRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AMRQ");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_request(&mut Encoder(&mut bytes), value);
    bytes
}

fn encode_canonical_management_authorization_plan(value: &ManagementAuthorizationPlan) -> Vec<u8> {
    value
        .encode()
        .expect("validated management authorization plan has a canonical encoding")
}

fn decode_canonical_management_authorization_plan(
    bytes: &[u8],
) -> Result<ManagementAuthorizationPlan, DecodeError> {
    ManagementAuthorizationPlan::decode(bytes).map_err(|error| match error {
        WireError::LimitExceeded => DecodeError::LimitExceeded,
        WireError::InvalidValue => DecodeError::NonCanonical,
        WireError::Decode(error) => error,
    })
}

fn encode_authority_credential_call_unsigned(
    encoder: &mut Encoder<'_>,
    value: &AuthorityCredentialCall,
) {
    encoder.fixed(value.invocation.as_bytes());
    encode_authority_credential_call_invocation_payload(encoder, value);
}

fn encode_authority_credential_call_invocation_payload(
    encoder: &mut Encoder<'_>,
    value: &AuthorityCredentialCall,
) {
    encode_authority_actor_target(encoder, value.authority);
    encode_managed_agent_target(encoder, value.managed);
    encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encoder.u64(value.request_sequence.get());
    encoder.u64(value.requested_valid_from);
    encoder.u64(value.requested_expires_at);
    encoder.bytes(&encode_canonical_management_authorization_plan(&value.plan));
}

pub(crate) fn authority_credential_call_invocation_payload_commitment(
    value: &AuthorityCredentialCall,
) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ACP3");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_credential_call_invocation_payload(&mut Encoder(&mut bytes), value);
    Hash::digest(
        b"vos/agent/authority-management-invocation-payload/v3",
        &[&bytes],
    )
}

pub(crate) fn authority_credential_call_signing_bytes(value: &AuthorityCredentialCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AC3S");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_credential_call_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn authority_credential_call_encoded_len(value: &AuthorityCredentialCall) -> usize {
    let mut body = Vec::new();
    encode_authority_credential_call_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(CREDENTIAL_SIGNATURE_BYTES)
}

impl CanonicalWire for AuthorityCredentialCall {
    const MAGIC: [u8; 4] = *b"ACC3";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_credential_call_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation = InvocationId(decoder.fixed()?);
        let authority = decode_authority_actor_target(decoder)?;
        let managed = decode_managed_agent_target(decoder)?;
        let (principal, credential, credential_public_key, authenticated_node) =
            decode_credential_caller(decoder)?;
        let request_sequence =
            core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
        let requested_valid_from = decoder.u64()?;
        let requested_expires_at = decoder.u64()?;
        let plan = decode_canonical_management_authorization_plan(
            decoder.bytes_ref_bounded(MAX_INVOCATION_MESSAGE_BYTES)?,
        )?;
        let signature = decoder
            .take(CREDENTIAL_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let value = Self {
            invocation,
            authority,
            managed,
            principal,
            credential,
            request_sequence,
            credential_public_key,
            authenticated_node,
            requested_valid_from,
            requested_expires_at,
            plan,
            signature,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_authority_credential_enrollment(
    encoder: &mut Encoder<'_>,
    value: AuthorityCredentialEnrollment,
) {
    encoder.fixed(value.credential.as_bytes());
    encoder.u8(value.kind as u8);
    encoder.0.extend_from_slice(&value.public_key);
}

fn decode_authority_credential_enrollment(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityCredentialEnrollment, DecodeError> {
    let value = AuthorityCredentialEnrollment {
        credential: CredentialId(decoder.fixed()?),
        kind: match decoder.u8()? {
            0 => AuthorityCredentialKind::Ssh,
            1 => AuthorityCredentialKind::Api,
            _ => return Err(DecodeError::InvalidTag),
        },
        public_key: decoder
            .take(CREDENTIAL_PUBLIC_KEY_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_authority_admin_operation(encoder: &mut Encoder<'_>, value: &AuthorityAdminOperation) {
    match value {
        AuthorityAdminOperation::EnrollPrincipal {
            principal,
            credential,
        } => {
            encoder.u8(0);
            encoder.fixed(principal.as_bytes());
            encode_authority_credential_enrollment(encoder, *credential);
        }
        AuthorityAdminOperation::AddCredential {
            principal,
            credential,
        } => {
            encoder.u8(1);
            encoder.fixed(principal.as_bytes());
            encode_authority_credential_enrollment(encoder, *credential);
        }
        AuthorityAdminOperation::RevokeCredential {
            principal,
            credential,
        } => {
            encoder.u8(2);
            encoder.fixed(principal.as_bytes());
            encoder.fixed(credential.as_bytes());
        }
        AuthorityAdminOperation::EnrollNode { enrollment } => {
            encoder.u8(3);
            encoder.bytes(&encode_node_encryption_enrollment_wire(enrollment));
        }
        AuthorityAdminOperation::UnbindNodeOwner { node, owner } => {
            encoder.u8(4);
            encoder.fixed(node.as_bytes());
            encoder.fixed(owner.as_bytes());
        }
        AuthorityAdminOperation::SetBuiltinRole { principal, role } => {
            encoder.u8(5);
            encoder.fixed(principal.as_bytes());
            encoder.u8(*role as u8);
        }
        AuthorityAdminOperation::SetSpaceRole {
            principal,
            role,
            granted,
        } => {
            encoder.u8(6);
            encoder.fixed(principal.as_bytes());
            encoder.fixed(role.as_bytes());
            encoder.bool(*granted);
        }
        AuthorityAdminOperation::SetActorRole {
            principal,
            agent,
            actor,
            deployment,
            role,
            granted,
        } => {
            encoder.u8(7);
            encoder.fixed(principal.as_bytes());
            encoder.fixed(agent.as_bytes());
            encoder.fixed(actor.as_bytes());
            encoder.fixed(deployment.as_bytes());
            encoder.fixed(role.as_bytes());
            encoder.bool(*granted);
        }
        AuthorityAdminOperation::SetCapability {
            principal,
            agent,
            actor,
            deployment,
            capability,
            granted,
        } => {
            encoder.u8(8);
            encoder.fixed(principal.as_bytes());
            encoder.fixed(agent.as_bytes());
            encoder.fixed(actor.as_bytes());
            encoder.fixed(deployment.as_bytes());
            encoder.fixed(capability.as_bytes());
            encoder.bool(*granted);
        }
    }
}

fn decode_authority_admin_operation(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityAdminOperation, DecodeError> {
    let value = match decoder.u8()? {
        0 => AuthorityAdminOperation::EnrollPrincipal {
            principal: PrincipalId(decoder.fixed()?),
            credential: decode_authority_credential_enrollment(decoder)?,
        },
        1 => AuthorityAdminOperation::AddCredential {
            principal: PrincipalId(decoder.fixed()?),
            credential: decode_authority_credential_enrollment(decoder)?,
        },
        2 => AuthorityAdminOperation::RevokeCredential {
            principal: PrincipalId(decoder.fixed()?),
            credential: CredentialId(decoder.fixed()?),
        },
        3 => AuthorityAdminOperation::EnrollNode {
            enrollment: NodeEncryptionEnrollment::decode(
                decoder.bytes_ref_bounded(MAX_NODE_ENCRYPTION_ENROLLMENT_WIRE_BYTES)?,
            )
            .map_err(|_| DecodeError::NonCanonical)?,
        },
        4 => AuthorityAdminOperation::UnbindNodeOwner {
            node: NodeId(decoder.fixed()?),
            owner: PrincipalId(decoder.fixed()?),
        },
        5 => AuthorityAdminOperation::SetBuiltinRole {
            principal: PrincipalId(decoder.fixed()?),
            role: match decoder.u8()? {
                0 => AuthorityBuiltinRole::Member,
                1 => AuthorityBuiltinRole::Developer,
                2 => AuthorityBuiltinRole::Admin,
                _ => return Err(DecodeError::InvalidTag),
            },
        },
        6 => AuthorityAdminOperation::SetSpaceRole {
            principal: PrincipalId(decoder.fixed()?),
            role: RoleId(decoder.fixed()?),
            granted: decoder.bool()?,
        },
        7 => AuthorityAdminOperation::SetActorRole {
            principal: PrincipalId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            deployment: DeploymentId(decoder.fixed()?),
            role: RoleId(decoder.fixed()?),
            granted: decoder.bool()?,
        },
        8 => AuthorityAdminOperation::SetCapability {
            principal: PrincipalId(decoder.fixed()?),
            agent: AgentId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            deployment: DeploymentId(decoder.fixed()?),
            capability: CapabilityId(decoder.fixed()?),
            granted: decoder.bool()?,
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate_shape()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_admin_operation_commitment(value: &AuthorityAdminOperation) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AAO3");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_admin_operation(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-admin-operation/v3", &[&bytes])
}

fn encode_authority_admin_call_unsigned(encoder: &mut Encoder<'_>, value: &AuthorityAdminCall) {
    encoder.fixed(value.invocation.as_bytes());
    encode_authority_admin_call_invocation_payload(encoder, value);
}

fn encode_authority_admin_call_invocation_payload(
    encoder: &mut Encoder<'_>,
    value: &AuthorityAdminCall,
) {
    encode_authority_actor_target(encoder, value.authority);
    encoder.fixed(value.administrator.as_bytes());
    encoder.fixed(value.credential.as_bytes());
    encoder.u64(value.request_sequence.get());
    encoder.0.extend_from_slice(&value.credential_public_key);
    encoder.fixed(value.authenticated_node.as_bytes());
    encoder.u64(value.observed_slot);
    encoder.u64(value.expected_generation.get());
    encode_authority_admin_operation(encoder, &value.operation);
}

pub(crate) fn authority_admin_call_invocation_payload_commitment(
    value: &AuthorityAdminCall,
) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AIP4");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_admin_call_invocation_payload(&mut Encoder(&mut bytes), value);
    Hash::digest(
        b"vos/agent/authority-admin-invocation-payload/v4",
        &[&bytes],
    )
}

pub(crate) fn authority_admin_call_signing_bytes(value: &AuthorityAdminCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AA4S");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_admin_call_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn authority_admin_call_encoded_len(value: &AuthorityAdminCall) -> usize {
    let mut body = Vec::new();
    encode_authority_admin_call_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(CREDENTIAL_SIGNATURE_BYTES)
}

fn encode_authority_admin_call_body(encoder: &mut Encoder<'_>, value: &AuthorityAdminCall) {
    encode_authority_admin_call_unsigned(encoder, value);
    encoder.0.extend_from_slice(&value.signature);
}

fn decode_authority_admin_call_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityAdminCall, DecodeError> {
    let value = AuthorityAdminCall {
        invocation: InvocationId(decoder.fixed()?),
        authority: decode_authority_actor_target(decoder)?,
        administrator: PrincipalId(decoder.fixed()?),
        credential: CredentialId(decoder.fixed()?),
        request_sequence: core::num::NonZeroU64::new(decoder.u64()?)
            .ok_or(DecodeError::NonCanonical)?,
        credential_public_key: decoder
            .take(CREDENTIAL_PUBLIC_KEY_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        authenticated_node: NodeId(decoder.fixed()?),
        observed_slot: decoder.u64()?,
        expected_generation: core::num::NonZeroU64::new(decoder.u64()?)
            .ok_or(DecodeError::NonCanonical)?,
        operation: decode_authority_admin_operation(decoder)?,
        signature: decoder
            .take(CREDENTIAL_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for AuthorityAdminCall {
    const MAGIC: [u8; 4] = *b"AAD4";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_ADMIN_CALL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_admin_call_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_admin_call_body(decoder)
    }
}

fn encode_authority_admin_result_body(encoder: &mut Encoder<'_>, value: &AuthorityAdminResult) {
    encode_authority_admin_call_body(encoder, &value.call);
    encoder.u64(value.generation.get());
}

pub(crate) fn authority_admin_result_encoded_len(value: &AuthorityAdminResult) -> usize {
    let mut body = Vec::new();
    encode_authority_admin_result_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

pub(crate) fn authority_admin_result_commitment(value: &AuthorityAdminResult) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AAR4");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_admin_result_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-admin-result/v4", &[&bytes])
}

impl CanonicalWire for AuthorityAdminResult {
    const MAGIC: [u8; 4] = *b"AAR4";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_ADMIN_RESULT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_admin_result_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call: decode_authority_admin_call_body(decoder)?,
            generation: core::num::NonZeroU64::new(decoder.u64()?)
                .ok_or(DecodeError::NonCanonical)?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_authority_projection_selector(
    encoder: &mut Encoder<'_>,
    value: AuthorityProjectionSelector,
) {
    match value {
        AuthorityProjectionSelector::Inventory {
            after,
            limit,
            known_head,
        } => {
            encoder.u8(4);
            encoder.option(&after, |encoder, cursor| {
                encode_inventory_cursor(encoder, *cursor)
            });
            encoder.u16(limit);
            encoder.option(&known_head, |encoder, head| {
                encode_authority_projection_head(encoder, *head)
            });
        }
        AuthorityProjectionSelector::Credential => encoder.u8(0),
        AuthorityProjectionSelector::Agents { after, limit } => {
            encoder.u8(1);
            encoder.option(&after, |encoder, value| encoder.fixed(value.as_bytes()));
            encoder.u16(limit);
        }
        AuthorityProjectionSelector::AgentReplicas {
            agent,
            after,
            limit,
        } => {
            encoder.u8(2);
            encoder.fixed(agent.as_bytes());
            encoder.option(&after, |encoder, value| encoder.fixed(value.as_bytes()));
            encoder.u16(limit);
        }
        AuthorityProjectionSelector::Actors {
            agent,
            after,
            limit,
        } => {
            encoder.u8(3);
            encoder.fixed(agent.as_bytes());
            encoder.option(&after, |encoder, value| encoder.fixed(value.as_bytes()));
            encoder.u16(limit);
        }
    }
}

fn decode_authority_projection_selector(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityProjectionSelector, DecodeError> {
    let value = match decoder.u8()? {
        0 => AuthorityProjectionSelector::Credential,
        4 => AuthorityProjectionSelector::Inventory {
            after: decoder.option(decode_inventory_cursor)?,
            limit: decoder.u16()?,
            known_head: decoder.option(decode_authority_projection_head)?,
        },
        1 => AuthorityProjectionSelector::Agents {
            after: decoder.option(|decoder| Ok(AgentId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        },
        2 => AuthorityProjectionSelector::AgentReplicas {
            agent: AgentId(decoder.fixed()?),
            after: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        },
        3 => AuthorityProjectionSelector::Actors {
            agent: AgentId(decoder.fixed()?),
            after: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate_shape()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_inventory_cursor(encoder: &mut Encoder<'_>, value: AuthorityInventoryCursor) {
    encoder.fixed(value.agent.as_bytes());
    match value.position {
        AuthorityInventoryPosition::Agent => encoder.u8(0),
        AuthorityInventoryPosition::Replica(node) => {
            encoder.u8(1);
            encoder.fixed(node.as_bytes());
        }
        AuthorityInventoryPosition::Actor(actor) => {
            encoder.u8(2);
            encoder.fixed(actor.as_bytes());
        }
    }
}

fn decode_inventory_cursor(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityInventoryCursor, DecodeError> {
    let agent = AgentId(decoder.fixed()?);
    let position = match decoder.u8()? {
        0 => AuthorityInventoryPosition::Agent,
        1 => AuthorityInventoryPosition::Replica(NodeId(decoder.fixed()?)),
        2 => AuthorityInventoryPosition::Actor(ActorId(decoder.fixed()?)),
        _ => return Err(DecodeError::InvalidTag),
    };
    let cursor = AuthorityInventoryCursor { agent, position };
    cursor
        .is_valid()
        .then_some(cursor)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_inventory_entry(encoder: &mut Encoder<'_>, value: &AuthorityInventoryEntry) {
    match value {
        AuthorityInventoryEntry::Agent(row) => {
            encoder.u8(0);
            encode_authority_agent_projection(encoder, row);
        }
        AuthorityInventoryEntry::Replica { agent, replica } => {
            encoder.u8(1);
            encoder.fixed(agent.as_bytes());
            encode_replica(encoder, replica);
        }
        AuthorityInventoryEntry::Actor(row) => {
            encoder.u8(2);
            encode_authority_actor_projection(encoder, row);
        }
    }
}

fn decode_inventory_entry(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityInventoryEntry, DecodeError> {
    match decoder.u8()? {
        0 => Ok(AuthorityInventoryEntry::Agent(
            decode_authority_agent_projection(decoder)?,
        )),
        1 => Ok(AuthorityInventoryEntry::Replica {
            agent: AgentId(decoder.fixed()?),
            replica: decode_replica(decoder)?,
        }),
        2 => Ok(AuthorityInventoryEntry::Actor(
            decode_authority_actor_projection(decoder)?,
        )),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_inventory_page_body(encoder: &mut Encoder<'_>, value: &AuthorityInventoryProjectionPage) {
    encode_authority_credential_projection_body(encoder, &value.credential);
    encoder.bool(value.unchanged);
    encoder.list(&value.entries, encode_inventory_entry);
    encoder.option(&value.next, |encoder, cursor| {
        encode_inventory_cursor(encoder, *cursor)
    });
}

pub(crate) fn authority_inventory_projection_page_encoded_len(
    value: &AuthorityInventoryProjectionPage,
) -> usize {
    let mut body = Vec::new();
    encode_inventory_page_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityInventoryProjectionPage {
    const MAGIC: [u8; 4] = *b"AIP1";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_inventory_page_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let page = Self {
            credential: decode_authority_credential_projection_body(decoder)?,
            unchanged: decoder.bool()?,
            entries: decoder
                .list_bounded(MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES, decode_inventory_entry)?,
            next: decoder.option(decode_inventory_cursor)?,
        };
        page.validate_shape()
            .is_ok()
            .then_some(page)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_authority_projection_query_unsigned(
    encoder: &mut Encoder<'_>,
    value: &AuthorityProjectionQuery,
) {
    encode_authority_actor_target(encoder, value.authority);
    encoder.fixed(value.credential.as_bytes());
    encoder.fixed(value.nonce.as_bytes());
    encode_authority_projection_selector(encoder, value.selector);
    encode_projection_authentication_unsigned(encoder, value);
}

// Query-only extension: tags 0/1 retain the exact APQ1 legacy encoding; tags
// 2/3 add signed recovery scope. Never teach the shared AOC5 authenticator to
// accept these tags. Old Authority guests reject delegated queries explicitly.
fn encode_projection_authentication_unsigned(
    encoder: &mut Encoder<'_>,
    value: &AuthorityProjectionQuery,
) {
    let start = encoder.0.len();
    encode_authority_ingress_authentication_unsigned(encoder, value.authentication);
    if let Some(recovery) = value.recovery {
        encoder.0[start] += 2;
        encoder.fixed(recovery.generation.as_bytes());
        encoder.fixed(recovery.committee.as_bytes());
        encoder.u64(recovery.accepted_slot);
        encoder.u64(recovery.expires_at);
    }
}

pub(crate) fn encode_authority_ingress_authentication_unsigned(
    encoder: &mut Encoder<'_>,
    value: AuthorityIngressAuthentication,
) {
    match value {
        AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key,
            ..
        } => {
            encoder.u8(0);
            encoder.0.extend_from_slice(&credential_public_key);
        }
        AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key,
            node,
            request_binding,
            ..
        } => {
            encoder.u8(1);
            encoder.0.extend_from_slice(&credential_public_key);
            encoder.fixed(node.as_bytes());
            encoder.fixed(request_binding.as_bytes());
        }
    }
}

pub(crate) fn encode_authority_ingress_authentication(
    encoder: &mut Encoder<'_>,
    value: AuthorityIngressAuthentication,
) {
    encode_authority_ingress_authentication_unsigned(encoder, value);
    encoder.0.extend_from_slice(&value.signature());
}

pub(crate) fn decode_authority_ingress_authentication(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityIngressAuthentication, DecodeError> {
    let tag = decoder.u8()?;
    let authentication = decode_authority_ingress_authentication_unsigned(decoder, tag)?;
    decode_ingress_signature(decoder, authentication)
}

fn decode_authority_ingress_authentication_unsigned(
    decoder: &mut Decoder<'_>,
    tag: u8,
) -> Result<AuthorityIngressAuthentication, DecodeError> {
    let authentication = match tag {
        0 => AuthorityIngressAuthentication::ApiCredentialSignature {
            credential_public_key: decoder
                .take(CREDENTIAL_PUBLIC_KEY_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            signature: [0; CREDENTIAL_SIGNATURE_BYTES],
        },
        1 => AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: decoder
                .take(CREDENTIAL_PUBLIC_KEY_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            node: NodeId(decoder.fixed()?),
            request_binding: Hash(decoder.fixed()?),
            signature: [0; CREDENTIAL_SIGNATURE_BYTES],
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    Ok(authentication)
}

fn decode_ingress_signature(
    decoder: &mut Decoder<'_>,
    mut authentication: AuthorityIngressAuthentication,
) -> Result<AuthorityIngressAuthentication, DecodeError> {
    let signature = decoder
        .take(CREDENTIAL_SIGNATURE_BYTES)?
        .try_into()
        .map_err(|_| DecodeError::Truncated)?;
    match &mut authentication {
        AuthorityIngressAuthentication::ApiCredentialSignature {
            signature: field, ..
        }
        | AuthorityIngressAuthentication::SshNodeAttestation {
            signature: field, ..
        } => {
            *field = signature;
        }
    }
    Ok(authentication)
}

pub(crate) fn authority_projection_query_signing_bytes(
    value: &AuthorityProjectionQuery,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(if value.recovery.is_some() {
        b"APQD"
    } else {
        b"APQS"
    });
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_authority_projection_query_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

fn encode_authority_projection_query_body(
    encoder: &mut Encoder<'_>,
    value: &AuthorityProjectionQuery,
) {
    encode_authority_projection_query_unsigned(encoder, value);
    encoder
        .0
        .extend_from_slice(&value.authentication.signature());
}

fn decode_authority_projection_query_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityProjectionQuery, DecodeError> {
    let authority = decode_authority_actor_target(decoder)?;
    let credential = CredentialId(decoder.fixed()?);
    let nonce = Hash(decoder.fixed()?);
    let selector = decode_authority_projection_selector(decoder)?;
    let tag = decoder.u8()?;
    if tag > 3 {
        return Err(DecodeError::InvalidTag);
    }
    let authentication = decode_authority_ingress_authentication_unsigned(decoder, tag % 2)?;
    let recovery = if tag >= 2 {
        Some(AuthorityProjectionRecoveryDelegation {
            generation: Hash(decoder.fixed()?),
            committee: Hash(decoder.fixed()?),
            accepted_slot: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    } else {
        None
    };
    let value = AuthorityProjectionQuery {
        authority,
        credential,
        nonce,
        selector,
        authentication: decode_ingress_signature(decoder, authentication)?,
        recovery,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_projection_query_encoded_len(value: &AuthorityProjectionQuery) -> usize {
    let mut body = Vec::new();
    encode_authority_projection_query_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityProjectionQuery {
    const MAGIC: [u8; 4] = *b"APQ1";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_projection_query_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_projection_query_body(decoder)
    }
}

fn encode_authority_projection_head(encoder: &mut Encoder<'_>, value: AuthorityProjectionHead) {
    encoder.u64(value.state_revision.get());
    encoder.u64(value.epoch.get());
    encoder.u64(value.authorization_sequence.get());
    encoder.u64(value.administration_generation.get());
    encoder.fixed(value.state_commitment.as_bytes());
}

fn decode_authority_projection_head(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityProjectionHead, DecodeError> {
    let value = AuthorityProjectionHead {
        state_revision: core::num::NonZeroU64::new(decoder.u64()?)
            .ok_or(DecodeError::NonCanonical)?,
        epoch: core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
        authorization_sequence: core::num::NonZeroU64::new(decoder.u64()?)
            .ok_or(DecodeError::NonCanonical)?,
        administration_generation: core::num::NonZeroU64::new(decoder.u64()?)
            .ok_or(DecodeError::NonCanonical)?,
        state_commitment: Hash(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_actor_role_grant(encoder: &mut Encoder<'_>, value: &AuthorityActorRoleGrant) {
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.role.as_bytes());
}

fn decode_actor_role_grant(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityActorRoleGrant, DecodeError> {
    let value = AuthorityActorRoleGrant {
        agent: AgentId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        role: RoleId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_capability_grant(encoder: &mut Encoder<'_>, value: &AuthorityCapabilityGrant) {
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.capability.as_bytes());
}

fn decode_capability_grant(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityCapabilityGrant, DecodeError> {
    let value = AuthorityCapabilityGrant {
        agent: AgentId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        capability: CapabilityId(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_authority_credential_projection_body(
    encoder: &mut Encoder<'_>,
    value: &AuthorityCredentialProjection,
) {
    encode_authority_projection_query_body(encoder, &value.query);
    encode_authority_projection_head(encoder, value.head);
    encoder.fixed(value.principal.as_bytes());
    encoder.u8(value.status as u8);
    encoder.u8(value.kind as u8);
    encoder.u8(value.builtin_role as u8);
    encoder.u64(value.management_request_high_water);
    encoder.u64(value.operation_request_high_water);
    encoder.u64(value.admin_request_high_water);
    encoder.list(&value.space_roles, |encoder, role| {
        encoder.fixed(role.as_bytes())
    });
    encoder.list(&value.actor_roles, encode_actor_role_grant);
    encoder.list(&value.capabilities, encode_capability_grant);
}

fn decode_authority_credential_projection_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityCredentialProjection, DecodeError> {
    let value = AuthorityCredentialProjection {
        query: decode_authority_projection_query_body(decoder)?,
        head: decode_authority_projection_head(decoder)?,
        principal: PrincipalId(decoder.fixed()?),
        status: match decoder.u8()? {
            0 => AuthorityCredentialStatus::Active,
            1 => AuthorityCredentialStatus::Revoked,
            _ => return Err(DecodeError::InvalidTag),
        },
        kind: match decoder.u8()? {
            0 => AuthorityCredentialKind::Ssh,
            1 => AuthorityCredentialKind::Api,
            _ => return Err(DecodeError::InvalidTag),
        },
        builtin_role: match decoder.u8()? {
            0 => AuthorityBuiltinRole::Member,
            1 => AuthorityBuiltinRole::Developer,
            2 => AuthorityBuiltinRole::Admin,
            _ => return Err(DecodeError::InvalidTag),
        },
        management_request_high_water: decoder.u64()?,
        operation_request_high_water: decoder.u64()?,
        admin_request_high_water: decoder.u64()?,
        space_roles: decoder.list_bounded(MAX_AUTHORITY_PRINCIPAL_GRANTS, |decoder| {
            Ok(RoleId(decoder.fixed()?))
        })?,
        actor_roles: decoder
            .list_bounded(MAX_AUTHORITY_PRINCIPAL_GRANTS, decode_actor_role_grant)?,
        capabilities: decoder
            .list_bounded(MAX_AUTHORITY_PRINCIPAL_GRANTS, decode_capability_grant)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_credential_projection_encoded_len(
    value: &AuthorityCredentialProjection,
) -> usize {
    let mut body = Vec::new();
    encode_authority_credential_projection_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityCredentialProjection {
    const MAGIC: [u8; 4] = *b"ACP2";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_CREDENTIAL_PROJECTION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_credential_projection_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_credential_projection_body(decoder)
    }
}

fn encode_authority_agent_projection(encoder: &mut Encoder<'_>, value: &AuthorityAgentProjection) {
    encode_agent_identity(encoder, &value.identity);
    encoder.fixed(value.creation_nonce.as_bytes());
    encode_agent_authority_binding(encoder, value.authority);
    encoder.option(&value.private_recovery, encode_private_recovery_binding);
    encode_blob(encoder, &value.runtime_package);
    encode_runtime_contract(encoder, value.runtime_contract);
    encode_capabilities(encoder, value.capabilities);
    encoder.u16(value.replica_count);
    encoder.fixed(value.replica_generation.as_bytes());
}

fn decode_authority_agent_projection(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityAgentProjection, DecodeError> {
    let value = AuthorityAgentProjection {
        identity: decode_agent_identity(decoder)?,
        creation_nonce: Hash(decoder.fixed()?),
        authority: decode_agent_authority_binding(decoder)?,
        private_recovery: decoder.option(decode_private_recovery_binding)?,
        runtime_package: decode_blob(decoder)?,
        runtime_contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
        replica_count: decoder.u16()?,
        replica_generation: Hash(decoder.fixed()?),
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_authority_agent_projection_page_body(
    encoder: &mut Encoder<'_>,
    value: &AuthorityAgentProjectionPage,
) {
    encode_authority_projection_query_body(encoder, &value.query);
    encode_authority_projection_head(encoder, value.head);
    encoder.list(&value.entries, encode_authority_agent_projection);
    encoder.option(&value.next, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_authority_agent_projection_page_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityAgentProjectionPage, DecodeError> {
    let value = AuthorityAgentProjectionPage {
        query: decode_authority_projection_query_body(decoder)?,
        head: decode_authority_projection_head(decoder)?,
        entries: decoder.list_bounded(
            MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES,
            decode_authority_agent_projection,
        )?,
        next: decoder.option(|decoder| Ok(AgentId(decoder.fixed()?)))?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_agent_projection_page_encoded_len(
    value: &AuthorityAgentProjectionPage,
) -> usize {
    let mut body = Vec::new();
    encode_authority_agent_projection_page_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityAgentProjectionPage {
    const MAGIC: [u8; 4] = *b"AAP2";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_AGENT_PROJECTION_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_agent_projection_page_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_agent_projection_page_body(decoder)
    }
}

fn encode_authority_agent_replica_projection_page_body(
    encoder: &mut Encoder<'_>,
    value: &AuthorityAgentReplicaProjectionPage,
) {
    encode_authority_projection_query_body(encoder, &value.query);
    encode_authority_projection_head(encoder, value.head);
    encoder.u16(value.replica_count);
    encoder.fixed(value.replica_generation.as_bytes());
    encoder.list(&value.entries, encode_replica);
    encoder.option(&value.next, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_authority_agent_replica_projection_page_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityAgentReplicaProjectionPage, DecodeError> {
    let value = AuthorityAgentReplicaProjectionPage {
        query: decode_authority_projection_query_body(decoder)?,
        head: decode_authority_projection_head(decoder)?,
        replica_count: decoder.u16()?,
        replica_generation: Hash(decoder.fixed()?),
        entries: decoder.list_bounded(MAX_AUTHORITY_REPLICA_PAGE_ENTRIES, decode_replica)?,
        next: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_agent_replica_projection_page_encoded_len(
    value: &AuthorityAgentReplicaProjectionPage,
) -> usize {
    let mut body = Vec::new();
    encode_authority_agent_replica_projection_page_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityAgentReplicaProjectionPage {
    const MAGIC: [u8; 4] = *b"ARP2";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_AGENT_REPLICA_PROJECTION_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_agent_replica_projection_page_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_agent_replica_projection_page_body(decoder)
    }
}

fn encode_authority_actor_projection(encoder: &mut Encoder<'_>, value: &AuthorityActorProjection) {
    encoder.fixed(value.agent.as_bytes());
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.producer.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
    encoder.bool(value.root_provenance);
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
    encoder.fixed(value.install_request.as_bytes());
}

fn decode_authority_actor_projection(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityActorProjection, DecodeError> {
    let value = AuthorityActorProjection {
        agent: AgentId(decoder.fixed()?),
        entry: decode_actor_entry(decoder)?,
        producer: ProducerId(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
        root_provenance: decoder.bool()?,
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
        install_request: Hash(decoder.fixed()?),
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_authority_actor_projection_page_body(
    encoder: &mut Encoder<'_>,
    value: &AuthorityActorProjectionPage,
) {
    encode_authority_projection_query_body(encoder, &value.query);
    encode_authority_projection_head(encoder, value.head);
    encoder.list(&value.entries, encode_authority_actor_projection);
    encoder.option(&value.next, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_authority_actor_projection_page_body(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityActorProjectionPage, DecodeError> {
    let value = AuthorityActorProjectionPage {
        query: decode_authority_projection_query_body(decoder)?,
        head: decode_authority_projection_head(decoder)?,
        entries: decoder.list_bounded(
            MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES,
            decode_authority_actor_projection,
        )?,
        next: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn authority_actor_projection_page_encoded_len(
    value: &AuthorityActorProjectionPage,
) -> usize {
    let mut body = Vec::new();
    encode_authority_actor_projection_page_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

impl CanonicalWire for AuthorityActorProjectionPage {
    const MAGIC: [u8; 4] = *b"ATP2";
    const MAX_ENCODED_BYTES: usize = MAX_AUTHORITY_ACTOR_PROJECTION_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_authority_actor_projection_page_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_authority_actor_projection_page_body(decoder)
    }
}

fn encode_authority_evidence(encoder: &mut Encoder<'_>, value: &AuthorityEvidence) {
    encode_optional_blob(encoder, &value.package);
    encode_optional_blob(encoder, &value.proof);
    encoder.fixed(value.commitment.as_bytes());
}

fn decode_authority_evidence(decoder: &mut Decoder<'_>) -> Result<AuthorityEvidence, DecodeError> {
    let value = AuthorityEvidence {
        package: decode_optional_blob(decoder)?,
        proof: decode_optional_blob(decoder)?,
        commitment: Hash(decoder.fixed()?),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_management_approval_body(encoder: &mut Encoder<'_>, value: &ManagementApproval) {
    encoder.fixed(value.credential_call.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    encoder.fixed(value.acknowledgement_invocation.as_bytes());
    encode_authority_actor_target(encoder, value.authority);
    encode_managed_agent_target(encoder, value.managed);
    encode_credential_caller(
        encoder,
        value.principal,
        value.credential,
        &value.credential_public_key,
        value.authenticated_node,
    );
    encode_authority_evidence(encoder, &value.evidence);
    encode_lane_roots(encoder, value.lane_roots);
    encoder.u64(value.epoch);
    encoder.u64(value.valid_from);
    encoder.u64(value.expires_at);
    encoder.bytes(&encode_canonical_management_authorization_plan(&value.plan));
    encoder.fixed(value.plan_commitment.as_bytes());
}

pub(crate) fn management_approval_encoded_len(value: &ManagementApproval) -> usize {
    let mut body = Vec::new();
    encode_management_approval_body(&mut Encoder(&mut body), value);
    HEADER_BYTES.saturating_add(body.len())
}

pub(crate) fn management_approval_commitment(value: &ManagementApproval) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MPC2");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_approval_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/management-approval/v2", &[&bytes])
}

impl CanonicalWire for ManagementApproval {
    const MAGIC: [u8; 4] = *b"MAP2";
    const MAX_ENCODED_BYTES: usize = MAX_MANAGEMENT_APPROVAL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_management_approval_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let credential_call = Hash(decoder.fixed()?);
        let authorization_sequence =
            core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
        let acknowledgement_invocation = InvocationId(decoder.fixed()?);
        let authority = decode_authority_actor_target(decoder)?;
        let managed = decode_managed_agent_target(decoder)?;
        let (principal, credential, credential_public_key, authenticated_node) =
            decode_credential_caller(decoder)?;
        let evidence = decode_authority_evidence(decoder)?;
        let lane_roots = decode_lane_roots(decoder)?;
        let epoch = decoder.u64()?;
        let valid_from = decoder.u64()?;
        let expires_at = decoder.u64()?;
        let plan = decode_canonical_management_authorization_plan(
            decoder.bytes_ref_bounded(MAX_INVOCATION_REPLY_BYTES)?,
        )?;
        let plan_commitment = Hash(decoder.fixed()?);
        let value = Self {
            credential_call,
            authorization_sequence,
            acknowledgement_invocation,
            authority,
            managed,
            principal,
            credential,
            credential_public_key,
            authenticated_node,
            evidence,
            lane_roots,
            epoch,
            valid_from,
            expires_at,
            plan,
            plan_commitment,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_management_application_ack_unsigned(
    encoder: &mut Encoder<'_>,
    value: &ManagementApplicationAck,
) {
    encoder.fixed(value.authorization_invocation.as_bytes());
    encoder.fixed(value.acknowledgement_invocation.as_bytes());
    encode_authority_actor_target(encoder, value.authority);
    encode_managed_agent_target(encoder, value.managed);
    encoder.fixed(value.credential_call.as_bytes());
    encoder.fixed(value.approval.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    encoder.fixed(value.request.as_bytes());
    encode_authority_receipt_body(encoder, &value.receipt);
    encode_management_reply(encoder, &value.application);
    encoder.fixed(value.reopened_state.as_bytes());
    encoder.u64(value.applied_at);
}

pub(crate) fn management_application_ack_signing_bytes(
    value: &ManagementApplicationAck,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MA2S");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_application_ack_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn management_application_ack_encoded_len(value: &ManagementApplicationAck) -> usize {
    let mut body = Vec::new();
    encode_management_application_ack_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(AUTHORITY_SIGNATURE_BYTES)
}

impl CanonicalWire for ManagementApplicationAck {
    const MAGIC: [u8; 4] = *b"MAA2";
    const MAX_ENCODED_BYTES: usize = MAX_MANAGEMENT_APPLICATION_ACK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_management_application_ack_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let authorization_invocation = InvocationId(decoder.fixed()?);
        let acknowledgement_invocation = InvocationId(decoder.fixed()?);
        let authority = decode_authority_actor_target(decoder)?;
        let managed = decode_managed_agent_target(decoder)?;
        let credential_call = Hash(decoder.fixed()?);
        let approval = Hash(decoder.fixed()?);
        let authorization_sequence =
            core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
        let request = Hash(decoder.fixed()?);
        let receipt = decode_authority_receipt_body(decoder)?;
        let application = decode_management_reply(decoder)?;
        let reopened_state = Hash(decoder.fixed()?);
        let applied_at = decoder.u64()?;
        let signature = decoder
            .take(AUTHORITY_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let value = Self {
            authorization_invocation,
            acknowledgement_invocation,
            authority,
            managed,
            credential_call,
            approval,
            authorization_sequence,
            request,
            receipt,
            application,
            reopened_state,
            applied_at,
            signature,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_management_application_failure_unsigned(
    encoder: &mut Encoder<'_>,
    value: &ManagementApplicationFailure,
) {
    encoder.fixed(value.authorization_invocation.as_bytes());
    encoder.fixed(value.acknowledgement_invocation.as_bytes());
    encode_authority_actor_target(encoder, value.authority);
    encode_managed_agent_target(encoder, value.managed);
    encoder.fixed(value.credential_call.as_bytes());
    encoder.fixed(value.approval.as_bytes());
    encoder.u64(value.authorization_sequence.get());
    encoder.fixed(value.request.as_bytes());
    encode_authority_receipt_body(encoder, &value.receipt);
    encode_management_error(encoder, value.error);
    encoder.fixed(value.reopened_state.as_bytes());
    encoder.u64(value.failed_at);
}

pub(crate) fn management_application_failure_signing_bytes(
    value: &ManagementApplicationFailure,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MF1S");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_application_failure_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn management_application_failure_encoded_len(
    value: &ManagementApplicationFailure,
) -> usize {
    let mut body = Vec::new();
    encode_management_application_failure_unsigned(&mut Encoder(&mut body), value);
    HEADER_BYTES
        .saturating_add(body.len())
        .saturating_add(AUTHORITY_SIGNATURE_BYTES)
}

impl CanonicalWire for ManagementApplicationFailure {
    const MAGIC: [u8; 4] = *b"MAF1";
    const MAX_ENCODED_BYTES: usize = MAX_INVOCATION_MESSAGE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_management_application_failure_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let authorization_invocation = InvocationId(decoder.fixed()?);
        let acknowledgement_invocation = InvocationId(decoder.fixed()?);
        let authority = decode_authority_actor_target(decoder)?;
        let managed = decode_managed_agent_target(decoder)?;
        let credential_call = Hash(decoder.fixed()?);
        let approval = Hash(decoder.fixed()?);
        let authorization_sequence =
            core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?;
        let request = Hash(decoder.fixed()?);
        let receipt = decode_authority_receipt_body(decoder)?;
        let error = decode_management_error(decoder)?;
        let reopened_state = Hash(decoder.fixed()?);
        let failed_at = decoder.u64()?;
        let signature = decoder
            .take(AUTHORITY_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let value = Self {
            authorization_invocation,
            acknowledgement_invocation,
            authority,
            managed,
            credential_call,
            approval,
            authorization_sequence,
            request,
            receipt,
            error,
            reopened_state,
            failed_at,
            signature,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

pub(crate) fn encode_catalog_actor_target(encoder: &mut Encoder<'_>, value: CatalogActorTarget) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.system_agent.as_bytes());
    encoder.fixed(value.system_runtime_deployment.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encode_agent_authority_binding(encoder, value.authority);
}

pub(crate) fn decode_catalog_actor_target(
    decoder: &mut Decoder<'_>,
) -> Result<CatalogActorTarget, DecodeError> {
    let value = CatalogActorTarget {
        space: SpaceId(decoder.fixed()?),
        system_agent: AgentId(decoder.fixed()?),
        system_runtime_deployment: DeploymentId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        authority: decode_agent_authority_binding(decoder)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_catalog_alias(encoder: &mut Encoder<'_>, value: &CatalogAlias) {
    encoder.string(&value.namespace);
    encoder.string(&value.name);
}

pub(crate) fn decode_catalog_alias(decoder: &mut Decoder<'_>) -> Result<CatalogAlias, DecodeError> {
    let value = CatalogAlias {
        namespace: decoder.string_bounded(MAX_CATALOG_NAMESPACE_BYTES)?,
        name: decoder.string_bounded(MAX_CATALOG_ALIAS_BYTES)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_catalog_publication(encoder: &mut Encoder<'_>, value: &CatalogPublication) {
    encode_agent_identity(encoder, &value.identity);
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.actor_deployment.as_bytes());
    encoder.fixed(value.actor_program.as_bytes());
    encode_blob(encoder, &value.actor_package);
    encode_blob(encoder, &value.content);
}

pub(crate) fn decode_catalog_publication(
    decoder: &mut Decoder<'_>,
) -> Result<CatalogPublication, DecodeError> {
    let value = CatalogPublication {
        identity: decode_agent_identity(decoder)?,
        actor: ActorId(decoder.fixed()?),
        actor_deployment: DeploymentId(decoder.fixed()?),
        actor_program: ProgramId(decoder.fixed()?),
        actor_package: decode_blob(decoder)?,
        content: decode_blob(decoder)?,
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_catalog_mutation_kind(encoder: &mut Encoder<'_>, value: CatalogMutationKind) {
    encoder.u8(value as u8);
}

pub(crate) fn decode_catalog_mutation_kind(
    decoder: &mut Decoder<'_>,
) -> Result<CatalogMutationKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(CatalogMutationKind::Publish),
        1 => Ok(CatalogMutationKind::Withdraw),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_catalog_mutation_request_without_invocation(
    encoder: &mut Encoder<'_>,
    value: &CatalogMutationRequest,
) {
    encode_catalog_actor_target(encoder, value.catalog);
    encode_catalog_alias(encoder, &value.alias);
    encoder.u64(value.generation.get());
    encode_catalog_mutation_kind(encoder, value.kind);
    encode_catalog_publication(encoder, &value.publication);
}

fn encode_catalog_mutation_request_body(encoder: &mut Encoder<'_>, value: &CatalogMutationRequest) {
    encoder.fixed(value.invocation.as_bytes());
    encode_catalog_mutation_request_without_invocation(encoder, value);
}

fn decode_catalog_mutation_request_body(
    decoder: &mut Decoder<'_>,
) -> Result<CatalogMutationRequest, DecodeError> {
    let value = CatalogMutationRequest {
        invocation: InvocationId(decoder.fixed()?),
        catalog: decode_catalog_actor_target(decoder)?,
        alias: decode_catalog_alias(decoder)?,
        generation: core::num::NonZeroU64::new(decoder.u64()?).ok_or(DecodeError::NonCanonical)?,
        kind: decode_catalog_mutation_kind(decoder)?,
        publication: decode_catalog_publication(decoder)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn canonical_catalog_mutation_request_bytes(value: &CatalogMutationRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CMT1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_catalog_mutation_request_body(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn catalog_mutation_request_encoded_len(value: &CatalogMutationRequest) -> usize {
    canonical_catalog_mutation_request_bytes(value).len()
}

pub(crate) fn catalog_mutation_request_commitment(value: &CatalogMutationRequest) -> Hash {
    Hash::digest(
        b"vos/agent/catalog-mutation-request/v1",
        &[&canonical_catalog_mutation_request_bytes(value)],
    )
}

pub(crate) fn catalog_mutation_semantic_commitment(value: &CatalogMutationRequest) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CMS1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_catalog_mutation_request_without_invocation(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/catalog-mutation-semantic/v1", &[&bytes])
}

impl CanonicalWire for CatalogMutationRequest {
    const MAGIC: [u8; 4] = *b"CMT1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_MUTATION_REQUEST_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_catalog_mutation_request_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_catalog_mutation_request_body(decoder)
    }
}

fn encode_catalog_mutation_call_body(encoder: &mut Encoder<'_>, value: &CatalogMutationCall) {
    encode_catalog_mutation_request_body(encoder, &value.request);
    encode_authority_receipt_body(encoder, &value.authority);
}

fn decode_catalog_mutation_call_body(
    decoder: &mut Decoder<'_>,
) -> Result<CatalogMutationCall, DecodeError> {
    let value = CatalogMutationCall {
        request: decode_catalog_mutation_request_body(decoder)?,
        authority: decode_authority_receipt_body(decoder)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn canonical_catalog_mutation_call_bytes(value: &CatalogMutationCall) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CMC1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_catalog_mutation_call_body(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn catalog_mutation_call_encoded_len(value: &CatalogMutationCall) -> usize {
    canonical_catalog_mutation_call_bytes(value).len()
}

pub(crate) fn catalog_mutation_call_commitment(value: &CatalogMutationCall) -> Hash {
    Hash::digest(
        b"vos/agent/catalog-mutation-call/v1",
        &[&canonical_catalog_mutation_call_bytes(value)],
    )
}

impl CanonicalWire for CatalogMutationCall {
    const MAGIC: [u8; 4] = *b"CMC1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_MUTATION_CALL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_catalog_mutation_call_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_catalog_mutation_call_body(decoder)
    }
}

impl CanonicalWire for CatalogMutationResult {
    const MAGIC: [u8; 4] = *b"CMO1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.is_valid()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.invocation.as_bytes());
        encoder.fixed(self.request.as_bytes());
        encoder.fixed(self.mutation.as_bytes());
        encoder.fixed(self.call.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            invocation: InvocationId(decoder.fixed()?),
            request: Hash(decoder.fixed()?),
            mutation: Hash(decoder.fixed()?),
            call: Hash(decoder.fixed()?),
        };
        value
            .is_valid()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_catalog_entry_body(encoder: &mut Encoder<'_>, value: &CatalogEntry) {
    encode_catalog_mutation_request_body(encoder, &value.request);
    encode_authority_receipt_body(encoder, &value.authority);
}

fn decode_catalog_entry_body(decoder: &mut Decoder<'_>) -> Result<CatalogEntry, DecodeError> {
    let value = CatalogEntry {
        request: decode_catalog_mutation_request_body(decoder)?,
        authority: decode_authority_receipt_body(decoder)?,
    };
    value
        .validate_shape()
        .is_ok()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn catalog_entry_commitment(value: &CatalogEntry) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CEN1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_catalog_entry_body(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/catalog-entry/v1", &[&bytes])
}

impl CanonicalWire for CatalogEntry {
    const MAGIC: [u8; 4] = *b"CEN1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_ENTRY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_catalog_entry_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_catalog_entry_body(decoder)
    }
}

impl CanonicalWire for CatalogPageRequest {
    const MAGIC: [u8; 4] = *b"CPQ1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_PAGE_REQUEST_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_catalog_actor_target(encoder, self.catalog);
        encoder.string(&self.namespace);
        encoder.option(&self.after, |encoder, value| encoder.string(value));
        encoder.u16(self.limit);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            catalog: decode_catalog_actor_target(decoder)?,
            namespace: decoder.string_bounded(MAX_CATALOG_NAMESPACE_BYTES)?,
            after: decoder.option(|decoder| decoder.string_bounded(MAX_CATALOG_ALIAS_BYTES))?,
            limit: decoder.u16()?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

impl CanonicalWire for CatalogPage {
    const MAGIC: [u8; 4] = *b"CAP1";
    const MAX_ENCODED_BYTES: usize = MAX_CATALOG_PAGE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_catalog_actor_target(encoder, self.catalog);
        encoder.string(&self.namespace);
        encoder.list(&self.entries, encode_catalog_entry_body);
        encoder.option(&self.next, |encoder, value| encoder.string(value));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            catalog: decode_catalog_actor_target(decoder)?,
            namespace: decoder.string_bounded(MAX_CATALOG_NAMESPACE_BYTES)?,
            entries: decoder.list_bounded(MAX_CATALOG_PAGE_ENTRIES, decode_catalog_entry_body)?,
            next: decoder.option(|decoder| decoder.string_bounded(MAX_CATALOG_ALIAS_BYTES))?,
        };
        value
            .validate_shape()
            .is_ok()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn install_valid(value: &InstallActor) -> bool {
    value.installation_id != InstallationId::ZERO
        && value.registry_reservation != Hash::ZERO
        && value.entry.validate().is_ok()
        && value.producer != ProducerId::ZERO
        && value.package == value.entry.package
        && value.agent_schema == value.entry.agent_schema
        && value.method_policy == value.entry.method_policy
        && value.constructor_abi == value.entry.constructor_abi
        && value.constructor_abi != Hash::ZERO
        && value.installation_data.as_ref().map(|data| &data.reference)
            == value.entry.installation_data.as_ref()
        && value
            .installation_data
            .as_ref()
            .is_none_or(|data| data.validate().is_ok())
        && value.installation_data.as_ref().is_none_or(|data| {
            [&value.package, &value.agent_schema, &value.method_policy]
                .into_iter()
                .all(|artifact| artifact.hash != data.reference.hash)
        })
        && value.state_layout == value.entry.state_layout
        && value.contract.is_valid()
        && value.requirements.lanes.bits() == value.entry.lanes.bits()
}

fn encode_install(encoder: &mut Encoder<'_>, value: &InstallActor) {
    encoder.fixed(value.installation_id.as_bytes());
    encoder.fixed(value.registry_reservation.as_bytes());
    encode_actor_entry(encoder, &value.entry);
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encoder.option(&value.installation_data, encode_installation_data);
    encoder.fixed(value.state_layout.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
}

fn decode_install(decoder: &mut Decoder<'_>) -> Result<InstallActor, DecodeError> {
    let value = InstallActor {
        installation_id: InstallationId(decoder.fixed()?),
        registry_reservation: Hash(decoder.fixed()?),
        entry: decode_actor_entry(decoder)?,
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        installation_data: decoder.option(decode_installation_data)?,
        state_layout: Hash(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
    };
    install_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn upgrade_actor_valid(value: &UpgradeActor) -> bool {
    value.actor != ActorId::ZERO
        && value.from_deployment != DeploymentId::ZERO
        && value.to_deployment != DeploymentId::ZERO
        && value.from_deployment != value.to_deployment
        && value.to_program != ProgramId::ZERO
        && value.producer != ProducerId::ZERO
        && crate::model::valid_blob(&value.package)
        && crate::model::valid_blob(&value.agent_schema)
        && crate::model::valid_blob(&value.method_policy)
        && value.constructor_abi != Hash::ZERO
        && value.state_layout != Hash::ZERO
        && value.contract.is_valid()
}

fn encode_upgrade_actor(encoder: &mut Encoder<'_>, value: &UpgradeActor) {
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.from_deployment.as_bytes());
    encoder.fixed(value.to_deployment.as_bytes());
    encoder.fixed(value.to_program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_blob(encoder, &value.agent_schema);
    encode_blob(encoder, &value.method_policy);
    encoder.fixed(value.constructor_abi.as_bytes());
    encoder.fixed(value.state_layout.as_bytes());
    encode_actor_contract(encoder, value.contract);
    encode_requirements(encoder, value.requirements);
}

fn decode_upgrade_actor(decoder: &mut Decoder<'_>) -> Result<UpgradeActor, DecodeError> {
    let value = UpgradeActor {
        actor: ActorId(decoder.fixed()?),
        from_deployment: DeploymentId(decoder.fixed()?),
        to_deployment: DeploymentId(decoder.fixed()?),
        to_program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        method_policy: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        state_layout: Hash(decoder.fixed()?),
        contract: decode_actor_contract(decoder)?,
        requirements: decode_requirements(decoder)?,
    };
    upgrade_actor_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn runtime_upgrade_valid(value: &RuntimeUpgrade) -> bool {
    value.from_deployment != DeploymentId::ZERO
        && value.to_deployment != DeploymentId::ZERO
        && value.from_deployment != value.to_deployment
        && value.to_program != ProgramId::ZERO
        && value.producer != ProducerId::ZERO
        && crate::model::valid_blob(&value.package)
        && value.contract.is_valid()
        && value.capabilities.max_actors != 0
        && value.capabilities.max_actors <= STANDARD_MAX_ACTORS
}

fn encode_runtime_upgrade(encoder: &mut Encoder<'_>, value: &RuntimeUpgrade) {
    encoder.fixed(value.from_deployment.as_bytes());
    encoder.fixed(value.to_deployment.as_bytes());
    encoder.fixed(value.to_program.as_bytes());
    encoder.fixed(value.producer.as_bytes());
    encode_blob(encoder, &value.package);
    encode_runtime_contract(encoder, value.contract);
    encode_capabilities(encoder, value.capabilities);
}

fn decode_runtime_upgrade(decoder: &mut Decoder<'_>) -> Result<RuntimeUpgrade, DecodeError> {
    let value = RuntimeUpgrade {
        from_deployment: DeploymentId(decoder.fixed()?),
        to_deployment: DeploymentId(decoder.fixed()?),
        to_program: ProgramId(decoder.fixed()?),
        producer: ProducerId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        contract: decode_runtime_contract(decoder)?,
        capabilities: decode_capabilities(decoder)?,
    };
    runtime_upgrade_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn replica_set_valid(replicas: &[AgentReplica]) -> bool {
    !replicas.is_empty()
        && replicas.len() <= MAX_AGENT_REPLICAS
        && replicas
            .iter()
            .all(|replica| replica.node != NodeId::ZERO && replica.principal != PrincipalId::ZERO)
        && replicas.windows(2).all(|pair| pair[0].node < pair[1].node)
}

pub(crate) fn private_runtime_mutation_valid(value: &PrivateRuntimeMutation) -> bool {
    match value {
        PrivateRuntimeMutation::SetResourcePolicy(policy) => policy.is_valid(),
        PrivateRuntimeMutation::Install(install) => {
            install_valid(install) && install.validate_for_profile(AgentProfile::Private).is_ok()
        }
        PrivateRuntimeMutation::UpgradeActor(upgrade) => {
            upgrade_actor_valid(upgrade) && upgrade.requirements.supported_by(AgentProfile::Private)
        }
        PrivateRuntimeMutation::Suspend {
            actor,
            expected_deployment,
        }
        | PrivateRuntimeMutation::Resume {
            actor,
            expected_deployment,
        }
        | PrivateRuntimeMutation::RemoveLeaf {
            actor,
            expected_deployment,
        } => *actor != ActorId::ZERO && *expected_deployment != DeploymentId::ZERO,
    }
}

fn encode_private_runtime_mutation(encoder: &mut Encoder<'_>, value: &PrivateRuntimeMutation) {
    match value {
        PrivateRuntimeMutation::SetResourcePolicy(policy) => {
            encoder.u8(0);
            encode_runtime_resource_policy(encoder, *policy);
        }
        PrivateRuntimeMutation::Install(install) => {
            encoder.u8(1);
            encode_install(encoder, install);
        }
        PrivateRuntimeMutation::UpgradeActor(upgrade) => {
            encoder.u8(2);
            encode_upgrade_actor(encoder, upgrade);
        }
        PrivateRuntimeMutation::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(3);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        PrivateRuntimeMutation::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(4);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        PrivateRuntimeMutation::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
    }
}

fn decode_private_runtime_mutation(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateRuntimeMutation, DecodeError> {
    let value = match decoder.u8()? {
        0 => PrivateRuntimeMutation::SetResourcePolicy(decode_runtime_resource_policy(decoder)?),
        1 => PrivateRuntimeMutation::Install(decode_install(decoder)?),
        2 => PrivateRuntimeMutation::UpgradeActor(decode_upgrade_actor(decoder)?),
        3 => PrivateRuntimeMutation::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        4 => PrivateRuntimeMutation::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        5 => PrivateRuntimeMutation::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    private_runtime_mutation_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for PrivateRuntimeMutation {
    const MAGIC: [u8; 4] = *b"PRM1";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        private_runtime_mutation_valid(self)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_runtime_mutation(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_runtime_mutation(decoder)
    }
}

pub(crate) fn private_runtime_mutation_commitment(value: &PrivateRuntimeMutation) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PRM1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_private_runtime_mutation(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/private-runtime-mutation/v1", &[&bytes])
}

fn private_control_request_valid(
    control: &PrivateControlRecord,
    mutation: &PrivateRuntimeMutation,
) -> bool {
    if !control.validate_shape() || !private_runtime_mutation_valid(mutation) {
        return false;
    }
    match (&control.operation, mutation) {
        (
            PrivateControlOperation::SetResourcePolicy { policy: reference },
            PrivateRuntimeMutation::SetResourcePolicy(policy),
        ) => policy
            .encode()
            .is_ok_and(|bytes| reference.matches(bytes.as_slice())),
        (
            PrivateControlOperation::ActorLifecycle {
                actor,
                operation,
                request,
            },
            mutation,
        ) => {
            mutation.lifecycle_kind() == Some(*operation)
                && mutation.actor() == Some(*actor)
                && mutation.commitment() == *request
        }
        _ => false,
    }
}

pub(crate) fn private_runtime_reply_matches(
    request: &ManagementRequest,
    reply: &ManagementReply,
) -> bool {
    let ManagementRequest::PrivateControl { mutation, .. } = request else {
        return false;
    };
    match (mutation.as_ref(), reply) {
        (
            PrivateRuntimeMutation::SetResourcePolicy(expected),
            ManagementReply::ResourcePolicySet(policy),
        ) => expected == policy,
        (PrivateRuntimeMutation::Install(install), ManagementReply::Installed(entry)) => {
            install.entry == *entry
        }
        (PrivateRuntimeMutation::UpgradeActor(upgrade), ManagementReply::Upgraded(entry)) => {
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
            PrivateRuntimeMutation::Suspend {
                actor,
                expected_deployment,
            },
            ManagementReply::Suspended(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && entry.suspended,
        (
            PrivateRuntimeMutation::Resume {
                actor,
                expected_deployment,
            },
            ManagementReply::Resumed(entry),
        ) => entry.actor == *actor && entry.deployment == *expected_deployment && !entry.suspended,
        (PrivateRuntimeMutation::RemoveLeaf { actor, .. }, ManagementReply::Removed(removed)) => {
            actor == removed
        }
        _ => false,
    }
}

pub(crate) fn management_request_valid(value: &ManagementRequest) -> bool {
    match value {
        ManagementRequest::Create(descriptor) => descriptor.validate().is_ok(),
        ManagementRequest::InspectActors { after, limit } => {
            *limit != 0
                && usize::from(*limit) <= MAX_DIRECTORY_PAGE_ENTRIES
                && *after != Some(ActorId::ZERO)
        }
        ManagementRequest::InspectResources => true,
        ManagementRequest::InspectManagementHistory => true,
        ManagementRequest::Install(value) => install_valid(value),
        ManagementRequest::UpgradeActor(value) => upgrade_actor_valid(value),
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
        } => *actor != ActorId::ZERO && *expected_deployment != DeploymentId::ZERO,
        ManagementRequest::UpgradeRuntime(value) => runtime_upgrade_valid(value),
        ManagementRequest::ChangeReplicas {
            expected_generation,
            replicas,
        } => *expected_generation != Hash::ZERO && replica_set_valid(replicas),
        ManagementRequest::PrivateControl { control, mutation } => {
            private_control_request_valid(control, mutation)
        }
    }
}

fn encode_management_request(encoder: &mut Encoder<'_>, value: &ManagementRequest) {
    match value {
        ManagementRequest::Create(value) => {
            encoder.u8(0);
            encode_agent_descriptor(encoder, value);
        }
        ManagementRequest::InspectActors { after, limit } => {
            encoder.u8(1);
            encoder.option(after, |encoder, value| encoder.fixed(value.as_bytes()));
            encoder.u16(*limit);
        }
        ManagementRequest::InspectResources => encoder.u8(2),
        ManagementRequest::InspectManagementHistory => encoder.u8(11),
        ManagementRequest::Install(value) => {
            encoder.u8(3);
            encode_install(encoder, value);
        }
        ManagementRequest::UpgradeActor(value) => {
            encoder.u8(4);
            encode_upgrade_actor(encoder, value);
        }
        ManagementRequest::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(6);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(7);
            encoder.fixed(actor.as_bytes());
            encoder.fixed(expected_deployment.as_bytes());
        }
        ManagementRequest::UpgradeRuntime(value) => {
            encoder.u8(8);
            encode_runtime_upgrade(encoder, value);
        }
        ManagementRequest::ChangeReplicas {
            expected_generation,
            replicas,
        } => {
            encoder.u8(9);
            encoder.fixed(expected_generation.as_bytes());
            encoder.list(replicas, encode_replica);
        }
        ManagementRequest::PrivateControl { control, mutation } => {
            encoder.u8(10);
            let control = control
                .encode()
                .expect("validated Private runtime request has canonical PCTL");
            let mutation = mutation
                .encode()
                .expect("validated Private runtime request has canonical mutation");
            encoder.bytes(&control);
            encoder.bytes(&mutation);
        }
    }
}

// Keep each boxed variant's decode scratch in its own frame. Otherwise the
// largest variant reserves stack even when decoding a different management
// request, and that reservation stays live throughout nested validation.
#[inline(never)]
fn decode_boxed_management_value<T>(
    decode: impl FnOnce() -> Result<T, DecodeError>,
) -> Result<alloc::boxed::Box<T>, DecodeError> {
    decode().map(alloc::boxed::Box::new)
}

fn decode_management_request(decoder: &mut Decoder<'_>) -> Result<ManagementRequest, DecodeError> {
    let value = match decoder.u8()? {
        0 => ManagementRequest::Create(decode_boxed_management_value(|| {
            decode_agent_descriptor(decoder)
        })?),
        1 => ManagementRequest::InspectActors {
            after: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        },
        2 => ManagementRequest::InspectResources,
        11 => ManagementRequest::InspectManagementHistory,
        3 => ManagementRequest::Install(decode_boxed_management_value(|| decode_install(decoder))?),
        4 => ManagementRequest::UpgradeActor(decode_boxed_management_value(|| {
            decode_upgrade_actor(decoder)
        })?),
        5 => ManagementRequest::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        6 => ManagementRequest::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        7 => ManagementRequest::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        },
        8 => ManagementRequest::UpgradeRuntime(decode_boxed_management_value(|| {
            decode_runtime_upgrade(decoder)
        })?),
        9 => ManagementRequest::ChangeReplicas {
            expected_generation: Hash(decoder.fixed()?),
            replicas: decoder.list_bounded(MAX_AGENT_REPLICAS, decode_replica)?,
        },
        10 => {
            let control = decoder.bytes_bounded(MAX_PRIVATE_RUNTIME_CONTROL_WIRE_BYTES)?;
            let mutation = decoder.bytes_bounded(MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES)?;
            ManagementRequest::PrivateControl {
                control: decode_boxed_management_value(|| {
                    PrivateControlRecord::decode(&control).map_err(|_| DecodeError::NonCanonical)
                })?,
                mutation: decode_boxed_management_value(|| {
                    PrivateRuntimeMutation::decode(&mutation).map_err(|_| DecodeError::NonCanonical)
                })?,
            }
        }
        _ => return Err(DecodeError::InvalidTag),
    };
    management_request_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for ManagementRequest {
    const MAGIC: [u8; 4] = *b"AMRQ";
    const MAX_ENCODED_BYTES: usize = MAX_MANAGEMENT_REQUEST_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        management_request_valid(self)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_management_request(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_management_request(decoder)
    }
}

pub(crate) fn management_request_commitment(value: &ManagementRequest) -> Hash {
    if let ManagementRequest::PrivateControl { control, .. } = value {
        return control.commitment();
    }
    if let Some(plan) = ManagementAuthorizationPlan::from_request(value) {
        return plan.commitment();
    }
    match value {
        ManagementRequest::InspectActors { .. }
        | ManagementRequest::InspectResources
        | ManagementRequest::InspectManagementHistory
            if value.is_valid() =>
        {
            Hash::digest(
                b"vos/agent/read-only-management-request/v1",
                &[&encode_canonical_management_request(value)],
            )
        }
        _ => Hash::ZERO,
    }
}

pub(crate) fn management_request_replay_commitment(value: &ManagementRequest) -> Hash {
    if !matches!(value, ManagementRequest::PrivateControl { .. }) {
        return management_request_commitment(value);
    }
    Hash::digest(
        b"vos/agent/management-replay-request/v1",
        &[
            RUNTIME_ABI_ID.as_bytes(),
            &encode_canonical_management_request(value),
        ],
    )
}

pub(crate) fn required_management_operation(
    value: &ManagementRequest,
) -> Option<AuthorityOperationKind> {
    match value {
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
        ManagementRequest::PrivateControl { control, .. } => match control.operation {
            PrivateControlOperation::SetResourcePolicy { .. } => {
                Some(AuthorityOperationKind::SetPrivateResourcePolicy)
            }
            PrivateControlOperation::ActorLifecycle { .. } => {
                Some(AuthorityOperationKind::PrivateActorLifecycle)
            }
            _ => None,
        },
    }
}

pub(crate) fn management_actor(value: &ManagementRequest) -> Option<(ActorId, DeploymentId)> {
    match value {
        ManagementRequest::Install(value) => Some((value.entry.actor, value.entry.deployment)),
        ManagementRequest::UpgradeActor(value) => Some((value.actor, value.to_deployment)),
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

pub(crate) fn management_actor_selector(
    value: &ManagementRequest,
) -> (Option<ActorId>, Option<DeploymentId>) {
    match value {
        ManagementRequest::PrivateControl { control, .. } => match control.operation {
            PrivateControlOperation::ActorLifecycle { actor, .. } => (Some(actor), None),
            _ => (None, None),
        },
        _ => management_actor(value)
            .map(|(actor, deployment)| (Some(actor), Some(deployment)))
            .unwrap_or((None, None)),
    }
}

fn authority_matches_management(
    receipt: &AuthorityReceipt,
    space: SpaceId,
    agent: AgentId,
    runtime_deployment: DeploymentId,
    request: &ManagementRequest,
    _observed_slot: u64,
) -> bool {
    let (operation, request_commitment, actor) = if let Some(plan) = request.authorization_plan() {
        (
            plan.authority_operation(),
            plan.commitment(),
            plan.authority_actor()
                .map(|(actor, deployment)| (Some(actor), Some(deployment)))
                .unwrap_or((None, None)),
        )
    } else if matches!(request, ManagementRequest::PrivateControl { .. }) {
        (
            required_management_operation(request).unwrap(),
            management_request_commitment(request),
            management_actor_selector(request),
        )
    } else {
        return false;
    };
    receipt.validate_shape().is_ok()
        && receipt.selector.space == space
        && receipt.selector.agent == agent
        && receipt.selector.runtime_deployment == runtime_deployment
        && receipt.selector.operation == operation
        && receipt.selector.request == request_commitment
        && actor == (receipt.selector.actor, receipt.selector.actor_deployment)
}

fn encode_runtime_state(encoder: &mut Encoder<'_>, value: &RuntimeState) {
    encoder.bytes(&value.control);
    encoder.bytes(&value.linear);
    encoder.bytes(&value.merge);
    encoder.bytes(&value.local);
}

fn decode_runtime_state(decoder: &mut Decoder<'_>) -> Result<RuntimeState, DecodeError> {
    let control = decoder.bytes_bounded(MAX_RUNTIME_STATE_BYTES)?;
    let mut remaining = MAX_RUNTIME_STATE_BYTES - control.len();
    let linear = decoder.bytes_bounded(remaining)?;
    remaining -= linear.len();
    let merge = decoder.bytes_bounded(remaining)?;
    remaining -= merge.len();
    let local = decoder.bytes_bounded(remaining)?;
    let value = RuntimeState {
        control,
        linear,
        merge,
        local,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::LimitExceeded)
}

pub(crate) fn encode_origin(encoder: &mut Encoder<'_>, value: InvocationOrigin) {
    encoder.option(&value.principal, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.transport_node, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.credential, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.capability, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

pub(crate) fn decode_origin(decoder: &mut Decoder<'_>) -> Result<InvocationOrigin, DecodeError> {
    let value = InvocationOrigin {
        principal: decoder.option(|decoder| Ok(PrincipalId(decoder.fixed()?)))?,
        transport_node: decoder.option(|decoder| Ok(NodeId(decoder.fixed()?)))?,
        credential: decoder.option(|decoder| Ok(CredentialId(decoder.fixed()?)))?,
        actor: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_invocation_roles(encoder: &mut Encoder<'_>, value: InvocationRoleClaims) {
    encoder.option(&value.space, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

pub(crate) fn decode_invocation_roles(
    decoder: &mut Decoder<'_>,
    origin: InvocationOrigin,
) -> Result<InvocationRoleClaims, DecodeError> {
    let value = InvocationRoleClaims {
        space: decoder.option(|decoder| Ok(RoleId(decoder.fixed()?)))?,
        actor: decoder.option(|decoder| Ok(RoleId(decoder.fixed()?)))?,
    };
    value
        .validate_for(origin)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for InvocationContext {
    const MAGIC: [u8; 4] = *b"AIC1";
    const MAX_ENCODED_BYTES: usize = MAX_INVOCATION_CONTEXT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.invocation.as_bytes());
        encoder.fixed(self.actor.as_bytes());
        encoder.u8(self.mode as u8);
        encode_origin(encoder, self.origin);
        encode_invocation_roles(encoder, self.roles);
        encoder.u64(self.observed_slot);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation = InvocationId(decoder.fixed()?);
        let actor = ActorId(decoder.fixed()?);
        let mode = decode_method_mode(decoder)?;
        let origin = decode_origin(decoder)?;
        let roles = decode_invocation_roles(decoder, origin)?;
        let value = Self {
            invocation,
            actor,
            mode,
            origin,
            roles,
            observed_slot: decoder.u64()?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_runtime_blob(encoder: &mut Encoder<'_>, value: &RuntimeBlob) {
    encode_blob(encoder, &value.reference);
    encoder.bytes(&value.bytes);
}

fn decode_runtime_availability(decoder: &mut Decoder<'_>) -> Result<Vec<RuntimeBlob>, DecodeError> {
    let mut remaining = MAX_RUNTIME_AVAILABILITY_BYTES;
    decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, |decoder| {
        let reference = decode_blob(decoder)?;
        let bytes = decoder.bytes_bounded(remaining)?;
        remaining -= bytes.len();
        // Both callers validate their complete Invoke/Resume value before
        // returning it. Hash payloads there once, alongside ordering and
        // installation-reference checks, after bounded parsing here.
        Ok(RuntimeBlob { reference, bytes })
    })
}

fn encode_required_refs(encoder: &mut Encoder<'_>, values: &[BlobRef]) {
    encoder.list(values, encode_blob);
}

fn decode_required_refs(
    decoder: &mut Decoder<'_>,
    installation_data: Option<&BlobRef>,
) -> Result<Vec<BlobRef>, DecodeError> {
    let values = decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, decode_blob)?;
    let valid = values.iter().all(|reference| {
        reference.hash != Hash::ZERO
            && (reference.len != 0 || installation_data == Some(reference))
            && reference.len <= MAX_RUNTIME_AVAILABILITY_BYTES as u64
    }) && installation_data
        .is_none_or(|required| values.iter().any(|value| value == required))
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .try_fold(0u64, |total, reference| total.checked_add(reference.len))
            .is_some_and(|total| total <= MAX_RUNTIME_AVAILABILITY_BYTES as u64);
    valid.then_some(values).ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_work(encoder: &mut Encoder<'_>, value: &InvocationWork) {
    encode_invocation_work_with_availability(encoder, value, true);
}

fn encode_invocation_work_with_availability(
    encoder: &mut Encoder<'_>,
    value: &InvocationWork,
    include_preimages: bool,
) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.runtime_deployment.as_bytes());
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_origin(encoder, value.origin);
    encode_invocation_roles(encoder, value.roles);
    encoder.bytes(&value.message);
    encode_optional_blob(encoder, &value.installation_data);
    if include_preimages {
        encoder.list(&value.availability, encode_runtime_blob);
    } else {
        encoder.list(&value.availability, |encoder, blob| {
            encode_blob(encoder, &blob.reference);
        });
    }
    encoder.u64(value.gas);
    encoder.bool(value.recovery_only);
}

fn decode_invocation_work(decoder: &mut Decoder<'_>) -> Result<InvocationWork, DecodeError> {
    let space = SpaceId(decoder.fixed()?);
    let agent = AgentId(decoder.fixed()?);
    let runtime_deployment = DeploymentId(decoder.fixed()?);
    let invocation = InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder)?;
    let origin = decode_origin(decoder)?;
    let roles = decode_invocation_roles(decoder, origin)?;
    let value = InvocationWork {
        space,
        agent,
        runtime_deployment,
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        origin,
        roles,
        message: decoder.bytes_bounded(MAX_INVOCATION_MESSAGE_BYTES)?,
        installation_data: decode_optional_blob(decoder)?,
        availability: decode_runtime_availability(decoder)?,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn invocation_work_commitment(value: &InvocationWork) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AINV");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    // Validated content-addressed references bind the preimages without
    // requiring continuations and terminal results to retain caller-sized data.
    encode_invocation_work_with_availability(&mut Encoder(&mut bytes), value, false);
    Hash::digest(b"vos/agent/invocation", &[&bytes])
}

impl CanonicalWire for InvocationRetirement {
    const MAGIC: [u8; 4] = *b"AIRT";
    const MAX_ENCODED_BYTES: usize =
        HEADER_BYTES + MAX_INVOCATION_MESSAGE_BYTES + MAX_RUNTIME_AVAILABILITY_ITEMS * 40 + 1024;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.space.as_bytes());
        encoder.fixed(self.agent.as_bytes());
        encoder.fixed(self.runtime_deployment.as_bytes());
        encoder.fixed(self.invocation.as_bytes());
        encoder.fixed(self.actor.as_bytes());
        encoder.fixed(self.incarnation.as_bytes());
        encoder.fixed(self.deployment.as_bytes());
        encoder.fixed(self.program.as_bytes());
        encoder.u8(self.mode as u8);
        encode_origin(encoder, self.origin);
        encode_invocation_roles(encoder, self.roles);
        encoder.bytes(&self.message);
        encode_optional_blob(encoder, &self.installation_data);
        encode_required_refs(encoder, &self.required);
        encoder.u64(self.gas);
        encoder.bool(self.recovery_only);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let space = SpaceId(decoder.fixed()?);
        let agent = AgentId(decoder.fixed()?);
        let runtime_deployment = DeploymentId(decoder.fixed()?);
        let invocation = InvocationId(decoder.fixed()?);
        let actor = ActorId(decoder.fixed()?);
        let incarnation = Hash(decoder.fixed()?);
        let deployment = DeploymentId(decoder.fixed()?);
        let program = ProgramId(decoder.fixed()?);
        let mode = decode_method_mode(decoder)?;
        let origin = decode_origin(decoder)?;
        let roles = decode_invocation_roles(decoder, origin)?;
        let message = decoder.bytes_bounded(MAX_INVOCATION_MESSAGE_BYTES)?;
        let installation_data = decode_optional_blob(decoder)?;
        let availability = decode_required_refs(decoder, installation_data.as_ref())?;
        let value = Self {
            space,
            agent,
            runtime_deployment,
            invocation,
            actor,
            incarnation,
            deployment,
            program,
            mode,
            origin,
            roles,
            message,
            installation_data,
            required: availability,
            gas: decoder.u64()?,
            recovery_only: decoder.bool()?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

pub(crate) fn invocation_retirement_commitment(value: &InvocationRetirement) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AINV");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    value.encode_body(&mut Encoder(&mut bytes));
    Hash::digest(b"vos/agent/invocation", &[&bytes])
}

fn encode_invocation_authorization(encoder: &mut Encoder<'_>, value: &InvocationAuthorization) {
    match value {
        InvocationAuthorization::AuthorityReceipt(receipt) => {
            encoder.u8(0);
            <AuthorityReceipt as CanonicalWire>::encode_body(receipt, encoder);
        }
        InvocationAuthorization::PublicPreflight(preflight) => {
            encoder.u8(1);
            encoder.fixed(preflight.work.as_bytes());
            encode_origin(encoder, preflight.origin);
            encoder.u64(preflight.observed_slot);
        }
    }
}

fn decode_invocation_authorization(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationAuthorization, DecodeError> {
    let value = match decoder.u8()? {
        0 => InvocationAuthorization::AuthorityReceipt(
            <AuthorityReceipt as CanonicalWire>::decode_body(decoder)?,
        ),
        1 => InvocationAuthorization::PublicPreflight(PublicPreflight {
            work: Hash(decoder.fixed()?),
            origin: decode_origin(decoder)?,
            observed_slot: decoder.u64()?,
        }),
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate_shape()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn invocation_authorization_commitment(value: &InvocationAuthorization) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"IAU1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_invocation_authorization(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/invocation-authorization-envelope/v1", &[&bytes])
}

impl CanonicalWire for InvocationAuthorization {
    const MAGIC: [u8; 4] = *b"IAU1";
    const MAX_ENCODED_BYTES: usize = MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_invocation_authorization(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_invocation_authorization(decoder)
    }
}

fn encode_resume_input(encoder: &mut Encoder<'_>, value: &ResumeInput) {
    match value {
        ResumeInput::Ready(bytes) => {
            encoder.u8(0);
            encoder.bytes(bytes);
        }
        ResumeInput::Failed(code) => {
            encoder.u8(1);
            encoder.u32(*code);
        }
    }
}

fn decode_resume_input(decoder: &mut Decoder<'_>) -> Result<ResumeInput, DecodeError> {
    let value = match decoder.u8()? {
        0 => ResumeInput::Ready(decoder.bytes_bounded(MAX_RESUME_INPUT_BYTES)?),
        1 => ResumeInput::Failed(decoder.u32()?),
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_resume_work(encoder: &mut Encoder<'_>, value: &ResumeWork) {
    encode_resume_work_with_availability(encoder, value, true);
}

fn encode_resume_work_with_availability(
    encoder: &mut Encoder<'_>,
    value: &ResumeWork,
    include_preimages: bool,
) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_blob(encoder, &value.continuation);
    encoder.u64(value.ready_sequence);
    encode_optional_blob(encoder, &value.installation_data);
    if include_preimages {
        encoder.list(&value.availability, encode_runtime_blob);
    } else {
        encoder.list(&value.availability, |encoder, blob| {
            encode_blob(encoder, &blob.reference);
        });
    }
    encoder.option(&value.input, encode_resume_input);
}

fn decode_resume_work(decoder: &mut Decoder<'_>) -> Result<ResumeWork, DecodeError> {
    let value = ResumeWork {
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        continuation: decode_blob(decoder)?,
        ready_sequence: decoder.u64()?,
        installation_data: decode_optional_blob(decoder)?,
        availability: decode_runtime_availability(decoder)?,
        input: decoder.option(decode_resume_input)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_execution_context(encoder: &mut Encoder<'_>, value: RuntimeExecutionContext) {
    match value {
        RuntimeExecutionContext::Direct => encoder.u8(0),
        RuntimeExecutionContext::Attested { proof_system } => {
            encoder.u8(1);
            encoder.fixed(proof_system.as_bytes());
        }
    }
}

fn decode_runtime_execution_context(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimeExecutionContext, DecodeError> {
    let value = match decoder.u8()? {
        0 => RuntimeExecutionContext::Direct,
        1 => RuntimeExecutionContext::Attested {
            proof_system: Hash(decoder.fixed()?),
        },
        _ => return Err(DecodeError::InvalidTag),
    };
    value
        .is_valid()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn runtime_work_valid(value: &RuntimeWork) -> bool {
    runtime_work_valid_with_nested(value, false)
}

/// Envelope checks shared by constructed values and the body decoder. The
/// latter has already validated its nested Invoke/Resume value, including all
/// availability bytes; do not hash those bytes again at this layer.
fn runtime_work_valid_with_nested(value: &RuntimeWork, nested_already_validated: bool) -> bool {
    match value {
        RuntimeWork::Manage {
            context,
            space,
            agent,
            runtime_deployment,
            state,
            request,
            authority,
            observed_slot,
        } => {
            if !context.is_valid()
                || *space == SpaceId::ZERO
                || *agent == AgentId::ZERO
                || *runtime_deployment == DeploymentId::ZERO
                || !state.validate()
                || !management_request_valid(request)
            {
                return false;
            }
            if let ManagementRequest::Create(descriptor) = request.as_ref() {
                if descriptor.identity.space != *space
                    || descriptor.identity.agent != *agent
                    || descriptor.identity.runtime_deployment != *runtime_deployment
                    || authority
                        .as_deref()
                        .is_none_or(|receipt| !descriptor.authority.accepts(receipt))
                {
                    return false;
                }
            }
            if let ManagementRequest::PrivateControl { control, .. } = request.as_ref()
                && (!context.is_direct() || control.space != *space || control.agent != *agent)
            {
                return false;
            }
            match (required_management_operation(request), authority) {
                (None, None) => true,
                (None, Some(_)) => false,
                (Some(_), Some(receipt)) => authority_matches_management(
                    receipt,
                    *space,
                    *agent,
                    *runtime_deployment,
                    request,
                    *observed_slot,
                ),
                (Some(_), None) => false,
            }
        }
        RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } => {
            context.is_valid()
                && state.validate()
                && (nested_already_validated || invocation.validate())
                && authorization.matches_invoke(invocation, *observed_slot)
        }
        RuntimeWork::Resume {
            context,
            state,
            resume,
        } => {
            context.is_valid()
                && state.validate()
                && (nested_already_validated || resume.validate())
        }
        RuntimeWork::Acknowledge {
            context,
            state,
            invocation,
            authorization,
        } => {
            context.is_valid()
                && state.validate()
                && (nested_already_validated || invocation.validate())
                && authorization.matches_retirement(invocation)
        }
        #[cfg(feature = "experimental-state-blocks")]
        RuntimeWork::InspectInvocation {
            context,
            state,
            invocation,
            authorization,
            ..
        } => {
            context.is_direct()
                && state.validate()
                && (nested_already_validated || invocation.validate())
                && authorization.matches_retirement(invocation)
        }
    }
}

impl CanonicalWire for RuntimeWork {
    const MAGIC: [u8; 4] = *b"AWRK";
    const MAX_ENCODED_BYTES: usize = MAX_RUNTIME_WORK_WIRE_BYTES;

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        // decode_body validates nested values and the envelope. Repeating
        // validate_wire here would rehash all caller-sized availability.
        decode_canonical_frame::<Self>(bytes)
    }

    fn validate_wire(&self) -> bool {
        runtime_work_valid(self)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_runtime_work_body(encoder, self, true);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = match decoder.u8()? {
            0 => RuntimeWork::Manage {
                context: decode_runtime_execution_context(decoder)?,
                space: SpaceId(decoder.fixed()?),
                agent: AgentId(decoder.fixed()?),
                runtime_deployment: DeploymentId(decoder.fixed()?),
                state: decode_runtime_state(decoder)?,
                request: alloc::boxed::Box::new(decode_management_request(decoder)?),
                authority: decoder
                    .option(<AuthorityReceipt as CanonicalWire>::decode_body)?
                    .map(alloc::boxed::Box::new),
                observed_slot: decoder.u64()?,
            },
            1 => RuntimeWork::Invoke {
                context: decode_runtime_execution_context(decoder)?,
                state: decode_runtime_state(decoder)?,
                invocation: alloc::boxed::Box::new(decode_invocation_work(decoder)?),
                authorization: alloc::boxed::Box::new(decode_invocation_authorization(decoder)?),
                observed_slot: decoder.u64()?,
            },
            2 => RuntimeWork::Resume {
                context: decode_runtime_execution_context(decoder)?,
                state: decode_runtime_state(decoder)?,
                resume: alloc::boxed::Box::new(decode_resume_work(decoder)?),
            },
            3 => RuntimeWork::Acknowledge {
                context: decode_runtime_execution_context(decoder)?,
                state: decode_runtime_state(decoder)?,
                invocation: alloc::boxed::Box::new(InvocationRetirement::decode_body(decoder)?),
                authorization: alloc::boxed::Box::new(decode_invocation_authorization(decoder)?),
            },
            #[cfg(feature = "experimental-state-blocks")]
            4 => RuntimeWork::InspectInvocation {
                context: decode_runtime_execution_context(decoder)?,
                state: decode_runtime_state(decoder)?,
                invocation: alloc::boxed::Box::new(InvocationRetirement::decode_body(decoder)?),
                authorization: alloc::boxed::Box::new(decode_invocation_authorization(decoder)?),
                observed_slot: decoder.u64()?,
            },
            _ => return Err(DecodeError::InvalidTag),
        };
        runtime_work_valid_with_nested(&value, true)
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_runtime_work_body(
    encoder: &mut Encoder<'_>,
    work: &RuntimeWork,
    include_preimages: bool,
) {
    match work {
        RuntimeWork::Manage {
            context,
            space,
            agent,
            runtime_deployment,
            state,
            request,
            authority,
            observed_slot,
        } => {
            encoder.u8(0);
            encode_runtime_execution_context(encoder, *context);
            encoder.fixed(space.as_bytes());
            encoder.fixed(agent.as_bytes());
            encoder.fixed(runtime_deployment.as_bytes());
            encode_runtime_state(encoder, state);
            encode_management_request(encoder, request);
            encoder.option(authority, |encoder, value| {
                <AuthorityReceipt as CanonicalWire>::encode_body(value, encoder)
            });
            encoder.u64(*observed_slot);
        }
        RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } => {
            encoder.u8(1);
            encode_runtime_execution_context(encoder, *context);
            encode_runtime_state(encoder, state);
            encode_invocation_work_with_availability(encoder, invocation, include_preimages);
            encode_invocation_authorization(encoder, authorization);
            encoder.u64(*observed_slot);
        }
        RuntimeWork::Resume {
            context,
            state,
            resume,
        } => {
            encoder.u8(2);
            encode_runtime_execution_context(encoder, *context);
            encode_runtime_state(encoder, state);
            encode_resume_work_with_availability(encoder, resume, include_preimages);
        }
        RuntimeWork::Acknowledge {
            context,
            state,
            invocation,
            authorization,
        } => {
            encoder.u8(3);
            encode_runtime_execution_context(encoder, *context);
            encode_runtime_state(encoder, state);
            invocation.encode_body(encoder);
            encode_invocation_authorization(encoder, authorization);
        }
        #[cfg(feature = "experimental-state-blocks")]
        RuntimeWork::InspectInvocation {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } => {
            encoder.u8(4);
            encode_runtime_execution_context(encoder, *context);
            encode_runtime_state(encoder, state);
            invocation.encode_body(encoder);
            encode_invocation_authorization(encoder, authorization);
            encoder.u64(*observed_slot);
        }
    }
}

/// Commitment of one canonical [`RuntimeWork`] with every availability blob of
/// an Invoke or Resume replaced by its [`BlobRef`].
///
/// This binds exactly the bytes the canonical work binds, without hashing the
/// preimages again: the work's decoder accepts an Invoke or Resume only after
/// `availability_valid` has checked every blob's bytes against its reference
/// (`RuntimeBlob::validate`, hash and length), and a reference is
/// `BLAKE2b-256("vos/blob" || bytes)` plus the length. Two decodable works with
/// the same commitment therefore differ in no byte, unless BLAKE2b collides.
/// The reference form keeps the frame's magic and ABI identity, every other
/// field and every length, so it is itself an unambiguous encoding.
///
/// Callers must pass a value obtained from [`CanonicalWire::decode`] (or one
/// whose availability they validated); the function does not hash preimages.
pub fn runtime_work_reference_commitment(work: &RuntimeWork) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&<RuntimeWork as CanonicalWire>::MAGIC);
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_runtime_work_body(&mut Encoder(&mut bytes), work, false);
    Hash::digest(b"vos/agent/runtime-work-by-reference/v1", &[&bytes])
}

fn encode_lifecycle_debt(encoder: &mut Encoder<'_>, value: ActorLifecycleDebt) {
    encoder.u32(value.children);
    encoder.u32(value.continuations);
    encoder.u32(value.inbox);
    encoder.u32(value.outbox);
    encoder.u32(value.schedules);
    encoder.u32(value.proof_artifacts);
    encoder.u32(value.lifecycle_operations);
}

fn decode_lifecycle_debt(decoder: &mut Decoder<'_>) -> Result<ActorLifecycleDebt, DecodeError> {
    Ok(ActorLifecycleDebt {
        children: decoder.u32()?,
        continuations: decoder.u32()?,
        inbox: decoder.u32()?,
        outbox: decoder.u32()?,
        schedules: decoder.u32()?,
        proof_artifacts: decoder.u32()?,
        lifecycle_operations: decoder.u32()?,
    })
}

fn encode_resource_usage(encoder: &mut Encoder<'_>, value: RuntimeResourceUsage) {
    encoder.u32(value.actors);
    encoder.u8(value.active_machines);
    encoder.u32(value.continuations);
    encoder.u32(value.inbox);
    encoder.u32(value.outbox);
    encoder.u32(value.schedules);
    encoder.u32(value.proof_artifacts);
    encoder.u32(value.state_bytes);
    encoder.u32(value.artifact_references);
    encoder.u64(value.artifact_referenced_bytes);
    encoder.u64(value.proof_material_bytes);
}

fn decode_resource_usage(decoder: &mut Decoder<'_>) -> Result<RuntimeResourceUsage, DecodeError> {
    let value = RuntimeResourceUsage {
        actors: decoder.u32()?,
        active_machines: decoder.u8()?,
        continuations: decoder.u32()?,
        inbox: decoder.u32()?,
        outbox: decoder.u32()?,
        schedules: decoder.u32()?,
        proof_artifacts: decoder.u32()?,
        state_bytes: decoder.u32()?,
        artifact_references: decoder.u32()?,
        artifact_referenced_bytes: decoder.u64()?,
        proof_material_bytes: decoder.u64()?,
    };
    if value.actors > STANDARD_MAX_ACTORS
        || value.active_machines > 63
        || value.state_bytes as usize > MAX_RUNTIME_STATE_BYTES
        || value.artifact_references > MAX_CATALOG_ARTIFACT_REFERENCES
        || value.artifact_referenced_bytes > MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        || value.proof_material_bytes > MAX_TRANSITION_PROOF_MATERIAL_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn identity_valid(value: &AgentIdentity) -> bool {
    value.space != SpaceId::ZERO
        && value.agent != AgentId::ZERO
        && value.owner != PrincipalId::ZERO
        && value.runtime_deployment != DeploymentId::ZERO
        && value.runtime_program != ProgramId::ZERO
        && value.runtime_producer != ProducerId::ZERO
        && value.transition_producer != ProducerId::ZERO
        && value.transition_producer != value.runtime_producer
}

pub(crate) fn management_reply_valid(value: &ManagementReply) -> bool {
    match value {
        ManagementReply::Created(identity) | ManagementReply::RuntimeUpgraded(identity) => {
            identity_valid(identity)
        }
        ManagementReply::Actors(page) => page.validate().is_ok(),
        ManagementReply::ManagementHistory(commitment) => *commitment != Hash::ZERO,
        ManagementReply::Resources(usage) => {
            usage.actors <= STANDARD_MAX_ACTORS
                && usage.active_machines <= 63
                && usage.state_bytes as usize <= MAX_RUNTIME_STATE_BYTES
                && usage.artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
                && usage.artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
                && usage.proof_material_bytes <= MAX_TRANSITION_PROOF_MATERIAL_BYTES
        }
        ManagementReply::Installed(entry)
        | ManagementReply::Upgraded(entry)
        | ManagementReply::Suspended(entry)
        | ManagementReply::Resumed(entry) => entry.validate().is_ok(),
        ManagementReply::Removed(actor) => *actor != ActorId::ZERO,
        ManagementReply::ReplicasChanged { generation } => *generation != Hash::ZERO,
        ManagementReply::ResourcePolicySet(policy) => policy.is_valid(),
    }
}

/// Commitment of one exact typed management application reply. Durable
/// issuers use this while pledging an MAA2 before invoking an external signer.
pub fn management_reply_commitment(value: &ManagementReply) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MRC2");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_reply(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/management-reply/v2", &[&bytes])
}

/// Separate domain for a signed terminal guest error. An error may never be
/// confused with a successful management reply in Authority retry state.
pub fn management_error_commitment(value: ManagementError) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MEC1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_management_error(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/management-error/v1", &[&bytes])
}

fn encode_management_reply(encoder: &mut Encoder<'_>, value: &ManagementReply) {
    match value {
        ManagementReply::Created(value) => {
            encoder.u8(0);
            encode_agent_identity(encoder, value);
        }
        ManagementReply::Actors(value) => {
            encoder.u8(1);
            encode_directory_page(encoder, value);
        }
        ManagementReply::Resources(value) => {
            encoder.u8(2);
            encode_resource_usage(encoder, *value);
        }
        ManagementReply::ManagementHistory(value) => {
            encoder.u8(11);
            encoder.fixed(value.as_bytes());
        }
        ManagementReply::Installed(value) => {
            encoder.u8(3);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Upgraded(value) => {
            encoder.u8(4);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Suspended(value) => {
            encoder.u8(5);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Resumed(value) => {
            encoder.u8(6);
            encode_actor_entry(encoder, value);
        }
        ManagementReply::Removed(value) => {
            encoder.u8(7);
            encoder.fixed(value.as_bytes());
        }
        ManagementReply::RuntimeUpgraded(value) => {
            encoder.u8(8);
            encode_agent_identity(encoder, value);
        }
        ManagementReply::ReplicasChanged { generation } => {
            encoder.u8(9);
            encoder.fixed(generation.as_bytes());
        }
        ManagementReply::ResourcePolicySet(policy) => {
            encoder.u8(10);
            encode_runtime_resource_policy(encoder, *policy);
        }
    }
}

fn decode_management_reply(decoder: &mut Decoder<'_>) -> Result<ManagementReply, DecodeError> {
    let value = match decoder.u8()? {
        0 => ManagementReply::Created(decode_agent_identity(decoder)?),
        1 => ManagementReply::Actors(decode_directory_page(decoder)?),
        2 => ManagementReply::Resources(decode_resource_usage(decoder)?),
        11 => ManagementReply::ManagementHistory(Hash(decoder.fixed()?)),
        3 => ManagementReply::Installed(decode_actor_entry(decoder)?),
        4 => ManagementReply::Upgraded(decode_actor_entry(decoder)?),
        5 => ManagementReply::Suspended(decode_actor_entry(decoder)?),
        6 => ManagementReply::Resumed(decode_actor_entry(decoder)?),
        7 => ManagementReply::Removed(ActorId(decoder.fixed()?)),
        8 => ManagementReply::RuntimeUpgraded(decode_agent_identity(decoder)?),
        9 => ManagementReply::ReplicasChanged {
            generation: Hash(decoder.fixed()?),
        },
        10 => ManagementReply::ResourcePolicySet(decode_runtime_resource_policy(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    };
    management_reply_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_management_error(encoder: &mut Encoder<'_>, value: ManagementError) {
    match value {
        ManagementError::NotCreated => encoder.u8(0),
        ManagementError::AlreadyCreated => encoder.u8(1),
        ManagementError::NotFound => encoder.u8(2),
        ManagementError::AlreadyExists => encoder.u8(3),
        ManagementError::StaleDeployment => encoder.u8(4),
        ManagementError::UnsupportedRuntime => encoder.u8(5),
        ManagementError::UnsupportedLane => encoder.u8(6),
        ManagementError::Busy(debt) => {
            encoder.u8(7);
            encode_lifecycle_debt(encoder, debt);
        }
        ManagementError::DirectoryFull => encoder.u8(8),
        ManagementError::InvalidRequest => encoder.u8(9),
        ManagementError::AuthoritySequenceRegressed => encoder.u8(10),
        ManagementError::AuthoritySequenceConflict => encoder.u8(11),
        ManagementError::AuthoritySlotRegressed => encoder.u8(12),
        ManagementError::ResourceLimit => encoder.u8(13),
        ManagementError::ExpiredBeforeApplication => encoder.u8(14),
    }
}

fn decode_management_error(decoder: &mut Decoder<'_>) -> Result<ManagementError, DecodeError> {
    match decoder.u8()? {
        0 => Ok(ManagementError::NotCreated),
        1 => Ok(ManagementError::AlreadyCreated),
        2 => Ok(ManagementError::NotFound),
        3 => Ok(ManagementError::AlreadyExists),
        4 => Ok(ManagementError::StaleDeployment),
        5 => Ok(ManagementError::UnsupportedRuntime),
        6 => Ok(ManagementError::UnsupportedLane),
        7 => Ok(ManagementError::Busy(decode_lifecycle_debt(decoder)?)),
        8 => Ok(ManagementError::DirectoryFull),
        9 => Ok(ManagementError::InvalidRequest),
        10 => Ok(ManagementError::AuthoritySequenceRegressed),
        11 => Ok(ManagementError::AuthoritySequenceConflict),
        12 => Ok(ManagementError::AuthoritySlotRegressed),
        13 => Ok(ManagementError::ResourceLimit),
        14 => Ok(ManagementError::ExpiredBeforeApplication),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_observation(encoder: &mut Encoder<'_>, value: InvocationObservation) {
    encoder.option(&value.linear_revision, |encoder, value| encoder.u64(*value));
    encode_optional_hash(encoder, &value.merge_frontier);
    encoder.option(&value.local_revision, |encoder, value| encoder.u64(*value));
}

fn decode_observation(decoder: &mut Decoder<'_>) -> Result<InvocationObservation, DecodeError> {
    let value = InvocationObservation {
        linear_revision: decoder.option(|decoder| decoder.u64())?,
        merge_frontier: decode_optional_hash(decoder)?,
        local_revision: decoder.option(|decoder| decoder.u64())?,
    };
    if value.merge_frontier == Some(Hash::ZERO) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn invocation_reply_valid(value: &InvocationReply) -> bool {
    value.invocation != InvocationId::ZERO
        && value.actor != ActorId::ZERO
        && value.incarnation != Hash::ZERO
        && value.deployment != DeploymentId::ZERO
        && value.lane == value.mode.write_lane()
        && value.reply.len() <= MAX_INVOCATION_REPLY_BYTES
        && value.observation.merge_frontier != Some(Hash::ZERO)
}

fn encode_invocation_reply(encoder: &mut Encoder<'_>, value: &InvocationReply) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.u8(value.mode as u8);
    encoder.option(&value.lane, |encoder, value| encode_lane(encoder, *value));
    encoder.u8(value.status as u8);
    encoder.bytes(&value.reply);
    encoder.u64(value.gas_remaining);
    encode_observation(encoder, value.observation);
}

fn decode_invocation_reply(decoder: &mut Decoder<'_>) -> Result<InvocationReply, DecodeError> {
    let value = InvocationReply {
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        lane: decoder.option(decode_lane)?,
        status: match decoder.u8()? {
            0 => InvocationStatus::Done,
            1 => InvocationStatus::Forbidden,
            2 => InvocationStatus::Panicked,
            3 => InvocationStatus::OutOfGas,
            _ => return Err(DecodeError::InvalidTag),
        },
        reply: decoder.bytes_bounded(MAX_INVOCATION_REPLY_BYTES)?,
        gas_remaining: decoder.u64()?,
        observation: decode_observation(decoder)?,
    };
    invocation_reply_valid(&value)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_acknowledgement(encoder: &mut Encoder<'_>, value: &InvocationAcknowledgement) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.u8(value.mode as u8);
    encoder.fixed(value.work.as_bytes());
    encoder.fixed(value.authorization.as_bytes());
}

fn decode_invocation_acknowledgement(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationAcknowledgement, DecodeError> {
    let value = InvocationAcknowledgement {
        invocation: InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        mode: decode_method_mode(decoder)?,
        work: Hash(decoder.fixed()?),
        authorization: Hash(decoder.fixed()?),
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_error(encoder: &mut Encoder<'_>, value: InvocationError) {
    match value {
        InvocationError::NotCreated => encoder.u8(0),
        InvocationError::NotFound => encoder.u8(1),
        InvocationError::StaleIncarnation => encoder.u8(2),
        InvocationError::Suspended => encoder.u8(3),
        InvocationError::StaleDeployment => encoder.u8(4),
        InvocationError::WrongProgram => encoder.u8(5),
        InvocationError::UnsupportedMethod => encoder.u8(6),
        InvocationError::UnsupportedResultStorage => encoder.u8(7),
        InvocationError::MissingState => encoder.u8(8),
        InvocationError::InvalidAvailability => encoder.u8(9),
        InvocationError::InvalidInput => encoder.u8(10),
        InvocationError::InvalidActorOutput => encoder.u8(11),
        InvocationError::DivergentInvocation => encoder.u8(12),
        InvocationError::ResultCapacity => encoder.u8(13),
        InvocationError::InvalidAuthorization => encoder.u8(14),
        InvocationError::AuthorityExpired => encoder.u8(15),
        InvocationError::AuthoritySlotRegressed => encoder.u8(16),
        InvocationError::UnsupportedHostCall(call) => {
            encoder.u8(17);
            encoder.u64(call);
        }
        InvocationError::StaleContinuation => encoder.u8(18),
        InvocationError::NotReady => encoder.u8(19),
        InvocationError::ExpiredBeforeExecution => encoder.u8(20),
    }
}

fn decode_invocation_error(decoder: &mut Decoder<'_>) -> Result<InvocationError, DecodeError> {
    match decoder.u8()? {
        0 => Ok(InvocationError::NotCreated),
        1 => Ok(InvocationError::NotFound),
        2 => Ok(InvocationError::StaleIncarnation),
        3 => Ok(InvocationError::Suspended),
        4 => Ok(InvocationError::StaleDeployment),
        5 => Ok(InvocationError::WrongProgram),
        6 => Ok(InvocationError::UnsupportedMethod),
        7 => Ok(InvocationError::UnsupportedResultStorage),
        8 => Ok(InvocationError::MissingState),
        9 => Ok(InvocationError::InvalidAvailability),
        10 => Ok(InvocationError::InvalidInput),
        11 => Ok(InvocationError::InvalidActorOutput),
        12 => Ok(InvocationError::DivergentInvocation),
        13 => Ok(InvocationError::ResultCapacity),
        14 => Ok(InvocationError::InvalidAuthorization),
        15 => Ok(InvocationError::AuthorityExpired),
        16 => Ok(InvocationError::AuthoritySlotRegressed),
        17 => Ok(InvocationError::UnsupportedHostCall(decoder.u64()?)),
        18 => Ok(InvocationError::StaleContinuation),
        19 => Ok(InvocationError::NotReady),
        20 => Ok(InvocationError::ExpiredBeforeExecution),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_yield_reason(encoder: &mut Encoder<'_>, value: YieldReason) {
    match value {
        YieldReason::Cooperative => encoder.u8(0),
        YieldReason::Await { call } => {
            encoder.u8(1);
            encoder.fixed(call.as_bytes());
        }
    }
}

fn decode_yield_reason(decoder: &mut Decoder<'_>) -> Result<YieldReason, DecodeError> {
    match decoder.u8()? {
        0 => Ok(YieldReason::Cooperative),
        1 => {
            let call = CallId(decoder.fixed()?);
            if call == CallId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(YieldReason::Await { call })
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_yielded(encoder: &mut Encoder<'_>, value: &YieldedInvocation) {
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.program.as_bytes());
    encoder.u8(value.mode as u8);
    encode_blob(encoder, &value.continuation);
    encoder.u64(value.ready_sequence);
    encode_optional_blob(encoder, &value.installation_data);
    encode_required_refs(encoder, &value.required);
    encode_yield_reason(encoder, value.reason);
}

fn decode_yielded(decoder: &mut Decoder<'_>) -> Result<YieldedInvocation, DecodeError> {
    let invocation = InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder)?;
    let continuation = decode_blob(decoder)?;
    let ready_sequence = decoder.u64()?;
    let installation_data = decode_optional_blob(decoder)?;
    let required = decode_required_refs(decoder, installation_data.as_ref())?;
    let value = YieldedInvocation {
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        continuation,
        ready_sequence,
        installation_data,
        required,
        reason: decode_yield_reason(decoder)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_runtime_outcome(encoder: &mut Encoder<'_>, value: &RuntimeOutcome) {
    match value {
        RuntimeOutcome::Management(result) => {
            encoder.u8(0);
            match result {
                Ok(reply) => {
                    encoder.bool(true);
                    encode_management_reply(encoder, reply);
                }
                Err(error) => {
                    encoder.bool(false);
                    encode_management_error(encoder, *error);
                }
            }
        }
        RuntimeOutcome::Completed(result) => {
            encoder.u8(1);
            match result {
                Ok(reply) => {
                    encoder.bool(true);
                    encode_invocation_reply(encoder, reply);
                }
                Err(error) => {
                    encoder.bool(false);
                    encode_invocation_error(encoder, *error);
                }
            }
        }
        RuntimeOutcome::Yielded(value) => {
            encoder.u8(2);
            encode_yielded(encoder, value);
        }
        RuntimeOutcome::Acknowledged(result) => {
            encoder.u8(3);
            match result {
                Ok(acknowledgement) => {
                    encoder.bool(true);
                    encode_invocation_acknowledgement(encoder, acknowledgement);
                }
                Err(error) => {
                    encoder.bool(false);
                    encode_invocation_error(encoder, *error);
                }
            }
        }
    }
}

fn decode_runtime_outcome(decoder: &mut Decoder<'_>) -> Result<RuntimeOutcome, DecodeError> {
    match decoder.u8()? {
        0 => Ok(RuntimeOutcome::Management(if decoder.bool()? {
            Ok(decode_management_reply(decoder)?)
        } else {
            Err(decode_management_error(decoder)?)
        })),
        1 => Ok(RuntimeOutcome::Completed(if decoder.bool()? {
            Ok(decode_invocation_reply(decoder)?)
        } else {
            Err(decode_invocation_error(decoder)?)
        })),
        2 => Ok(RuntimeOutcome::Yielded(decode_yielded(decoder)?)),
        3 => Ok(RuntimeOutcome::Acknowledged(if decoder.bool()? {
            Ok(decode_invocation_acknowledgement(decoder)?)
        } else {
            Err(decode_invocation_error(decoder)?)
        })),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for RuntimeTransition {
    const MAGIC: [u8; 4] = *b"ATRN";
    const MAX_ENCODED_BYTES: usize = MAX_RUNTIME_TRANSITION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_runtime_state(encoder, &self.state);
        encode_runtime_outcome(encoder, &self.outcome);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            state: decode_runtime_state(decoder)?,
            outcome: decode_runtime_outcome(decoder)?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

use crate::private::{
    ED25519_TRANSPORT_PEER_ID_BYTES, EncryptedObjectKind, EncryptedPrivateObject,
    MAX_PRIVATE_CIPHERTEXT_BYTES, MAX_PRIVATE_INVITE_HISTORY_EPOCHS, MAX_PRIVATE_NODES,
    MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES, MAX_SEALED_KEY_BYTES,
    MAX_TRANSPORT_IDENTITY_BYTES, NodeEncryptionEnrollment,
    PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES, PRIVATE_NONCE_BYTES, PRIVATE_SIGNATURE_BYTES,
    PrivateActorLifecycleKind, PrivateControlOperation, PrivateControlRecord, PrivateControlSigner,
    PrivateInviteHistoryGrant, PrivateKeyEpoch, PrivateNodeIdentity, PrivateRecoveryKeyringGrant,
    SealedPrivateKey, SealedRecoveryKey,
};

pub const MAX_NODE_ENCRYPTION_ENROLLMENT_WIRE_BYTES: usize = 512;
pub const MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES: usize = 1_024;
pub const MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES: usize = HEADER_BYTES
    + 192
    + (32 + 4 + MAX_SEALED_KEY_BYTES)
    + 2 * MAX_PRIVATE_NODES * (32 + 32 + 4 + MAX_SEALED_KEY_BYTES);
pub const MAX_PRIVATE_RECOVERY_KEYRING_GRANT_WIRE_BYTES: usize = HEADER_BYTES
    + 256
    + MAX_PRIVATE_NODES * (32 + 32 + 4 + MAX_SEALED_KEY_BYTES)
    + MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES;
pub const MAX_PRIVATE_INVITE_HISTORY_GRANT_WIRE_BYTES: usize =
    7 * 32 + 8 + 32 + 32 + 4 + PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES;
pub const MAX_PRIVATE_CONTROL_WIRE_BYTES: usize = HEADER_BYTES
    + MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES
    + MAX_PRIVATE_RECOVERY_KEYRING_GRANT_WIRE_BYTES
    + MAX_PRIVATE_INVITE_HISTORY_EPOCHS * MAX_PRIVATE_INVITE_HISTORY_GRANT_WIRE_BYTES
    + MAX_PRIVATE_NODES * (MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES + 32)
    + 512;
pub const MAX_PRIVATE_OBJECT_WIRE_BYTES: usize =
    HEADER_BYTES + 32 + 32 + 8 + 1 + 32 + PRIVATE_NONCE_BYTES + 4 + MAX_PRIVATE_CIPHERTEXT_BYTES;

fn encode_node_encryption_enrollment_fields(
    encoder: &mut Encoder<'_>,
    value: &NodeEncryptionEnrollment,
) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.principal.as_bytes());
    encoder.fixed(value.node.as_bytes());
    encoder.0.extend_from_slice(&value.transport_public_key);
    encoder.0.extend_from_slice(&value.transport_peer_id);
    encoder.0.extend_from_slice(&value.encryption_public_key);
}

fn encode_node_encryption_enrollment_wire(value: &NodeEncryptionEnrollment) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_NODE_ENCRYPTION_ENROLLMENT_WIRE_BYTES);
    bytes.extend_from_slice(b"NEN1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_node_encryption_enrollment_fields(&mut Encoder(&mut bytes), value);
    bytes.extend_from_slice(&value.transport_signature);
    bytes
}

/// Exact Ed25519 possession-proof preimage. This is deliberately a sibling
/// domain of the full `NEN1` wire so a signature cannot be replayed as any
/// other canonical message or over a representation which already contains
/// the signature.
pub(crate) fn node_encryption_enrollment_signing_bytes(
    value: &NodeEncryptionEnrollment,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_NODE_ENCRYPTION_ENROLLMENT_WIRE_BYTES);
    bytes.extend_from_slice(b"NES1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_node_encryption_enrollment_fields(&mut Encoder(&mut bytes), value);
    bytes
}

impl CanonicalWire for NodeEncryptionEnrollment {
    const MAGIC: [u8; 4] = *b"NEN1";
    const MAX_ENCODED_BYTES: usize = MAX_NODE_ENCRYPTION_ENROLLMENT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        let nested = encode_node_encryption_enrollment_wire(self);
        encoder.0.extend_from_slice(&nested[HEADER_BYTES..]);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            space: SpaceId(decoder.fixed()?),
            principal: PrincipalId(decoder.fixed()?),
            node: NodeId(decoder.fixed()?),
            transport_public_key: decoder
                .take(32)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            transport_peer_id: decoder
                .take(ED25519_TRANSPORT_PEER_ID_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            encryption_public_key: decoder
                .take(32)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            transport_signature: decoder
                .take(PRIVATE_SIGNATURE_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        };
        value
            .validate_shape()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

pub(crate) fn encode_private_node(encoder: &mut Encoder<'_>, value: &PrivateNodeIdentity) {
    encoder.fixed(value.node.as_bytes());
    encoder.fixed(value.principal.as_bytes());
    encoder.bytes(&value.transport_identity);
    encoder.0.extend_from_slice(&value.encryption_public_key);
    encoder.fixed(value.authority_binding.as_bytes());
    encoder.0.extend_from_slice(&value.transport_signature);
}

/// Commitment carried by an AOC3 Private Invite for one exact enrolled
/// transport/encryption identity.
///
/// This public computation lets an authority guest compare the compact AOC3
/// field with its verified NEN1 row without trusting a caller-supplied second
/// encoding of the identity.
pub fn authority_private_node_identity_commitment(value: &PrivateNodeIdentity) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APNI");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_private_node(&mut Encoder(&mut bytes), value);
    Hash::digest(b"vos/agent/authority-private-node/v1", &[&bytes])
}

fn decode_private_node(decoder: &mut Decoder<'_>) -> Result<PrivateNodeIdentity, DecodeError> {
    let value = PrivateNodeIdentity {
        node: NodeId(decoder.fixed()?),
        principal: PrincipalId(decoder.fixed()?),
        transport_identity: decoder.bytes_bounded(MAX_TRANSPORT_IDENTITY_BYTES)?,
        encryption_public_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        authority_binding: Hash(decoder.fixed()?),
        transport_signature: decoder
            .take(PRIVATE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for PrivateNodeIdentity {
    const MAGIC: [u8; 4] = *b"PNID";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_NODE_IDENTITY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_node(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_node(decoder)
    }
}

fn encode_sealed_key(encoder: &mut Encoder<'_>, value: &SealedPrivateKey) {
    encoder.fixed(value.node.as_bytes());
    encoder.0.extend_from_slice(&value.recipient_key);
    encoder.bytes(&value.sealed);
}

fn decode_sealed_key(decoder: &mut Decoder<'_>) -> Result<SealedPrivateKey, DecodeError> {
    let value = SealedPrivateKey {
        node: NodeId(decoder.fixed()?),
        recipient_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        sealed: decoder.bytes_bounded(MAX_SEALED_KEY_BYTES)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_private_invite_history_grant(
    encoder: &mut Encoder<'_>,
    value: &PrivateInviteHistoryGrant,
) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(value.owner.as_bytes());
    encoder.fixed(value.transition.as_bytes());
    encoder.fixed(value.recipient.as_bytes());
    encoder.0.extend_from_slice(&value.recipient_key);
    encoder.u64(value.epoch);
    encoder.fixed(value.data_key_commitment.as_bytes());
    encode_sealed_key(encoder, &value.sealed_data_key);
}

fn decode_private_invite_history_grant(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateInviteHistoryGrant, DecodeError> {
    let value = PrivateInviteHistoryGrant {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        owner: PrincipalId(decoder.fixed()?),
        transition: Hash(decoder.fixed()?),
        recipient: NodeId(decoder.fixed()?),
        recipient_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        epoch: decoder.u64()?,
        data_key_commitment: Hash(decoder.fixed()?),
        sealed_data_key: decode_sealed_key(decoder)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_sealed_recovery_key(encoder: &mut Encoder<'_>, value: &SealedRecoveryKey) {
    encoder.0.extend_from_slice(&value.recipient_key);
    encoder.bytes(&value.sealed);
}

fn decode_sealed_recovery_key(decoder: &mut Decoder<'_>) -> Result<SealedRecoveryKey, DecodeError> {
    let value = SealedRecoveryKey {
        recipient_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        sealed: decoder.bytes_bounded(MAX_SEALED_KEY_BYTES)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_private_epoch(encoder: &mut Encoder<'_>, value: &PrivateKeyEpoch) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.u64(value.epoch);
    encoder.fixed(value.owner_key_commitment.as_bytes());
    encoder.fixed(value.data_key_commitment.as_bytes());
    encoder.fixed(value.recovery_key_commitment.as_bytes());
    encoder
        .0
        .extend_from_slice(&value.recovery_encryption_public_key);
    encode_sealed_recovery_key(encoder, &value.sealed_recovery_data_key);
    encoder.list(&value.sealed_owner_keys, encode_sealed_key);
    encoder.list(&value.sealed_data_keys, encode_sealed_key);
}

fn decode_private_epoch(decoder: &mut Decoder<'_>) -> Result<PrivateKeyEpoch, DecodeError> {
    let value = PrivateKeyEpoch {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        epoch: decoder.u64()?,
        owner_key_commitment: Hash(decoder.fixed()?),
        data_key_commitment: Hash(decoder.fixed()?),
        recovery_key_commitment: Hash(decoder.fixed()?),
        recovery_encryption_public_key: decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        sealed_recovery_data_key: decode_sealed_recovery_key(decoder)?,
        sealed_owner_keys: decoder.list_bounded(MAX_PRIVATE_NODES, decode_sealed_key)?,
        sealed_data_keys: decoder.list_bounded(MAX_PRIVATE_NODES, decode_sealed_key)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

impl CanonicalWire for PrivateKeyEpoch {
    const MAGIC: [u8; 4] = *b"PKEY";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_KEY_EPOCH_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_epoch(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_private_epoch(decoder)
    }
}

fn encode_encrypted_kind(encoder: &mut Encoder<'_>, value: EncryptedObjectKind) {
    encoder.u8(value as u8);
}

fn encode_encrypted_private_object_body(encoder: &mut Encoder<'_>, value: &EncryptedPrivateObject) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.u64(value.epoch);
    encode_encrypted_kind(encoder, value.kind);
    encoder.fixed(value.content.as_bytes());
    encoder.0.extend_from_slice(&value.nonce);
    encoder.bytes(&value.ciphertext);
}

fn decode_encrypted_private_object_body(
    decoder: &mut Decoder<'_>,
    maximum_ciphertext_bytes: usize,
) -> Result<EncryptedPrivateObject, DecodeError> {
    let value = EncryptedPrivateObject {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        epoch: decoder.u64()?,
        kind: decode_encrypted_kind(decoder)?,
        content: Hash(decoder.fixed()?),
        nonce: decoder
            .take(PRIVATE_NONCE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?,
        ciphertext: decoder.bytes_bounded(maximum_ciphertext_bytes)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_encrypted_kind(decoder: &mut Decoder<'_>) -> Result<EncryptedObjectKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(EncryptedObjectKind::CrdtNode),
        1 => Ok(EncryptedObjectKind::Package),
        2 => Ok(EncryptedObjectKind::Blob),
        3 => Ok(EncryptedObjectKind::Index),
        4 => Ok(EncryptedObjectKind::Snapshot),
        5 => Ok(EncryptedObjectKind::Control),
        _ => Err(DecodeError::InvalidTag),
    }
}

impl CanonicalWire for EncryptedPrivateObject {
    const MAGIC: [u8; 4] = *b"POBJ";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_OBJECT_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_encrypted_private_object_body(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_encrypted_private_object_body(decoder, MAX_PRIVATE_CIPHERTEXT_BYTES)
    }
}

pub(crate) fn encode_private_recovery_keyring_grant(
    encoder: &mut Encoder<'_>,
    value: &PrivateRecoveryKeyringGrant,
) {
    encoder.fixed(value.key_commitment.as_bytes());
    encoder.list(&value.sealed_keys, encode_sealed_key);
    encode_encrypted_private_object_body(encoder, &value.ciphertext);
}

fn decode_private_recovery_keyring_grant(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateRecoveryKeyringGrant, DecodeError> {
    let value = PrivateRecoveryKeyringGrant {
        key_commitment: Hash(decoder.fixed()?),
        sealed_keys: decoder.list_bounded(MAX_PRIVATE_NODES, decode_sealed_key)?,
        ciphertext: decode_encrypted_private_object_body(
            decoder,
            MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES,
        )?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_private_lifecycle_kind(encoder: &mut Encoder<'_>, value: PrivateActorLifecycleKind) {
    encoder.u8(value as u8);
}

fn decode_private_lifecycle_kind(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateActorLifecycleKind, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PrivateActorLifecycleKind::Install),
        1 => Ok(PrivateActorLifecycleKind::Upgrade),
        2 => Ok(PrivateActorLifecycleKind::Suspend),
        3 => Ok(PrivateActorLifecycleKind::Resume),
        4 => Ok(PrivateActorLifecycleKind::Remove),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_private_operation(encoder: &mut Encoder<'_>, value: &PrivateControlOperation) {
    match value {
        PrivateControlOperation::Invite {
            node,
            epoch,
            sealed_owner_key,
            sealed_data_key,
            historical_grants,
        } => {
            encoder.u8(0);
            encode_private_node(encoder, node);
            encoder.u64(*epoch);
            encode_sealed_key(encoder, sealed_owner_key);
            encode_sealed_key(encoder, sealed_data_key);
            encoder.list(historical_grants, encode_private_invite_history_grant);
        }
        PrivateControlOperation::Revoke { node, next_epoch } => {
            encoder.u8(1);
            encoder.fixed(node.as_bytes());
            encode_private_epoch(encoder, next_epoch);
        }
        PrivateControlOperation::RotateKeys { next_epoch } => {
            encoder.u8(2);
            encode_private_epoch(encoder, next_epoch);
        }
        PrivateControlOperation::SetResourcePolicy { policy } => {
            encoder.u8(3);
            encode_blob(encoder, policy);
        }
        PrivateControlOperation::ActorLifecycle {
            actor,
            operation,
            request,
        } => {
            encoder.u8(4);
            encoder.fixed(actor.as_bytes());
            encode_private_lifecycle_kind(encoder, *operation);
            encoder.fixed(request.as_bytes());
        }
        PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
            historical_keyring,
        } => {
            encoder.u8(5);
            encoder.list(superseded_heads, |encoder, value| {
                encoder.fixed(value.as_bytes())
            });
            encode_private_epoch(encoder, next_epoch);
            encoder.list(replacement_nodes, encode_private_node);
            encode_private_recovery_keyring_grant(encoder, historical_keyring);
        }
    }
}

fn decode_private_operation(
    decoder: &mut Decoder<'_>,
) -> Result<PrivateControlOperation, DecodeError> {
    match decoder.u8()? {
        0 => Ok(PrivateControlOperation::Invite {
            node: decode_private_node(decoder)?,
            epoch: decoder.u64()?,
            sealed_owner_key: decode_sealed_key(decoder)?,
            sealed_data_key: decode_sealed_key(decoder)?,
            historical_grants: decoder.list_bounded(
                MAX_PRIVATE_INVITE_HISTORY_EPOCHS,
                decode_private_invite_history_grant,
            )?,
        }),
        1 => Ok(PrivateControlOperation::Revoke {
            node: NodeId(decoder.fixed()?),
            next_epoch: decode_private_epoch(decoder)?,
        }),
        2 => Ok(PrivateControlOperation::RotateKeys {
            next_epoch: decode_private_epoch(decoder)?,
        }),
        3 => Ok(PrivateControlOperation::SetResourcePolicy {
            policy: decode_blob(decoder)?,
        }),
        4 => Ok(PrivateControlOperation::ActorLifecycle {
            actor: ActorId(decoder.fixed()?),
            operation: decode_private_lifecycle_kind(decoder)?,
            request: Hash(decoder.fixed()?),
        }),
        5 => Ok(PrivateControlOperation::Recover {
            superseded_heads: decoder
                .list_bounded(MAX_PRIVATE_NODES, |decoder| Ok(Hash(decoder.fixed()?)))?,
            next_epoch: decode_private_epoch(decoder)?,
            replacement_nodes: decoder.list_bounded(MAX_PRIVATE_NODES, decode_private_node)?,
            historical_keyring: decode_private_recovery_keyring_grant(decoder)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_private_control_unsigned(encoder: &mut Encoder<'_>, value: &PrivateControlRecord) {
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.u64(value.sequence);
    encode_optional_hash(encoder, &value.previous);
    encode_private_operation(encoder, &value.operation);
    encoder.u8(value.signer as u8);
    encoder.0.extend_from_slice(&value.signer_public_key);
}

pub(crate) fn private_control_signing_bytes(value: &PrivateControlRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PCSG");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    encode_private_control_unsigned(&mut Encoder(&mut bytes), value);
    bytes
}

pub(crate) fn private_invite_transition_binding(value: &PrivateControlRecord) -> Option<Hash> {
    let PrivateControlOperation::Invite {
        node,
        epoch,
        sealed_owner_key,
        sealed_data_key,
        ..
    } = &value.operation
    else {
        return None;
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.fixed(value.space.as_bytes());
    encoder.fixed(value.agent.as_bytes());
    encoder.fixed(node.principal.as_bytes());
    encoder.u64(value.sequence);
    encode_optional_hash(&mut encoder, &value.previous);
    encode_private_node(&mut encoder, node);
    encoder.u64(*epoch);
    encode_sealed_key(&mut encoder, sealed_owner_key);
    encode_sealed_key(&mut encoder, sealed_data_key);
    Some(Hash::digest(b"vos/private/invite-transition/v1", &[&bytes]))
}

impl CanonicalWire for PrivateControlRecord {
    const MAGIC: [u8; 4] = *b"PCTL";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_CONTROL_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_private_control_unsigned(encoder, self);
        encoder.0.extend_from_slice(&self.signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let space = SpaceId(decoder.fixed()?);
        let agent = AgentId(decoder.fixed()?);
        let sequence = decoder.u64()?;
        let previous = decode_optional_hash(decoder)?;
        let operation = decode_private_operation(decoder)?;
        let signer = match decoder.u8()? {
            0 => PrivateControlSigner::Owner,
            1 => PrivateControlSigner::Recovery,
            _ => return Err(DecodeError::InvalidTag),
        };
        let signer_public_key = decoder
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let signature = decoder
            .take(PRIVATE_SIGNATURE_BYTES)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let value = Self {
            space,
            agent,
            sequence,
            previous,
            operation,
            signer,
            signer_public_key,
            signature,
        };
        value
            .validate_shape()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(byte: u8) -> BlobRef {
        BlobRef {
            hash: Hash([byte; 32]),
            len: 1,
        }
    }

    fn actor(byte: u8) -> ActorEntry {
        ActorEntry {
            actor: ActorId([byte; 32]),
            name: alloc::format!("actor-{byte}"),
            parent: None,
            deployment: DeploymentId([byte.wrapping_add(1); 32]),
            program: ProgramId([byte.wrapping_add(2); 32]),
            package: blob(byte.wrapping_add(3)),
            agent_schema: blob(byte.wrapping_add(4)),
            method_policy: blob(byte.wrapping_add(5)),
            constructor_abi: Hash([byte.wrapping_add(6); 32]),
            installation_data: Some(blob(byte.wrapping_add(7))),
            state_layout: Hash([byte.wrapping_add(8); 32]),
            lanes: LaneSet::of(StateLane::Linear),
            suspended: false,
        }
    }

    fn authority_actor_target() -> AuthorityActorTarget {
        let public_key = [0x28; AUTHORITY_PUBLIC_KEY_BYTES];
        AuthorityActorTarget {
            space: SpaceId([0x21; 32]),
            system_agent: AgentId([0x22; 32]),
            system_runtime_deployment: DeploymentId([0x23; 32]),
            binding: AgentAuthorityBinding {
                policy: Hash([0x20; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x24; 32]),
                    actor: ActorId([0x25; 32]),
                    deployment: DeploymentId([0x26; 32]),
                    program: ProgramId([0x27; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
        }
    }

    fn managed_agent_target() -> ManagedAgentTarget {
        ManagedAgentTarget {
            space: authority_actor_target().space,
            agent: AgentId([0x29; 32]),
            owner: PrincipalId([0x2b; 32]),
            profile: AgentProfile::Shared,
            runtime_deployment: DeploymentId([0x2a; 32]),
            transition_producer: ProducerId([0x2c; 32]),
        }
    }

    fn authority_credential_call() -> AuthorityCredentialCall {
        let credential_public_key = [0x2b; CREDENTIAL_PUBLIC_KEY_BYTES];
        let plan = ManagementRequest::Suspend {
            actor: ActorId([0x30; 32]),
            expected_deployment: DeploymentId([0x31; 32]),
        }
        .authorization_plan()
        .unwrap();
        let mut call = AuthorityCredentialCall {
            invocation: InvocationId::ZERO,
            authority: authority_actor_target(),
            managed: managed_agent_target(),
            principal: PrincipalId([0x2d; 32]),
            credential: CredentialId::of_public_key(&credential_public_key),
            request_sequence: core::num::NonZeroU64::new(1).unwrap(),
            credential_public_key,
            authenticated_node: Some(NodeId([0x2e; 32])),
            requested_valid_from: 47,
            requested_expires_at: 59,
            plan,
            signature: [0x32; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call
    }

    fn management_approval() -> ManagementApproval {
        let call = authority_credential_call();
        ManagementApproval::from_call(
            &call,
            core::num::NonZeroU64::new(61).unwrap(),
            AuthorityEvidence {
                package: Some(blob(0x33)),
                proof: Some(blob(0x34)),
                commitment: Hash([0x35; 32]),
            },
            AuthorityLaneRoots {
                control: Some(Hash([0x36; 32])),
                linear: Some(Hash([0x37; 32])),
                merge: Some(Hash([0x38; 32])),
                local: None,
            },
            62,
            48,
            58,
        )
        .unwrap()
    }

    fn management_application_ack() -> ManagementApplicationAck {
        let call = authority_credential_call();
        let approval = management_approval();
        let mut applied_actor = actor(0x30);
        applied_actor.suspended = true;
        let actor = approval.plan.authority_actor();
        let receipt = AuthorityReceipt {
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
            signature: [0x50; AUTHORITY_SIGNATURE_BYTES],
        };
        ManagementApplicationAck {
            authorization_invocation: call.invocation,
            acknowledgement_invocation: approval.acknowledgement_invocation,
            authority: approval.authority,
            managed: approval.managed,
            credential_call: call.commitment(),
            approval: approval.commitment(),
            authorization_sequence: approval.authorization_sequence,
            request: approval.plan_commitment,
            application: ManagementReply::Suspended(applied_actor),
            receipt,
            reopened_state: Hash([0x52; 32]),
            applied_at: approval.valid_from,
            signature: [0x53; AUTHORITY_SIGNATURE_BYTES],
        }
    }

    fn authority_admin_call() -> AuthorityAdminCall {
        let credential_public_key = [0x61; CREDENTIAL_PUBLIC_KEY_BYTES];
        let mut call = AuthorityAdminCall {
            invocation: InvocationId::ZERO,
            authority: authority_actor_target(),
            administrator: PrincipalId([0x63; 32]),
            credential: CredentialId::of_public_key(&credential_public_key),
            request_sequence: core::num::NonZeroU64::new(1).unwrap(),
            credential_public_key,
            authenticated_node: NodeId([0x64; 32]),
            observed_slot: 65,
            expected_generation: core::num::NonZeroU64::new(7).unwrap(),
            operation: AuthorityAdminOperation::EnrollPrincipal {
                principal: PrincipalId([0x66; 32]),
                credential: AuthorityCredentialEnrollment::from_public_key(
                    AuthorityCredentialKind::Api,
                    [0x67; CREDENTIAL_PUBLIC_KEY_BYTES],
                ),
            },
            signature: [0x68; CREDENTIAL_SIGNATURE_BYTES],
        };
        call.invocation = call.expected_invocation();
        call
    }

    fn authority_projection_query(
        selector: AuthorityProjectionSelector,
    ) -> AuthorityProjectionQuery {
        let credential_public_key = [0x71; CREDENTIAL_PUBLIC_KEY_BYTES];
        AuthorityProjectionQuery {
            recovery: None,
            authority: authority_actor_target(),
            credential: CredentialId::of_public_key(&credential_public_key),
            nonce: Hash([0x72; 32]),
            selector,
            authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                credential_public_key,
                signature: [0x73; CREDENTIAL_SIGNATURE_BYTES],
            },
        }
    }

    fn authority_projection_head() -> AuthorityProjectionHead {
        AuthorityProjectionHead {
            state_revision: core::num::NonZeroU64::new(10).unwrap(),
            epoch: core::num::NonZeroU64::new(7).unwrap(),
            authorization_sequence: core::num::NonZeroU64::new(8).unwrap(),
            administration_generation: core::num::NonZeroU64::new(9).unwrap(),
            state_commitment: Hash([0x74; 32]),
        }
    }

    fn authority_agent_projection(marker: u8) -> AuthorityAgentProjection {
        let owner = PrincipalId([marker.wrapping_add(1); 32]);
        let creation_nonce = Hash([marker.wrapping_add(2); 32]);
        let identity = AgentIdentity {
            space: authority_actor_target().space,
            agent: AgentId::derive(
                authority_actor_target().space,
                owner,
                creation_nonce.as_bytes(),
            ),
            owner,
            profile: AgentProfile::Private,
            runtime_deployment: DeploymentId([marker.wrapping_add(3); 32]),
            runtime_program: ProgramId([marker.wrapping_add(4); 32]),
            runtime_producer: ProducerId([marker.wrapping_add(5); 32]),
            transition_producer: ProducerId([marker.wrapping_add(0x20); 32]),
        };
        let replicas = alloc::vec![AgentReplica {
            node: NodeId([marker.wrapping_add(6); 32]),
            principal: owner,
            role: ReplicaRole::Observer,
        }];
        let replica_generation = replica_set_generation(&identity, creation_nonce, &replicas);
        AuthorityAgentProjection {
            identity,
            creation_nonce,
            authority: authority_actor_target().binding,
            private_recovery: Some(PrivateRecoveryBinding {
                signing_key_commitment: Hash([marker.wrapping_add(7); 32]),
                encryption_public_key: [0x42; 32],
            }),
            runtime_package: blob(marker.wrapping_add(8)),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replica_count: replicas.len().try_into().unwrap(),
            replica_generation,
        }
    }

    fn authority_actor_projection(agent: AgentId, marker: u8) -> AuthorityActorProjection {
        let entry = actor(marker);
        AuthorityActorProjection {
            agent,
            requirements: RuntimeRequirements {
                lanes: entry.lanes,
                scheduling: true,
                proof_systems: ProofSystemSet::EMPTY,
            },
            entry,
            producer: ProducerId([marker.wrapping_add(9); 32]),
            contract: ActorPackageContract::canonical(),
            root_provenance: false,
            installation_id: InstallationId([marker.wrapping_add(10); 32]),
            registry_reservation: Hash([marker.wrapping_add(11); 32]),
            install_request: Hash([marker.wrapping_add(12); 32]),
        }
    }

    #[test]
    fn authority_actor_protocol_has_bounded_distinct_golden_wires() {
        let call = authority_credential_call();
        let call_bytes = call.encode().unwrap();
        assert_eq!(call_bytes.get(..4), Some(b"ACC3".as_slice()));
        assert!(call_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES);
        assert_eq!(AuthorityCredentialCall::decode(&call_bytes), Ok(call));
        assert_eq!(
            Hash::digest(b"vos/test/acc3-golden", &[&call_bytes]).0,
            [
                0x03, 0x25, 0xfc, 0x8b, 0xd6, 0x5b, 0xd3, 0xbb, 0x3a, 0x49, 0xc0, 0xa9, 0x0f, 0xc0,
                0x3f, 0x28, 0xa0, 0xe6, 0x89, 0xb9, 0x84, 0x7e, 0x50, 0xc6, 0x16, 0x9d, 0x64, 0xb3,
                0x3e, 0x19, 0xde, 0x03,
            ]
        );

        let approval = management_approval();
        let approval_bytes = approval.encode().unwrap();
        assert_eq!(approval_bytes.get(..4), Some(b"MAP2".as_slice()));
        assert!(approval_bytes.len() <= MAX_INVOCATION_REPLY_BYTES);
        assert_eq!(ManagementApproval::decode(&approval_bytes), Ok(approval));
        assert_eq!(
            Hash::digest(b"vos/test/map2-golden", &[&approval_bytes]).0,
            [
                0xe3, 0xc2, 0xf7, 0x03, 0xc0, 0x59, 0x7c, 0x11, 0x9b, 0x67, 0x67, 0xa3, 0x71, 0x68,
                0xe8, 0x02, 0xb2, 0xb9, 0x3c, 0xe8, 0x46, 0xce, 0xbb, 0xd8, 0x92, 0xb2, 0x7f, 0x79,
                0x16, 0xfe, 0x97, 0x85,
            ]
        );

        let acknowledgement = management_application_ack();
        let acknowledgement_bytes = acknowledgement.encode().unwrap();
        assert_eq!(acknowledgement_bytes.get(..4), Some(b"MAA2".as_slice()));
        assert!(acknowledgement_bytes.len() <= MAX_INVOCATION_MESSAGE_BYTES);
        assert_eq!(
            ManagementApplicationAck::decode(&acknowledgement_bytes),
            Ok(acknowledgement.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/maa2-golden", &[&acknowledgement_bytes]).0,
            [
                0x26, 0xa6, 0xa0, 0x42, 0xae, 0xf0, 0x4b, 0x9e, 0xd3, 0x19, 0xbe, 0x64, 0x64, 0x8e,
                0x61, 0xd7, 0x7a, 0x0e, 0xdf, 0x49, 0xf4, 0x66, 0xee, 0x4b, 0x2f, 0xc3, 0x16, 0xd5,
                0x78, 0x99, 0xfb, 0xa6,
            ]
        );

        let mut failure_receipt = acknowledgement.receipt.clone();
        failure_receipt.selector.operation = AuthorityOperationKind::InstallActor;
        let failure = ManagementApplicationFailure {
            authorization_invocation: acknowledgement.authorization_invocation,
            acknowledgement_invocation: acknowledgement.acknowledgement_invocation,
            authority: acknowledgement.authority,
            managed: ManagedAgentTarget {
                profile: crate::AgentProfile::Local,
                ..acknowledgement.managed
            },
            credential_call: acknowledgement.credential_call,
            approval: acknowledgement.approval,
            authorization_sequence: acknowledgement.authorization_sequence,
            request: acknowledgement.request,
            receipt: failure_receipt,
            error: crate::ManagementError::AlreadyExists,
            reopened_state: acknowledgement.reopened_state,
            failed_at: acknowledgement.applied_at,
            signature: acknowledgement.signature,
        };
        let failure_bytes = failure.encode().unwrap();
        assert_eq!(failure_bytes.get(..4), Some(b"MAF1".as_slice()));
        assert_eq!(
            ManagementApplicationFailure::decode(&failure_bytes),
            Ok(failure)
        );
        assert!(ManagementApplicationAck::decode(&failure_bytes).is_err());
        assert!(ManagementApplicationFailure::decode(&acknowledgement_bytes).is_err());
    }

    #[test]
    fn authority_admin_call_and_result_are_exact_bounded_clean_wires() {
        let call = authority_admin_call();
        let bytes = call.encode().unwrap();
        assert_eq!(bytes.get(..4), Some(b"AAD4".as_slice()));
        assert!(bytes.len() <= MAX_AUTHORITY_ADMIN_CALL_WIRE_BYTES);
        assert_eq!(AuthorityAdminCall::decode(&bytes), Ok(call.clone()));
        assert_eq!(
            Hash::digest(b"vos/test/aad4-golden", &[&bytes]).0,
            [
                0xd6, 0x96, 0xea, 0x94, 0xb5, 0xb8, 0xb7, 0x4f, 0xe2, 0xfa, 0x76, 0x0e, 0x37, 0x77,
                0xed, 0x03, 0xea, 0x17, 0x9e, 0x1c, 0x2d, 0x1b, 0x25, 0xbb, 0x95, 0x86, 0x38, 0xc1,
                0xd1, 0x0a, 0x62, 0xb2,
            ]
        );

        let result = AuthorityAdminResult::from_call(call.clone()).unwrap();
        let result_bytes = result.encode().unwrap();
        assert_eq!(result_bytes.get(..4), Some(b"AAR4".as_slice()));
        assert!(result_bytes.len() <= MAX_AUTHORITY_ADMIN_RESULT_WIRE_BYTES);
        assert_eq!(
            AuthorityAdminResult::decode(&result_bytes),
            Ok(result.clone())
        );
        assert_eq!(
            Hash::digest(b"vos/test/aar4-golden", &[&result_bytes]).0,
            [
                0x0e, 0x6d, 0x57, 0x28, 0x5d, 0x18, 0x0a, 0x96, 0x24, 0xf2, 0x86, 0x1f, 0x63, 0xc4,
                0x3e, 0x54, 0x02, 0xa8, 0x45, 0xb9, 0x42, 0xc3, 0xa1, 0x86, 0xd9, 0x15, 0xf3, 0xc1,
                0x3c, 0x69, 0x03, 0x8f,
            ]
        );
        assert_ne!(call.commitment(), result.commitment());

        let mut changed_node = call.clone();
        changed_node.authenticated_node = NodeId([0x69; 32]);
        assert_ne!(changed_node.signing_bytes(), call.signing_bytes());
        let mut changed_generation = call.clone();
        changed_generation.expected_generation = core::num::NonZeroU64::new(8).unwrap();
        assert_ne!(changed_generation.signing_bytes(), call.signing_bytes());
        let mut changed_kind = call.clone();
        let AuthorityAdminOperation::EnrollPrincipal { credential, .. } =
            &mut changed_kind.operation
        else {
            unreachable!()
        };
        credential.kind = AuthorityCredentialKind::Ssh;
        assert_ne!(changed_kind.signing_bytes(), call.signing_bytes());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(AuthorityAdminCall::decode(&trailing).is_err());
        let mut previous_generation = bytes.clone();
        previous_generation[..4].copy_from_slice(b"AAD3");
        assert!(AuthorityAdminCall::decode(&previous_generation).is_err());
        let mut previous_result_generation = result_bytes;
        previous_result_generation[..4].copy_from_slice(b"AAR3");
        assert!(AuthorityAdminResult::decode(&previous_result_generation).is_err());
        let mut prior_abi = bytes;
        prior_abi[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert!(AuthorityAdminCall::decode(&prior_abi).is_err());
        let mut unknown_operation = call.encode().unwrap();
        // Header + invocation + full AuthorityActorTarget + caller tuple,
        // request sequence, observed slot, and expected generation precede
        // the operation tag.
        let operation_tag = 36 + 32 + 328 + 32 + 32 + 8 + 32 + 32 + 8 + 8;
        unknown_operation[operation_tag] = 0xff;
        assert!(AuthorityAdminCall::decode(&unknown_operation).is_err());
    }

    #[test]
    fn projection_delegation_preserves_legacy_bytes_and_is_query_only() {
        let mut query = authority_projection_query(AuthorityProjectionSelector::Credential);
        for ssh in [false, true] {
            query.authentication = if ssh {
                AuthorityIngressAuthentication::SshNodeAttestation {
                    credential_public_key: query.credential_public_key(),
                    node: NodeId([0x91; 32]),
                    request_binding: Hash([0x92; 32]),
                    signature: [0x93; 64],
                }
            } else {
                AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: query.credential_public_key(),
                    signature: [0x93; 64],
                }
            };
            query.recovery = None;
            // Reconstruct the pre-extension APQ1/APQS encoding independently.
            let mut unsigned = Vec::new();
            let encoder = &mut Encoder(&mut unsigned);
            encode_authority_actor_target(encoder, query.authority);
            encoder.fixed(query.credential.as_bytes());
            encoder.fixed(query.nonce.as_bytes());
            encode_authority_projection_selector(encoder, query.selector);
            let authentication_offset = encoder.0.len();
            encode_authority_ingress_authentication_unsigned(encoder, query.authentication);
            let mut signing = b"APQS".to_vec();
            signing.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
            signing.extend_from_slice(&unsigned);
            assert_eq!(query.signing_bytes(), signing);
            assert_eq!(
                query.commitment(),
                Hash::digest(
                    b"vos/agent/authority-projection-query/v1",
                    &[&signing, &query.authentication.signature()],
                )
            );
            let mut legacy = b"APQ1".to_vec();
            legacy.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
            legacy.extend_from_slice(&unsigned);
            legacy.extend_from_slice(&query.authentication.signature());
            assert_eq!(query.encode().unwrap(), legacy);
            assert_eq!(AuthorityProjectionQuery::decode(&legacy), Ok(query.clone()));

            query.recovery = Some(AuthorityProjectionRecoveryDelegation {
                generation: Hash([0x94; 32]),
                committee: Hash([0x95; 32]),
                accepted_slot: 42,
                expires_at: 52,
            });
            let delegated = query.encode().unwrap();
            assert_eq!(delegated.len(), legacy.len() + 80);
            let tag_offset = HEADER_BYTES + authentication_offset;
            assert_eq!(delegated[tag_offset], if ssh { 3 } else { 2 });
            assert_eq!(
                AuthorityProjectionQuery::decode(&delegated),
                Ok(query.clone())
            );
            assert_eq!(&query.signing_bytes()[..4], b"APQD");
            assert!(
                decode_authority_ingress_authentication(&mut Decoder::new(
                    &delegated[tag_offset..]
                ),)
                .is_err(),
                "AOC5 must not accept query delegation"
            );
            for end in tag_offset..delegated.len() {
                assert!(AuthorityProjectionQuery::decode(&delegated[..end]).is_err());
            }
            let mut unknown = delegated.clone();
            unknown[tag_offset] = 4;
            assert!(AuthorityProjectionQuery::decode(&unknown).is_err());
            let mut trailing = delegated;
            trailing.push(0);
            assert!(AuthorityProjectionQuery::decode(&trailing).is_err());
        }
    }

    #[test]
    fn authority_projection_wires_are_bounded_complete_and_canonical() {
        let credential_query = authority_projection_query(AuthorityProjectionSelector::Credential);
        let query_bytes = credential_query.encode().unwrap();
        assert_eq!(query_bytes.get(..4), Some(b"APQ1".as_slice()));
        assert!(query_bytes.len() <= MAX_AUTHORITY_PROJECTION_QUERY_WIRE_BYTES);
        assert_eq!(
            AuthorityProjectionQuery::decode(&query_bytes),
            Ok(credential_query.clone())
        );

        let credential = AuthorityCredentialProjection {
            query: credential_query,
            head: authority_projection_head(),
            principal: PrincipalId([0x75; 32]),
            status: AuthorityCredentialStatus::Revoked,
            kind: AuthorityCredentialKind::Api,
            builtin_role: AuthorityBuiltinRole::Developer,
            management_request_high_water: 11,
            operation_request_high_water: 12,
            admin_request_high_water: 13,
            space_roles: alloc::vec![RoleId([0x10; 32]), RoleId([0x11; 32])],
            actor_roles: alloc::vec![AuthorityActorRoleGrant {
                agent: AgentId([0x12; 32]),
                actor: ActorId([0x13; 32]),
                deployment: DeploymentId([0x14; 32]),
                role: RoleId([0x15; 32]),
            }],
            capabilities: alloc::vec![AuthorityCapabilityGrant {
                agent: AgentId([0x16; 32]),
                actor: ActorId([0x17; 32]),
                deployment: DeploymentId([0x18; 32]),
                capability: CapabilityId([0x19; 32]),
            }],
        };
        let credential_bytes = credential.encode().unwrap();
        assert_eq!(credential_bytes.get(..4), Some(b"ACP2".as_slice()));
        let mut credential_v1 = credential_bytes.clone();
        credential_v1[..4].copy_from_slice(b"ACP1");
        assert!(AuthorityCredentialProjection::decode(&credential_v1).is_err());
        assert!(credential_bytes.len() <= MAX_AUTHORITY_CREDENTIAL_PROJECTION_WIRE_BYTES);
        assert_eq!(
            AuthorityCredentialProjection::decode(&credential_bytes),
            Ok(credential)
        );

        let mut agents = alloc::vec![
            authority_agent_projection(0x31),
            authority_agent_projection(0x41),
        ];
        agents.sort_unstable_by_key(|entry| entry.identity.agent);
        let agent_query = authority_projection_query(AuthorityProjectionSelector::Agents {
            after: None,
            limit: 2,
        });
        let agent_page = AuthorityAgentProjectionPage {
            query: agent_query,
            head: authority_projection_head(),
            next: agents.last().map(|entry| entry.identity.agent),
            entries: agents,
        };
        let agent_bytes = agent_page.encode().unwrap();
        assert_eq!(agent_bytes.get(..4), Some(b"AAP2".as_slice()));
        let mut agent_v1 = agent_bytes.clone();
        agent_v1[..4].copy_from_slice(b"AAP1");
        assert!(AuthorityAgentProjectionPage::decode(&agent_v1).is_err());
        assert!(agent_bytes.len() <= MAX_AUTHORITY_AGENT_PROJECTION_PAGE_WIRE_BYTES);
        assert_eq!(
            AuthorityAgentProjectionPage::decode(&agent_bytes),
            Ok(agent_page.clone())
        );
        let projected = &agent_page.entries[0];
        assert!(projected.private_recovery.is_some());
        assert!(projected.runtime_contract.is_valid());
        assert_eq!(projected.capabilities, RuntimeCapabilities::standard());

        let replicas = alloc::vec![AgentReplica {
            node: NodeId([0x4a; 32]),
            principal: projected.identity.owner,
            role: ReplicaRole::Observer,
        }];
        let replica_page = AuthorityAgentReplicaProjectionPage {
            query: authority_projection_query(AuthorityProjectionSelector::AgentReplicas {
                agent: projected.identity.agent,
                after: None,
                limit: 1,
            }),
            head: authority_projection_head(),
            replica_count: projected.replica_count,
            replica_generation: projected.replica_generation,
            next: None,
            entries: replicas,
        };
        let replica_bytes = replica_page.encode().unwrap();
        assert_eq!(replica_bytes.get(..4), Some(b"ARP2".as_slice()));
        let mut replica_v1 = replica_bytes.clone();
        replica_v1[..4].copy_from_slice(b"ARP1");
        assert!(AuthorityAgentReplicaProjectionPage::decode(&replica_v1).is_err());
        assert!(replica_bytes.len() <= MAX_AUTHORITY_AGENT_REPLICA_PROJECTION_PAGE_WIRE_BYTES);
        assert_eq!(
            AuthorityAgentReplicaProjectionPage::decode(&replica_bytes),
            Ok(replica_page.clone())
        );
        assert!(replica_page.matches_agent_at_head(projected, agent_page.head));

        let agent = AgentId([0x51; 32]);
        let mut actors = alloc::vec![
            authority_actor_projection(agent, 0x52),
            authority_actor_projection(agent, 0x62),
        ];
        actors.sort_unstable_by_key(|entry| entry.entry.actor);
        let actor_query = authority_projection_query(AuthorityProjectionSelector::Actors {
            agent,
            after: None,
            limit: 2,
        });
        let actor_page = AuthorityActorProjectionPage {
            query: actor_query,
            head: authority_projection_head(),
            next: actors.last().map(|entry| entry.entry.actor),
            entries: actors,
        };
        let actor_bytes = actor_page.encode().unwrap();
        assert_eq!(actor_bytes.get(..4), Some(b"ATP2".as_slice()));
        let mut actor_v1 = actor_bytes.clone();
        actor_v1[..4].copy_from_slice(b"ATP1");
        assert!(AuthorityActorProjectionPage::decode(&actor_v1).is_err());
        assert!(actor_bytes.len() <= MAX_AUTHORITY_ACTOR_PROJECTION_PAGE_WIRE_BYTES);
        assert_eq!(
            AuthorityActorProjectionPage::decode(&actor_bytes),
            Ok(actor_page.clone())
        );
        assert!(actor_page.entries.iter().all(|entry| {
            entry.contract == ActorPackageContract::canonical()
                && entry.requirements.lanes == entry.entry.lanes
                && entry.entry.package.hash != Hash::ZERO
                && entry.entry.agent_schema.hash != Hash::ZERO
                && entry.entry.method_policy.hash != Hash::ZERO
        }));

        let mut reordered = agent_page.clone();
        reordered.entries.swap(0, 1);
        assert_eq!(reordered.encode(), Err(WireError::InvalidValue));
        let mut wrong_cursor = actor_page.clone();
        wrong_cursor.next = Some(ActorId([0xff; 32]));
        assert_eq!(wrong_cursor.encode(), Err(WireError::InvalidValue));
        let mut zero_progress = replica_page;
        zero_progress.entries.clear();
        zero_progress.next = Some(NodeId([0x4a; 32]));
        assert_eq!(zero_progress.encode(), Err(WireError::InvalidValue));
        let mut old_query = query_bytes;
        old_query[..4].copy_from_slice(b"APQ0");
        assert!(AuthorityProjectionQuery::decode(&old_query).is_err());
    }

    fn inventory_page_fixture() -> AuthorityInventoryProjectionPage {
        let row = authority_agent_projection(0x31);
        let agent = row.identity.agent;
        AuthorityInventoryProjectionPage {
            credential: AuthorityCredentialProjection {
                query: authority_projection_query(AuthorityProjectionSelector::Inventory {
                    after: None,
                    limit: 8,
                    known_head: None,
                }),
                head: authority_projection_head(),
                principal: row.identity.owner,
                status: AuthorityCredentialStatus::Active,
                kind: AuthorityCredentialKind::Api,
                builtin_role: AuthorityBuiltinRole::Admin,
                management_request_high_water: 11,
                operation_request_high_water: 12,
                admin_request_high_water: 13,
                space_roles: Vec::new(),
                actor_roles: Vec::new(),
                capabilities: Vec::new(),
            },
            unchanged: false,
            entries: alloc::vec![
                AuthorityInventoryEntry::Agent(row.clone()),
                AuthorityInventoryEntry::Replica {
                    agent,
                    replica: AgentReplica {
                        node: NodeId([0x4a; 32]),
                        principal: row.identity.owner,
                        role: ReplicaRole::Observer,
                    }
                },
                AuthorityInventoryEntry::Actor(authority_actor_projection(agent, 0x52)),
            ],
            next: None,
        }
    }

    #[test]
    fn inventory_stream_wire_is_bounded_ordered_and_query_bound() {
        let mut page = inventory_page_fixture();
        page.next = page.entries.last().map(AuthorityInventoryEntry::cursor);
        let bytes = page.encode().unwrap();
        assert!(bytes.len() <= MAX_INVOCATION_REPLY_BYTES);
        assert_eq!(&bytes[..4], b"AIP1");
        assert_eq!(
            AuthorityInventoryProjectionPage::decode(&bytes),
            Ok(page.clone())
        );
        for length in 0..bytes.len() {
            assert!(AuthorityInventoryProjectionPage::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(AuthorityInventoryProjectionPage::decode(&trailing).is_err());
        assert!(
            AuthorityInventoryProjectionPage::decode(
                &alloc::vec![0; MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES + 1]
            )
            .is_err()
        );
        let query = &page.credential.query;
        let mut changed = query.clone();
        changed.selector = AuthorityProjectionSelector::Inventory {
            after: page.next,
            limit: 8,
            known_head: None,
        };
        assert_ne!(query.signing_bytes(), changed.signing_bytes());
        assert_eq!(
            AuthorityProjectionQuery::decode(&changed.encode().unwrap()),
            Ok(changed.clone())
        );
        changed.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 8,
            known_head: Some(page.credential.head),
        };
        assert_ne!(query.signing_bytes(), changed.signing_bytes());
        assert_eq!(
            AuthorityProjectionQuery::decode(&changed.encode().unwrap()),
            Ok(changed)
        );

        let mut bad = page.clone();
        bad.entries.swap(1, 2);
        assert!(bad.encode().is_err());
        let mut bad = page.clone();
        bad.entries[1] = bad.entries[0].clone();
        assert!(bad.encode().is_err());
        let mut bad = page.clone();
        bad.next = Some(bad.entries[0].cursor());
        assert!(bad.encode().is_err());
        let mut bad = page.clone();
        bad.entries.clear();
        assert!(bad.encode().is_err()); // nonterminal page cannot make no progress
        let mut bad = page.clone();
        bad.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: Some(page.entries[0].cursor()),
            limit: 8,
            known_head: None,
        };
        assert!(bad.encode().is_err()); // exclusive cursor
        let mut bad = page.clone();
        if let AuthorityInventoryEntry::Agent(row) = &mut bad.entries[0] {
            row.authority.initial_epoch += 1;
        }
        assert!(bad.encode().is_err());

        let mut prefix = Vec::new();
        encode_authority_credential_projection_body(&mut Encoder(&mut prefix), &page.credential);
        let mut oversized_count = bytes;
        let count_offset = HEADER_BYTES + prefix.len() + 1;
        oversized_count[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(AuthorityInventoryProjectionPage::decode(&oversized_count).is_err());
    }

    #[test]
    fn inventory_stream_preserves_dense_rosters_with_separate_complex_row_bound() {
        let mut page = inventory_page_fixture();
        let agent = page.entries[0].cursor().agent;
        page.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: Some(AuthorityInventoryCursor {
                agent,
                position: AuthorityInventoryPosition::Agent,
            }),
            limit: 64,
            known_head: None,
        };
        page.entries = (1..=64)
            .map(|marker| AuthorityInventoryEntry::Replica {
                agent,
                replica: AgentReplica {
                    node: NodeId([marker; 32]),
                    principal: page.credential.principal,
                    role: ReplicaRole::Observer,
                },
            })
            .collect();
        let encoded = page.encode().unwrap();
        assert!(encoded.len() + 5 <= MAX_INVOCATION_REPLY_BYTES);
        assert_eq!(
            AuthorityInventoryProjectionPage::decode(&encoded),
            Ok(page.clone())
        );
        page.entries.push(AuthorityInventoryEntry::Replica {
            agent,
            replica: AgentReplica {
                node: NodeId([65; 32]),
                principal: page.credential.principal,
                role: ReplicaRole::Observer,
            },
        });
        assert!(page.encode().is_err());
        page.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 64,
            known_head: None,
        };
        page.entries = (1..=9)
            .map(|marker| AuthorityInventoryEntry::Agent(authority_agent_projection(marker)))
            .collect();
        page.entries.sort_by_key(AuthorityInventoryEntry::cursor);
        assert!(
            page.encode().is_err(),
            "large rows retain an independent eight-row ceiling"
        );
        page.entries.pop();
        assert!(page.encode().is_ok());
        // Both row-count budgets can hold while the aggregate claims + rows
        // exceed the reply byte ceiling. A producer must trim, never truncate.
        page.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: Some(AuthorityInventoryCursor {
                agent,
                position: AuthorityInventoryPosition::Agent,
            }),
            limit: 64,
            known_head: None,
        };
        page.entries = (1..=56)
            .map(|marker| AuthorityInventoryEntry::Replica {
                agent,
                replica: AgentReplica {
                    node: NodeId([marker; 32]),
                    principal: page.credential.principal,
                    role: ReplicaRole::Observer,
                },
            })
            .chain((1..=8).map(|marker| {
                AuthorityInventoryEntry::Actor(authority_actor_projection(agent, marker))
            }))
            .collect();
        page.entries.sort_by_key(AuthorityInventoryEntry::cursor);
        page.credential.capabilities = (1..=64)
            .map(|marker| AuthorityCapabilityGrant {
                agent,
                actor: ActorId([marker; 32]),
                deployment: DeploymentId([1; 32]),
                capability: CapabilityId([1; 32]),
            })
            .collect();
        assert_eq!(page.entries.len(), MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES);
        page.credential.validate_shape().unwrap();
        assert!(
            authority_inventory_projection_page_encoded_len(&page)
                > MAX_AUTHORITY_INVENTORY_PROJECTION_BYTES
        );
        assert!(page.encode().is_err());
        while page.encode().is_err() {
            page.entries.pop().unwrap();
            page.next = page.entries.last().map(AuthorityInventoryEntry::cursor);
        }
        let bytes = page.encode().unwrap();
        assert!(bytes.len() + 5 <= MAX_INVOCATION_REPLY_BYTES);
        assert_eq!(AuthorityInventoryProjectionPage::decode(&bytes), Ok(page));
    }

    #[test]
    fn inventory_stream_unchanged_and_revoked_responses_cannot_carry_rows() {
        let mut page = inventory_page_fixture();
        page.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: None,
            limit: 8,
            known_head: Some(page.credential.head),
        };
        page.unchanged = true;
        assert!(page.encode().is_err());
        page.entries.clear();
        assert_eq!(
            AuthorityInventoryProjectionPage::decode(&page.encode().unwrap()),
            Ok(page.clone())
        );
        let mut bad = page.clone();
        bad.credential.head.state_commitment = Hash([0xee; 32]);
        assert!(bad.encode().is_err());
        let mut bad = page.clone();
        bad.credential.query.selector = AuthorityProjectionSelector::Inventory {
            after: Some(AuthorityInventoryCursor {
                agent: AgentId([1; 32]),
                position: AuthorityInventoryPosition::Agent,
            }),
            limit: 8,
            known_head: Some(page.credential.head),
        };
        assert!(bad.encode().is_err());
        page.credential.status = AuthorityCredentialStatus::Revoked;
        assert!(page.encode().is_err());
        page.unchanged = false;
        assert!(page.encode().is_ok());
        page.entries = inventory_page_fixture().entries;
        assert!(page.encode().is_err());
        for limit in [0, 65, u16::MAX] {
            assert!(
                !AuthorityProjectionSelector::Inventory {
                    after: None,
                    limit,
                    known_head: None
                }
                .validate_shape()
            );
        }
        for position in [
            AuthorityInventoryPosition::Agent,
            AuthorityInventoryPosition::Replica(NodeId::ZERO),
            AuthorityInventoryPosition::Actor(ActorId::ZERO),
        ] {
            assert!(
                !AuthorityInventoryCursor {
                    agent: AgentId::ZERO,
                    position
                }
                .is_valid()
            );
        }
        let agent = AgentId([1; 32]);
        let next_agent = AgentId([2; 32]);
        assert!(
            AuthorityInventoryCursor {
                agent,
                position: AuthorityInventoryPosition::Actor(ActorId([255; 32]))
            } < AuthorityInventoryCursor {
                agent: next_agent,
                position: AuthorityInventoryPosition::Agent
            }
        );
    }

    #[test]
    fn authority_projection_ssh_attestation_wire_binds_stable_request_identity() {
        let credential_public_key = [0x81; CREDENTIAL_PUBLIC_KEY_BYTES];
        let query = AuthorityProjectionQuery {
            recovery: None,
            authority: authority_actor_target(),
            credential: CredentialId::of_public_key(&credential_public_key),
            nonce: Hash([0x82; 32]),
            selector: AuthorityProjectionSelector::Agents {
                after: Some(AgentId([0x83; 32])),
                limit: 3,
            },
            authentication: AuthorityIngressAuthentication::SshNodeAttestation {
                credential_public_key,
                node: NodeId([0x84; 32]),
                request_binding: Hash([0x85; 32]),
                signature: [0x86; CREDENTIAL_SIGNATURE_BYTES],
            },
        };
        let bytes = query.encode().unwrap();
        assert_eq!(AuthorityProjectionQuery::decode(&bytes), Ok(query.clone()));
        let signing = query.signing_bytes();

        let mut rebound = query.clone();
        let AuthorityIngressAuthentication::SshNodeAttestation {
            request_binding, ..
        } = &mut rebound.authentication
        else {
            unreachable!();
        };
        request_binding.0[0] ^= 1;
        assert_ne!(rebound.signing_bytes(), signing);

        let mut zero_binding = query;
        let AuthorityIngressAuthentication::SshNodeAttestation {
            request_binding, ..
        } = &mut zero_binding.authentication
        else {
            unreachable!();
        };
        *request_binding = Hash::ZERO;
        assert_eq!(zero_binding.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn maximum_agent_roster_is_reconstructible_from_bounded_progress_pages() {
        let mut agent = authority_agent_projection(0x91);
        let mut replicas = Vec::with_capacity(MAX_AGENT_REPLICAS);
        for ordinal in 1..=MAX_AGENT_REPLICAS {
            let mut node = [0; 32];
            node[30..].copy_from_slice(&(ordinal as u16).to_be_bytes());
            replicas.push(AgentReplica {
                node: NodeId(node),
                principal: agent.identity.owner,
                role: ReplicaRole::Observer,
            });
        }
        agent.replica_count = replicas.len().try_into().unwrap();
        agent.replica_generation =
            replica_set_generation(&agent.identity, agent.creation_nonce, &replicas);
        assert_eq!(
            agent
                .reconstruct_descriptor(replicas.clone())
                .unwrap()
                .replicas,
            replicas
        );

        let first_entries = replicas[..MAX_AUTHORITY_REPLICA_PAGE_ENTRIES].to_vec();
        let first = AuthorityAgentReplicaProjectionPage {
            query: authority_projection_query(AuthorityProjectionSelector::AgentReplicas {
                agent: agent.identity.agent,
                after: None,
                limit: MAX_AUTHORITY_REPLICA_PAGE_ENTRIES as u16,
            }),
            head: authority_projection_head(),
            replica_count: agent.replica_count,
            replica_generation: agent.replica_generation,
            next: first_entries.last().map(|replica| replica.node),
            entries: first_entries,
        };
        let encoded = first.encode().unwrap();
        assert!(encoded.len() <= MAX_AUTHORITY_AGENT_REPLICA_PROJECTION_PAGE_WIRE_BYTES);
        assert_eq!(
            AuthorityAgentReplicaProjectionPage::decode(&encoded),
            Ok(first.clone())
        );
        let mut duplicate = first;
        duplicate.entries[1] = duplicate.entries[0];
        assert_eq!(duplicate.encode(), Err(WireError::InvalidValue));

        let mut too_many = replicas;
        let mut node = [0xff; 32];
        node[31] = 1;
        too_many.push(AgentReplica {
            node: NodeId(node),
            principal: agent.identity.owner,
            role: ReplicaRole::Observer,
        });
        assert!(agent.reconstruct_descriptor(too_many).is_err());
    }

    #[test]
    fn credential_call_signature_and_commitment_bind_every_identity_target_and_request() {
        let call = authority_credential_call();
        let signing = call.signing_bytes();
        let commitment = call.commitment();
        assert_eq!(signing.get(..4), Some(b"AC3S".as_slice()));

        let mut forced_invocation = call.clone();
        forced_invocation.invocation = InvocationId([0x40; 32]);
        assert!(forced_invocation.validate_shape().is_err());
        assert_ne!(forced_invocation.signing_bytes(), signing);
        assert_ne!(forced_invocation.commitment(), commitment);

        let mut variants = Vec::new();
        let mut value = call.clone();
        value.authority.space = SpaceId([0x41; 32]);
        value.managed.space = value.authority.space;
        variants.push(value);
        let mut value = call.clone();
        value.authority.system_agent = AgentId([0x42; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.system_runtime_deployment = DeploymentId([0x43; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.issuer.principal = PrincipalId([0x44; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.issuer.actor = ActorId([0x45; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.issuer.deployment = DeploymentId([0x46; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.issuer.program = ProgramId([0x47; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.public_key = [0x48; 32];
        value.authority.binding.issuer.producer =
            ProducerId::of_public_key(&value.authority.binding.public_key);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.policy = Hash([0x49; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.public_key = [0x4a; 32];
        value.authority.binding.issuer.producer =
            ProducerId::of_public_key(&value.authority.binding.public_key);
        variants.push(value);
        let mut value = call.clone();
        value.authority.binding.initial_epoch += 1;
        variants.push(value);
        let mut value = call.clone();
        value.managed.agent = AgentId([0x4b; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.managed.runtime_deployment = DeploymentId([0x4c; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.principal = PrincipalId([0x4d; 32]);
        variants.push(value);
        let mut value = call.clone();
        value.credential_public_key = [0x4e; 32];
        value.credential = CredentialId::of_public_key(&value.credential_public_key);
        variants.push(value);
        let mut value = call.clone();
        value.authenticated_node = Some(NodeId([0x4f; 32]));
        variants.push(value);
        let mut value = call.clone();
        value.requested_valid_from += 1;
        variants.push(value);
        let mut value = call.clone();
        value.requested_expires_at += 1;
        variants.push(value);
        let mut value = call.clone();
        value.plan = ManagementRequest::Resume {
            actor: ActorId([0x30; 32]),
            expected_deployment: DeploymentId([0x31; 32]),
        }
        .authorization_plan()
        .unwrap();
        variants.push(value);

        for mut variant in variants {
            variant.invocation = variant.expected_invocation();
            assert_eq!(variant.validate_shape(), Ok(()));
            assert_ne!(variant.signing_bytes(), signing);
            assert_ne!(variant.commitment(), commitment);
        }

        let mut signature_only = call;
        signature_only.signature[0] ^= 1;
        assert_eq!(signature_only.signing_bytes(), signing);
        assert_ne!(signature_only.commitment(), commitment);
    }

    #[test]
    fn management_approval_commitment_binds_policy_output_and_exact_request() {
        let approval = management_approval();
        let commitment = approval.commitment();
        let mut variants = Vec::new();

        let mut value = approval.clone();
        value.authorization_sequence = core::num::NonZeroU64::new(62).unwrap();
        variants.push(value);
        let mut value = approval.clone();
        value.acknowledgement_invocation = InvocationId([0x50; 32]);
        variants.push(value);
        let mut value = approval.clone();
        value.evidence.commitment = Hash([0x51; 32]);
        variants.push(value);
        let mut value = approval.clone();
        value.lane_roots.local = Some(Hash([0x52; 32]));
        variants.push(value);
        let mut value = approval.clone();
        value.epoch += 1;
        variants.push(value);
        let mut value = approval.clone();
        value.valid_from += 1;
        variants.push(value);
        let mut value = approval;
        value.plan = ManagementRequest::Resume {
            actor: ActorId([0x30; 32]),
            expected_deployment: DeploymentId([0x31; 32]),
        }
        .authorization_plan()
        .unwrap();
        value.plan_commitment = value.plan.commitment();
        variants.push(value);

        for variant in variants {
            assert_eq!(variant.validate_shape(), Ok(()));
            assert_ne!(variant.commitment(), commitment);
        }
    }

    #[test]
    fn authority_actor_protocol_rejects_old_corrupt_and_ambiguous_wires() {
        let call = authority_credential_call();
        let encoded = call.encode().unwrap();
        let mut old_generation = encoded.clone();
        old_generation[..4].copy_from_slice(b"ACC2");
        assert!(AuthorityCredentialCall::decode(&old_generation).is_err());
        let mut old = encoded.clone();
        old[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert_eq!(
            AuthorityCredentialCall::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );
        let plan_at = encoded
            .windows(4)
            .position(|window| window == b"AMP1")
            .expect("nested canonical authorization plan");
        let mut old_nested_request = encoded.clone();
        old_nested_request[plan_at..plan_at + 4].copy_from_slice(b"AMRQ");
        assert_eq!(
            AuthorityCredentialCall::decode(&old_nested_request),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            AuthorityCredentialCall::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
        assert!(matches!(
            AuthorityCredentialCall::decode(&encoded[..encoded.len() - 1]),
            Err(WireError::Decode(DecodeError::Truncated))
        ));
        let mut zero_invocation = encoded;
        zero_invocation[HEADER_BYTES..HEADER_BYTES + 32].fill(0);
        assert_eq!(
            AuthorityCredentialCall::decode(&zero_invocation),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let approval = management_approval();
        let encoded = approval.encode().unwrap();
        let mut previous_generation = encoded.clone();
        previous_generation[..4].copy_from_slice(b"MAP1");
        assert!(ManagementApproval::decode(&previous_generation).is_err());
        let mut old = encoded.clone();
        old[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert_eq!(
            ManagementApproval::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );
        let mut zero_sequence = encoded.clone();
        zero_sequence[HEADER_BYTES + 32..HEADER_BYTES + 40].fill(0);
        assert_eq!(
            ManagementApproval::decode(&zero_sequence),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );
        let mut zero_acknowledgement = encoded.clone();
        zero_acknowledgement[HEADER_BYTES + 40..HEADER_BYTES + 72].fill(0);
        assert_eq!(
            ManagementApproval::decode(&zero_acknowledgement),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );
        let mut zero_request_commitment = encoded;
        let end = zero_request_commitment.len();
        zero_request_commitment[end - 32..].fill(0);
        assert_eq!(
            ManagementApproval::decode(&zero_request_commitment),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let acknowledgement = management_application_ack();
        let encoded = acknowledgement.encode().unwrap();
        let mut previous_generation = encoded.clone();
        previous_generation[..4].copy_from_slice(b"MAA1");
        assert!(ManagementApplicationAck::decode(&previous_generation).is_err());
        let mut old = encoded.clone();
        old[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert_eq!(
            ManagementApplicationAck::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            ManagementApplicationAck::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
        let mut same_invocation = acknowledgement;
        same_invocation.acknowledgement_invocation = same_invocation.authorization_invocation;
        assert_eq!(same_invocation.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn amp1_keeps_full_replica_limit_create_and_change_below_actor_message_bound() {
        let replicas = (1..=MAX_AGENT_REPLICAS)
            .map(|index| {
                let mut node = [0; 32];
                node[..2].copy_from_slice(&(index as u16).to_be_bytes());
                AgentReplica {
                    node: NodeId(node),
                    principal: PrincipalId([0x61; 32]),
                    role: ReplicaRole::Voter,
                }
            })
            .collect::<Vec<_>>();
        let change_request = ManagementRequest::ChangeReplicas {
            expected_generation: Hash([0x62; 32]),
            replicas: replicas.clone(),
        };
        assert!(change_request.is_valid());

        let authority = authority_actor_target();
        let space = authority.space;
        let owner = PrincipalId([0x61; 32]);
        let creation_nonce = Hash([0x63; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x64; 32]),
                runtime_program: ProgramId([0x65; 32]),
                runtime_producer: ProducerId([0x66; 32]),
                transition_producer: ProducerId([0x6b; 32]),
            },
            creation_nonce,
            authority: authority.binding,
            private_recovery: None,
            runtime_package: blob(0x67),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas,
        };
        let create_request = ManagementRequest::Create(alloc::boxed::Box::new(descriptor));
        assert!(create_request.is_valid());

        for request in [create_request, change_request] {
            assert!(
                encode_canonical_management_request(&request).len() > MAX_INVOCATION_MESSAGE_BYTES
            );
            let plan = request.authorization_plan().unwrap();
            let plan_bytes = plan.encode().unwrap();
            assert_eq!(plan_bytes.get(..4), Some(b"AMP1".as_slice()));
            assert!(plan_bytes.len() <= MAX_MANAGEMENT_AUTHORIZATION_PLAN_WIRE_BYTES);
            assert_eq!(
                ManagementAuthorizationPlan::decode(&plan_bytes),
                Ok(plan.clone())
            );

            let mut old_plan = plan_bytes.clone();
            old_plan[..4].copy_from_slice(b"AMRQ");
            assert!(ManagementAuthorizationPlan::decode(&old_plan).is_err());
            let mut unknown_plan = plan_bytes.clone();
            unknown_plan[HEADER_BYTES] = 0xff;
            assert_eq!(
                ManagementAuthorizationPlan::decode(&unknown_plan),
                Err(WireError::Decode(DecodeError::InvalidTag))
            );
            let mut trailing_plan = plan_bytes;
            trailing_plan.push(0);
            assert_eq!(
                ManagementAuthorizationPlan::decode(&trailing_plan),
                Err(WireError::Decode(DecodeError::TrailingBytes))
            );

            let mut call = AuthorityCredentialCall {
                plan,
                ..authority_credential_call()
            };
            if let ManagementRequest::Create(descriptor) = &request {
                call.managed.agent = descriptor.identity.agent;
                call.managed.owner = descriptor.identity.owner;
                call.managed.profile = descriptor.identity.profile;
                call.managed.runtime_deployment = descriptor.identity.runtime_deployment;
                call.managed.transition_producer = descriptor.identity.transition_producer;
            }
            call.invocation = call.expected_invocation();
            assert_eq!(call.validate_shape(), Ok(()));
            assert!(authority_credential_call_encoded_len(&call) <= MAX_INVOCATION_MESSAGE_BYTES);
            assert_eq!(
                AuthorityCredentialCall::decode(&call.encode().unwrap()),
                Ok(call.clone())
            );

            let mut approval = management_approval();
            approval.credential_call = call.commitment();
            approval.acknowledgement_invocation =
                ManagementApproval::derive_acknowledgement_invocation(&call);
            approval.managed = call.managed;
            approval.plan = call.plan;
            approval.plan_commitment = approval.plan.commitment();
            assert_eq!(approval.validate_shape(), Ok(()));
            assert!(management_approval_encoded_len(&approval) <= MAX_INVOCATION_REPLY_BYTES);
            assert_eq!(
                ManagementApproval::decode(&approval.encode().unwrap()),
                Ok(approval)
            );
        }
    }

    #[test]
    fn actor_forest_round_trip_is_exact_and_bounded() {
        let page = ActorDirectoryPage {
            entries: alloc::vec![
                ActorDirectoryRecord {
                    entry: actor(1),
                    incarnation: Hash([20; 32]),
                    installation_id: InstallationId([21; 32]),
                    registry_reservation: Hash([22; 32]),
                    install_request: Hash([26; 32]),
                },
                ActorDirectoryRecord {
                    entry: actor(2),
                    incarnation: Hash([23; 32]),
                    installation_id: InstallationId([24; 32]),
                    registry_reservation: Hash([25; 32]),
                    install_request: Hash([27; 32]),
                },
            ],
            next: Some(ActorId([2; 32])),
        };
        let encoded = page.encode().unwrap();
        assert_eq!(ActorDirectoryPage::decode(&encoded), Ok(page.clone()));
        // Four fixed-width identities follow the actor entry; pin the new
        // lineage field independently of the round-trip encoder/decoder.
        let lineage_offset = HEADER_BYTES
            + 4
            + (page.entries[0].entry.encode().unwrap().len() - HEADER_BYTES)
            + 3 * 32;
        assert_eq!(&encoded[lineage_offset..lineage_offset + 32], &[26; 32]);
        let mut missing_lineage = encoded.clone();
        missing_lineage.drain(lineage_offset..lineage_offset + 32);
        assert!(ActorDirectoryPage::decode(&missing_lineage).is_err());
        let mut zero_lineage = encoded.clone();
        zero_lineage[lineage_offset..lineage_offset + 32].fill(0);
        assert!(ActorDirectoryPage::decode(&zero_lineage).is_err());
        let mut previous_generation = encoded;
        previous_generation[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-260910-r14");
        assert!(ActorDirectoryPage::decode(&previous_generation).is_err());

        let mut oversized = actor(3);
        oversized.name = alloc::string::String::from_utf8(alloc::vec![b'x'; 129]).unwrap();
        assert_eq!(oversized.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn installation_data_is_bounded_and_committed_by_install_request() {
        let mut entry = actor(3);
        let installation_bytes = alloc::vec![0x5a, 0xa5];
        entry.installation_data = Some(BlobRef::of_bytes(&installation_bytes));
        let install = InstallActor {
            installation_id: InstallationId([31; 32]),
            registry_reservation: Hash([32; 32]),
            producer: ProducerId([33; 32]),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: Some(InstallationData {
                reference: entry.installation_data.clone().unwrap(),
                bytes: installation_bytes,
            }),
            state_layout: entry.state_layout,
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: entry.lanes,
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            },
            entry,
        };
        let with_data = ManagementRequest::Install(alloc::boxed::Box::new(install.clone()));
        assert!(management_request_valid(&with_data));
        let standalone = with_data.encode().unwrap();
        assert!(standalone.len() <= MAX_MANAGEMENT_REQUEST_WIRE_BYTES);
        assert_eq!(
            ManagementRequest::decode(&standalone),
            Ok(with_data.clone())
        );
        let mut trailing = standalone;
        trailing.push(0);
        assert!(ManagementRequest::decode(&trailing).is_err());

        let mut without_data = install.clone();
        without_data.entry.installation_data = None;
        without_data.installation_data = None;
        let without_data = ManagementRequest::Install(alloc::boxed::Box::new(without_data));
        assert!(management_request_valid(&without_data));
        assert_ne!(with_data.commitment(), without_data.commitment());

        let mut present_empty = install.clone();
        let empty_reference = BlobRef::of_bytes(&[]);
        present_empty.entry.installation_data = Some(empty_reference.clone());
        present_empty.installation_data = Some(InstallationData {
            reference: empty_reference,
            bytes: alloc::vec![],
        });
        let present_empty_request =
            ManagementRequest::Install(alloc::boxed::Box::new(present_empty.clone()));
        assert!(management_request_valid(&present_empty_request));
        assert_ne!(
            present_empty_request.commitment(),
            without_data.commitment()
        );

        let mut encoded = alloc::vec![];
        encode_install(&mut Encoder(&mut encoded), &present_empty);
        let mut decoder = Decoder::new(&encoded);
        assert_eq!(decode_install(&mut decoder).unwrap(), present_empty);
        assert!(decoder.exhausted());

        let mut aliased = install.clone();
        let data_reference = aliased
            .installation_data
            .as_ref()
            .unwrap()
            .reference
            .clone();
        aliased.package = data_reference.clone();
        aliased.entry.package = data_reference;
        assert!(!management_request_valid(&ManagementRequest::Install(
            alloc::boxed::Box::new(aliased)
        )));

        let mut oversized = install;
        let bytes = alloc::vec![0; crate::MAX_INSTALLATION_DATA_BYTES + 1];
        let reference = BlobRef::of_bytes(&bytes);
        oversized.entry.installation_data = Some(reference.clone());
        oversized.installation_data = Some(InstallationData { reference, bytes });
        assert!(!management_request_valid(&ManagementRequest::Install(
            alloc::boxed::Box::new(oversized)
        )));
    }

    #[test]
    fn installation_data_decoder_rejects_declared_oversize_mismatch_truncation_and_trailing() {
        let empty = InstallationData {
            reference: BlobRef::of_bytes(&[]),
            bytes: alloc::vec![],
        };
        let mut canonical = alloc::vec![];
        encode_installation_data(&mut Encoder(&mut canonical), &empty);
        let mut decoder = Decoder::new(&canonical);
        assert_eq!(decode_installation_data(&mut decoder), Ok(empty));
        assert!(decoder.exhausted());

        let mut oversized_declaration = alloc::vec![];
        encode_blob(
            &mut Encoder(&mut oversized_declaration),
            &BlobRef {
                hash: Hash([1; 32]),
                len: (MAX_INSTALLATION_DATA_BYTES + 1) as u64,
            },
        );
        Encoder(&mut oversized_declaration).u32((MAX_INSTALLATION_DATA_BYTES + 1) as u32);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&oversized_declaration)),
            Err(DecodeError::LimitExceeded)
        );

        let mut truncated = alloc::vec![];
        encode_blob(&mut Encoder(&mut truncated), &BlobRef::of_bytes(&[0x51]));
        Encoder(&mut truncated).u32(1);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&truncated)),
            Err(DecodeError::Truncated)
        );

        let mut mismatch = alloc::vec![];
        encode_blob(&mut Encoder(&mut mismatch), &BlobRef::of_bytes(&[]));
        Encoder(&mut mismatch).bytes(&[0x51]);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&mismatch)),
            Err(DecodeError::NonCanonical)
        );

        canonical.push(0xff);
        let mut decoder = Decoder::new(&canonical);
        assert!(decode_installation_data(&mut decoder).is_ok());
        assert!(
            !decoder.exhausted(),
            "the enclosing canonical wire rejects trailing bytes"
        );
    }

    fn invocation() -> InvocationWork {
        InvocationWork {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([4; 32]),
            actor: ActorId([5; 32]),
            incarnation: Hash([6; 32]),
            deployment: DeploymentId([7; 32]),
            program: ProgramId([8; 32]),
            mode: MethodMode::Linear,
            origin: InvocationOrigin {
                principal: Some(PrincipalId([9; 32])),
                transport_node: Some(NodeId([10; 32])),
                credential: Some(CredentialId([11; 32])),
                actor: None,
                capability: Some(CapabilityId([12; 32])),
            },
            roles: InvocationRoleClaims::none(),
            message: alloc::vec![13, 14],
            installation_data: None,
            availability: alloc::vec![],
            gas: 1_000,
            recovery_only: false,
        }
    }

    #[test]
    fn r19_retirement_rejects_the_previous_abi_header() {
        let retirement = InvocationRetirement::from_work(&invocation());
        let mut bytes = retirement.encode().unwrap();
        bytes[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-260920-r18");
        assert!(InvocationRetirement::decode(&bytes).is_err());
    }

    #[test]
    fn retirement_wire_preserves_work_commitment_without_artifact_preimages() {
        let mut work = invocation();
        let bytes = alloc::vec![0x57; 1024 * 1024];
        work.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        assert!(work.validate());
        let retirement = InvocationRetirement::from_work(&work);
        assert!(retirement.validate());
        assert_eq!(retirement.commitment(), work.commitment());
        let encoded = retirement.encode().unwrap();
        assert!(
            encoded.len() < 1024,
            "artifact size must not determine retirement size"
        );
        assert_eq!(InvocationRetirement::decode(&encoded).unwrap(), retirement);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(InvocationRetirement::decode(&trailing).is_err());
        assert!(InvocationRetirement::decode(&encoded[..encoded.len() - 1]).is_err());
        // A reference-only description makes no claim about a supplied preimage.
        // Runtime integration must match authenticated retained state instead.
        work.availability[0].bytes[0] ^= 1;
        assert!(!work.validate());
        assert_eq!(InvocationRetirement::from_work(&work), retirement);
    }

    #[test]
    fn retirement_commitment_binds_every_invocation_field() {
        let baseline = invocation();
        let commitment = baseline.commitment();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut work = baseline.clone();
                work.$field = $value;
                let retirement = InvocationRetirement::from_work(&work);
                assert_eq!(retirement.commitment(), work.commitment());
                assert_ne!(retirement.commitment(), commitment, stringify!($field));
            }};
        }
        changed!(space, SpaceId([0x99; 32]));
        changed!(agent, AgentId([0x99; 32]));
        changed!(runtime_deployment, DeploymentId([0x99; 32]));
        changed!(invocation, InvocationId([0x99; 32]));
        changed!(actor, ActorId([0x99; 32]));
        changed!(incarnation, Hash([0x99; 32]));
        changed!(deployment, DeploymentId([0x99; 32]));
        changed!(program, ProgramId([0x99; 32]));
        changed!(mode, MethodMode::Query);
        changed!(origin, InvocationOrigin::anonymous());
        changed!(
            roles,
            InvocationRoleClaims {
                space: Some(RoleId([0x99; 32])),
                actor: None
            }
        );
        changed!(message, alloc::vec![0x99]);
        changed!(installation_data, Some(BlobRef::of_bytes(&[])));
        changed!(
            availability,
            alloc::vec![RuntimeBlob {
                reference: BlobRef::of_bytes(b"a"),
                bytes: b"a".to_vec()
            }]
        );
        changed!(gas, 1001);
        changed!(recovery_only, true);
    }

    #[test]
    fn retirement_rejects_noncanonical_or_unbounded_references() {
        let mut work = invocation();
        let empty = BlobRef::of_bytes(&[]);
        work.installation_data = Some(empty.clone());
        work.availability.push(RuntimeBlob {
            reference: empty,
            bytes: Vec::new(),
        });
        let valid = InvocationRetirement::from_work(&work);
        assert!(valid.validate());
        assert_eq!(valid.commitment(), work.commitment());
        assert_eq!(
            InvocationRetirement::decode(&valid.encode().unwrap()).unwrap(),
            valid
        );
        let mut cases = Vec::new();
        let mut invalid = valid.clone();
        invalid.installation_data = None;
        cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.required.clear();
        cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.required.push(invalid.required[0].clone());
        cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.required[0].len = u64::MAX;
        cases.push(invalid);
        let mut invalid = valid.clone();
        invalid.message.resize(MAX_INVOCATION_MESSAGE_BYTES + 1, 0);
        cases.push(invalid);
        let mut invalid = valid;
        invalid.actor = ActorId::ZERO;
        cases.push(invalid);
        for invalid in cases {
            assert!(!invalid.validate());
            assert!(invalid.encode().is_err());
            let mut hostile = Vec::from(InvocationRetirement::MAGIC);
            hostile.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
            invalid.encode_body(&mut Encoder(&mut hostile));
            assert!(InvocationRetirement::decode(&hostile).is_err());
        }
    }

    #[test]
    fn retirement_authorization_matches_original_exact_binding() {
        let mut work = invocation();
        work.origin.capability = None;
        let compact = InvocationRetirement::from_work(&work);
        for authorization in [
            InvocationAuthorization::AuthorityReceipt(receipt_for(&work)),
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 45)),
        ] {
            assert!(authorization.matches_work(&work));
            assert!(authorization.matches_retirement(&compact));
            let mut variants = alloc::vec![compact.clone(); 4];
            variants[0].agent = AgentId([0x91; 32]);
            variants[1].message.push(0x91);
            variants[2].origin.principal = Some(PrincipalId([0x91; 32]));
            variants[3].recovery_only = true;
            for changed in variants {
                assert!(!authorization.matches_retirement(&changed));
            }
        }
        work.origin.capability = Some(CapabilityId([0x91; 32]));
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 45));
        assert!(!authorization.matches_retirement(&InvocationRetirement::from_work(&work)));
    }

    #[test]
    fn retained_acceptance_shares_metadata_but_refuses_recovery_only_creation() {
        let mut work = invocation();
        let bytes = b"accepted artifact".to_vec();
        work.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        let accepted = InvocationRetirement::from_work(&work);
        assert!(accepted.validate_accepted());
        assert_eq!(accepted.with_availability(work.availability.clone()), work);
        assert!(
            !accepted
                .with_availability(alloc::vec![RuntimeBlob {
                    reference: work.availability[0].reference.clone(),
                    bytes: b"wrong preimage".to_vec(),
                }])
                .validate()
        );
        work.recovery_only = true;
        let recovery = InvocationRetirement::from_work(&work);
        assert!(recovery.validate());
        assert!(!recovery.validate_accepted());
    }

    fn invocation_context() -> InvocationContext {
        InvocationContext {
            invocation: InvocationId([41; 32]),
            actor: ActorId([42; 32]),
            mode: MethodMode::Merge,
            origin: InvocationOrigin {
                principal: Some(PrincipalId([43; 32])),
                transport_node: Some(NodeId([44; 32])),
                credential: Some(CredentialId([45; 32])),
                actor: Some(ActorId([46; 32])),
                capability: None,
            },
            roles: InvocationRoleClaims {
                space: None,
                actor: Some(RoleId([47; 32])),
            },
            observed_slot: 48,
        }
    }

    #[test]
    fn aic1_invocation_context_has_one_bounded_golden_wire() {
        let context = invocation_context();
        let encoded = context.encode().unwrap();
        assert_eq!(encoded.get(..4), Some(b"AIC1".as_slice()));
        assert_eq!(
            encoded.get(4..HEADER_BYTES),
            Some(RUNTIME_ABI_ID.as_bytes().as_slice())
        );
        assert!(encoded.len() <= MAX_INVOCATION_CONTEXT_WIRE_BYTES);
        assert_eq!(InvocationContext::decode(&encoded), Ok(context));
        let golden = Hash::digest(b"vos/test/aic1-golden", &[&encoded]);
        assert_eq!(
            golden.0,
            [
                0xa8, 0x76, 0xf3, 0x2a, 0x4c, 0xf5, 0x5a, 0x62, 0x52, 0x88, 0xec, 0x31, 0xd9, 0x1e,
                0x41, 0x3f, 0x57, 0x5b, 0x0f, 0xe4, 0xb4, 0xc7, 0x09, 0x9c, 0x06, 0x79, 0x7b, 0xe1,
                0x48, 0xd8, 0x40, 0x4a,
            ]
        );

        let mut variants = [context; 8];
        variants[0].invocation = InvocationId([51; 32]);
        variants[1].actor = ActorId([52; 32]);
        variants[2].origin.principal = Some(PrincipalId([53; 32]));
        variants[3].origin.transport_node = Some(NodeId([54; 32]));
        variants[4].origin.credential = Some(CredentialId([55; 32]));
        variants[5].origin.actor = Some(ActorId([56; 32]));
        variants[6].roles.actor = Some(RoleId([57; 32]));
        variants[7].observed_slot += 1;
        for variant in variants {
            let variant = variant.encode().unwrap();
            assert_ne!(
                Hash::digest(b"vos/test/aic1-golden", &[&variant]),
                golden,
                "every authenticated identity, role, and slot is wire-bound"
            );
        }
    }

    #[test]
    fn aic1_invocation_context_rejects_hostile_and_ambiguous_claims() {
        let context = invocation_context();
        let encoded = context.encode().unwrap();

        let mut previous_generation = encoded.clone();
        previous_generation[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert_eq!(
            InvocationContext::decode(&previous_generation),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            InvocationContext::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
        assert!(matches!(
            InvocationContext::decode(&encoded[..encoded.len() - 1]),
            Err(WireError::Decode(DecodeError::Truncated))
        ));

        let role_at = encoded
            .windows(32)
            .position(|window| window == [47; 32])
            .expect("unique actor role preimage");
        let mut zero_role = encoded.clone();
        zero_role[role_at..role_at + 32].fill(0);
        assert_eq!(
            InvocationContext::decode(&zero_role),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );
        let mut invalid_role_tag = encoded;
        invalid_role_tag[role_at - 1] = 2;
        assert_eq!(
            InvocationContext::decode(&invalid_role_tag),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let mut both_roles = context;
        both_roles.roles.space = Some(RoleId([49; 32]));
        assert_eq!(both_roles.encode(), Err(WireError::InvalidValue));
        let mut role_and_capability = context;
        role_and_capability.origin.capability = Some(CapabilityId([50; 32]));
        assert_eq!(role_and_capability.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn invocation_commitment_binds_references_and_admission_checks_preimages() {
        let mut work = invocation();
        let bytes = alloc::vec![1, 2, 3];
        work.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        assert!(work.validate());
        let commitment = work.commitment();
        let mut references_only = work.clone();
        references_only.availability[0].bytes.clear();
        assert_eq!(references_only.commitment(), commitment);
        assert!(!references_only.validate());
        let mut corrupt = work.clone();
        corrupt.availability[0].bytes[0] ^= 1;
        assert_eq!(corrupt.commitment(), commitment);
        assert!(!corrupt.validate(), "hashing never replaces byte admission");
        let mut changed = work.clone();
        changed.availability[0].reference.hash = Hash([0xef; 32]);
        assert_ne!(changed.commitment(), commitment);
        changed = work.clone();
        changed.availability[0].reference.len += 1;
        assert_ne!(changed.commitment(), commitment);
        changed = work.clone();
        changed.availability.clear();
        assert_ne!(changed.commitment(), commitment);
        changed = work.clone();
        changed.availability.push(work.availability[0].clone());
        assert_ne!(changed.commitment(), commitment);
        assert!(!changed.validate());

        let mut old_bytes = Vec::new();
        old_bytes.extend_from_slice(b"AINV");
        old_bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        encode_invocation_work(&mut Encoder(&mut old_bytes), &work);
        assert_ne!(
            Hash::digest(b"vos/agent/invocation", &[&old_bytes]),
            commitment
        );
    }

    #[test]
    fn invocation_commitment_binds_exact_role_scope_and_identity() {
        let mut public = invocation();
        public.origin.capability = None;
        let public_commitment = public.commitment();

        let mut space = public.clone();
        space.roles.space = Some(RoleId([51; 32]));
        let mut actor = public;
        actor.roles.actor = Some(RoleId([51; 32]));
        assert_ne!(space.commitment(), public_commitment);
        assert_ne!(actor.commitment(), public_commitment);
        assert_ne!(actor.commitment(), space.commitment());

        actor.roles.actor = Some(RoleId([52; 32]));
        assert_ne!(actor.commitment(), space.commitment());
    }

    fn receipt_for(invocation: &InvocationWork) -> AuthorityReceipt {
        let public_key = [31; 32];
        AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash([15; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([16; 32]),
                    actor: ActorId([17; 32]),
                    deployment: DeploymentId([18; 32]),
                    program: ProgramId([19; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: invocation.space,
                agent: invocation.agent,
                operation: AuthorityOperationKind::InvokeActor,
                runtime_deployment: invocation.runtime_deployment,
                actor: Some(invocation.actor),
                actor_deployment: Some(invocation.deployment),
                evidence: AuthorityEvidence {
                    package: Some(blob(20)),
                    proof: None,
                    commitment: Hash([21; 32]),
                },
                lane_roots: AuthorityLaneRoots {
                    linear: Some(Hash([22; 32])),
                    ..AuthorityLaneRoots::default()
                },
                epoch: 3,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 40,
                expires_at: 50,
                request: invocation.commitment(),
            },
            public_key,
            signature: [32; 64],
        }
    }

    #[test]
    fn invoke_work_round_trip_binds_receipt_to_exact_request() {
        let invocation = invocation();
        let work = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            authorization: alloc::boxed::Box::new(InvocationAuthorization::AuthorityReceipt(
                receipt_for(&invocation),
            )),
            invocation: alloc::boxed::Box::new(invocation),
            observed_slot: 45,
        };
        let encoded = work.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));

        let mut later_retry = work.clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut later_retry else {
            unreachable!()
        };
        *observed_slot = 51;
        assert!(
            later_retry.encode().is_ok(),
            "the guest must distinguish an exact retry from unseen expired work before applying the signed slot window"
        );

        let RuntimeWork::Invoke {
            context,
            mut authorization,
            state,
            invocation,
            observed_slot,
        } = work
        else {
            unreachable!()
        };
        let InvocationAuthorization::AuthorityReceipt(authority) = authorization.as_mut() else {
            unreachable!()
        };
        authority.selector.request = Hash([99; 32]);
        let mismatched = RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        };
        assert_eq!(mismatched.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn invoke_authorization_single_work_check_matches_previous_predicate() {
        fn previous(
            authorization: &InvocationAuthorization,
            work: &InvocationWork,
            observed_slot: u64,
        ) -> bool {
            if !authorization.matches_work(work) {
                return false;
            }
            match authorization {
                InvocationAuthorization::AuthorityReceipt(_) => true,
                InvocationAuthorization::PublicPreflight(preflight) => {
                    preflight.matches_work(work) && observed_slot >= preflight.observed_slot
                }
            }
        }

        let mut original = invocation();
        original.origin.capability = None;
        original.roles = InvocationRoleClaims::none();
        let mut variants = alloc::vec![original.clone()];
        let mut changed = original.clone();
        changed.message.push(0x91);
        variants.push(changed);
        let mut changed = original.clone();
        changed.origin.transport_node = Some(NodeId([0x92; 32]));
        variants.push(changed);
        let mut changed = original.clone();
        changed.roles.space = Some(RoleId([0x93; 32]));
        variants.push(changed);

        let preflight = PublicPreflight::for_work(&original, 45);
        let mut zero_commitment = preflight;
        zero_commitment.work = Hash::ZERO;
        let mut different_origin = preflight;
        different_origin.origin.transport_node = Some(NodeId([0x94; 32]));
        let authorizations = [
            InvocationAuthorization::PublicPreflight(preflight),
            InvocationAuthorization::PublicPreflight(zero_commitment),
            InvocationAuthorization::PublicPreflight(different_origin),
            // Even a self-consistent commitment must not admit public role claims.
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&variants[3], 45)),
            InvocationAuthorization::AuthorityReceipt(receipt_for(&original)),
        ];
        for authorization in &authorizations {
            for work in &variants {
                for slot in [0, 44, 45, 46, u64::MAX] {
                    assert_eq!(
                        authorization.matches_invoke(work, slot),
                        previous(authorization, work, slot),
                        "authorization matching differs at observation {slot}"
                    );
                }
            }
        }
        assert!(authorizations[0].matches_invoke(&original, 45));
        assert!(!authorizations[0].matches_invoke(&original, 44));
        assert!(!authorizations[3].matches_invoke(&variants[3], 45));
    }

    #[test]
    fn public_preflight_wire_binds_exact_work_origin_and_acceptance_slot() {
        let mut invocation = invocation();
        invocation.origin.capability = None;
        invocation.roles = InvocationRoleClaims::none();
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 45));
        let work = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: alloc::boxed::Box::new(invocation.clone()),
            authorization: alloc::boxed::Box::new(authorization.clone()),
            observed_slot: 45,
        };
        let encoded = work.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));
        assert_eq!(
            InvocationAuthorization::decode(&authorization.encode().unwrap()),
            Ok(authorization.clone())
        );

        let mut different_slot = work.clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut different_slot else {
            unreachable!()
        };
        *observed_slot += 1;
        let encoded_retry = different_slot.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded_retry), Ok(different_slot));
        assert!(authorization.matches_invoke(&invocation, 46));
        let InvocationAuthorization::PublicPreflight(preflight) = &authorization else {
            unreachable!()
        };
        assert!(!preflight.matches(&invocation, 46));

        let mut regressed_slot = work.clone();
        let RuntimeWork::Invoke { observed_slot, .. } = &mut regressed_slot else {
            unreachable!()
        };
        *observed_slot -= 1;
        assert_eq!(regressed_slot.encode(), Err(WireError::InvalidValue));

        let mut different_origin = work.clone();
        let RuntimeWork::Invoke {
            invocation: mutated_invocation,
            ..
        } = &mut different_origin
        else {
            unreachable!()
        };
        mutated_invocation.origin.transport_node = Some(NodeId([0x91; 32]));
        assert_eq!(different_origin.encode(), Err(WireError::InvalidValue));

        let mut claimed_role = invocation.clone();
        claimed_role.roles.space = Some(RoleId([0x92; 32]));
        let claimed = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            authorization: alloc::boxed::Box::new(InvocationAuthorization::PublicPreflight(
                PublicPreflight::for_work(&claimed_role, 45),
            )),
            invocation: alloc::boxed::Box::new(claimed_role),
            observed_slot: 45,
        };
        assert_eq!(claimed.encode(), Err(WireError::InvalidValue));

        let acknowledgement = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: alloc::boxed::Box::new(InvocationRetirement::from_work(&invocation)),
            authorization: alloc::boxed::Box::new(authorization),
        };
        assert_eq!(
            RuntimeWork::decode(&acknowledgement.encode().unwrap()),
            Ok(acknowledgement)
        );
    }

    #[test]
    fn runtime_work_single_pass_rejects_invalid_nested_availability() {
        let mut invocation = invocation();
        let bytes = alloc::vec![0xa7; 768 * 1024];
        invocation.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        let authorization = InvocationAuthorization::AuthorityReceipt(receipt_for(&invocation));
        let resume = ResumeWork {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            program: invocation.program,
            mode: invocation.mode,
            continuation: blob(61),
            ready_sequence: 1,
            installation_data: None,
            availability: invocation.availability.clone(),
            input: None,
        };
        for work in [
            RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                invocation: alloc::boxed::Box::new(invocation.clone()),
                authorization: alloc::boxed::Box::new(authorization.clone()),
                observed_slot: 45,
            },
            RuntimeWork::Resume {
                context: RuntimeExecutionContext::Direct,
                state: RuntimeState::default(),
                resume: alloc::boxed::Box::new(resume),
            },
        ] {
            let encoded = work.encode().unwrap();
            assert_eq!(RuntimeWork::decode(&encoded).unwrap(), work);
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(RuntimeWork::decode(&trailing).is_err());
            assert!(RuntimeWork::decode(&encoded[..encoded.len() - 1]).is_err());
            for mutation in 0..5 {
                let mut invalid = work.clone();
                let (availability, installation_data) = match &mut invalid {
                    RuntimeWork::Invoke { invocation, .. } => (
                        &mut invocation.availability,
                        &mut invocation.installation_data,
                    ),
                    RuntimeWork::Resume { resume, .. } => {
                        (&mut resume.availability, &mut resume.installation_data)
                    }
                    _ => unreachable!(),
                };
                match mutation {
                    0 => availability[0].bytes[0] ^= 1,
                    1 => availability[0].reference.len += 1,
                    2 => availability[0].reference.hash = Hash::ZERO,
                    3 => availability.push(availability[0].clone()),
                    4 => *installation_data = Some(blob(62)),
                    _ => unreachable!(),
                }
                assert!(!invalid.validate_wire());
                assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
                // Bypass the validating encoder to exercise hostile wire,
                // including callers using the body decoder directly.
                let mut body = Vec::new();
                invalid.encode_body(&mut Encoder(&mut body));
                assert!(RuntimeWork::decode_body(&mut Decoder::new(&body)).is_err());
                let mut raw = RuntimeWork::MAGIC.to_vec();
                raw.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
                raw.extend_from_slice(&body);
                assert!(RuntimeWork::decode(&raw).is_err());
            }
        }
    }

    #[test]
    fn expiry_fence_has_a_distinct_canonical_outcome() {
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::ExpiredBeforeExecution)),
        };
        let encoded = transition.encode().unwrap();
        assert_eq!(RuntimeTransition::decode(&encoded).unwrap(), transition);
        let rejection = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::AuthorityExpired)),
        };
        assert_ne!(encoded, rejection.encode().unwrap());
        let mut previous_abi = encoded.clone();
        previous_abi[4..36].copy_from_slice(b"vos-agent-runtime-abi-260912-r16");
        assert!(RuntimeTransition::decode(&previous_abi).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(RuntimeTransition::decode(&trailing).is_err());
    }

    #[test]
    fn acknowledgement_transport_is_reference_only_and_rejects_invalid_metadata() {
        let mut invocation = invocation();
        let bytes = alloc::vec![0xa7; 1024 * 1024];
        invocation.availability = alloc::vec![RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        }];
        invocation.installation_data = None;
        let retirement = InvocationRetirement::from_work(&invocation);
        let work = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: alloc::boxed::Box::new(retirement.clone()),
            authorization: alloc::boxed::Box::new(InvocationAuthorization::AuthorityReceipt(
                receipt_for(&invocation),
            )),
        };
        let encoded = work.encode().unwrap();
        assert!(
            encoded.len() < 2048,
            "ACK must not carry the 1 MiB preimage"
        );
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RuntimeWork::decode(&trailing).is_err());
        assert!(RuntimeWork::decode(&encoded[..encoded.len() - 1]).is_err());
        for mutation in 0..5 {
            let mut invalid = work.clone();
            let RuntimeWork::Acknowledge { invocation, .. } = &mut invalid else {
                unreachable!()
            };
            match mutation {
                0 => invocation.required[0].hash = Hash::ZERO,
                1 => invocation.required.push(invocation.required[0].clone()),
                2 => invocation.installation_data = Some(blob(62)),
                3 => invocation.message.push(0x91),
                4 => invocation.required[0].len += 1,
                _ => unreachable!(),
            }
            assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
            let mut body = Vec::new();
            invalid.encode_body(&mut Encoder(&mut body));
            assert!(RuntimeWork::decode_body(&mut Decoder::new(&body)).is_err());
        }
    }

    #[test]
    fn acknowledgement_work_and_outcome_have_one_r19_canonical_wire() {
        let invocation = invocation();
        let authority = receipt_for(&invocation);
        let work = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            invocation: alloc::boxed::Box::new(InvocationRetirement::from_work(&invocation)),
            authorization: alloc::boxed::Box::new(InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )),
        };
        let encoded = work.encode().unwrap();
        assert!(encoded.len() <= RuntimeWork::MAX_ENCODED_BYTES);
        assert_eq!(encoded[HEADER_BYTES], 3, "Acknowledge owns work tag 3");
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));

        let mut previous_generation = encoded.clone();
        previous_generation[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-260902-r18");
        assert_eq!(
            RuntimeWork::decode(&previous_generation),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );

        #[cfg(not(feature = "experimental-state-blocks"))]
        {
            let mut experimental_tag = encoded.clone();
            experimental_tag[HEADER_BYTES] = 4;
            assert_eq!(
                RuntimeWork::decode(&experimental_tag),
                Err(WireError::Decode(DecodeError::InvalidTag))
            );
        }
        let mut unknown_tag = encoded;
        unknown_tag[HEADER_BYTES] = 5;
        assert_eq!(
            RuntimeWork::decode(&unknown_tag),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );

        let mut mismatched = work;
        let RuntimeWork::Acknowledge {
            authorization: mismatched_authorization,
            ..
        } = &mut mismatched
        else {
            unreachable!()
        };
        let InvocationAuthorization::AuthorityReceipt(mismatched_authority) =
            mismatched_authorization.as_mut()
        else {
            unreachable!()
        };
        mismatched_authority.selector.request = Hash([99; 32]);
        assert_eq!(mismatched.encode(), Err(WireError::InvalidValue));

        let acknowledgement = InvocationAcknowledgement {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            work: invocation.commitment(),
            authorization: InvocationAuthorization::AuthorityReceipt(authority).commitment(),
        };
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
        };
        let encoded = transition.encode().unwrap();
        assert!(encoded.len() <= RuntimeTransition::MAX_ENCODED_BYTES);
        assert_eq!(RuntimeTransition::decode(&encoded), Ok(transition));

        let invalid = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Acknowledged(Ok(InvocationAcknowledgement {
                work: Hash::ZERO,
                ..acknowledgement
            })),
        };
        assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn read_only_management_has_one_authority_representation() {
        let invocation = invocation();
        let read = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: invocation.space,
            agent: invocation.agent,
            runtime_deployment: invocation.runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 45,
        };
        let encoded = read.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(read));

        let with_receipt = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: invocation.space,
            agent: invocation.agent,
            runtime_deployment: invocation.runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectResources),
            authority: Some(alloc::boxed::Box::new(receipt_for(&invocation))),
            observed_slot: 45,
        };
        assert_eq!(with_receipt.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn management_expiry_error_has_a_distinct_append_only_wire_tag() {
        for (error, tag) in [
            (ManagementError::InvalidRequest, 9),
            (ManagementError::ResourceLimit, 13),
            (ManagementError::ExpiredBeforeApplication, 14),
        ] {
            let mut bytes = Vec::new();
            encode_management_error(&mut Encoder(&mut bytes), error);
            assert_eq!(bytes, [tag]);
            assert_eq!(
                decode_management_error(&mut Decoder::new(&bytes)).unwrap(),
                error
            );
        }
        assert!(decode_management_error(&mut Decoder::new(&[15])).is_err());
    }

    #[test]
    fn runtime_execution_context_is_explicit_and_fail_closed_on_wire() {
        let invocation = invocation();
        let direct = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: invocation.space,
            agent: invocation.agent,
            runtime_deployment: invocation.runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 45,
        };
        let encoded = direct.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(direct.clone()));

        let mut unknown = encoded;
        unknown[HEADER_BYTES + 1] = 2;
        assert_eq!(
            RuntimeWork::decode(&unknown),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );

        let mut attested = direct.clone();
        let RuntimeWork::Manage { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash([0x71; 32]),
        };
        let encoded = attested.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&encoded), Ok(attested.clone()));

        let RuntimeWork::Manage { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash::ZERO,
        };
        assert_eq!(attested.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn rrp1_and_all_resource_usage_fields_have_one_bounded_wire() {
        let policy = RuntimeResourcePolicy::standard();
        let encoded = policy.encode().unwrap();
        assert_eq!(encoded.len(), MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES);
        assert_eq!(RuntimeResourcePolicy::decode(&encoded), Ok(policy));

        let mut old_magic = encoded.clone();
        old_magic[..4].copy_from_slice(b"RRP0");
        assert_eq!(
            RuntimeResourcePolicy::decode(&old_magic),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            RuntimeResourcePolicy::decode(&trailing),
            Err(WireError::LimitExceeded),
            "RRP1 has a fixed maximum-width wire, so trailing data exceeds its bound"
        );
        let mut over_ceiling = encoded;
        over_ceiling[HEADER_BYTES + 20..HEADER_BYTES + 28]
            .copy_from_slice(&(MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1).to_le_bytes());
        assert_eq!(
            RuntimeResourcePolicy::decode(&over_ceiling),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let usage = RuntimeResourceUsage {
            actors: 1,
            active_machines: 2,
            continuations: 3,
            inbox: 4,
            outbox: 5,
            schedules: 6,
            proof_artifacts: 7,
            state_bytes: 8,
            artifact_references: 9,
            artifact_referenced_bytes: 10,
            proof_material_bytes: 11,
        };
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Management(Ok(ManagementReply::Resources(usage))),
        };
        let encoded = transition.encode().unwrap();
        assert_eq!(RuntimeTransition::decode(&encoded), Ok(transition));

        for invalid_usage in [
            RuntimeResourceUsage {
                artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..usage
            },
            RuntimeResourceUsage {
                artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES + 1,
                ..usage
            },
            RuntimeResourceUsage {
                proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
                ..usage
            },
        ] {
            let invalid = RuntimeTransition {
                state: RuntimeState::default(),
                outcome: RuntimeOutcome::Management(Ok(ManagementReply::Resources(invalid_usage))),
            };
            assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
        }
    }

    #[test]
    fn create_retry_may_carry_predecessor_state_but_cannot_self_select_trust() {
        let space = SpaceId([41; 32]);
        let owner = PrincipalId([42; 32]);
        let creation_nonce = Hash([43; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let runtime_deployment = DeploymentId([44; 32]);
        let mut authority = receipt_for(&invocation());
        authority.selector.space = space;
        authority.selector.agent = agent;
        authority.selector.operation = AuthorityOperationKind::CreateAgent;
        authority.selector.decision_sequence = 1;
        authority.selector.runtime_deployment = runtime_deployment;
        authority.selector.actor = None;
        authority.selector.actor_deployment = None;
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment,
                runtime_program: ProgramId([45; 32]),
                runtime_producer: ProducerId([46; 32]),
                transition_producer: ProducerId([52; 32]),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: authority.selector.policy,
                issuer: authority.selector.issuer,
                public_key: authority.public_key,
                initial_epoch: authority.selector.epoch,
            },
            private_recovery: None,
            runtime_package: blob(47),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: alloc::vec![AgentReplica {
                node: NodeId([48; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        let descriptor_bytes = descriptor.encode().unwrap();
        assert_eq!(
            AgentDescriptor::decode(&descriptor_bytes),
            Ok(descriptor.clone())
        );
        let request = ManagementRequest::Create(alloc::boxed::Box::new(descriptor));
        authority.selector.request = request.commitment();
        let work = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space,
            agent,
            runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(request),
            authority: Some(alloc::boxed::Box::new(authority)),
            observed_slot: 45,
        };
        assert!(work.encode().is_ok());

        let mut self_selected = work.clone();
        let RuntimeWork::Manage {
            authority: Some(receipt),
            ..
        } = &mut self_selected
        else {
            unreachable!()
        };
        receipt.selector.policy = Hash([49; 32]);
        assert_eq!(self_selected.encode(), Err(WireError::InvalidValue));

        let mut with_predecessor = work;
        let RuntimeWork::Manage { state, .. } = &mut with_predecessor else {
            unreachable!()
        };
        state.control.push(1);
        assert!(with_predecessor.encode().is_ok());
    }

    #[test]
    fn yielded_transition_round_trip_and_old_generation_rejection() {
        let installation_data = BlobRef::of_bytes(&[]);
        let mut required = alloc::vec![
            BlobRef::of_bytes(b"actor program"),
            installation_data.clone(),
        ];
        required.sort();
        let transition = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Yielded(YieldedInvocation {
                invocation: InvocationId([1; 32]),
                actor: ActorId([2; 32]),
                incarnation: Hash([3; 32]),
                deployment: DeploymentId([4; 32]),
                program: ProgramId([5; 32]),
                mode: MethodMode::Merge,
                continuation: BlobRef {
                    hash: Hash([6; 32]),
                    len: 512,
                },
                ready_sequence: 7,
                installation_data: Some(installation_data),
                required,
                reason: YieldReason::Await {
                    call: CallId([8; 32]),
                },
            }),
        };
        let encoded = transition.encode().unwrap();
        assert_eq!(RuntimeTransition::decode(&encoded), Ok(transition));

        let mut old_generation = encoded.clone();
        old_generation[4] ^= 0xff;
        assert_eq!(
            RuntimeTransition::decode(&old_generation),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            RuntimeTransition::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
    }

    fn private_node() -> PrivateNodeIdentity {
        let transport_identity = alloc::vec![3; 48];
        PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: PrincipalId([2; 32]),
            transport_identity,
            encryption_public_key: [4; 32],
            authority_binding: Hash([5; 32]),
            transport_signature: [6; 64],
        }
    }

    fn private_policy_request(
        sequence: u64,
        previous: Option<Hash>,
        policy: RuntimeResourcePolicy,
    ) -> ManagementRequest {
        let policy_bytes = policy.encode().unwrap();
        ManagementRequest::PrivateControl {
            control: alloc::boxed::Box::new(PrivateControlRecord {
                space: SpaceId([0x71; 32]),
                agent: AgentId([0x72; 32]),
                sequence,
                previous,
                operation: PrivateControlOperation::SetResourcePolicy {
                    policy: BlobRef::of_bytes(&policy_bytes),
                },
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0x73; 32],
                signature: [0x74; PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: alloc::boxed::Box::new(PrivateRuntimeMutation::SetResourcePolicy(policy)),
        }
    }

    fn private_lifecycle_request(
        sequence: u64,
        previous: Option<Hash>,
        mutation: PrivateRuntimeMutation,
    ) -> ManagementRequest {
        let actor = mutation.actor().unwrap();
        let operation = mutation.lifecycle_kind().unwrap();
        let request = mutation.commitment();
        ManagementRequest::PrivateControl {
            control: alloc::boxed::Box::new(PrivateControlRecord {
                space: SpaceId([0x71; 32]),
                agent: AgentId([0x72; 32]),
                sequence,
                previous,
                operation: PrivateControlOperation::ActorLifecycle {
                    actor,
                    operation,
                    request,
                },
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0x73; 32],
                signature: [0x74; PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: alloc::boxed::Box::new(mutation),
        }
    }

    fn private_management_receipt(
        request: &ManagementRequest,
        runtime_deployment: DeploymentId,
    ) -> AuthorityReceipt {
        let public_key = [0x75; AUTHORITY_PUBLIC_KEY_BYTES];
        let (actor, actor_deployment) = request.authority_actor_selector();
        AuthorityReceipt {
            selector: AuthorityReceiptSelector {
                policy: Hash([0x76; 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([0x77; 32]),
                    actor: ActorId([0x78; 32]),
                    deployment: DeploymentId([0x79; 32]),
                    program: ProgramId([0x7a; 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                space: SpaceId([0x71; 32]),
                agent: AgentId([0x72; 32]),
                operation: request.authority_operation().unwrap(),
                runtime_deployment,
                actor,
                actor_deployment,
                evidence: AuthorityEvidence {
                    package: None,
                    proof: None,
                    commitment: Hash([0x7b; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch: 3,
                decision_sequence: 0,
                acknowledged_through: 0,
                valid_from: 10,
                expires_at: 20,
                request: request.commitment(),
            },
            public_key,
            signature: [0x7c; AUTHORITY_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn private_runtime_management_has_distinct_selector_and_exact_replay_commitments() {
        let policy = RuntimeResourcePolicy {
            max_actors: 17,
            ..RuntimeResourcePolicy::standard()
        };
        let request = private_policy_request(4, Some(Hash([0x70; 32])), policy);
        assert!(request.is_valid());
        let ManagementRequest::PrivateControl { control, mutation } = &request else {
            unreachable!()
        };
        assert_eq!(request.commitment(), control.commitment());
        assert_ne!(request.replay_commitment(), request.commitment());
        assert_eq!(
            request.authority_operation(),
            Some(AuthorityOperationKind::SetPrivateResourcePolicy)
        );
        assert_eq!(request.authority_actor_selector(), (None, None));

        let encoded_mutation = mutation.encode().unwrap();
        assert_eq!(
            PrivateRuntimeMutation::decode(&encoded_mutation),
            Ok((**mutation).clone())
        );

        let mut substituted = request.clone();
        let ManagementRequest::PrivateControl { mutation, .. } = &mut substituted else {
            unreachable!()
        };
        **mutation = PrivateRuntimeMutation::SetResourcePolicy(RuntimeResourcePolicy {
            max_actors: 18,
            ..policy
        });
        assert!(!substituted.is_valid());
        assert_eq!(substituted.commitment(), request.commitment());
        assert_ne!(substituted.replay_commitment(), request.replay_commitment());

        assert!(
            request.authorization_plan().is_none(),
            "Private PCTLs use retained AOC/AOP/PCA and cannot enter ACC3"
        );

        let mut old_magic = encoded_mutation.clone();
        old_magic[..4].copy_from_slice(b"PRM0");
        assert_eq!(
            PrivateRuntimeMutation::decode(&old_magic),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );
        let mut old_abi = encoded_mutation.clone();
        old_abi[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-260907-r13");
        assert_eq!(
            PrivateRuntimeMutation::decode(&old_abi),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );
        let mut trailing = encoded_mutation;
        trailing.push(0);
        assert_eq!(
            PrivateRuntimeMutation::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
    }

    #[test]
    fn private_runtime_work_is_direct_bounded_and_strictly_canonical() {
        let runtime_deployment = DeploymentId([0x7d; 32]);
        let request = private_lifecycle_request(
            9,
            Some(Hash([0x7e; 32])),
            PrivateRuntimeMutation::Suspend {
                actor: ActorId([0x7f; 32]),
                expected_deployment: DeploymentId([0x80; 32]),
            },
        );
        let ManagementRequest::PrivateControl { control, mutation } = &request else {
            unreachable!()
        };
        assert_eq!(
            control.encode().unwrap().len(),
            MAX_PRIVATE_RUNTIME_CONTROL_WIRE_BYTES
        );
        assert!(mutation.encode().unwrap().len() <= MAX_PRIVATE_RUNTIME_MUTATION_WIRE_BYTES);
        assert_eq!(
            request.authority_operation(),
            Some(AuthorityOperationKind::PrivateActorLifecycle)
        );
        assert_eq!(
            request.authority_actor_selector(),
            (Some(ActorId([0x7f; 32])), None)
        );

        let work = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([0x71; 32]),
            agent: AgentId([0x72; 32]),
            runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(request.clone()),
            authority: Some(alloc::boxed::Box::new(private_management_receipt(
                &request,
                runtime_deployment,
            ))),
            observed_slot: 10,
        };
        let encoded = work.encode().unwrap();
        assert!(encoded.len() <= MAX_RUNTIME_WORK_WIRE_BYTES);
        assert!(encoded.len() < 32 * 1024 * 1024);
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work.clone()));

        let mut attested = work.clone();
        let RuntimeWork::Manage { context, .. } = &mut attested else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: Hash([0x81; 32]),
        };
        assert_eq!(attested.encode(), Err(WireError::InvalidValue));

        let mut wrong_route = work.clone();
        let RuntimeWork::Manage { space, .. } = &mut wrong_route else {
            unreachable!()
        };
        *space = SpaceId([0x82; 32]);
        assert_eq!(wrong_route.encode(), Err(WireError::InvalidValue));

        let mut substituted_deployment = work.clone();
        let RuntimeWork::Manage { request, .. } = &mut substituted_deployment else {
            unreachable!()
        };
        let ManagementRequest::PrivateControl { mutation, .. } = request.as_mut() else {
            unreachable!()
        };
        **mutation = PrivateRuntimeMutation::Suspend {
            actor: ActorId([0x7f; 32]),
            expected_deployment: DeploymentId([0x8a; 32]),
        };
        assert!(mutation.is_valid());
        assert!(!request.is_valid());
        assert_eq!(
            substituted_deployment.encode(),
            Err(WireError::InvalidValue)
        );

        let mut selected_deployment = work.clone();
        let RuntimeWork::Manage {
            authority: Some(authority),
            ..
        } = &mut selected_deployment
        else {
            unreachable!()
        };
        authority.selector.actor_deployment = Some(DeploymentId([0x8b; 32]));
        assert_eq!(selected_deployment.encode(), Err(WireError::InvalidValue));

        let mut old_abi = encoded.clone();
        old_abi[4..HEADER_BYTES].copy_from_slice(b"vos-agent-runtime-abi-260907-r13");
        assert_eq!(
            RuntimeWork::decode(&old_abi),
            Err(WireError::Decode(DecodeError::InvalidPlatform))
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            RuntimeWork::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );

        let valid_policy = private_policy_request(0, None, RuntimeResourcePolicy::standard());
        let RuntimeWork::Manage {
            authority: valid_authority,
            ..
        } = work.clone()
        else {
            unreachable!()
        };
        let make_unsupported = |operation| {
            let mut request = valid_policy.clone();
            let ManagementRequest::PrivateControl { control, .. } = &mut request else {
                unreachable!()
            };
            control.operation = operation;
            assert!(control.validate_shape());
            let space = control.space;
            let agent = control.agent;
            assert!(!request.is_valid());
            let work = RuntimeWork::Manage {
                context: RuntimeExecutionContext::Direct,
                space,
                agent,
                runtime_deployment,
                state: RuntimeState::default(),
                request: alloc::boxed::Box::new(request),
                authority: valid_authority.clone(),
                observed_slot: 10,
            };
            assert_eq!(work.encode(), Err(WireError::InvalidValue));
        };
        let epoch = PrivateKeyEpoch {
            space: SpaceId([0x71; 32]),
            agent: AgentId([0x72; 32]),
            epoch: 1,
            owner_key_commitment: Hash([0x8c; 32]),
            data_key_commitment: Hash([0x8d; 32]),
            recovery_key_commitment: Hash([0x8e; 32]),
            recovery_encryption_public_key: [0x8f; 32],
            sealed_recovery_data_key: SealedRecoveryKey {
                recipient_key: [0x8f; 32],
                sealed: alloc::vec![0x90; 48],
            },
            sealed_owner_keys: alloc::vec![SealedPrivateKey {
                node: NodeId([0x91; 32]),
                recipient_key: [0x92; 32],
                sealed: alloc::vec![0x93; 48],
            }],
            sealed_data_keys: alloc::vec![SealedPrivateKey {
                node: NodeId([0x91; 32]),
                recipient_key: [0x92; 32],
                sealed: alloc::vec![0x94; 48],
            }],
        };
        assert!(epoch.validate());
        make_unsupported(PrivateControlOperation::RotateKeys {
            next_epoch: epoch.clone(),
        });
        make_unsupported(PrivateControlOperation::Revoke {
            node: NodeId([0x95; 32]),
            next_epoch: epoch,
        });
        let node = private_node();
        make_unsupported(PrivateControlOperation::Invite {
            node: node.clone(),
            epoch: 0,
            sealed_owner_key: SealedPrivateKey {
                node: node.node,
                recipient_key: node.encryption_public_key,
                sealed: alloc::vec![0x96; 48],
            },
            sealed_data_key: SealedPrivateKey {
                node: node.node,
                recipient_key: node.encryption_public_key,
                sealed: alloc::vec![0x97; 48],
            },
            historical_grants: Vec::new(),
        });
    }

    #[test]
    fn maximum_private_install_mutation_fits_runtime_work_and_guest_heap_bounds() {
        let mut entry = actor(0x83);
        entry.lanes = LaneSet::of(StateLane::Merge);
        let bytes = alloc::vec![0x84; crate::MAX_INSTALLATION_DATA_BYTES];
        let reference = BlobRef::of_bytes(&bytes);
        entry.installation_data = Some(reference.clone());
        let install = InstallActor {
            installation_id: InstallationId([0x85; 32]),
            registry_reservation: Hash([0x86; 32]),
            producer: ProducerId([0x87; 32]),
            package: entry.package.clone(),
            agent_schema: entry.agent_schema.clone(),
            method_policy: entry.method_policy.clone(),
            constructor_abi: entry.constructor_abi,
            installation_data: Some(InstallationData { reference, bytes }),
            state_layout: entry.state_layout,
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: entry.lanes,
                scheduling: false,
                proof_systems: ProofSystemSet::EMPTY,
            },
            entry,
        };
        let request = private_lifecycle_request(
            1,
            Some(Hash([0x88; 32])),
            PrivateRuntimeMutation::Install(install),
        );
        assert!(request.is_valid());
        let mut substituted_package = request.clone();
        let ManagementRequest::PrivateControl { mutation, .. } = &mut substituted_package else {
            unreachable!()
        };
        let PrivateRuntimeMutation::Install(install) = mutation.as_mut() else {
            unreachable!()
        };
        let replacement = BlobRef::of_bytes(b"substituted package preimage");
        install.package = replacement.clone();
        install.entry.package = replacement;
        assert!(mutation.is_valid());
        assert!(!substituted_package.is_valid());
        let runtime_deployment = DeploymentId([0x89; 32]);
        let work = RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: SpaceId([0x71; 32]),
            agent: AgentId([0x72; 32]),
            runtime_deployment,
            state: RuntimeState::default(),
            request: alloc::boxed::Box::new(request.clone()),
            authority: Some(alloc::boxed::Box::new(private_management_receipt(
                &request,
                runtime_deployment,
            ))),
            observed_slot: 10,
        };
        let encoded = work.encode().unwrap();
        assert!(encoded.len() <= MAX_RUNTIME_WORK_WIRE_BYTES);
        assert!(encoded.len() < 32 * 1024 * 1024);
        assert_eq!(RuntimeWork::decode(&encoded), Ok(work));
    }

    #[test]
    fn private_records_and_ciphertext_have_strict_canonical_wires() {
        let node = private_node();
        let sealed = |byte| SealedPrivateKey {
            node: node.node,
            recipient_key: node.encryption_public_key,
            sealed: alloc::vec![byte; 48],
        };
        let control = PrivateControlRecord {
            space: SpaceId([7; 32]),
            agent: AgentId([8; 32]),
            sequence: 0,
            previous: None,
            operation: PrivateControlOperation::Invite {
                node: node.clone(),
                epoch: 0,
                sealed_owner_key: sealed(9),
                sealed_data_key: sealed(10),
                historical_grants: Vec::new(),
            },
            signer: PrivateControlSigner::Owner,
            signer_public_key: [11; 32],
            signature: [12; 64],
        };
        let encoded = control.encode().unwrap();
        assert_eq!(PrivateControlRecord::decode(&encoded), Ok(control));

        let object = EncryptedPrivateObject {
            space: SpaceId([7; 32]),
            agent: AgentId([8; 32]),
            epoch: 1,
            kind: EncryptedObjectKind::CrdtNode,
            content: Hash([13; 32]),
            nonce: [14; PRIVATE_NONCE_BYTES],
            ciphertext: alloc::vec![15; 128],
        };
        let encoded = object.encode().unwrap();
        assert_eq!(EncryptedPrivateObject::decode(&encoded), Ok(object));
    }

    #[test]
    fn runtime_state_aggregate_bound_is_enforced_while_decoding() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(&alloc::vec![0; MAX_RUNTIME_STATE_BYTES]);
        encoder.bytes(&[1]);
        encoder.bytes(&[]);
        encoder.bytes(&[]);
        assert_eq!(
            decode_runtime_state(&mut Decoder::new(&bytes)),
            Err(DecodeError::LimitExceeded)
        );
    }
}
