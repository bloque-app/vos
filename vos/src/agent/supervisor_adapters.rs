//! Canonical clean-host adapters for [`super::supervisor::AgentSupervisorOwner`].
//!
//! The generic supervisor deliberately treats payloads as bounded opaque
//! bytes. This module is the only clean Agent adapter allowed to cross that
//! seam: it accepts one canonical `ASQ1` envelope containing the exact SDK
//! [`InvocationWork`] and [`InvocationAuthorization`], verifies every route
//! identity field again, and emits one canonical `ASR1` response. Legacy
//! Service frames and direct nested runtime frames are not compatibility
//! inputs.
//!
//! Direct responses contain only a canonical [`RuntimeOutcome`]. Attested
//! responses are a distinct variant carrying the public
//! [`TransitionProofRecord`] and either its exact content-addressed bytes or
//! the exact reference. Producer-private witnesses have no representation in
//! this module.

use core::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
use super::sdk::authority::{
    AuthorityActorProjection, AuthorityActorTarget, AuthorityProjectionHead,
    AuthorityProjectionQuery,
};
use super::sdk::method_policy::{
    ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
    AuthorizationPolicySelector,
};
use super::sdk::proof::{
    MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES, TransitionProofKey,
    TransitionProofMaterialManifest, TransitionProofRecord,
};
use super::sdk::wire::{
    CanonicalWire, MAX_RUNTIME_TRANSITION_WIRE_BYTES, MAX_RUNTIME_WORK_WIRE_BYTES, WireError,
};
use super::sdk::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorId, AgentDescriptor, AgentId, AgentProfile,
    BlobRef, CapabilityId, CredentialId, DeploymentId, Hash, InvocationAuthorization, InvocationId,
    InvocationOrigin, InvocationResultStorage, InvocationRoleClaims, InvocationWork,
    MAX_CATALOG_ARTIFACT_BYTES, MAX_DIRECTORY_PAGE_ENTRIES, MAX_INVOCATION_MESSAGE_BYTES,
    MAX_RUNTIME_AVAILABILITY_BYTES, MAX_RUNTIME_AVAILABILITY_ITEMS, MethodMode, NodeId,
    PrincipalId, ProgramId, RoleId, RuntimeBlob, RuntimeExecutionContext, RuntimeOutcome,
    RuntimeState, RuntimeTransition, RuntimeWork, SpaceId,
};
use super::supervisor::{
    AgentRoute, AgentRouteAttachment, AgentRouteError, AgentRouteIdentity, AgentRouteKey,
    AgentRouteSnapshot, AgentRouteWorkerError, AgentRouteWorkerOwner, AgentSupervisorError,
};

const REQUEST_MAGIC: [u8; 4] = *b"ASQ1";
const RESPONSE_MAGIC: [u8; 4] = *b"ASR1";
const PREPARATION_REQUEST_MAGIC: [u8; 4] = *b"APQ1";
const PREPARATION_RESPONSE_MAGIC: [u8; 4] = *b"APR1";
// Generation 2 carries the exact execution context and conditional live-proof
// key. Generation 1 frames are deliberately not upgraded implicitly.
const RESUME_REQUEST_MAGIC: [u8; 4] = *b"ARQ3";
const RESUME_RESPONSE_MAGIC: [u8; 4] = *b"ARR3";
const ACKNOWLEDGEMENT_REQUEST_MAGIC: [u8; 4] = *b"AAQ3";
const ACKNOWLEDGEMENT_RESPONSE_MAGIC: [u8; 4] = *b"AAR3";
const MAX_YIELDED_SELECTOR_BYTES: usize = 8 * 1024;
const TRANSITION_PROOF_KEY_WIRE_BYTES: usize = 2 * 32;
const ROUTE_WORKER_RUNNING: u8 = 0;
const ROUTE_WORKER_CLOSING: u8 = 1;
const ROUTE_WORKER_CLOSED: u8 = 2;
const ROUTE_WORKER_FAILED: u8 = 3;

/// Caller-selected portion of a new clean invocation.
///
/// Physical identity, installation data, and availability are deliberately
/// absent. They are selected only by the live route worker. This first seam
/// admits no supplemental caller availability: its exact closure is the
/// installed program, schema, AMP2 policy, and optional constructor data, so
/// an ingress cannot smuggle arbitrary blobs beside a valid package. Resuming
/// a yielded invocation is also intentionally absent: the route-owned
/// continuation driver must reconstruct [`super::sdk::ResumeWork`] from its
/// durable FIFO head and its retained exact availability references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInvocationIntent {
    invocation: InvocationId,
    mode: MethodMode,
    origin: InvocationOrigin,
    roles: InvocationRoleClaims,
    message: Vec<u8>,
    gas: u64,
    recovery_only: bool,
}

impl AgentInvocationIntent {
    pub fn new(
        invocation: InvocationId,
        mode: MethodMode,
        origin: InvocationOrigin,
        roles: InvocationRoleClaims,
        message: Vec<u8>,
        gas: u64,
        recovery_only: bool,
    ) -> Result<Self, WireError> {
        let value = Self {
            invocation,
            mode,
            origin,
            roles,
            message,
            gas,
            recovery_only,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub const fn invocation(&self) -> InvocationId {
        self.invocation
    }

    pub const fn mode(&self) -> MethodMode {
        self.mode
    }

    pub const fn origin(&self) -> InvocationOrigin {
        self.origin
    }

    pub const fn roles(&self) -> InvocationRoleClaims {
        self.roles
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub const fn gas(&self) -> u64 {
        self.gas
    }

    pub const fn recovery_only(&self) -> bool {
        self.recovery_only
    }

    fn validate(&self) -> bool {
        self.invocation != InvocationId::ZERO
            && self.origin.validate()
            && self.roles.validate_for(self.origin)
            && !self.message.is_empty()
            && self.message.len() <= MAX_INVOCATION_MESSAGE_BYTES
            && self.gas != 0
            && self.gas <= super::execution::MAX_INVOCATION_GAS_CEILING
    }
}

/// Complete host-prepared work. The request commitment binds the exact
/// readiness generation used to obtain it; the work commitment is therefore
/// stable input for either PublicPreflight construction or AOC5 issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAgentInvocation {
    request: Hash,
    profile: AgentProfile,
    runtime_program: ProgramId,
    runtime_package: BlobRef,
    observed_slot: u64,
    work: InvocationWork,
    policies: ActorMethodPolicyArtifact,
    selected_method: String,
}

impl PreparedAgentInvocation {
    pub const fn request_commitment(&self) -> Hash {
        self.request
    }

    pub const fn profile(&self) -> AgentProfile {
        self.profile
    }

    pub const fn runtime_program(&self) -> ProgramId {
        self.runtime_program
    }

    pub const fn runtime_package(&self) -> &BlobRef {
        &self.runtime_package
    }

    pub const fn observed_slot(&self) -> u64 {
        self.observed_slot
    }

    pub const fn work(&self) -> &InvocationWork {
        &self.work
    }

    pub fn into_work(self) -> InvocationWork {
        self.work
    }

    pub const fn method_policy_artifact(&self) -> &ActorMethodPolicyArtifact {
        &self.policies
    }

    pub fn selected_method(&self) -> &ActorMethodPolicy {
        self.policies
            .method(&self.selected_method)
            .expect("validated prepared invocation retained its selected method")
    }

    pub fn public_preflight(&self) -> Option<super::sdk::PublicPreflight> {
        (self.selected_method().authorization_policy == AuthorizationPolicySelector::Public)
            .then(|| super::sdk::PublicPreflight::for_work(&self.work, self.observed_slot))
    }
}

/// Remote preparation selects only a route and untrusted invocation intent.
/// The live host supplies incarnation, packages, installation data and policy.
/// Preparation itself is neither caller authentication nor authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTargetedPreparationRequest {
    target: AgentRouteKey,
    intent: AgentInvocationIntent,
}

impl AgentTargetedPreparationRequest {
    pub fn new(target: AgentRouteKey, intent: AgentInvocationIntent) -> Result<Self, WireError> {
        let value = Self { target, intent };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub const fn target(&self) -> AgentRouteKey {
        self.target
    }

    pub const fn intent(&self) -> &AgentInvocationIntent {
        &self.intent
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/targeted-preparation/v1",
            &[&self.encode().expect("validated preparation")],
        )
    }
}

impl CanonicalWire for AgentTargetedPreparationRequest {
    const MAGIC: [u8; 4] = *b"ATQ1";
    const MAX_ENCODED_BYTES: usize = AgentPreparationRequest::MAX_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        self.intent.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.target.space().as_bytes());
        encoder.fixed(self.target.agent().as_bytes());
        encoder.fixed(self.target.actor().as_bytes());
        encode_intent(encoder, &self.intent);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let target = AgentRouteKey::new(
            SpaceId(decoder.fixed()?),
            AgentId(decoder.fixed()?),
            ActorId(decoder.fixed()?),
        )
        .map_err(|_| DecodeError::NonCanonical)?;
        Self::new(target, decode_intent(decoder)?).map_err(|_| DecodeError::NonCanonical)
    }
}

/// Response-bound physical preparation, not a signed Authority approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTargetedPreparationResponse {
    request: Hash,
    prepared: PreparedAgentInvocation,
}

impl AgentTargetedPreparationResponse {
    /// Check the exact remote intent before using any returned physical work.
    /// This does not independently authenticate the responding host or policy.
    pub fn for_request(
        &self,
        request: &AgentTargetedPreparationRequest,
    ) -> Option<&PreparedAgentInvocation> {
        let work = self.prepared.work();
        let intent = request.intent();
        (self.request == request.commitment()
            && work.space == request.target.space()
            && work.agent == request.target.agent()
            && work.actor == request.target.actor()
            && work.invocation == intent.invocation
            && work.mode == intent.mode
            && work.origin == intent.origin
            && work.roles == intent.roles
            && work.message == intent.message
            && work.gas == intent.gas
            && work.recovery_only == intent.recovery_only)
            .then_some(&self.prepared)
    }
}

impl CanonicalWire for AgentTargetedPreparationResponse {
    const MAGIC: [u8; 4] = *b"ATP1";
    const MAX_ENCODED_BYTES: usize = 36 + 32 + 4 + AgentPreparationResponse::MAX_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        self.request != Hash::ZERO && prepared_invocation_valid(&self.prepared)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.request.as_bytes());
        encoder.bytes(
            &AgentPreparationResponse {
                prepared: self.prepared.clone(),
            }
            .encode()
            .expect("validated preparation"),
        );
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = Hash(decoder.fixed()?);
        let bytes = decoder.bytes_bounded(AgentPreparationResponse::MAX_ENCODED_BYTES)?;
        let prepared = AgentPreparationResponse::decode(&bytes)
            .map_err(|_| DecodeError::NonCanonical)?
            .prepared;
        let value = Self { request, prepared };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

/// Resolve a client-selected target at the current live generation. Neither
/// cached identity nor caller-supplied availability enters this preparation.
pub fn prepare_targeted_invocation(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    request: &AgentTargetedPreparationRequest,
) -> Result<AgentTargetedPreparationResponse, AgentSupervisorError> {
    let snapshot = supervisor.snapshot(request.target)?;
    let prepared = prepare_invocation(supervisor, snapshot, request.intent.clone())?;
    Ok(AgentTargetedPreparationResponse {
        request: request.commitment(),
        prepared,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentPreparationRequest {
    expected: AgentRouteIdentity,
    readiness_generation: u64,
    intent: AgentInvocationIntent,
}

impl AgentPreparationRequest {
    fn new(snapshot: AgentRouteSnapshot, intent: AgentInvocationIntent) -> Result<Self, WireError> {
        let value = Self {
            expected: snapshot.identity(),
            readiness_generation: snapshot.readiness_generation().get(),
            intent,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    fn matches_route(&self, route: AgentRouteSnapshot) -> bool {
        self.expected == route.identity()
            && self.readiness_generation == route.readiness_generation().get()
    }

    fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/supervisor-invocation-preparation/v1",
            &[&self
                .encode()
                .expect("validated preparation request is canonical")],
        )
    }
}

impl CanonicalWire for AgentPreparationRequest {
    const MAGIC: [u8; 4] = PREPARATION_REQUEST_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4
        + 32
        + (7 * 32 + 1)
        + 8
        + (32 + 1 + 5 * (1 + 32) + 2 * (1 + 32) + 4 + MAX_INVOCATION_MESSAGE_BYTES + 8 + 1);

    fn validate_wire(&self) -> bool {
        self.expected.profile() != AgentProfile::Private
            && self.readiness_generation != 0
            && self.intent.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_route_identity(encoder, self.expected);
        encoder.u64(self.readiness_generation);
        encode_intent(encoder, &self.intent);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            expected: decode_route_identity(decoder)?,
            readiness_generation: decoder.u64()?,
            intent: decode_intent(decoder)?,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentPreparationResponse {
    prepared: PreparedAgentInvocation,
}

impl CanonicalWire for AgentPreparationResponse {
    const MAGIC: [u8; 4] = PREPARATION_RESPONSE_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4
        + 32
        + 32
        + 1
        + 32
        + 32
        + 8
        + 8
        + MAX_RUNTIME_WORK_WIRE_BYTES
        + 4
        + ActorMethodPolicyArtifact::MAX_ENCODED_BYTES
        + 4
        + super::sdk::method_policy::MAX_METHOD_POLICY_NAME_BYTES;

    fn validate_wire(&self) -> bool {
        prepared_invocation_valid(&self.prepared)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.prepared.request.as_bytes());
        encoder.u8(self.prepared.profile as u8);
        encoder.fixed(self.prepared.runtime_program.as_bytes());
        encode_blob_ref(encoder, &self.prepared.runtime_package);
        encoder.u64(self.prepared.observed_slot);
        encode_invocation_work(encoder, &self.prepared.work);
        let policies = self
            .prepared
            .policies
            .encode()
            .expect("validated prepared invocation has canonical AMP2");
        encoder.bytes(&policies);
        encoder.string(&self.prepared.selected_method);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = Hash(decoder.fixed()?);
        let profile = decode_profile(decoder.u8()?)?;
        let runtime_program = ProgramId(decoder.fixed()?);
        let runtime_package = decode_blob_ref(decoder)?;
        let observed_slot = decoder.u64()?;
        let work = decode_invocation_work(decoder)?;
        let policies = decoder
            .bytes_bounded(ActorMethodPolicyArtifact::MAX_ENCODED_BYTES)
            .and_then(|bytes| {
                ActorMethodPolicyArtifact::decode(&bytes).map_err(|_| DecodeError::NonCanonical)
            })?;
        let prepared = PreparedAgentInvocation {
            request,
            profile,
            runtime_program,
            runtime_package,
            observed_slot,
            work,
            policies,
            selected_method: decoder
                .string_bounded(super::sdk::method_policy::MAX_METHOD_POLICY_NAME_BYTES)?,
        };
        let value = Self { prepared };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn encode_route_identity(encoder: &mut Encoder<'_>, identity: AgentRouteIdentity) {
    encoder.fixed(identity.key().space().as_bytes());
    encoder.fixed(identity.key().agent().as_bytes());
    encoder.fixed(identity.key().actor().as_bytes());
    encoder.fixed(identity.incarnation().as_bytes());
    encoder.fixed(identity.runtime_deployment().as_bytes());
    encoder.fixed(identity.actor_deployment().as_bytes());
    encoder.fixed(identity.actor_program().as_bytes());
    encoder.u8(identity.profile() as u8);
}

fn decode_route_identity(decoder: &mut Decoder<'_>) -> Result<AgentRouteIdentity, DecodeError> {
    let key = AgentRouteKey::new(
        SpaceId(decoder.fixed()?),
        AgentId(decoder.fixed()?),
        ActorId(decoder.fixed()?),
    )
    .map_err(|_| DecodeError::NonCanonical)?;
    AgentRouteIdentity::new(
        key,
        Hash(decoder.fixed()?),
        DeploymentId(decoder.fixed()?),
        DeploymentId(decoder.fixed()?),
        ProgramId(decoder.fixed()?),
        decode_profile(decoder.u8()?)?,
    )
    .map_err(|_| DecodeError::NonCanonical)
}

fn encode_intent(encoder: &mut Encoder<'_>, intent: &AgentInvocationIntent) {
    encoder.fixed(intent.invocation.as_bytes());
    encoder.u8(intent.mode as u8);
    encode_origin(encoder, intent.origin);
    encode_roles(encoder, intent.roles);
    encoder.bytes(&intent.message);
    encoder.u64(intent.gas);
    encoder.bool(intent.recovery_only);
}

fn decode_intent(decoder: &mut Decoder<'_>) -> Result<AgentInvocationIntent, DecodeError> {
    let invocation = InvocationId(decoder.fixed()?);
    let mode = decode_mode(decoder.u8()?)?;
    let origin = decode_origin(decoder)?;
    let roles = decode_roles(decoder, origin)?;
    let value = AgentInvocationIntent {
        invocation,
        mode,
        origin,
        roles,
        message: decoder.bytes_bounded(MAX_INVOCATION_MESSAGE_BYTES)?,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_origin(encoder: &mut Encoder<'_>, origin: InvocationOrigin) {
    encoder.option(&origin.principal, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.transport_node, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.credential, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&origin.capability, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_origin(decoder: &mut Decoder<'_>) -> Result<InvocationOrigin, DecodeError> {
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

fn encode_roles(encoder: &mut Encoder<'_>, roles: InvocationRoleClaims) {
    encoder.option(&roles.space, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&roles.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_roles(
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

fn encode_blob_ref(encoder: &mut Encoder<'_>, reference: &BlobRef) {
    encoder.fixed(reference.hash.as_bytes());
    encoder.u64(reference.len);
}

fn decode_blob_ref(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_runtime_blob(encoder: &mut Encoder<'_>, blob: &RuntimeBlob) {
    encode_blob_ref(encoder, &blob.reference);
    encoder.bytes(&blob.bytes);
}

fn decode_runtime_blob(decoder: &mut Decoder<'_>) -> Result<RuntimeBlob, DecodeError> {
    let value = RuntimeBlob {
        reference: decode_blob_ref(decoder)?,
        bytes: decoder.bytes_bounded(MAX_RUNTIME_AVAILABILITY_BYTES)?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_invocation_work(encoder: &mut Encoder<'_>, work: &InvocationWork) {
    encoder.fixed(work.space.as_bytes());
    encoder.fixed(work.agent.as_bytes());
    encoder.fixed(work.runtime_deployment.as_bytes());
    encoder.fixed(work.invocation.as_bytes());
    encoder.fixed(work.actor.as_bytes());
    encoder.fixed(work.incarnation.as_bytes());
    encoder.fixed(work.deployment.as_bytes());
    encoder.fixed(work.program.as_bytes());
    encoder.u8(work.mode as u8);
    encode_origin(encoder, work.origin);
    encode_roles(encoder, work.roles);
    encoder.bytes(&work.message);
    encoder.option(&work.installation_data, encode_blob_ref);
    encoder.list(&work.availability, encode_runtime_blob);
    encoder.u64(work.gas);
    encoder.bool(work.recovery_only);
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
    let mode = decode_mode(decoder.u8()?)?;
    let origin = decode_origin(decoder)?;
    let roles = decode_roles(decoder, origin)?;
    let work = InvocationWork {
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
        installation_data: decoder.option(decode_blob_ref)?,
        availability: decoder.list_bounded(MAX_RUNTIME_AVAILABILITY_ITEMS, decode_runtime_blob)?,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    work.validate()
        .then_some(work)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_profile(value: u8) -> Result<AgentProfile, DecodeError> {
    match value {
        0 => Ok(AgentProfile::Local),
        1 => Ok(AgentProfile::Shared),
        2 => Ok(AgentProfile::Private),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn decode_mode(value: u8) -> Result<MethodMode, DecodeError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn invocation_method_name(message: &[u8]) -> Option<String> {
    use crate::actors::codec::Decode as _;
    use crate::actors::value::{Msg, TAG_DYNAMIC};

    message
        .strip_prefix(&[TAG_DYNAMIC])
        .and_then(Msg::try_decode)
        .map(|message| message.name)
}

fn claims_match_policy(
    policy: AuthorizationPolicySelector,
    origin: InvocationOrigin,
    roles: InvocationRoleClaims,
) -> bool {
    match policy {
        AuthorizationPolicySelector::Public => {
            origin.capability.is_none() && roles == InvocationRoleClaims::none()
        }
        AuthorizationPolicySelector::Capability(required) => {
            origin.capability == Some(required) && roles == InvocationRoleClaims::none()
        }
        AuthorizationPolicySelector::SpaceRole(required) => {
            origin.capability.is_none() && roles.space == Some(required) && roles.actor.is_none()
        }
        AuthorizationPolicySelector::ActorRole(required) => {
            origin.capability.is_none() && roles.actor == Some(required) && roles.space.is_none()
        }
    }
}

fn prepared_invocation_valid(prepared: &PreparedAgentInvocation) -> bool {
    if prepared.request == Hash::ZERO
        || prepared.profile == AgentProfile::Private
        || prepared.runtime_program == ProgramId::ZERO
        || prepared.runtime_package.hash == Hash::ZERO
        || prepared.runtime_package.len == 0
        || prepared.runtime_package.len > MAX_CATALOG_ARTIFACT_BYTES
        || !prepared.work.validate()
        || prepared.policies.validate().is_err()
        || prepared.selected_method.is_empty()
    {
        return false;
    }
    let Ok(policy_bytes) = prepared.policies.encode() else {
        return false;
    };
    let policy_reference = BlobRef::of_bytes(&policy_bytes);
    let mut program = None;
    let mut schema = None;
    let mut policies = None;
    let mut installation_data = None;
    for (index, blob) in prepared.work.availability.iter().enumerate() {
        if ProgramId::of_pvm(&blob.bytes) == prepared.work.program {
            if program.replace(index).is_some() {
                return false;
            }
        }
        if blob.reference == prepared.policies.actor_schema {
            if schema.replace(index).is_some() {
                return false;
            }
        }
        if blob.reference == policy_reference {
            if policies.replace(index).is_some() {
                return false;
            }
        }
        if prepared
            .work
            .installation_data
            .as_ref()
            .is_some_and(|reference| blob.reference == *reference)
            && installation_data.replace(index).is_some()
        {
            return false;
        }
    }
    let (Some(program), Some(schema), Some(policies)) = (program, schema, policies) else {
        return false;
    };
    let installation_data = match (prepared.work.installation_data.as_ref(), installation_data) {
        (None, None) => None,
        (Some(_), Some(index)) => Some(index),
        _ => return false,
    };
    let mut roles = vec![program, schema, policies];
    roles.extend(installation_data);
    roles.sort_unstable();
    if roles.windows(2).any(|pair| pair[0] == pair[1])
        || roles.len() != prepared.work.availability.len()
        || prepared.work.availability[policies].bytes != policy_bytes
    {
        return false;
    }
    let schema_bytes = &prepared.work.availability[schema].bytes;
    let Ok(parsed_schema) = super::sdk::schema::decode(schema_bytes) else {
        return false;
    };
    if prepared
        .policies
        .validate_against_schema(&parsed_schema)
        .is_err()
        || !parsed_schema.lanes().supported_by(prepared.profile)
        || parsed_schema.requires_installation_data() != prepared.work.installation_data.is_some()
    {
        return false;
    }
    let Some(method_name) = invocation_method_name(&prepared.work.message) else {
        return false;
    };
    let Some(method) = prepared.policies.method(&method_name) else {
        return false;
    };
    if method_name != prepared.selected_method
        || method.mode != prepared.work.mode
        || !claims_match_policy(
            method.authorization_policy,
            prepared.work.origin,
            prepared.work.roles,
        )
    {
        return false;
    }
    match prepared.work.mode.result_storage() {
        InvocationResultStorage::Control => true,
        InvocationResultStorage::Lane(lane) => prepared.profile.supports(lane),
    }
}

fn prepare_from_physical_material(
    request: &AgentPreparationRequest,
    material: super::invocation_preparation::PhysicalInvocationMaterial,
) -> Result<PreparedAgentInvocation, AgentRouteError> {
    let identity = &material.descriptor.identity;
    let expected = request.expected;
    if material.descriptor.validate().is_err()
        || identity.profile == AgentProfile::Private
        || identity.space != expected.key().space()
        || identity.agent != expected.key().agent()
        || identity.runtime_deployment != expected.runtime_deployment()
        || material.actor.validate().is_err()
        || material.actor.install_request != material.install_request
        || material
            .actor
            .entry
            .validate_for_profile(identity.profile)
            .is_err()
        || material.actor.entry.suspended
        || material.actor.entry.actor != expected.key().actor()
        || material.actor.incarnation != expected.incarnation()
        || material.actor.entry.deployment != expected.actor_deployment()
        || material.actor.entry.program != expected.actor_program()
        || !material.program.validate()
        || ProgramId::of_pvm(&material.program.bytes) != material.actor.entry.program
        || !material.schema.validate()
        || material.schema.reference != material.actor.entry.agent_schema
        || !material.policies.validate()
        || material.policies.reference != material.actor.entry.method_policy
        || match (
            material.actor.entry.installation_data.as_ref(),
            material.installation_data.as_ref(),
        ) {
            (None, None) => false,
            (Some(expected), Some(actual)) => !actual.validate() || actual.reference != *expected,
            _ => true,
        }
    {
        return Err(AgentRouteError::Unavailable);
    }
    let policies = ActorMethodPolicyArtifact::decode(&material.policies.bytes)
        .map_err(|_| AgentRouteError::Unavailable)?;
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    if availability
        .windows(2)
        .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(AgentRouteError::Unavailable);
    }
    let intent = &request.intent;
    let work = InvocationWork {
        space: expected.key().space(),
        agent: expected.key().agent(),
        runtime_deployment: expected.runtime_deployment(),
        invocation: intent.invocation,
        actor: expected.key().actor(),
        incarnation: expected.incarnation(),
        deployment: expected.actor_deployment(),
        program: expected.actor_program(),
        mode: intent.mode,
        origin: intent.origin,
        roles: intent.roles,
        message: intent.message.clone(),
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: intent.gas,
        recovery_only: intent.recovery_only,
    };
    let selected_method = invocation_method_name(&work.message).ok_or(AgentRouteError::Rejected)?;
    let prepared = PreparedAgentInvocation {
        request: request.commitment(),
        profile: identity.profile,
        runtime_program: identity.runtime_program,
        runtime_package: material.descriptor.runtime_package,
        observed_slot: material.observed_slot,
        work,
        policies,
        selected_method,
    };
    prepared_invocation_valid(&prepared)
        .then_some(prepared)
        .ok_or(AgentRouteError::Rejected)
}

fn physical_material_matches_identity(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
    expected: AgentRouteIdentity,
) -> bool {
    let identity = &material.descriptor.identity;
    material.descriptor.validate().is_ok()
        && material.actor.validate().is_ok()
        && material.actor.install_request == material.install_request
        && identity.space == expected.key().space()
        && identity.agent == expected.key().agent()
        && identity.profile == expected.profile()
        && identity.runtime_deployment == expected.runtime_deployment()
        && material.actor.entry.actor == expected.key().actor()
        && material.actor.incarnation == expected.incarnation()
        && material.actor.entry.deployment == expected.actor_deployment()
        && material.actor.entry.program == expected.actor_program()
        && !material.actor.entry.suspended
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn physical_material_identity(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
) -> Result<AgentRouteIdentity, AgentRouteError> {
    let descriptor = &material.descriptor;
    let actor = &material.actor;
    let key = AgentRouteKey::new(
        descriptor.identity.space,
        descriptor.identity.agent,
        actor.entry.actor,
    )
    .map_err(|_| AgentRouteError::Unavailable)?;
    let identity = AgentRouteIdentity::new(
        key,
        actor.incarnation,
        descriptor.identity.runtime_deployment,
        actor.entry.deployment,
        actor.entry.program,
        descriptor.identity.profile,
    )
    .map_err(|_| AgentRouteError::Unavailable)?;
    physical_material_matches_identity(material, identity)
        .then_some(identity)
        .ok_or(AgentRouteError::Unavailable)
}

/// Compare policy facts with the independently loaded physical descriptor,
/// install record, and admitted content-addressed actor package.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn physical_material_matches_authority(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
    descriptor: &AgentDescriptor,
    actor: &AuthorityActorProjection,
) -> bool {
    material.descriptor == *descriptor
        && material.descriptor.validate().is_ok()
        && material.actor.validate().is_ok()
        && material.actor.install_request == material.install_request
        && material.actor.entry == actor.entry
        && material.actor.installation_id == actor.installation_id
        && material.actor.registry_reservation == actor.registry_reservation
        && material.install_request == actor.install_request
        && material.producer == actor.producer
        && material.contract == actor.contract
        && material.requirements == actor.requirements
        && material.root_provenance == actor.root_provenance
        && material.program.validate()
        && ProgramId::of_pvm(&material.program.bytes) == actor.entry.program
        && material.schema.validate()
        && material.schema.reference == actor.entry.agent_schema
        && material.policies.validate()
        && material.policies.reference == actor.entry.method_policy
        && match (
            actor.entry.installation_data.as_ref(),
            material.installation_data.as_ref(),
        ) {
            (None, None) => true,
            (Some(expected), Some(actual)) => actual.validate() && actual.reference == *expected,
            _ => false,
        }
}

/// Re-check one exact invocation against the physically loaded actor closure.
///
/// A `PublicPreflight` is intentionally unsigned, so accepting it based only
/// on its work commitment would let a caller bypass a Capability/role or
/// attestation-required AMP2 selector when the admitted runtime is custom.
/// Concrete Local, Shared, and System routes call this after loading current
/// physical material and before handing any work to the runtime.
pub(crate) fn physical_material_authorizes_work(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
    expected: AgentRouteIdentity,
    execution: RuntimeExecutionContext,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
) -> bool {
    physical_material_authorizes_work_at(
        material,
        expected,
        execution,
        work,
        authorization,
        material.observed_slot,
    )
}

/// Re-check exact durably prepared work at the preflight slot accepted before
/// its pending record was committed. Projection recovery and management
/// coordination use this path; physical actor/artifact/route state remains
/// current and exact. This does not itself reserve journal capacity.
pub(crate) fn physical_material_authorizes_reserved_work(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
    expected: AgentRouteIdentity,
    execution: RuntimeExecutionContext,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    accepted_observed_slot: u64,
) -> bool {
    accepted_observed_slot <= material.observed_slot
        && physical_material_authorizes_work_at(
            material,
            expected,
            execution,
            work,
            authorization,
            accepted_observed_slot,
        )
}

fn physical_material_authorizes_work_at(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
    expected: AgentRouteIdentity,
    execution: RuntimeExecutionContext,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    accepted_observed_slot: u64,
) -> bool {
    if !physical_material_matches_identity(material, expected)
        || !execution.is_valid()
        || !work.validate()
        || !authorization.matches_invoke(work, accepted_observed_slot)
        || work.space != expected.key().space()
        || work.agent != expected.key().agent()
        || work.actor != expected.key().actor()
        || work.incarnation != expected.incarnation()
        || work.runtime_deployment != expected.runtime_deployment()
        || work.deployment != expected.actor_deployment()
        || work.program != expected.actor_program()
        || work.installation_data != material.actor.entry.installation_data
        || !material.program.validate()
        || ProgramId::of_pvm(&material.program.bytes) != work.program
        || !material.schema.validate()
        || material.schema.reference != material.actor.entry.agent_schema
        || !material.policies.validate()
        || material.policies.reference != material.actor.entry.method_policy
        || match (
            material.actor.entry.installation_data.as_ref(),
            material.installation_data.as_ref(),
        ) {
            (None, None) => false,
            (Some(reference), Some(blob)) => !blob.validate() || &blob.reference != reference,
            _ => true,
        }
    {
        return false;
    }

    let mut availability = vec![
        material.program.clone(),
        material.schema.clone(),
        material.policies.clone(),
    ];
    availability.extend(material.installation_data.clone());
    availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    let genesis_publication = invocation_method_name(&work.message).as_deref()
        == Some("publish_genesis")
        && work.actor == material.descriptor.authority.issuer.actor
        && work.deployment == material.descriptor.authority.issuer.deployment
        && work.program == material.descriptor.authority.issuer.program
        && material.producer == material.descriptor.authority.issuer.producer;
    if availability != work.availability || genesis_publication {
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        {
            // Publication permits one bound provision blob, never arbitrary
            // replacement/removal of authenticated installation artifacts.
            if !genesis_publication || work.availability.len() != availability.len() + 1 {
                return false;
            }
            let Some(extra) = work.availability.iter().find(|blob| {
                !availability
                    .iter()
                    .any(|base| base.reference == blob.reference)
            }) else {
                return false;
            };
            if !super::clean_bootstrap::genesis_issuance::publication_blob_matches(work, extra) {
                return false;
            }
            availability.push(extra.clone());
            availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
            if availability != work.availability {
                return false;
            }
        }
        #[cfg(not(all(feature = "storage", feature = "network", target_os = "linux")))]
        return false;
    }

    let Ok(schema) = super::sdk::schema::decode(&material.schema.bytes) else {
        return false;
    };
    let Ok(policies) = ActorMethodPolicyArtifact::decode(&material.policies.bytes) else {
        return false;
    };
    if policies.validate_against_schema(&schema).is_err()
        || schema
            .state_layout_hash()
            .ok()
            .is_none_or(|layout| layout != material.actor.entry.state_layout)
        || schema.lanes() != material.actor.entry.lanes
        || schema.requires_installation_data() != work.installation_data.is_some()
    {
        return false;
    }
    let Some(method_name) = invocation_method_name(&work.message) else {
        return false;
    };
    let Some(method) = policies.method(&method_name) else {
        return false;
    };
    if method.mode != work.mode
        || !execution_matches_attestation(execution, method.attestation)
        || !claims_match_policy(method.authorization_policy, work.origin, work.roles)
    {
        return false;
    }

    match authorization {
        InvocationAuthorization::PublicPreflight(_) => {
            method.authorization_policy == AuthorizationPolicySelector::Public
        }
        InvocationAuthorization::AuthorityReceipt(receipt) => {
            material.descriptor.authority.accepts(receipt)
                && super::authority::verify_raw_ed25519(
                    &receipt.public_key,
                    &receipt.signing_bytes(),
                    &receipt.signature,
                )
        }
    }
}

fn execution_matches_attestation(
    execution: RuntimeExecutionContext,
    required: AttestationRequirement,
) -> bool {
    matches!(
        (execution, required),
        (
            RuntimeExecutionContext::Direct,
            AttestationRequirement::None
        )
    ) || matches!(
        (execution, required),
        (
            RuntimeExecutionContext::Attested { proof_system },
            AttestationRequirement::Required {
                proof_system: required,
            },
        ) if proof_system == required
    )
}

fn prepared_matches_request(
    prepared: &PreparedAgentInvocation,
    snapshot: AgentRouteSnapshot,
    request: &AgentPreparationRequest,
) -> bool {
    let work = &prepared.work;
    prepared_invocation_valid(prepared)
        && prepared.request == request.commitment()
        && prepared.profile == snapshot.profile()
        && work.space == snapshot.key().space()
        && work.agent == snapshot.key().agent()
        && work.actor == snapshot.key().actor()
        && work.incarnation == snapshot.incarnation()
        && work.runtime_deployment == snapshot.runtime_deployment()
        && work.deployment == snapshot.actor_deployment()
        && work.program == snapshot.actor_program()
        && work.invocation == request.intent.invocation
        && work.mode == request.intent.mode
        && work.origin == request.intent.origin
        && work.roles == request.intent.roles
        && work.message == request.intent.message
        && work.gas == request.intent.gas
        && work.recovery_only == request.intent.recovery_only
}

/// One canonical supervisor invocation. The host, never ingress, supplies
/// current runtime state and trusted logical time after this envelope is
/// decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInvocationRequest {
    execution: RuntimeExecutionContext,
    work: InvocationWork,
    authorization: InvocationAuthorization,
}

impl AgentInvocationRequest {
    pub fn new(
        execution: RuntimeExecutionContext,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<Self, WireError> {
        let value = Self {
            execution,
            work,
            authorization,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub const fn execution(&self) -> RuntimeExecutionContext {
        self.execution
    }

    pub const fn work(&self) -> &InvocationWork {
        &self.work
    }

    pub const fn authorization(&self) -> &InvocationAuthorization {
        &self.authorization
    }

    /// Commitment of the complete canonical supervisor request. Every ASR1
    /// response repeats this value, including identity-free execution errors,
    /// so a valid response cannot be replayed across two invocations.
    pub fn commitment(&self) -> super::sdk::Hash {
        super::sdk::Hash::digest(
            b"vos/agent/supervisor-invocation-request/v1",
            &[&self
                .encode()
                .expect("validated supervisor invocation is canonical")],
        )
    }

    fn nested_work(&self) -> RuntimeWork {
        RuntimeWork::Invoke {
            context: self.execution,
            state: RuntimeState::default(),
            invocation: Box::new(self.work.clone()),
            authorization: Box::new(self.authorization.clone()),
            observed_slot: canonical_transport_slot(&self.authorization),
        }
    }

    fn matches_route(&self, route: AgentRouteSnapshot) -> bool {
        let work = &self.work;
        work.space == route.key().space()
            && work.agent == route.key().agent()
            && work.actor == route.key().actor()
            && work.incarnation == route.incarnation()
            && work.runtime_deployment == route.runtime_deployment()
            && work.deployment == route.actor_deployment()
            && work.program == route.actor_program()
    }
}

impl CanonicalWire for AgentInvocationRequest {
    const MAGIC: [u8; 4] = REQUEST_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4 + 32 + 4 + MAX_RUNTIME_WORK_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.execution.is_valid()
            && self.work.validate()
            && self.authorization.matches_work(&self.work)
            // Attested execution never accepts Invoke's exact-result-only
            // recovery flag. Proof recovery resumes the retained proof
            // workflow through its dedicated Resume path instead.
            && (!matches!(self.execution, RuntimeExecutionContext::Attested { .. })
                || !self.work.recovery_only)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        let nested = self
            .nested_work()
            .encode()
            .expect("validated supervisor invocation has canonical nested work");
        encoder.bytes(&nested);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let nested = decoder.bytes_bounded(MAX_RUNTIME_WORK_WIRE_BYTES)?;
        let nested = RuntimeWork::decode(&nested).map_err(|_| DecodeError::NonCanonical)?;
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = nested
        else {
            return Err(DecodeError::NonCanonical);
        };
        if !state.is_empty() || observed_slot != canonical_transport_slot(&authorization) {
            return Err(DecodeError::NonCanonical);
        }
        let value = Self {
            execution: context,
            work: *invocation,
            authorization: *authorization,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn canonical_transport_slot(authorization: &InvocationAuthorization) -> u64 {
    match authorization {
        InvocationAuthorization::AuthorityReceipt(_) => 0,
        InvocationAuthorization::PublicPreflight(preflight) => preflight.observed_slot,
    }
}

fn encode_transition_proof_key(encoder: &mut Encoder<'_>, key: &TransitionProofKey) {
    encoder.fixed(key.invocation.as_bytes());
    encoder.fixed(key.execution.as_bytes());
}

fn decode_transition_proof_key(
    decoder: &mut Decoder<'_>,
) -> Result<TransitionProofKey, DecodeError> {
    let key = TransitionProofKey {
        invocation: super::sdk::InvocationId(decoder.fixed()?),
        execution: Hash(decoder.fixed()?),
    };
    key.validate()
        .then_some(key)
        .ok_or(DecodeError::NonCanonical)
}

fn live_proof_key_matches_execution(
    execution: RuntimeExecutionContext,
    expected_live: Option<TransitionProofKey>,
    invocation: super::sdk::InvocationId,
) -> bool {
    match (execution, expected_live) {
        (RuntimeExecutionContext::Direct, None) => true,
        (RuntimeExecutionContext::Attested { .. }, Some(key)) => {
            key.validate() && key.invocation == invocation
        }
        _ => false,
    }
}

/// Canonical request to advance one exact yielded invocation. The caller
/// supplies the yielded record it received only as a concurrency selector;
/// the physical host reconstructs ResumeWork from its durable FIFO record and
/// the original exact work/authorization pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentResumeRequest {
    invocation: AgentInvocationRequest,
    expected_live: Option<TransitionProofKey>,
    yielded: super::sdk::YieldedInvocation,
}

impl AgentResumeRequest {
    pub fn new(
        execution: RuntimeExecutionContext,
        expected_live: Option<TransitionProofKey>,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        yielded: super::sdk::YieldedInvocation,
    ) -> Result<Self, WireError> {
        let value = Self {
            invocation: AgentInvocationRequest::new(execution, work, authorization)?,
            expected_live,
            yielded,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub const fn execution(&self) -> RuntimeExecutionContext {
        self.invocation.execution()
    }

    /// Exact live transition proof conditionally consumed by an Attested
    /// Resume. Direct execution has no proof record and must carry `None`.
    pub const fn expected_live(&self) -> Option<TransitionProofKey> {
        self.expected_live
    }

    pub const fn work(&self) -> &InvocationWork {
        self.invocation.work()
    }

    pub const fn authorization(&self) -> &InvocationAuthorization {
        self.invocation.authorization()
    }

    pub const fn yielded(&self) -> &super::sdk::YieldedInvocation {
        &self.yielded
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/supervisor-resume-request/v3",
            &[&self
                .encode()
                .expect("validated supervisor resume is canonical")],
        )
    }

    fn matches_route(&self, route: AgentRouteSnapshot) -> bool {
        self.invocation.matches_route(route)
    }
}

impl CanonicalWire for AgentResumeRequest {
    const MAGIC: [u8; 4] = RESUME_REQUEST_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4
        + 32
        + 4
        + AgentInvocationRequest::MAX_ENCODED_BYTES
        + 1
        + TRANSITION_PROOF_KEY_WIRE_BYTES
        + 4
        + MAX_YIELDED_SELECTOR_BYTES;

    fn validate_wire(&self) -> bool {
        let work = self.work();
        self.invocation.validate_wire()
            && live_proof_key_matches_execution(
                self.execution(),
                self.expected_live,
                work.invocation,
            )
            && self.yielded.validate()
            && self.yielded.invocation == work.invocation
            && self.yielded.actor == work.actor
            && self.yielded.incarnation == work.incarnation
            && self.yielded.deployment == work.deployment
            && self.yielded.program == work.program
            && self.yielded.mode == work.mode
            && self.yielded.installation_data == work.installation_data
            && self.yielded.required
                == work
                    .availability
                    .iter()
                    .map(|blob| blob.reference.clone())
                    .collect::<Vec<_>>()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(
            &self
                .invocation
                .encode()
                .expect("validated resume carries canonical exact work"),
        );
        encoder.option(&self.expected_live, encode_transition_proof_key);
        let yielded = RuntimeTransition {
            state: RuntimeState::default(),
            outcome: RuntimeOutcome::Yielded(self.yielded.clone()),
        }
        .encode()
        .expect("validated resume carries canonical yielded selector");
        encoder.bytes(&yielded);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let invocation = decoder.bytes_bounded(AgentInvocationRequest::MAX_ENCODED_BYTES)?;
        let invocation =
            AgentInvocationRequest::decode(&invocation).map_err(|_| DecodeError::NonCanonical)?;
        let expected_live = decoder.option(decode_transition_proof_key)?;
        let yielded = decoder.bytes_bounded(MAX_YIELDED_SELECTOR_BYTES)?;
        let transition =
            RuntimeTransition::decode(&yielded).map_err(|_| DecodeError::NonCanonical)?;
        if transition.encode().map_err(|_| DecodeError::NonCanonical)? != yielded
            || !transition.state.is_empty()
        {
            return Err(DecodeError::NonCanonical);
        }
        let RuntimeOutcome::Yielded(yielded) = transition.outcome else {
            return Err(DecodeError::NonCanonical);
        };
        let value = Self {
            invocation,
            expected_live,
            yielded,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

/// Canonical desired-state retirement of one exact delivered result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAcknowledgementRequest {
    invocation: AgentInvocationRequest,
    expected_live: Option<TransitionProofKey>,
}

impl AgentAcknowledgementRequest {
    pub fn new(
        execution: RuntimeExecutionContext,
        expected_live: Option<TransitionProofKey>,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<Self, WireError> {
        let value = Self {
            invocation: AgentInvocationRequest::new(execution, work, authorization)?,
            expected_live,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub const fn execution(&self) -> RuntimeExecutionContext {
        self.invocation.execution()
    }

    /// Exact delivered transition proof retired by an Attested
    /// acknowledgement. The acknowledgement is not itself a proved
    /// transition.
    pub const fn expected_live(&self) -> Option<TransitionProofKey> {
        self.expected_live
    }

    pub const fn work(&self) -> &InvocationWork {
        self.invocation.work()
    }

    pub const fn authorization(&self) -> &InvocationAuthorization {
        self.invocation.authorization()
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/agent/supervisor-acknowledgement-request/v3",
            &[&self
                .encode()
                .expect("validated supervisor acknowledgement is canonical")],
        )
    }

    fn matches_route(&self, route: AgentRouteSnapshot) -> bool {
        self.invocation.matches_route(route)
    }
}

impl CanonicalWire for AgentAcknowledgementRequest {
    const MAGIC: [u8; 4] = ACKNOWLEDGEMENT_REQUEST_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4
        + 32
        + 4
        + AgentInvocationRequest::MAX_ENCODED_BYTES
        + 1
        + TRANSITION_PROOF_KEY_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.invocation.validate_wire()
            && live_proof_key_matches_execution(
                self.execution(),
                self.expected_live,
                self.work().invocation,
            )
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.bytes(
            &self
                .invocation
                .encode()
                .expect("validated acknowledgement carries canonical exact work"),
        );
        encoder.option(&self.expected_live, encode_transition_proof_key);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let encoded = decoder.bytes_bounded(AgentInvocationRequest::MAX_ENCODED_BYTES)?;
        let invocation =
            AgentInvocationRequest::decode(&encoded).map_err(|_| DecodeError::NonCanonical)?;
        let expected_live = decoder.option(decode_transition_proof_key)?;
        let value = Self {
            invocation,
            expected_live,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

/// Public proof-manifest delivery. `Inline` must be one canonical APM1
/// manifest which hashes to the record's exact `BlobRef`; `Reference`
/// announces only that same bounded content identity for a separate CAS
/// fetch. There is intentionally no producer-witness variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentTransitionProofDelivery {
    Inline(Vec<u8>),
    Reference(BlobRef),
}

/// Canonical response from a clean Agent route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentInvocationResponse {
    Direct {
        request: super::sdk::Hash,
        outcome: RuntimeOutcome,
    },
    Attested {
        request: super::sdk::Hash,
        outcome: RuntimeOutcome,
        record: TransitionProofRecord,
        proof: AgentTransitionProofDelivery,
    },
}

impl AgentInvocationResponse {
    fn direct(request: &AgentInvocationRequest, outcome: RuntimeOutcome) -> Self {
        Self::Direct {
            request: request.commitment(),
            outcome,
        }
    }

    pub const fn request_commitment(&self) -> super::sdk::Hash {
        match self {
            Self::Direct { request, .. } | Self::Attested { request, .. } => *request,
        }
    }

    fn outcome(&self) -> &RuntimeOutcome {
        match self {
            Self::Direct { outcome, .. } | Self::Attested { outcome, .. } => outcome,
        }
    }

    fn nested_transition(&self) -> RuntimeTransition {
        RuntimeTransition {
            state: RuntimeState::default(),
            outcome: self.outcome().clone(),
        }
    }

    /// Verify exact transport binding, including identity-bearing outcomes.
    /// This is not an independent signature/finality proof for a Direct reply.
    pub fn matches_request(&self, request: &AgentInvocationRequest) -> bool {
        if self.request_commitment() != request.commitment()
            || !outcome_matches_work(self.outcome(), &request.work)
        {
            return false;
        }
        match (request.execution, self) {
            (RuntimeExecutionContext::Direct, Self::Direct { .. }) => true,
            // APR3 decoding authenticates only a bounded canonical shape. It
            // does not verify the producer signature, physical proof, exact
            // canonical work/transition, or independently resolved roots.
            // Generic AgentRoute output therefore cannot grant Attested
            // response admission. The production proof-host adapter must
            // return a sealed exact-verification capability before exposing
            // this outcome.
            (RuntimeExecutionContext::Attested { .. }, Self::Attested { .. }) => false,
            _ => false,
        }
    }
}

impl CanonicalWire for AgentInvocationResponse {
    const MAGIC: [u8; 4] = RESPONSE_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4
        + 32
        + 1
        + 32
        + 4
        + MAX_RUNTIME_TRANSITION_WIRE_BYTES
        + 4
        + TransitionProofRecord::MAX_ENCODED_BYTES
        + 1
        + 32
        + 8
        + 4
        + MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES;

    fn validate_wire(&self) -> bool {
        if self.request_commitment() == super::sdk::Hash::ZERO
            || !invocation_outcome(self.outcome())
            || !self.nested_transition().validate()
        {
            return false;
        }
        match self {
            Self::Direct { .. } => true,
            Self::Attested { record, proof, .. } => {
                proof_delivery_matches_record(record, proof)
                    && outcome_matches_subject(self.outcome(), record)
            }
        }
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        match self {
            Self::Direct { .. } => encoder.u8(0),
            Self::Attested { .. } => encoder.u8(1),
        }
        encoder.fixed(self.request_commitment().as_bytes());
        let transition = self
            .nested_transition()
            .encode()
            .expect("validated supervisor response has canonical outcome");
        encoder.bytes(&transition);
        if let Self::Attested { record, proof, .. } = self {
            let record = record
                .encode()
                .expect("validated supervisor response has canonical proof record");
            encoder.bytes(&record);
            match proof {
                AgentTransitionProofDelivery::Inline(bytes) => {
                    encoder.u8(0);
                    encoder.bytes(bytes);
                }
                AgentTransitionProofDelivery::Reference(reference) => {
                    encoder.u8(1);
                    encoder.fixed(reference.hash.as_bytes());
                    encoder.u64(reference.len);
                }
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let kind = decoder.u8()?;
        let request = super::sdk::Hash(decoder.fixed()?);
        let transition = decoder.bytes_bounded(MAX_RUNTIME_TRANSITION_WIRE_BYTES)?;
        let transition =
            RuntimeTransition::decode(&transition).map_err(|_| DecodeError::NonCanonical)?;
        if !transition.state.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let value = match kind {
            0 => Self::Direct {
                request,
                outcome: transition.outcome,
            },
            1 => {
                let record = decoder
                    .bytes_bounded(TransitionProofRecord::MAX_ENCODED_BYTES)
                    .and_then(|bytes| {
                        TransitionProofRecord::decode(&bytes).map_err(|_| DecodeError::NonCanonical)
                    })?;
                let proof = match decoder.u8()? {
                    0 => AgentTransitionProofDelivery::Inline(
                        decoder.bytes_bounded(MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES)?,
                    ),
                    1 => AgentTransitionProofDelivery::Reference(BlobRef {
                        hash: super::sdk::Hash(decoder.fixed()?),
                        len: decoder.u64()?,
                    }),
                    _ => return Err(DecodeError::InvalidTag),
                };
                Self::Attested {
                    request,
                    outcome: transition.outcome,
                    record,
                    proof,
                }
            }
            _ => return Err(DecodeError::InvalidTag),
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn proof_delivery_matches_record(
    record: &TransitionProofRecord,
    proof: &AgentTransitionProofDelivery,
) -> bool {
    record.validate_shape()
        && match proof {
            AgentTransitionProofDelivery::Inline(bytes) => {
                !bytes.is_empty()
                    && bytes.len() <= MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES
                    && record.proof.matches(bytes)
                    && TransitionProofMaterialManifest::decode(bytes).is_ok()
            }
            AgentTransitionProofDelivery::Reference(reference) => reference == &record.proof,
        }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentResumeResponse {
    Direct {
        request: Hash,
        outcome: RuntimeOutcome,
    },
    Attested {
        request: Hash,
        outcome: RuntimeOutcome,
        record: TransitionProofRecord,
        proof: AgentTransitionProofDelivery,
    },
}

impl AgentResumeResponse {
    fn direct(request: &AgentResumeRequest, outcome: RuntimeOutcome) -> Self {
        Self::Direct {
            request: request.commitment(),
            outcome,
        }
    }

    pub const fn request_commitment(&self) -> Hash {
        match self {
            Self::Direct { request, .. } | Self::Attested { request, .. } => *request,
        }
    }

    pub const fn outcome(&self) -> &RuntimeOutcome {
        match self {
            Self::Direct { outcome, .. } | Self::Attested { outcome, .. } => outcome,
        }
    }

    pub const fn proof_record(&self) -> Option<&TransitionProofRecord> {
        match self {
            Self::Direct { .. } => None,
            Self::Attested { record, .. } => Some(record),
        }
    }

    /// New exact proof key published by a successful Attested Resume. This
    /// is distinct from the prior `expected_live` key consumed by the
    /// request.
    pub fn transition_proof_key(&self) -> Option<TransitionProofKey> {
        match self {
            Self::Direct { .. } => None,
            Self::Attested { record, .. } => Some(record.statement.key()),
        }
    }

    fn nested_transition(&self) -> RuntimeTransition {
        RuntimeTransition {
            state: RuntimeState::default(),
            outcome: self.outcome().clone(),
        }
    }

    /// Check exact Direct response binding; this is not a finality proof.
    pub fn matches_request(&self, request: &AgentResumeRequest) -> bool {
        if self.request_commitment() != request.commitment()
            || !outcome_matches_work(self.outcome(), request.work())
            || !match self.outcome() {
                RuntimeOutcome::Yielded(yielded) => {
                    yielded.ready_sequence > request.yielded.ready_sequence
                }
                RuntimeOutcome::Completed(_) => true,
                RuntimeOutcome::Management(_) | RuntimeOutcome::Acknowledged(_) => false,
            }
        {
            return false;
        }
        match (request.execution(), self) {
            (RuntimeExecutionContext::Direct, Self::Direct { .. }) => true,
            // A different nonzero work hash for the same invocation is not
            // evidence that this is the exact successor of expected_live.
            // Only authoritative replay plus full proof verification can
            // grant that capability, so an untrusted AgentRoute response is
            // never admitted here.
            (RuntimeExecutionContext::Attested { .. }, Self::Attested { .. }) => false,
            _ => false,
        }
    }
}

impl CanonicalWire for AgentResumeResponse {
    const MAGIC: [u8; 4] = RESUME_RESPONSE_MAGIC;
    const MAX_ENCODED_BYTES: usize = AgentInvocationResponse::MAX_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        if self.request_commitment() == Hash::ZERO
            || !invocation_outcome(self.outcome())
            || !self.nested_transition().validate()
        {
            return false;
        }
        match self {
            Self::Direct { .. } => true,
            Self::Attested { record, proof, .. } => {
                proof_delivery_matches_record(record, proof)
                    && outcome_matches_subject(self.outcome(), record)
            }
        }
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        match self {
            Self::Direct { .. } => encoder.u8(0),
            Self::Attested { .. } => encoder.u8(1),
        }
        encoder.fixed(self.request_commitment().as_bytes());
        let transition = self
            .nested_transition()
            .encode()
            .expect("validated resume response has canonical outcome");
        encoder.bytes(&transition);
        if let Self::Attested { record, proof, .. } = self {
            let record = record
                .encode()
                .expect("validated resume response has canonical proof record");
            encoder.bytes(&record);
            match proof {
                AgentTransitionProofDelivery::Inline(bytes) => {
                    encoder.u8(0);
                    encoder.bytes(bytes);
                }
                AgentTransitionProofDelivery::Reference(reference) => {
                    encoder.u8(1);
                    encoder.fixed(reference.hash.as_bytes());
                    encoder.u64(reference.len);
                }
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let kind = decoder.u8()?;
        let request = Hash(decoder.fixed()?);
        let transition = decoder.bytes_bounded(MAX_RUNTIME_TRANSITION_WIRE_BYTES)?;
        let transition =
            RuntimeTransition::decode(&transition).map_err(|_| DecodeError::NonCanonical)?;
        if !transition.state.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let value = match kind {
            0 => Self::Direct {
                request,
                outcome: transition.outcome,
            },
            1 => {
                let record = decoder
                    .bytes_bounded(TransitionProofRecord::MAX_ENCODED_BYTES)
                    .and_then(|bytes| {
                        TransitionProofRecord::decode(&bytes).map_err(|_| DecodeError::NonCanonical)
                    })?;
                let proof = match decoder.u8()? {
                    0 => AgentTransitionProofDelivery::Inline(
                        decoder.bytes_bounded(MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES)?,
                    ),
                    1 => AgentTransitionProofDelivery::Reference(BlobRef {
                        hash: Hash(decoder.fixed()?),
                        len: decoder.u64()?,
                    }),
                    _ => return Err(DecodeError::InvalidTag),
                };
                Self::Attested {
                    request,
                    outcome: transition.outcome,
                    record,
                    proof,
                }
            }
            _ => return Err(DecodeError::InvalidTag),
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAcknowledgementResponse {
    request: Hash,
    outcome: RuntimeOutcome,
}

impl AgentAcknowledgementResponse {
    fn new(request: &AgentAcknowledgementRequest, outcome: RuntimeOutcome) -> Self {
        Self {
            request: request.commitment(),
            outcome,
        }
    }

    pub const fn request_commitment(&self) -> Hash {
        self.request
    }

    pub const fn outcome(&self) -> &RuntimeOutcome {
        &self.outcome
    }

    /// Check exact Direct retirement response binding, including result scope.
    pub fn matches_request(&self, request: &AgentAcknowledgementRequest) -> bool {
        if self.request != request.commitment()
            || !matches!(request.execution(), RuntimeExecutionContext::Direct)
        {
            // A request-bound acknowledgement is still only untrusted route
            // output. Attested retirement additionally requires the
            // authoritative journal to conditionally consume expected_live;
            // generic AgentRoute output cannot grant that capability.
            return false;
        }
        match &self.outcome {
            RuntimeOutcome::Acknowledged(Ok(acknowledged)) => {
                let work = request.work();
                acknowledged.invocation == work.invocation
                    && acknowledged.actor == work.actor
                    && acknowledged.incarnation == work.incarnation
                    && acknowledged.deployment == work.deployment
                    && acknowledged.mode == work.mode
                    && acknowledged.work == work.commitment()
                    && acknowledged.authorization == request.authorization().commitment()
            }
            RuntimeOutcome::Acknowledged(Err(_)) => true,
            _ => false,
        }
    }
}

impl CanonicalWire for AgentAcknowledgementResponse {
    const MAGIC: [u8; 4] = ACKNOWLEDGEMENT_RESPONSE_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4 + 32 + 32 + 4 + MAX_RUNTIME_TRANSITION_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.request != Hash::ZERO
            && matches!(self.outcome, RuntimeOutcome::Acknowledged(_))
            && RuntimeTransition {
                state: RuntimeState::default(),
                outcome: self.outcome.clone(),
            }
            .validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.request.as_bytes());
        encoder.bytes(
            &RuntimeTransition {
                state: RuntimeState::default(),
                outcome: self.outcome.clone(),
            }
            .encode()
            .expect("validated acknowledgement response has canonical outcome"),
        );
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request = Hash(decoder.fixed()?);
        let transition = decoder.bytes_bounded(MAX_RUNTIME_TRANSITION_WIRE_BYTES)?;
        let transition =
            RuntimeTransition::decode(&transition).map_err(|_| DecodeError::NonCanonical)?;
        if !transition.state.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let value = Self {
            request,
            outcome: transition.outcome,
        };
        value
            .validate_wire()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

fn invocation_outcome(outcome: &RuntimeOutcome) -> bool {
    matches!(
        outcome,
        RuntimeOutcome::Completed(_) | RuntimeOutcome::Yielded(_)
    )
}

fn outcome_matches_work(outcome: &RuntimeOutcome, work: &InvocationWork) -> bool {
    match outcome {
        RuntimeOutcome::Completed(Ok(reply)) => {
            reply.invocation == work.invocation
                && reply.actor == work.actor
                && reply.incarnation == work.incarnation
                && reply.deployment == work.deployment
                && reply.mode == work.mode
                && reply.gas_remaining <= work.gas
        }
        RuntimeOutcome::Completed(Err(_)) => true,
        RuntimeOutcome::Yielded(yielded) => {
            yielded.invocation == work.invocation
                && yielded.actor == work.actor
                && yielded.incarnation == work.incarnation
                && yielded.deployment == work.deployment
                && yielded.program == work.program
                && yielded.mode == work.mode
                && yielded.installation_data == work.installation_data
                && yielded.required
                    == work
                        .availability
                        .iter()
                        .map(|blob| blob.reference.clone())
                        .collect::<Vec<_>>()
        }
        RuntimeOutcome::Management(_) | RuntimeOutcome::Acknowledged(_) => false,
    }
}

fn outcome_matches_subject(outcome: &RuntimeOutcome, record: &TransitionProofRecord) -> bool {
    let subject = &record.statement.subject;
    match outcome {
        RuntimeOutcome::Completed(Ok(reply)) => {
            reply.invocation == subject.invocation
                && reply.actor == subject.actor
                && reply.incarnation == subject.incarnation
                && reply.deployment == subject.actor_deployment
                && reply.mode == subject.mode
        }
        RuntimeOutcome::Completed(Err(_)) => true,
        RuntimeOutcome::Yielded(yielded) => {
            yielded.invocation == subject.invocation
                && yielded.actor == subject.actor
                && yielded.incarnation == subject.incarnation
                && yielded.deployment == subject.actor_deployment
                && yielded.program == subject.actor_program
                && yielded.mode == subject.mode
        }
        RuntimeOutcome::Management(_) | RuntimeOutcome::Acknowledged(_) => false,
    }
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T, AgentRouteError>
where
    T: CanonicalWire + PartialEq,
{
    let value = T::decode(bytes).map_err(|_| AgentRouteError::Rejected)?;
    (value.encode().ok().as_deref() == Some(bytes))
        .then_some(value)
        .ok_or(AgentRouteError::Rejected)
}

/// Stable construction errors for an owned clean-host route worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentRouteAdapterError {
    InvalidQueueCapacity,
    NoReadyRoutes,
    Route(AgentRouteError),
    Worker(AgentRouteWorkerError),
}

impl fmt::Display for AgentRouteAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Agent route adapter failed: {self:?}")
    }
}

impl std::error::Error for AgentRouteAdapterError {}

trait CleanAgentRouteBackend: Send + 'static {
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError>;

    fn ready(&mut self) -> Result<(), AgentRouteError> {
        Ok(())
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError>;

    fn resume(
        &mut self,
        _identity: AgentRouteIdentity,
        _request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    fn acknowledge(
        &mut self,
        _identity: AgentRouteIdentity,
        _request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    fn prepare(
        &mut self,
        _identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn authorize_projection(
        &mut self,
        _head: AuthorityProjectionHead,
        _projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn authority_target(&mut self) -> Result<AuthorityActorTarget, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn authority_projection(
        &mut self,
        _query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn recover_authority_projection(&mut self) -> Result<bool, AgentRouteError> {
        Ok(false)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn peer_authority_projection(
        &mut self,
        _query: AuthorityProjectionQuery,
        _recovering: bool,
        _sender: NodeId,
    ) -> Result<(), AgentRouteError> {
        Err(AgentRouteError::Rejected)
    }

    fn retire(&mut self) -> Result<(), AgentRouteWorkerError> {
        Ok(())
    }
}

enum RouteHostCommand {
    Identities(SyncSender<Result<Vec<AgentRouteIdentity>, AgentRouteError>>),
    Ready(SyncSender<Result<(), AgentRouteError>>),
    Invoke {
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
        reply: SyncSender<Result<AgentInvocationResponse, AgentRouteError>>,
    },
    Resume {
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
        reply: SyncSender<Result<AgentResumeResponse, AgentRouteError>>,
    },
    Acknowledge {
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
        reply: SyncSender<Result<AgentAcknowledgementResponse, AgentRouteError>>,
    },
    Prepare {
        identity: AgentRouteIdentity,
        reply: SyncSender<
            Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError>,
        >,
    },
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    AuthorizeProjection {
        head: AuthorityProjectionHead,
        projection: Vec<AgentAuthorityRouteProjection>,
        reply: SyncSender<Result<Vec<AgentRouteIdentity>, AgentRouteError>>,
    },
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    AuthorityTarget(SyncSender<Result<AuthorityActorTarget, AgentRouteError>>),
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    AuthorityProjection {
        query: AuthorityProjectionQuery,
        reply: SyncSender<Result<Vec<u8>, AgentRouteError>>,
    },
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    RecoverAuthorityProjection(SyncSender<Result<bool, AgentRouteError>>),
    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    PeerAuthorityProjection(AuthorityProjectionQuery, bool, NodeId),
    Retire(SyncSender<Result<(), AgentRouteWorkerError>>),
}

/// One complete authority projection which a physical route worker must
/// authenticate before any route from that host may be published.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AgentAuthorityRouteProjection {
    replica_generation: Hash,
    descriptor: AgentDescriptor,
    actors: Vec<AuthorityActorProjection>,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl AgentAuthorityRouteProjection {
    pub(crate) fn new(
        replica_generation: Hash,
        descriptor: AgentDescriptor,
        actors: Vec<AuthorityActorProjection>,
    ) -> Result<Self, AgentRouteError> {
        if replica_generation == Hash::ZERO
            || replica_generation != descriptor.replica_generation()
            || descriptor.validate().is_err()
            || actors.len() > descriptor.capabilities.max_actors as usize
            || actors.iter().any(|actor| {
                actor.validate_shape().is_err()
                    || actor.agent != descriptor.identity.agent
                    || actor
                        .entry
                        .validate_for_profile(descriptor.identity.profile)
                        .is_err()
                    || !descriptor.runtime_contract.supports(actor.contract)
                    || !descriptor.capabilities.satisfies(actor.requirements)
            })
            || actors
                .windows(2)
                .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
        {
            return Err(AgentRouteError::Rejected);
        }
        Ok(Self {
            replica_generation,
            descriptor,
            actors,
        })
    }

    pub(crate) const fn replica_generation(&self) -> Hash {
        self.replica_generation
    }

    pub(crate) const fn descriptor(&self) -> &AgentDescriptor {
        &self.descriptor
    }

    pub(crate) fn actors(&self) -> &[AuthorityActorProjection] {
        &self.actors
    }
}

/// Independently decoded physical state used only to classify the one valid
/// audit mismatch: a successful management mutation committed before the
/// authority's final application acknowledgement. It never grants a route;
/// an exact match keeps the attachment dormant until a later projection.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) struct PhysicalAuthorityRouteProjection {
    pub(crate) descriptor: AgentDescriptor,
    pub(crate) actors: Vec<super::invocation_preparation::PhysicalInvocationMaterial>,
    pub(crate) disposition: Option<super::standard::StandardCleanManagementDisposition>,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn material_authority_projection(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
) -> Option<AuthorityActorProjection> {
    let actor = AuthorityActorProjection {
        agent: material.descriptor.identity.agent,
        entry: material.actor.entry.clone(),
        producer: material.producer,
        contract: material.contract,
        requirements: material.requirements,
        root_provenance: material.root_provenance,
        installation_id: material.actor.installation_id,
        registry_reservation: material.actor.registry_reservation,
        install_request: material.install_request,
    };
    (actor.validate_shape().is_ok()
        && physical_material_matches_authority(material, &material.descriptor, &actor))
    .then_some(actor)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn disposition_matches(
    head: AuthorityProjectionHead,
    disposition: &super::standard::StandardCleanManagementDisposition,
    request: &super::sdk::ManagementRequest,
    reply: &super::sdk::ManagementReply,
) -> bool {
    request.is_valid()
        && disposition.authority != Hash::ZERO
        && disposition.sequence != 0
        && disposition.sequence <= head.authorization_sequence.get()
        && disposition.epoch != 0
        && disposition.epoch <= head.epoch.get()
        && disposition.request == request.replay_commitment()
        && disposition.result.as_ref() == Ok(reply)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn descriptor_lag_request(
    old: &AgentAuthorityRouteProjection,
    current: &AgentDescriptor,
    disposition: &super::standard::StandardCleanManagementDisposition,
    head: AuthorityProjectionHead,
) -> bool {
    let mut expected = old.descriptor.clone();
    expected.replicas = current.replicas.clone();
    if expected == *current && old.descriptor.replicas != current.replicas {
        let request = super::sdk::ManagementRequest::ChangeReplicas {
            expected_generation: old.replica_generation,
            replicas: current.replicas.clone(),
        };
        let reply = super::sdk::ManagementReply::ReplicasChanged {
            generation: current.replica_generation(),
        };
        return disposition_matches(head, disposition, &request, &reply);
    }

    let mut expected = old.descriptor.clone();
    let identity = &current.identity;
    expected.identity.runtime_deployment = identity.runtime_deployment;
    expected.identity.runtime_program = identity.runtime_program;
    expected.identity.runtime_producer = identity.runtime_producer;
    expected.runtime_package = current.runtime_package.clone();
    expected.runtime_contract = current.runtime_contract;
    expected.capabilities = current.capabilities;
    if expected != *current
        || old.descriptor.identity.runtime_deployment == identity.runtime_deployment
    {
        return false;
    }
    let request =
        super::sdk::ManagementRequest::UpgradeRuntime(Box::new(super::sdk::RuntimeUpgrade {
            from_deployment: old.descriptor.identity.runtime_deployment,
            to_deployment: identity.runtime_deployment,
            to_program: identity.runtime_program,
            producer: identity.runtime_producer,
            package: current.runtime_package.clone(),
            contract: current.runtime_contract,
            capabilities: current.capabilities,
        }));
    disposition_matches(
        head,
        disposition,
        &request,
        &super::sdk::ManagementReply::RuntimeUpgraded(identity.clone()),
    )
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn install_lag_request(
    material: &super::invocation_preparation::PhysicalInvocationMaterial,
) -> super::sdk::ManagementRequest {
    super::sdk::ManagementRequest::Install(Box::new(super::sdk::InstallActor {
        installation_id: material.actor.installation_id,
        registry_reservation: material.actor.registry_reservation,
        entry: material.actor.entry.clone(),
        producer: material.producer,
        package: material.actor.entry.package.clone(),
        agent_schema: material.actor.entry.agent_schema.clone(),
        method_policy: material.actor.entry.method_policy.clone(),
        constructor_abi: material.actor.entry.constructor_abi,
        installation_data: material.installation_data.as_ref().map(|blob| {
            super::sdk::InstallationData {
                reference: blob.reference.clone(),
                bytes: blob.bytes.clone(),
            }
        }),
        state_layout: material.actor.entry.state_layout,
        contract: material.contract,
        requirements: material.requirements,
    }))
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn actor_lag_request(
    old: &AgentAuthorityRouteProjection,
    current_materials: &[super::invocation_preparation::PhysicalInvocationMaterial],
    current: &[AuthorityActorProjection],
    disposition: &super::standard::StandardCleanManagementDisposition,
    head: AuthorityProjectionHead,
) -> bool {
    let mut old_index = 0usize;
    let mut current_index = 0usize;
    let mut difference = None;
    while old_index < old.actors.len() || current_index < current.len() {
        match (old.actors.get(old_index), current.get(current_index)) {
            (Some(left), Some(right)) if left.entry.actor == right.entry.actor => {
                if left != right && difference.replace((Some(left), Some(right))).is_some() {
                    return false;
                }
                old_index += 1;
                current_index += 1;
            }
            (Some(left), Some(right)) if left.entry.actor < right.entry.actor => {
                if difference.replace((Some(left), None)).is_some() {
                    return false;
                }
                old_index += 1;
            }
            (Some(_), Some(right)) => {
                if difference.replace((None, Some(right))).is_some() {
                    return false;
                }
                current_index += 1;
            }
            (Some(left), None) => {
                if difference.replace((Some(left), None)).is_some() {
                    return false;
                }
                old_index += 1;
            }
            (None, Some(right)) => {
                if difference.replace((None, Some(right))).is_some() {
                    return false;
                }
                current_index += 1;
            }
            (None, None) => break,
        }
    }
    let Some((before, after)) = difference else {
        return false;
    };
    match (before, after) {
        (None, Some(after)) => {
            let Some((_, material)) = current
                .iter()
                .zip(current_materials)
                .find(|(actor, _)| actor.entry.actor == after.entry.actor)
            else {
                return false;
            };
            let request = install_lag_request(material);
            after.root_provenance == false
                && after.install_request
                    == match &request {
                        super::sdk::ManagementRequest::Install(install) => {
                            install.lineage_commitment()
                        }
                        _ => unreachable!(),
                    }
                && disposition_matches(
                    head,
                    disposition,
                    &request,
                    &super::sdk::ManagementReply::Installed(after.entry.clone()),
                )
        }
        (Some(before), None) => {
            let request = super::sdk::ManagementRequest::RemoveLeaf {
                actor: before.entry.actor,
                expected_deployment: before.entry.deployment,
            };
            disposition_matches(
                head,
                disposition,
                &request,
                &super::sdk::ManagementReply::Removed(before.entry.actor),
            )
        }
        (Some(before), Some(after)) => {
            let mut toggled = before.clone();
            toggled.entry.suspended = after.entry.suspended;
            if toggled == *after && before.entry.suspended != after.entry.suspended {
                let request = if after.entry.suspended {
                    super::sdk::ManagementRequest::Suspend {
                        actor: before.entry.actor,
                        expected_deployment: before.entry.deployment,
                    }
                } else {
                    super::sdk::ManagementRequest::Resume {
                        actor: before.entry.actor,
                        expected_deployment: before.entry.deployment,
                    }
                };
                let reply = if after.entry.suspended {
                    super::sdk::ManagementReply::Suspended(after.entry.clone())
                } else {
                    super::sdk::ManagementReply::Resumed(after.entry.clone())
                };
                return disposition_matches(head, disposition, &request, &reply);
            }

            let mut upgraded = before.clone();
            upgraded.entry.deployment = after.entry.deployment;
            upgraded.entry.program = after.entry.program;
            upgraded.entry.package = after.entry.package.clone();
            upgraded.entry.agent_schema = after.entry.agent_schema.clone();
            upgraded.entry.method_policy = after.entry.method_policy.clone();
            upgraded.entry.constructor_abi = after.entry.constructor_abi;
            upgraded.entry.state_layout = after.entry.state_layout;
            upgraded.entry.lanes = after.entry.lanes;
            upgraded.producer = after.producer;
            upgraded.contract = after.contract;
            upgraded.requirements = after.requirements;
            if upgraded != *after || before.entry.deployment == after.entry.deployment {
                return false;
            }
            let request =
                super::sdk::ManagementRequest::UpgradeActor(Box::new(super::sdk::UpgradeActor {
                    actor: before.entry.actor,
                    from_deployment: before.entry.deployment,
                    to_deployment: after.entry.deployment,
                    to_program: after.entry.program,
                    producer: after.producer,
                    package: after.entry.package.clone(),
                    agent_schema: after.entry.agent_schema.clone(),
                    method_policy: after.entry.method_policy.clone(),
                    constructor_abi: after.entry.constructor_abi,
                    state_layout: after.entry.state_layout,
                    contract: after.contract,
                    requirements: after.requirements,
                }));
            disposition_matches(
                head,
                disposition,
                &request,
                &super::sdk::ManagementReply::Upgraded(after.entry.clone()),
            )
        }
        (None, None) => false,
    }
}

/// Classify only the exact one-mutation physical-ahead window. Corrupt,
/// malformed, multi-step, and unrelated mismatches return false and retain
/// their ordinary fail-closed audit error.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn physical_projection_is_exactly_one_ack_ahead(
    head: AuthorityProjectionHead,
    projected: &[AgentAuthorityRouteProjection],
    physical: &[PhysicalAuthorityRouteProjection],
) -> bool {
    if !head.is_valid()
        || projected
            .windows(2)
            .any(|pair| pair[0].descriptor.identity.agent >= pair[1].descriptor.identity.agent)
        || physical
            .windows(2)
            .any(|pair| pair[0].descriptor.identity.agent >= pair[1].descriptor.identity.agent)
    {
        return false;
    }
    let mut lagged = 0usize;
    for current in physical {
        if current.descriptor.validate().is_err()
            || current
                .actors
                .windows(2)
                .any(|pair| pair[0].actor.entry.actor >= pair[1].actor.entry.actor)
            || current
                .actors
                .iter()
                .any(|material| material.descriptor != current.descriptor)
        {
            return false;
        }
        let Some(current_actors) = current
            .actors
            .iter()
            .map(material_authority_projection)
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let old = projected
            .binary_search_by_key(&current.descriptor.identity.agent, |projection| {
                projection.descriptor.identity.agent
            })
            .ok()
            .and_then(|index| projected.get(index));
        if old
            .is_some_and(|old| old.descriptor == current.descriptor && old.actors == current_actors)
        {
            continue;
        }
        let Some(disposition) = current.disposition.as_ref() else {
            return false;
        };
        let exact = if let Some(old) = old {
            if old.descriptor.identity.agent != current.descriptor.identity.agent {
                false
            } else if old.descriptor != current.descriptor {
                old.actors == current_actors
                    && descriptor_lag_request(old, &current.descriptor, disposition, head)
            } else {
                actor_lag_request(old, &current.actors, &current_actors, disposition, head)
            }
        } else {
            current.actors.is_empty()
                && disposition_matches(
                    head,
                    disposition,
                    &super::sdk::ManagementRequest::Create(Box::new(current.descriptor.clone())),
                    &super::sdk::ManagementReply::Created(current.descriptor.identity.clone()),
                )
        };
        if !exact || lagged != 0 {
            return false;
        }
        lagged = 1;
    }
    lagged == 1
        && projected.iter().all(|authority| {
            physical.iter().any(|current| {
                current.descriptor.identity.agent == authority.descriptor.identity.agent
            })
        })
}

/// Cloneable control handle for a concrete host worker. It exposes only
/// projection/readiness, which a lifecycle owner uses to request an atomic
/// supervisor refresh after a durable runtime or actor upgrade.
#[derive(Clone)]
pub struct AgentRouteHostHandle {
    transport: RouteHostTransport,
    state: Arc<AtomicU8>,
}

#[derive(Clone)]
enum RouteHostTransport {
    Worker(SyncSender<RouteHostCommand>),
    // Per-Agent ownership executed on the supervisor's bounded pool. Idle
    // Agents allocate no threads; lifecycle/control calls share the same lock.
    Inline(Arc<std::sync::Mutex<Option<Box<dyn CleanAgentRouteBackend>>>>),
}

impl AgentRouteHostHandle {
    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Acquire) == ROUTE_WORKER_RUNNING
    }

    pub fn identities(&self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Identities(reply))?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    fn ready(&self) -> Result<(), AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Ready(reply))?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    fn invoke(
        &self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Invoke {
            identity,
            request,
            reply,
        })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    fn resume(
        &self,
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Resume {
            identity,
            request,
            reply,
        })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    fn acknowledge(
        &self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Acknowledge {
            identity,
            request,
            reply,
        })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    fn prepare(
        &self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::Prepare { identity, reply })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn authorize_projection(
        &self,
        head: AuthorityProjectionHead,
        projection: Vec<AgentAuthorityRouteProjection>,
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::AuthorizeProjection {
            head,
            projection,
            reply,
        })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn authority_target(&self) -> Result<AuthorityActorTarget, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::AuthorityTarget(reply))?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn authority_projection(
        &self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::AuthorityProjection { query, reply })?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn authority_projection_bounded(
        &self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::AuthorityProjection { query, reply })?;
        result
            .recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    pub(crate) fn recover_authority_projection(&self) -> Result<bool, AgentRouteError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.send(RouteHostCommand::RecoverAuthorityProjection(reply))?;
        result.recv().unwrap_or(Err(AgentRouteError::Unavailable))
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn enqueue_peer_projection(
        &self,
        query: AuthorityProjectionQuery,
        recovering: bool,
        sender: NodeId,
    ) -> Result<(), AgentRouteError> {
        self.send(RouteHostCommand::PeerAuthorityProjection(
            query, recovering, sender,
        ))
    }

    fn send(&self, command: RouteHostCommand) -> Result<(), AgentRouteError> {
        if !self.is_running() {
            return Err(AgentRouteError::Unavailable);
        }
        match &self.transport {
            RouteHostTransport::Worker(commands) => {
                commands.try_send(command).map_err(|error| match error {
                    TrySendError::Full(_) => AgentRouteError::NotReady,
                    TrySendError::Disconnected(_) => AgentRouteError::Unavailable,
                })
            }
            RouteHostTransport::Inline(backend) => {
                let mut backend = backend.lock().map_err(|_| AgentRouteError::Unavailable)?;
                // Retirement may have started while this caller waited.
                if !self.is_running() {
                    return Err(AgentRouteError::Unavailable);
                }
                let backend = backend.as_mut().ok_or(AgentRouteError::Unavailable)?;
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    execute_route_host_command(backend.as_mut(), command)
                }));
                if !matches!(result, Ok(None)) {
                    self.state.store(ROUTE_WORKER_FAILED, Ordering::Release);
                    return Err(AgentRouteError::Unavailable);
                }
                Ok(())
            }
        }
    }

    pub(crate) fn request_retire(&self) -> Result<(), AgentRouteWorkerError> {
        if let RouteHostTransport::Inline(backend) = &self.transport {
            // Close admission before waiting for the operation lock. Every
            // retirement caller drains that lock, including callers observing
            // CLOSING or FAILED; neither state proves resources were released.
            let _ = self.state.compare_exchange(
                ROUTE_WORKER_RUNNING,
                ROUTE_WORKER_CLOSING,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            let (mut slot, poisoned) = match backend.lock() {
                Ok(slot) => (slot, false),
                Err(error) => (error.into_inner(), true),
            };
            let failed = poisoned || self.state.load(Ordering::Acquire) == ROUTE_WORKER_FAILED;
            let Some(mut owned) = slot.take() else {
                return if !failed && self.state.load(Ordering::Acquire) == ROUTE_WORKER_CLOSED {
                    Ok(())
                } else {
                    Err(AgentRouteWorkerError::Failed)
                };
            };
            let retired = panic::catch_unwind(AssertUnwindSafe(|| owned.retire()))
                .unwrap_or(Err(AgentRouteWorkerError::Panicked));
            // Drop even after an error/panic, while still holding the drain
            // lock. Closed clones retain only the empty slot and status.
            let dropped = panic::catch_unwind(AssertUnwindSafe(|| drop(owned)))
                .map_err(|_| AgentRouteWorkerError::Panicked);
            let result = retired.and(dropped).and(if failed {
                Err(AgentRouteWorkerError::Failed)
            } else {
                Ok(())
            });
            self.state.store(
                if result.is_ok() {
                    ROUTE_WORKER_CLOSED
                } else {
                    ROUTE_WORKER_FAILED
                },
                Ordering::Release,
            );
            return result;
        }
        let state = self.state.compare_exchange(
            ROUTE_WORKER_RUNNING,
            ROUTE_WORKER_CLOSING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        match state {
            Ok(_) => {}
            Err(ROUTE_WORKER_CLOSING | ROUTE_WORKER_CLOSED) => return Ok(()),
            Err(_) => return Err(AgentRouteWorkerError::Failed),
        }
        let (reply, result) = mpsc::sync_channel(1);
        match &self.transport {
            RouteHostTransport::Worker(commands) => commands
                .send(RouteHostCommand::Retire(reply))
                .map_err(|_| AgentRouteWorkerError::Failed)?,
            RouteHostTransport::Inline(_) => unreachable!("inline retirement drained above"),
        }
        result.recv().unwrap_or(Err(AgentRouteWorkerError::Failed))
    }
}

struct CleanHostRouteAdapter {
    host: AgentRouteHostHandle,
}

impl AgentRoute for CleanHostRouteAdapter {
    fn reconcile(
        &mut self,
        proposed: &[AgentRouteSnapshot],
    ) -> Result<Vec<AgentRouteSnapshot>, AgentRouteError> {
        self.host.ready()?;
        if proposed.is_empty() {
            return Ok(Vec::new());
        }
        let identities = self.host.identities()?;
        if identities.len() != proposed.len()
            || identities
                .iter()
                .zip(proposed)
                .any(|(identity, snapshot)| *identity != snapshot.identity())
        {
            return Err(AgentRouteError::NotReady);
        }
        Ok(proposed.to_vec())
    }

    fn dispatch(
        &mut self,
        route: &AgentRouteSnapshot,
        payload: &[u8],
    ) -> Result<Vec<u8>, AgentRouteError> {
        if payload.starts_with(&PREPARATION_REQUEST_MAGIC) {
            let request = canonical_decode::<AgentPreparationRequest>(payload)?;
            if !request.matches_route(*route) {
                return Err(AgentRouteError::Rejected);
            }
            let material = self.host.prepare(route.identity())?;
            let prepared = prepare_from_physical_material(&request, material)?;
            return (AgentPreparationResponse { prepared })
                .encode()
                .map_err(|_| AgentRouteError::Unavailable);
        }
        if payload.starts_with(&RESUME_REQUEST_MAGIC) {
            let request = canonical_decode::<AgentResumeRequest>(payload)?;
            if !request.matches_route(*route) {
                return Err(AgentRouteError::Rejected);
            }
            let response = self.host.resume(route.identity(), request.clone())?;
            if !response.matches_request(&request) {
                return Err(AgentRouteError::Unavailable);
            }
            return response.encode().map_err(|_| AgentRouteError::Unavailable);
        }
        if payload.starts_with(&ACKNOWLEDGEMENT_REQUEST_MAGIC) {
            let request = canonical_decode::<AgentAcknowledgementRequest>(payload)?;
            if !request.matches_route(*route) {
                return Err(AgentRouteError::Rejected);
            }
            let response = self.host.acknowledge(route.identity(), request.clone())?;
            if !response.matches_request(&request) {
                return Err(AgentRouteError::Unavailable);
            }
            return response.encode().map_err(|_| AgentRouteError::Unavailable);
        }
        let request = canonical_decode::<AgentInvocationRequest>(payload)?;
        if !request.matches_route(*route) {
            return Err(AgentRouteError::Rejected);
        }
        let response = self.host.invoke(route.identity(), request.clone())?;
        if !response.matches_request(&request) {
            return Err(AgentRouteError::Unavailable);
        }
        response.encode().map_err(|_| AgentRouteError::Unavailable)
    }
}

struct CleanHostWorkerOwner {
    handle: AgentRouteHostHandle,
    thread: Option<JoinHandle<()>>,
}

impl AgentRouteWorkerOwner for CleanHostWorkerOwner {
    fn request_retire(&mut self) -> Result<(), AgentRouteWorkerError> {
        self.handle.request_retire()
    }

    fn join(mut self: Box<Self>) -> Result<(), AgentRouteWorkerError> {
        let thread = self.thread.take().ok_or(AgentRouteWorkerError::Failed)?;
        if thread.join().is_err() {
            self.handle
                .state
                .store(ROUTE_WORKER_FAILED, Ordering::Release);
            return Err(AgentRouteWorkerError::Panicked);
        }
        match self.handle.state.load(Ordering::Acquire) {
            ROUTE_WORKER_CLOSED => Ok(()),
            _ => Err(AgentRouteWorkerError::Failed),
        }
    }
}

/// One ready-to-attach concrete host worker plus its projection handle.
pub struct AgentRouteHostAttachment {
    attachment: AgentRouteAttachment,
    handle: AgentRouteHostHandle,
}

impl AgentRouteHostAttachment {
    pub fn handle(&self) -> AgentRouteHostHandle {
        self.handle.clone()
    }

    pub fn into_parts(self) -> (AgentRouteAttachment, AgentRouteHostHandle) {
        (self.attachment, self.handle)
    }

    pub(crate) fn into_parts_with_identities(
        mut self,
        identities: Vec<AgentRouteIdentity>,
    ) -> (AgentRouteAttachment, AgentRouteHostHandle) {
        self.attachment.replace_identities(identities);
        (self.attachment, self.handle)
    }

    pub(crate) fn retire(self) -> Result<(), AgentSupervisorError> {
        super::supervisor::retire_unpublished(self.attachment)
    }
}

struct InlineHostOwner(AgentRouteHostHandle);

impl AgentRouteWorkerOwner for InlineHostOwner {
    fn request_retire(&mut self) -> Result<(), AgentRouteWorkerError> {
        self.0.request_retire()
    }

    fn join(self: Box<Self>) -> Result<(), AgentRouteWorkerError> {
        // The supervisor drains dispatch ownership before retirement. The
        // mutex also drains an already-admitted direct control operation.
        self.0.request_retire()
    }
}

fn inline_backend<B: CleanAgentRouteBackend>(
    mut backend: B,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    let identities = backend
        .identities()
        .map_err(AgentRouteAdapterError::Route)?;
    let handle = AgentRouteHostHandle {
        transport: RouteHostTransport::Inline(Arc::new(std::sync::Mutex::new(Some(Box::new(
            backend,
        ))))),
        state: Arc::new(AtomicU8::new(ROUTE_WORKER_RUNNING)),
    };
    Ok(AgentRouteHostAttachment {
        attachment: AgentRouteAttachment::new(
            identities,
            CleanHostRouteAdapter {
                host: handle.clone(),
            },
            InlineHostOwner(handle.clone()),
        ),
        handle,
    })
}

fn spawn_backend<B: CleanAgentRouteBackend>(
    backend: B,
    queue_capacity: usize,
    name: &'static str,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    if queue_capacity == 0 {
        return Err(AgentRouteAdapterError::InvalidQueueCapacity);
    }
    let (commands, receiver) = mpsc::sync_channel(queue_capacity);
    let state = Arc::new(AtomicU8::new(ROUTE_WORKER_RUNNING));
    let worker_state = state.clone();
    let (ready, started) = mpsc::sync_channel(0);
    let thread = thread::Builder::new()
        .name(name.into())
        .spawn(move || route_host_thread(backend, receiver, worker_state, ready))
        .map_err(|_| AgentRouteAdapterError::Worker(AgentRouteWorkerError::Failed))?;
    if started.recv().is_err() {
        let _ = thread.join();
        return Err(AgentRouteAdapterError::Worker(
            AgentRouteWorkerError::Failed,
        ));
    }
    let handle = AgentRouteHostHandle {
        transport: RouteHostTransport::Worker(commands),
        state,
    };
    let mut owner = CleanHostWorkerOwner {
        handle: handle.clone(),
        thread: Some(thread),
    };
    let identities = match handle.identities() {
        Ok(identities) => identities,
        Err(error) => {
            let _ = owner.request_retire();
            let _ = Box::new(owner).join();
            return Err(AgentRouteAdapterError::Route(error));
        }
    };
    Ok(AgentRouteHostAttachment {
        attachment: AgentRouteAttachment::new(
            identities,
            CleanHostRouteAdapter {
                host: handle.clone(),
            },
            owner,
        ),
        handle,
    })
}

fn execute_route_host_command(
    backend: &mut dyn CleanAgentRouteBackend,
    command: RouteHostCommand,
) -> Option<bool> {
    match command {
        RouteHostCommand::Identities(reply) => {
            let _ = reply.send(backend.identities());
        }
        RouteHostCommand::Ready(reply) => {
            let _ = reply.send(backend.ready());
        }
        RouteHostCommand::Invoke {
            identity,
            request,
            reply,
        } => {
            let _ = reply.send(backend.invoke(identity, request));
        }
        RouteHostCommand::Resume {
            identity,
            request,
            reply,
        } => {
            let _ = reply.send(backend.resume(identity, request));
        }
        RouteHostCommand::Acknowledge {
            identity,
            request,
            reply,
        } => {
            let _ = reply.send(backend.acknowledge(identity, request));
        }
        RouteHostCommand::Prepare { identity, reply } => {
            let _ = reply.send(backend.prepare(identity));
        }
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        RouteHostCommand::AuthorizeProjection {
            head,
            projection,
            reply,
        } => {
            let _ = reply.send(backend.authorize_projection(head, &projection));
        }
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        RouteHostCommand::AuthorityTarget(reply) => {
            let _ = reply.send(backend.authority_target());
        }
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        RouteHostCommand::AuthorityProjection { query, reply } => {
            let _ = reply.send(backend.authority_projection(query));
        }
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        RouteHostCommand::RecoverAuthorityProjection(reply) => {
            let _ = reply.send(backend.recover_authority_projection());
        }
        #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
        RouteHostCommand::PeerAuthorityProjection(query, recovering, sender) => {
            let _ = backend.peer_authority_projection(query, recovering, sender);
        }
        RouteHostCommand::Retire(reply) => {
            let retired = backend.retire();
            let success = retired.is_ok();
            let _ = reply.send(retired);
            return Some(success);
        }
    }
    None
}

fn route_host_thread<B: CleanAgentRouteBackend>(
    mut backend: B,
    receiver: Receiver<RouteHostCommand>,
    state: Arc<AtomicU8>,
    ready: SyncSender<()>,
) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = ready.send(());
        while let Ok(command) = receiver.recv() {
            if let Some(success) = execute_route_host_command(&mut backend, command) {
                return success;
            }
        }
        false
    }));
    state.store(
        if matches!(result, Ok(true)) {
            ROUTE_WORKER_CLOSED
        } else {
            ROUTE_WORKER_FAILED
        },
        Ordering::Release,
    );
}

pub(crate) fn route_identities(
    descriptor: &AgentDescriptor,
    records: Vec<ActorDirectoryRecord>,
    expected_profile: AgentProfile,
) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
    if descriptor.validate().is_err() || descriptor.identity.profile != expected_profile {
        return Err(AgentRouteError::Unavailable);
    }
    if records.len() > descriptor.capabilities.max_actors as usize
        || records.windows(2).any(|pair| {
            pair[0].entry.actor >= pair[1].entry.actor
                || pair[0].validate().is_err()
                || pair[1].validate().is_err()
        })
        || records
            .first()
            .is_some_and(|record| record.validate().is_err())
    {
        return Err(AgentRouteError::Unavailable);
    }
    let mut identities = Vec::new();
    for record in records {
        if record.entry.suspended {
            continue;
        }
        let key = AgentRouteKey::new(
            descriptor.identity.space,
            descriptor.identity.agent,
            record.entry.actor,
        )
        .map_err(|_| AgentRouteError::Unavailable)?;
        identities.push(
            AgentRouteIdentity::new(
                key,
                record.incarnation,
                descriptor.identity.runtime_deployment,
                record.entry.deployment,
                record.entry.program,
                descriptor.identity.profile,
            )
            .map_err(|_| AgentRouteError::Unavailable)?,
        );
    }
    Ok(identities)
}

pub(crate) fn collect_actor_directory(
    maximum: usize,
    mut inspect: impl FnMut(Option<ActorId>, u16) -> Result<ActorDirectoryPage, AgentRouteError>,
) -> Result<Vec<ActorDirectoryRecord>, AgentRouteError> {
    let limit =
        u16::try_from(MAX_DIRECTORY_PAGE_ENTRIES).map_err(|_| AgentRouteError::Unavailable)?;
    let pages = maximum
        .div_ceil(MAX_DIRECTORY_PAGE_ENTRIES)
        .saturating_add(1);
    let mut records = Vec::new();
    let mut after = None;
    for _ in 0..pages {
        let page = inspect(after, limit)?;
        if page.validate().is_err()
            || page
                .entries
                .first()
                .is_some_and(|record| after.is_some_and(|after| record.entry.actor <= after))
            || records
                .len()
                .checked_add(page.entries.len())
                .is_none_or(|count| count > maximum)
            || (page.next.is_some() && page.entries.len() != usize::from(limit))
        {
            return Err(AgentRouteError::Unavailable);
        }
        records.extend(page.entries);
        let Some(next) = page.next else {
            return Ok(records);
        };
        if after == Some(next) {
            return Err(AgentRouteError::Unavailable);
        }
        after = Some(next);
    }
    Err(AgentRouteError::Unavailable)
}

struct LocalAgentRouteBackend {
    host: Arc<std::sync::Mutex<super::local_sdk_host::LocalAgentHost>>,
    selected: Option<AgentId>,
}

impl CleanAgentRouteBackend for LocalAgentRouteBackend {
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        if let Some(agent) = self.selected {
            return super::local_sdk_host::LocalAgentHost::checkout(&self.host, agent)
                .and_then(|execution| execution.route_identities())
                .map_err(map_local_host_error);
        }
        let mut identities = Vec::new();
        let mut host = self.host.lock().map_err(|_| AgentRouteError::Unavailable)?;
        let agents = host.list().map_err(map_local_host_error)?;
        for agent in agents {
            if self.selected.is_some_and(|selected| selected != agent) {
                continue;
            }
            let descriptor = host.show(agent).map_err(map_local_host_error)?.clone();
            let maximum = descriptor.capabilities.max_actors as usize;
            let records = collect_actor_directory(maximum, |after, limit| {
                match host
                    .manage(
                        agent,
                        super::sdk::ManagementRequest::InspectActors { after, limit },
                        None,
                        super::driver::SdkManagementArtifacts::None,
                    )
                    .map_err(map_local_host_error)?
                {
                    RuntimeOutcome::Management(Ok(super::sdk::ManagementReply::Actors(page))) => {
                        Ok(page)
                    }
                    _ => Err(AgentRouteError::Unavailable),
                }
            })?;
            identities.extend(route_identities(&descriptor, records, AgentProfile::Local)?);
        }
        Ok(identities)
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        if !request.execution.is_direct()
            || self
                .selected
                .is_some_and(|agent| agent != identity.key().agent())
        {
            return Err(AgentRouteError::Rejected);
        }
        let mut host =
            super::local_sdk_host::LocalAgentHost::checkout(&self.host, identity.key().agent())
                .map_err(map_local_host_error)?;
        let material = host
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_local_host_error)?;
        if !physical_material_matches_identity(&material, identity) {
            return Err(AgentRouteError::NotReady);
        }
        if !physical_material_authorizes_work(
            &material,
            identity,
            request.execution(),
            request.work(),
            request.authorization(),
        ) {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        host.invoke(request.work.agent, request.work, request.authorization)
            .map(|outcome| AgentInvocationResponse::direct(&response_request, outcome))
            .map_err(map_local_host_error)
    }

    fn resume(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        if !request.execution().is_direct()
            || self
                .selected
                .is_some_and(|agent| agent != identity.key().agent())
        {
            return Err(AgentRouteError::Rejected);
        }
        let mut host =
            super::local_sdk_host::LocalAgentHost::checkout(&self.host, identity.key().agent())
                .map_err(map_local_host_error)?;
        let material = host
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_local_host_error)?;
        if !physical_material_matches_identity(&material, identity) {
            return Err(AgentRouteError::NotReady);
        }
        if !physical_material_authorizes_work(
            &material,
            identity,
            request.execution(),
            request.work(),
            request.authorization(),
        ) {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        host.resume_sdk_exact(
            request.work().agent,
            request.invocation.work,
            request.invocation.authorization,
            request.yielded,
        )
        .map(|outcome| AgentResumeResponse::direct(&response_request, outcome))
        .map_err(map_local_host_error)
    }

    fn acknowledge(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        if !request.execution().is_direct()
            || self
                .selected
                .is_some_and(|agent| agent != identity.key().agent())
        {
            return Err(AgentRouteError::Rejected);
        }
        let mut host =
            super::local_sdk_host::LocalAgentHost::checkout(&self.host, identity.key().agent())
                .map_err(map_local_host_error)?;
        let material = host
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_local_host_error)?;
        if !physical_material_matches_identity(&material, identity) {
            return Err(AgentRouteError::NotReady);
        }
        if !physical_material_authorizes_work(
            &material,
            identity,
            request.execution(),
            request.work(),
            request.authorization(),
        ) {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        host.acknowledge_sdk(
            request.work().agent,
            request.invocation.work,
            request.invocation.authorization,
        )
        .map(|outcome| AgentAcknowledgementResponse::new(&response_request, outcome))
        .map_err(map_local_host_error)
    }

    fn prepare(
        &mut self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        if self
            .selected
            .is_some_and(|agent| agent != identity.key().agent())
        {
            return Err(AgentRouteError::Rejected);
        }
        super::local_sdk_host::LocalAgentHost::checkout(&self.host, identity.key().agent())
            .map_err(map_local_host_error)?
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_local_host_error)
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    fn authorize_projection(
        &mut self,
        head: AuthorityProjectionHead,
        projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let audit = if let Some(agent) = self.selected {
            super::local_sdk_host::LocalAgentHost::checkout(&self.host, agent)
                .and_then(|execution| execution.audit_authority_projection(head, projection))
        } else {
            self.host
                .lock()
                .map_err(|_| AgentRouteError::Unavailable)?
                .audit_authority_projection(head, projection)
        };
        match audit {
            Ok(super::local_sdk_host::LocalAuthorityProjectionAudit::Ready(identities)) => {
                Ok(identities)
            }
            Ok(super::local_sdk_host::LocalAuthorityProjectionAudit::Lag) => {
                Err(AgentRouteError::NotReady)
            }
            Err(super::local_sdk_host::LocalAgentHostError::Busy) => Err(AgentRouteError::NotReady),
            Err(error) => Err(match error {
                super::local_sdk_host::LocalAgentHostError::InvalidDescriptor
                | super::local_sdk_host::LocalAgentHostError::NotFound => AgentRouteError::Rejected,
                error => map_local_host_error(error),
            }),
        }
    }
}

fn map_local_host_error(error: super::local_sdk_host::LocalAgentHostError) -> AgentRouteError {
    use super::driver::AgentDriverError;
    use super::local_sdk_host::LocalAgentHostError;
    match error {
        LocalAgentHostError::NotFound => AgentRouteError::NotReady,
        LocalAgentHostError::Busy
        | LocalAgentHostError::AlreadyExists
        | LocalAgentHostError::InvalidDescriptor
        | LocalAgentHostError::UnsupportedProfile
        | LocalAgentHostError::LimitExceeded => AgentRouteError::Rejected,
        LocalAgentHostError::Driver(
            AgentDriverError::Execution(_)
            | AgentDriverError::Lifecycle(_)
            | AgentDriverError::SdkManagement(_)
            | AgentDriverError::Authority(_),
        ) => AgentRouteError::Rejected,
        LocalAgentHostError::Io
        | LocalAgentHostError::InvalidRoot
        | LocalAgentHostError::InvalidScope
        | LocalAgentHostError::Alias
        | LocalAgentHostError::Corrupt
        | LocalAgentHostError::Driver(_) => AgentRouteError::Unavailable,
    }
}

/// Move one clean Local host into an exclusively owned bounded route worker.
pub fn local_agent_supervisor_attachment(
    host: super::local_sdk_host::LocalAgentHost,
    queue_capacity: usize,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    local_agent_supervisor_attachment_shared(Arc::new(std::sync::Mutex::new(host)), queue_capacity)
}

/// Attach a route worker to the lifecycle owner's existing physical host.
/// Requests check out one exclusive Agent driver, releasing the registry
/// mutex before execution. Lifecycle work on that Agent is refused while its
/// driver is checked out. The lifecycle owner must never wait for this worker
/// while holding the registry mutex. This attachment still has one worker;
/// independent-Agent scheduling requires separate execution attachments.
/// Retiring a worker drops its reference, not the lifecycle owner's lease.
pub(crate) fn local_agent_supervisor_attachment_shared(
    host: Arc<std::sync::Mutex<super::local_sdk_host::LocalAgentHost>>,
    queue_capacity: usize,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    spawn_backend(
        LocalAgentRouteBackend {
            host,
            selected: None,
        },
        queue_capacity,
        "vos-local-agent-route",
    )
}

/// One Agent, no dedicated thread. The supervisor pool owns serving work;
/// the inline backend mutex excludes lifecycle inspection of this same Agent.
pub(crate) fn local_agent_supervisor_attachment_for_agent(
    host: Arc<std::sync::Mutex<super::local_sdk_host::LocalAgentHost>>,
    agent: AgentId,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    inline_backend(LocalAgentRouteBackend {
        host,
        selected: Some(agent),
    })
}

/// One experimental external-state Local Agent. The locked journal owner is
/// already generation-pinned and must have completed signed Create finality
/// before this backend can be attached. Each request obtains trusted logical
/// time and rechecks the physical actor closure before guest admission.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
struct ExternalLocalAgentRouteBackend {
    owner: Arc<std::sync::Mutex<super::external_local_executor::ExternalLocalJournalOwner>>,
    clock: Arc<dyn super::driver::AgentTrustProvider>,
    agent: AgentId,
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl ExternalLocalAgentRouteBackend {
    fn slot(&self) -> Result<u64, AgentRouteError> {
        self.clock
            .current_logical_slot()
            .ok_or(AgentRouteError::Unavailable)
    }

    fn budget() -> super::sdk::state_blocks::ReadBudget {
        // Provisional bounded owner-side IO, pending the measured release
        // gate. This is a limit, not a throughput or dataset qualification.
        super::sdk::state_blocks::ReadBudget::new(10_000, 10_000_000)
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
fn map_external_local_error(error: super::journal_store::JournalStoreError) -> AgentRouteError {
    use super::journal_store::JournalStoreError;
    match error {
        JournalStoreError::Conflict
        | JournalStoreError::ScopeMismatch
        | JournalStoreError::NonCanonical => AgentRouteError::Rejected,
        JournalStoreError::Backpressure | JournalStoreError::GcPending => AgentRouteError::NotReady,
        _ => AgentRouteError::Unavailable,
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
impl CleanAgentRouteBackend for ExternalLocalAgentRouteBackend {
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let slot = self.slot()?;
        let owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        if owner.descriptor().identity.agent != self.agent {
            return Err(AgentRouteError::Unavailable);
        }
        owner.route_identities(slot, &mut Self::budget())
    }

    fn ready(&mut self) -> Result<(), AgentRouteError> {
        self.slot()?;
        let owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        if owner.descriptor().identity.agent != self.agent {
            return Err(AgentRouteError::Unavailable);
        }
        owner.materialization().map_err(map_external_local_error)?;
        Ok(())
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        if !request.execution().is_direct() || identity.key().agent() != self.agent {
            return Err(AgentRouteError::Rejected);
        }
        let slot = self.slot()?;
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        let mut budget = Self::budget();
        let material = owner
            .physical_invocation_material(identity.key().actor(), slot, &mut budget)
            .map_err(map_external_local_error)?;
        if !physical_material_matches_identity(&material, identity) {
            return Err(AgentRouteError::NotReady);
        }
        if !physical_material_authorizes_work(
            &material,
            identity,
            request.execution(),
            request.work(),
            request.authorization(),
        ) {
            return Err(AgentRouteError::Rejected);
        }
        let input = super::journal::ReplayInput {
            runtime: owner
                .materialization()
                .map_err(map_external_local_error)?
                .runtime()
                .clone(),
            operation: super::journal::ReplayOperation::CleanInvoke {
                context: RuntimeExecutionContext::Direct,
                work: request.work().clone(),
                authorization: request.authorization().clone(),
                observed_slot: slot,
            },
        };
        let outcome = owner
            .submit_direct_clean(input, slot, &mut budget)
            .map_err(map_external_local_error)?;
        Ok(AgentInvocationResponse::direct(&request, outcome))
    }

    fn acknowledge(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        if !request.execution().is_direct()
            || request.expected_live().is_some()
            || identity.key().agent() != self.agent
        {
            return Err(AgentRouteError::Rejected);
        }
        let slot = self.slot()?;
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        let mut budget = Self::budget();
        let material = owner
            .physical_invocation_material(identity.key().actor(), slot, &mut budget)
            .map_err(map_external_local_error)?;
        if !physical_material_matches_identity(&material, identity) {
            return Err(AgentRouteError::NotReady);
        }
        if !physical_material_authorizes_work(
            &material,
            identity,
            request.execution(),
            request.work(),
            request.authorization(),
        ) {
            return Err(AgentRouteError::Rejected);
        }
        let input = super::journal::ReplayInput {
            runtime: owner
                .materialization()
                .map_err(map_external_local_error)?
                .runtime()
                .clone(),
            operation: super::journal::ReplayOperation::CleanAcknowledge {
                context: RuntimeExecutionContext::Direct,
                expected_live: None,
                work: super::sdk::InvocationRetirement::from_work(request.work()),
                authorization: request.authorization().clone(),
            },
        };
        let outcome = owner
            .submit_direct_clean(input, slot, &mut budget)
            .map_err(map_external_local_error)?;
        Ok(AgentAcknowledgementResponse::new(&request, outcome))
    }

    fn prepare(
        &mut self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        if identity.key().agent() != self.agent {
            return Err(AgentRouteError::Rejected);
        }
        let slot = self.slot()?;
        let owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        let material = owner
            .physical_invocation_material(identity.key().actor(), slot, &mut Self::budget())
            .map_err(map_external_local_error)?;
        physical_material_matches_identity(&material, identity)
            .then_some(material)
            .ok_or(AgentRouteError::NotReady)
    }

    #[cfg(feature = "network")]
    fn authorize_projection(
        &mut self,
        _head: AuthorityProjectionHead,
        projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let [expected] = projection else {
            return Err(AgentRouteError::NotReady);
        };
        let slot = self.slot()?;
        let owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        if owner.descriptor() != expected.descriptor()
            || owner.descriptor().identity.agent != self.agent
        {
            return Err(AgentRouteError::NotReady);
        }
        let descriptor = owner.descriptor();
        let mut budget = Self::budget();
        let records = collect_actor_directory(
            descriptor.capabilities.max_actors as usize,
            |after, limit| {
                owner
                    .inspect_actors(after, limit, slot, &mut budget)
                    .map_err(map_external_local_error)
            },
        )?;
        if records.len() != expected.actors().len() {
            return Err(AgentRouteError::NotReady);
        }
        let mut identities = Vec::new();
        for (record, actor) in records.iter().zip(expected.actors()) {
            if record.entry.actor != actor.entry.actor {
                return Err(AgentRouteError::NotReady);
            }
            let material = owner
                .physical_invocation_material(record.entry.actor, slot, &mut budget)
                .map_err(map_external_local_error)?;
            if !physical_material_matches_authority(&material, descriptor, actor) {
                return Err(AgentRouteError::NotReady);
            }
            if !record.entry.suspended {
                identities.push(physical_material_identity(&material)?);
            }
        }
        Ok(identities)
    }
}

/// Attach an already-finalized experimental external Local generation to one
/// inline supervisor worker. Startup/lifecycle owns the Arc and its locked
/// slot; dropping or retiring this attachment cannot release that lease.
#[cfg(all(
    target_os = "linux",
    feature = "storage",
    feature = "experimental-state-blocks"
))]
pub(crate) fn external_local_agent_supervisor_attachment_for_agent(
    owner: Arc<std::sync::Mutex<super::external_local_executor::ExternalLocalJournalOwner>>,
    clock: Arc<dyn super::driver::AgentTrustProvider>,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    let agent = owner
        .lock()
        .map_err(|_| AgentRouteAdapterError::Route(AgentRouteError::Unavailable))?
        .descriptor()
        .identity
        .agent;
    inline_backend(ExternalLocalAgentRouteBackend {
        owner,
        clock,
        agent,
    })
}

/// File-owner fixture bridge: exercise the actual inline worker, projection
/// authorization, Direct route envelopes, retry and retirement. The fixture
/// supplies a physically finalized owner and a newly signed query; this does
/// not stand in for startup lifecycle selection or Authority finality.
#[cfg(all(
    test,
    target_os = "linux",
    feature = "storage",
    feature = "network",
    feature = "experimental-state-blocks"
))]
pub(crate) fn qualify_external_local_route_for_test(
    owner: Arc<std::sync::Mutex<super::external_local_executor::ExternalLocalJournalOwner>>,
    input: super::journal::ReplayInput,
) {
    use core::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FixedClock(AtomicU64);
    impl super::driver::AgentTrustProvider for FixedClock {
        fn current_logical_slot(&self) -> Option<u64> {
            Some(self.0.load(Ordering::Acquire))
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

    let slot = match &input.operation {
        super::journal::ReplayOperation::CleanInvoke { observed_slot, .. } => *observed_slot,
        _ => panic!("route fixture requires a clean Invoke"),
    };
    let clock = Arc::new(FixedClock(AtomicU64::new(slot)));
    let attachment =
        external_local_agent_supervisor_attachment_for_agent(owner.clone(), clock.clone()).unwrap();
    let handle = attachment.handle();
    let identities = handle.identities().unwrap();
    let [identity] = identities.as_slice() else {
        panic!("route fixture requires exactly one installed Actor")
    };
    let material = handle.prepare(*identity).unwrap();
    let actor = AuthorityActorProjection {
        agent: material.descriptor.identity.agent,
        entry: material.actor.entry.clone(),
        producer: material.producer,
        contract: material.contract,
        requirements: material.requirements,
        root_provenance: material.root_provenance,
        installation_id: material.actor.installation_id,
        registry_reservation: material.actor.registry_reservation,
        install_request: material.install_request,
    };
    let projection = AgentAuthorityRouteProjection::new(
        material.descriptor.replica_generation(),
        material.descriptor.clone(),
        vec![actor],
    )
    .unwrap();
    let one = NonZeroU64::new(1).unwrap();
    let head = AuthorityProjectionHead {
        state_revision: one,
        epoch: one,
        authorization_sequence: one,
        administration_generation: one,
        state_commitment: Hash([0x33; 32]),
    };
    assert_eq!(
        handle.authorize_projection(head, vec![projection]).unwrap(),
        identities
    );
    let super::journal::ReplayOperation::CleanInvoke {
        work,
        authorization,
        ..
    } = input.operation
    else {
        unreachable!()
    };
    let request = AgentInvocationRequest::new(
        RuntimeExecutionContext::Direct,
        work.clone(),
        authorization.clone(),
    )
    .unwrap();
    let first = handle.invoke(*identity, request.clone()).unwrap();
    assert!(matches!(first.outcome(), RuntimeOutcome::Completed(Ok(_))));
    assert_eq!(handle.invoke(*identity, request.clone()).unwrap(), first);
    let acknowledge = AgentAcknowledgementRequest::new(
        RuntimeExecutionContext::Direct,
        None,
        work,
        authorization,
    )
    .unwrap();
    let acknowledged = handle.acknowledge(*identity, acknowledge.clone()).unwrap();
    assert!(acknowledged.matches_request(&acknowledge));
    assert_eq!(
        handle.acknowledge(*identity, acknowledge).unwrap(),
        acknowledged
    );
    clock.0.store(slot + 99, Ordering::Release);
    assert_eq!(
        handle.invoke(*identity, request),
        Err(AgentRouteError::Rejected),
    );
    drop(handle);
    attachment.retire().unwrap();
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
struct SharedAgentRouteBackend {
    host: crate::network::SharedAgentNetworkHost,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl CleanAgentRouteBackend for SharedAgentRouteBackend {
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let projections = self
            .host
            .supervisor_projections()
            .map_err(map_shared_host_error)?;
        let mut identities = Vec::new();
        for projection in projections {
            identities.extend(route_identities(
                &projection.descriptor,
                projection.actors,
                AgentProfile::Shared,
            )?);
        }
        if identities
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            identities.sort_by_key(|identity| identity.key());
            if identities
                .windows(2)
                .any(|pair| pair[0].key() >= pair[1].key())
            {
                return Err(AgentRouteError::Unavailable);
            }
        }
        Ok(identities)
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        if !request.execution.is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.host
            .supervisor_invoke(identity, request.work, request.authorization)
            .map(|outcome| AgentInvocationResponse::direct(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn resume(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.host
            .supervisor_resume(
                identity,
                request.invocation.work,
                request.invocation.authorization,
                request.yielded,
            )
            .map(|outcome| AgentResumeResponse::direct(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn acknowledge(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.host
            .supervisor_acknowledge(
                identity,
                request.invocation.work,
                request.invocation.authorization,
            )
            .map(|outcome| AgentAcknowledgementResponse::new(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn prepare(
        &mut self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        self.host
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_shared_host_error)
    }

    fn authorize_projection(
        &mut self,
        head: AuthorityProjectionHead,
        projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        match self.host.audit_authority_projection(head, projection, None) {
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Ready(identities)) => {
                Ok(identities)
            }
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Lag) => {
                Err(AgentRouteError::NotReady)
            }
            Err(error) => Err(map_shared_projection_error(error)),
        }
    }
}

/// One backend per exact ordinary generation, borrowing its network owner's
/// lifecycle without retaining that owner after shutdown. The bounded
/// supervisor executor supplies dispatch threads, as for ordinary Local Agents.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl CleanAgentRouteBackend for crate::network::shared_agent::SharedAgentRouteHandle {
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let projection = self.projection().map_err(map_shared_host_error)?;
        route_identities(
            &projection.descriptor,
            projection.actors,
            AgentProfile::Shared,
        )
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        if !request.execution.is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.execute(
            identity,
            super::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work: request.work,
                authorization: request.authorization,
            },
        )
        .map(|outcome| AgentInvocationResponse::direct(&response_request, outcome))
        .map_err(map_shared_host_error)
    }

    fn resume(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.execute(
            identity,
            super::shared_journal_driver::CleanInvocationReplayRequest::Resume {
                context: RuntimeExecutionContext::Direct,
                work: request.invocation.work,
                authorization: request.invocation.authorization,
                yielded: request.yielded,
            },
        )
        .map(|outcome| AgentResumeResponse::direct(&response_request, outcome))
        .map_err(map_shared_host_error)
    }

    fn acknowledge(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.execute(
            identity,
            super::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work: request.invocation.work,
                authorization: request.invocation.authorization,
            },
        )
        .map(|outcome| AgentAcknowledgementResponse::new(&response_request, outcome))
        .map_err(map_shared_host_error)
    }

    fn prepare(
        &mut self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        let material = self
            .material(identity.key().actor())
            .map_err(map_shared_host_error)?;
        if material.descriptor.identity.space != identity.key().space()
            || material.descriptor.identity.agent != identity.key().agent()
        {
            return Err(AgentRouteError::Rejected);
        }
        Ok(material)
    }

    fn authorize_projection(
        &mut self,
        head: AuthorityProjectionHead,
        projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        match self.audit(head, projection) {
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Ready(identities)) => {
                Ok(identities)
            }
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Lag) => {
                Err(AgentRouteError::NotReady)
            }
            Err(error) => Err(map_shared_projection_error(error)),
        }
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn shared_agent_supervisor_attachment_for_generation(
    handle: crate::network::shared_agent::SharedAgentRouteHandle,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    inline_backend(handle)
}

/// Move the complete live Shared-network owner into one bounded supervisor
/// worker. Its existing `Drop` retires exact network routes and joins Raft,
/// apply, and Merge workers before this attachment can finish joining.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub fn shared_agent_supervisor_attachment(
    host: crate::network::SharedAgentNetworkHost,
    queue_capacity: usize,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
    spawn_backend(
        SharedAgentRouteBackend { host },
        queue_capacity,
        "vos-shared-agent-route",
    )
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
struct SystemAgentRouteBackend<P, R, I>
where
    P: super::clean_bootstrap::CleanSystemAgentBootstrapStore,
    R: super::clean_bootstrap::CleanSystemAgentBootstrapStore,
    I: super::clean_authority_issuer::CleanManagementIssuerStore,
{
    owner: Arc<std::sync::Mutex<super::clean_bootstrap::CleanSystemAgentBootstrapOwner<P, R, I>>>,
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
impl<P, R, I> CleanAgentRouteBackend for SystemAgentRouteBackend<P, R, I>
where
    P: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    R: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    I: super::clean_authority_issuer::CleanManagementIssuerStore + Send + 'static,
{
    fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let projections = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .supervisor_projections()
            .map_err(map_shared_host_error)?;
        let projection = projections
            .into_iter()
            .next()
            .ok_or(AgentRouteError::Unavailable)?;
        route_identities(
            &projection.descriptor,
            projection.actors,
            AgentProfile::Shared,
        )
    }

    fn invoke(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentInvocationRequest,
    ) -> Result<AgentInvocationResponse, AgentRouteError> {
        if !request.execution.is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .supervisor_invoke(identity, request.work, request.authorization)
            .map(|outcome| AgentInvocationResponse::direct(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn resume(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentResumeRequest,
    ) -> Result<AgentResumeResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .supervisor_resume(
                identity,
                request.invocation.work,
                request.invocation.authorization,
                request.yielded,
            )
            .map(|outcome| AgentResumeResponse::direct(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn acknowledge(
        &mut self,
        identity: AgentRouteIdentity,
        request: AgentAcknowledgementRequest,
    ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
        if !request.execution().is_direct() {
            return Err(AgentRouteError::Rejected);
        }
        let response_request = request.clone();
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .supervisor_acknowledge(
                identity,
                request.invocation.work,
                request.invocation.authorization,
            )
            .map(|outcome| AgentAcknowledgementResponse::new(&response_request, outcome))
            .map_err(map_shared_host_error)
    }

    fn prepare(
        &mut self,
        identity: AgentRouteIdentity,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, AgentRouteError> {
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .supervisor_invocation_material(identity.key().agent(), identity.key().actor())
            .map_err(map_shared_host_error)
    }

    fn authorize_projection(
        &mut self,
        head: AuthorityProjectionHead,
        projection: &[AgentAuthorityRouteProjection],
    ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?;
        match owner.audit_authority_projection(head, projection) {
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Ready(identities)) => {
                Ok(identities)
            }
            Ok(super::shared_host::SharedAuthorityProjectionAudit::Lag) => {
                Err(AgentRouteError::NotReady)
            }
            Err(error) => Err(map_shared_projection_error(error)),
        }
    }

    fn authority_target(&mut self) -> Result<AuthorityActorTarget, AgentRouteError> {
        Ok(self
            .owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .authority_target())
    }

    fn authority_projection(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentRouteError> {
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .invoke_authority_projection(query)
            .map_err(|error| {
                tracing::debug!(?error, "System authority projection failed");
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some() {
                    eprintln!("system projection host error: {error:?}");
                }
                map_authority_read_error(error)
            })
    }

    fn recover_authority_projection(&mut self) -> Result<bool, AgentRouteError> {
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .recover_pending_authority_projection()
            .map_err(map_authority_read_error)
    }

    fn peer_authority_projection(
        &mut self,
        query: AuthorityProjectionQuery,
        recovering: bool,
        sender: NodeId,
    ) -> Result<(), AgentRouteError> {
        self.owner
            .lock()
            .map_err(|_| AgentRouteError::Unavailable)?
            .invoke_peer_authority_projection(query, recovering, sender)
            .map(|_| ())
            .map_err(map_authority_read_error)
    }
}

/// Move the complete bootstrapped system-Agent owner—including its durable
/// issuer and live Shared-network owner—behind one exclusive route worker.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub fn system_agent_supervisor_attachment<P, R, I>(
    owner: super::clean_bootstrap::CleanSystemAgentBootstrapOwner<P, R, I>,
    queue_capacity: usize,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>
where
    P: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    R: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    I: super::clean_authority_issuer::CleanManagementIssuerStore + Send + 'static,
{
    system_agent_supervisor_attachment_shared(
        Arc::new(std::sync::Mutex::new(owner)),
        queue_capacity,
    )
}

/// Share the existing system owner with native lifecycle coordination. All
/// worker operations serialize on this owner, without a second network host.
/// Never wait for this worker while holding the owner mutex. Native shutdown
/// must join lifecycle work and release its reference as well as retiring the
/// route worker before expecting the physical/network lease to be released.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn system_agent_supervisor_attachment_shared<P, R, I>(
    owner: Arc<std::sync::Mutex<super::clean_bootstrap::CleanSystemAgentBootstrapOwner<P, R, I>>>,
    queue_capacity: usize,
) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError>
where
    P: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    R: super::clean_bootstrap::CleanSystemAgentBootstrapStore + Send + 'static,
    I: super::clean_authority_issuer::CleanManagementIssuerStore + Send + 'static,
{
    let attachment = spawn_backend(
        SystemAgentRouteBackend {
            owner: Arc::clone(&owner),
        },
        queue_capacity,
        "vos-system-agent-route",
    )?;
    let handle = attachment.handle();
    owner
        .lock()
        .map_err(|_| AgentRouteAdapterError::Route(AgentRouteError::Unavailable))?
        .install_projection_dispatch(Arc::new(move |query, recovering, sender| {
            handle
                .enqueue_peer_projection(query, recovering, sender)
                .is_ok()
        }))
        .map_err(|error| AgentRouteAdapterError::Route(map_shared_host_error(error)))?;
    Ok(attachment)
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_shared_host_error(error: super::shared_host::SharedAgentHostError) -> AgentRouteError {
    use super::shared_host::SharedAgentHostError;
    match error {
        SharedAgentHostError::AgentNotFound | SharedAgentHostError::TransportNotAttached => {
            AgentRouteError::NotReady
        }
        SharedAgentHostError::CapacityExhausted
        | SharedAgentHostError::Conflict
        | SharedAgentHostError::ProjectionExpired
        | SharedAgentHostError::InvalidProvision => AgentRouteError::Rejected,
        _ => AgentRouteError::Unavailable,
    }
}

#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_shared_projection_error(error: super::shared_host::SharedAgentHostError) -> AgentRouteError {
    use super::shared_host::SharedAgentHostError;
    match error {
        SharedAgentHostError::AgentNotFound | SharedAgentHostError::ScopeMismatch => {
            AgentRouteError::Rejected
        }
        error => map_shared_host_error(error),
    }
}

// Keep temporary consensus unavailability distinct from malformed state or
// failed authentication. Only this private Authority-read path may defer
// initial publication while retaining its consensus owner.
#[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
fn map_authority_read_error(error: super::shared_host::SharedAgentHostError) -> AgentRouteError {
    match error {
        super::shared_host::SharedAgentHostError::Unavailable => AgentRouteError::NotReady,
        super::shared_host::SharedAgentHostError::ProjectionExpired => AgentRouteError::Rejected,
        _ => AgentRouteError::Unavailable,
    }
}

/// Resolve one exact new invocation from a still-current physical route.
///
/// This performs no authorization and emits no receipt. The returned work,
/// trusted slot, and physically selected AMP2 policy are the immutable input
/// to the later PublicPreflight/AOC5 decision. Private routes are rejected;
/// there is no plaintext preparation fallback.
pub fn prepare_invocation(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    intent: AgentInvocationIntent,
) -> Result<PreparedAgentInvocation, AgentSupervisorError> {
    if snapshot.profile() == AgentProfile::Private {
        return Err(AgentSupervisorError::Route(AgentRouteError::Rejected));
    }
    let request = AgentPreparationRequest::new(snapshot, intent)
        .map_err(|_| AgentSupervisorError::Route(AgentRouteError::Rejected))?;
    let payload = request
        .encode()
        .map_err(|_| AgentSupervisorError::Route(AgentRouteError::Rejected))?;
    let response = supervisor.dispatch(snapshot, payload)?;
    let prepared = canonical_decode::<AgentPreparationResponse>(&response)
        .map_err(AgentSupervisorError::Route)?
        .prepared;
    if !prepared_matches_request(&prepared, snapshot, &request) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Unavailable));
    }
    Ok(prepared)
}

/// Canonically encode, dispatch, and decode one typed clean Agent invocation.
/// A generic/legacy route which emits a non-`ASR1` response is rejected.
pub fn dispatch_invocation(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    request: AgentInvocationRequest,
) -> Result<AgentInvocationResponse, AgentSupervisorError> {
    let encoded_request = request
        .encode()
        .map_err(|_| AgentSupervisorError::Route(AgentRouteError::Rejected))?;
    dispatch_encoded_invocation(supervisor, snapshot, &encoded_request)
}

/// Replay an already-persisted canonical public invocation envelope without
/// preparation or authorization reconstruction. The exact bytes are decoded
/// and checked against the selected route before dispatch.
pub fn dispatch_encoded_invocation(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    encoded_request: &[u8],
) -> Result<AgentInvocationResponse, AgentSupervisorError> {
    let request = canonical_decode::<AgentInvocationRequest>(encoded_request)
        .map_err(AgentSupervisorError::Route)?;
    if !request.matches_route(snapshot) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Rejected));
    }
    let response = supervisor.dispatch(snapshot, encoded_request.to_vec())?;
    let response = canonical_decode::<AgentInvocationResponse>(&response)
        .map_err(AgentSupervisorError::Route)?;
    // Do not rely solely on the concrete clean adapter's check: this public
    // typed boundary may be handed a snapshot installed by another
    // `AgentRoute` implementation. Every response, including an otherwise
    // identity-free execution error, must bind this exact request.
    if !response.matches_request(&request) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Unavailable));
    }
    Ok(response)
}

pub fn dispatch_resume(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    request: AgentResumeRequest,
) -> Result<AgentResumeResponse, AgentSupervisorError> {
    let encoded = request
        .encode()
        .map_err(|_| AgentSupervisorError::Route(AgentRouteError::Rejected))?;
    dispatch_encoded_resume(supervisor, snapshot, &encoded)
}

pub fn dispatch_encoded_resume(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    encoded_request: &[u8],
) -> Result<AgentResumeResponse, AgentSupervisorError> {
    let request = canonical_decode::<AgentResumeRequest>(encoded_request)
        .map_err(AgentSupervisorError::Route)?;
    if !request.matches_route(snapshot) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Rejected));
    }
    let response = supervisor.dispatch(snapshot, encoded_request.to_vec())?;
    let response =
        canonical_decode::<AgentResumeResponse>(&response).map_err(AgentSupervisorError::Route)?;
    if !response.matches_request(&request) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Unavailable));
    }
    Ok(response)
}

pub fn dispatch_acknowledgement(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    request: AgentAcknowledgementRequest,
) -> Result<AgentAcknowledgementResponse, AgentSupervisorError> {
    let encoded = request
        .encode()
        .map_err(|_| AgentSupervisorError::Route(AgentRouteError::Rejected))?;
    dispatch_encoded_acknowledgement(supervisor, snapshot, &encoded)
}

pub fn dispatch_encoded_acknowledgement(
    supervisor: &super::supervisor::AgentSupervisorHandle,
    snapshot: AgentRouteSnapshot,
    encoded_request: &[u8],
) -> Result<AgentAcknowledgementResponse, AgentSupervisorError> {
    let request = canonical_decode::<AgentAcknowledgementRequest>(encoded_request)
        .map_err(AgentSupervisorError::Route)?;
    if !request.matches_route(snapshot) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Rejected));
    }
    let response = supervisor.dispatch(snapshot, encoded_request.to_vec())?;
    let response = canonical_decode::<AgentAcknowledgementResponse>(&response)
        .map_err(AgentSupervisorError::Route)?;
    if !response.matches_request(&request) {
        return Err(AgentSupervisorError::Route(AgentRouteError::Unavailable));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    #[test]
    fn shared_projection_expiry_is_terminal_route_rejection() {
        use crate::agent::shared_host::SharedAgentHostError as Error;
        assert_eq!(
            map_shared_host_error(Error::ProjectionExpired),
            AgentRouteError::Rejected
        );
        assert_eq!(
            map_authority_read_error(Error::ProjectionExpired),
            AgentRouteError::Rejected
        );
    }

    #[cfg(all(feature = "storage", feature = "network", target_os = "linux"))]
    #[test]
    fn authority_read_only_defers_explicit_unavailability() {
        use crate::agent::shared_host::SharedAgentHostError as Error;
        assert_eq!(
            map_authority_read_error(Error::Unavailable),
            AgentRouteError::NotReady
        );
        for error in [
            Error::CorruptResidue,
            Error::ScopeMismatch,
            Error::SnapshotCertificateInvalid,
            Error::CapacityExhausted,
            Error::Conflict,
            Error::AgentNotFound,
            Error::TransportNotAttached,
        ] {
            assert_eq!(
                map_authority_read_error(error),
                AgentRouteError::Unavailable
            );
        }
    }
    use core::num::NonZeroU64;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    use crate::actors::codec::Encode as _;
    use crate::actors::value::{Msg, TAG_DYNAMIC};
    use crate::agent::invocation_preparation::PhysicalInvocationMaterial;
    use crate::agent::sdk::authority::{
        AgentAuthorityBinding, AuthorityActorProjectionPage, AuthorityAgentProjection,
        AuthorityAgentProjectionPage, AuthorityAgentReplicaProjectionPage, AuthorityBuiltinRole,
        AuthorityCredentialKind, AuthorityCredentialProjection, AuthorityCredentialStatus,
        AuthorityIngressAuthentication, AuthorityIssuer, AuthorityProjectionHead,
        AuthorityProjectionSelector,
    };
    use crate::agent::sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use crate::agent::sdk::method_policy::{AttestationRequirement, IdempotencyRequirement};
    use crate::agent::sdk::proof::{
        PROOF_PUBLIC_KEY_BYTES, PROOF_SIGNATURE_BYTES, ProofLaneRoots, TransitionProofStatement,
        TransitionProofSubject,
    };
    use crate::agent::sdk::schema::{
        ConstructorArgument, ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod,
        ParsedSchema,
    };
    use crate::agent::sdk::{
        ActorEntry, AgentId, AgentIdentity, AgentReplica, CredentialId, DeploymentId,
        FieldPersistence, Hash, InstallationId, InvocationError, InvocationId, InvocationOrigin,
        InvocationRoleClaims, LaneSet, MethodMode, PrincipalId, ProducerId, ProgramId,
        PublicPreflight, ReplicaRole, RuntimeBlob, RuntimeCapabilities, RuntimeRequirements,
        SpaceId, StateLane,
    };
    use crate::agent::supervisor::{AgentSupervisorLimits, AgentSupervisorOwner};

    fn request(seed: u8, execution: RuntimeExecutionContext) -> AgentInvocationRequest {
        let work = InvocationWork {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            runtime_deployment: DeploymentId([3; 32]),
            invocation: InvocationId([seed; 32]),
            actor: ActorId([4; 32]),
            incarnation: Hash([5; 32]),
            deployment: DeploymentId([6; 32]),
            program: ProgramId([7; 32]),
            mode: MethodMode::Query,
            origin: InvocationOrigin::anonymous(),
            roles: InvocationRoleClaims::none(),
            message: vec![seed],
            installation_data: None,
            availability: Vec::new(),
            gas: 100,
            recovery_only: false,
        };
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 17));
        AgentInvocationRequest::new(execution, work, authorization).unwrap()
    }

    fn proof_key(request: &AgentInvocationRequest, seed: u8) -> TransitionProofKey {
        TransitionProofKey {
            invocation: request.work().invocation,
            execution: Hash([seed; 32]),
        }
    }

    fn encode_unchecked<T: CanonicalWire>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&T::MAGIC);
        bytes.extend_from_slice(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        value.encode_body(&mut Encoder(&mut bytes));
        bytes
    }

    fn identity(request: &AgentInvocationRequest) -> AgentRouteIdentity {
        AgentRouteIdentity::new(
            AgentRouteKey::new(request.work.space, request.work.agent, request.work.actor).unwrap(),
            request.work.incarnation,
            request.work.runtime_deployment,
            request.work.deployment,
            request.work.program,
            AgentProfile::Local,
        )
        .unwrap()
    }

    fn yielded(
        request: &AgentInvocationRequest,
        ready_sequence: u64,
    ) -> super::super::sdk::YieldedInvocation {
        super::super::sdk::YieldedInvocation {
            invocation: request.work.invocation,
            actor: request.work.actor,
            incarnation: request.work.incarnation,
            deployment: request.work.deployment,
            program: request.work.program,
            mode: request.work.mode,
            continuation: BlobRef::of_bytes(b"retained-supervisor-continuation"),
            ready_sequence,
            installation_data: request.work.installation_data.clone(),
            required: request
                .work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: super::super::sdk::YieldReason::Cooperative,
        }
    }

    fn acknowledged(
        request: &AgentAcknowledgementRequest,
    ) -> super::super::sdk::InvocationAcknowledgement {
        let work = request.work();
        super::super::sdk::InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: work.commitment(),
            authorization: request.authorization().commitment(),
        }
    }

    fn limits() -> AgentSupervisorLimits {
        AgentSupervisorLimits::new(8, 4, 4, AgentInvocationResponse::MAX_ENCODED_BYTES)
    }

    struct ReadyGate {
        started: SyncSender<()>,
        release: Receiver<()>,
    }

    enum FakeReply {
        RequestBoundError,
        Fixed(AgentInvocationResponse),
        Panic,
    }

    struct FakeBackend {
        identities: Arc<Mutex<Vec<AgentRouteIdentity>>>,
        ready: Option<ReadyGate>,
        reply: FakeReply,
        invokes: Arc<AtomicUsize>,
        retired: Arc<AtomicBool>,
    }

    impl CleanAgentRouteBackend for FakeBackend {
        fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
            self.identities
                .lock()
                .map(|identities| identities.clone())
                .map_err(|_| AgentRouteError::Unavailable)
        }

        fn ready(&mut self) -> Result<(), AgentRouteError> {
            if let Some(gate) = self.ready.take() {
                gate.started
                    .send(())
                    .map_err(|_| AgentRouteError::Unavailable)?;
                gate.release
                    .recv()
                    .map_err(|_| AgentRouteError::Unavailable)?;
            }
            Ok(())
        }

        fn invoke(
            &mut self,
            _identity: AgentRouteIdentity,
            request: AgentInvocationRequest,
        ) -> Result<AgentInvocationResponse, AgentRouteError> {
            self.invokes.fetch_add(1, Ordering::AcqRel);
            match &self.reply {
                FakeReply::RequestBoundError => Ok(AgentInvocationResponse::direct(
                    &request,
                    RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
                )),
                FakeReply::Fixed(response) => Ok(response.clone()),
                FakeReply::Panic => panic!("intentional clean host adapter panic"),
            }
        }

        fn retire(&mut self) -> Result<(), AgentRouteWorkerError> {
            self.retired.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[test]
    fn inline_retirement_and_join_drain_an_admitted_operation() {
        let request = request(0x63, RuntimeExecutionContext::Direct);
        let identities = Arc::new(Mutex::new(vec![identity(&request)]));
        let lifetime = Arc::downgrade(&identities);
        let (started, observed) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let attachment = inline_backend(FakeBackend {
            identities,
            ready: Some(ReadyGate {
                started,
                release: wait,
            }),
            reply: FakeReply::RequestBoundError,
            invokes: Arc::new(AtomicUsize::new(0)),
            retired: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        let handle = attachment.handle();
        let operation_handle = handle.clone();
        let operation = std::thread::spawn(move || operation_handle.ready());
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (done, completion) = mpsc::sync_channel(1);
        let retiring = std::thread::spawn(move || {
            let result = attachment.retire();
            let _ = done.send(());
            result
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while handle.is_running() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        let closing = handle.state.load(Ordering::Acquire) == ROUTE_WORKER_CLOSING;
        let pending = completion.try_recv().is_err();
        let retained_during_operation = lifetime.upgrade().is_some();
        let join_handle = handle.clone();
        let joining = std::thread::spawn(move || Box::new(InlineHostOwner(join_handle)).join());
        release.send(()).unwrap();
        operation.join().unwrap().unwrap();
        retiring.join().unwrap().unwrap();
        joining.join().unwrap().unwrap();
        assert!(closing && pending && retained_during_operation);
        assert!(lifetime.upgrade().is_none());
        assert_eq!(handle.identities(), Err(AgentRouteError::Unavailable));
    }

    #[test]
    fn inline_retirement_releases_resources_after_retire_error_or_panic() {
        struct Backend {
            _resource: Arc<()>,
            mode: u8,
        }
        impl CleanAgentRouteBackend for Backend {
            fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
                Ok(Vec::new())
            }
            fn invoke(
                &mut self,
                _: AgentRouteIdentity,
                _: AgentInvocationRequest,
            ) -> Result<AgentInvocationResponse, AgentRouteError> {
                unreachable!()
            }
            fn retire(&mut self) -> Result<(), AgentRouteWorkerError> {
                match self.mode {
                    1 => Err(AgentRouteWorkerError::Failed),
                    2 => panic!("retirement failure"),
                    _ => Ok(()),
                }
            }
        }
        impl Drop for Backend {
            fn drop(&mut self) {
                if self.mode == 3 {
                    panic!("backend destructor failure");
                }
            }
        }
        for mode in 0..=4 {
            let resource = Arc::new(());
            let lifetime = Arc::downgrade(&resource);
            let attachment = inline_backend(Backend {
                _resource: resource,
                mode,
            })
            .unwrap();
            let handle = attachment.handle();
            if mode == 4 {
                let RouteHostTransport::Inline(slot) = &handle.transport else {
                    unreachable!()
                };
                let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                    let _guard = slot.lock().unwrap();
                    panic!("poison backend lock");
                }));
            }
            assert_eq!(attachment.retire().is_ok(), mode == 0);
            assert!(
                lifetime.upgrade().is_none(),
                "mode {mode} retained its resource"
            );
            assert!(!handle.is_running());
            assert_eq!(handle.identities(), Err(AgentRouteError::Unavailable));
            assert_eq!(handle.request_retire().is_ok(), mode == 0);
        }
    }

    #[test]
    fn inline_backend_retirement_closes_all_cloned_handles() {
        let request = request(0x61, RuntimeExecutionContext::Direct);
        let identity = identity(&request);
        let retired = Arc::new(AtomicBool::new(false));
        let invokes = Arc::new(AtomicUsize::new(0));
        let identities = Arc::new(Mutex::new(vec![identity]));
        let lifetime = Arc::downgrade(&identities);
        let attachment = inline_backend(FakeBackend {
            identities,
            ready: None,
            reply: FakeReply::RequestBoundError,
            invokes: invokes.clone(),
            retired: retired.clone(),
        })
        .unwrap();
        let handle = attachment.handle();
        let clone = handle.clone();
        assert!(
            handle
                .invoke(identity, request.clone())
                .unwrap()
                .matches_request(&request)
        );
        assert_eq!(invokes.load(Ordering::Acquire), 1);
        attachment.retire().unwrap();
        assert!(
            lifetime.upgrade().is_none(),
            "closed handles must not own the backend"
        );
        assert!(retired.load(Ordering::Acquire));
        assert!(!clone.is_running());
        assert_eq!(clone.identities(), Err(AgentRouteError::Unavailable));
        assert_eq!(
            clone.invoke(identity, request),
            Err(AgentRouteError::Unavailable)
        );
        assert_eq!(invokes.load(Ordering::Acquire), 1);
        clone.request_retire().unwrap();
    }

    #[test]
    fn inline_backend_panic_unpublishes_and_cannot_reuse_driver() {
        let request = request(0x62, RuntimeExecutionContext::Direct);
        let identity = identity(&request);
        let identities = Arc::new(Mutex::new(vec![identity]));
        let lifetime = Arc::downgrade(&identities);
        let attachment = inline_backend(FakeBackend {
            identities,
            ready: None,
            reply: FakeReply::Panic,
            invokes: Arc::new(AtomicUsize::new(0)),
            retired: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        let handle = attachment.handle();
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];
        assert!(dispatch_invocation(&owner.handle(), snapshot, request).is_err());
        assert!(!handle.is_running());
        assert!(lifetime.upgrade().is_none());
        assert_eq!(handle.identities(), Err(AgentRouteError::Unavailable));
        assert_eq!(
            owner.handle().snapshot(snapshot.key()),
            Err(AgentSupervisorError::NotFound)
        );
        owner.shutdown_and_join().unwrap();
    }

    fn fake_attachment(
        identity: AgentRouteIdentity,
        ready: Option<ReadyGate>,
        reply: FakeReply,
    ) -> (
        AgentRouteHostAttachment,
        Arc<Mutex<Vec<AgentRouteIdentity>>>,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
    ) {
        let identities = Arc::new(Mutex::new(vec![identity]));
        let invokes = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicBool::new(false));
        let attachment = spawn_backend(
            FakeBackend {
                identities: identities.clone(),
                ready,
                reply,
                invokes: invokes.clone(),
                retired: retired.clone(),
            },
            2,
            "vos-agent-adapter-test",
        )
        .unwrap();
        (attachment, identities, invokes, retired)
    }

    struct LifecycleBackend {
        identity: AgentRouteIdentity,
        invokes: Arc<AtomicUsize>,
        resumes: Arc<AtomicUsize>,
        acknowledgements: Arc<AtomicUsize>,
    }

    impl CleanAgentRouteBackend for LifecycleBackend {
        fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
            Ok(vec![self.identity])
        }

        fn invoke(
            &mut self,
            identity: AgentRouteIdentity,
            request: AgentInvocationRequest,
        ) -> Result<AgentInvocationResponse, AgentRouteError> {
            if identity != self.identity {
                return Err(AgentRouteError::NotReady);
            }
            self.invokes.fetch_add(1, Ordering::AcqRel);
            Ok(AgentInvocationResponse::direct(
                &request,
                RuntimeOutcome::Yielded(yielded(&request, 1)),
            ))
        }

        fn resume(
            &mut self,
            identity: AgentRouteIdentity,
            request: AgentResumeRequest,
        ) -> Result<AgentResumeResponse, AgentRouteError> {
            if identity != self.identity {
                return Err(AgentRouteError::NotReady);
            }
            self.resumes.fetch_add(1, Ordering::AcqRel);
            Ok(AgentResumeResponse::direct(
                &request,
                RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            ))
        }

        fn acknowledge(
            &mut self,
            identity: AgentRouteIdentity,
            request: AgentAcknowledgementRequest,
        ) -> Result<AgentAcknowledgementResponse, AgentRouteError> {
            if identity != self.identity {
                return Err(AgentRouteError::NotReady);
            }
            self.acknowledgements.fetch_add(1, Ordering::AcqRel);
            Ok(AgentAcknowledgementResponse::new(
                &request,
                RuntimeOutcome::Acknowledged(Ok(acknowledged(&request))),
            ))
        }
    }

    type LifecycleCounters = (Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>);

    fn lifecycle_attachment(
        identity: AgentRouteIdentity,
    ) -> (AgentRouteHostAttachment, LifecycleCounters) {
        let invokes = Arc::new(AtomicUsize::new(0));
        let resumes = Arc::new(AtomicUsize::new(0));
        let acknowledgements = Arc::new(AtomicUsize::new(0));
        let attachment = spawn_backend(
            LifecycleBackend {
                identity,
                invokes: Arc::clone(&invokes),
                resumes: Arc::clone(&resumes),
                acknowledgements: Arc::clone(&acknowledgements),
            },
            2,
            "vos-agent-lifecycle-test",
        )
        .unwrap();
        (attachment, (invokes, resumes, acknowledgements))
    }

    struct PreparingBackend {
        identities: Arc<Mutex<Vec<AgentRouteIdentity>>>,
        material: PhysicalInvocationMaterial,
        retired: Arc<AtomicBool>,
    }

    impl CleanAgentRouteBackend for PreparingBackend {
        fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
            self.identities
                .lock()
                .map(|identities| identities.clone())
                .map_err(|_| AgentRouteError::Unavailable)
        }

        fn invoke(
            &mut self,
            _identity: AgentRouteIdentity,
            _request: AgentInvocationRequest,
        ) -> Result<AgentInvocationResponse, AgentRouteError> {
            Err(AgentRouteError::Rejected)
        }

        fn prepare(
            &mut self,
            identity: AgentRouteIdentity,
        ) -> Result<PhysicalInvocationMaterial, AgentRouteError> {
            if !self
                .identities
                .lock()
                .map_err(|_| AgentRouteError::Unavailable)?
                .contains(&identity)
            {
                return Err(AgentRouteError::NotReady);
            }
            Ok(self.material.clone())
        }

        fn retire(&mut self) -> Result<(), AgentRouteWorkerError> {
            self.retired.store(true, Ordering::Release);
            Ok(())
        }
    }

    fn preparation_fixture(
        seed: u8,
    ) -> (
        PhysicalInvocationMaterial,
        AgentRouteIdentity,
        AgentInvocationIntent,
    ) {
        let program_bytes = vec![0x7f, seed, 0x51, 0x09];
        let program = ProgramId::of_pvm(&program_bytes);
        let schema = ParsedSchema {
            constructor: ConstructorContract::RequiredRaw(ConstructorArgument {
                name: "input".into(),
                type_identity: crate::agent::sdk::schema::RAW_CONSTRUCTOR_TYPE_IDENTITY.into(),
            }),
            fields: vec![ParsedField::Inline(ParsedInlineField {
                source_index: 0,
                name: "value".into(),
                type_identity: "core::primitive::u8".into(),
                persistence: FieldPersistence::State(StateLane::Linear),
            })],
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: MethodMode::Linear,
                explicit: true,
            }],
        };
        let schema_bytes = schema.encode().unwrap();
        let schema_reference = BlobRef::of_bytes(&schema_bytes);
        let policies = ActorMethodPolicyArtifact {
            actor_schema: schema_reference.clone(),
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
        let policy_reference = BlobRef::of_bytes(&policy_bytes);
        let space = SpaceId([seed; 32]);
        let owner = PrincipalId([seed.wrapping_add(1); 32]);
        let creation_nonce = Hash([seed.wrapping_add(2); 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let runtime_deployment = DeploymentId([seed.wrapping_add(3); 32]);
        let runtime_program = ProgramId([seed.wrapping_add(4); 32]);
        let public_key = [seed.wrapping_add(5); 32];
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment,
                runtime_program,
                runtime_producer: ProducerId::of_public_key(&public_key),
                transition_producer: ProducerId([seed.wrapping_add(0x40); 32]),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: Hash([seed.wrapping_add(6); 32]),
                issuer: AuthorityIssuer {
                    principal: PrincipalId([seed.wrapping_add(7); 32]),
                    actor: ActorId([seed.wrapping_add(8); 32]),
                    deployment: DeploymentId([seed.wrapping_add(9); 32]),
                    program: ProgramId([seed.wrapping_add(10); 32]),
                    producer: ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
            private_recovery: None,
            runtime_package: BlobRef::of_bytes(b"prepared-runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node: NodeId([seed.wrapping_add(11); 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        let actor = ActorId::top_level(agent, "prepared-counter");
        let deployment = DeploymentId([seed.wrapping_add(12); 32]);
        let installation_bytes = vec![seed, seed.wrapping_add(1)];
        let installation_reference = BlobRef::of_bytes(&installation_bytes);
        let entry = ActorEntry {
            actor,
            name: "prepared-counter".into(),
            parent: None,
            deployment,
            program,
            package: BlobRef::of_bytes(b"prepared-actor-package"),
            agent_schema: schema_reference.clone(),
            method_policy: policy_reference.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: Some(installation_reference.clone()),
            state_layout: schema.state_layout_hash().unwrap(),
            lanes: LaneSet::of(StateLane::Linear),
            suspended: false,
        };
        let record = ActorDirectoryRecord {
            entry,
            incarnation: Hash([seed.wrapping_add(13); 32]),
            installation_id: InstallationId([seed.wrapping_add(14); 32]),
            registry_reservation: Hash([seed.wrapping_add(15); 32]),
            install_request: Hash([seed.wrapping_add(17); 32]),
        };
        record.validate().unwrap();
        let material = PhysicalInvocationMaterial {
            descriptor,
            actor: record.clone(),
            install_request: Hash([seed.wrapping_add(17); 32]),
            producer: ProducerId::of_public_key(&public_key),
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(StateLane::Linear),
                ..RuntimeRequirements::default()
            },
            root_provenance: false,
            observed_slot: 73,
            program: RuntimeBlob {
                reference: BlobRef::of_bytes(&program_bytes),
                bytes: program_bytes,
            },
            schema: RuntimeBlob {
                reference: schema_reference,
                bytes: schema_bytes,
            },
            policies: RuntimeBlob {
                reference: policy_reference,
                bytes: policy_bytes,
            },
            installation_data: Some(RuntimeBlob {
                reference: installation_reference,
                bytes: installation_bytes,
            }),
        };
        let identity = AgentRouteIdentity::new(
            AgentRouteKey::new(space, agent, actor).unwrap(),
            record.incarnation,
            runtime_deployment,
            deployment,
            program,
            AgentProfile::Local,
        )
        .unwrap();
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("write").encode());
        let intent = AgentInvocationIntent::new(
            InvocationId([seed.wrapping_add(16); 32]),
            MethodMode::Linear,
            InvocationOrigin::anonymous(),
            InvocationRoleClaims::none(),
            message,
            10_000,
            false,
        )
        .unwrap();
        (material, identity, intent)
    }

    fn preparing_attachment(
        material: PhysicalInvocationMaterial,
        identity: AgentRouteIdentity,
    ) -> (
        AgentRouteHostAttachment,
        Arc<Mutex<Vec<AgentRouteIdentity>>>,
        Arc<AtomicBool>,
    ) {
        let identities = Arc::new(Mutex::new(vec![identity]));
        let retired = Arc::new(AtomicBool::new(false));
        let attachment = spawn_backend(
            PreparingBackend {
                identities: identities.clone(),
                material,
                retired: retired.clone(),
            },
            2,
            "vos-agent-preparation-test",
        )
        .unwrap();
        (attachment, identities, retired)
    }

    #[test]
    fn canonical_request_rejects_trailing_nested_legacy_and_attested_recovery_frames() {
        let direct_request = request(9, RuntimeExecutionContext::Direct);
        let encoded = direct_request.encode().unwrap();
        assert_eq!(
            AgentInvocationRequest::decode(&encoded).unwrap(),
            direct_request
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(AgentInvocationRequest::decode(&trailing).is_err());
        assert!(
            AgentInvocationRequest::decode(&direct_request.nested_work().encode().unwrap())
                .is_err()
        );

        let mut legacy = Vec::from(*b"VRIW");
        legacy.extend_from_slice(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        assert!(AgentInvocationRequest::decode(&legacy).is_err());

        let mut recovery = request(
            10,
            RuntimeExecutionContext::Attested {
                proof_system: Hash([11; 32]),
            },
        );
        recovery.work.recovery_only = true;
        recovery.authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&recovery.work, 17));
        assert!(!recovery.validate_wire());
        assert!(recovery.encode().is_err());
    }

    #[test]
    fn canonical_request_preserves_and_authenticates_exact_availability_preimages() {
        let mut with_availability = request(11, RuntimeExecutionContext::Direct);
        let bytes = b"canonical availability preimage".to_vec();
        with_availability.work.availability = vec![RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes: bytes.clone(),
        }];
        with_availability.authorization = InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(&with_availability.work, 17),
        );
        let with_availability = AgentInvocationRequest::new(
            with_availability.execution,
            with_availability.work,
            with_availability.authorization,
        )
        .unwrap();
        let decoded = AgentInvocationRequest::decode(&with_availability.encode().unwrap()).unwrap();
        assert_eq!(decoded, with_availability);
        assert_eq!(decoded.work.availability[0].bytes, bytes);

        let mut mismatched = decoded.work.clone();
        mismatched.availability[0].reference = BlobRef::of_bytes(b"different preimage");
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&mismatched, 17));
        assert!(AgentInvocationRequest::new(decoded.execution, mismatched, authorization).is_err());
    }

    #[test]
    fn resume_and_acknowledgement_frames_are_canonical_exact_and_hostile_decode_closed() {
        let invocation = request(0x21, RuntimeExecutionContext::Direct);
        let yielded = yielded(&invocation, 7);
        let resume = AgentResumeRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            invocation.work.clone(),
            invocation.authorization.clone(),
            yielded.clone(),
        )
        .unwrap();
        let encoded_resume = resume.encode().unwrap();
        assert_eq!(&encoded_resume[..4], b"ARQ3");
        assert_eq!(resume.execution(), RuntimeExecutionContext::Direct);
        assert_eq!(resume.expected_live(), None);
        assert_eq!(AgentResumeRequest::decode(&encoded_resume).unwrap(), resume);
        assert!(encoded_resume.len() <= AgentResumeRequest::MAX_ENCODED_BYTES);

        for magic in [b"ARQ1", b"ARQ2"] {
            let mut predecessor = encoded_resume.clone();
            predecessor[..4].copy_from_slice(magic);
            assert!(AgentResumeRequest::decode(&predecessor).is_err());
        }

        let mut trailing_resume = encoded_resume.clone();
        trailing_resume.push(0);
        assert!(AgentResumeRequest::decode(&trailing_resume).is_err());
        let live_key_tag = 4 + 32 + 4 + invocation.encode().unwrap().len();
        assert_eq!(encoded_resume[live_key_tag], 0);
        let mut invalid_resume_option = encoded_resume.clone();
        invalid_resume_option[live_key_tag] = 2;
        assert!(AgentResumeRequest::decode(&invalid_resume_option).is_err());
        assert!(
            AgentResumeRequest::decode(&vec![0; AgentResumeRequest::MAX_ENCODED_BYTES + 1])
                .is_err()
        );
        assert!(
            AgentResumeRequest::decode(&invocation.nested_work().encode().unwrap()).is_err(),
            "a nested RuntimeWork is not a supervisor Resume envelope"
        );
        let mut substituted_yield = yielded;
        substituted_yield.ready_sequence += 1;
        substituted_yield.actor = ActorId([0xa2; 32]);
        assert!(
            AgentResumeRequest::new(
                RuntimeExecutionContext::Direct,
                None,
                invocation.work.clone(),
                invocation.authorization.clone(),
                substituted_yield,
            )
            .is_err()
        );

        let acknowledgement = AgentAcknowledgementRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            invocation.work.clone(),
            invocation.authorization.clone(),
        )
        .unwrap();
        let encoded_acknowledgement = acknowledgement.encode().unwrap();
        assert_eq!(&encoded_acknowledgement[..4], b"AAQ3");
        assert_eq!(acknowledgement.execution(), RuntimeExecutionContext::Direct);
        assert_eq!(acknowledgement.expected_live(), None);
        assert_eq!(
            AgentAcknowledgementRequest::decode(&encoded_acknowledgement).unwrap(),
            acknowledgement
        );
        assert!(encoded_acknowledgement.len() <= AgentAcknowledgementRequest::MAX_ENCODED_BYTES);
        for magic in [b"AAQ1", b"AAQ2"] {
            let mut predecessor = encoded_acknowledgement.clone();
            predecessor[..4].copy_from_slice(magic);
            assert!(AgentAcknowledgementRequest::decode(&predecessor).is_err());
        }
        let mut trailing_acknowledgement = encoded_acknowledgement;
        trailing_acknowledgement.push(0);
        assert!(AgentAcknowledgementRequest::decode(&trailing_acknowledgement).is_err());
        let mut invalid_acknowledgement_option = acknowledgement.encode().unwrap();
        assert_eq!(invalid_acknowledgement_option[live_key_tag], 0);
        invalid_acknowledgement_option[live_key_tag] = 2;
        assert!(AgentAcknowledgementRequest::decode(&invalid_acknowledgement_option).is_err());
        assert!(
            AgentAcknowledgementRequest::decode(&vec![
                0;
                AgentAcknowledgementRequest::MAX_ENCODED_BYTES
                    + 1
            ])
            .is_err()
        );

        let stale_resume_response =
            AgentResumeResponse::direct(&resume, RuntimeOutcome::Yielded(resume.yielded().clone()));
        assert!(
            !stale_resume_response.matches_request(&resume),
            "a Resume response cannot replay the selector it was meant to consume"
        );
        let mut successor_yielded = resume.yielded().clone();
        successor_yielded.ready_sequence += 1;
        let resume_response =
            AgentResumeResponse::direct(&resume, RuntimeOutcome::Yielded(successor_yielded));
        assert_eq!(&resume_response.encode().unwrap()[..4], b"ARR3");
        assert_eq!(resume_response.proof_record(), None);
        assert_eq!(resume_response.transition_proof_key(), None);
        assert_eq!(
            AgentResumeResponse::decode(&resume_response.encode().unwrap()).unwrap(),
            resume_response
        );
        assert!(resume_response.matches_request(&resume));

        let mut substituted_closure = resume.yielded().clone();
        substituted_closure.ready_sequence += 1;
        substituted_closure.required = vec![BlobRef::of_bytes(b"unrequested-preimage")];
        let substituted_closure =
            AgentResumeResponse::direct(&resume, RuntimeOutcome::Yielded(substituted_closure));
        assert!(substituted_closure.encode().is_ok());
        assert!(
            !substituted_closure.matches_request(&resume),
            "a canonical response cannot substitute the accepted availability closure"
        );

        let excessive_gas = AgentInvocationResponse::direct(
            &invocation,
            RuntimeOutcome::Completed(Ok(super::super::sdk::InvocationReply {
                invocation: invocation.work.invocation,
                actor: invocation.work.actor,
                incarnation: invocation.work.incarnation,
                deployment: invocation.work.deployment,
                mode: invocation.work.mode,
                lane: invocation.work.mode.write_lane(),
                status: super::super::sdk::InvocationStatus::Done,
                reply: Vec::new(),
                gas_remaining: invocation.work.gas + 1,
                observation: super::super::sdk::InvocationObservation::default(),
            })),
        );
        assert!(excessive_gas.encode().is_ok());
        assert!(
            !excessive_gas.matches_request(&invocation),
            "a canonical response cannot mint gas beyond the exact request"
        );

        let acknowledgement_response = AgentAcknowledgementResponse::new(
            &acknowledgement,
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound)),
        );
        assert!(matches!(
            acknowledgement_response.outcome(),
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound))
        ));
        assert_eq!(&acknowledgement_response.encode().unwrap()[..4], b"AAR3");
        for magic in [b"AAR1", b"AAR2"] {
            let mut predecessor = acknowledgement_response.encode().unwrap();
            predecessor[..4].copy_from_slice(magic);
            assert!(AgentAcknowledgementResponse::decode(&predecessor).is_err());
        }
        assert_eq!(
            AgentAcknowledgementResponse::decode(&acknowledgement_response.encode().unwrap())
                .unwrap(),
            acknowledgement_response
        );
        assert!(acknowledgement_response.matches_request(&acknowledgement));

        let successful_acknowledgement = AgentAcknowledgementResponse::new(
            &acknowledgement,
            RuntimeOutcome::Acknowledged(Ok(acknowledged(&acknowledgement))),
        );
        assert!(successful_acknowledgement.matches_request(&acknowledgement));
    }

    #[test]
    fn attested_lifecycle_requests_preserve_context_and_bind_exact_live_proof_key() {
        let proof_system = Hash([0x41; 32]);
        let execution = RuntimeExecutionContext::Attested { proof_system };
        let invocation = request(0x42, execution);
        let expected_live = proof_key(&invocation, 0x43);
        let selected_yield = yielded(&invocation, 9);

        let resume = AgentResumeRequest::new(
            execution,
            Some(expected_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
            selected_yield.clone(),
        )
        .unwrap();
        let encoded_resume = resume.encode().unwrap();
        let decoded_resume = AgentResumeRequest::decode(&encoded_resume).unwrap();
        assert_eq!(decoded_resume, resume);
        assert_eq!(decoded_resume.execution(), execution);
        assert_eq!(decoded_resume.expected_live(), Some(expected_live));
        assert!(encoded_resume.len() <= AgentResumeRequest::MAX_ENCODED_BYTES);

        let acknowledgement = AgentAcknowledgementRequest::new(
            execution,
            Some(expected_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
        )
        .unwrap();
        let encoded_acknowledgement = acknowledgement.encode().unwrap();
        let decoded_acknowledgement =
            AgentAcknowledgementRequest::decode(&encoded_acknowledgement).unwrap();
        assert_eq!(decoded_acknowledgement, acknowledgement);
        assert_eq!(decoded_acknowledgement.execution(), execution);
        assert_eq!(decoded_acknowledgement.expected_live(), Some(expected_live));
        assert!(encoded_acknowledgement.len() <= AgentAcknowledgementRequest::MAX_ENCODED_BYTES);

        let missing_resume = AgentResumeRequest {
            invocation: invocation.clone(),
            expected_live: None,
            yielded: selected_yield.clone(),
        };
        assert!(!missing_resume.validate_wire());
        assert!(AgentResumeRequest::decode(&encode_unchecked(&missing_resume)).is_err());
        let missing_acknowledgement = AgentAcknowledgementRequest {
            invocation: invocation.clone(),
            expected_live: None,
        };
        assert!(!missing_acknowledgement.validate_wire());
        assert!(
            AgentAcknowledgementRequest::decode(&encode_unchecked(&missing_acknowledgement))
                .is_err()
        );

        let direct = request(0x42, RuntimeExecutionContext::Direct);
        let direct_with_proof = AgentResumeRequest {
            invocation: direct.clone(),
            expected_live: Some(expected_live),
            yielded: yielded(&direct, 9),
        };
        assert!(!direct_with_proof.validate_wire());
        assert!(AgentResumeRequest::decode(&encode_unchecked(&direct_with_proof)).is_err());
        let direct_ack_with_proof = AgentAcknowledgementRequest {
            invocation: direct,
            expected_live: Some(expected_live),
        };
        assert!(!direct_ack_with_proof.validate_wire());
        assert!(
            AgentAcknowledgementRequest::decode(&encode_unchecked(&direct_ack_with_proof)).is_err()
        );

        let wrong_invocation = TransitionProofKey {
            invocation: InvocationId([0x44; 32]),
            execution: expected_live.execution,
        };
        let wrong_resume = AgentResumeRequest {
            invocation: invocation.clone(),
            expected_live: Some(wrong_invocation),
            yielded: selected_yield,
        };
        assert!(!wrong_resume.validate_wire());
        assert!(AgentResumeRequest::decode(&encode_unchecked(&wrong_resume)).is_err());
        let wrong_acknowledgement = AgentAcknowledgementRequest {
            invocation: invocation.clone(),
            expected_live: Some(wrong_invocation),
        };
        assert!(!wrong_acknowledgement.validate_wire());
        assert!(
            AgentAcknowledgementRequest::decode(&encode_unchecked(&wrong_acknowledgement)).is_err()
        );
        let zero_work_key = AgentAcknowledgementRequest {
            invocation: invocation.clone(),
            expected_live: Some(TransitionProofKey {
                invocation: invocation.work().invocation,
                execution: Hash::ZERO,
            }),
        };
        assert!(!zero_work_key.validate_wire());
        assert!(AgentAcknowledgementRequest::decode(&encode_unchecked(&zero_work_key)).is_err());

        // A different slice of the same invocation is structurally valid;
        // the journal compares it to its durable expected-live key. The
        // canonical request commitment prevents substituting it in transit.
        let substituted_live = proof_key(&invocation, 0x45);
        let substituted_acknowledgement = AgentAcknowledgementRequest::new(
            execution,
            Some(substituted_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
        )
        .unwrap();
        assert_ne!(
            acknowledgement.commitment(),
            substituted_acknowledgement.commitment()
        );
        let response = AgentAcknowledgementResponse::new(
            &acknowledgement,
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound)),
        );
        assert!(
            !response.matches_request(&acknowledgement),
            "request binding alone cannot authorize Attested retirement"
        );
        assert!(!response.matches_request(&substituted_acknowledgement));
    }

    #[test]
    fn encoded_lifecycle_requests_retry_without_repreparation_and_survive_route_restart() {
        let invocation = request(0x22, RuntimeExecutionContext::Direct);
        let route_identity = identity(&invocation);
        let invocation_bytes = invocation.encode().unwrap();
        let resume = AgentResumeRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            invocation.work.clone(),
            invocation.authorization.clone(),
            yielded(&invocation, 1),
        )
        .unwrap();
        let resume_bytes = resume.encode().unwrap();
        let acknowledgement = AgentAcknowledgementRequest::new(
            RuntimeExecutionContext::Direct,
            None,
            invocation.work.clone(),
            invocation.authorization.clone(),
        )
        .unwrap();
        let acknowledgement_bytes = acknowledgement.encode().unwrap();

        let (attachment, counters) = lifecycle_attachment(route_identity);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];
        for _ in 0..2 {
            let response =
                dispatch_encoded_invocation(&owner.handle(), snapshot, &invocation_bytes).unwrap();
            assert!(matches!(response.outcome(), RuntimeOutcome::Yielded(_)));
            let response =
                dispatch_encoded_resume(&owner.handle(), snapshot, &resume_bytes).unwrap();
            assert!(matches!(
                response.outcome(),
                RuntimeOutcome::Completed(Err(InvocationError::NotFound))
            ));
            let response =
                dispatch_encoded_acknowledgement(&owner.handle(), snapshot, &acknowledgement_bytes)
                    .unwrap();
            assert!(matches!(
                response.outcome(),
                RuntimeOutcome::Acknowledged(Ok(result))
                    if result.work == invocation.work.commitment()
                        && result.authorization == invocation.authorization.commitment()
            ));
        }
        assert_eq!(counters.0.load(Ordering::Acquire), 2);
        assert_eq!(counters.1.load(Ordering::Acquire), 2);
        assert_eq!(counters.2.load(Ordering::Acquire), 2);
        owner.shutdown_and_join().unwrap();

        let (reopened_attachment, reopened_counters) = lifecycle_attachment(route_identity);
        let mut reopened = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = reopened.attach(reopened_attachment.into_parts().0).unwrap();
        let reopened_snapshot = publication.snapshots()[0];
        let response = dispatch_encoded_acknowledgement(
            &reopened.handle(),
            reopened_snapshot,
            &acknowledgement_bytes,
        )
        .unwrap();
        assert!(matches!(
            response.outcome(),
            RuntimeOutcome::Acknowledged(Ok(result))
                if result.work == invocation.work.commitment()
                    && result.authorization == invocation.authorization.commitment()
        ));
        assert_eq!(reopened_counters.2.load(Ordering::Acquire), 1);
        assert_eq!(reopened_counters.0.load(Ordering::Acquire), 0);
        assert_eq!(reopened_counters.1.load(Ordering::Acquire), 0);
        reopened.shutdown_and_join().unwrap();
    }

    #[test]
    fn preparation_returns_only_physical_closure_and_stable_admission_inputs() {
        let (material, identity, intent) = preparation_fixture(0x31);
        let expected_material = material.clone();
        let (attachment, _, retired) = preparing_attachment(material, identity);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];

        let prepared = prepare_invocation(&owner.handle(), snapshot, intent.clone()).unwrap();
        let targeted =
            AgentTargetedPreparationRequest::new(snapshot.key(), intent.clone()).unwrap();
        let encoded_target = targeted.encode().unwrap();
        assert_eq!(
            AgentTargetedPreparationRequest::decode(&encoded_target).unwrap(),
            targeted
        );
        let mut trailing = encoded_target.clone();
        trailing.push(0);
        assert!(AgentTargetedPreparationRequest::decode(&trailing).is_err());
        assert!(AgentPreparationRequest::decode(&encoded_target).is_err());
        let remote = prepare_targeted_invocation(&owner.handle(), &targeted).unwrap();
        let encoded_remote = remote.encode().unwrap();
        let remote = AgentTargetedPreparationResponse::decode(&encoded_remote).unwrap();
        assert_eq!(remote.for_request(&targeted), Some(&prepared));
        let mut trailing = encoded_remote;
        trailing.push(0);
        assert!(AgentTargetedPreparationResponse::decode(&trailing).is_err());
        let mut changed = targeted.clone();
        changed.intent.gas += 1;
        assert!(remote.for_request(&changed).is_none());
        let mut forged = remote.clone();
        forged.request = changed.commitment();
        assert!(
            forged.for_request(&changed).is_none(),
            "echo alone cannot bind substituted work"
        );
        changed = targeted.clone();
        changed.target = AgentRouteKey::new(
            SpaceId([0x88; 32]),
            changed.target.agent(),
            changed.target.actor(),
        )
        .unwrap();
        assert!(remote.for_request(&changed).is_none());
        assert!(prepare_targeted_invocation(&owner.handle(), &changed).is_err());
        assert_eq!(prepared.profile(), AgentProfile::Local);
        assert_eq!(
            prepared.runtime_program(),
            expected_material.descriptor.identity.runtime_program
        );
        assert_eq!(
            prepared.runtime_package(),
            &expected_material.descriptor.runtime_package
        );
        assert_eq!(prepared.observed_slot(), expected_material.observed_slot);
        assert_eq!(prepared.work().space, snapshot.key().space());
        assert_eq!(prepared.work().agent, snapshot.key().agent());
        assert_eq!(prepared.work().actor, snapshot.key().actor());
        assert_eq!(prepared.work().incarnation, snapshot.incarnation());
        assert_eq!(
            prepared.work().runtime_deployment,
            snapshot.runtime_deployment()
        );
        assert_eq!(prepared.work().deployment, snapshot.actor_deployment());
        assert_eq!(prepared.work().program, snapshot.actor_program());
        assert_eq!(prepared.work().availability.len(), 4);
        assert!(
            prepared
                .work()
                .availability
                .iter()
                .any(|blob| blob == &expected_material.program)
        );
        assert!(
            prepared
                .work()
                .availability
                .iter()
                .any(|blob| blob == &expected_material.schema)
        );
        assert!(
            prepared
                .work()
                .availability
                .iter()
                .any(|blob| blob == &expected_material.policies)
        );
        assert!(prepared.work().availability.iter().any(|blob| {
            expected_material
                .installation_data
                .as_ref()
                .is_some_and(|expected| blob == expected)
        }));
        assert_eq!(
            prepared.work().installation_data,
            expected_material
                .installation_data
                .as_ref()
                .map(|blob| blob.reference.clone())
        );
        assert_eq!(prepared.selected_method().name, "write");
        let preflight = prepared.public_preflight().unwrap();
        assert!(preflight.matches(prepared.work(), prepared.observed_slot()));

        let response = AgentPreparationResponse {
            prepared: prepared.clone(),
        };
        let encoded = response.encode().unwrap();
        assert_eq!(
            AgentPreparationResponse::decode(&encoded).unwrap(),
            response
        );
        let request = AgentPreparationRequest::new(snapshot, intent).unwrap();
        assert_eq!(prepared.request_commitment(), request.commitment());
        assert!(prepared_matches_request(&prepared, snapshot, &request));
        assert!(!retired.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
        assert!(retired.load(Ordering::Acquire));
    }

    #[test]
    fn physical_dispatch_rechecks_exact_public_policy_attestation_and_availability() {
        let (material, identity, intent) = preparation_fixture(0x35);
        let preparation = AgentPreparationRequest {
            expected: identity,
            readiness_generation: 1,
            intent,
        };
        let prepared = prepare_from_physical_material(&preparation, material.clone()).unwrap();
        let work = prepared.work().clone();
        let authorization = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
            &work,
            material.observed_slot,
        ));
        assert!(physical_material_authorizes_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            &work,
            &authorization,
        ));
        assert!(!physical_material_authorizes_work(
            &material,
            identity,
            RuntimeExecutionContext::Attested {
                proof_system: Hash([0x37; 32]),
            },
            &work,
            &authorization,
        ));

        let rebind_availability =
            |work: &mut InvocationWork, material: &PhysicalInvocationMaterial| {
                work.installation_data = material.actor.entry.installation_data.clone();
                work.availability = vec![
                    material.program.clone(),
                    material.schema.clone(),
                    material.policies.clone(),
                ];
                work.availability.extend(material.installation_data.clone());
                work.availability
                    .sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
            };

        let mut capability_material = material.clone();
        let mut capability_policies =
            ActorMethodPolicyArtifact::decode(&capability_material.policies.bytes).unwrap();
        capability_policies.methods[0].authorization_policy =
            AuthorizationPolicySelector::Capability(CapabilityId([0x36; 32]));
        let capability_bytes = capability_policies.encode().unwrap();
        capability_material.policies = RuntimeBlob {
            reference: BlobRef::of_bytes(&capability_bytes),
            bytes: capability_bytes,
        };
        capability_material.actor.entry.method_policy =
            capability_material.policies.reference.clone();
        let mut capability_work = work.clone();
        rebind_availability(&mut capability_work, &capability_material);
        let forged_public = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
            &capability_work,
            capability_material.observed_slot,
        ));
        assert!(forged_public.matches_work(&capability_work));
        assert!(!physical_material_authorizes_work(
            &capability_material,
            identity,
            RuntimeExecutionContext::Direct,
            &capability_work,
            &forged_public,
        ));

        let mut attested_material = material.clone();
        let mut attested_policies =
            ActorMethodPolicyArtifact::decode(&attested_material.policies.bytes).unwrap();
        attested_policies.methods[0].attestation = AttestationRequirement::Required {
            proof_system: Hash([0x37; 32]),
        };
        let attested_bytes = attested_policies.encode().unwrap();
        attested_material.policies = RuntimeBlob {
            reference: BlobRef::of_bytes(&attested_bytes),
            bytes: attested_bytes,
        };
        attested_material.actor.entry.method_policy = attested_material.policies.reference.clone();
        let mut direct_work = work.clone();
        rebind_availability(&mut direct_work, &attested_material);
        let direct_authorization = InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(&direct_work, attested_material.observed_slot),
        );
        assert!(!physical_material_authorizes_work(
            &attested_material,
            identity,
            RuntimeExecutionContext::Direct,
            &direct_work,
            &direct_authorization,
        ));
        assert!(physical_material_authorizes_work(
            &attested_material,
            identity,
            RuntimeExecutionContext::Attested {
                proof_system: Hash([0x37; 32]),
            },
            &direct_work,
            &direct_authorization,
        ));
        assert!(!physical_material_authorizes_work(
            &attested_material,
            identity,
            RuntimeExecutionContext::Attested {
                proof_system: Hash([0x38; 32]),
            },
            &direct_work,
            &direct_authorization,
        ));

        let mut substituted = work;
        substituted.availability[0].bytes.push(0xff);
        let substituted_authorization = InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(&substituted, material.observed_slot),
        );
        assert!(!physical_material_authorizes_work(
            &material,
            identity,
            RuntimeExecutionContext::Direct,
            &substituted,
            &substituted_authorization,
        ));
    }

    #[test]
    fn preparation_substituted_or_missing_physical_artifact_fails_closed() {
        for missing in [false, true] {
            let (mut material, identity, intent) =
                preparation_fixture(if missing { 0x33 } else { 0x32 });
            if missing {
                material.policies.bytes.clear();
            } else {
                material.policies.bytes[0] ^= 0x80;
            }
            let (attachment, _, retired) = preparing_attachment(material, identity);
            let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
            let publication = owner.attach(attachment.into_parts().0).unwrap();
            let snapshot = publication.snapshots()[0];
            assert_eq!(
                prepare_invocation(&owner.handle(), snapshot, intent),
                Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
            );
            assert_eq!(
                owner.handle().snapshot(snapshot.key()),
                Err(AgentSupervisorError::NotFound)
            );
            assert!(retired.load(Ordering::Acquire));
            owner.shutdown_and_join().unwrap();
        }
    }

    #[test]
    fn preparation_rejects_stale_physical_projection_and_retires_attachment() {
        let (material, identity, intent) = preparation_fixture(0x34);
        let (attachment, identities, retired) = preparing_attachment(material, identity);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];
        let replacement = AgentRouteIdentity::new(
            identity.key(),
            Hash([0xf1; 32]),
            identity.runtime_deployment(),
            identity.actor_deployment(),
            identity.actor_program(),
            identity.profile(),
        )
        .unwrap();
        *identities.lock().unwrap() = vec![replacement];

        assert_eq!(
            prepare_invocation(&owner.handle(), snapshot, intent),
            Err(AgentSupervisorError::Route(AgentRouteError::NotReady))
        );
        assert_eq!(
            owner.handle().snapshot(snapshot.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(retired.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn physical_local_shared_and_system_provenance_is_exact() {
        use crate::agent::invocation_preparation::PhysicalRootLineage;

        let (local, _, _) = preparation_fixture(0x39);
        for (profile, root_provenance) in [
            (AgentProfile::Local, false),
            (AgentProfile::Shared, false),
            (AgentProfile::Shared, true),
        ] {
            let mut material = local.clone();
            material.descriptor.identity.profile = profile;
            material.root_provenance = root_provenance;
            material.descriptor.validate().unwrap();
            let descriptor = material.descriptor.clone();
            let authority = AuthorityActorProjection {
                agent: descriptor.identity.agent,
                entry: material.actor.entry.clone(),
                producer: material.producer,
                contract: material.contract,
                requirements: material.requirements,
                root_provenance,
                installation_id: material.actor.installation_id,
                registry_reservation: material.actor.registry_reservation,
                install_request: material.install_request,
            };
            assert!(physical_material_matches_authority(
                &material,
                &descriptor,
                &authority
            ));

            let mut changed = authority.clone();
            changed.install_request = Hash([0xe1; 32]);
            assert!(!physical_material_matches_authority(
                &material,
                &descriptor,
                &changed
            ));
            let mut changed = authority.clone();
            changed.registry_reservation = Hash([0xe2; 32]);
            assert!(!physical_material_matches_authority(
                &material,
                &descriptor,
                &changed
            ));
            let mut changed = authority.clone();
            changed.producer = ProducerId([0xe3; 32]);
            assert!(!physical_material_matches_authority(
                &material,
                &descriptor,
                &changed
            ));
            let mut changed = authority.clone();
            changed.root_provenance = !root_provenance;
            assert!(!physical_material_matches_authority(
                &material,
                &descriptor,
                &changed
            ));
            let mut changed = material.clone();
            changed.program.bytes.push(0);
            assert!(!physical_material_matches_authority(
                &changed,
                &descriptor,
                &authority
            ));
            let mut changed = material.clone();
            changed.actor.installation_id = InstallationId([0xe4; 32]);
            assert!(!physical_material_matches_authority(
                &changed,
                &descriptor,
                &authority
            ));

            if root_provenance {
                let lineage = PhysicalRootLineage {
                    agent: authority.agent,
                    actor: authority.entry.actor,
                    installation_id: authority.installation_id,
                    registry_reservation: authority.registry_reservation,
                    install_request: authority.install_request,
                };
                assert!(lineage.matches(&authority));
                let mut upgraded = authority.clone();
                upgraded.entry.deployment = DeploymentId([0xe5; 32]);
                upgraded.entry.program = ProgramId([0xe6; 32]);
                upgraded.entry.package = BlobRef::of_bytes(b"upgraded-root-package");
                assert!(
                    lineage.matches(&upgraded),
                    "mutable root catalog facts must not replace bootstrap lineage"
                );
                upgraded.installation_id = InstallationId([0xe7; 32]);
                assert!(!lineage.matches(&upgraded));
            }
        }
    }

    #[test]
    fn preparation_same_identity_detach_reattach_rejects_aba_snapshot() {
        let (material, identity, intent) = preparation_fixture(0x35);
        let (first, _, first_retired) = preparing_attachment(material.clone(), identity);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let first_publication = owner.attach(first.into_parts().0).unwrap();
        let old = first_publication.snapshots()[0];
        let first_prepared = prepare_invocation(&owner.handle(), old, intent.clone()).unwrap();
        owner.detach(&first_publication).unwrap();
        assert!(first_retired.load(Ordering::Acquire));

        let (second, _, second_retired) = preparing_attachment(material, identity);
        let second_publication = owner.attach(second.into_parts().0).unwrap();
        let current = second_publication.snapshots()[0];
        assert_ne!(old.readiness_generation(), current.readiness_generation());
        assert_eq!(
            prepare_invocation(&owner.handle(), old, intent.clone()),
            Err(AgentSupervisorError::StaleSnapshot)
        );
        let second_prepared = prepare_invocation(&owner.handle(), current, intent).unwrap();
        assert_eq!(first_prepared.work(), second_prepared.work());
        assert_ne!(
            first_prepared.request_commitment(),
            second_prepared.request_commitment()
        );
        owner.shutdown_and_join().unwrap();
        assert!(second_retired.load(Ordering::Acquire));
    }

    #[test]
    fn preparation_frames_are_bounded_and_private_plaintext_is_rejected() {
        let (material, identity, intent) = preparation_fixture(0x36);
        let wrong_mode = AgentInvocationIntent::new(
            intent.invocation(),
            MethodMode::Query,
            intent.origin(),
            intent.roles(),
            intent.message().to_vec(),
            intent.gas(),
            intent.recovery_only(),
        )
        .unwrap();
        let (attachment, _, _) = preparing_attachment(material, identity);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];
        assert_eq!(
            prepare_invocation(&owner.handle(), snapshot, wrong_mode),
            Err(AgentSupervisorError::Route(AgentRouteError::Rejected))
        );
        let maximum = AgentInvocationIntent::new(
            InvocationId([0x37; 32]),
            MethodMode::Linear,
            InvocationOrigin::anonymous(),
            InvocationRoleClaims::none(),
            vec![0; MAX_INVOCATION_MESSAGE_BYTES],
            1,
            false,
        )
        .unwrap();
        let maximum_frame = AgentPreparationRequest::new(snapshot, maximum)
            .unwrap()
            .encode()
            .unwrap();
        assert!(maximum_frame.len() <= AgentPreparationRequest::MAX_ENCODED_BYTES);
        owner.shutdown_and_join().unwrap();

        let mut private_identity = identity;
        private_identity = AgentRouteIdentity::new(
            private_identity.key(),
            private_identity.incarnation(),
            private_identity.runtime_deployment(),
            private_identity.actor_deployment(),
            private_identity.actor_program(),
            AgentProfile::Private,
        )
        .unwrap();
        let (attachment, _, _, _) =
            fake_attachment(private_identity, None, FakeReply::RequestBoundError);
        let mut private_owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = private_owner.attach(attachment.into_parts().0).unwrap();
        let snapshot = publication.snapshots()[0];
        assert_eq!(
            prepare_invocation(&private_owner.handle(), snapshot, intent),
            Err(AgentSupervisorError::Route(AgentRouteError::Rejected))
        );

        let resume = RuntimeWork::Resume {
            context: RuntimeExecutionContext::Direct,
            state: RuntimeState::default(),
            resume: Box::new(crate::agent::sdk::ResumeWork {
                invocation: InvocationId([0x38; 32]),
                actor: identity.key().actor(),
                incarnation: identity.incarnation(),
                deployment: identity.actor_deployment(),
                program: identity.actor_program(),
                mode: MethodMode::Linear,
                continuation: BlobRef::of_bytes(b"durable-yielded-continuation"),
                ready_sequence: 1,
                installation_data: None,
                availability: Vec::new(),
                input: None,
            }),
        };
        assert!(resume.encode().is_ok());
        assert!(AgentPreparationRequest::decode(&resume.encode().unwrap()).is_err());

        let oversized = AgentInvocationIntent::new(
            InvocationId([0x39; 32]),
            MethodMode::Linear,
            InvocationOrigin::anonymous(),
            InvocationRoleClaims::none(),
            vec![0; MAX_INVOCATION_MESSAGE_BYTES + 1],
            1,
            false,
        );
        assert_eq!(oversized, Err(WireError::InvalidValue));
        private_owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn direct_response_binds_identity_free_error_to_exact_request() {
        let first = request(12, RuntimeExecutionContext::Direct);
        let second = request(13, RuntimeExecutionContext::Direct);
        let response = AgentInvocationResponse::direct(
            &first,
            RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        );
        let encoded = response.encode().unwrap();
        assert_eq!(AgentInvocationResponse::decode(&encoded).unwrap(), response);
        assert!(response.matches_request(&first));
        assert!(!response.matches_request(&second));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(AgentInvocationResponse::decode(&trailing).is_err());
        let mut legacy = Vec::from(*b"VARW");
        legacy.extend_from_slice(crate::agent::sdk::RUNTIME_ABI_ID.as_bytes());
        assert!(AgentInvocationResponse::decode(&legacy).is_err());
    }

    fn proof_record(request: &AgentInvocationRequest, proof: &[u8]) -> TransitionProofRecord {
        let proof_system = match request.execution {
            RuntimeExecutionContext::Attested { proof_system } => proof_system,
            RuntimeExecutionContext::Direct => panic!("attested fixture required"),
        };
        let public_key = [9; 32];
        let lanes = ProofLaneRoots {
            control: Hash([21; 32]),
            linear: None,
            merge: None,
            local: None,
        };
        TransitionProofRecord {
            statement: TransitionProofStatement {
                subject: TransitionProofSubject {
                    space: request.work.space,
                    agent: request.work.agent,
                    runtime_deployment: request.work.runtime_deployment,
                    runtime_program: ProgramId([22; 32]),
                    runtime_package: BlobRef::of_bytes(b"runtime-package"),
                    actor: request.work.actor,
                    incarnation: request.work.incarnation,
                    actor_deployment: request.work.deployment,
                    actor_program: request.work.program,
                    invocation: request.work.invocation,
                    method: "read".into(),
                    mode: request.work.mode,
                },
                before: lanes,
                after: ProofLaneRoots {
                    control: Hash([23; 32]),
                    ..lanes
                },
                work: Hash([24; 32]),
                transition: Hash([25; 32]),
                refine_trace: Hash([26; 32]),
                public_io: Hash([27; 32]),
                proof_system,
            },
            proof: BlobRef::of_bytes(proof),
            producer: ProducerId::of_public_key(&public_key),
            producer_public_key: public_key,
            producer_signature: [8; PROOF_SIGNATURE_BYTES],
        }
    }

    fn proof_manifest(material: &[u8]) -> Vec<u8> {
        TransitionProofMaterialManifest::for_material(material)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn attested_transport_is_structural_only_without_exact_verifier_admission() {
        let request = request(
            14,
            RuntimeExecutionContext::Attested {
                proof_system: Hash([15; 32]),
            },
        );
        let proof = proof_manifest(b"public-proof");
        let record = proof_record(&request, &proof);
        let response = AgentInvocationResponse::Attested {
            request: request.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: record.clone(),
            proof: AgentTransitionProofDelivery::Inline(proof),
        };
        assert!(response.validate_wire());
        assert!(
            !response.matches_request(&request),
            "canonical shape is not a producer signature, exact proof, or root verification"
        );
        let encoded = response.encode().unwrap();
        assert_eq!(AgentInvocationResponse::decode(&encoded).unwrap(), response);

        let malformed_manifest = b"not-a-canonical-apm1-manifest".to_vec();
        let malformed_record = proof_record(&request, &malformed_manifest);
        let malformed = AgentInvocationResponse::Attested {
            request: request.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: malformed_record,
            proof: AgentTransitionProofDelivery::Inline(malformed_manifest),
        };
        assert!(!malformed.validate_wire());
        assert!(AgentInvocationResponse::decode(&encode_unchecked(&malformed)).is_err());

        let oversized = AgentInvocationResponse::Attested {
            request: request.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: record.clone(),
            proof: AgentTransitionProofDelivery::Inline(vec![
                0x5a;
                MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES
                    + 1
            ]),
        };
        let oversized = encode_unchecked(&oversized);
        assert!(oversized.len() <= AgentInvocationResponse::MAX_ENCODED_BYTES);
        assert!(AgentInvocationResponse::decode(&oversized).is_err());

        let reference = AgentInvocationResponse::Attested {
            request: request.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            proof: AgentTransitionProofDelivery::Reference(record.proof.clone()),
            record,
        };
        assert_eq!(
            AgentInvocationResponse::decode(&reference.encode().unwrap()).unwrap(),
            reference
        );
        assert!(!reference.matches_request(&request));
    }

    #[test]
    fn attested_resume_response_replaces_exact_live_key_and_rejects_substitution() {
        let proof_system = Hash([0x51; 32]);
        let execution = RuntimeExecutionContext::Attested { proof_system };
        let invocation = request(0x52, execution);
        let expected_live = proof_key(&invocation, 0x53);
        let resume = AgentResumeRequest::new(
            execution,
            Some(expected_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
            yielded(&invocation, 3),
        )
        .unwrap();
        let proof = proof_manifest(b"public-resume-proof");
        let record = proof_record(&invocation, &proof);
        assert_ne!(record.statement.key(), expected_live);
        let response = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: record.clone(),
            proof: AgentTransitionProofDelivery::Inline(proof),
        };
        assert!(response.validate_wire());
        assert!(
            !response.matches_request(&resume),
            "a merely different same-invocation proof key is not an authenticated successor"
        );
        assert_eq!(response.proof_record(), Some(&record));
        assert_eq!(
            response.transition_proof_key(),
            Some(record.statement.key())
        );
        let encoded = response.encode().unwrap();
        assert_eq!(&encoded[..4], b"ARR3");
        assert_eq!(AgentResumeResponse::decode(&encoded).unwrap(), response);
        assert!(encoded.len() <= AgentResumeResponse::MAX_ENCODED_BYTES);

        let oversized = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: record.clone(),
            proof: AgentTransitionProofDelivery::Inline(vec![
                0x5b;
                MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES
                    + 1
            ]),
        };
        let oversized = encode_unchecked(&oversized);
        assert!(oversized.len() <= AgentResumeResponse::MAX_ENCODED_BYTES);
        assert!(AgentResumeResponse::decode(&oversized).is_err());

        let reference = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: record.clone(),
            proof: AgentTransitionProofDelivery::Reference(record.proof.clone()),
        };
        assert!(!reference.matches_request(&resume));
        assert_eq!(
            AgentResumeResponse::decode(&reference.encode().unwrap()).unwrap(),
            reference
        );

        let direct_response = AgentResumeResponse::direct(
            &resume,
            RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        );
        assert!(direct_response.validate_wire());
        assert!(!direct_response.matches_request(&resume));

        let substituted_live = proof_key(&invocation, 0x54);
        let substituted_request = AgentResumeRequest::new(
            execution,
            Some(substituted_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
            yielded(&invocation, 3),
        )
        .unwrap();
        assert_ne!(resume.commitment(), substituted_request.commitment());
        assert!(!response.matches_request(&substituted_request));

        let mut stale_record = record.clone();
        stale_record.statement.work = expected_live.execution;
        let stale = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: stale_record,
            proof: AgentTransitionProofDelivery::Reference(record.proof.clone()),
        };
        assert!(stale.validate_wire());
        assert!(!stale.matches_request(&resume));

        let mut wrong_system_record = record.clone();
        wrong_system_record.statement.proof_system = Hash([0x55; 32]);
        let wrong_system = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: wrong_system_record,
            proof: AgentTransitionProofDelivery::Reference(record.proof.clone()),
        };
        assert!(wrong_system.validate_wire());
        assert!(!wrong_system.matches_request(&resume));

        let mut wrong_subject_record = record.clone();
        wrong_subject_record.statement.subject.invocation = InvocationId([0x56; 32]);
        let wrong_subject = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: wrong_subject_record,
            proof: AgentTransitionProofDelivery::Reference(record.proof.clone()),
        };
        assert!(wrong_subject.validate_wire());
        assert!(!wrong_subject.matches_request(&resume));

        let substituted_proof = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record,
            proof: AgentTransitionProofDelivery::Inline(b"substituted-proof".to_vec()),
        };
        assert!(!substituted_proof.validate_wire());
        assert!(substituted_proof.encode().is_err());

        for magic in [b"ARR1", b"ARR2"] {
            let mut predecessor = encoded.clone();
            predecessor[..4].copy_from_slice(magic);
            assert!(AgentResumeResponse::decode(&predecessor).is_err());
        }
    }

    #[test]
    fn concrete_adapter_publishes_only_after_readiness_and_rejects_legacy_without_dispatch() {
        let request = request(30, RuntimeExecutionContext::Direct);
        let identity = identity(&request);
        let (started, waiting) = mpsc::sync_channel(0);
        let (release, released) = mpsc::sync_channel(0);
        let (attachment, _, invokes, retired) = fake_attachment(
            identity,
            Some(ReadyGate {
                started,
                release: released,
            }),
            FakeReply::RequestBoundError,
        );
        let (attachment, route_host) = attachment.into_parts();
        let owner = AgentSupervisorOwner::start(limits()).unwrap();
        let handle = owner.handle();
        let attach = thread::spawn(move || {
            let mut owner = owner;
            let result = owner.attach(attachment);
            (owner, result)
        });
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            handle.snapshot(identity.key()),
            Err(AgentSupervisorError::NotFound)
        );
        release.send(()).unwrap();
        let (owner, publication) = attach.join().unwrap();
        let snapshot = publication.unwrap().snapshots()[0];

        for rejected in [
            Vec::from(*b"VRIW"),
            request.nested_work().encode().unwrap(),
            {
                let mut bytes = request.encode().unwrap();
                bytes.push(0);
                bytes
            },
        ] {
            assert_eq!(
                handle.dispatch(snapshot, rejected),
                Err(AgentSupervisorError::Route(AgentRouteError::Rejected))
            );
            assert_eq!(handle.snapshot(identity.key()).unwrap(), snapshot);
        }
        assert_eq!(invokes.load(Ordering::Acquire), 0);
        let response = dispatch_invocation(&handle, snapshot, request).unwrap();
        assert!(matches!(
            response,
            AgentInvocationResponse::Direct {
                outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
                ..
            }
        ));
        assert_eq!(invokes.load(Ordering::Acquire), 1);
        owner.shutdown_and_join().unwrap();
        assert!(retired.load(Ordering::Acquire));
        assert!(!route_host.is_running());
    }

    #[test]
    fn concrete_host_fanout_is_bounded_and_reports_backpressure() {
        let request = request(0x2f, RuntimeExecutionContext::Direct);
        let identity = identity(&request);
        let (started, waiting) = mpsc::sync_channel(0);
        let (release, released) = mpsc::sync_channel(0);
        let (attachment, _, _, retired) = fake_attachment(
            identity,
            Some(ReadyGate {
                started,
                release: released,
            }),
            FakeReply::RequestBoundError,
        );
        let route_host = attachment.handle();
        let blocked_host = route_host.clone();
        let blocked = thread::spawn(move || blocked_host.ready());
        waiting.recv_timeout(Duration::from_secs(3)).unwrap();

        let (first_reply, first_result) = mpsc::sync_channel(1);
        route_host
            .send(RouteHostCommand::Identities(first_reply))
            .unwrap();
        let (second_reply, second_result) = mpsc::sync_channel(1);
        route_host
            .send(RouteHostCommand::Identities(second_reply))
            .unwrap();
        let (overflow_reply, _) = mpsc::sync_channel(1);
        assert_eq!(
            route_host.send(RouteHostCommand::Identities(overflow_reply)),
            Err(AgentRouteError::NotReady)
        );

        release.send(()).unwrap();
        assert_eq!(blocked.join().unwrap(), Ok(()));
        assert_eq!(first_result.recv().unwrap().unwrap(), vec![identity]);
        assert_eq!(second_result.recv().unwrap().unwrap(), vec![identity]);

        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment.into_parts().0).unwrap();
        owner.shutdown_and_join().unwrap();
        assert!(retired.load(Ordering::Acquire));
        assert!(!route_host.is_running());
    }

    #[test]
    fn cross_request_error_replay_fails_closed_and_retires_host_worker() {
        let first = request(31, RuntimeExecutionContext::Direct);
        let second = request(32, RuntimeExecutionContext::Direct);
        let stale = AgentInvocationResponse::direct(
            &first,
            RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        );
        let (attachment, _, invokes, retired) =
            fake_attachment(identity(&first), None, FakeReply::Fixed(stale));
        let (attachment, _) = attachment.into_parts();
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let handle = owner.handle();
        let snapshot = handle.snapshot(identity(&first).key()).unwrap();
        assert_eq!(
            dispatch_invocation(&handle, snapshot, second),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );
        assert_eq!(invokes.load(Ordering::Acquire), 1);
        assert!(retired.load(Ordering::Acquire));
        assert_eq!(
            handle.snapshot(identity(&first).key()),
            Err(AgentSupervisorError::NotFound)
        );
        owner.shutdown_and_join().unwrap();
    }

    struct ReplayRoute(Vec<u8>);

    impl AgentRoute for ReplayRoute {
        fn reconcile(
            &mut self,
            proposed: &[AgentRouteSnapshot],
        ) -> Result<Vec<AgentRouteSnapshot>, AgentRouteError> {
            Ok(proposed.to_vec())
        }

        fn dispatch(
            &mut self,
            _route: &AgentRouteSnapshot,
            _payload: &[u8],
        ) -> Result<Vec<u8>, AgentRouteError> {
            Ok(self.0.clone())
        }
    }

    struct NoopWorker;

    impl AgentRouteWorkerOwner for NoopWorker {
        fn request_retire(&mut self) -> Result<(), AgentRouteWorkerError> {
            Ok(())
        }

        fn join(self: Box<Self>) -> Result<(), AgentRouteWorkerError> {
            Ok(())
        }
    }

    fn dispatch_replayed_invocation(
        request: AgentInvocationRequest,
        response: AgentInvocationResponse,
    ) -> Result<AgentInvocationResponse, AgentSupervisorError> {
        let route_identity = identity(&request);
        let attachment = AgentRouteAttachment::new(
            vec![route_identity],
            ReplayRoute(response.encode().unwrap()),
            NoopWorker,
        );
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let snapshot = owner.handle().snapshot(route_identity.key()).unwrap();
        let result = dispatch_invocation(&owner.handle(), snapshot, request);
        owner.shutdown_and_join().unwrap();
        result
    }

    fn dispatch_replayed_resume(
        request: AgentResumeRequest,
        response: AgentResumeResponse,
    ) -> Result<AgentResumeResponse, AgentSupervisorError> {
        let route_identity = identity(&request.invocation);
        let attachment = AgentRouteAttachment::new(
            vec![route_identity],
            ReplayRoute(response.encode().unwrap()),
            NoopWorker,
        );
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let snapshot = owner.handle().snapshot(route_identity.key()).unwrap();
        let result = dispatch_resume(&owner.handle(), snapshot, request);
        owner.shutdown_and_join().unwrap();
        result
    }

    fn dispatch_replayed_acknowledgement(
        request: AgentAcknowledgementRequest,
        response: AgentAcknowledgementResponse,
    ) -> Result<AgentAcknowledgementResponse, AgentSupervisorError> {
        let route_identity = identity(&request.invocation);
        let attachment = AgentRouteAttachment::new(
            vec![route_identity],
            ReplayRoute(response.encode().unwrap()),
            NoopWorker,
        );
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let snapshot = owner.handle().snapshot(route_identity.key()).unwrap();
        let result = dispatch_acknowledgement(&owner.handle(), snapshot, request);
        owner.shutdown_and_join().unwrap();
        result
    }

    #[test]
    fn generic_route_cannot_forge_attested_response_admission() {
        let proof_system = Hash([0x71; 32]);
        let execution = RuntimeExecutionContext::Attested { proof_system };
        let invocation = request(0x72, execution);
        let manifest = proof_manifest(b"unverified-attested-transport");
        let record = proof_record(&invocation, &manifest);

        let mut forged_signature = record.clone();
        forged_signature.producer_signature[0] ^= 1;
        assert!(forged_signature.validate_shape());
        let forged_signature_response = AgentInvocationResponse::Attested {
            request: invocation.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: forged_signature,
            proof: AgentTransitionProofDelivery::Inline(manifest.clone()),
        };
        assert_eq!(
            dispatch_replayed_invocation(invocation.clone(), forged_signature_response),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );

        let mut wrong_producer = record.clone();
        wrong_producer.producer_public_key = [0x73; PROOF_PUBLIC_KEY_BYTES];
        wrong_producer.producer = ProducerId::of_public_key(&wrong_producer.producer_public_key);
        wrong_producer.producer_signature = [0x74; PROOF_SIGNATURE_BYTES];
        assert!(wrong_producer.validate_shape());
        let wrong_producer_response = AgentInvocationResponse::Attested {
            request: invocation.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: wrong_producer,
            proof: AgentTransitionProofDelivery::Inline(manifest.clone()),
        };
        assert_eq!(
            dispatch_replayed_invocation(invocation.clone(), wrong_producer_response),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );

        let expected_live = proof_key(&invocation, 0x75);
        let resume = AgentResumeRequest::new(
            execution,
            Some(expected_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
            yielded(&invocation, 1),
        )
        .unwrap();
        let mut stale_sibling = record;
        stale_sibling.statement.work = Hash([0x76; 32]);
        assert_ne!(stale_sibling.statement.key(), expected_live);
        assert!(stale_sibling.validate_shape());
        let stale_sibling_response = AgentResumeResponse::Attested {
            request: resume.commitment(),
            outcome: RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
            record: stale_sibling,
            proof: AgentTransitionProofDelivery::Inline(manifest),
        };
        assert_eq!(
            dispatch_replayed_resume(resume, stale_sibling_response),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );

        let acknowledgement = AgentAcknowledgementRequest::new(
            execution,
            Some(expected_live),
            invocation.work.clone(),
            invocation.authorization.clone(),
        )
        .unwrap();
        let forged_success = AgentAcknowledgementResponse::new(
            &acknowledgement,
            RuntimeOutcome::Acknowledged(Ok(acknowledged(&acknowledgement))),
        );
        assert_eq!(
            dispatch_replayed_acknowledgement(acknowledgement.clone(), forged_success),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );

        let forged_error = AgentAcknowledgementResponse::new(
            &acknowledgement,
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound)),
        );
        assert_eq!(
            dispatch_replayed_acknowledgement(acknowledgement, forged_error),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );
    }

    #[test]
    fn typed_dispatch_rejects_cross_request_replay_from_non_clean_route() {
        let first = request(35, RuntimeExecutionContext::Direct);
        let second = request(36, RuntimeExecutionContext::Direct);
        let stale = AgentInvocationResponse::direct(
            &first,
            RuntimeOutcome::Completed(Err(InvocationError::NotFound)),
        )
        .encode()
        .unwrap();
        let attachment =
            AgentRouteAttachment::new(vec![identity(&second)], ReplayRoute(stale), NoopWorker);
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let handle = owner.handle();
        let snapshot = handle.snapshot(identity(&second).key()).unwrap();
        assert_eq!(
            dispatch_invocation(&handle, snapshot, second),
            Err(AgentSupervisorError::Route(AgentRouteError::Unavailable))
        );
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn concrete_projection_refresh_invalidates_runtime_and_actor_upgrade_aba() {
        let request = request(33, RuntimeExecutionContext::Direct);
        let old_identity = identity(&request);
        let (attachment, identities, _, retired) =
            fake_attachment(old_identity, None, FakeReply::RequestBoundError);
        let route_host = attachment.handle();
        let (attachment, _) = attachment.into_parts();
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        let publication = owner.attach(attachment).unwrap();
        let handle = owner.handle();
        let old = handle.snapshot(old_identity.key()).unwrap();

        let upgraded = AgentRouteIdentity::new(
            old_identity.key(),
            old_identity.incarnation(),
            DeploymentId([41; 32]),
            old_identity.actor_deployment(),
            old_identity.actor_program(),
            old_identity.profile(),
        )
        .unwrap();
        *identities.lock().unwrap() = vec![upgraded];
        let replacement = owner
            .refresh(&publication, route_host.identities().unwrap())
            .unwrap();
        let current = handle.snapshot(old_identity.key()).unwrap();
        assert_eq!(current, replacement.snapshots()[0]);
        assert_eq!(current.runtime_deployment(), DeploymentId([41; 32]));
        assert_eq!(
            handle.dispatch(old, request.encode().unwrap()),
            Err(AgentSupervisorError::StaleSnapshot)
        );

        let actor_upgraded = AgentRouteIdentity::new(
            old_identity.key(),
            Hash([42; 32]),
            upgraded.runtime_deployment(),
            DeploymentId([43; 32]),
            ProgramId([44; 32]),
            old_identity.profile(),
        )
        .unwrap();
        *identities.lock().unwrap() = vec![actor_upgraded];
        let replacement = owner
            .refresh(&replacement, route_host.identities().unwrap())
            .unwrap();
        let newest = handle.snapshot(old_identity.key()).unwrap();
        assert_eq!(newest, replacement.snapshots()[0]);
        assert_eq!(newest.incarnation(), Hash([42; 32]));
        assert_eq!(newest.actor_deployment(), DeploymentId([43; 32]));
        assert_eq!(newest.actor_program(), ProgramId([44; 32]));
        assert_eq!(newest.runtime_deployment(), DeploymentId([41; 32]));
        assert_eq!(
            handle.dispatch(current, request.encode().unwrap()),
            Err(AgentSupervisorError::StaleSnapshot)
        );
        owner.shutdown_and_join().unwrap();
        assert!(retired.load(Ordering::Acquire));
    }

    #[test]
    fn panicked_concrete_backend_is_unpublished_and_joined() {
        let request = request(34, RuntimeExecutionContext::Direct);
        let identity = identity(&request);
        let (attachment, _, invokes, retired) = fake_attachment(identity, None, FakeReply::Panic);
        let (attachment, route_host) = attachment.into_parts();
        let mut owner = AgentSupervisorOwner::start(limits()).unwrap();
        owner.attach(attachment).unwrap();
        let handle = owner.handle();
        let snapshot = handle.snapshot(identity.key()).unwrap();
        assert!(dispatch_invocation(&handle, snapshot, request).is_err());
        assert_eq!(invokes.load(Ordering::Acquire), 1);
        assert!(!retired.load(Ordering::Acquire));
        assert!(!route_host.is_running());
        assert_eq!(
            handle.snapshot(identity.key()),
            Err(AgentSupervisorError::NotFound)
        );
        owner.shutdown_and_join().unwrap();
    }

    fn owner_authority() -> AgentAuthorityBinding {
        let public_key = [0xa1; 32];
        AgentAuthorityBinding {
            policy: Hash([0xa2; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0xa3; 32]),
                actor: ActorId([0xa4; 32]),
                deployment: DeploymentId([0xa5; 32]),
                program: ProgramId([0xa6; 32]),
                producer: ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 1,
        }
    }

    fn owner_descriptor(seed: u8, profile: AgentProfile, node: NodeId) -> AgentDescriptor {
        let space = SpaceId([0xb1; 32]);
        let owner = PrincipalId([seed; 32]);
        let creation_nonce = Hash([seed.wrapping_add(1); 32]);
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, creation_nonce.as_bytes()),
                owner,
                profile,
                runtime_deployment: DeploymentId([seed.wrapping_add(2); 32]),
                runtime_program: ProgramId([seed.wrapping_add(3); 32]),
                runtime_producer: ProducerId([seed.wrapping_add(4); 32]),
                transition_producer: ProducerId([seed.wrapping_add(5); 32]),
            },
            creation_nonce,
            authority: owner_authority(),
            private_recovery: None,
            runtime_package: BlobRef::of_bytes(&[seed, 0x51]),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node,
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        descriptor
    }

    fn owner_projection(
        descriptor: AgentDescriptor,
        seed: u8,
        root: bool,
    ) -> AgentAuthorityRouteProjection {
        let lanes = LaneSet::of(StateLane::Linear);
        let replica_generation = descriptor.replica_generation();
        AgentAuthorityRouteProjection::new(
            replica_generation,
            descriptor.clone(),
            vec![AuthorityActorProjection {
                agent: descriptor.identity.agent,
                entry: ActorEntry {
                    actor: ActorId([seed.wrapping_add(10); 32]),
                    name: format!("actor-{seed}"),
                    parent: None,
                    deployment: DeploymentId([seed.wrapping_add(11); 32]),
                    program: ProgramId::of_pvm(&[seed, 1]),
                    package: BlobRef::of_bytes(&[seed, 1]),
                    agent_schema: BlobRef::of_bytes(&[seed, 2]),
                    method_policy: BlobRef::of_bytes(&[seed, 3]),
                    constructor_abi: Hash([seed.wrapping_add(13); 32]),
                    installation_data: None,
                    state_layout: Hash([seed.wrapping_add(14); 32]),
                    lanes,
                    suspended: false,
                },
                producer: ProducerId([seed.wrapping_add(15); 32]),
                contract: ActorPackageContract::canonical(),
                requirements: RuntimeRequirements {
                    lanes,
                    scheduling: false,
                    proof_systems: crate::agent::sdk::ProofSystemSet::EMPTY,
                },
                root_provenance: root,
                installation_id: InstallationId([seed.wrapping_add(16); 32]),
                registry_reservation: Hash([seed.wrapping_add(17); 32]),
                install_request: Hash([seed.wrapping_add(18); 32]),
            }],
        )
        .unwrap()
    }

    fn owner_identity(
        projection: &AgentAuthorityRouteProjection,
        incarnation: u8,
    ) -> AgentRouteIdentity {
        let descriptor = projection.descriptor();
        let actor = &projection.actors()[0].entry;
        AgentRouteIdentity::new(
            AgentRouteKey::new(
                descriptor.identity.space,
                descriptor.identity.agent,
                actor.actor,
            )
            .unwrap(),
            Hash([incarnation; 32]),
            descriptor.identity.runtime_deployment,
            actor.deployment,
            actor.program,
            descriptor.identity.profile,
        )
        .unwrap()
    }

    fn owner_head(counter: u64) -> AuthorityProjectionHead {
        AuthorityProjectionHead {
            state_revision: NonZeroU64::new(counter).unwrap(),
            epoch: NonZeroU64::new(counter).unwrap(),
            authorization_sequence: NonZeroU64::new(counter).unwrap(),
            administration_generation: NonZeroU64::new(counter).unwrap(),
            state_commitment: Hash([u8::try_from(counter).unwrap(); 32]),
        }
    }

    fn owner_physical_material(
        projection: &AgentAuthorityRouteProjection,
        descriptor: AgentDescriptor,
        seed: u8,
    ) -> PhysicalInvocationMaterial {
        let actor = &projection.actors()[0];
        PhysicalInvocationMaterial {
            descriptor,
            actor: crate::agent::sdk::ActorDirectoryRecord {
                entry: actor.entry.clone(),
                incarnation: Hash([seed.wrapping_add(20); 32]),
                installation_id: actor.installation_id,
                registry_reservation: actor.registry_reservation,
                install_request: actor.install_request,
            },
            install_request: actor.install_request,
            producer: actor.producer,
            contract: actor.contract,
            requirements: actor.requirements,
            root_provenance: actor.root_provenance,
            observed_slot: 17,
            program: RuntimeBlob {
                reference: actor.entry.package.clone(),
                bytes: vec![seed, 1],
            },
            schema: RuntimeBlob {
                reference: actor.entry.agent_schema.clone(),
                bytes: vec![seed, 2],
            },
            policies: RuntimeBlob {
                reference: actor.entry.method_policy.clone(),
                bytes: vec![seed, 3],
            },
            installation_data: None,
        }
    }

    #[test]
    fn physical_projection_lag_requires_exact_replica_generation_reply() {
        let seed = 0x35;
        let descriptor = owner_descriptor(seed, AgentProfile::Shared, NodeId([0x31; 32]));
        let projected = owner_projection(descriptor.clone(), seed, false);
        assert_eq!(
            AgentAuthorityRouteProjection::new(
                Hash([0xfe; 32]),
                descriptor.clone(),
                projected.actors().to_vec(),
            ),
            Err(AgentRouteError::Rejected)
        );

        let mut current = descriptor.clone();
        current.replicas.push(AgentReplica {
            node: NodeId([0x41; 32]),
            principal: descriptor.identity.owner,
            role: ReplicaRole::Observer,
        });
        current
            .replicas
            .sort_unstable_by_key(|replica| replica.node);
        current.validate().unwrap();
        let request = crate::agent::sdk::ManagementRequest::ChangeReplicas {
            expected_generation: descriptor.replica_generation(),
            replicas: current.replicas.clone(),
        };
        let exact_reply = crate::agent::sdk::ManagementReply::ReplicasChanged {
            generation: current.replica_generation(),
        };
        let disposition = crate::agent::standard::StandardCleanManagementDisposition {
            authority: Hash([0x71; 32]),
            request: request.replay_commitment(),
            epoch: 1,
            sequence: 1,
            observed_slot: 17,
            result: Ok(exact_reply),
        };
        let material = owner_physical_material(&projected, current.clone(), seed);
        let physical = PhysicalAuthorityRouteProjection {
            descriptor: current,
            actors: vec![material],
            disposition: Some(disposition.clone()),
        };
        assert!(physical_projection_is_exactly_one_ack_ahead(
            owner_head(1),
            core::slice::from_ref(&projected),
            core::slice::from_ref(&physical),
        ));

        let mut wrong_generation = physical;
        wrong_generation.disposition.as_mut().unwrap().result =
            Ok(crate::agent::sdk::ManagementReply::ReplicasChanged {
                generation: Hash([0x72; 32]),
            });
        assert!(!physical_projection_is_exactly_one_ack_ahead(
            owner_head(1),
            &[projected],
            &[wrong_generation],
        ));
    }

    fn owner_target(system: &AgentAuthorityRouteProjection) -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: system.descriptor().identity.space,
            system_agent: system.descriptor().identity.agent,
            system_runtime_deployment: system.descriptor().identity.runtime_deployment,
            binding: system.descriptor().authority,
        }
    }

    struct OwnerAuthenticator(u8);

    #[test]
    fn peer_projection_queue_is_bounded_and_closed_handles_release_backend() {
        use crate::agent::production_owner::AuthorityProjectionQueryAuthenticator as _;

        let system = owner_projection(
            owner_descriptor(0x31, AgentProfile::Shared, NodeId([0x32; 32])),
            0x31,
            true,
        );
        let query = OwnerAuthenticator(0)
            .authenticate(
                owner_target(&system),
                AuthorityProjectionSelector::Credential,
            )
            .unwrap();
        let request = request(0x33, RuntimeExecutionContext::Direct);
        let (started, observed) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let (attachment, identities, _, retired) = fake_attachment(
            identity(&request),
            Some(ReadyGate {
                started,
                release: wait,
            }),
            FakeReply::RequestBoundError,
        );
        let lifetime = Arc::downgrade(&identities);
        drop(identities);
        let handle = attachment.handle();
        let operation_handle = handle.clone();
        let operation = std::thread::spawn(move || operation_handle.ready());
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        // Acceptance means admission only: the worker is blocked and the
        // default backend will reject these queries when it drains them.
        let first = handle.enqueue_peer_projection(query.clone(), false, NodeId([0xc3; 32]));
        let second = handle.enqueue_peer_projection(query.clone(), true, NodeId([0xc3; 32]));
        let full = handle.enqueue_peer_projection(query.clone(), true, NodeId([0xc3; 32]));
        release.send(()).unwrap();
        operation.join().unwrap().unwrap();
        attachment.retire().unwrap();
        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
        assert_eq!(full, Err(AgentRouteError::NotReady));
        assert!(retired.load(Ordering::Acquire));
        assert!(lifetime.upgrade().is_none());
        assert_eq!(
            handle.enqueue_peer_projection(query, true, NodeId([0xc3; 32])),
            Err(AgentRouteError::Unavailable)
        );
    }

    impl crate::agent::production_owner::AuthorityProjectionQueryAuthenticator for OwnerAuthenticator {
        fn expected_kind(&self) -> AuthorityCredentialKind {
            AuthorityCredentialKind::Api
        }

        fn authenticate(
            &mut self,
            authority: AuthorityActorTarget,
            selector: AuthorityProjectionSelector,
        ) -> Result<
            AuthorityProjectionQuery,
            crate::agent::production_owner::AgentProductionOwnerError,
        > {
            self.0 = self.0.wrapping_add(1).max(1);
            let public_key = [0xc1; 32];
            Ok(AuthorityProjectionQuery {
                authority,
                credential: CredentialId::of_public_key(&public_key),
                nonce: Hash([self.0; 32]),
                selector,
                recovery: None,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [0xc2; 64],
                },
            })
        }
    }

    struct OwnerInventoryState {
        head: std::sync::atomic::AtomicU64,
        consistent: AtomicBool,
        projections: Vec<AgentAuthorityRouteProjection>,
        queries: AtomicUsize,
    }

    struct OwnerRouteState {
        identity: Mutex<AgentRouteIdentity>,
        replace_after_audit: Mutex<Option<AgentRouteIdentity>>,
        audit: AtomicBool,
        dormant: AtomicBool,
        zero_routes: AtomicBool,
        retired: AtomicBool,
    }

    struct OwnerRouteBackend {
        route: Arc<OwnerRouteState>,
        target: Option<AuthorityActorTarget>,
        inventory: Option<Arc<OwnerInventoryState>>,
    }

    impl CleanAgentRouteBackend for OwnerRouteBackend {
        fn identities(&mut self) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
            self.route
                .identity
                .lock()
                .map(|identity| vec![*identity])
                .map_err(|_| AgentRouteError::Unavailable)
        }

        fn invoke(
            &mut self,
            _identity: AgentRouteIdentity,
            _request: AgentInvocationRequest,
        ) -> Result<AgentInvocationResponse, AgentRouteError> {
            Err(AgentRouteError::Rejected)
        }

        fn authorize_projection(
            &mut self,
            _head: AuthorityProjectionHead,
            projection: &[AgentAuthorityRouteProjection],
        ) -> Result<Vec<AgentRouteIdentity>, AgentRouteError> {
            if self.route.dormant.load(Ordering::Acquire) {
                return Err(AgentRouteError::NotReady);
            }
            if self.route.zero_routes.load(Ordering::Acquire) {
                return Ok(Vec::new());
            }
            let identity = *self
                .route
                .identity
                .lock()
                .map_err(|_| AgentRouteError::Unavailable)?;
            if !self.route.audit.load(Ordering::Acquire)
                || projection.len() != 1
                || projection[0].descriptor().identity.agent != identity.key().agent()
                || projection[0].descriptor().identity.space != identity.key().space()
                || projection[0].descriptor().identity.profile != identity.profile()
            {
                return Err(AgentRouteError::Rejected);
            }
            if let Some(replacement) = self.route.replace_after_audit.lock().unwrap().take() {
                *self.route.identity.lock().unwrap() = replacement;
            }
            Ok(vec![identity])
        }

        fn authority_target(&mut self) -> Result<AuthorityActorTarget, AgentRouteError> {
            self.target.ok_or(AgentRouteError::Rejected)
        }

        fn authority_projection(
            &mut self,
            query: AuthorityProjectionQuery,
        ) -> Result<Vec<u8>, AgentRouteError> {
            let target = self.target.ok_or(AgentRouteError::Rejected)?;
            let inventory = self.inventory.as_ref().ok_or(AgentRouteError::Rejected)?;
            if query.authority != target || query.validate_shape().is_err() {
                return Err(AgentRouteError::Rejected);
            }
            inventory.queries.fetch_add(1, Ordering::AcqRel);
            let counter = inventory.head.load(Ordering::Acquire);
            let head = owner_head(counter);
            let mut projections = inventory.projections.clone();
            projections.sort_by_key(|projection| projection.descriptor().identity.agent);
            let bytes = match query.selector {
                AuthorityProjectionSelector::Inventory { after, .. } => {
                    let consistent = inventory.consistent.load(Ordering::Acquire);
                    let descriptors: Vec<_> = projections
                        .iter()
                        .map(|projection| projection.descriptor().clone())
                        .collect();
                    let actors: Vec<_> = projections
                        .iter()
                        .flat_map(|projection| projection.actors().iter().cloned())
                        .collect();
                    return super::super::production_owner::inventory_page_fixture(
                        query,
                        if !consistent && after.is_some() {
                            owner_head(counter + 1)
                        } else {
                            head
                        },
                        PrincipalId([0xc3; 32]),
                        &descriptors,
                        &actors,
                        if consistent { usize::MAX } else { 1 },
                    )
                    .map_err(|_| AgentRouteError::Rejected);
                }
                AuthorityProjectionSelector::Credential => AuthorityCredentialProjection {
                    query,
                    head,
                    principal: PrincipalId([0xc3; 32]),
                    status: AuthorityCredentialStatus::Active,
                    kind: AuthorityCredentialKind::Api,
                    builtin_role: AuthorityBuiltinRole::Admin,
                    management_request_high_water: 0,
                    operation_request_high_water: 0,
                    admin_request_high_water: 0,
                    space_roles: Vec::new(),
                    actor_roles: Vec::new(),
                    capabilities: Vec::new(),
                }
                .encode(),
                AuthorityProjectionSelector::Agents { .. } => AuthorityAgentProjectionPage {
                    query,
                    head,
                    entries: projections
                        .iter()
                        .map(|projection| {
                            let descriptor = projection.descriptor();
                            AuthorityAgentProjection {
                                identity: descriptor.identity.clone(),
                                creation_nonce: descriptor.creation_nonce,
                                authority: descriptor.authority,
                                private_recovery: descriptor.private_recovery,
                                runtime_package: descriptor.runtime_package.clone(),
                                runtime_contract: descriptor.runtime_contract,
                                capabilities: descriptor.capabilities,
                                replica_count: descriptor.replicas.len() as u16,
                                replica_generation: descriptor.replica_generation(),
                            }
                        })
                        .collect(),
                    next: None,
                }
                .encode(),
                AuthorityProjectionSelector::AgentReplicas { agent, .. } => {
                    let descriptor = projections
                        .iter()
                        .find(|projection| projection.descriptor().identity.agent == agent)
                        .ok_or(AgentRouteError::Rejected)?
                        .descriptor();
                    AuthorityAgentReplicaProjectionPage {
                        query,
                        head,
                        replica_count: descriptor.replicas.len() as u16,
                        replica_generation: descriptor.replica_generation(),
                        entries: descriptor.replicas.clone(),
                        next: None,
                    }
                    .encode()
                }
                AuthorityProjectionSelector::Actors { agent, .. } => {
                    let projection = projections
                        .iter()
                        .find(|projection| projection.descriptor().identity.agent == agent)
                        .ok_or(AgentRouteError::Rejected)?;
                    AuthorityActorProjectionPage {
                        query,
                        head: if inventory.consistent.load(Ordering::Acquire) {
                            head
                        } else {
                            owner_head(counter + 1)
                        },
                        entries: projection.actors().to_vec(),
                        next: None,
                    }
                    .encode()
                }
            };
            bytes.map_err(|_| AgentRouteError::Rejected)
        }

        fn retire(&mut self) -> Result<(), AgentRouteWorkerError> {
            self.route.retired.store(true, Ordering::Release);
            Ok(())
        }
    }

    fn owner_attachment(
        projection: &AgentAuthorityRouteProjection,
        incarnation: u8,
        target: Option<AuthorityActorTarget>,
        inventory: Option<Arc<OwnerInventoryState>>,
    ) -> (AgentRouteHostAttachment, Arc<OwnerRouteState>) {
        let route = Arc::new(OwnerRouteState {
            identity: Mutex::new(owner_identity(projection, incarnation)),
            replace_after_audit: Mutex::new(None),
            audit: AtomicBool::new(true),
            dormant: AtomicBool::new(false),
            zero_routes: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        });
        let attachment = spawn_backend(
            OwnerRouteBackend {
                route: route.clone(),
                target,
                inventory,
            },
            8,
            "vos-production-owner-lifecycle-test",
        )
        .unwrap();
        (attachment, route)
    }

    fn owner_snapshot(
        handle: &crate::agent::supervisor::AgentSupervisorHandle,
        agent: AgentId,
    ) -> crate::agent::supervisor::AgentRouteSnapshot {
        handle
            .snapshots()
            .unwrap()
            .into_iter()
            .find(|snapshot| snapshot.key().agent() == agent)
            .unwrap()
    }

    #[test]
    fn production_owner_failure_is_mutation_free_and_aba_cleanup_is_total() {
        use crate::agent::production_owner::{AgentProductionOwner, AgentProductionOwnerError};

        let node = NodeId([0xd1; 32]);
        let system = owner_projection(
            owner_descriptor(0x31, AgentProfile::Shared, node),
            0x41,
            true,
        );
        let local = owner_projection(
            owner_descriptor(0x32, AgentProfile::Local, node),
            0x42,
            false,
        );
        let inventory = Arc::new(OwnerInventoryState {
            head: std::sync::atomic::AtomicU64::new(1),
            consistent: AtomicBool::new(true),
            projections: vec![system.clone(), local.clone()],
            queries: AtomicUsize::new(0),
        });
        let target = owner_target(&system);
        let (system_attachment, system_route) =
            owner_attachment(&system, 1, Some(target), Some(inventory.clone()));
        let mut owner = AgentProductionOwner::start(
            node,
            limits(),
            system_attachment,
            Box::new(OwnerAuthenticator(0)),
            Duration::from_secs(60),
        )
        .unwrap();
        let (local_attachment, local_route) = owner_attachment(&local, 2, None, None);
        owner.install_local_host(local_attachment).unwrap();

        // An authenticated unchanged head reuses already-validated inventory.
        // Advance it so the injected cross-page mismatch is actually queried.
        inventory.head.store(2, Ordering::Release);
        inventory.consistent.store(false, Ordering::Release);
        let queries_before_failure = inventory.queries.load(Ordering::Acquire);
        assert_eq!(
            owner.reconcile(),
            Err(AgentProductionOwnerError::InconsistentHead)
        );
        assert!(inventory.queries.load(Ordering::Acquire) > queries_before_failure + 1);
        let handle = owner.handle();
        assert_eq!(handle.snapshots().unwrap().len(), 1);
        assert!(!local_route.retired.load(Ordering::Acquire));

        inventory.consistent.store(true, Ordering::Release);
        *local_route.replace_after_audit.lock().unwrap() = Some(owner_identity(&local, 3));
        assert_eq!(
            owner.reconcile(),
            Err(AgentProductionOwnerError::InvalidProjection)
        );
        assert!(local_route.retired.load(Ordering::Acquire));
        assert_eq!(handle.snapshots().unwrap().len(), 1);

        let (local_attachment, local_route) = owner_attachment(&local, 2, None, None);
        owner.install_local_host(local_attachment).unwrap();
        owner.reconcile().unwrap();
        let first = owner_snapshot(&handle, local.descriptor().identity.agent);
        *local_route.identity.lock().unwrap() = owner_identity(&local, 3);
        inventory.head.store(3, Ordering::Release);
        owner.reconcile().unwrap();
        let second = owner_snapshot(&handle, local.descriptor().identity.agent);
        assert_ne!(first.readiness_generation(), second.readiness_generation());

        *local_route.identity.lock().unwrap() = owner_identity(&local, 2);
        inventory.head.store(4, Ordering::Release);
        owner.reconcile().unwrap();
        let third = owner_snapshot(&handle, local.descriptor().identity.agent);
        assert_ne!(first.readiness_generation(), third.readiness_generation());
        assert_ne!(second.readiness_generation(), third.readiness_generation());

        local_route.audit.store(false, Ordering::Release);
        inventory.head.store(5, Ordering::Release);
        assert_eq!(
            owner.reconcile(),
            Err(AgentProductionOwnerError::InvalidProjection)
        );
        assert_eq!(
            handle.snapshot(third.key()),
            Err(AgentSupervisorError::NotFound)
        );
        assert!(local_route.retired.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
        assert!(system_route.retired.load(Ordering::Acquire));
        assert!(!handle.is_running());
    }

    #[test]
    fn production_owner_retains_dormant_worker_until_exact_routes_resume() {
        use crate::agent::production_owner::AgentProductionOwner;

        let node = NodeId([0xd3; 32]);
        let system = owner_projection(
            owner_descriptor(0x61, AgentProfile::Shared, node),
            0x71,
            true,
        );
        let local = owner_projection(
            owner_descriptor(0x62, AgentProfile::Local, node),
            0x72,
            false,
        );
        let inventory = Arc::new(OwnerInventoryState {
            head: std::sync::atomic::AtomicU64::new(1),
            consistent: AtomicBool::new(true),
            projections: vec![system.clone(), local.clone()],
            queries: AtomicUsize::new(0),
        });
        let target = owner_target(&system);
        let (system_attachment, _) =
            owner_attachment(&system, 1, Some(target), Some(inventory.clone()));
        let mut owner = AgentProductionOwner::start(
            node,
            limits(),
            system_attachment,
            Box::new(OwnerAuthenticator(0)),
            Duration::from_secs(60),
        )
        .unwrap();
        let handle = owner.handle();
        let (local_attachment, local_route) = owner_attachment(&local, 2, None, None);
        local_route.zero_routes.store(true, Ordering::Release);
        owner.install_local_host(local_attachment).unwrap();

        inventory.head.store(2, Ordering::Release);
        owner.reconcile().unwrap();
        assert_eq!(handle.snapshots().unwrap().len(), 1);
        assert!(!local_route.retired.load(Ordering::Acquire));

        local_route.zero_routes.store(false, Ordering::Release);
        owner.reconcile().unwrap();
        let first = owner_snapshot(&handle, local.descriptor().identity.agent);
        assert!(!local_route.retired.load(Ordering::Acquire));

        local_route.dormant.store(true, Ordering::Release);
        inventory.head.store(3, Ordering::Release);
        owner.reconcile().unwrap();
        assert_eq!(handle.snapshots().unwrap().len(), 1);
        assert!(!local_route.retired.load(Ordering::Acquire));

        local_route.dormant.store(false, Ordering::Release);
        inventory.head.store(4, Ordering::Release);
        owner.reconcile().unwrap();
        let resumed = owner_snapshot(&handle, local.descriptor().identity.agent);
        assert_ne!(first.readiness_generation(), resumed.readiness_generation());
        assert!(!local_route.retired.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn production_shutdown_signals_all_pending_hosts_before_join() {
        use crate::agent::production_owner::AgentProductionOwner;

        let node = NodeId([0xd4; 32]);
        let system = owner_projection(
            owner_descriptor(0x71, AgentProfile::Shared, node),
            0x81,
            true,
        );
        let local = owner_projection(
            owner_descriptor(0x72, AgentProfile::Local, node),
            0x82,
            false,
        );
        let shared = owner_projection(
            owner_descriptor(0x73, AgentProfile::Shared, node),
            0x83,
            false,
        );
        let inventory = Arc::new(OwnerInventoryState {
            head: std::sync::atomic::AtomicU64::new(1),
            consistent: AtomicBool::new(true),
            projections: vec![system.clone()],
            queries: AtomicUsize::new(0),
        });
        let (system_attachment, _) =
            owner_attachment(&system, 1, Some(owner_target(&system)), Some(inventory));
        let mut owner = AgentProductionOwner::start(
            node,
            limits(),
            system_attachment,
            Box::new(OwnerAuthenticator(0)),
            Duration::from_secs(60),
        )
        .unwrap();
        let (local_attachment, local_route) = owner_attachment(&local, 2, None, None);
        let (shared_attachment, shared_route) = owner_attachment(&shared, 3, None, None);
        owner.install_local_host(local_attachment).unwrap();
        owner.install_shared_host(shared_attachment).unwrap();

        owner.request_shutdown();
        for _ in 0..100 {
            if local_route.retired.load(Ordering::Acquire)
                && shared_route.retired.load(Ordering::Acquire)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(local_route.retired.load(Ordering::Acquire));
        assert!(shared_route.retired.load(Ordering::Acquire));
        owner.shutdown_and_join().unwrap();
    }

    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    #[test]
    fn node_exposes_only_reconciled_owner_and_shutdown_joins_all_routes() {
        use crate::agent::production_owner::AgentProductionOwner;

        let node_id = NodeId([0xd2; 32]);
        let system = owner_projection(
            owner_descriptor(0x51, AgentProfile::Shared, node_id),
            0x61,
            true,
        );
        let inventory = Arc::new(OwnerInventoryState {
            head: std::sync::atomic::AtomicU64::new(1),
            consistent: AtomicBool::new(true),
            projections: vec![system.clone()],
            queries: AtomicUsize::new(0),
        });
        let target = owner_target(&system);
        let (system_attachment, system_route) =
            owner_attachment(&system, 1, Some(target), Some(inventory.clone()));
        let owner = AgentProductionOwner::start(
            node_id,
            limits(),
            system_attachment,
            Box::new(OwnerAuthenticator(0)),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(inventory.queries.load(Ordering::Acquire) > 0);
        let supervisor = owner.handle();
        assert_eq!(supervisor.snapshots().unwrap().len(), 1);

        let mut node = crate::node::VosNode::new();
        assert!(node.clean_agent_supervisor().is_none());
        let ingress = node.ingress_handle();
        assert!(ingress.clean_agent_supervisor().is_none());
        node.attach_clean_agent_owner(owner).unwrap();
        assert_eq!(
            node.clean_agent_supervisor()
                .unwrap()
                .snapshots()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ingress
                .clean_agent_supervisor()
                .unwrap()
                .snapshots()
                .unwrap()
                .len(),
            1
        );

        #[cfg(feature = "http-ingress")]
        {
            let credential = crate::ingress::ApiAccessCredential::from_seed([0x71; 32]).unwrap();
            let before = inventory.queries.load(Ordering::Acquire);
            for nonce in [Hash([0x72; 32]), Hash([0x73; 32])] {
                let projection = ingress.authenticate_clean_api(&credential, nonce).unwrap();
                assert_eq!(projection.query.authority, target);
                assert_eq!(projection.query.nonce, nonce);
                assert_eq!(projection.query.credential, credential.credential_id());
                assert_eq!(
                    projection.query.selector,
                    AuthorityProjectionSelector::Credential
                );
                projection
                    .query
                    .verify_api_with(&crate::agent::clean_bootstrap::RawCredentialVerifier)
                    .unwrap();
            }
            assert_eq!(inventory.queries.load(Ordering::Acquire), before + 2);
        }

        node.shutdown();
        assert!(node.clean_agent_supervisor().is_none());
        assert!(ingress.clean_agent_supervisor().is_none());
        #[cfg(feature = "http-ingress")]
        assert_eq!(
            ingress.authenticate_clean_api(
                &crate::ingress::ApiAccessCredential::from_seed([0x71; 32]).unwrap(),
                Hash([0x74; 32])
            ),
            Err(crate::node::IngressAuthenticationError::AuthorityUnavailable)
        );
        node.collect_checked().unwrap();
        assert!(system_route.retired.load(Ordering::Acquire));
        assert!(!supervisor.is_running());
    }
}
