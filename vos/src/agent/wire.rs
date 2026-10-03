//! Stable management ABI between a node and an agent-runtime PVM.

use alloc::{boxed::Box, vec::Vec};

use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth, RuntimeBlob, RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::standard::{
    StandardActorState, StandardAgentRuntime, StandardAuthorityDisposition,
    StandardCleanActorInstallation, StandardCleanActorPackage, StandardCleanManagementDisposition,
    StandardInvocationResult, StandardLaneEntry, StandardLaneState, StandardMachineContinuation,
    StandardPrivateManagementDisposition, StandardRuntimeState,
};
use super::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, ActorLifecycleDebt, AgentConfig,
    AgentIdentity, AgentProfile, AgentReplica, InvocationScope, LaneSet, LifecycleError,
    LifecycleReply, LifecycleRequest, MethodMode, ReplicaRole, RuntimeCapabilities,
    RuntimeRequirements, StateLane,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{
    ActorId, AgentId, BlobRef, CapabilityId, DeploymentId, Hash, NodeId, PrincipalId, ProducerId,
    ProgramId, SpaceId,
};

/// Replay-authenticated identity of the exact journal generation applying a
/// management input. These bytes are deterministic state-machine input, not a
/// capability: only replay may construct a scoped call which is eligible for
/// publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeJournalContext {
    genesis: super::journal::AgentJournalGenesisId,
    agent_admission: super::genesis::AgentGenesisAdmissionId,
}

impl RuntimeJournalContext {
    fn new(
        genesis: super::journal::AgentJournalGenesisId,
        agent_admission: super::genesis::AgentGenesisAdmissionId,
    ) -> Result<Self, super::system_authority::SystemAuthorityError> {
        if genesis == super::journal::AgentJournalGenesisId::ZERO
            || agent_admission == super::genesis::AgentGenesisAdmissionId::ZERO
        {
            return Err(super::system_authority::SystemAuthorityError::InvalidScope);
        }
        Ok(Self {
            genesis,
            agent_admission,
        })
    }

    /// Derive deterministic guest input from replay's opaque root identity.
    /// This value remains data only: decoding or copying it never mints the
    /// separate `SystemAuthorityJournalScope` capability.
    pub(crate) fn from_replayed_root(
        identity: &super::replay::ReplayedRootJournalIdentity,
    ) -> Result<Self, super::system_authority::SystemAuthorityError> {
        Self::new(identity.genesis(), identity.outer_admission())
    }

    pub(crate) const fn genesis(self) -> super::journal::AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn agent_admission(self) -> super::genesis::AgentGenesisAdmissionId {
        self.agent_admission
    }

    pub(crate) fn matches_system_authority_scope(
        self,
        scope: super::system_authority::SystemAuthorityJournalScope,
    ) -> bool {
        self.genesis == scope.system_genesis() && self.agent_admission == scope.agent_admission()
    }
}

/// One management call. Runtime-owned state is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeCall {
    pub state: RuntimeState,
    pub request: LifecycleRequest,
    journal_context: Option<RuntimeJournalContext>,
}

impl RuntimeCall {
    /// Construct an unscoped public call. Pre-genesis Create and logical
    /// operation commitments use this form. Direct live-authority commands
    /// deterministically reject it.
    pub const fn new(state: RuntimeState, request: LifecycleRequest) -> Self {
        Self {
            state,
            request,
            journal_context: None,
        }
    }

    /// Construct the exact replay input used by native and guest execution.
    pub(crate) const fn scoped_system_authority(
        state: RuntimeState,
        request: LifecycleRequest,
        trusted_scope: super::system_authority::SystemAuthorityJournalScope,
    ) -> Self {
        Self {
            state,
            request,
            journal_context: Some(RuntimeJournalContext {
                genesis: trusted_scope.system_genesis(),
                agent_admission: trusted_scope.agent_admission(),
            }),
        }
    }

    /// Construct a replay-selected guest call from data-only journal
    /// context. Only replay can obtain the context used by live authority
    /// execution; the guest still receives ordinary bytes, not a capability.
    pub(crate) const fn from_replay_context(
        state: RuntimeState,
        request: LifecycleRequest,
        journal_context: RuntimeJournalContext,
    ) -> Self {
        Self {
            state,
            request,
            journal_context: Some(journal_context),
        }
    }

    pub(crate) const fn journal_context(&self) -> Option<RuntimeJournalContext> {
        self.journal_context
    }
}

/// Private runtime-to-actor dispatch control. Unlike the dynamic application
/// message, these bytes are constructed only after the runtime has validated
/// the signed method schema and authenticated invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActorDispatchControl {
    pub invocation: crate::service::InvocationId,
    pub actor: ActorId,
    pub mode: MethodMode,
    pub auth: ActorInvocationAuth,
}

impl ServiceWire for ActorDispatchControl {
    const MAGIC: [u8; 4] = *b"AGDC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.actor.0);
        encoder.u8(encode_method_mode(self.mode));
        encode_invocation_auth(&mut encoder, &self.auth);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let value = Self {
            invocation: crate::service::InvocationId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            mode: decode_method_mode(decoder.u8()?)?,
            auth: decode_invocation_auth(decoder)?,
        };
        if value.invocation == crate::service::InvocationId::ZERO
            || value.actor == ActorId::ZERO
            || !value.auth.validate()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Runtime-owned state split only at the replication boundary. The node does
/// not interpret any component, but can order and persist each component with
/// the consistency semantics promised by its lane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub control: Vec<u8>,
    pub linear: Vec<u8>,
    pub merge: Vec<u8>,
    pub local: Vec<u8>,
}

/// Deterministic result of one management call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReturn {
    pub state: RuntimeState,
    pub result: Result<LifecycleReply, LifecycleError>,
}

impl ServiceWire for RuntimeCall {
    const MAGIC: [u8; 4] = *b"AGRT";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encoder.option(&self.journal_context, |encoder, context| {
            encoder.fixed(&context.genesis.0);
            encoder.fixed(context.agent_admission.as_bytes());
        });
        encode_runtime_state(&mut encoder, &self.state);
        encode_request(&mut encoder, &self.request);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let journal_context = decoder.option(|decoder| {
            RuntimeJournalContext::new(
                super::journal::AgentJournalGenesisId(decoder.fixed()?),
                super::genesis::AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            )
            .map_err(|_| DecodeError::NonCanonical)
        })?;
        Ok(Self {
            state: decode_runtime_state(decoder)?,
            request: decode_request(decoder)?,
            journal_context,
        })
    }
}

impl ServiceWire for AgentConfig {
    const MAGIC: [u8; 4] = *b"AGCF";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_config(&mut encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        decode_config(decoder)
    }
}

impl ServiceWire for RuntimeReturn {
    const MAGIC: [u8; 4] = *b"AGRR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_runtime_state(&mut encoder, &self.state);
        match &self.result {
            Ok(reply) => {
                encoder.bool(true);
                encode_reply(&mut encoder, reply);
            }
            Err(error) => {
                encoder.bool(false);
                encode_error(&mut encoder, *error);
            }
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = decode_runtime_state(decoder)?;
        let result = if decoder.bool()? {
            Ok(decode_reply(decoder)?)
        } else {
            Err(decode_error(decoder)?)
        };
        Ok(Self { state, result })
    }
}

impl ServiceWire for RuntimeExecutionCall {
    const MAGIC: [u8; 4] = *b"AGEX";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_runtime_state(&mut encoder, &self.state);
        encode_actor_invocation(&mut encoder, &self.invocation);
        encoder.bytes(&self.authority.encode());
        encoder.u64(self.observed_slot);
        encoder.bool(self.recovery_only);
        encoder.bytes(&self.actor_pvm);
        encode_blob(&mut encoder, &self.actor_schema.reference);
        encoder.bytes(&self.actor_schema.bytes);
        encode_blob(&mut encoder, &self.actor_policies.reference);
        encoder.bytes(&self.actor_policies.bytes);
        encoder.option(&self.installation_data, |encoder, data| {
            encode_blob(encoder, &data.reference);
            encoder.bytes(&data.bytes);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let call = Self {
            state: decode_runtime_state(decoder)?,
            invocation: decode_actor_invocation(decoder)?,
            authority: super::authority::ActorInvocationReceipt::decode(&decoder.bytes()?)?,
            observed_slot: decoder.u64()?,
            recovery_only: decoder.bool()?,
            actor_pvm: {
                // Borrow first so the protocol limit remains at the allocation
                // boundary and oversized guest input is never copied.
                let bytes = decoder.bytes_ref()?;
                if bytes.len() > super::execution::MAX_EXECUTION_PROGRAM_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                bytes.to_vec()
            },
            actor_schema: RuntimeBlob {
                reference: decode_blob(decoder)?,
                bytes: {
                    let bytes = decoder.bytes_ref()?;
                    if bytes.len() > super::schema::MAX_ENCODED_BYTES {
                        return Err(DecodeError::LimitExceeded);
                    }
                    bytes.to_vec()
                },
            },
            actor_policies: RuntimeBlob {
                reference: decode_blob(decoder)?,
                bytes: {
                    let bytes = decoder.bytes_ref()?;
                    if bytes.len() > super::execution::MAX_EXECUTION_POLICY_BYTES {
                        return Err(DecodeError::LimitExceeded);
                    }
                    bytes.to_vec()
                },
            },
            installation_data: decoder.option(|decoder| {
                let reference = decode_blob(decoder)?;
                let len = decoder.u32()? as usize;
                if len > super::MAX_INSTALLATION_DATA_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                let bytes = decoder.take(len)?;
                Ok(RuntimeBlob {
                    reference,
                    bytes: bytes.to_vec(),
                })
            })?,
        };
        call.invocation
            .validate()
            .map_err(|_| DecodeError::NonCanonical)?;
        let artifacts_absent = call.actor_pvm.is_empty()
            && call.actor_schema.reference.hash == Hash::ZERO
            && call.actor_schema.reference.len == 0
            && call.actor_schema.bytes.is_empty()
            && call.actor_policies.reference.hash == Hash::ZERO
            && call.actor_policies.reference.len == 0
            && call.actor_policies.bytes.is_empty()
            && call.installation_data.is_none();
        let artifacts_valid = !call.actor_pvm.is_empty()
            && call.actor_pvm.len() <= super::execution::MAX_EXECUTION_PROGRAM_BYTES
            && ProgramId::of_pvm(&call.actor_pvm) == call.invocation.program
            && call
                .actor_schema
                .reference
                .matches(&call.actor_schema.bytes)
            && super::schema::decode(&call.actor_schema.bytes).is_some()
            && call
                .actor_policies
                .reference
                .matches(&call.actor_policies.bytes)
            && crate::service::PackageRolePolicies::decode(&call.actor_policies.bytes).is_ok()
            && call.installation_data.as_ref().is_none_or(|data| {
                data.bytes.len() <= super::MAX_INSTALLATION_DATA_BYTES
                    && data.reference.hash != Hash::ZERO
                    && data.reference.matches(&data.bytes)
            });
        if (call.recovery_only && !artifacts_absent) || (!call.recovery_only && !artifacts_valid) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(call)
    }
}

impl ServiceWire for RuntimeExecutionReturn {
    const MAGIC: [u8; 4] = *b"AGER";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&super::RUNTIME_ABI_ID.0);
        encode_runtime_state(&mut encoder, &self.state);
        encode_execution_result(&mut encoder, &self.result);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
            return Err(DecodeError::InvalidPlatform);
        }
        let state = decode_runtime_state(decoder)?;
        let result = decode_execution_result(decoder)?;
        Ok(Self { state, result })
    }
}

impl RuntimeState {
    pub fn is_empty(&self) -> bool {
        self.control.is_empty()
            && self.linear.is_empty()
            && self.merge.is_empty()
            && self.local.is_empty()
    }

    pub fn component(&self, lane: StateLane) -> &[u8] {
        match lane {
            StateLane::Linear => &self.linear,
            StateLane::Merge => &self.merge,
            StateLane::Local => &self.local,
        }
    }

    /// Checked aggregate bytes owned by the opaque runtime image.
    pub fn encoded_len(&self) -> Option<usize> {
        self.control
            .len()
            .checked_add(self.linear.len())?
            .checked_add(self.merge.len())?
            .checked_add(self.local.len())
    }
}

fn decode_bounded_list<T>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    let len = decoder.u32()? as usize;
    if len > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    // Validate the declared cardinality before allocating, then grow only
    // after a complete item consumed authenticated input.
    let mut values = Vec::new();
    for _ in 0..len {
        let before = decoder.remaining();
        let value = decode(decoder)?;
        if decoder.remaining() >= before {
            return Err(DecodeError::NonCanonical);
        }
        values
            .try_reserve(1)
            .map_err(|_| DecodeError::LimitExceeded)?;
        values.push(value);
    }
    Ok(values)
}

pub(crate) const MAX_CLEAN_MANAGEMENT_RESULT_BYTES: usize = 8 * 1024;
const STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC: [u8; 4] = *b"SCAP";
const STANDARD_CLEAN_ACTOR_INSTALLATIONS_MAGIC: [u8; 4] = *b"SCI2";
const STANDARD_CLEAN_INVOCATION_ERRORS_MAGIC: [u8; 4] = *b"SCER";
const STANDARD_SEQUENCED_RETIREMENT_MAGIC: [u8; 4] = *b"SQRT";
const STANDARD_PROGRAM_BINDINGS_MAGIC: [u8; 4] = *b"SPB1";

/// Optional last section of the control component: the guest-verified
/// program bindings. Absent while empty, so an image without bindings encodes
/// exactly as before the section existed.
fn encode_program_bindings(encoder: &mut Encoder<'_>, state: &StandardRuntimeState) {
    if state.program_bindings.is_empty() {
        return;
    }
    encoder.0.extend_from_slice(&STANDARD_PROGRAM_BINDINGS_MAGIC);
    encoder.u16(1);
    encoder.list(&state.program_bindings, |encoder, binding| {
        encoder.fixed(&binding.actor.0);
        encoder.fixed(&binding.program.0);
        encoder.fixed(&binding.reference.hash.0);
        encoder.u64(binding.reference.len);
    });
}

fn decode_program_bindings(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<super::standard::StandardProgramBinding>, DecodeError> {
    if decoder.exhausted() {
        return Ok(Vec::new());
    }
    if decoder.take(4)? != STANDARD_PROGRAM_BINDINGS_MAGIC || decoder.u16()? != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let bindings = decode_bounded_list(
        decoder,
        super::contract::STANDARD_MAX_ACTORS as usize,
        |decoder| {
            Ok(super::standard::StandardProgramBinding {
                actor: ActorId(decoder.fixed()?),
                program: ProgramId(decoder.fixed()?),
                reference: crate::agent_sdk::BlobRef {
                    hash: crate::agent_sdk::Hash(decoder.fixed()?),
                    len: decoder.u64()?,
                },
            })
        },
    )?;
    // Present only when nonempty; ordering and membership are checked when
    // the runtime is restored.
    if bindings.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(bindings)
}

/// Optional trailing section of one result component: its sequenced
/// retirement watermark. Absent while zero, so a component that never
/// compacted encodes exactly as before this section existed.
fn encode_sequenced_retirement(
    encoder: &mut Encoder<'_>,
    state: &StandardRuntimeState,
    storage: super::InvocationResultStorage,
) {
    let retired_through = state.sequenced_retired_through.get(storage);
    if retired_through == 0 {
        return;
    }
    encoder
        .0
        .extend_from_slice(&STANDARD_SEQUENCED_RETIREMENT_MAGIC);
    encoder.u16(1);
    encoder.u64(retired_through);
}

/// The errors section and the watermark section are both optional, in that
/// order. Returns both, leaving the decoder at the component's end.
fn decode_result_component_tail(
    decoder: &mut Decoder<'_>,
    storage: super::InvocationResultStorage,
) -> Result<(Vec<super::standard::StandardCleanInvocationError>, u64), DecodeError> {
    let next_is = |decoder: &Decoder<'_>, magic: &[u8; 4]| {
        decoder.peek(magic.len()) == Some(&magic[..])
    };
    let errors = if next_is(decoder, &STANDARD_SEQUENCED_RETIREMENT_MAGIC)
        || next_is(decoder, &STANDARD_PROGRAM_BINDINGS_MAGIC)
    {
        Vec::new()
    } else {
        decode_clean_invocation_errors(decoder, storage)?
    };
    if decoder.exhausted() || next_is(decoder, &STANDARD_PROGRAM_BINDINGS_MAGIC) {
        return Ok((errors, 0));
    }
    if decoder.take(4)? != STANDARD_SEQUENCED_RETIREMENT_MAGIC || decoder.u16()? != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let retired_through = decoder.u64()?;
    if retired_through == 0 {
        return Err(DecodeError::NonCanonical);
    }
    Ok((errors, retired_through))
}

pub(crate) fn encode_clean_invocation_error(
    value: &super::standard::StandardCleanInvocationError,
) -> Vec<u8> {
    use crate::agent_sdk::wire::CanonicalWire as _;
    let mut bytes = Vec::new();
    let mut encoder = Encoder(&mut bytes);
    encode_clean_invocation_result(&mut encoder, &value.binding);
    encoder.bytes(
        &crate::agent_sdk::RuntimeTransition {
            state: crate::agent_sdk::RuntimeState::default(),
            outcome: crate::agent_sdk::RuntimeOutcome::Completed(Err(value.error)),
        }
        .encode()
        .expect("typed invocation error is canonical"),
    );
    bytes
}

fn encode_clean_invocation_errors(
    encoder: &mut Encoder<'_>,
    state: &StandardRuntimeState,
    storage: super::InvocationResultStorage,
) {
    let errors = state
        .clean_invocation_errors
        .iter()
        .filter(|item| item.storage() == storage)
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return;
    }
    encoder
        .0
        .extend_from_slice(&STANDARD_CLEAN_INVOCATION_ERRORS_MAGIC);
    encoder.u16(1);
    encoder.list(&errors, |encoder, item| {
        encoder
            .0
            .extend_from_slice(&encode_clean_invocation_error(item))
    });
}

fn decode_clean_invocation_errors(
    decoder: &mut Decoder<'_>,
    storage: super::InvocationResultStorage,
) -> Result<Vec<super::standard::StandardCleanInvocationError>, DecodeError> {
    use crate::agent_sdk::wire::CanonicalWire as _;
    if decoder.exhausted() {
        return Ok(Vec::new());
    }
    if decoder.take(4)? != STANDARD_CLEAN_INVOCATION_ERRORS_MAGIC || decoder.u16()? != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let errors = decode_bounded_list(
        decoder,
        super::standard::MAX_INVOCATION_RESULTS_PER_LANE,
        |decoder| {
            let binding = decode_clean_invocation_result_binding(decoder)?;
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > 256 {
                return Err(DecodeError::LimitExceeded);
            }
            let transition = crate::agent_sdk::RuntimeTransition::decode(bytes)
                .map_err(|_| DecodeError::NonCanonical)?;
            let crate::agent_sdk::RuntimeOutcome::Completed(Err(error)) = transition.outcome else {
                return Err(DecodeError::NonCanonical);
            };
            let value = super::standard::StandardCleanInvocationError { binding, error };
            if transition.state != crate::agent_sdk::RuntimeState::default()
                || !error.is_durable_exact_outcome()
                || value.storage() != storage
                || !StandardAgentRuntime::clean_error_authorization_window_is_valid(
                    &value.binding.authorization,
                    error,
                    value.binding.observed_slot,
                )
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(value)
        },
    )?;
    if errors.is_empty() || errors.windows(2).any(|pair| pair[0].key() >= pair[1].key()) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(errors)
}

pub(crate) fn encode_clean_management_result(
    result: &Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>,
) -> Vec<u8> {
    use crate::agent_sdk::wire::CanonicalWire as _;
    crate::agent_sdk::RuntimeTransition {
        state: crate::agent_sdk::RuntimeState::default(),
        outcome: crate::agent_sdk::RuntimeOutcome::Management(result.clone()),
    }
    .encode()
    .expect("persisted clean management result is canonical")
}

pub(crate) fn decode_clean_management_result(
    bytes: &[u8],
) -> Result<Result<crate::agent_sdk::ManagementReply, crate::agent_sdk::ManagementError>, DecodeError>
{
    use crate::agent_sdk::wire::CanonicalWire as _;
    let transition = crate::agent_sdk::RuntimeTransition::decode(bytes)
        .map_err(|_| DecodeError::NonCanonical)?;
    if !transition.state.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    match transition.outcome {
        crate::agent_sdk::RuntimeOutcome::Management(result) => Ok(result),
        _ => Err(DecodeError::NonCanonical),
    }
}

/// Encode the standard runtime's policy state and three actor-state lanes as
/// independently durable opaque components.
pub fn encode_standard_runtime_state(state: &StandardRuntimeState) -> RuntimeState {
    let mut control = Vec::new();
    let mut encoder = Encoder(&mut control);
    encoder.fixed(&super::RUNTIME_ABI_ID.0);
    encoder.option(&state.config, encode_config);
    encoder.option(&state.clean_creation_descriptor, |encoder, descriptor| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        encoder.bytes(
            &descriptor
                .encode()
                .expect("persisted clean creation descriptor is canonical"),
        )
    });
    encoder.option(&state.clean_descriptor, |encoder, descriptor| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        encoder.bytes(
            &descriptor
                .encode()
                .expect("persisted clean current descriptor is canonical"),
        )
    });
    encoder.option(&state.clean_authority_epoch_high_water, |encoder, epoch| {
        encoder.u64(*epoch)
    });
    encoder.option(
        &state.clean_decision_sequence_high_water,
        |encoder, sequence| encoder.u64(*sequence),
    );
    encoder.u64(state.clean_acknowledged_through);
    encoder.list(&state.clean_management_dispositions, |encoder, item| {
        encoder.fixed(item.authority.as_bytes());
        encoder.fixed(item.request.as_bytes());
        encoder.u64(item.epoch);
        encoder.u64(item.sequence);
        encoder.u64(item.observed_slot);
        encoder.bytes(&encode_clean_management_result(&item.result));
    });
    encoder.option(&state.active_resource_policy, |encoder, policy| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        encoder.bytes(
            &policy
                .encode()
                .expect("persisted active resource policy is canonical"),
        );
    });
    encoder.option(
        &state.private_runtime_control_commitment,
        |encoder, control| encoder.fixed(control.as_bytes()),
    );
    encoder.option(
        &state.private_runtime_control_sequence,
        |encoder, sequence| encoder.u64(*sequence),
    );
    encoder.option(
        &state.private_authority_epoch_high_water,
        |encoder, epoch| encoder.u64(*epoch),
    );
    encoder.option(&state.private_control_slot_high_water, |encoder, slot| {
        encoder.u64(*slot)
    });
    encoder.list(&state.private_management_dispositions, |encoder, item| {
        encoder.fixed(item.authority.as_bytes());
        encoder.fixed(item.control.as_bytes());
        encoder.fixed(item.request.as_bytes());
        encoder.u64(item.sequence);
        encoder.option(&item.previous, |encoder, previous| {
            encoder.fixed(previous.as_bytes())
        });
        encoder.u64(item.epoch);
        encoder.u64(item.observed_slot);
        encoder.bytes(&encode_clean_management_result(&item.result));
    });
    encoder.option(&state.system_authority, |encoder, authority| {
        encoder.bytes(&authority.encode())
    });
    encoder.list(&state.actors, |encoder, actor| {
        encode_entry(encoder, &actor.record.entry);
        encoder.fixed(&actor.record.state_generation.0);
        encoder.fixed(actor.record.installation_id.as_bytes());
        encoder.fixed(&actor.record.registry_reservation.0);
        encoder.fixed(&actor.record.install_request_commitment.0);
        encoder.fixed(&actor.record.producer.0);
        encode_blob(encoder, &actor.record.package);
        encode_blob(encoder, &actor.record.agent_schema);
        encode_blob(encoder, &actor.record.role_policies);
        encoder.fixed(&actor.record.constructor_abi.0);
        encoder.option(&actor.record.installation_data, encode_blob);
        encoder.fixed(&actor.record.state_layout.0);
        super::contract::encode_actor_contract(encoder, actor.record.contract);
        encode_requirements(encoder, actor.record.requirements);
        encode_debt(encoder, actor.debt);
    });
    encoder.list(
        &state.retired_installation_ids,
        |encoder, installation_id| encoder.fixed(installation_id.as_bytes()),
    );
    encoder.option(&state.authority_slot_high_water, |encoder, slot| {
        encoder.u64(*slot)
    });
    encoder.option(&state.authority_sequence_high_water, |encoder, sequence| {
        encoder.u64(*sequence)
    });
    encoder.list(&state.authority_dispositions, |encoder, disposition| {
        encoder.fixed(&disposition.credential.0);
        encoder.u64(disposition.sequence);
        encoder.fixed(&disposition.claim.0);
        encoder.fixed(&disposition.operation.0);
        match &disposition.result {
            Ok(reply) => {
                encoder.bool(true);
                encode_reply(encoder, reply);
            }
            Err(error) => {
                encoder.bool(false);
                encode_error(encoder, *error);
            }
        }
    });
    encoder.option(&state.control_authority_slot, |encoder, slot| {
        encoder.u64(*slot)
    });
    encoder.list(
        &state
            .invocation_results
            .iter()
            .filter(|result| result.storage == super::InvocationResultStorage::Control)
            .collect::<Vec<_>>(),
        |encoder, result| {
            encoder.u8(encode_invocation_scope(result.scope));
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.incarnation.0);
            encoder.fixed(&result.request.0);
            encode_execution_reply(encoder, &result.reply);
            encoder.option(&result.clean, encode_clean_invocation_result);
        },
    );
    encoder.list(
        &state
            .clean_invocation_acknowledgements
            .iter()
            .filter(|item| {
                item.mode.result_storage() == crate::agent_sdk::InvocationResultStorage::Control
            })
            .collect::<Vec<_>>(),
        |encoder, acknowledgement| {
            encode_clean_invocation_acknowledgement(encoder, acknowledgement)
        },
    );
    encoder.list(
        &state
            .machine_continuations
            .iter()
            .filter(|continuation| {
                continuation.mode.result_storage() == super::InvocationResultStorage::Control
            })
            .collect::<Vec<_>>(),
        |encoder, continuation| encode_machine_continuation(encoder, continuation),
    );
    if let Some(packages) = &state.clean_actor_packages {
        encoder
            .0
            .extend_from_slice(&STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC);
        encoder.list(packages, |encoder, package| {
            encoder.fixed(package.actor.as_bytes());
            encoder.u32(package.contract.actor_abi);
            encoder.u8(package.requirements.lanes.bits());
            encoder.bool(package.requirements.scheduling);
            encoder.list(
                package.requirements.proof_systems.as_slice(),
                |encoder, proof_system| encoder.fixed(proof_system.as_bytes()),
            );
        });
    }
    if let Some(installations) = &state.clean_actor_installations {
        encoder
            .0
            .extend_from_slice(&STANDARD_CLEAN_ACTOR_INSTALLATIONS_MAGIC);
        encoder.list(installations, |encoder, installation| {
            use crate::agent_sdk::wire::CanonicalWire as _;
            encoder.fixed(installation.actor.as_bytes());
            encoder.fixed(installation.commitment.as_bytes());
            encoder.u32(installation.contract.actor_abi);
            encoder.u8(installation.requirements.lanes.bits());
            encoder.bool(installation.requirements.scheduling);
            encoder.list(
                installation.requirements.proof_systems.as_slice(),
                |encoder, proof_system| encoder.fixed(proof_system.as_bytes()),
            );
            let plan = crate::agent_sdk::authority::ManagementAuthorizationPlan::Install(
                alloc::boxed::Box::new(installation.original.clone()),
            );
            encoder.bytes(&plan.encode().expect("valid original install plan"));
        });
    }
    encode_clean_invocation_errors(&mut encoder, state, super::InvocationResultStorage::Control);
    encode_sequenced_retirement(&mut encoder, state, super::InvocationResultStorage::Control);
    encode_program_bindings(&mut encoder, state);
    RuntimeState {
        control,
        linear: encode_standard_lane(state, StateLane::Linear),
        merge: encode_standard_lane(state, StateLane::Merge),
        local: encode_standard_lane(state, StateLane::Local),
    }
}

/// A clean Create starts from the wholly absent runtime state, while the
/// canonical Standard successor materializes empty lane envelopes alongside
/// Control. Treat those envelopes as initialization, never as actor-owned
/// lane mutation. Any revision, value, result, acknowledgement, or
/// continuation makes the bytes differ from this exact empty encoding.
pub(crate) fn clean_create_initializes_only_empty_lanes(
    before: &RuntimeState,
    after: &RuntimeState,
) -> bool {
    if !before.is_empty() || decode_standard_runtime_state(after).is_err() {
        return false;
    }
    let empty = encode_standard_runtime_state(&StandardRuntimeState::default());
    after.linear == empty.linear && after.merge == empty.merge && after.local == empty.local
}

/// Common public management lane boundary for image and journal hosts.
/// Request authentication and exact reply validation must happen separately.
pub(crate) fn clean_management_lane_changes_allowed(
    request: &crate::agent_sdk::ManagementRequest,
    before: &RuntimeState,
    after: &RuntimeState,
    success: bool,
) -> bool {
    use crate::agent_sdk::{LaneSet, ManagementRequest, StateLane};
    if matches!(
        request,
        ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory
    ) {
        return before == after;
    }
    if matches!(request, ManagementRequest::PrivateControl { .. }) {
        return false;
    }
    let allowed = if success {
        match request {
            ManagementRequest::Install(install) => install.requirements.lanes,
            ManagementRequest::UpgradeActor(upgrade) => upgrade.requirements.lanes,
            ManagementRequest::UpgradeRuntime(upgrade) => upgrade.capabilities.lanes,
            // The admitted runtime resolves the retired actor's ownership;
            // removal may clear any lane. This is not authorization by itself.
            ManagementRequest::RemoveLeaf { .. } => LaneSet::ALL,
            _ => LaneSet::NONE,
        }
    } else {
        LaneSet::NONE
    };
    if success
        && matches!(request, ManagementRequest::Create(_))
        && clean_create_initializes_only_empty_lanes(before, after)
    {
        return true;
    }
    [
        (StateLane::Linear, &before.linear, &after.linear),
        (StateLane::Merge, &before.merge, &after.merge),
        (StateLane::Local, &before.local, &after.local),
    ]
    .into_iter()
    .all(|(lane, prior, next)| prior == next || allowed.bits() & LaneSet::of(lane).bits() != 0)
}

/// Decode all opaque standard-runtime components. Lane maps are sparse and
/// independently keyed: matching active generations hydrate actor state,
/// missing matching entries mean fresh empty state, and nonmatching entries
/// remain historical until checkpoint compaction.
pub fn decode_standard_runtime_state(
    state: &RuntimeState,
) -> Result<StandardRuntimeState, DecodeError> {
    let decoded = decode_standard_runtime_components(state)?;
    StandardAgentRuntime::restore(decoded.clone()).map_err(|_| DecodeError::NonCanonical)?;
    Ok(decoded)
}

/// Execution consumes the validated runtime instead of restoring a validation
/// clone and then restoring the same components a second time. No unchecked
/// components leave this helper, including on the empty-state path.
fn restore_standard_runtime_state(
    state: &RuntimeState,
) -> Result<(StandardAgentRuntime, usize), DecodeError> {
    let decoded = decode_standard_runtime_components(state)?;
    let state_limit = standard_state_limit(&decoded);
    let runtime = StandardAgentRuntime::restore(decoded).map_err(|_| DecodeError::NonCanonical)?;
    Ok((runtime, state_limit))
}

// Structural decoding only. Callers must restore before using this state.
fn decode_standard_runtime_components(
    state: &RuntimeState,
) -> Result<StandardRuntimeState, DecodeError> {
    if state
        .encoded_len()
        .is_none_or(|bytes| bytes > super::execution::MAX_RUNTIME_STATE_BYTES)
    {
        return Err(DecodeError::LimitExceeded);
    }
    if state.is_empty() {
        return Ok(StandardRuntimeState::default());
    }
    if state.control.is_empty()
        || state.linear.is_empty()
        || state.merge.is_empty()
        || state.local.is_empty()
    {
        return Err(DecodeError::NonCanonical);
    }
    let mut decoder = Decoder::new(&state.control);
    if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID {
        return Err(DecodeError::InvalidPlatform);
    }
    // Clean SDK state carries an internal AgentConfig projection whose
    // AgentId is derived in the SDK domain. Decode its shape first; restore
    // below validates it against the exact persisted SDK descriptor. Legacy
    // standalone AgentConfig and lifecycle decoders still use decode_config
    // and therefore retain the historical identity-domain validation.
    let config = decoder.option(decode_config_unvalidated)?;
    let clean_creation_descriptor = decoder.option(|decoder| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let bytes = decoder.bytes_ref().and_then(|bytes| {
            (bytes.len() <= crate::agent_sdk::wire::MAX_AGENT_DESCRIPTOR_WIRE_BYTES)
                .then_some(bytes)
                .ok_or(DecodeError::LimitExceeded)
        })?;
        crate::agent_sdk::AgentDescriptor::decode(bytes).map_err(|_| DecodeError::NonCanonical)
    })?;
    let clean_descriptor = decoder.option(|decoder| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let bytes = decoder.bytes_ref().and_then(|bytes| {
            (bytes.len() <= crate::agent_sdk::wire::MAX_AGENT_DESCRIPTOR_WIRE_BYTES)
                .then_some(bytes)
                .ok_or(DecodeError::LimitExceeded)
        })?;
        crate::agent_sdk::AgentDescriptor::decode(bytes).map_err(|_| DecodeError::NonCanonical)
    })?;
    let clean_authority_epoch_high_water = decoder.option(Decoder::u64)?;
    let clean_decision_sequence_high_water = decoder.option(Decoder::u64)?;
    let clean_acknowledged_through = decoder.u64()?;
    let clean_management_dispositions = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_AUTHORITY_DISPOSITIONS,
        |decoder| {
            let authority = crate::agent_sdk::Hash(decoder.fixed()?);
            let request = crate::agent_sdk::Hash(decoder.fixed()?);
            let epoch = decoder.u64()?;
            let sequence = decoder.u64()?;
            let observed_slot = decoder.u64()?;
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let result = decode_clean_management_result(bytes)?;
            Ok(StandardCleanManagementDisposition {
                authority,
                request,
                epoch,
                sequence,
                observed_slot,
                result,
            })
        },
    )?;
    let active_resource_policy = decoder.option(|decoder| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > crate::agent_sdk::wire::MAX_RUNTIME_RESOURCE_POLICY_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        crate::agent_sdk::contract::RuntimeResourcePolicy::decode(bytes)
            .map_err(|_| DecodeError::NonCanonical)
    })?;
    let private_runtime_control_commitment = decoder.option(|decoder| {
        let value = crate::agent_sdk::Hash(decoder.fixed()?);
        (value != crate::agent_sdk::Hash::ZERO)
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    })?;
    let private_runtime_control_sequence = decoder.option(Decoder::u64)?;
    let private_authority_epoch_high_water = decoder.option(Decoder::u64)?;
    let private_control_slot_high_water = decoder.option(Decoder::u64)?;
    let private_management_dispositions = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_AUTHORITY_DISPOSITIONS,
        |decoder| {
            let authority = crate::agent_sdk::Hash(decoder.fixed()?);
            let control = crate::agent_sdk::Hash(decoder.fixed()?);
            let request = crate::agent_sdk::Hash(decoder.fixed()?);
            let sequence = decoder.u64()?;
            let previous = decoder.option(|decoder| {
                let value = crate::agent_sdk::Hash(decoder.fixed()?);
                (value != crate::agent_sdk::Hash::ZERO)
                    .then_some(value)
                    .ok_or(DecodeError::NonCanonical)
            })?;
            let epoch = decoder.u64()?;
            let observed_slot = decoder.u64()?;
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > MAX_CLEAN_MANAGEMENT_RESULT_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            let result = decode_clean_management_result(bytes)?;
            Ok(StandardPrivateManagementDisposition {
                authority,
                control,
                request,
                sequence,
                previous,
                epoch,
                observed_slot,
                result,
            })
        },
    )?;
    let system_authority = decoder.option(|decoder| {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_STATE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        super::system_authority::SystemAuthorityState::decode(bytes)
    })?;
    let actors = decode_bounded_list(
        &mut decoder,
        super::contract::STANDARD_MAX_ACTORS as usize,
        |decoder| {
            let entry = decode_entry(decoder)?;
            let state_generation = Hash(decoder.fixed()?);
            let installation_id = crate::service::InstallationId(decoder.fixed()?);
            let registry_reservation = Hash(decoder.fixed()?);
            let install_request_commitment = Hash(decoder.fixed()?);
            if state_generation == Hash::ZERO
                || installation_id == crate::service::InstallationId::ZERO
                || registry_reservation == Hash::ZERO
                || install_request_commitment == Hash::ZERO
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardActorState {
                record: super::ActorRecord {
                    entry,
                    state_generation,
                    installation_id,
                    registry_reservation,
                    install_request_commitment,
                    producer: ProducerId(decoder.fixed()?),
                    package: decode_blob(decoder)?,
                    agent_schema: decode_blob(decoder)?,
                    role_policies: decode_blob(decoder)?,
                    constructor_abi: Hash(decoder.fixed()?),
                    installation_data: decoder.option(decode_blob)?,
                    state_layout: Hash(decoder.fixed()?),
                    contract: super::contract::decode_actor_contract(decoder)?,
                    requirements: decode_requirements(decoder)?,
                },
                debt: decode_debt(decoder)?,
            })
        },
    )?;
    let retired_installation_ids = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_RETIRED_INSTALLATION_IDS,
        |decoder| {
            let installation_id = crate::service::InstallationId(decoder.fixed()?);
            if installation_id == crate::service::InstallationId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(installation_id)
        },
    )?;
    if retired_installation_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(DecodeError::NonCanonical);
    }
    let authority_slot_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_sequence_high_water = decoder.option(|decoder| decoder.u64())?;
    let authority_dispositions = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_AUTHORITY_DISPOSITIONS,
        |decoder| {
            Ok(StandardAuthorityDisposition {
                credential: crate::service::CredentialId(decoder.fixed()?),
                sequence: decoder.u64()?,
                claim: Hash(decoder.fixed()?),
                operation: Hash(decoder.fixed()?),
                result: if decoder.bool()? {
                    Ok(decode_reply(decoder)?)
                } else {
                    Err(decode_error(decoder)?)
                },
            })
        },
    )?;
    let control_authority_slot = decoder.option(Decoder::u64)?;
    let mut invocation_results = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_RESULTS_PER_LANE,
        |decoder| {
            let scope = decode_invocation_scope(decoder.u8()?)?;
            let invocation = crate::service::InvocationId(decoder.fixed()?);
            let incarnation = Hash(decoder.fixed()?);
            let request = Hash(decoder.fixed()?);
            let reply = decode_execution_reply(decoder)?;
            let clean = decoder.option(decode_clean_invocation_result)?;
            if scope != InvocationScope::Ordered
                || invocation == crate::service::InvocationId::ZERO
                || incarnation == Hash::ZERO
                || request == Hash::ZERO
                || reply.invocation != invocation
                || reply.incarnation != incarnation
                || reply.mode.invocation_scope() != scope
                || reply.mode.result_storage() != super::InvocationResultStorage::Control
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardInvocationResult {
                scope,
                invocation,
                incarnation,
                request,
                reply,
                storage: super::InvocationResultStorage::Control,
                clean,
            })
        },
    )?;
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
    {
        return Err(DecodeError::NonCanonical);
    }
    let mut clean_invocation_acknowledgements = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE,
        |decoder| {
            decode_clean_invocation_acknowledgement(
                decoder,
                super::InvocationResultStorage::Control,
            )
        },
    )?;
    let mut machine_continuations = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_MACHINE_CONTINUATIONS,
        |decoder| decode_machine_continuation(decoder, super::InvocationResultStorage::Control),
    )?;
    if machine_continuations
        .windows(2)
        .any(|pair| pair[0].ready_sequence >= pair[1].ready_sequence)
    {
        return Err(DecodeError::NonCanonical);
    }
    let clean_actor_packages = if decoder.exhausted() {
        None
    } else {
        if decoder.take(STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC.len())?
            != STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC
        {
            return Err(DecodeError::NonCanonical);
        }
        Some(decode_bounded_list(
            &mut decoder,
            super::contract::STANDARD_MAX_ACTORS as usize,
            |decoder| {
                let actor = crate::agent_sdk::ActorId(decoder.fixed()?);
                let contract = crate::agent_sdk::contract::ActorPackageContract {
                    actor_abi: decoder.u32()?,
                };
                let lanes = crate::agent_sdk::LaneSet::from_bits(decoder.u8()?)
                    .ok_or(DecodeError::NonCanonical)?;
                let scheduling = decoder.bool()?;
                let proof_systems = decode_bounded_list(
                    decoder,
                    crate::agent_sdk::proof_system::MAX_PROOF_SYSTEMS,
                    |decoder| Ok(crate::agent_sdk::Hash(decoder.fixed()?)),
                )?;
                let proof_systems = crate::agent_sdk::ProofSystemSet::from_sorted(&proof_systems)
                    .map_err(|_| DecodeError::NonCanonical)?;
                if actor == crate::agent_sdk::ActorId::ZERO || !contract.is_valid() {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(StandardCleanActorPackage {
                    actor,
                    contract,
                    requirements: crate::agent_sdk::RuntimeRequirements {
                        lanes,
                        scheduling,
                        proof_systems,
                    },
                })
            },
        )?)
    };
    let clean_actor_installations = if decoder.exhausted() {
        None
    } else {
        if decoder.take(STANDARD_CLEAN_ACTOR_INSTALLATIONS_MAGIC.len())?
            != STANDARD_CLEAN_ACTOR_INSTALLATIONS_MAGIC
        {
            return Err(DecodeError::NonCanonical);
        }
        Some(decode_bounded_list(
            &mut decoder,
            super::contract::STANDARD_MAX_ACTORS as usize,
            |decoder| {
                let actor = crate::agent_sdk::ActorId(decoder.fixed()?);
                let commitment = crate::agent_sdk::Hash(decoder.fixed()?);
                let contract = crate::agent_sdk::contract::ActorPackageContract {
                    actor_abi: decoder.u32()?,
                };
                let lanes = crate::agent_sdk::LaneSet::from_bits(decoder.u8()?)
                    .ok_or(DecodeError::NonCanonical)?;
                let scheduling = decoder.bool()?;
                let proof_systems = decode_bounded_list(
                    decoder,
                    crate::agent_sdk::proof_system::MAX_PROOF_SYSTEMS,
                    |decoder| Ok(crate::agent_sdk::Hash(decoder.fixed()?)),
                )?;
                let proof_systems = crate::agent_sdk::ProofSystemSet::from_sorted(&proof_systems)
                    .map_err(|_| DecodeError::NonCanonical)?;
                if actor == crate::agent_sdk::ActorId::ZERO
                    || commitment == crate::agent_sdk::Hash::ZERO
                    || !contract.is_valid()
                {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(StandardCleanActorInstallation {
                    actor,
                    commitment,
                    contract,
                    requirements: crate::agent_sdk::RuntimeRequirements {
                        lanes,
                        scheduling,
                        proof_systems,
                    },
                    original: {
                        use crate::agent_sdk::wire::CanonicalWire as _;
                        let bytes = decoder.bytes_ref()?;
                        if bytes.len()
                            > crate::agent_sdk::wire::MAX_MANAGEMENT_AUTHORIZATION_PLAN_WIRE_BYTES
                        {
                            return Err(DecodeError::LimitExceeded);
                        }
                        match crate::agent_sdk::authority::ManagementAuthorizationPlan::decode(
                            bytes,
                        )
                        .map_err(|_| DecodeError::NonCanonical)?
                        {
                            crate::agent_sdk::authority::ManagementAuthorizationPlan::Install(
                                plan,
                            ) => *plan,
                            _ => return Err(DecodeError::NonCanonical),
                        }
                    },
                })
            },
        )?)
    };
    let (mut clean_invocation_errors, control_retired_through) =
        decode_result_component_tail(&mut decoder, super::InvocationResultStorage::Control)?;
    let program_bindings = decode_program_bindings(&mut decoder)?;
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes);
    }
    let mut sequenced_retired_through = super::standard::StandardSequencedRetirement {
        control: control_retired_through,
        ..Default::default()
    };
    let mut lane_revisions = super::standard::StandardLaneRevisions::default();
    let mut lane_state = StandardLaneState::default();
    for (lane, bytes) in [
        (StateLane::Linear, state.linear.as_slice()),
        (StateLane::Merge, state.merge.as_slice()),
        (StateLane::Local, state.local.as_slice()),
    ] {
        let remaining_continuations = super::standard::MAX_MACHINE_CONTINUATIONS
            .checked_sub(machine_continuations.len())
            .ok_or(DecodeError::LimitExceeded)?;
        let decoded = decode_standard_lane(bytes, lane, remaining_continuations)?;
        match lane {
            StateLane::Linear => {
                lane_revisions.linear = decoded.revision;
                lane_revisions.linear_authority_slot = decoded.authority_slot;
            }
            StateLane::Merge => {
                lane_revisions.merge = decoded.revision;
                lane_revisions.merge_authority_slot = decoded.authority_slot;
            }
            StateLane::Local => {
                lane_revisions.local = decoded.revision;
                lane_revisions.local_authority_slot = decoded.authority_slot;
            }
        }
        match lane {
            StateLane::Linear => lane_state.linear = decoded.values,
            StateLane::Merge => lane_state.merge = decoded.values,
            StateLane::Local => lane_state.local = decoded.values,
        }
        match lane {
            StateLane::Linear => sequenced_retired_through.linear = decoded.retired_through,
            StateLane::Merge => sequenced_retired_through.merge = decoded.retired_through,
            StateLane::Local => sequenced_retired_through.local = decoded.retired_through,
        }
        invocation_results.extend(decoded.invocation_results);
        clean_invocation_errors.extend(decoded.clean_invocation_errors);
        clean_invocation_acknowledgements.extend(decoded.clean_invocation_acknowledgements);
        machine_continuations.extend(decoded.machine_continuations);
    }
    invocation_results.sort_unstable_by_key(|result| (result.scope, result.invocation));
    clean_invocation_errors.sort_unstable_by_key(|item| item.key());
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
    {
        return Err(DecodeError::NonCanonical);
    }
    if machine_continuations.windows(2).any(|pair| {
        (
            invocation_result_storage_tag(pair[0].mode.result_storage()),
            pair[0].ready_sequence,
        ) >= (
            invocation_result_storage_tag(pair[1].mode.result_storage()),
            pair[1].ready_sequence,
        )
    }) {
        return Err(DecodeError::NonCanonical);
    }
    let state = StandardRuntimeState {
        config,
        clean_creation_descriptor,
        clean_descriptor,
        clean_authority_epoch_high_water,
        clean_decision_sequence_high_water,
        clean_acknowledged_through,
        clean_management_dispositions,
        active_resource_policy,
        private_runtime_control_commitment,
        private_runtime_control_sequence,
        private_authority_epoch_high_water,
        private_control_slot_high_water,
        private_management_dispositions,
        system_authority,
        actors,
        clean_actor_packages,
        clean_actor_installations,
        retired_installation_ids,
        lane_state,
        invocation_results,
        clean_invocation_errors,
        clean_invocation_acknowledgements,
        sequenced_retired_through,
        machine_continuations,
        lane_revisions,
        control_authority_slot,
        authority_slot_high_water,
        authority_sequence_high_water,
        authority_dispositions,
        program_bindings,
    };
    Ok(state)
}

/// Decode the clean SDK state container through the same canonical Standard
/// runtime decoder used by execution. Host-side route projection uses this
/// narrow bridge without exposing or re-encoding any state component.
pub(crate) fn decode_clean_standard_runtime_state(
    state: &crate::agent_sdk::RuntimeState,
) -> Result<StandardRuntimeState, DecodeError> {
    decode_standard_runtime_state(&RuntimeState {
        control: state.control.clone(),
        linear: state.linear.clone(),
        merge: state.merge.clone(),
        local: state.local.clone(),
    })
}

fn encode_standard_lane(state: &StandardRuntimeState, lane: StateLane) -> Vec<u8> {
    let mut output = Vec::new();
    let mut encoder = Encoder(&mut output);
    encoder.fixed(&super::RUNTIME_ABI_ID.0);
    encoder.0.extend_from_slice(b"SLR1");
    encoder.u8(lane as u8);
    encoder.u64(match lane {
        StateLane::Linear => state.lane_revisions.linear,
        StateLane::Merge => state.lane_revisions.merge,
        StateLane::Local => state.lane_revisions.local,
    });
    encoder.option(
        &match lane {
            StateLane::Linear => state.lane_revisions.linear_authority_slot,
            StateLane::Merge => state.lane_revisions.merge_authority_slot,
            StateLane::Local => state.lane_revisions.local_authority_slot,
        },
        |encoder, slot| encoder.u64(*slot),
    );
    let entries = match lane {
        StateLane::Linear => &state.lane_state.linear,
        StateLane::Merge => &state.lane_state.merge,
        StateLane::Local => &state.lane_state.local,
    };
    encoder.list(entries, |encoder, entry| {
        encoder.fixed(&entry.actor.0);
        encoder.fixed(&entry.state_generation.0);
        let length_at = encoder.0.len();
        encoder.u32(0);
        let image_at = encoder.0.len();
        super::actor_storage::ActorLaneImage::append_parts(encoder.0, &entry.value, &entry.rows);
        let image_len = (encoder.0.len() - image_at) as u32;
        encoder.0[length_at..image_at].copy_from_slice(&image_len.to_le_bytes());
    });
    encoder.list(
        &state
            .invocation_results
            .iter()
            .filter(|result| result.storage == super::InvocationResultStorage::Lane(lane))
            .collect::<Vec<_>>(),
        |encoder, result| {
            encoder.u8(encode_invocation_scope(result.scope));
            encoder.fixed(&result.invocation.0);
            encoder.fixed(&result.incarnation.0);
            encoder.fixed(&result.request.0);
            encode_execution_reply(encoder, &result.reply);
            encoder.option(&result.clean, encode_clean_invocation_result);
        },
    );
    let sdk_lane = match lane {
        StateLane::Linear => crate::agent_sdk::StateLane::Linear,
        StateLane::Merge => crate::agent_sdk::StateLane::Merge,
        StateLane::Local => crate::agent_sdk::StateLane::Local,
    };
    encoder.list(
        &state
            .clean_invocation_acknowledgements
            .iter()
            .filter(|item| {
                item.mode.result_storage()
                    == crate::agent_sdk::InvocationResultStorage::Lane(sdk_lane)
            })
            .collect::<Vec<_>>(),
        |encoder, acknowledgement| {
            encode_clean_invocation_acknowledgement(encoder, acknowledgement)
        },
    );
    encoder.list(
        &state
            .machine_continuations
            .iter()
            .filter(|continuation| {
                continuation.mode.result_storage() == super::InvocationResultStorage::Lane(lane)
            })
            .collect::<Vec<_>>(),
        |encoder, continuation| encode_machine_continuation(encoder, continuation),
    );
    encode_clean_invocation_errors(
        &mut encoder,
        state,
        super::InvocationResultStorage::Lane(lane),
    );
    encode_sequenced_retirement(
        &mut encoder,
        state,
        super::InvocationResultStorage::Lane(lane),
    );
    output
}

struct DecodedStandardLane {
    revision: u64,
    authority_slot: Option<u64>,
    values: Vec<StandardLaneEntry>,
    invocation_results: Vec<StandardInvocationResult>,
    clean_invocation_errors: Vec<super::standard::StandardCleanInvocationError>,
    clean_invocation_acknowledgements: Vec<crate::agent_sdk::InvocationAcknowledgement>,
    machine_continuations: Vec<StandardMachineContinuation>,
    retired_through: u64,
}

pub(crate) const STANDARD_MACHINE_CONTINUATION_MAGIC: [u8; 4] = *b"SMCN";
pub(crate) const STANDARD_MACHINE_CONTINUATION_VERSION: u16 = 1;
pub(crate) const MAX_STANDARD_MACHINE_CONTINUATION_BYTES: usize =
    super::execution::MAX_RUNTIME_STATE_BYTES;

/// Encode one self-contained portable continuation record. Its clean SDK
/// BlobRef is computed over these exact bytes; embedded runtime state uses the
/// same envelope rather than a second, subtly different representation.
pub(crate) fn encode_standard_machine_continuation(
    value: &StandardMachineContinuation,
) -> Result<Vec<u8>, DecodeError> {
    if !value.validate_record() {
        return Err(DecodeError::NonCanonical);
    }
    let mut output = Vec::new();
    output.extend_from_slice(&STANDARD_MACHINE_CONTINUATION_MAGIC);
    output.extend_from_slice(crate::agent_sdk::RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut output);
    encoder.u16(STANDARD_MACHINE_CONTINUATION_VERSION);
    encode_machine_continuation_body(&mut encoder, value)?;
    if output.len() > MAX_STANDARD_MACHINE_CONTINUATION_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(output)
}

pub(crate) fn decode_standard_machine_continuation(
    bytes: &[u8],
) -> Result<StandardMachineContinuation, DecodeError> {
    if bytes.len() > MAX_STANDARD_MACHINE_CONTINUATION_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4)? != STANDARD_MACHINE_CONTINUATION_MAGIC {
        return Err(DecodeError::InvalidTag);
    }
    if decoder.fixed()? != crate::agent_sdk::RUNTIME_ABI_ID.0
        || decoder.u16()? != STANDARD_MACHINE_CONTINUATION_VERSION
    {
        return Err(DecodeError::InvalidPlatform);
    }
    let value = decode_machine_continuation_body(&mut decoder)?;
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes);
    }
    value
        .validate_record()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_machine_continuation(encoder: &mut Encoder<'_>, value: &StandardMachineContinuation) {
    let bytes = encode_standard_machine_continuation(value)
        .expect("restored standard continuation is canonically encodable");
    encoder.bytes(&bytes);
}

fn encode_machine_continuation_body(
    encoder: &mut Encoder<'_>,
    value: &StandardMachineContinuation,
) -> Result<(), DecodeError> {
    encoder.fixed(&value.invocation.0);
    encoder.fixed(&value.actor.0);
    encoder.fixed(&value.incarnation.0);
    encoder.fixed(&value.deployment.0);
    encoder.fixed(&value.program.0);
    encoder.u8(encode_method_mode(value.mode));
    encoder.fixed(&value.request.0);
    encoder.fixed(&value.work.0);
    encoder.u64(value.ready_sequence);
    encoder.u64(value.observed_slot);
    encoder.option(&value.accepted, |encoder, accepted| {
        encode_accepted_invocation(encoder, accepted)
    });
    encoder.option(&value.authorization, |encoder, authorization| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let bytes = authorization
            .encode()
            .expect("validated clean invocation authorization is encodable");
        encoder.bytes(&bytes);
    });
    encoder.u8(value.continuation.fetch_index);
    encoder.u32(value.continuation.host_budget.calls);
    encoder.u32(value.continuation.host_budget.fetch_calls);
    encoder.u32(value.continuation.host_budget.fetch_bytes);
    encoder.u32(value.continuation.host_budget.blake2b_compressions);
    encoder.u32(value.continuation.host_budget.debug_bytes);
    encoder.u32(value.continuation.machine.pc);
    encoder.u64(value.continuation.machine.gas_remaining);
    for register in value.continuation.machine.registers {
        encoder.u64(register);
    }
    encoder.list(&value.continuation.machine.memory, |encoder, region| {
        encoder.u32(region.base);
        encoder.bytes(&region.bytes);
    });
    Ok(())
}

fn decode_machine_continuation(
    decoder: &mut Decoder<'_>,
    expected_storage: super::InvocationResultStorage,
) -> Result<StandardMachineContinuation, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > MAX_STANDARD_MACHINE_CONTINUATION_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let value = decode_standard_machine_continuation(bytes)?;
    if value.mode.result_storage() != expected_storage {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn decode_machine_continuation_body(
    decoder: &mut Decoder<'_>,
) -> Result<StandardMachineContinuation, DecodeError> {
    let invocation = crate::service::InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder.u8()?)?;
    let request = Hash(decoder.fixed()?);
    let work = Hash(decoder.fixed()?);
    let ready_sequence = decoder.u64()?;
    let observed_slot = decoder.u64()?;
    let accepted = decoder.option(decode_accepted_invocation)?;
    let authorization = decoder.option(|decoder| {
        use crate::agent_sdk::wire::CanonicalWire as _;
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > crate::agent_sdk::wire::MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        crate::agent_sdk::InvocationAuthorization::decode(bytes)
            .map_err(|_| DecodeError::NonCanonical)
    })?;
    let fetch_index = decoder.u8()?;
    let host_budget = super::execution::ActorHostBudget {
        calls: decoder.u32()?,
        fetch_calls: decoder.u32()?,
        fetch_bytes: decoder.u32()?,
        blake2b_compressions: decoder.u32()?,
        debug_bytes: decoder.u32()?,
    };
    let pc = decoder.u32()?;
    let gas_remaining = decoder.u64()?;
    let mut registers = [0u64; vos_pvm_program::REGISTER_COUNT];
    for register in &mut registers {
        *register = decoder.u64()?;
    }
    let memory = decode_bounded_list(
        decoder,
        super::execution::MAX_PORTABLE_MACHINE_REGIONS,
        |decoder| {
            let base = decoder.u32()?;
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::execution::MAX_PORTABLE_MACHINE_MEMORY_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(super::execution::PortableMemoryRegion {
                base,
                bytes: bytes.to_vec(),
            })
        },
    )?;
    let continuation = super::execution::ActorMachineContinuation {
        machine: super::execution::PortableMachineSnapshot {
            pc,
            gas_remaining,
            registers,
            memory,
        },
        fetch_index,
        host_budget,
    };
    let value = StandardMachineContinuation {
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        request,
        work,
        ready_sequence,
        accepted,
        authorization,
        observed_slot,
        continuation,
    };
    if invocation == crate::service::InvocationId::ZERO
        || actor == ActorId::ZERO
        || incarnation == Hash::ZERO
        || deployment == DeploymentId::ZERO
        || program == ProgramId::ZERO
        || request == Hash::ZERO
        || work == Hash::ZERO
        || ready_sequence == 0
        || !value.validate_record()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_sdk_blob(encoder: &mut Encoder<'_>, value: &crate::agent_sdk::BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_sdk_blob(decoder: &mut Decoder<'_>) -> Result<crate::agent_sdk::BlobRef, DecodeError> {
    Ok(crate::agent_sdk::BlobRef {
        hash: crate::agent_sdk::Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_sdk_origin(encoder: &mut Encoder<'_>, value: crate::agent_sdk::InvocationOrigin) {
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

fn decode_sdk_origin(
    decoder: &mut Decoder<'_>,
) -> Result<crate::agent_sdk::InvocationOrigin, DecodeError> {
    let value = crate::agent_sdk::InvocationOrigin {
        principal: decoder.option(|decoder| Ok(crate::agent_sdk::PrincipalId(decoder.fixed()?)))?,
        transport_node: decoder.option(|decoder| Ok(crate::agent_sdk::NodeId(decoder.fixed()?)))?,
        credential: decoder
            .option(|decoder| Ok(crate::agent_sdk::CredentialId(decoder.fixed()?)))?,
        actor: decoder.option(|decoder| Ok(crate::agent_sdk::ActorId(decoder.fixed()?)))?,
        capability: decoder
            .option(|decoder| Ok(crate::agent_sdk::CapabilityId(decoder.fixed()?)))?,
    };
    value
        .validate()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_sdk_invocation_roles(
    encoder: &mut Encoder<'_>,
    value: crate::agent_sdk::InvocationRoleClaims,
) {
    encoder.option(&value.space, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
    encoder.option(&value.actor, |encoder, value| {
        encoder.fixed(value.as_bytes())
    });
}

fn decode_sdk_invocation_roles(
    decoder: &mut Decoder<'_>,
    origin: crate::agent_sdk::InvocationOrigin,
) -> Result<crate::agent_sdk::InvocationRoleClaims, DecodeError> {
    let value = crate::agent_sdk::InvocationRoleClaims {
        space: decoder.option(|decoder| Ok(crate::agent_sdk::RoleId(decoder.fixed()?)))?,
        actor: decoder.option(|decoder| Ok(crate::agent_sdk::RoleId(decoder.fixed()?)))?,
    };
    value
        .validate_for(origin)
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn decode_sdk_method_mode(value: u8) -> Result<crate::agent_sdk::MethodMode, DecodeError> {
    match value {
        0 => Ok(crate::agent_sdk::MethodMode::Query),
        1 => Ok(crate::agent_sdk::MethodMode::LinearizableQuery),
        2 => Ok(crate::agent_sdk::MethodMode::LocalQuery),
        3 => Ok(crate::agent_sdk::MethodMode::Linear),
        4 => Ok(crate::agent_sdk::MethodMode::Merge),
        5 => Ok(crate::agent_sdk::MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_accepted_invocation(
    encoder: &mut Encoder<'_>,
    value: &super::standard::StandardAcceptedInvocation,
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
    encode_sdk_origin(encoder, value.origin);
    encode_sdk_invocation_roles(encoder, value.roles);
    encoder.bytes(&value.message);
    encoder.option(&value.installation_data, encode_sdk_blob);
    encoder.list(&value.required, encode_sdk_blob);
    encoder.u64(value.gas);
    encoder.bool(value.recovery_only);
}

fn decode_accepted_invocation(
    decoder: &mut Decoder<'_>,
) -> Result<super::standard::StandardAcceptedInvocation, DecodeError> {
    let space = crate::agent_sdk::SpaceId(decoder.fixed()?);
    let agent = crate::agent_sdk::AgentId(decoder.fixed()?);
    let runtime_deployment = crate::agent_sdk::DeploymentId(decoder.fixed()?);
    let invocation = crate::agent_sdk::InvocationId(decoder.fixed()?);
    let actor = crate::agent_sdk::ActorId(decoder.fixed()?);
    let incarnation = crate::agent_sdk::Hash(decoder.fixed()?);
    let deployment = crate::agent_sdk::DeploymentId(decoder.fixed()?);
    let program = crate::agent_sdk::ProgramId(decoder.fixed()?);
    let mode = decode_sdk_method_mode(decoder.u8()?)?;
    let origin = decode_sdk_origin(decoder)?;
    let roles = decode_sdk_invocation_roles(decoder, origin)?;
    let value = super::standard::StandardAcceptedInvocation {
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
        message: {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            bytes.to_vec()
        },
        installation_data: decoder.option(decode_sdk_blob)?,
        required: decode_bounded_list(
            decoder,
            crate::agent_sdk::MAX_RUNTIME_AVAILABILITY_ITEMS,
            decode_sdk_blob,
        )?,
        gas: decoder.u64()?,
        recovery_only: decoder.bool()?,
    };
    value
        .validate_accepted()
        .then_some(value)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_clean_invocation_result(
    encoder: &mut Encoder<'_>,
    value: &super::standard::StandardCleanInvocationResult,
) {
    use crate::agent_sdk::wire::CanonicalWire as _;

    encoder.fixed(value.work.as_bytes());
    encoder.u64(value.observed_slot);
    encode_accepted_invocation(encoder, &value.accepted);
    encoder.bytes(
        &value
            .authorization
            .encode()
            .expect("validated clean invocation authorization"),
    );
}

fn decode_clean_invocation_result(
    decoder: &mut Decoder<'_>,
) -> Result<super::standard::StandardCleanInvocationResult, DecodeError> {
    let value = decode_clean_invocation_result_binding(decoder)?;
    if !super::standard::clean_authorization_is_live_at(&value.authorization, value.observed_slot) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

// Ordinary results require live acceptance; expiry fences require the opposite
// window. Their callers validate that distinction after decoding the error tag.
fn decode_clean_invocation_result_binding(
    decoder: &mut Decoder<'_>,
) -> Result<super::standard::StandardCleanInvocationResult, DecodeError> {
    use crate::agent_sdk::wire::CanonicalWire as _;

    let work = crate::agent_sdk::Hash(decoder.fixed()?);
    let observed_slot = decoder.u64()?;
    let accepted = decode_accepted_invocation(decoder)?;
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > crate::agent_sdk::wire::MAX_INVOCATION_AUTHORIZATION_WIRE_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let authorization = crate::agent_sdk::InvocationAuthorization::decode(bytes)
        .map_err(|_| DecodeError::NonCanonical)?;
    if work == crate::agent_sdk::Hash::ZERO
        || super::standard::clean_authorization_work(&authorization) != Hash(work.0)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(super::standard::StandardCleanInvocationResult {
        accepted,
        authorization,
        work,
        observed_slot,
    })
}

fn encode_clean_invocation_acknowledgement(
    encoder: &mut Encoder<'_>,
    value: &crate::agent_sdk::InvocationAcknowledgement,
) {
    encoder.u8(value.mode as u8);
    encoder.fixed(value.invocation.as_bytes());
    encoder.fixed(value.actor.as_bytes());
    encoder.fixed(value.incarnation.as_bytes());
    encoder.fixed(value.deployment.as_bytes());
    encoder.fixed(value.work.as_bytes());
    encoder.fixed(value.authorization.as_bytes());
}

fn decode_clean_invocation_acknowledgement(
    decoder: &mut Decoder<'_>,
    expected_storage: super::InvocationResultStorage,
) -> Result<crate::agent_sdk::InvocationAcknowledgement, DecodeError> {
    let value = crate::agent_sdk::InvocationAcknowledgement {
        mode: decode_sdk_method_mode(decoder.u8()?)?,
        invocation: crate::agent_sdk::InvocationId(decoder.fixed()?),
        actor: crate::agent_sdk::ActorId(decoder.fixed()?),
        incarnation: crate::agent_sdk::Hash(decoder.fixed()?),
        deployment: crate::agent_sdk::DeploymentId(decoder.fixed()?),
        work: crate::agent_sdk::Hash(decoder.fixed()?),
        authorization: crate::agent_sdk::Hash(decoder.fixed()?),
    };
    let storage = match value.mode.result_storage() {
        crate::agent_sdk::InvocationResultStorage::Control => {
            super::InvocationResultStorage::Control
        }
        crate::agent_sdk::InvocationResultStorage::Lane(crate::agent_sdk::StateLane::Linear) => {
            super::InvocationResultStorage::Lane(StateLane::Linear)
        }
        crate::agent_sdk::InvocationResultStorage::Lane(crate::agent_sdk::StateLane::Merge) => {
            super::InvocationResultStorage::Lane(StateLane::Merge)
        }
        crate::agent_sdk::InvocationResultStorage::Lane(crate::agent_sdk::StateLane::Local) => {
            super::InvocationResultStorage::Lane(StateLane::Local)
        }
    };
    if !value.validate() || storage != expected_storage {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn decode_standard_lane(
    bytes: &[u8],
    expected_lane: StateLane,
    remaining_continuations: usize,
) -> Result<DecodedStandardLane, DecodeError> {
    let mut decoder = Decoder::new(bytes);
    if Hash(decoder.fixed()?) != super::RUNTIME_ABI_ID
        || decoder.take(4)? != b"SLR1"
        || decode_state_lane(decoder.u8()?)? != expected_lane
    {
        return Err(DecodeError::InvalidPlatform);
    }
    let revision = decoder.u64()?;
    let authority_slot = decoder.option(Decoder::u64)?;
    let values = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_LANE_STATE_ENTRIES,
        |decoder| {
            let actor = ActorId(decoder.fixed()?);
            let state_generation = Hash(decoder.fixed()?);
            let (value, rows) =
                super::actor_storage::ActorLaneImage::decode(decoder.bytes_ref()?)?.into_parts();
            if actor == ActorId::ZERO
                || state_generation == Hash::ZERO
                || (value.is_empty() && rows.is_empty())
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardLaneEntry {
                actor,
                state_generation,
                value,
                rows,
            })
        },
    )?;
    if values.windows(2).any(|pair| {
        (pair[0].actor, pair[0].state_generation) >= (pair[1].actor, pair[1].state_generation)
    }) {
        return Err(DecodeError::NonCanonical);
    }
    let invocation_results = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_RESULTS_PER_LANE,
        |decoder| {
            let scope = decode_invocation_scope(decoder.u8()?)?;
            let invocation = crate::service::InvocationId(decoder.fixed()?);
            let incarnation = Hash(decoder.fixed()?);
            let request = Hash(decoder.fixed()?);
            let reply = decode_execution_reply(decoder)?;
            let clean = decoder.option(decode_clean_invocation_result)?;
            if scope != invocation_scope_for_lane(expected_lane)
                || invocation == crate::service::InvocationId::ZERO
                || incarnation == Hash::ZERO
                || request == Hash::ZERO
                || reply.invocation != invocation
                || reply.incarnation != incarnation
                || reply.mode.invocation_scope() != scope
                || reply.mode.result_storage()
                    != super::InvocationResultStorage::Lane(expected_lane)
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(StandardInvocationResult {
                scope,
                invocation,
                incarnation,
                request,
                reply,
                storage: super::InvocationResultStorage::Lane(expected_lane),
                clean,
            })
        },
    )?;
    if invocation_results
        .windows(2)
        .any(|pair| (pair[0].scope, pair[0].invocation) >= (pair[1].scope, pair[1].invocation))
    {
        return Err(DecodeError::NonCanonical);
    }
    let clean_invocation_acknowledgements = decode_bounded_list(
        &mut decoder,
        super::standard::MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE,
        |decoder| {
            decode_clean_invocation_acknowledgement(
                decoder,
                super::InvocationResultStorage::Lane(expected_lane),
            )
        },
    )?;
    let machine_continuations =
        decode_bounded_list(&mut decoder, remaining_continuations, |decoder| {
            decode_machine_continuation(
                decoder,
                super::InvocationResultStorage::Lane(expected_lane),
            )
        })?;
    if machine_continuations
        .windows(2)
        .any(|pair| pair[0].ready_sequence >= pair[1].ready_sequence)
    {
        return Err(DecodeError::NonCanonical);
    }
    let (clean_invocation_errors, retired_through) = decode_result_component_tail(
        &mut decoder,
        super::InvocationResultStorage::Lane(expected_lane),
    )?;
    if !decoder.exhausted() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(DecodedStandardLane {
        revision,
        authority_slot,
        values,
        invocation_results,
        clean_invocation_errors,
        clean_invocation_acknowledgements,
        machine_continuations,
        retired_through,
    })
}

/// Apply one management call with the bundled deterministic runtime.
pub fn apply_standard(call: RuntimeCall) -> Result<RuntimeReturn, DecodeError> {
    let (mut runtime, _) = restore_standard_runtime_state(&call.state)?;
    let result = runtime.apply_guest(call.journal_context(), call.request);
    Ok(RuntimeReturn {
        state: encode_standard_runtime_state(&runtime.snapshot()),
        result,
    })
}

/// Execute one actor call with the bundled runtime. Deterministic exact
/// outcomes advance only their owning result component's authority clock;
/// admission failures and unavailable execution keep byte-identical state.
#[cfg(feature = "pvm")]
pub fn apply_standard_execution(
    call: RuntimeExecutionCall,
) -> Result<RuntimeExecutionReturn, DecodeError> {
    let original_state = call.state;
    let (mut runtime, state_limit) = restore_standard_runtime_state(&original_state)?;
    let (mut result, commit_candidate) = match call.invocation.validate() {
        Err(error) => (Err(error), false),
        Ok(()) => match runtime.verify_invocation_authority(&call.invocation, &call.authority) {
            Err(error) => (Err(error), false),
            Ok(()) => match runtime.validate_invocation_result_storage(&call.invocation) {
                Err(error) => (Err(error), false),
                Ok(()) => match runtime.recover_execution(&call.invocation, call.observed_slot) {
                    Ok(Some(reply)) => (Ok(reply), true),
                    Err(ActorExecutionError::DivergentInvocation) => {
                        (Err(ActorExecutionError::DivergentInvocation), false)
                    }
                    unseen => match runtime.validate_unseen_invocation_slot(
                        &call.invocation,
                        &call.authority,
                        call.observed_slot,
                    ) {
                        Err(error) => (Err(error), false),
                        Ok(()) => {
                            let pristine = runtime.clone();
                            let mut terminal_continuation = None;
                            let mut result = match unseen {
                                Err(error) => Err(error),
                                Ok(None) if call.recovery_only => {
                                    Err(ActorExecutionError::InvalidAvailability)
                                }
                                Ok(None) => match runtime
                                    .validate_execution_installation_data(
                                        &call.invocation,
                                        call.installation_data.as_ref(),
                                    )
                                    .and_then(|()| {
                                        runtime.validate_execution_schema(
                                            &call.invocation,
                                            &call.actor_schema,
                                        )
                                    })
                                    .and_then(|()| {
                                        runtime.authorize_execution(
                                            &call.invocation,
                                            &call.actor_policies,
                                        )
                                    }) {
                                    Err(error) => Err(error),
                                    Ok(false) => Ok(ActorExecutionReply {
                                        invocation: call.invocation.invocation,
                                        actor: call.invocation.actor,
                                        incarnation: call.invocation.incarnation,
                                        deployment: call.invocation.deployment,
                                        mode: call.invocation.mode,
                                        lane: call.invocation.mode.write_lane(),
                                        status: ActorExecutionStatus::Forbidden,
                                        reply: Vec::new(),
                                        gas_remaining: call.invocation.gas,
                                        observation: super::execution::ActorObservation::default(),
                                    }),
                                    Ok(true) => runtime
                                        .machine_continuation(&call.invocation)
                                        .and_then(|pending| {
                                            runtime
                                                .prepare_execution_state(&call.invocation)
                                                .and_then(|before| {
                                                    let actor_state = before
                                                        .visible_for(call.invocation.mode);
                                                    let expected_sequence = pending
                                                        .as_ref()
                                                        .map(|(sequence, _)| *sequence);
                                                    super::execution::run_inner_actor(
                                                        &call.invocation,
                                                        None,
                                                        &call.actor_pvm,
                                                        call.installation_data
                                                            .as_ref()
                                                            .map(|data| data.bytes.as_slice()),
                                                        &actor_state,
                                                        pending.map(|(_, continuation)| {
                                                            continuation
                                                        }),
                                                    )
                                                    .and_then(|outcome| match outcome {
                                                        super::execution::ActorRunOutcome::Completed {
                                                            mut reply,
                                                            state: next_state,
                                                            ..
                                                        } => {
                                                            if reply.status
                                                                == ActorExecutionStatus::Done
                                                            {
                                                                if let Some(sequence) =
                                                                    expected_sequence
                                                                {
                                                                    runtime
                                                                        .consume_machine_continuation(
                                                                            &call.invocation,
                                                                            sequence,
                                                                        )?;
                                                                }
                                                                runtime.commit_execution(
                                                                    &call.invocation,
                                                                    &mut reply,
                                                                    &before,
                                                                    next_state,
                                                                    call.observed_slot,
                                                                )?;
                                                            } else if let Some(sequence) =
                                                                expected_sequence
                                                            {
                                                                runtime
                                                                    .consume_machine_continuation(
                                                                        &call.invocation,
                                                                        sequence,
                                                                    )?;
                                                                terminal_continuation =
                                                                    Some(sequence);
                                                            }
                                                            Ok(reply)
                                                        }
                                                        super::execution::ActorRunOutcome::Yielded {
                                                            reply,
                                                            state: next_state,
                                                            continuation,
                                                            ..
                                                        } => {
                                                            runtime.commit_yielded_execution(
                                                                &call.invocation,
                                                                &reply,
                                                                &before,
                                                                next_state,
                                                                call.observed_slot,
                                                                expected_sequence,
                                                                continuation,
                                                                None,
                                                            )?;
                                                            Ok(reply)
                                                        }
                                                    })
                                                })
                                        }),
                                },
                                Ok(Some(_)) => unreachable!("exact recovery returned above"),
                            };
                            let commit_candidate = finalize_unseen_standard_outcome(
                                &mut runtime,
                                pristine,
                                &call.invocation,
                                call.observed_slot,
                                terminal_continuation,
                                &mut result,
                            );
                            (result, commit_candidate)
                        }
                    },
                },
            },
        },
    };
    let state = finish_standard_execution_candidate(
        original_state,
        &runtime,
        commit_candidate,
        state_limit,
        &mut result,
    );
    Ok(RuntimeExecutionReturn { state, result })
}

/// Borrowed proof of complete canonical invocation validation. Only this
/// module can construct it, immediately after decoding the exact work bytes.
#[cfg(feature = "pvm")]
pub(super) struct ValidatedInvocationWork<'a>(&'a crate::agent_sdk::InvocationWork);

#[cfg(feature = "pvm")]
impl<'a> ValidatedInvocationWork<'a> {
    pub(super) fn work(&self) -> &'a crate::agent_sdk::InvocationWork {
        self.0
    }
}

/// Decode and execute one canonical work item. The decoder validates all
/// availability preimages before this module mints a borrowed validation
/// capability. It cannot escape this immutable invocation or authorize a
/// different work item. Constructed-value entry points still validate fully.
#[cfg(feature = "pvm")]
pub fn apply_standard_runtime_input(
    input: &[u8],
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    use crate::agent_sdk::wire::CanonicalWire as _;

    let work =
        crate::agent_sdk::RuntimeWork::decode(input).map_err(|_| DecodeError::NonCanonical)?;
    apply_decoded_standard_runtime_work(work)
}

/// [`apply_standard_runtime_input`], also returning the work's by-reference
/// commitment ([`crate::agent_sdk::wire::runtime_work_reference_commitment`])
/// for the public I/O. The commitment is taken from the decoded work, whose
/// availability the decoder has authenticated, before execution consumes it.
#[cfg(feature = "pvm")]
pub fn apply_standard_runtime_input_committed(
    input: &[u8],
) -> Result<(crate::agent_sdk::RuntimeTransition, crate::agent_sdk::Hash), DecodeError> {
    use crate::agent_sdk::wire::CanonicalWire as _;

    let work =
        crate::agent_sdk::RuntimeWork::decode(input).map_err(|_| DecodeError::NonCanonical)?;
    let commitment = crate::agent_sdk::wire::runtime_work_reference_commitment(&work);
    Ok((apply_decoded_standard_runtime_work(work)?, commitment))
}

#[cfg(feature = "pvm")]
fn apply_decoded_standard_runtime_work(
    work: crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    if !work.execution_context().is_direct() {
        #[cfg(all(feature = "agent-runtime", target_arch = "riscv64"))]
        return apply_proof_host_attested_standard_runtime_work(work);
        #[cfg(not(all(feature = "agent-runtime", target_arch = "riscv64")))]
        return Err(DecodeError::NonCanonical);
    }
    match work {
        crate::agent_sdk::RuntimeWork::Invoke {
            state,
            invocation,
            authorization,
            observed_slot,
            ..
        } => apply_clean_invoke_inner(
            state,
            *invocation,
            *authorization,
            observed_slot,
            CleanExecutionAdmission::direct(),
            true,
        ),
        crate::agent_sdk::RuntimeWork::Acknowledge {
            state,
            invocation,
            authorization,
            ..
        } => apply_clean_acknowledge(state, *invocation, *authorization),
        other => apply_standard_runtime_work(other),
    }
}

/// Experimental standard-runtime lifecycle, invocation, resume, retirement and
/// inspection with metadata in accounted external roots. External yielded
/// writes remain unavailable until continuation budgets are retained. This
/// never publishes storage.
#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
pub fn apply_standard_external_runtime_input(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    #[cfg(target_arch = "riscv64")]
    return apply_standard_external_runtime_input_with_reader(input, |scope| {
        crate::agent_sdk::state_guest::PvmBlockReader::new(scope.lane())
    });
    #[cfg(not(target_arch = "riscv64"))]
    {
        struct NoBase;
        impl crate::agent_sdk::state_tree::BlockReader for NoBase {
            fn read(
                &mut self,
                _: crate::agent_sdk::state_blocks::BlockRef,
                _: &mut [u8],
            ) -> Result<bool, crate::agent_sdk::state_tree::TreeError> {
                Err(crate::agent_sdk::state_tree::TreeError::Storage)
            }
        }
        // Native callers get no implicit provider or interpretation of missing
        // blocks as empty state. Tests supply an explicit authenticated reader.
        apply_standard_external_runtime_input_with_reader(input, |_| NoBase)
    }
}

#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
fn apply_standard_external_runtime_input_with_reader<
    R: crate::agent_sdk::state_tree::BlockReader,
>(
    input: &[u8],
    mut reader: impl FnMut(crate::agent_sdk::state_blocks::BlockScope) -> R,
) -> Result<Vec<u8>, DecodeError> {
    use crate::agent_sdk::{
        ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeWork,
        state_blocks::ReadBudget,
        state_change::StateChange,
        state_execution::{StateExecutionOutput, StateExecutionWork},
        state_metadata::RuntimeMetadataUpdate,
        state_rows::initialize_accounted_metadata,
        state_tree::WriteBudget,
    };
    let work = StateExecutionWork::decode(input).map_err(|_| DecodeError::NonCanonical)?;
    let (space, agent, deployment, state, supported) = match work.work() {
        RuntimeWork::Manage {
            space,
            agent,
            runtime_deployment,
            state,
            request,
            ..
        } => (
            *space,
            *agent,
            Some(*runtime_deployment),
            state,
            matches!(
                request.as_ref(),
                ManagementRequest::InspectActors { .. }
                    | ManagementRequest::InspectResources
                    | ManagementRequest::InspectManagementHistory
                    | ManagementRequest::Install(_)
            ),
        ),
        RuntimeWork::Acknowledge {
            state, invocation, ..
        } => (
            invocation.space,
            invocation.agent,
            Some(invocation.runtime_deployment),
            state,
            true,
        ),
        RuntimeWork::InspectInvocation {
            state, invocation, ..
        } => (
            invocation.space,
            invocation.agent,
            Some(invocation.runtime_deployment),
            state,
            true,
        ),
        RuntimeWork::Invoke {
            state, invocation, ..
        } => (
            invocation.space,
            invocation.agent,
            Some(invocation.runtime_deployment),
            state,
            true,
        ),
        RuntimeWork::Resume { state, .. } => {
            let scope = work.lanes()[0].base.context().scope();
            (scope.space(), scope.agent(), None, state, true)
        }
    };
    if supported {
        let mut decoded = encode_standard_runtime_state(&StandardRuntimeState::default());
        decoded.control = state.control.clone();
        let mut remaining = crate::agent_sdk::MAX_RUNTIME_STATE_BYTES
            .checked_sub(decoded.control.len())
            .ok_or(DecodeError::LimitExceeded)?;
        let mut reads =
            ReadBudget::new(4096, (crate::agent_sdk::MAX_RUNTIME_STATE_BYTES * 2) as u64);
        for lane in [
            crate::agent_sdk::StateLane::Linear,
            crate::agent_sdk::StateLane::Merge,
            crate::agent_sdk::StateLane::Local,
        ] {
            let bytes = if let Some(selected) = work
                .lanes()
                .iter()
                .find(|selected| selected.base.context().scope().lane() == lane)
            {
                let tree = selected
                    .base
                    .bind(selected.base.context(), selected.base.commitment())
                    .map_err(|_| DecodeError::NonCanonical)?;
                let mut provider = reader(tree.scope());
                let usage =
                    crate::agent_sdk::state_rows::lane_row_usage(tree, &mut provider, &mut reads)
                        .map_err(|_| DecodeError::NonCanonical)?;
                if usage.rows > work.limits().max_rows_per_lane
                    || usage.bytes > work.limits().max_row_bytes_per_lane
                {
                    return Err(DecodeError::LimitExceeded);
                }
                crate::agent_sdk::state_metadata::read_runtime_metadata(
                    tree,
                    remaining,
                    &mut provider,
                    &mut reads,
                )
                .map_err(|_| DecodeError::NonCanonical)?
                .ok_or(DecodeError::NonCanonical)?
            } else {
                if !state.component(lane).is_empty() {
                    return Err(DecodeError::NonCanonical);
                }
                match lane {
                    crate::agent_sdk::StateLane::Linear => decoded.linear.clone(),
                    crate::agent_sdk::StateLane::Merge => decoded.merge.clone(),
                    crate::agent_sdk::StateLane::Local => decoded.local.clone(),
                }
            };
            remaining = remaining
                .checked_sub(bytes.len())
                .ok_or(DecodeError::LimitExceeded)?;
            match lane {
                crate::agent_sdk::StateLane::Linear => decoded.linear = bytes,
                crate::agent_sdk::StateLane::Merge => decoded.merge = bytes,
                crate::agent_sdk::StateLane::Local => decoded.local = bytes,
            }
        }
        let (mut runtime, _) = restore_standard_runtime_state(&decoded)?;
        if runtime.has_image_rows() {
            return Err(DecodeError::NonCanonical);
        }
        let descriptor = runtime
            .clean_descriptor()
            .ok_or(DecodeError::NonCanonical)?;
        let declared = work.lanes().iter().fold(0u8, |bits, lane| {
            bits | crate::agent_sdk::LaneSet::of(lane.base.context().scope().lane()).bits()
        });
        if descriptor.identity.space != space
            || descriptor.identity.agent != agent
            || deployment.is_some_and(|selected| descriptor.identity.runtime_deployment != selected)
            || descriptor.runtime_contract.lifecycle_abi
                != crate::agent_sdk::state_execution::STATE_EXECUTION_ABI_ID
            || descriptor.capabilities.lanes.bits() != declared
            || decoded.encoded_len().is_none_or(|bytes| {
                bytes
                    > descriptor
                        .runtime_contract
                        .resources
                        .max_runtime_state_bytes as usize
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        let limit = descriptor
            .runtime_contract
            .resources
            .max_runtime_state_bytes as usize;
        let mut writes = WriteBudget::new(
            4096,
            crate::agent_sdk::state_change::MAX_STATE_CHANGE_BYTES as u64,
        );
        let mut row_candidate = None;
        let (successor, outcome) = match work.work() {
            RuntimeWork::Manage {
                request,
                authority,
                observed_slot,
                runtime_deployment,
                ..
            } => {
                let outcome = runtime.apply_clean_management(
                    space,
                    agent,
                    *runtime_deployment,
                    request.as_ref().clone(),
                    authority.as_deref().cloned(),
                    *observed_slot,
                    false,
                );
                let successor = if matches!(request.as_ref(), ManagementRequest::Install(_)) {
                    encode_standard_runtime_state(&runtime.snapshot())
                } else {
                    decoded.clone()
                };
                // Install updates only bounded control/directory metadata.
                if runtime.has_image_rows()
                    || successor.linear != decoded.linear
                    || successor.merge != decoded.merge
                    || successor.local != decoded.local
                {
                    return Err(DecodeError::NonCanonical);
                }
                (successor, RuntimeOutcome::Management(outcome))
            }
            RuntimeWork::Acknowledge {
                invocation,
                authorization,
                ..
            } => {
                // Use the same retirement/retry/capacity implementation as r19,
                // consuming the already restored runtime, without a second restore.
                let result = apply_clean_acknowledge_restored(
                    decoded.clone(),
                    runtime,
                    limit,
                    invocation.as_ref().clone(),
                    authorization.as_ref().clone(),
                )?;
                (clean_state_to_legacy(&result.state), result.outcome)
            }
            RuntimeWork::InspectInvocation {
                invocation,
                authorization,
                observed_slot,
                ..
            } => (
                decoded.clone(),
                clean_retained_inspection_outcome(runtime.inspect_clean_retained_terminal(
                    invocation,
                    authorization,
                    *observed_slot,
                )),
            ),
            RuntimeWork::Invoke {
                invocation,
                authorization,
                observed_slot,
                ..
            } => {
                // The image runtime's Merge observation hashes embedded rows.
                // External Merge frontiers need their own committed semantics;
                // never report that image-derived frontier for external rows.
                if runtime
                    .clean_actor_record(invocation.actor)
                    .is_some_and(|record| {
                        record
                            .entry
                            .lanes
                            .contains(crate::agent_sdk::StateLane::Merge)
                    })
                {
                    return Err(DecodeError::InvalidPlatform);
                }
                let mut storage = ExternalInvocationStorage {
                    reader: &mut reader,
                    lanes: work.lanes(),
                    limits: work.limits(),
                    reads: &mut reads,
                    writes: &mut writes,
                    candidate: None,
                };
                let result = apply_clean_invoke_restored(
                    decoded.clone(),
                    runtime,
                    limit,
                    invocation.as_ref().clone(),
                    authorization.as_ref().clone(),
                    *observed_slot,
                    CleanExecutionAdmission::direct(),
                    false,
                    &mut storage,
                )?;
                let successor = clean_state_to_legacy(&result.state);
                if let Some((expected, update)) = storage.candidate {
                    if expected != successor {
                        return Err(DecodeError::NonCanonical);
                    }
                    row_candidate = Some(update);
                }
                (successor, result.outcome)
            }
            RuntimeWork::Resume { resume, .. } => {
                // External Merge observations need frontier-aware row semantics.
                // Keep the same fail-closed boundary as Invoke.
                if runtime
                    .clean_actor_record(resume.actor)
                    .is_some_and(|record| {
                        record
                            .entry
                            .lanes
                            .contains(crate::agent_sdk::StateLane::Merge)
                    })
                {
                    return Err(DecodeError::InvalidPlatform);
                }
                let mut storage = ExternalInvocationStorage {
                    reader: &mut reader,
                    lanes: work.lanes(),
                    limits: work.limits(),
                    reads: &mut reads,
                    writes: &mut writes,
                    candidate: None,
                };
                let result = apply_clean_resume_restored(
                    decoded.clone(),
                    runtime,
                    limit,
                    resume.as_ref().clone(),
                    CleanExecutionAdmission::direct(),
                    &mut storage,
                )?;
                let successor = clean_state_to_legacy(&result.state);
                if let Some((expected, update)) = storage.candidate {
                    if expected != successor {
                        return Err(DecodeError::NonCanonical);
                    }
                    row_candidate = Some(update);
                }
                (successor, result.outcome)
            }
        };
        if successor.encoded_len().is_none_or(|bytes| bytes > limit) {
            return Err(DecodeError::LimitExceeded);
        }
        let mut transition = crate::agent_sdk::RuntimeTransition {
            state: state.clone(),
            outcome,
        };
        transition.state.control = successor.control;
        let mut changes = Vec::new();
        for (lane, before, after) in [
            (
                crate::agent_sdk::StateLane::Linear,
                &decoded.linear,
                &successor.linear,
            ),
            (
                crate::agent_sdk::StateLane::Merge,
                &decoded.merge,
                &successor.merge,
            ),
            (
                crate::agent_sdk::StateLane::Local,
                &decoded.local,
                &successor.local,
            ),
        ] {
            let owns_rows = row_candidate
                .as_ref()
                .is_some_and(|update| update.tree.scope().lane() == lane);
            if before == after && !owns_rows {
                continue;
            }
            let selected = work
                .lanes()
                .iter()
                .find(|selected| selected.base.context().scope().lane() == lane)
                .ok_or(DecodeError::NonCanonical)?;
            if selected.next == selected.base.context() {
                return Err(DecodeError::NonCanonical);
            }
            let tree = selected
                .base
                .bind(selected.base.context(), selected.base.commitment())
                .map_err(|_| DecodeError::NonCanonical)?;
            let update = if owns_rows {
                row_candidate.take().ok_or(DecodeError::NonCanonical)?
            } else {
                crate::agent_sdk::state_rows::update_accounted_metadata(
                    tree,
                    RuntimeMetadataUpdate::new(after, limit)
                        .map_err(|_| DecodeError::LimitExceeded)?,
                    work.limits(),
                    &mut reader(tree.scope()),
                    &mut reads,
                    &mut writes,
                )
                .map_err(|_| DecodeError::NonCanonical)?
                .update
            };
            let change =
                StateChange::from_update(selected.base.commitment(), selected.next, update)
                    .map_err(|_| DecodeError::LimitExceeded)?;
            match lane {
                crate::agent_sdk::StateLane::Linear => {
                    transition.state.linear = change.next().encode()
                }
                crate::agent_sdk::StateLane::Merge => {
                    transition.state.merge = change.next().encode()
                }
                crate::agent_sdk::StateLane::Local => {
                    transition.state.local = change.next().encode()
                }
            }
            changes.push(change);
        }
        return StateExecutionOutput::new(&work, transition, changes)
            .and_then(|output| output.encode())
            .map_err(|_| DecodeError::NonCanonical);
    }
    let RuntimeWork::Manage { request, .. } = work.work() else {
        return Err(DecodeError::InvalidPlatform);
    };
    let ManagementRequest::Create(descriptor) = request.as_ref() else {
        return Err(DecodeError::InvalidPlatform);
    };
    if !state.is_empty()
        || descriptor.runtime_contract.lifecycle_abi
            != crate::agent_sdk::state_execution::STATE_EXECUTION_ABI_ID
    {
        return Err(DecodeError::InvalidPlatform);
    }
    let declared = work.lanes().iter().fold(0u8, |bits, lane| {
        bits | crate::agent_sdk::LaneSet::of(lane.base.context().scope().lane()).bits()
    });
    if declared != descriptor.capabilities.lanes.bits() {
        return Err(DecodeError::NonCanonical);
    }
    // The existing standard runtime performs Create authority, descriptor,
    // identity and lifecycle checks. No native substitute executes in the host.
    let mut transition = apply_standard_runtime_work(work.work().clone())?;
    if !matches!(&transition.outcome, RuntimeOutcome::Management(Ok(ManagementReply::Created(identity))) if identity == &descriptor.identity)
    {
        return Err(DecodeError::NonCanonical);
    }
    let limit = descriptor
        .runtime_contract
        .resources
        .max_runtime_state_bytes as usize;
    if transition.state.encoded_len().is_none_or(|len| len > limit) {
        return Err(DecodeError::LimitExceeded);
    }
    let empty = encode_standard_runtime_state(&StandardRuntimeState::default());
    let mut changes = Vec::new();
    let mut reads = ReadBudget::new(4096, crate::agent_sdk::MAX_RUNTIME_STATE_BYTES as u64);
    let mut writes = WriteBudget::new(
        4096,
        crate::agent_sdk::state_change::MAX_STATE_CHANGE_BYTES as u64,
    );
    for lane in [
        crate::agent_sdk::StateLane::Linear,
        crate::agent_sdk::StateLane::Merge,
        crate::agent_sdk::StateLane::Local,
    ] {
        let bytes = transition.state.component(lane);
        let successor = if let Some(selected) = work
            .lanes()
            .iter()
            .find(|selected| selected.base.context().scope().lane() == lane)
        {
            let tree = selected
                .base
                .bind(selected.base.context(), selected.base.commitment())
                .map_err(|_| DecodeError::NonCanonical)?;
            let metadata =
                RuntimeMetadataUpdate::new(bytes, limit).map_err(|_| DecodeError::LimitExceeded)?;
            let batch = initialize_accounted_metadata(
                tree,
                metadata,
                &mut reader(tree.scope()),
                &mut reads,
                &mut writes,
            )
            .map_err(|_| DecodeError::NonCanonical)?;
            let change =
                StateChange::from_update(selected.base.commitment(), selected.next, batch.update)
                    .map_err(|_| DecodeError::LimitExceeded)?;
            let root = change.next().encode();
            changes.push(change);
            root
        } else {
            // Unsupported lanes may only discard the canonical empty metadata,
            // which a later standard loader can reconstruct without data loss.
            let native_lane = match lane {
                crate::agent_sdk::StateLane::Linear => StateLane::Linear,
                crate::agent_sdk::StateLane::Merge => StateLane::Merge,
                crate::agent_sdk::StateLane::Local => StateLane::Local,
            };
            if bytes != empty.component(native_lane) {
                return Err(DecodeError::NonCanonical);
            }
            Vec::new()
        };
        match lane {
            crate::agent_sdk::StateLane::Linear => transition.state.linear = successor,
            crate::agent_sdk::StateLane::Merge => transition.state.merge = successor,
            crate::agent_sdk::StateLane::Local => transition.state.local = successor,
        }
    }
    StateExecutionOutput::new(&work, transition, changes)
        .and_then(|output| output.encode())
        .map_err(|_| DecodeError::NonCanonical)
}

/// Return a retained result only; absence and ACK are distinct fail-closed
/// outcomes, never a reason to execute unseen work.
#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
fn clean_retained_inspection_outcome(
    inspected: Result<
        Option<super::standard::RetainedCleanTerminal>,
        crate::agent_sdk::InvocationError,
    >,
) -> crate::agent_sdk::RuntimeOutcome {
    use super::standard::RetainedCleanTerminal;
    use crate::agent_sdk::{InvocationError, RuntimeOutcome};
    match inspected {
        Ok(Some(RetainedCleanTerminal::Completed(result))) => {
            RuntimeOutcome::Completed(result.map(clean_reply))
        }
        Ok(Some(RetainedCleanTerminal::Acknowledged(acknowledgement))) => {
            RuntimeOutcome::Acknowledged(Ok(acknowledgement))
        }
        Ok(None) => RuntimeOutcome::Completed(Err(InvocationError::NotReady)),
        Err(error) => RuntimeOutcome::Completed(Err(error)),
    }
}

/// Execute constructed Direct work, validating its invocation preimages.
#[cfg(feature = "pvm")]
pub fn apply_standard_runtime_work(
    work: crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    if !work.execution_context().is_direct() {
        return Err(DecodeError::NonCanonical);
    }
    match work {
        crate::agent_sdk::RuntimeWork::Invoke {
            state,
            invocation,
            authorization,
            observed_slot,
            ..
        } => apply_clean_invoke(
            state,
            *invocation,
            *authorization,
            observed_slot,
            CleanExecutionAdmission::direct(),
        ),
        crate::agent_sdk::RuntimeWork::Resume { state, resume, .. } => {
            apply_clean_resume(state, *resume, CleanExecutionAdmission::direct())
        }
        crate::agent_sdk::RuntimeWork::Acknowledge {
            state,
            invocation,
            authorization,
            ..
        } => apply_clean_acknowledge(state, *invocation, *authorization),
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation {
            state,
            invocation,
            authorization,
            observed_slot,
            ..
        } => {
            let original_state = state.clone();
            let (runtime, _) = restore_standard_runtime_state(&clean_state_to_legacy(&state))?;
            Ok(crate::agent_sdk::RuntimeTransition {
                state: original_state,
                outcome: clean_retained_inspection_outcome(
                    runtime.inspect_clean_retained_terminal(
                        &invocation,
                        &authorization,
                        observed_slot,
                    ),
                ),
            })
        }
        crate::agent_sdk::RuntimeWork::Manage {
            space,
            agent,
            runtime_deployment,
            state,
            request,
            authority,
            observed_slot,
            ..
        } => apply_clean_manage(
            space,
            agent,
            runtime_deployment,
            state,
            *request,
            authority.map(|value| *value),
            observed_slot,
        ),
    }
}

/// Apply an Attested Invoke/Resume inside the bundled Standard runtime PVM.
///
/// This target-only entry is not a native authorization API. Its caller is
/// the proof host, which authenticates the exact package/program/work before
/// starting the PVM and publishes output only after physical proof
/// verification. The guest repeats installed-package and AMP2
/// Required{proof system} checks. Native callers cannot select this function,
/// and the ordinary public runtime entry remains Direct-only.
#[doc(hidden)]
#[cfg(all(feature = "pvm", feature = "agent-runtime", target_arch = "riscv64"))]
pub fn apply_proof_host_attested_standard_runtime_work(
    work: crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    let proof_system = match work.execution_context() {
        crate::agent_sdk::RuntimeExecutionContext::Attested { proof_system } => proof_system,
        crate::agent_sdk::RuntimeExecutionContext::Direct => return Err(DecodeError::NonCanonical),
    };
    match work {
        crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
            state,
            invocation,
            authorization,
            observed_slot,
        } => apply_clean_invoke(
            state,
            *invocation,
            *authorization,
            observed_slot,
            CleanExecutionAdmission::ProofHostAttested(proof_system),
        ),
        crate::agent_sdk::RuntimeWork::Resume {
            context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
            state,
            resume,
        } => apply_clean_resume(
            state,
            *resume,
            CleanExecutionAdmission::ProofHostAttested(proof_system),
        ),
        crate::agent_sdk::RuntimeWork::Manage { .. }
        | crate::agent_sdk::RuntimeWork::Acknowledge { .. }
        | crate::agent_sdk::RuntimeWork::Invoke { .. }
        | crate::agent_sdk::RuntimeWork::Resume { .. } => Err(DecodeError::NonCanonical),
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => Err(DecodeError::NonCanonical),
    }
}

/// Execute an exact attested Invoke or Resume after proof-host admission.
///
/// The capability is intentionally constructible only by
/// `transition_proof_host`; callers cannot turn an arbitrary Attested work
/// item into a Standard-runtime execution. Management and acknowledgement
/// remain Direct-only, and the public executor above rejects every Attested
/// context.
#[cfg(all(feature = "pvm", feature = "std"))]
pub(crate) fn apply_authenticated_attested_standard_runtime_work(
    authenticated: &super::transition_proof_host::AuthenticatedAttestedTransition,
    work: crate::agent_sdk::RuntimeWork,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    if !authenticated.authorizes_standard_work(&work) {
        return Err(DecodeError::NonCanonical);
    }
    if let crate::agent_sdk::RuntimeWork::Resume { state, resume, .. } = &work {
        use crate::actors::codec::Decode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};

        let (runtime, _) = restore_standard_runtime_state(&clean_state_to_legacy(state))?;
        let (_, accepted_work) = runtime
            .resolve_clean_resume(resume)
            .map_err(|_| DecodeError::NonCanonical)?;
        let recovered_method = accepted_work
            .message
            .strip_prefix(&[TAG_DYNAMIC])
            .and_then(Msg::try_decode)
            .map(|message| message.name)
            .ok_or(DecodeError::NonCanonical)?;
        if recovered_method != authenticated.method() {
            return Err(DecodeError::NonCanonical);
        }
    }
    match work {
        crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
            state,
            invocation,
            authorization,
            observed_slot,
        } => apply_clean_invoke(
            state,
            *invocation,
            *authorization,
            observed_slot,
            CleanExecutionAdmission::Attested(authenticated),
        ),
        crate::agent_sdk::RuntimeWork::Resume {
            context: crate::agent_sdk::RuntimeExecutionContext::Attested { .. },
            state,
            resume,
        } => apply_clean_resume(
            state,
            *resume,
            CleanExecutionAdmission::Attested(authenticated),
        ),
        crate::agent_sdk::RuntimeWork::Manage { .. }
        | crate::agent_sdk::RuntimeWork::Acknowledge { .. }
        | crate::agent_sdk::RuntimeWork::Invoke { .. }
        | crate::agent_sdk::RuntimeWork::Resume { .. } => Err(DecodeError::NonCanonical),
        #[cfg(feature = "experimental-state-blocks")]
        crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => Err(DecodeError::NonCanonical),
    }
}

#[cfg(feature = "pvm")]
fn apply_clean_manage(
    space: crate::agent_sdk::SpaceId,
    agent: crate::agent_sdk::AgentId,
    runtime_deployment: crate::agent_sdk::DeploymentId,
    state: crate::agent_sdk::RuntimeState,
    request: crate::agent_sdk::ManagementRequest,
    authority: Option<crate::agent_sdk::authority::AuthorityReceipt>,
    observed_slot: u64,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    let pristine_input = state.is_empty();
    let read_only = matches!(
        &request,
        crate::agent_sdk::ManagementRequest::InspectActors { .. }
            | crate::agent_sdk::ManagementRequest::InspectResources
            | crate::agent_sdk::ManagementRequest::InspectManagementHistory
    );
    let (mut runtime, _) = restore_standard_runtime_state(&clean_state_to_legacy(&state))?;
    let result = runtime.apply_clean_management(
        space,
        agent,
        runtime_deployment,
        request,
        authority,
        observed_slot,
        pristine_input,
    );
    let successor = if read_only {
        state
    } else {
        legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()))
    };
    Ok(crate::agent_sdk::RuntimeTransition {
        state: successor,
        outcome: crate::agent_sdk::RuntimeOutcome::Management(result),
    })
}

#[cfg(feature = "pvm")]
enum CleanExecutionAdmission<'a> {
    Direct(core::marker::PhantomData<&'a ()>),
    #[cfg(feature = "std")]
    Attested(&'a super::transition_proof_host::AuthenticatedAttestedTransition),
    #[cfg(all(feature = "agent-runtime", target_arch = "riscv64"))]
    ProofHostAttested(crate::agent_sdk::Hash),
}

#[cfg(feature = "pvm")]
impl CleanExecutionAdmission<'_> {
    fn direct() -> Self {
        Self::Direct(core::marker::PhantomData)
    }
}

#[cfg(feature = "pvm")]
fn apply_clean_invoke(
    state: crate::agent_sdk::RuntimeState,
    work: crate::agent_sdk::InvocationWork,
    authorization: crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
    admission: CleanExecutionAdmission<'_>,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    apply_clean_invoke_inner(state, work, authorization, observed_slot, admission, false)
}

#[cfg(feature = "pvm")]
trait CleanInvocationStorage {
    fn execute(
        &mut self,
        runtime: &StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        run: impl FnOnce(
            &dyn super::actor_storage::ActorRowStorage,
        ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError>,
    ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError>;

    fn commit<T>(
        &mut self,
        runtime: &mut StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        inline: Vec<u8>,
        rows: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        commit: impl FnOnce(&mut StandardAgentRuntime) -> Result<T, ActorExecutionError>,
    ) -> Result<T, ActorExecutionError>;
}

#[cfg(feature = "pvm")]
struct ImageInvocationStorage;

/// Per-execution external IO and an unpublished row/metadata candidate. It
/// cannot publish storage or replace authorization/retry/failure semantics.
#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
struct ExternalInvocationStorage<'a, F> {
    reader: F,
    lanes: &'a [crate::agent_sdk::state_execution::ExternalLaneWork],
    limits: crate::agent_sdk::contract::ExternalStateResourceLimits,
    reads: &'a mut crate::agent_sdk::state_blocks::ReadBudget,
    writes: &'a mut crate::agent_sdk::state_tree::WriteBudget,
    candidate: Option<(RuntimeState, crate::agent_sdk::state_tree::TreeUpdate)>,
}

#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
impl<
    R: crate::agent_sdk::state_tree::BlockReader,
    F: FnMut(crate::agent_sdk::state_blocks::BlockScope) -> R,
> ExternalInvocationStorage<'_, F>
{
    fn readers(
        &mut self,
    ) -> Result<[Option<(crate::agent_sdk::state_tree::StateTree, R)>; 3], ActorExecutionError>
    {
        let mut select = |lane| {
            self.lanes
                .iter()
                .find(|selected| selected.base.context().scope().lane() == lane)
                .map(|selected| {
                    let tree = selected
                        .base
                        .bind(selected.base.context(), selected.base.commitment())
                        .map_err(|_| ActorExecutionError::InvalidAvailability)?;
                    Ok((tree, (self.reader)(tree.scope())))
                })
                .transpose()
        };
        Ok([
            select(crate::agent_sdk::StateLane::Linear)?,
            select(crate::agent_sdk::StateLane::Merge)?,
            select(crate::agent_sdk::StateLane::Local)?,
        ])
    }
}

#[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
impl<
    R: crate::agent_sdk::state_tree::BlockReader,
    F: FnMut(crate::agent_sdk::state_blocks::BlockScope) -> R,
> CleanInvocationStorage for ExternalInvocationStorage<'_, F>
{
    fn execute(
        &mut self,
        runtime: &StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        run: impl FnOnce(
            &dyn super::actor_storage::ActorRowStorage,
        ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError>,
    ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError> {
        let lanes = self.readers()?;
        let reader =
            runtime.resolve_clean_external_storage_reader(work, schema, lanes, self.reads)?;
        let outcome = run(&reader)?;
        // Do not persist a continuation until aggregate external work budgets
        // are carried by that continuation. No yielded writes may escape.
        if matches!(outcome, super::execution::ActorRunOutcome::Yielded { .. }) {
            return Err(ActorExecutionError::InvalidAvailability);
        }
        Ok(outcome)
    }

    fn commit<T>(
        &mut self,
        runtime: &mut StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        _inline: Vec<u8>,
        rows: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        commit: impl FnOnce(&mut StandardAgentRuntime) -> Result<T, ActorExecutionError>,
    ) -> Result<T, ActorExecutionError> {
        if rows.is_empty() {
            return commit(runtime);
        }
        if self.candidate.is_some() {
            return Err(ActorExecutionError::InvalidActorOutput);
        }
        let lanes = self.readers()?;
        let (candidate, update, result) = runtime.prepare_clean_external_row_batch(
            work,
            schema,
            &rows,
            self.limits,
            lanes,
            (self.reads, self.writes),
            commit,
        )?;
        self.candidate = Some((encode_standard_runtime_state(&candidate.snapshot()), update));
        *runtime = candidate;
        Ok(result)
    }
}

#[cfg(feature = "pvm")]
impl CleanInvocationStorage for ImageInvocationStorage {
    fn execute(
        &mut self,
        runtime: &StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        run: impl FnOnce(
            &dyn super::actor_storage::ActorRowStorage,
        ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError>,
    ) -> Result<super::execution::ActorRunOutcome, ActorExecutionError> {
        let reader = runtime.resolve_clean_storage_reader(work, schema)?;
        run(&reader)
    }

    fn commit<T>(
        &mut self,
        runtime: &mut StandardAgentRuntime,
        work: &crate::agent_sdk::InvocationWork,
        schema: &crate::agent_sdk::RuntimeBlob,
        inline: Vec<u8>,
        rows: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        commit: impl FnOnce(&mut StandardAgentRuntime) -> Result<T, ActorExecutionError>,
    ) -> Result<T, ActorExecutionError> {
        if rows.is_empty() {
            commit(runtime)
        } else {
            runtime.commit_clean_row_batch(work, schema, inline, rows, commit)
        }
    }
}

#[cfg(feature = "pvm")]
fn apply_clean_invoke_inner(
    state: crate::agent_sdk::RuntimeState,
    work: crate::agent_sdk::InvocationWork,
    authorization: crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
    admission: CleanExecutionAdmission<'_>,
    decoded_work: bool,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    // Keep one owned encoded rollback image, not both SDK and legacy copies.
    // The fields have identical bytes; only the enclosing wire types differ.
    let original_state = RuntimeState {
        control: state.control,
        linear: state.linear,
        merge: state.merge,
        local: state.local,
    };
    let (runtime, state_limit) = restore_standard_runtime_state(&original_state)?;
    apply_clean_invoke_restored(
        original_state,
        runtime,
        state_limit,
        work,
        authorization,
        observed_slot,
        admission,
        decoded_work,
        &mut ImageInvocationStorage,
    )
}

#[cfg(feature = "pvm")]
fn apply_clean_invoke_restored(
    original_state: RuntimeState,
    mut runtime: StandardAgentRuntime,
    state_limit: usize,
    work: crate::agent_sdk::InvocationWork,
    authorization: crate::agent_sdk::InvocationAuthorization,
    observed_slot: u64,
    admission: CleanExecutionAdmission<'_>,
    decoded_work: bool,
    storage_backend: &mut impl CleanInvocationStorage,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeTransition};
    // Retained authenticated errors can name a missing or stale actor.
    // Recovery begins with full work/authorization verification before any
    // mutation, so do not repeat that verification (including blob hashes and
    // receipt signatures) here. Recover before consulting current actor policy.
    let recovered = if decoded_work {
        runtime.recover_validated_clean_invocation_error(
            ValidatedInvocationWork(&work),
            &authorization,
            observed_slot,
        )
    } else {
        runtime.recover_clean_invocation_error(&work, &authorization, observed_slot)
    };
    match recovered {
        Ok(Some(error)) => {
            let candidate = encode_standard_runtime_state(&runtime.snapshot());
            if candidate.encoded_len().is_none_or(|len| len > state_limit) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::ResultCapacity),
                ));
            }
            return Ok(clean_completed(
                legacy_state_to_clean(candidate),
                Err(error),
            ));
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
        Ok(None) => {}
    }
    // A signed non-execution fence needs no actor execution/proof admission.
    // Existing results/continuations are left to their exact recovery below.
    match runtime.retain_clean_unseen_expiry(&work, &authorization, observed_slot) {
        Ok(true) => {
            let candidate = encode_standard_runtime_state(&runtime.snapshot());
            if candidate.encoded_len().is_none_or(|len| len > state_limit) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::ResultCapacity),
                ));
            }
            return Ok(clean_completed(
                legacy_state_to_clean(candidate),
                Err(InvocationError::ExpiredBeforeExecution),
            ));
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
        Ok(false) => {}
    }
    let policy_admission = match &admission {
        #[cfg(feature = "std")]
        CleanExecutionAdmission::Attested(authenticated) => {
            admit_clean_attested_work(&runtime, authenticated, &work, &authorization)
        }
        #[cfg(all(feature = "agent-runtime", target_arch = "riscv64"))]
        CleanExecutionAdmission::ProofHostAttested(proof_system) => {
            admit_clean_proof_host_work(&runtime, *proof_system, &work, &authorization)
        }
        CleanExecutionAdmission::Direct(_) => {
            admit_clean_public_preflight(&runtime, &work, &authorization)
        }
    };
    if let Err(error) = policy_admission {
        // Missing proof/authorization is non-durable. An authenticated
        // unsupported method or target must retain its exact rejection.
        if error.is_durable_exact_outcome() {
            if let Err(error) = runtime
                .validate_clean_unseen_invocation_slot(&authorization, observed_slot)
                .and_then(|()| {
                    runtime.retain_clean_invocation_error(
                        &work,
                        &authorization,
                        error,
                        observed_slot,
                        None,
                    )
                })
            {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(error),
                ));
            }
            let candidate = encode_standard_runtime_state(&runtime.snapshot());
            if candidate.encoded_len().is_none_or(|len| len > state_limit) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::ResultCapacity),
                ));
            }
            return Ok(clean_completed(
                legacy_state_to_clean(candidate),
                Err(error),
            ));
        }
        return Ok(clean_completed(
            legacy_state_to_clean(original_state),
            Err(error),
        ));
    }
    match runtime.recover_clean_yield(&work, &authorization, observed_slot) {
        Ok(Some(yielded)) => {
            return Ok(RuntimeTransition {
                state: legacy_state_to_clean(original_state),
                outcome: RuntimeOutcome::Yielded(yielded),
            });
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
        Ok(None) => {}
    }
    let recovered_execution = if decoded_work {
        runtime.recover_validated_clean_execution(
            ValidatedInvocationWork(&work),
            &authorization,
            observed_slot,
        )
    } else {
        runtime.recover_clean_execution(&work, &authorization, observed_slot)
    };
    match recovered_execution {
        Ok(Some(reply)) => {
            let mut result = Ok(reply);
            let successor = finish_standard_execution_candidate(
                original_state,
                &runtime,
                true,
                state_limit,
                &mut result,
            );
            return Ok(clean_completed(
                legacy_state_to_clean(successor),
                result.map(clean_reply).map_err(clean_error),
            ));
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
        Ok(None) => {}
    }
    let resolved = if decoded_work {
        runtime.resolve_validated_clean_invocation_for_execution(ValidatedInvocationWork(&work))
    } else {
        runtime.resolve_clean_invocation_for_execution(&work)
    };
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(error) if error.is_durable_exact_outcome() => {
            if let Err(slot_error) =
                runtime.validate_clean_unseen_invocation_slot(&authorization, observed_slot)
            {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(slot_error),
                ));
            }
            if let Err(retention_error) = runtime.retain_clean_invocation_error(
                &work,
                &authorization,
                error,
                observed_slot,
                None,
            ) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(retention_error),
                ));
            }
            let candidate = encode_standard_runtime_state(&runtime.snapshot());
            if candidate.encoded_len().is_none_or(|len| len > state_limit) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::ResultCapacity),
                ));
            }
            return Ok(clean_completed(
                legacy_state_to_clean(candidate),
                Err(error),
            ));
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
    };
    if resolved.work_validated()
        && let Some(reference) = resolved.program_reference()
    {
        // The guest has hashed (or earlier bound) exactly these authenticated
        // bytes to the actor's current ProgramId; later invocations identify
        // the program by this verified reference without hashing it again.
        runtime.bind_program(resolved.actor_id(), reference);
    }
    let (invocation, actor_pvm, actor_schema, actor_policies, installation_data) = resolved.parts();
    let (mut result, commit_candidate) =
        match runtime.recover_execution(&invocation, observed_slot) {
            Ok(Some(_)) | Err(ActorExecutionError::DivergentInvocation) => {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::DivergentInvocation),
                ));
            }
            unseen => {
                match runtime.validate_clean_unseen_invocation_slot(&authorization, observed_slot) {
                    Err(error) => {
                        return Ok(clean_completed(
                            legacy_state_to_clean(original_state),
                            Err(error),
                        ));
                    }
                    Ok(()) => {
                        let pristine = runtime.clone();
                        let mut result = match unseen {
                            Err(error) => Err(error),
                            Ok(None) if work.recovery_only => {
                                Err(ActorExecutionError::InvalidAvailability)
                            }
                            Ok(None) => match runtime
                                .validate_clean_execution_installation_data(
                                    &work,
                                    installation_data.as_ref(),
                                )
                                .and_then(|()| {
                                    runtime.validate_clean_execution_schema(&work, &actor_schema)
                                })
                                .and_then(|()| {
                                    authorize_clean_execution_context(
                                        &runtime,
                                        &admission,
                                        &work,
                                        &authorization,
                                        &actor_schema,
                                        &actor_policies,
                                    )
                                }) {
                                Err(error) => Err(error),
                                Ok(false) => Ok(ActorExecutionReply {
                                    invocation: invocation.invocation,
                                    actor: invocation.actor,
                                    incarnation: invocation.incarnation,
                                    deployment: invocation.deployment,
                                    mode: invocation.mode,
                                    lane: invocation.mode.write_lane(),
                                    status: ActorExecutionStatus::Forbidden,
                                    reply: Vec::new(),
                                    gas_remaining: invocation.gas,
                                    observation: super::execution::ActorObservation::default(),
                                }),
                                Ok(true) => runtime.prepare_execution_state(&invocation).and_then(
                                    |before| {
                                        let visible = before.visible_for(invocation.mode);
                                        let outcome = storage_backend.execute(
                                            &runtime,
                                            &work,
                                            &actor_schema,
                                            |storage| {
                                                super::execution::run_inner_actor_with_storage(
                                                &invocation,
                                                Some(
                                                    crate::agent_sdk::InvocationContext::from_work(
                                                        &work,
                                                        observed_slot,
                                                    ),
                                                ),
                                                &actor_pvm,
                                                installation_data
                                                    .as_ref()
                                                    .map(|data| data.bytes.as_slice()),
                                                &visible,
                                                None,
                                                Some(storage),
                                            )
                                            },
                                        );
                                        outcome.and_then(|outcome| match outcome {
                                            super::execution::ActorRunOutcome::Completed {
                                                mut reply,
                                                state: next_state,
                                                rows,
                                            } => {
                                                if reply.status == ActorExecutionStatus::Done {
                                                    let inline = if rows.is_empty() {
                                                        Vec::new()
                                                    } else {
                                                        invocation
                                                            .mode
                                                            .write_lane()
                                                            .and_then(|lane| next_state.get(lane))
                                                            .unwrap_or_default()
                                                            .to_vec()
                                                    };
                                                    let commit =
                                                        |runtime: &mut StandardAgentRuntime| {
                                                            runtime.commit_resolved_clean_execution(
                                                                &resolved,
                                                                &authorization,
                                                                &mut reply,
                                                                &before,
                                                                next_state,
                                                                observed_slot,
                                                                None,
                                                            )
                                                        };
                                                    storage_backend.commit(
                                                        &mut runtime,
                                                        &work,
                                                        &actor_schema,
                                                        inline,
                                                        rows,
                                                        commit,
                                                    )?;
                                                }
                                                Ok(reply)
                                            }
                                            super::execution::ActorRunOutcome::Yielded {
                                                reply,
                                                state: next_state,
                                                continuation,
                                                rows,
                                            } => {
                                                let inline = if rows.is_empty() {
                                                    Vec::new()
                                                } else {
                                                    invocation
                                                        .mode
                                                        .write_lane()
                                                        .and_then(|lane| next_state.get(lane))
                                                        .unwrap_or_default()
                                                        .to_vec()
                                                };
                                                let commit =
                                                    |runtime: &mut StandardAgentRuntime| {
                                                        runtime.commit_yielded_execution(
                                        &invocation,
                                        &reply,
                                        &before,
                                        next_state,
                                        observed_slot,
                                        None,
                                        continuation,
                                        Some((
                                            super::standard::StandardAcceptedInvocation::from_work(
                                                &work,
                                            ),
                                            authorization.clone(),
                                        )),
                                    )
                                                    };
                                                storage_backend.commit(
                                                    &mut runtime,
                                                    &work,
                                                    &actor_schema,
                                                    inline,
                                                    rows,
                                                    commit,
                                                )?;
                                                Ok(reply)
                                            }
                                        })
                                    },
                                ),
                            },
                            Ok(Some(_)) => unreachable!("exact recovery returned above"),
                        };
                        let committed = finalize_unseen_clean_outcome(
                            &mut runtime,
                            pristine,
                            &work,
                            &authorization,
                            &invocation,
                            observed_slot,
                            None,
                            &mut result,
                        );
                        (result, committed)
                    }
                }
            }
        };
    let successor = finish_standard_execution_candidate(
        original_state,
        &runtime,
        commit_candidate,
        state_limit,
        &mut result,
    );
    let state = legacy_state_to_clean(successor);
    if matches!(&result, Ok(reply) if reply.status == ActorExecutionStatus::Yielded) {
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, observed_slot)
            .map_err(|_| DecodeError::NonCanonical)?
            .ok_or(DecodeError::NonCanonical)?;
        Ok(RuntimeTransition {
            state,
            outcome: RuntimeOutcome::Yielded(yielded),
        })
    } else {
        Ok(clean_completed(
            state,
            result.map(clean_reply).map_err(clean_error),
        ))
    }
}

#[cfg(feature = "pvm")]
fn apply_clean_resume(
    state: crate::agent_sdk::RuntimeState,
    resume: crate::agent_sdk::ResumeWork,
    admission: CleanExecutionAdmission<'_>,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    // Resume needs the same single owned rollback image as Invoke/ACK.
    let original_state = RuntimeState {
        control: state.control,
        linear: state.linear,
        merge: state.merge,
        local: state.local,
    };
    let (runtime, state_limit) = restore_standard_runtime_state(&original_state)?;
    apply_clean_resume_restored(
        original_state,
        runtime,
        state_limit,
        resume,
        admission,
        &mut ImageInvocationStorage,
    )
}

#[cfg(feature = "pvm")]
fn apply_clean_resume_restored(
    original_state: RuntimeState,
    mut runtime: StandardAgentRuntime,
    state_limit: usize,
    resume: crate::agent_sdk::ResumeWork,
    admission: CleanExecutionAdmission<'_>,
    storage_backend: &mut impl CleanInvocationStorage,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeTransition};
    if resume.input.is_some() {
        // Cooperative continuations accept no external completion payload.
        // A mismatched resume must not become a durable error for the
        // original invocation or retire its still-valid continuation.
        return Ok(clean_completed(
            legacy_state_to_clean(original_state),
            Err(InvocationError::StaleContinuation),
        ));
    }
    let (record, work) = match runtime.resolve_clean_resume(&resume) {
        Ok(value) => value,
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
    };
    let authorization = record
        .authorization
        .clone()
        .ok_or(DecodeError::NonCanonical)?;
    let resolved = match runtime.resolve_clean_invocation_for_execution(&work) {
        Ok(value) => value,
        Err(error) if error.is_durable_exact_outcome() => {
            if let Err(error) = runtime.retain_clean_invocation_error(
                &work,
                &authorization,
                error,
                record.observed_slot,
                Some(record.ready_sequence),
            ) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(error),
                ));
            }
            let candidate = encode_standard_runtime_state(&runtime.snapshot());
            if candidate.encoded_len().is_none_or(|len| len > state_limit) {
                return Ok(clean_completed(
                    legacy_state_to_clean(original_state),
                    Err(InvocationError::ResultCapacity),
                ));
            }
            return Ok(clean_completed(
                legacy_state_to_clean(candidate),
                Err(error),
            ));
        }
        Err(error) => {
            return Ok(clean_completed(
                legacy_state_to_clean(original_state),
                Err(error),
            ));
        }
    };
    let (invocation, actor_pvm, actor_schema, actor_policies, installation_data) = resolved.parts();
    if invocation.commitment() != record.request {
        return Ok(clean_completed(
            legacy_state_to_clean(original_state),
            Err(InvocationError::StaleContinuation),
        ));
    }
    let accepted = record.accepted.clone().ok_or(DecodeError::NonCanonical)?;
    let observed_slot = record.observed_slot;
    let pristine = runtime.clone();
    let mut terminal_sequence = None;
    let mut result = runtime
        .verify_clean_invocation_authorization(&work, &authorization, observed_slot)
        .map_err(|_| ActorExecutionError::InvalidAuthorization)
        .and_then(|()| {
            runtime.validate_clean_execution_installation_data(&work, installation_data.as_ref())
        })
        .and_then(|()| runtime.validate_clean_execution_schema(&work, &actor_schema))
        .and_then(|()| {
            authorize_clean_execution_context(
                &runtime,
                &admission,
                &work,
                &authorization,
                &actor_schema,
                &actor_policies,
            )
        })
        .and_then(|authorized| {
            if !authorized {
                return Err(ActorExecutionError::InvalidAuthorization);
            }
            runtime.prepare_execution_state(&invocation)
        })
        .and_then(|before| {
            let visible = before.visible_for(invocation.mode);
            let outcome = storage_backend.execute(&runtime, &work, &actor_schema, |storage| {
                super::execution::run_inner_actor_with_storage(
                    &invocation,
                    Some(crate::agent_sdk::InvocationContext::from_work(
                        &work,
                        observed_slot,
                    )),
                    &actor_pvm,
                    installation_data.as_ref().map(|data| data.bytes.as_slice()),
                    &visible,
                    Some(record.continuation.clone()),
                    Some(storage),
                )
            });
            outcome.and_then(|outcome| match outcome {
                super::execution::ActorRunOutcome::Completed {
                    mut reply,
                    state: next_state,
                    rows,
                } => {
                    if reply.status == ActorExecutionStatus::Done {
                        let inline = if rows.is_empty() {
                            Vec::new()
                        } else {
                            invocation
                                .mode
                                .write_lane()
                                .and_then(|lane| next_state.get(lane))
                                .unwrap_or_default()
                                .to_vec()
                        };
                        let commit = |runtime: &mut StandardAgentRuntime| {
                            runtime.commit_resolved_clean_execution(
                                &resolved,
                                &authorization,
                                &mut reply,
                                &before,
                                next_state,
                                observed_slot,
                                Some(record.ready_sequence),
                            )
                        };
                        storage_backend.commit(
                            &mut runtime,
                            &work,
                            &actor_schema,
                            inline,
                            rows,
                            commit,
                        )?;
                    } else {
                        terminal_sequence = Some(record.ready_sequence);
                    }
                    Ok(reply)
                }
                super::execution::ActorRunOutcome::Yielded {
                    reply,
                    state: next_state,
                    continuation,
                    rows,
                } => {
                    let inline = if rows.is_empty() {
                        Vec::new()
                    } else {
                        invocation
                            .mode
                            .write_lane()
                            .and_then(|lane| next_state.get(lane))
                            .unwrap_or_default()
                            .to_vec()
                    };
                    let commit = |runtime: &mut StandardAgentRuntime| {
                        runtime.commit_yielded_execution(
                            &invocation,
                            &reply,
                            &before,
                            next_state,
                            observed_slot,
                            Some(record.ready_sequence),
                            continuation,
                            Some((accepted.clone(), authorization.clone())),
                        )
                    };
                    storage_backend.commit(
                        &mut runtime,
                        &work,
                        &actor_schema,
                        inline,
                        rows,
                        commit,
                    )?;
                    Ok(reply)
                }
            })
        });
    if matches!(&result, Err(error) if error.is_durable_exact_outcome()) {
        terminal_sequence = Some(record.ready_sequence);
    }
    let commit_candidate = finalize_unseen_clean_outcome(
        &mut runtime,
        pristine,
        &work,
        &authorization,
        &invocation,
        observed_slot,
        terminal_sequence,
        &mut result,
    );
    let successor = finish_standard_execution_candidate(
        original_state,
        &runtime,
        commit_candidate,
        state_limit,
        &mut result,
    );
    let state = legacy_state_to_clean(successor);
    if matches!(&result, Ok(reply) if reply.status == ActorExecutionStatus::Yielded) {
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, observed_slot)
            .map_err(|_| DecodeError::NonCanonical)?
            .ok_or(DecodeError::NonCanonical)?;
        Ok(RuntimeTransition {
            state,
            outcome: RuntimeOutcome::Yielded(yielded),
        })
    } else {
        Ok(clean_completed(
            state,
            result.map(clean_reply).map_err(clean_error),
        ))
    }
}

#[cfg(feature = "pvm")]
fn apply_clean_acknowledge(
    state: crate::agent_sdk::RuntimeState,
    work: crate::agent_sdk::InvocationRetirement,
    authorization: crate::agent_sdk::InvocationAuthorization,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    // Retain one owned rollback image across admission and retirement. Keeping
    // an additional SDK copy can exhaust the guest heap near the state limit.
    let original_state = RuntimeState {
        control: state.control,
        linear: state.linear,
        merge: state.merge,
        local: state.local,
    };
    let (runtime, state_limit) = restore_standard_runtime_state(&original_state)?;
    apply_clean_acknowledge_restored(original_state, runtime, state_limit, work, authorization)
}

#[cfg(feature = "pvm")]
fn apply_clean_acknowledge_restored(
    original_state: RuntimeState,
    mut runtime: StandardAgentRuntime,
    state_limit: usize,
    work: crate::agent_sdk::InvocationRetirement,
    authorization: crate::agent_sdk::InvocationAuthorization,
) -> Result<crate::agent_sdk::RuntimeTransition, DecodeError> {
    use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeTransition};
    // Acknowledge retires an already retained exact result; it does not
    // execute the actor method again. Re-running the current AMP2 method
    // policy here would make a Required-attestation result impossible to
    // retire through the deliberately Direct housekeeping route. The runtime
    // below authenticates the original work, authorization, preflight, and
    // exact retained result before removing anything.
    let acknowledged = runtime.acknowledge_clean_retirement_with_status(&work, &authorization);
    let acknowledgement = match acknowledged {
        Ok((acknowledgement, true)) => acknowledgement,
        Ok((acknowledgement, false)) => {
            return Ok(RuntimeTransition {
                state: legacy_state_to_clean(original_state),
                outcome: RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
            });
        }
        Err(error) => {
            return Ok(RuntimeTransition {
                state: legacy_state_to_clean(original_state),
                outcome: RuntimeOutcome::Acknowledged(Err(error)),
            });
        }
    };
    let successor = encode_standard_runtime_state(&runtime.snapshot());
    if successor
        .encoded_len()
        .is_none_or(|encoded_len| encoded_len > state_limit)
    {
        return Ok(RuntimeTransition {
            state: legacy_state_to_clean(original_state),
            outcome: RuntimeOutcome::Acknowledged(Err(InvocationError::ResultCapacity)),
        });
    }
    Ok(RuntimeTransition {
        state: legacy_state_to_clean(successor),
        outcome: RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
    })
}

pub(crate) fn admit_clean_public_preflight(
    runtime: &StandardAgentRuntime,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Result<(), crate::agent_sdk::InvocationError> {
    let (_, _, schema, policies, _) = runtime.resolve_clean_invocation(work)?;
    match runtime.authorize_clean_execution(work, authorization, &schema, &policies) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::agent_sdk::InvocationError::InvalidAuthorization),
        Err(error) => Err(clean_error(error)),
    }
}

#[cfg(all(feature = "pvm", feature = "std"))]
fn admit_clean_attested_work(
    runtime: &StandardAgentRuntime,
    authenticated: &super::transition_proof_host::AuthenticatedAttestedTransition,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Result<(), crate::agent_sdk::InvocationError> {
    let (_, _, schema, policies, _) = runtime.resolve_clean_invocation(work)?;
    match runtime.authorize_clean_attested_execution(
        authenticated,
        work,
        authorization,
        &schema,
        &policies,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::agent_sdk::InvocationError::InvalidAuthorization),
        Err(error) => Err(clean_error(error)),
    }
}

#[cfg(all(feature = "pvm", feature = "agent-runtime", target_arch = "riscv64"))]
fn admit_clean_proof_host_work(
    runtime: &StandardAgentRuntime,
    proof_system: crate::agent_sdk::Hash,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
) -> Result<(), crate::agent_sdk::InvocationError> {
    let (_, _, schema, policies, _) = runtime.resolve_clean_invocation(work)?;
    match runtime.authorize_clean_proof_host_execution(
        proof_system,
        work,
        authorization,
        &schema,
        &policies,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::agent_sdk::InvocationError::InvalidAuthorization),
        Err(error) => Err(clean_error(error)),
    }
}

#[cfg(feature = "pvm")]
fn authorize_clean_execution_context(
    runtime: &StandardAgentRuntime,
    admission: &CleanExecutionAdmission<'_>,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    schema: &crate::agent_sdk::RuntimeBlob,
    policies: &crate::agent_sdk::RuntimeBlob,
) -> Result<bool, ActorExecutionError> {
    match admission {
        #[cfg(feature = "std")]
        CleanExecutionAdmission::Attested(authenticated) => runtime
            .authorize_clean_attested_execution(
                authenticated,
                work,
                authorization,
                schema,
                policies,
            ),
        #[cfg(all(feature = "agent-runtime", target_arch = "riscv64"))]
        CleanExecutionAdmission::ProofHostAttested(proof_system) => runtime
            .authorize_clean_proof_host_execution(
                *proof_system,
                work,
                authorization,
                schema,
                policies,
            ),
        CleanExecutionAdmission::Direct(_) => {
            runtime.authorize_clean_execution(work, authorization, schema, policies)
        }
    }
}

#[cfg(feature = "pvm")]
fn clean_completed(
    state: crate::agent_sdk::RuntimeState,
    result: Result<crate::agent_sdk::InvocationReply, crate::agent_sdk::InvocationError>,
) -> crate::agent_sdk::RuntimeTransition {
    crate::agent_sdk::RuntimeTransition {
        state,
        outcome: crate::agent_sdk::RuntimeOutcome::Completed(result),
    }
}

#[cfg(feature = "pvm")]
fn clean_state_to_legacy(state: &crate::agent_sdk::RuntimeState) -> RuntimeState {
    RuntimeState {
        control: state.control.clone(),
        linear: state.linear.clone(),
        merge: state.merge.clone(),
        local: state.local.clone(),
    }
}

#[cfg(feature = "pvm")]
fn legacy_state_to_clean(state: RuntimeState) -> crate::agent_sdk::RuntimeState {
    crate::agent_sdk::RuntimeState {
        control: state.control,
        linear: state.linear,
        merge: state.merge,
        local: state.local,
    }
}

fn standard_state_limit(state: &StandardRuntimeState) -> usize {
    let hard = super::execution::MAX_RUNTIME_STATE_BYTES;
    state.config.as_ref().map_or(hard, |config| {
        hard.min(config.runtime_contract.resources.max_runtime_state_bytes as usize)
    })
}

#[cfg(any(feature = "pvm", feature = "std"))]
pub(crate) fn clean_reply(reply: ActorExecutionReply) -> crate::agent_sdk::InvocationReply {
    crate::agent_sdk::InvocationReply {
        invocation: crate::agent_sdk::InvocationId(reply.invocation.0),
        actor: crate::agent_sdk::ActorId(reply.actor.0),
        incarnation: crate::agent_sdk::Hash(reply.incarnation.0),
        deployment: crate::agent_sdk::DeploymentId(reply.deployment.0),
        mode: clean_mode(reply.mode),
        lane: reply.lane.map(clean_lane),
        status: match reply.status {
            ActorExecutionStatus::Done => crate::agent_sdk::InvocationStatus::Done,
            ActorExecutionStatus::Forbidden => crate::agent_sdk::InvocationStatus::Forbidden,
            ActorExecutionStatus::Panicked => crate::agent_sdk::InvocationStatus::Panicked,
            ActorExecutionStatus::OutOfGas => crate::agent_sdk::InvocationStatus::OutOfGas,
            ActorExecutionStatus::Yielded => unreachable!("yield is a distinct clean outcome"),
        },
        reply: reply.reply,
        gas_remaining: reply.gas_remaining,
        observation: crate::agent_sdk::InvocationObservation {
            linear_revision: reply.observation.linear_revision,
            merge_frontier: reply
                .observation
                .merge_frontier
                .map(|value| crate::agent_sdk::Hash(value.0)),
            local_revision: reply.observation.local_revision,
        },
    }
}

#[cfg(any(feature = "pvm", feature = "std"))]
const fn clean_lane(lane: StateLane) -> crate::agent_sdk::StateLane {
    match lane {
        StateLane::Linear => crate::agent_sdk::StateLane::Linear,
        StateLane::Merge => crate::agent_sdk::StateLane::Merge,
        StateLane::Local => crate::agent_sdk::StateLane::Local,
    }
}

#[cfg(any(feature = "pvm", feature = "std"))]
const fn clean_mode(mode: super::MethodMode) -> crate::agent_sdk::MethodMode {
    match mode {
        super::MethodMode::Query => crate::agent_sdk::MethodMode::Query,
        super::MethodMode::LinearizableQuery => crate::agent_sdk::MethodMode::LinearizableQuery,
        super::MethodMode::LocalQuery => crate::agent_sdk::MethodMode::LocalQuery,
        super::MethodMode::Linear => crate::agent_sdk::MethodMode::Linear,
        super::MethodMode::Merge => crate::agent_sdk::MethodMode::Merge,
        super::MethodMode::Local => crate::agent_sdk::MethodMode::Local,
    }
}

const fn clean_error(error: ActorExecutionError) -> crate::agent_sdk::InvocationError {
    use crate::agent_sdk::InvocationError;
    match error {
        ActorExecutionError::NotCreated => InvocationError::NotCreated,
        ActorExecutionError::NotFound => InvocationError::NotFound,
        ActorExecutionError::StaleIncarnation => InvocationError::StaleIncarnation,
        ActorExecutionError::Suspended => InvocationError::Suspended,
        ActorExecutionError::StaleDeployment => InvocationError::StaleDeployment,
        ActorExecutionError::WrongProgram => InvocationError::WrongProgram,
        ActorExecutionError::UnsupportedMethod => InvocationError::UnsupportedMethod,
        ActorExecutionError::UnsupportedResultStorage => InvocationError::UnsupportedResultStorage,
        ActorExecutionError::MissingState => InvocationError::MissingState,
        ActorExecutionError::InvalidAvailability => InvocationError::InvalidAvailability,
        ActorExecutionError::InvalidInput => InvocationError::InvalidInput,
        ActorExecutionError::InvalidActorOutput => InvocationError::InvalidActorOutput,
        ActorExecutionError::DivergentInvocation => InvocationError::DivergentInvocation,
        ActorExecutionError::ResultCapacity => InvocationError::ResultCapacity,
        ActorExecutionError::InvalidAuthorization => InvocationError::InvalidAuthorization,
        ActorExecutionError::AuthorityExpired => InvocationError::AuthorityExpired,
        ActorExecutionError::AuthoritySlotRegressed => InvocationError::AuthoritySlotRegressed,
        ActorExecutionError::ContinuationNotReady => InvocationError::NotReady,
        ActorExecutionError::UnsupportedHostCall(call) => {
            InvocationError::UnsupportedHostCall(call)
        }
    }
}

#[cfg(feature = "pvm")]
fn finish_standard_execution_candidate(
    original_state: RuntimeState,
    runtime: &StandardAgentRuntime,
    commit_candidate: bool,
    state_limit: usize,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) -> RuntimeState {
    if !commit_candidate {
        return original_state;
    }
    let candidate = encode_standard_runtime_state(&runtime.snapshot());
    if candidate.encoded_len().is_none_or(|len| len > state_limit) {
        *result = Err(ActorExecutionError::ResultCapacity);
        original_state
    } else {
        candidate
    }
}

/// Clean terminal replies and durable typed errors retain the exact
/// authenticated outcome, never candidate actor writes.
#[cfg(feature = "pvm")]
#[allow(clippy::too_many_arguments)]
fn finalize_unseen_clean_outcome(
    runtime: &mut StandardAgentRuntime,
    pristine: StandardAgentRuntime,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    invocation: &ActorInvocation,
    observed_slot: u64,
    terminal_continuation: Option<u64>,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) -> bool {
    if let Err(error) = result
        && error.is_durable_exact_outcome()
    {
        let error = clean_error(*error);
        *runtime = pristine;
        return match runtime.retain_clean_invocation_error(
            work,
            authorization,
            error,
            observed_slot,
            terminal_continuation,
        ) {
            Ok(()) => true,
            Err(error) => {
                // Retention failures are nonterminal and commit nothing.
                *result = Err(match error {
                    crate::agent_sdk::InvocationError::ResultCapacity => {
                        ActorExecutionError::ResultCapacity
                    }
                    crate::agent_sdk::InvocationError::AuthorityExpired => {
                        ActorExecutionError::AuthorityExpired
                    }
                    crate::agent_sdk::InvocationError::AuthoritySlotRegressed => {
                        ActorExecutionError::AuthoritySlotRegressed
                    }
                    crate::agent_sdk::InvocationError::UnsupportedResultStorage => {
                        ActorExecutionError::UnsupportedResultStorage
                    }
                    crate::agent_sdk::InvocationError::DivergentInvocation
                    | crate::agent_sdk::InvocationError::StaleContinuation => {
                        ActorExecutionError::DivergentInvocation
                    }
                    _ => ActorExecutionError::InvalidAuthorization,
                });
                false
            }
        };
    }
    if let Ok(reply) = result
        && matches!(
            reply.status,
            ActorExecutionStatus::Forbidden
                | ActorExecutionStatus::Panicked
                | ActorExecutionStatus::OutOfGas
        )
    {
        *runtime = pristine;
        return match runtime.retain_clean_terminal_failure(
            work,
            authorization,
            invocation,
            reply,
            observed_slot,
            terminal_continuation,
        ) {
            Ok(()) => true,
            Err(error) => {
                *result = Err(error);
                false
            }
        };
    }
    finalize_unseen_standard_outcome(
        runtime,
        pristine,
        invocation,
        observed_slot,
        terminal_continuation,
        result,
    )
}

/// Finish a fresh, authenticated execution result. `Done` has already passed
/// through `commit_execution`; Yielded has already committed its lane image
/// and continuation. Every externally retained terminal/error result is
/// instead rebased on `pristine`, consumes a resumed continuation if present,
/// and advances only its owning clock.
#[cfg(feature = "pvm")]
fn finalize_unseen_standard_outcome(
    runtime: &mut StandardAgentRuntime,
    pristine: StandardAgentRuntime,
    invocation: &ActorInvocation,
    observed_slot: u64,
    terminal_continuation: Option<u64>,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) -> bool {
    if matches!(
        result,
        Ok(reply) if reply.status == ActorExecutionStatus::Yielded
    ) {
        return true;
    }
    let external_exact = match result {
        Ok(reply) => reply.status != ActorExecutionStatus::Done,
        Err(error) => error.is_durable_exact_outcome(),
    };
    if external_exact {
        // A failed Done commit may have changed a candidate lane before
        // detecting a deterministic guest error. Discard every such candidate
        // before advancing the sole permitted result-component clock.
        *runtime = pristine;
        if let Some(sequence) = terminal_continuation
            && let Err(error) = runtime.consume_machine_continuation(invocation, sequence)
        {
            *result = Err(error);
            return false;
        }
        return match runtime.commit_exact_outcome_clock(invocation, observed_slot) {
            Ok(()) => true,
            Err(error) => {
                *result = Err(error);
                false
            }
        };
    }
    if result.is_ok() {
        true
    } else {
        *runtime = pristine;
        false
    }
}

fn encode_runtime_state(encoder: &mut Encoder<'_>, state: &RuntimeState) {
    encoder.bytes(&state.control);
    encoder.bytes(&state.linear);
    encoder.bytes(&state.merge);
    encoder.bytes(&state.local);
}

fn decode_runtime_state(decoder: &mut Decoder<'_>) -> Result<RuntimeState, DecodeError> {
    let mut remaining = super::execution::MAX_RUNTIME_STATE_BYTES;
    let control = decoder.bytes_ref()?;
    if control.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let control = control.to_vec();
    remaining -= control.len();
    let linear = decoder.bytes_ref()?;
    if linear.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let linear = linear.to_vec();
    remaining -= linear.len();
    let merge = decoder.bytes_ref()?;
    if merge.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let merge = merge.to_vec();
    remaining -= merge.len();
    let local = decoder.bytes_ref()?;
    if local.len() > remaining {
        return Err(DecodeError::LimitExceeded);
    }
    let local = local.to_vec();
    Ok(RuntimeState {
        control,
        linear,
        merge,
        local,
    })
}

fn encode_actor_invocation(encoder: &mut Encoder<'_>, invocation: &ActorInvocation) {
    encoder.fixed(&invocation.invocation.0);
    encoder.fixed(&invocation.actor.0);
    encoder.fixed(&invocation.incarnation.0);
    encoder.fixed(&invocation.deployment.0);
    encoder.fixed(&invocation.program.0);
    encoder.u8(encode_method_mode(invocation.mode));
    encode_invocation_auth(encoder, &invocation.auth);
    encoder.bytes(&invocation.message);
    encoder.list(&invocation.availability, |encoder, blob| {
        encode_blob(encoder, &blob.reference);
        encoder.bytes(&blob.bytes);
    });
    encoder.u64(invocation.gas);
}

fn decode_actor_invocation(decoder: &mut Decoder<'_>) -> Result<ActorInvocation, DecodeError> {
    let invocation = crate::service::InvocationId(decoder.fixed()?);
    let actor = ActorId(decoder.fixed()?);
    let incarnation = Hash(decoder.fixed()?);
    let deployment = DeploymentId(decoder.fixed()?);
    let program = ProgramId(decoder.fixed()?);
    let mode = decode_method_mode(decoder.u8()?)?;
    let auth = decode_invocation_auth(decoder)?;
    let message = {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::execution::MAX_EXECUTION_MESSAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        bytes.to_vec()
    };
    let mut availability_remaining = super::execution::MAX_EXECUTION_AVAILABILITY_BYTES;
    let availability = decoder.list(|decoder| {
        let reference = decode_blob(decoder)?;
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > availability_remaining {
            return Err(DecodeError::LimitExceeded);
        }
        availability_remaining -= bytes.len();
        Ok(RuntimeBlob {
            reference,
            bytes: bytes.to_vec(),
        })
    })?;
    Ok(ActorInvocation {
        invocation,
        actor,
        incarnation,
        deployment,
        program,
        mode,
        auth,
        message,
        availability,
        gas: decoder.u64()?,
    })
}

fn encode_invocation_auth(encoder: &mut Encoder<'_>, auth: &ActorInvocationAuth) {
    crate::service::encode_origin(encoder, auth.origin);
    encoder.option(&auth.principal, |encoder, principal| {
        encoder.fixed(&principal.0)
    });
    encoder.option(&auth.origin_service, crate::service::encode_service);
    encoder.option(&auth.space_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.actor_role, |encoder, role| encoder.u8(*role));
    encoder.option(&auth.capability, |encoder, capability| {
        encoder.fixed(&capability.0)
    });
}

fn decode_invocation_auth(decoder: &mut Decoder<'_>) -> Result<ActorInvocationAuth, DecodeError> {
    let auth = ActorInvocationAuth {
        origin: crate::service::decode_origin(decoder)?,
        principal: decoder.option(|decoder| Ok(crate::service::PrincipalId(decoder.fixed()?)))?,
        origin_service: decoder.option(crate::service::decode_service)?,
        space_role: decoder.option(Decoder::u8)?,
        actor_role: decoder.option(Decoder::u8)?,
        capability: decoder.option(|decoder| Ok(CapabilityId(decoder.fixed()?)))?,
    };
    auth.validate()
        .then_some(auth)
        .ok_or(DecodeError::NonCanonical)
}

pub(crate) fn encode_execution_reply(encoder: &mut Encoder<'_>, reply: &ActorExecutionReply) {
    encoder.fixed(&reply.invocation.0);
    encoder.fixed(&reply.actor.0);
    encoder.fixed(&reply.incarnation.0);
    encoder.fixed(&reply.deployment.0);
    encoder.u8(encode_method_mode(reply.mode));
    encoder.option(&reply.lane, |encoder, lane| encoder.u8(*lane as u8));
    encoder.u8(reply.status as u8);
    encoder.bytes(&reply.reply);
    encoder.u64(reply.gas_remaining);
    encoder.option(&reply.observation.linear_revision, |encoder, revision| {
        encoder.u64(*revision)
    });
    encoder.option(&reply.observation.merge_frontier, |encoder, frontier| {
        encoder.fixed(&frontier.0)
    });
    encoder.option(&reply.observation.local_revision, |encoder, revision| {
        encoder.u64(*revision)
    });
}

pub(crate) fn decode_execution_reply(
    decoder: &mut Decoder<'_>,
) -> Result<ActorExecutionReply, DecodeError> {
    let reply = ActorExecutionReply {
        invocation: crate::service::InvocationId(decoder.fixed()?),
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        deployment: DeploymentId(decoder.fixed()?),
        mode: decode_method_mode(decoder.u8()?)?,
        lane: decoder.option(|decoder| decode_state_lane(decoder.u8()?))?,
        status: match decoder.u8()? {
            0 => ActorExecutionStatus::Done,
            1 => ActorExecutionStatus::Forbidden,
            2 => ActorExecutionStatus::Panicked,
            3 => ActorExecutionStatus::OutOfGas,
            4 => ActorExecutionStatus::Yielded,
            _ => return Err(DecodeError::InvalidTag),
        },
        reply: {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::execution::MAX_EXECUTION_REPLY_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            bytes.to_vec()
        },
        gas_remaining: decoder.u64()?,
        observation: super::execution::ActorObservation {
            linear_revision: decoder.option(Decoder::u64)?,
            merge_frontier: decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?,
            local_revision: decoder.option(Decoder::u64)?,
        },
    };
    validate_execution_reply(&reply)?;
    Ok(reply)
}

pub(crate) fn validate_execution_reply(reply: &ActorExecutionReply) -> Result<(), DecodeError> {
    if reply.invocation == crate::service::InvocationId::ZERO
        || reply.actor == ActorId::ZERO
        || reply.incarnation == Hash::ZERO
        || reply.deployment == DeploymentId::ZERO
        || reply.lane != reply.mode.write_lane()
        || reply.reply.len() > super::execution::MAX_EXECUTION_REPLY_BYTES
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

pub(crate) fn encode_execution_error(encoder: &mut Encoder<'_>, error: ActorExecutionError) {
    match error {
        ActorExecutionError::NotCreated => encoder.u8(0),
        ActorExecutionError::NotFound => encoder.u8(1),
        ActorExecutionError::Suspended => encoder.u8(2),
        ActorExecutionError::StaleDeployment => encoder.u8(3),
        ActorExecutionError::WrongProgram => encoder.u8(4),
        ActorExecutionError::UnsupportedMethod => encoder.u8(5),
        ActorExecutionError::MissingState => encoder.u8(6),
        ActorExecutionError::InvalidAvailability => encoder.u8(7),
        ActorExecutionError::InvalidInput => encoder.u8(8),
        ActorExecutionError::InvalidActorOutput => encoder.u8(9),
        ActorExecutionError::UnsupportedHostCall(id) => {
            encoder.u8(10);
            encoder.u64(id);
        }
        ActorExecutionError::DivergentInvocation => encoder.u8(11),
        ActorExecutionError::ResultCapacity => encoder.u8(12),
        ActorExecutionError::InvalidAuthorization => encoder.u8(13),
        ActorExecutionError::AuthorityExpired => encoder.u8(14),
        ActorExecutionError::AuthoritySlotRegressed => encoder.u8(15),
        ActorExecutionError::StaleIncarnation => encoder.u8(16),
        ActorExecutionError::UnsupportedResultStorage => encoder.u8(17),
        ActorExecutionError::ContinuationNotReady => encoder.u8(18),
    }
}

pub(crate) fn decode_execution_error(
    decoder: &mut Decoder<'_>,
) -> Result<ActorExecutionError, DecodeError> {
    Ok(match decoder.u8()? {
        0 => ActorExecutionError::NotCreated,
        1 => ActorExecutionError::NotFound,
        2 => ActorExecutionError::Suspended,
        3 => ActorExecutionError::StaleDeployment,
        4 => ActorExecutionError::WrongProgram,
        5 => ActorExecutionError::UnsupportedMethod,
        6 => ActorExecutionError::MissingState,
        7 => ActorExecutionError::InvalidAvailability,
        8 => ActorExecutionError::InvalidInput,
        9 => ActorExecutionError::InvalidActorOutput,
        10 => ActorExecutionError::UnsupportedHostCall(decoder.u64()?),
        11 => ActorExecutionError::DivergentInvocation,
        12 => ActorExecutionError::ResultCapacity,
        13 => ActorExecutionError::InvalidAuthorization,
        14 => ActorExecutionError::AuthorityExpired,
        15 => ActorExecutionError::AuthoritySlotRegressed,
        16 => ActorExecutionError::StaleIncarnation,
        17 => ActorExecutionError::UnsupportedResultStorage,
        18 => ActorExecutionError::ContinuationNotReady,
        _ => return Err(DecodeError::InvalidTag),
    })
}

/// Canonical nested codec shared by the runtime-return ABI and durable
/// invocation outcomes. Keeping one implementation prevents exact-result
/// recovery from assigning different tags or validation rules to a result
/// which crossed the live runtime boundary first.
pub(crate) fn encode_execution_result(
    encoder: &mut Encoder<'_>,
    result: &Result<ActorExecutionReply, ActorExecutionError>,
) {
    match result {
        Ok(reply) => {
            encoder.bool(true);
            encode_execution_reply(encoder, reply);
        }
        Err(error) => {
            encoder.bool(false);
            encode_execution_error(encoder, *error);
        }
    }
}

pub(crate) fn decode_execution_result(
    decoder: &mut Decoder<'_>,
) -> Result<Result<ActorExecutionReply, ActorExecutionError>, DecodeError> {
    if decoder.bool()? {
        Ok(Ok(decode_execution_reply(decoder)?))
    } else {
        Ok(Err(decode_execution_error(decoder)?))
    }
}

const fn encode_method_mode(mode: MethodMode) -> u8 {
    match mode {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::LocalQuery => 2,
        MethodMode::Linear => 3,
        MethodMode::Merge => 4,
        MethodMode::Local => 5,
    }
}

fn decode_method_mode(value: u8) -> Result<MethodMode, DecodeError> {
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

const fn encode_invocation_scope(scope: InvocationScope) -> u8 {
    scope as u8
}

fn decode_invocation_scope(value: u8) -> Result<InvocationScope, DecodeError> {
    match value {
        0 => Ok(InvocationScope::Ordered),
        1 => Ok(InvocationScope::Merge),
        2 => Ok(InvocationScope::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

const fn invocation_scope_for_lane(lane: StateLane) -> InvocationScope {
    match lane {
        StateLane::Linear => InvocationScope::Ordered,
        StateLane::Merge => InvocationScope::Merge,
        StateLane::Local => InvocationScope::Local,
    }
}

const fn invocation_result_storage_tag(storage: super::InvocationResultStorage) -> u8 {
    match storage {
        super::InvocationResultStorage::Control => 0,
        super::InvocationResultStorage::Lane(StateLane::Linear) => 1,
        super::InvocationResultStorage::Lane(StateLane::Merge) => 2,
        super::InvocationResultStorage::Lane(StateLane::Local) => 3,
    }
}

fn decode_state_lane(value: u8) -> Result<StateLane, DecodeError> {
    match value {
        0 => Ok(StateLane::Linear),
        1 => Ok(StateLane::Merge),
        2 => Ok(StateLane::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_request(encoder: &mut Encoder<'_>, request: &LifecycleRequest) {
    match request {
        LifecycleRequest::Create(config) => {
            encoder.u8(0);
            encode_config(encoder, config);
        }
        LifecycleRequest::Inspect { after, limit } => {
            encoder.u8(1);
            encoder.option(after, |encoder, actor| encoder.fixed(&actor.0));
            encoder.u16(*limit);
        }
        LifecycleRequest::Install(install) => {
            encoder.u8(2);
            encoder.fixed(install.installation_id.as_bytes());
            encoder.fixed(&install.registry_reservation.0);
            encode_entry(encoder, &install.entry);
            encoder.fixed(&install.producer.0);
            encode_blob(encoder, &install.package);
            encode_blob(encoder, &install.agent_schema);
            encode_blob(encoder, &install.role_policies);
            encoder.fixed(&install.constructor_abi.0);
            encoder.option(&install.installation_data, encode_installation_data);
            encoder.fixed(&install.state_layout.0);
            super::contract::encode_actor_contract(encoder, install.contract);
            encode_requirements(encoder, install.requirements);
        }
        LifecycleRequest::UpgradeActor(upgrade) => {
            encoder.u8(3);
            encoder.fixed(&upgrade.actor.0);
            encoder.fixed(&upgrade.from_deployment.0);
            encoder.fixed(&upgrade.to_deployment.0);
            encoder.fixed(&upgrade.to_program.0);
            encoder.fixed(&upgrade.producer.0);
            encode_blob(encoder, &upgrade.package);
            encode_blob(encoder, &upgrade.agent_schema);
            encode_blob(encoder, &upgrade.role_policies);
            encoder.fixed(&upgrade.constructor_abi.0);
            encoder.fixed(&upgrade.state_layout.0);
            super::contract::encode_actor_contract(encoder, upgrade.contract);
            encode_requirements(encoder, upgrade.requirements);
        }
        LifecycleRequest::Suspend {
            actor,
            expected_deployment,
        } => {
            encoder.u8(4);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::Resume {
            actor,
            expected_deployment,
        } => {
            encoder.u8(5);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::AcknowledgeInvocation {
            scope,
            invocation,
            request,
            authority,
        } => {
            encoder.u8(8);
            encoder.u8(encode_invocation_scope(*scope));
            encoder.fixed(&invocation.0);
            encoder.fixed(&request.0);
            encoder.bytes(&authority.encode());
        }
        LifecycleRequest::RemoveLeaf {
            actor,
            expected_deployment,
        } => {
            encoder.u8(6);
            encoder.fixed(&actor.0);
            encoder.fixed(&expected_deployment.0);
        }
        LifecycleRequest::UpgradeRuntime {
            from_deployment,
            to_deployment,
            to_program,
            producer,
            package,
            contract,
            capabilities,
        } => {
            encoder.u8(7);
            encoder.fixed(&from_deployment.0);
            encoder.fixed(&to_deployment.0);
            encoder.fixed(&to_program.0);
            encoder.fixed(&producer.0);
            encode_blob(encoder, package);
            super::contract::encode_runtime_contract(encoder, *contract);
            encode_capabilities(encoder, *capabilities);
        }
        LifecycleRequest::FinalizeSystemAuthority(finalize) => {
            encoder.u8(10);
            encoder.bytes(&finalize.encode());
        }
        LifecycleRequest::RotateSystemAuthority(rotation) => {
            encoder.u8(11);
            encoder.bytes(&rotation.encode());
        }
        LifecycleRequest::FinalizeCatalog(finalize) => {
            encoder.u8(12);
            encoder.bytes(&finalize.encode());
        }
        LifecycleRequest::Authorized { admission, request } => {
            encoder.u8(9);
            encoder.bytes(&admission.receipt.encode());
            encoder.u64(admission.observed_slot);
            encode_request(encoder, request);
        }
    }
}

fn decode_request(decoder: &mut Decoder<'_>) -> Result<LifecycleRequest, DecodeError> {
    decode_request_at_depth(decoder, 0)
}

fn decode_request_at_depth(
    decoder: &mut Decoder<'_>,
    authorized_depth: u8,
) -> Result<LifecycleRequest, DecodeError> {
    match decoder.u8()? {
        0 => Ok(LifecycleRequest::Create(decode_config(decoder)?)),
        1 => Ok(LifecycleRequest::Inspect {
            after: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
            limit: decoder.u16()?,
        }),
        2 => {
            let installation_id = crate::service::InstallationId(decoder.fixed()?);
            let registry_reservation = Hash(decoder.fixed()?);
            if installation_id == crate::service::InstallationId::ZERO
                || registry_reservation == Hash::ZERO
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(LifecycleRequest::Install(super::InstallActor {
                installation_id,
                registry_reservation,
                entry: decode_entry(decoder)?,
                producer: ProducerId(decoder.fixed()?),
                package: decode_blob(decoder)?,
                agent_schema: decode_blob(decoder)?,
                role_policies: decode_blob(decoder)?,
                constructor_abi: Hash(decoder.fixed()?),
                installation_data: decoder.option(decode_installation_data)?,
                state_layout: Hash(decoder.fixed()?),
                contract: super::contract::decode_actor_contract(decoder)?,
                requirements: decode_requirements(decoder)?,
            }))
        }
        3 => Ok(LifecycleRequest::UpgradeActor(super::UpgradeActor {
            actor: ActorId(decoder.fixed()?),
            from_deployment: DeploymentId(decoder.fixed()?),
            to_deployment: DeploymentId(decoder.fixed()?),
            to_program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            agent_schema: decode_blob(decoder)?,
            role_policies: decode_blob(decoder)?,
            constructor_abi: Hash(decoder.fixed()?),
            state_layout: Hash(decoder.fixed()?),
            contract: super::contract::decode_actor_contract(decoder)?,
            requirements: decode_requirements(decoder)?,
        })),
        4 => Ok(LifecycleRequest::Suspend {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
        5 => Ok(LifecycleRequest::Resume {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
        6 => Ok(LifecycleRequest::RemoveLeaf {
            actor: ActorId(decoder.fixed()?),
            expected_deployment: DeploymentId(decoder.fixed()?),
        }),
        7 => Ok(LifecycleRequest::UpgradeRuntime {
            from_deployment: DeploymentId(decoder.fixed()?),
            to_deployment: DeploymentId(decoder.fixed()?),
            to_program: ProgramId(decoder.fixed()?),
            producer: ProducerId(decoder.fixed()?),
            package: decode_blob(decoder)?,
            contract: super::contract::decode_runtime_contract(decoder)?,
            capabilities: decode_capabilities(decoder)?,
        }),
        8 => Ok(LifecycleRequest::AcknowledgeInvocation {
            scope: decode_invocation_scope(decoder.u8()?)?,
            invocation: crate::service::InvocationId(decoder.fixed()?),
            request: Hash(decoder.fixed()?),
            authority: Box::new(super::authority::ActorInvocationReceipt::decode(
                &decoder.bytes()?,
            )?),
        }),
        9 => {
            if authorized_depth != 0 {
                return Err(DecodeError::NonCanonical);
            }
            let admission = super::LifecycleAuthorityAdmission {
                receipt: super::authority::AgentAuthorityReceipt::decode(&decoder.bytes()?)?,
                observed_slot: decoder.u64()?,
            };
            let request = decode_request_at_depth(decoder, 1)?;
            Ok(LifecycleRequest::Authorized {
                admission,
                request: alloc::boxed::Box::new(request),
            })
        }
        10 => {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(LifecycleRequest::FinalizeSystemAuthority(
                super::system_authority::SystemAuthorityFinalize::decode(bytes)?,
            ))
        }
        11 => {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_ROTATION_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(LifecycleRequest::RotateSystemAuthority(
                super::system_authority::SystemAuthorityRotation::decode(bytes)?,
            ))
        }
        12 => {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_CATALOG_FINALIZE_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(LifecycleRequest::FinalizeCatalog(
                super::system_authority::SystemAuthorityCatalogFinalize::decode(bytes)?,
            ))
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_reply(encoder: &mut Encoder<'_>, reply: &LifecycleReply) {
    match reply {
        LifecycleReply::Created(identity) => {
            encoder.u8(0);
            encode_identity(encoder, identity);
        }
        LifecycleReply::Directory(page) => {
            encoder.u8(1);
            encode_directory_page(encoder, page);
        }
        LifecycleReply::Installed(entry) => {
            encoder.u8(2);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Upgraded(entry) => {
            encoder.u8(3);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Suspended(entry) => {
            encoder.u8(4);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Resumed(entry) => {
            encoder.u8(5);
            encode_entry(encoder, entry);
        }
        LifecycleReply::Removed(actor) => {
            encoder.u8(6);
            encoder.fixed(&actor.0);
        }
        LifecycleReply::RuntimeUpgraded(identity) => {
            encoder.u8(7);
            encode_identity(encoder, identity);
        }
        LifecycleReply::InvocationAcknowledged { scope, invocation } => {
            encoder.u8(8);
            encoder.u8(encode_invocation_scope(*scope));
            encoder.fixed(&invocation.0);
        }
        LifecycleReply::SystemAuthorityFinalized(outcome) => {
            encoder.u8(9);
            match outcome {
                super::system_authority::SystemAuthorityFinalizeOutcome::Admitted(decision) => {
                    encoder.u8(0);
                    encoder.fixed(decision.as_bytes());
                }
                super::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(decision) => {
                    encoder.u8(1);
                    encoder.fixed(decision.as_bytes());
                }
                super::system_authority::SystemAuthorityFinalizeOutcome::TargetConflict(
                    decision,
                ) => {
                    encoder.u8(2);
                    encoder.fixed(decision.as_bytes());
                }
            }
        }
        LifecycleReply::SystemAuthorityRotated {
            rotation,
            epoch,
            exact_retry,
        } => {
            encoder.u8(10);
            encoder.fixed(rotation.as_bytes());
            encoder.u64(*epoch);
            encoder.bool(*exact_retry);
        }
        LifecycleReply::CatalogFinalized(outcome) => {
            use super::system_authority::SystemAuthorityCatalogFinalizeOutcome;
            encoder.u8(11);
            match outcome {
                SystemAuthorityCatalogFinalizeOutcome::Finalized {
                    operation,
                    result,
                    catalog_head,
                    authority_generation,
                    sequence,
                }
                | SystemAuthorityCatalogFinalizeOutcome::ExactRetry {
                    operation,
                    result,
                    catalog_head,
                    authority_generation,
                    sequence,
                } => {
                    encoder.u8(if outcome.exact_retry() { 1 } else { 0 });
                    encoder.fixed(&operation.0);
                    encoder.fixed(&result.0);
                    encoder.fixed(&catalog_head.0);
                    encoder.fixed(&authority_generation.0);
                    encoder.u64(*sequence);
                }
                SystemAuthorityCatalogFinalizeOutcome::OperationConflict {
                    operation,
                    occupied_record,
                } => {
                    encoder.u8(2);
                    encoder.fixed(&operation.0);
                    encoder.fixed(occupied_record.as_bytes());
                }
            }
        }
    }
}

fn decode_reply(decoder: &mut Decoder<'_>) -> Result<LifecycleReply, DecodeError> {
    match decoder.u8()? {
        0 => Ok(LifecycleReply::Created(decode_identity(decoder)?)),
        1 => Ok(LifecycleReply::Directory(decode_directory_page(decoder)?)),
        2 => Ok(LifecycleReply::Installed(decode_entry(decoder)?)),
        3 => Ok(LifecycleReply::Upgraded(decode_entry(decoder)?)),
        4 => Ok(LifecycleReply::Suspended(decode_entry(decoder)?)),
        5 => Ok(LifecycleReply::Resumed(decode_entry(decoder)?)),
        6 => Ok(LifecycleReply::Removed(ActorId(decoder.fixed()?))),
        7 => Ok(LifecycleReply::RuntimeUpgraded(decode_identity(decoder)?)),
        8 => Ok(LifecycleReply::InvocationAcknowledged {
            scope: decode_invocation_scope(decoder.u8()?)?,
            invocation: crate::service::InvocationId(decoder.fixed()?),
        }),
        9 => {
            let outcome = decoder.u8()?;
            let decision = super::genesis::AgentGenesisDecisionId::from_bytes(decoder.fixed()?);
            if decision == super::genesis::AgentGenesisDecisionId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            Ok(LifecycleReply::SystemAuthorityFinalized(match outcome {
                0 => super::system_authority::SystemAuthorityFinalizeOutcome::Admitted(decision),
                1 => super::system_authority::SystemAuthorityFinalizeOutcome::ExactRetry(decision),
                2 => super::system_authority::SystemAuthorityFinalizeOutcome::TargetConflict(
                    decision,
                ),
                _ => return Err(DecodeError::InvalidTag),
            }))
        }
        10 => {
            let rotation =
                super::system_authority::SystemAuthorityRotationId::from_bytes(decoder.fixed()?);
            let epoch = decoder.u64()?;
            let exact_retry = decoder.bool()?;
            if rotation == super::system_authority::SystemAuthorityRotationId::ZERO || epoch == 0 {
                return Err(DecodeError::NonCanonical);
            }
            Ok(LifecycleReply::SystemAuthorityRotated {
                rotation,
                epoch,
                exact_retry,
            })
        }
        11 => {
            use super::system_authority::SystemAuthorityCatalogFinalizeOutcome;
            let disposition = decoder.u8()?;
            let operation = crate::service::OperationId(decoder.fixed()?);
            if operation == crate::service::OperationId::ZERO {
                return Err(DecodeError::NonCanonical);
            }
            let outcome = match disposition {
                0 | 1 => {
                    let result = crate::service::Hash(decoder.fixed()?);
                    let catalog_head = crate::service::Hash(decoder.fixed()?);
                    let authority_generation = crate::service::Hash(decoder.fixed()?);
                    let sequence = decoder.u64()?;
                    if result == crate::service::Hash::ZERO
                        || catalog_head == crate::service::Hash::ZERO
                        || authority_generation == crate::service::Hash::ZERO
                        || sequence == 0
                    {
                        return Err(DecodeError::NonCanonical);
                    }
                    if disposition == 0 {
                        SystemAuthorityCatalogFinalizeOutcome::Finalized {
                            operation,
                            result,
                            catalog_head,
                            authority_generation,
                            sequence,
                        }
                    } else {
                        SystemAuthorityCatalogFinalizeOutcome::ExactRetry {
                            operation,
                            result,
                            catalog_head,
                            authority_generation,
                            sequence,
                        }
                    }
                }
                2 => {
                    let occupied_record =
                        super::system_authority::SystemAuthorityCatalogRecordId::from_bytes(
                            decoder.fixed()?,
                        );
                    if occupied_record
                        == super::system_authority::SystemAuthorityCatalogRecordId::ZERO
                    {
                        return Err(DecodeError::NonCanonical);
                    }
                    SystemAuthorityCatalogFinalizeOutcome::OperationConflict {
                        operation,
                        occupied_record,
                    }
                }
                _ => return Err(DecodeError::InvalidTag),
            };
            Ok(LifecycleReply::CatalogFinalized(outcome))
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_error(encoder: &mut Encoder<'_>, error: LifecycleError) {
    let tag = match error {
        LifecycleError::NotCreated => 0,
        LifecycleError::AlreadyCreated => 1,
        LifecycleError::NotFound => 2,
        LifecycleError::AlreadyExists => 3,
        LifecycleError::StaleDeployment => 4,
        LifecycleError::UnsupportedRuntime => 5,
        LifecycleError::UnsupportedLane => 6,
        LifecycleError::Busy(debt) => {
            encoder.u8(7);
            encode_debt(encoder, debt);
            return;
        }
        LifecycleError::DirectoryFull => 8,
        LifecycleError::InvalidRequest => 9,
        LifecycleError::AuthoritySequenceRegressed => 10,
        LifecycleError::AuthoritySequenceConflict => 11,
        LifecycleError::AuthoritySlotRegressed => 12,
        LifecycleError::ResourceLimit => 13,
        LifecycleError::SystemAuthority(error) => {
            encoder.u8(14);
            encode_system_authority_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_error(decoder: &mut Decoder<'_>) -> Result<LifecycleError, DecodeError> {
    Ok(match decoder.u8()? {
        0 => LifecycleError::NotCreated,
        1 => LifecycleError::AlreadyCreated,
        2 => LifecycleError::NotFound,
        3 => LifecycleError::AlreadyExists,
        4 => LifecycleError::StaleDeployment,
        5 => LifecycleError::UnsupportedRuntime,
        6 => LifecycleError::UnsupportedLane,
        7 => LifecycleError::Busy(decode_debt(decoder)?),
        8 => LifecycleError::DirectoryFull,
        9 => LifecycleError::InvalidRequest,
        10 => LifecycleError::AuthoritySequenceRegressed,
        11 => LifecycleError::AuthoritySequenceConflict,
        12 => LifecycleError::AuthoritySlotRegressed,
        13 => LifecycleError::ResourceLimit,
        14 => LifecycleError::SystemAuthority(decode_system_authority_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_system_authority_error(
    encoder: &mut Encoder<'_>,
    error: super::system_authority::SystemAuthorityError,
) {
    use super::system_authority::SystemAuthorityError;
    let tag = match error {
        SystemAuthorityError::InvalidGenesis => 0,
        SystemAuthorityError::InvalidScope => 1,
        SystemAuthorityError::InvalidState => 2,
        SystemAuthorityError::InvalidDecisionFact => 3,
        SystemAuthorityError::InvalidDecisionNode => 4,
        SystemAuthorityError::InvalidDecisionProof => 5,
        SystemAuthorityError::InvalidRotationNode => 6,
        SystemAuthorityError::InvalidRotationProof => 7,
        SystemAuthorityError::InvalidFinalize => 8,
        SystemAuthorityError::InvalidProvision => 9,
        SystemAuthorityError::WrongSystemAgent => 10,
        SystemAuthorityError::StaleCommittee => 11,
        SystemAuthorityError::SequenceConflict => 12,
        SystemAuthorityError::RotationFirstSequencePending => 13,
        SystemAuthorityError::Capacity => 14,
        SystemAuthorityError::LimitExceeded => 15,
        SystemAuthorityError::Authority(error) => {
            encoder.u8(16);
            encode_authority_committee_error(encoder, error);
            return;
        }
        SystemAuthorityError::Genesis(error) => {
            encoder.u8(17);
            encode_agent_genesis_error(encoder, error);
            return;
        }
        SystemAuthorityError::InvalidCatalogRecord => 18,
        SystemAuthorityError::InvalidCatalogNode => 19,
        SystemAuthorityError::InvalidCatalogProof => 20,
        SystemAuthorityError::InvalidCatalogFinalize => 21,
        SystemAuthorityError::StaleAuthorityGeneration => 22,
        SystemAuthorityError::StaleCatalogHead => 23,
        SystemAuthorityError::CatalogOperationConflict => 24,
        SystemAuthorityError::Catalog(error) => {
            encoder.u8(25);
            encode_catalog_finality_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_system_authority_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::system_authority::SystemAuthorityError, DecodeError> {
    use super::system_authority::SystemAuthorityError;
    Ok(match decoder.u8()? {
        0 => SystemAuthorityError::InvalidGenesis,
        1 => SystemAuthorityError::InvalidScope,
        2 => SystemAuthorityError::InvalidState,
        3 => SystemAuthorityError::InvalidDecisionFact,
        4 => SystemAuthorityError::InvalidDecisionNode,
        5 => SystemAuthorityError::InvalidDecisionProof,
        6 => SystemAuthorityError::InvalidRotationNode,
        7 => SystemAuthorityError::InvalidRotationProof,
        8 => SystemAuthorityError::InvalidFinalize,
        9 => SystemAuthorityError::InvalidProvision,
        10 => SystemAuthorityError::WrongSystemAgent,
        11 => SystemAuthorityError::StaleCommittee,
        12 => SystemAuthorityError::SequenceConflict,
        13 => SystemAuthorityError::RotationFirstSequencePending,
        14 => SystemAuthorityError::Capacity,
        15 => SystemAuthorityError::LimitExceeded,
        16 => SystemAuthorityError::Authority(decode_authority_committee_error(decoder)?),
        17 => SystemAuthorityError::Genesis(decode_agent_genesis_error(decoder)?),
        18 => SystemAuthorityError::InvalidCatalogRecord,
        19 => SystemAuthorityError::InvalidCatalogNode,
        20 => SystemAuthorityError::InvalidCatalogProof,
        21 => SystemAuthorityError::InvalidCatalogFinalize,
        22 => SystemAuthorityError::StaleAuthorityGeneration,
        23 => SystemAuthorityError::StaleCatalogHead,
        24 => SystemAuthorityError::CatalogOperationConflict,
        25 => SystemAuthorityError::Catalog(decode_catalog_finality_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_catalog_finality_error(
    encoder: &mut Encoder<'_>,
    error: super::catalog_finality::CatalogFinalityError,
) {
    use super::catalog_finality::CatalogFinalityError;
    let tag = match error {
        CatalogFinalityError::InvalidBinding => 0,
        CatalogFinalityError::InvalidMutation => 1,
        CatalogFinalityError::InvalidResult => 2,
        CatalogFinalityError::InvalidIntent => 3,
        CatalogFinalityError::InvalidFact => 4,
        CatalogFinalityError::InvalidReceipt => 5,
        CatalogFinalityError::WrongSpace => 6,
        CatalogFinalityError::LimitExceeded => 7,
        CatalogFinalityError::Authority(error) => {
            encoder.u8(8);
            encode_authority_committee_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_catalog_finality_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::catalog_finality::CatalogFinalityError, DecodeError> {
    use super::catalog_finality::CatalogFinalityError;
    Ok(match decoder.u8()? {
        0 => CatalogFinalityError::InvalidBinding,
        1 => CatalogFinalityError::InvalidMutation,
        2 => CatalogFinalityError::InvalidResult,
        3 => CatalogFinalityError::InvalidIntent,
        4 => CatalogFinalityError::InvalidFact,
        5 => CatalogFinalityError::InvalidReceipt,
        6 => CatalogFinalityError::WrongSpace,
        7 => CatalogFinalityError::LimitExceeded,
        8 => CatalogFinalityError::Authority(decode_authority_committee_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_agent_genesis_error(encoder: &mut Encoder<'_>, error: super::genesis::AgentGenesisError) {
    use super::genesis::AgentGenesisError;
    let tag = match error {
        AgentGenesisError::InvalidLocator => 0,
        AgentGenesisError::InvalidExpectations => 1,
        AgentGenesisError::InvalidProposal => 2,
        AgentGenesisError::InvalidReplicaCommittee => 3,
        AgentGenesisError::InvalidClaim => 4,
        AgentGenesisError::InvalidEvidence => 5,
        AgentGenesisError::InvalidDecision => 6,
        AgentGenesisError::InvalidAdmission => 7,
        AgentGenesisError::InvalidProvision => 8,
        AgentGenesisError::InvalidCatalog => 9,
        AgentGenesisError::LimitExceeded => 10,
        AgentGenesisError::Authority(error) => {
            encoder.u8(11);
            encode_authority_committee_error(encoder, error);
            return;
        }
    };
    encoder.u8(tag);
}

fn decode_agent_genesis_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::genesis::AgentGenesisError, DecodeError> {
    use super::genesis::AgentGenesisError;
    Ok(match decoder.u8()? {
        0 => AgentGenesisError::InvalidLocator,
        1 => AgentGenesisError::InvalidExpectations,
        2 => AgentGenesisError::InvalidProposal,
        3 => AgentGenesisError::InvalidReplicaCommittee,
        4 => AgentGenesisError::InvalidClaim,
        5 => AgentGenesisError::InvalidEvidence,
        6 => AgentGenesisError::InvalidDecision,
        7 => AgentGenesisError::InvalidAdmission,
        8 => AgentGenesisError::InvalidProvision,
        9 => AgentGenesisError::InvalidCatalog,
        10 => AgentGenesisError::LimitExceeded,
        11 => AgentGenesisError::Authority(decode_authority_committee_error(decoder)?),
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_authority_committee_error(
    encoder: &mut Encoder<'_>,
    error: super::committee::AuthorityCommitteeError,
) {
    use super::committee::AuthorityCommitteeError;
    let tag = match error {
        AuthorityCommitteeError::InvalidBinding => 0,
        AuthorityCommitteeError::InvalidMember => 1,
        AuthorityCommitteeError::InvalidSigner => 2,
        AuthorityCommitteeError::InvalidEpoch => 3,
        AuthorityCommitteeError::InvalidPreviousCommittee => 4,
        AuthorityCommitteeError::CommitteeTooLarge => 5,
        AuthorityCommitteeError::CertificateTooLarge => 6,
        AuthorityCommitteeError::NoVoters => 7,
        AuthorityCommitteeError::DuplicateNode => 8,
        AuthorityCommitteeError::NonCanonicalOrder => 9,
        AuthorityCommitteeError::InvalidClaim => 10,
        AuthorityCommitteeError::WrongAuthorityBinding => 11,
        AuthorityCommitteeError::WrongEpoch => 12,
        AuthorityCommitteeError::WrongCommittee => 13,
        AuthorityCommitteeError::WrongClaim => 14,
        AuthorityCommitteeError::UnknownSigner => 15,
        AuthorityCommitteeError::ObserverSignature => 16,
        AuthorityCommitteeError::InsufficientQuorum => 17,
        AuthorityCommitteeError::InvalidSignature => 18,
        AuthorityCommitteeError::InvalidRotationEpoch => 19,
        AuthorityCommitteeError::InvalidRotationLink => 20,
        AuthorityCommitteeError::InvalidRotationSequence => 21,
        AuthorityCommitteeError::InvalidRootAnchor => 22,
        AuthorityCommitteeError::RootAnchorTooLarge => 23,
        AuthorityCommitteeError::InvalidGenesisIntent => 24,
        AuthorityCommitteeError::InvalidGenesisExpectation => 25,
        AuthorityCommitteeError::InvalidGenesisClaim => 26,
        AuthorityCommitteeError::GenesisEvidenceTooLarge => 27,
        AuthorityCommitteeError::InvalidGenesisAdmission => 28,
        AuthorityCommitteeError::GenesisAdmissionTooLarge => 29,
        AuthorityCommitteeError::InvalidBootstrapAnchor => 30,
        AuthorityCommitteeError::WrongBootstrapAnchor => 31,
        AuthorityCommitteeError::WrongGenesisIntent => 32,
        AuthorityCommitteeError::WrongGenesisExpectation => 33,
    };
    encoder.u8(tag);
}

fn decode_authority_committee_error(
    decoder: &mut Decoder<'_>,
) -> Result<super::committee::AuthorityCommitteeError, DecodeError> {
    use super::committee::AuthorityCommitteeError;
    Ok(match decoder.u8()? {
        0 => AuthorityCommitteeError::InvalidBinding,
        1 => AuthorityCommitteeError::InvalidMember,
        2 => AuthorityCommitteeError::InvalidSigner,
        3 => AuthorityCommitteeError::InvalidEpoch,
        4 => AuthorityCommitteeError::InvalidPreviousCommittee,
        5 => AuthorityCommitteeError::CommitteeTooLarge,
        6 => AuthorityCommitteeError::CertificateTooLarge,
        7 => AuthorityCommitteeError::NoVoters,
        8 => AuthorityCommitteeError::DuplicateNode,
        9 => AuthorityCommitteeError::NonCanonicalOrder,
        10 => AuthorityCommitteeError::InvalidClaim,
        11 => AuthorityCommitteeError::WrongAuthorityBinding,
        12 => AuthorityCommitteeError::WrongEpoch,
        13 => AuthorityCommitteeError::WrongCommittee,
        14 => AuthorityCommitteeError::WrongClaim,
        15 => AuthorityCommitteeError::UnknownSigner,
        16 => AuthorityCommitteeError::ObserverSignature,
        17 => AuthorityCommitteeError::InsufficientQuorum,
        18 => AuthorityCommitteeError::InvalidSignature,
        19 => AuthorityCommitteeError::InvalidRotationEpoch,
        20 => AuthorityCommitteeError::InvalidRotationLink,
        21 => AuthorityCommitteeError::InvalidRotationSequence,
        22 => AuthorityCommitteeError::InvalidRootAnchor,
        23 => AuthorityCommitteeError::RootAnchorTooLarge,
        24 => AuthorityCommitteeError::InvalidGenesisIntent,
        25 => AuthorityCommitteeError::InvalidGenesisExpectation,
        26 => AuthorityCommitteeError::InvalidGenesisClaim,
        27 => AuthorityCommitteeError::GenesisEvidenceTooLarge,
        28 => AuthorityCommitteeError::InvalidGenesisAdmission,
        29 => AuthorityCommitteeError::GenesisAdmissionTooLarge,
        30 => AuthorityCommitteeError::InvalidBootstrapAnchor,
        31 => AuthorityCommitteeError::WrongBootstrapAnchor,
        32 => AuthorityCommitteeError::WrongGenesisIntent,
        33 => AuthorityCommitteeError::WrongGenesisExpectation,
        _ => return Err(DecodeError::InvalidTag),
    })
}

fn encode_config(encoder: &mut Encoder<'_>, config: &AgentConfig) {
    encode_identity(encoder, &config.identity);
    encoder.fixed(&config.creation_nonce.0);
    super::authority::encode_binding(encoder, &config.authority);
    encoder.option(&config.system_authority_genesis, |encoder, genesis| {
        encoder.bytes(&genesis.encode())
    });
    encode_blob(encoder, &config.runtime_package);
    super::contract::encode_runtime_contract(encoder, config.runtime_contract);
    encode_capabilities(encoder, config.capabilities);
    encoder.list(&config.replicas, |encoder, replica| {
        encoder.fixed(&replica.node.0);
        encoder.fixed(&replica.principal.0);
        encoder.u8(replica.role as u8);
    });
}

fn decode_config(decoder: &mut Decoder<'_>) -> Result<AgentConfig, DecodeError> {
    let config = decode_config_unvalidated(decoder)?;
    config.validate().map_err(|_| DecodeError::NonCanonical)?;
    Ok(config)
}

fn decode_config_unvalidated(decoder: &mut Decoder<'_>) -> Result<AgentConfig, DecodeError> {
    let identity = decode_identity(decoder)?;
    let creation_nonce = Hash(decoder.fixed()?);
    let authority = super::authority::decode_binding(decoder)?;
    let system_authority_genesis = decoder.option(|decoder| {
        let bytes = decoder.bytes_ref()?;
        if bytes.len() > super::system_authority::MAX_SYSTEM_AUTHORITY_GENESIS_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        super::system_authority::SystemAuthorityGenesis::decode(bytes)
    })?;
    let runtime_package = decode_blob(decoder)?;
    let runtime_contract = super::contract::decode_runtime_contract(decoder)?;
    let capabilities = decode_capabilities(decoder)?;
    let replica_count = decoder.u32()? as usize;
    if replica_count > super::MAX_AGENT_REPLICAS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut replicas = Vec::new();
    replicas
        .try_reserve_exact(replica_count)
        .map_err(|_| DecodeError::LimitExceeded)?;
    for _ in 0..replica_count {
        replicas.push(AgentReplica {
            node: NodeId(decoder.fixed()?),
            principal: PrincipalId(decoder.fixed()?),
            role: match decoder.u8()? {
                0 => ReplicaRole::Voter,
                1 => ReplicaRole::Observer,
                _ => return Err(DecodeError::InvalidTag),
            },
        });
    }
    let config = AgentConfig {
        identity,
        creation_nonce,
        authority,
        system_authority_genesis,
        runtime_package,
        runtime_contract,
        capabilities,
        replicas,
    };
    Ok(config)
}

fn encode_identity(encoder: &mut Encoder<'_>, identity: &AgentIdentity) {
    encoder.fixed(&identity.space.0);
    encoder.fixed(&identity.agent.0);
    encoder.fixed(&identity.owner.0);
    encoder.u8(identity.profile as u8);
    encoder.fixed(&identity.runtime_deployment.0);
    encoder.fixed(&identity.runtime_program.0);
    encoder.fixed(&identity.runtime_producer.0);
    encoder.fixed(&identity.transition_producer.0);
}

fn decode_identity(decoder: &mut Decoder<'_>) -> Result<AgentIdentity, DecodeError> {
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

fn encode_entry(encoder: &mut Encoder<'_>, entry: &ActorEntry) {
    encoder.fixed(&entry.actor.0);
    encoder.string(&entry.name);
    encoder.option(&entry.parent, |encoder, parent| encoder.fixed(&parent.0));
    encoder.fixed(&entry.deployment.0);
    encoder.fixed(&entry.program.0);
    encode_blob(encoder, &entry.package);
    encode_blob(encoder, &entry.agent_schema);
    encode_blob(encoder, &entry.role_policies);
    encoder.fixed(&entry.constructor_abi.0);
    encoder.option(&entry.installation_data, encode_blob);
    encoder.fixed(&entry.state_layout.0);
    encoder.u8(entry.lanes.bits());
    encoder.bool(entry.suspended);
}

fn decode_entry(decoder: &mut Decoder<'_>) -> Result<ActorEntry, DecodeError> {
    let entry = ActorEntry {
        actor: ActorId(decoder.fixed()?),
        name: decoder.string()?,
        parent: decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?,
        deployment: DeploymentId(decoder.fixed()?),
        program: ProgramId(decoder.fixed()?),
        package: decode_blob(decoder)?,
        agent_schema: decode_blob(decoder)?,
        role_policies: decode_blob(decoder)?,
        constructor_abi: Hash(decoder.fixed()?),
        installation_data: decoder.option(decode_blob)?,
        state_layout: Hash(decoder.fixed()?),
        lanes: decode_lanes(decoder)?,
        suspended: decoder.bool()?,
    };
    if entry.name.is_empty()
        || entry.name.len() > crate::service::MAX_ACTOR_NAME_BYTES
        || entry.package.hash == Hash::ZERO
        || entry.package.len == 0
        || entry.agent_schema.hash == Hash::ZERO
        || entry.agent_schema.len == 0
        || entry.agent_schema.len > super::schema::MAX_ENCODED_BYTES as u64
        || entry.role_policies.hash == Hash::ZERO
        || entry.role_policies.len == 0
        || entry.role_policies.len > super::execution::MAX_EXECUTION_POLICY_BYTES as u64
        || entry.constructor_abi == Hash::ZERO
        || entry.installation_data.as_ref().is_some_and(|reference| {
            reference.hash == Hash::ZERO
                || reference.len > super::MAX_INSTALLATION_DATA_BYTES as u64
        })
        || entry.state_layout == Hash::ZERO
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(entry)
}

fn encode_directory_page(encoder: &mut Encoder<'_>, page: &ActorDirectoryPage) {
    encoder.list(&page.entries, |encoder, record| {
        encode_entry(encoder, &record.entry);
        encoder.fixed(&record.incarnation.0);
        encoder.fixed(record.installation_id.as_bytes());
        encoder.fixed(&record.registry_reservation.0);
    });
    encoder.option(&page.next, |encoder, next| encoder.fixed(&next.0));
}

fn decode_directory_page(decoder: &mut Decoder<'_>) -> Result<ActorDirectoryPage, DecodeError> {
    let entries = decode_bounded_list(
        decoder,
        usize::from(super::standard::MAX_DIRECTORY_PAGE),
        |decoder| {
            let entry = decode_entry(decoder)?;
            let incarnation = Hash(decoder.fixed()?);
            let installation_id = crate::service::InstallationId(decoder.fixed()?);
            let registry_reservation = Hash(decoder.fixed()?);
            if incarnation == Hash::ZERO
                || installation_id == crate::service::InstallationId::ZERO
                || registry_reservation == Hash::ZERO
            {
                return Err(DecodeError::NonCanonical);
            }
            Ok(ActorDirectoryRecord {
                entry,
                incarnation,
                installation_id,
                registry_reservation,
            })
        },
    )?;
    if entries
        .windows(2)
        .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
    {
        return Err(DecodeError::NonCanonical);
    }
    let next = decoder.option(|decoder| Ok(ActorId(decoder.fixed()?)))?;
    if next.is_some() && next != entries.last().map(|record| record.entry.actor) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(ActorDirectoryPage { entries, next })
}

fn encode_blob(encoder: &mut Encoder<'_>, blob: &BlobRef) {
    encoder.fixed(&blob.hash.0);
    encoder.u64(blob.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_installation_data(encoder: &mut Encoder<'_>, data: &super::InstallationData) {
    encode_blob(encoder, &data.reference);
    encoder.bytes(&data.bytes);
}

fn decode_installation_data(
    decoder: &mut Decoder<'_>,
) -> Result<super::InstallationData, DecodeError> {
    let reference = decode_blob(decoder)?;
    // Inspect the declared frame before copying attacker-controlled bytes.
    let len = decoder.u32()? as usize;
    if len > super::MAX_INSTALLATION_DATA_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let bytes = decoder.take(len)?;
    let data = super::InstallationData {
        reference,
        bytes: bytes.to_vec(),
    };
    if !data.is_valid() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(data)
}

fn encode_requirements(encoder: &mut Encoder<'_>, requirements: RuntimeRequirements) {
    encoder.u8(requirements.lanes.bits());
    encoder.bool(requirements.scheduling);
    encoder.bool(requirements.proofs);
}

fn decode_requirements(decoder: &mut Decoder<'_>) -> Result<RuntimeRequirements, DecodeError> {
    Ok(RuntimeRequirements {
        lanes: decode_lanes(decoder)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
    })
}

fn encode_capabilities(encoder: &mut Encoder<'_>, capabilities: RuntimeCapabilities) {
    encoder.u8(capabilities.lanes.bits());
    encoder.bool(capabilities.scheduling);
    encoder.bool(capabilities.proofs);
    encoder.u32(capabilities.max_actors);
}

fn decode_capabilities(decoder: &mut Decoder<'_>) -> Result<RuntimeCapabilities, DecodeError> {
    Ok(RuntimeCapabilities {
        lanes: decode_lanes(decoder)?,
        scheduling: decoder.bool()?,
        proofs: decoder.bool()?,
        max_actors: decoder.u32()?,
    })
}

fn decode_lanes(decoder: &mut Decoder<'_>) -> Result<LaneSet, DecodeError> {
    LaneSet::from_bits(decoder.u8()?).ok_or(DecodeError::NonCanonical)
}

fn encode_debt(encoder: &mut Encoder<'_>, debt: ActorLifecycleDebt) {
    encoder.u32(debt.children);
    encoder.u32(debt.continuations);
    encoder.u32(debt.inbox);
    encoder.u32(debt.outbox);
    encoder.u32(debt.schedules);
    encoder.u32(debt.proof_artifacts);
    encoder.u32(debt.lifecycle_operations);
}

fn decode_debt(decoder: &mut Decoder<'_>) -> Result<ActorLifecycleDebt, DecodeError> {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn authority_binding() -> crate::agent::authority::AgentAuthorityBinding {
        let public_key = crate::agent::authority::ed25519_public_key_wire(
            authority_key().verifying_key().to_bytes(),
        );
        crate::agent::authority::AgentAuthorityBinding {
            agent: AgentId([11; 32]),
            actor: ActorId([12; 32]),
            deployment: DeploymentId([13; 32]),
            program: ProgramId([14; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn config() -> AgentConfig {
        let owner = PrincipalId([1; 32]);
        let space = SpaceId([2; 32]);
        let creation_nonce = Hash([0x15; 32]);
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent: AgentId::derive(space, owner, &creation_nonce.0),
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
                transition_producer: ProducerId([16; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef {
                hash: Hash([7; 32]),
                len: 100,
            },
            runtime_contract: crate::agent::contract::RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![
                AgentReplica {
                    node: NodeId([8; 32]),
                    principal: owner,
                    role: ReplicaRole::Voter,
                },
                AgentReplica {
                    node: NodeId([9; 32]),
                    principal: PrincipalId([10; 32]),
                    role: ReplicaRole::Observer,
                },
            ],
        }
    }

    #[test]
    fn execution_restore_matches_validated_decode_and_rejects_invalid_records() {
        for encoded in [
            RuntimeState::default(),
            encode_standard_runtime_state(&sparse_standard_state()),
        ] {
            let decoded = decode_standard_runtime_state(&encoded).unwrap();
            let expected_limit = standard_state_limit(&decoded);
            let expected = StandardAgentRuntime::restore(decoded).unwrap();
            let (actual, limit) = restore_standard_runtime_state(&encoded).unwrap();
            assert_eq!(actual.snapshot(), expected.snapshot());
            assert_eq!(limit, expected_limit);
        }

        let mut invalid = sparse_standard_state();
        invalid.actors[0].record.entry.name = "different-name-with-unchanged-actor-id".into();
        let encoded = encode_standard_runtime_state(&invalid);
        // This is structurally valid; restoration, not parsing, enforces the
        // actor identity invariant. Execution must still perform that check.
        assert!(decode_standard_runtime_components(&encoded).is_ok());
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::NonCanonical)
        );
        assert!(matches!(
            restore_standard_runtime_state(&encoded),
            Err(DecodeError::NonCanonical)
        ));
    }

    fn sparse_standard_state() -> StandardRuntimeState {
        let config = config();
        let actor = ActorId::top_level(config.identity.agent, "sparse");
        let package = BlobRef {
            hash: Hash([0x81; 32]),
            len: 10,
        };
        let agent_schema = BlobRef {
            hash: Hash([0x82; 32]),
            len: 11,
        };
        let role_policies = BlobRef {
            hash: Hash([0x83; 32]),
            len: 12,
        };
        let generation = Hash([0x84; 32]);
        StandardRuntimeState {
            config: Some(config.clone()),
            system_authority: None,
            actors: vec![StandardActorState {
                record: super::super::ActorRecord {
                    entry: ActorEntry {
                        actor,
                        name: "sparse".into(),
                        parent: None,
                        deployment: DeploymentId([0x85; 32]),
                        program: ProgramId([0x86; 32]),
                        package: package.clone(),
                        agent_schema: agent_schema.clone(),
                        role_policies: role_policies.clone(),
                        constructor_abi: Hash([0x8c; 32]),
                        installation_data: None,
                        state_layout: Hash([0x87; 32]),
                        lanes: LaneSet::ALL,
                        suspended: false,
                    },
                    state_generation: generation,
                    installation_id: crate::service::InstallationId([0x89; 32]),
                    registry_reservation: Hash([0x8a; 32]),
                    install_request_commitment: Hash([0x8b; 32]),
                    producer: ProducerId([0x88; 32]),
                    package,
                    agent_schema,
                    role_policies,
                    constructor_abi: Hash([0x8c; 32]),
                    installation_data: None,
                    state_layout: Hash([0x87; 32]),
                    contract: super::super::contract::ActorPackageContract::canonical(),
                    requirements: RuntimeRequirements {
                        lanes: LaneSet::ALL,
                        scheduling: false,
                        proofs: false,
                    },
                },
                debt: ActorLifecycleDebt::default(),
            }],
            lane_state: StandardLaneState {
                linear: vec![StandardLaneEntry {
                    actor,
                    state_generation: generation,
                    value: vec![0x89],
                    rows: Default::default(),
                }],
                merge: Vec::new(),
                local: Vec::new(),
            },
            lane_revisions: super::super::standard::StandardLaneRevisions {
                linear: 1,
                ..Default::default()
            },
            authority_slot_high_water: Some(1),
            authority_sequence_high_water: Some(1),
            authority_dispositions: vec![StandardAuthorityDisposition {
                credential: crate::service::CredentialId([0x8a; 32]),
                sequence: 1,
                claim: Hash([0x8b; 32]),
                operation: Hash([0x8c; 32]),
                result: Ok(LifecycleReply::Created(config.identity)),
            }],
            ..Default::default()
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_test_descriptor(
        profile: crate::agent_sdk::AgentProfile,
    ) -> crate::agent_sdk::AgentDescriptor {
        use crate::agent_sdk::authority::{AgentAuthorityBinding, AuthorityIssuer};

        let space = crate::agent_sdk::SpaceId([2; 32]);
        let owner = crate::agent_sdk::PrincipalId([1; 32]);
        let creation_nonce = crate::agent_sdk::Hash([0x15; 32]);
        let agent = crate::agent_sdk::AgentId::derive(space, owner, creation_nonce.as_bytes());
        let public_key = authority_key().verifying_key().to_bytes();
        let replicas = match profile {
            crate::agent_sdk::AgentProfile::Local => vec![crate::agent_sdk::AgentReplica {
                node: crate::agent_sdk::NodeId([8; 32]),
                principal: owner,
                role: crate::agent_sdk::ReplicaRole::Voter,
            }],
            crate::agent_sdk::AgentProfile::Shared => vec![
                crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId([8; 32]),
                    principal: owner,
                    role: crate::agent_sdk::ReplicaRole::Voter,
                },
                crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId([9; 32]),
                    principal: crate::agent_sdk::PrincipalId([10; 32]),
                    role: crate::agent_sdk::ReplicaRole::Observer,
                },
            ],
            crate::agent_sdk::AgentProfile::Private => vec![
                crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId([8; 32]),
                    principal: owner,
                    role: crate::agent_sdk::ReplicaRole::Observer,
                },
                crate::agent_sdk::AgentReplica {
                    node: crate::agent_sdk::NodeId([9; 32]),
                    principal: owner,
                    role: crate::agent_sdk::ReplicaRole::Observer,
                },
            ],
        };
        let descriptor = crate::agent_sdk::AgentDescriptor {
            identity: crate::agent_sdk::AgentIdentity {
                space,
                agent,
                owner,
                profile,
                runtime_deployment: crate::agent_sdk::DeploymentId([4; 32]),
                runtime_program: crate::agent_sdk::ProgramId([5; 32]),
                runtime_producer: crate::agent_sdk::ProducerId([6; 32]),
                transition_producer: crate::agent_sdk::ProducerId([0x92; 32]),
            },
            creation_nonce,
            authority: AgentAuthorityBinding {
                policy: crate::agent_sdk::Hash([0x31; 32]),
                issuer: AuthorityIssuer {
                    principal: owner,
                    actor: crate::agent_sdk::ActorId([12; 32]),
                    deployment: crate::agent_sdk::DeploymentId([13; 32]),
                    program: crate::agent_sdk::ProgramId([14; 32]),
                    producer: crate::agent_sdk::ProducerId::of_public_key(&public_key),
                },
                public_key,
                initial_epoch: 1,
            },
            private_recovery: (profile == crate::agent_sdk::AgentProfile::Private).then_some(
                crate::agent_sdk::PrivateRecoveryBinding {
                    signing_key_commitment: crate::agent_sdk::Hash([0x32; 32]),
                    encryption_public_key: [0x33; 32],
                },
            ),
            runtime_package: crate::agent_sdk::BlobRef {
                hash: crate::agent_sdk::Hash([7; 32]),
                len: 100,
            },
            runtime_contract: crate::agent_sdk::contract::RuntimePackageContract::canonical(),
            capabilities: crate::agent_sdk::RuntimeCapabilities::standard(),
            replicas,
        };
        descriptor.validate().unwrap();
        descriptor
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn attested_route_uses_only_the_authenticated_transition_producer() {
        let descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Local);
        let route = super::super::transition_proof_host::AttestedTransitionRoute::for_descriptor(
            &descriptor,
            crate::agent_sdk::Hash([0x93; 32]),
            crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        )
        .unwrap();
        assert_eq!(route.producer(), descriptor.identity.transition_producer);
        assert_ne!(route.producer(), descriptor.identity.runtime_producer);

        let mut reused_runtime_producer = descriptor;
        reused_runtime_producer.identity.transition_producer =
            reused_runtime_producer.identity.runtime_producer;
        assert!(
            super::super::transition_proof_host::AttestedTransitionRoute::for_descriptor(
                &reused_runtime_producer,
                crate::agent_sdk::Hash([0x93; 32]),
                crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
            )
            .is_none()
        );
    }

    #[cfg(feature = "pvm")]
    fn clean_sparse_standard_state() -> StandardRuntimeState {
        let mut state = sparse_standard_state();
        let descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Shared);
        let config =
            super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap();
        let actor = crate::service::ActorId(
            crate::agent_sdk::ActorId::top_level(descriptor.identity.agent, "sparse").0,
        );
        state.config = Some(config.clone());
        state.actors[0].record.entry.actor = actor;
        state.actors[0].record.contract = super::super::contract::ActorPackageContract {
            actor_abi: crate::agent_sdk::contract::ACTOR_ABI,
        };
        state.lane_state.linear[0].actor = actor;
        state.clean_creation_descriptor = Some(descriptor.clone());
        state.clean_descriptor = Some(descriptor.clone());
        state.clean_actor_packages = Some(vec![StandardCleanActorPackage {
            actor: crate::agent_sdk::ActorId(actor.0),
            contract: crate::agent_sdk::contract::ActorPackageContract::canonical(),
            requirements: crate::agent_sdk::RuntimeRequirements {
                lanes: crate::agent_sdk::LaneSet::ALL,
                scheduling: false,
                proof_systems: crate::agent_sdk::ProofSystemSet::EMPTY,
            },
        }]);
        let record = &state.actors[0].record;
        let original = crate::agent_sdk::authority::CompactInstallActor {
            installation_id: crate::agent_sdk::InstallationId(record.installation_id.0),
            registry_reservation: crate::agent_sdk::Hash(record.registry_reservation.0),
            entry: super::super::standard::legacy_actor_record_to_clean(
                record,
                crate::agent_sdk::Hash::ZERO,
            )
            .entry,
            producer: crate::agent_sdk::ProducerId(record.producer.0),
            contract: crate::agent_sdk::contract::ActorPackageContract::canonical(),
            requirements: state.clean_actor_packages.as_ref().unwrap()[0].requirements,
        };
        state.clean_actor_installations = Some(vec![StandardCleanActorInstallation {
            actor: crate::agent_sdk::ActorId(actor.0),
            commitment: original.lineage_commitment(),
            contract: crate::agent_sdk::contract::ActorPackageContract::canonical(),
            requirements: crate::agent_sdk::RuntimeRequirements {
                lanes: crate::agent_sdk::LaneSet::ALL,
                scheduling: false,
                proof_systems: crate::agent_sdk::ProofSystemSet::EMPTY,
            },
            original,
        }]);
        state.active_resource_policy = Some(descriptor.initial_resource_policy());
        state.clean_authority_epoch_high_water = Some(1);
        state.clean_decision_sequence_high_water = Some(1);
        state.clean_management_dispositions = vec![StandardCleanManagementDisposition {
            authority: crate::agent_sdk::Hash([0x91; 32]),
            request: crate::agent_sdk::Hash([0x92; 32]),
            epoch: 1,
            sequence: 1,
            observed_slot: 1,
            result: Ok(crate::agent_sdk::ManagementReply::Created(
                descriptor.identity.clone(),
            )),
        }];
        state.authority_dispositions[0].result = Ok(LifecycleReply::Created(config.identity));
        StandardAgentRuntime::restore(state.clone()).unwrap();
        state
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "physical directory scaling; requires VOS_AGENT_RUNTIME_COST_CANDIDATE"]
    fn physical_directory_inspection_scaling() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeTransition, RuntimeWork,
        };
        let candidate = std::fs::read(
            std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE")
                .expect("set an explicitly rebuilt candidate PVM"),
        )
        .unwrap();
        let baseline = std::env::var_os("VOS_AGENT_RUNTIME_COST_BASELINE")
            .map(|path| std::fs::read(path).unwrap())
            .unwrap_or_else(|| include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec());
        let template = clean_sparse_standard_state();
        let descriptor = template.clean_descriptor.as_ref().unwrap();
        for count in [1, 32, 128, 512] {
            let mut state = template.clone();
            state.actors.clear();
            state.lane_state = StandardLaneState::default();
            state.clean_actor_packages.as_mut().unwrap().clear();
            state.clean_actor_installations.as_mut().unwrap().clear();
            for index in 0..count {
                let name = alloc::format!("scaling-{index:04}");
                let actor = crate::agent_sdk::ActorId::top_level(descriptor.identity.agent, &name);
                let mut entry = template.actors[0].clone();
                entry.record.entry.actor = ActorId(actor.0);
                entry.record.entry.name = name.clone();
                entry.record.installation_id = crate::service::InstallationId(actor.0);
                state.actors.push(entry);
                let mut package = template.clean_actor_packages.as_ref().unwrap()[0];
                package.actor = actor;
                state.clean_actor_packages.as_mut().unwrap().push(package);
                let mut installation =
                    template.clean_actor_installations.as_ref().unwrap()[0].clone();
                installation.actor = actor;
                installation.original.entry.actor = actor;
                installation.original.entry.name = name;
                installation.original.installation_id = crate::agent_sdk::InstallationId(actor.0);
                installation.commitment = installation.original.lineage_commitment();
                state
                    .clean_actor_installations
                    .as_mut()
                    .unwrap()
                    .push(installation);
            }
            state
                .actors
                .sort_unstable_by_key(|actor| actor.record.entry.actor);
            state
                .clean_actor_packages
                .as_mut()
                .unwrap()
                .sort_unstable_by_key(|item| item.actor);
            state
                .clean_actor_installations
                .as_mut()
                .unwrap()
                .sort_unstable_by_key(|item| item.actor);
            StandardAgentRuntime::restore(state.clone()).unwrap();
            let state = legacy_state_to_clean(encode_standard_runtime_state(&state));
            let work = RuntimeWork::Manage {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                runtime_deployment: descriptor.identity.runtime_deployment,
                state: state.clone(),
                request: Box::new(ManagementRequest::InspectActors {
                    after: None,
                    limit: 1,
                }),
                authority: None,
                observed_slot: 1,
            };
            let expected = apply_standard_runtime_work(work.clone()).unwrap();
            assert_eq!(expected.state, state);
            assert!(
                matches!(&expected.outcome, RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) if page.entries.len() == 1)
            );
            let input = work.encode().unwrap();
            let expected = expected.encode().unwrap();
            let mut baseline_gas = None;
            for (label, program) in [
                ("baseline", baseline.as_slice()),
                ("candidate", candidate.as_slice()),
            ] {
                let start = std::time::Instant::now();
                let execution =
                    vos_pvm::refine_host::RefineContext::load(program, &input, 20_000_000_000)
                        .unwrap()
                        .run();
                eprintln!(
                    "directory-scaling actors={count} label={label} input_bytes={} gas_used={} elapsed_us={} exit={:?}",
                    input.len(),
                    execution.gas_used,
                    start.elapsed().as_micros(),
                    execution.exit
                );
                assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
                assert_eq!(
                    execution
                        .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                        .unwrap(),
                    expected
                );
                if let Some(gas) = baseline_gas {
                    assert!(
                        execution.gas_used < gas,
                        "candidate should reduce directory inspection gas"
                    );
                } else {
                    baseline_gas = Some(execution.gas_used);
                }
            }
        }
    }

    #[cfg(feature = "pvm")]
    fn sparse_invocation(mode: MethodMode, id: u8) -> ActorInvocation {
        let state = sparse_standard_state();
        let actor = &state.actors[0].record;
        ActorInvocation {
            invocation: crate::service::InvocationId([id; 32]),
            actor: actor.entry.actor,
            incarnation: actor.state_generation,
            deployment: actor.entry.deployment,
            program: actor.entry.program,
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 100,
        }
    }

    #[cfg(feature = "pvm")]
    fn exact_reply(
        invocation: &ActorInvocation,
        status: ActorExecutionStatus,
    ) -> ActorExecutionReply {
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: invocation.mode.write_lane(),
            status,
            reply: vec![0xa5],
            gas_remaining: 50,
            observation: super::super::execution::ActorObservation::default(),
        }
    }

    #[cfg(feature = "pvm")]
    fn portable_continuation(
        invocation: &ActorInvocation,
        ready_sequence: u64,
        marker: u8,
    ) -> StandardMachineContinuation {
        let mut registers = [0u64; vos_pvm_program::REGISTER_COUNT];
        for (index, register) in registers.iter_mut().enumerate() {
            *register = u64::from(marker) << 32 | index as u64;
        }
        StandardMachineContinuation {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            program: invocation.program,
            mode: invocation.mode,
            request: invocation.commitment(),
            work: invocation.commitment(),
            ready_sequence,
            accepted: None,
            authorization: None,
            observed_slot: 1,
            continuation: super::super::execution::ActorMachineContinuation {
                machine: super::super::execution::PortableMachineSnapshot {
                    pc: u32::from(marker) * 2,
                    gas_remaining: 100 - u64::from(marker),
                    registers,
                    memory: vec![
                        super::super::execution::PortableMemoryRegion {
                            base: 2 * vos_pvm_program::ZONE_SIZE,
                            bytes: vec![marker; vos_pvm_program::PAGE_SIZE as usize],
                        },
                        super::super::execution::PortableMemoryRegion {
                            base: u32::MAX - (2 * vos_pvm_program::PAGE_SIZE) + 1,
                            bytes: vec![
                                marker.wrapping_add(1);
                                vos_pvm_program::PAGE_SIZE as usize
                            ],
                        },
                    ],
                },
                fetch_index: marker % 6,
                host_budget: super::super::execution::ActorHostBudget {
                    calls: u32::from(marker),
                    fetch_calls: u32::from(marker % 4),
                    fetch_bytes: u32::from(marker) * 17,
                    blake2b_compressions: u32::from(marker % 3),
                    debug_bytes: u32::from(marker) * 5,
                },
            },
        }
    }

    #[cfg(feature = "pvm")]
    fn minimal_portable_continuation(
        mode: MethodMode,
        ordinal: u32,
        ready_sequence: u64,
    ) -> StandardMachineContinuation {
        let mut invocation = sparse_invocation(mode, 0x41);
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&ordinal.to_le_bytes());
        id[31] = 1;
        invocation.invocation = crate::service::InvocationId(id);
        let mut record = portable_continuation(&invocation, ready_sequence, 1);
        record.continuation.machine.memory.clear();
        record
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standalone_continuation_wire_is_exact_bounded_and_strict() {
        let invocation = sparse_invocation(MethodMode::Linear, 0xd0);
        let record = portable_continuation(&invocation, 7, 3);
        let encoded = encode_standard_machine_continuation(&record).unwrap();

        assert_eq!(&encoded[..4], &STANDARD_MACHINE_CONTINUATION_MAGIC);
        assert_eq!(
            decode_standard_machine_continuation(&encoded).unwrap(),
            record
        );
        assert_eq!(
            encode_standard_machine_continuation(
                &decode_standard_machine_continuation(&encoded).unwrap()
            )
            .unwrap(),
            encoded
        );
        assert_eq!(
            record.clean_reference().unwrap(),
            crate::agent_sdk::BlobRef::of_bytes(&encoded),
            "the SDK continuation reference commits the standalone bytes"
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_standard_machine_continuation(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        assert!(decode_standard_machine_continuation(&encoded[..encoded.len() - 1]).is_err());
        assert!(decode_standard_machine_continuation(&encoded[..5]).is_err());

        let mut unknown_version = encoded.clone();
        let version_offset = STANDARD_MACHINE_CONTINUATION_MAGIC.len()
            + crate::agent_sdk::RUNTIME_ABI_ID.as_bytes().len();
        unknown_version[version_offset..version_offset + 2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode_standard_machine_continuation(&unknown_version),
            Err(DecodeError::InvalidPlatform)
        );

        let oversized = vec![0u8; MAX_STANDARD_MACHINE_CONTINUATION_BYTES + 1];
        assert_eq!(
            decode_standard_machine_continuation(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn continuation_decoder_rejects_hostile_order_and_aggregate_count() {
        let mut swapped = sparse_standard_state();
        swapped.machine_continuations = vec![
            minimal_portable_continuation(MethodMode::Query, 2, 2),
            minimal_portable_continuation(MethodMode::Query, 1, 1),
        ];
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&swapped)),
            Err(DecodeError::NonCanonical),
            "hostile component order must not be sorted into validity"
        );

        let mut aggregate = sparse_standard_state();
        aggregate.machine_continuations = (0..super::super::standard::MAX_MACHINE_CONTINUATIONS)
            .map(|index| {
                minimal_portable_continuation(
                    MethodMode::Query,
                    u32::try_from(index + 1).unwrap(),
                    u64::try_from(index + 1).unwrap(),
                )
            })
            .chain(core::iter::once(minimal_portable_continuation(
                MethodMode::Linear,
                u32::MAX,
                1,
            )))
            .collect();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&aggregate)),
            Err(DecodeError::LimitExceeded),
            "the continuation ceiling is aggregate across control and lane components"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn yielded_commit_rolls_back_mutations_when_capacity_is_full() {
        let mut state = sparse_standard_state();
        state.machine_continuations = (0..super::super::standard::MAX_MACHINE_CONTINUATIONS)
            .map(|index| {
                minimal_portable_continuation(
                    MethodMode::Query,
                    u32::try_from(index + 1).unwrap(),
                    u64::try_from(index + 1).unwrap(),
                )
            })
            .collect();
        let mut runtime = StandardAgentRuntime::restore(state).unwrap();
        let invocation = sparse_invocation(MethodMode::Linear, 0xf0);
        let before_lanes = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after_lanes = before_lanes.clone();
        after_lanes.linear = Some(vec![0xde, 0xad]);
        let before = runtime.snapshot();

        assert_eq!(
            runtime.commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before_lanes,
                after_lanes,
                10,
                None,
                minimal_portable_continuation(MethodMode::Linear, u32::MAX - 1, 1).continuation,
                None,
            ),
            Err(ActorExecutionError::ResultCapacity)
        );
        assert_eq!(runtime.snapshot(), before);
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn clean_authority_receipt(
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

    #[cfg(feature = "pvm")]
    fn clean_management_receipt_with_sequence(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        epoch: u64,
        decision_sequence: u64,
        acknowledged_through: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        use crate::agent_sdk::ManagementRequest;
        use crate::agent_sdk::authority::{
            AuthorityEvidence, AuthorityLaneRoots, AuthorityOperationKind, AuthorityReceipt,
            AuthorityReceiptSelector,
        };

        let (operation, actor, actor_deployment) = match request {
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
            ManagementRequest::PrivateControl { control, .. } => match control.operation {
                crate::agent_sdk::private::PrivateControlOperation::SetResourcePolicy {
                    ..
                } => (AuthorityOperationKind::SetPrivateResourcePolicy, None, None),
                crate::agent_sdk::private::PrivateControlOperation::ActorLifecycle {
                    actor,
                    ..
                } => (
                    AuthorityOperationKind::PrivateActorLifecycle,
                    Some(actor),
                    None,
                ),
                _ => panic!("non-runtime Private control has no runtime receipt"),
            },
            ManagementRequest::InspectActors { .. }
            | ManagementRequest::InspectResources
            | ManagementRequest::InspectManagementHistory => {
                panic!("read-only management has no authority receipt")
            }
        };
        let runtime_deployment = match request {
            ManagementRequest::Create(requested) => requested.identity.runtime_deployment,
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
                    commitment: crate::agent_sdk::Hash([0x32; 32]),
                },
                lane_roots: AuthorityLaneRoots::default(),
                epoch,
                decision_sequence,
                acknowledged_through,
                valid_from,
                expires_at,
                request: request.commitment(),
            },
            public_key: descriptor.authority.public_key,
            signature: [1; 64],
        };
        receipt.signature = authority_key().sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    #[cfg(feature = "pvm")]
    fn clean_management_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        let decision_sequence = if matches!(request, crate::agent_sdk::ManagementRequest::Create(_))
        {
            1
        } else {
            valid_from.max(2)
        };
        clean_management_receipt_with_sequence(
            descriptor,
            request,
            epoch,
            decision_sequence,
            0,
            valid_from,
            expires_at,
        )
    }

    #[cfg(feature = "pvm")]
    fn apply_clean_management_test(
        state: crate::agent_sdk::RuntimeState,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: crate::agent_sdk::ManagementRequest,
        authority: Option<crate::agent_sdk::authority::AuthorityReceipt>,
        observed_slot: u64,
    ) -> crate::agent_sdk::RuntimeTransition {
        let runtime_deployment = match authority.as_ref() {
            Some(receipt) => receipt.selector.runtime_deployment,
            None => descriptor.identity.runtime_deployment,
        };
        apply_standard_runtime_work(crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment,
            state,
            request: Box::new(request),
            authority: authority.map(Box::new),
            observed_slot,
        })
        .unwrap()
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standard_runtime_executor_fails_closed_on_attested_work() {
        let descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Shared);
        let work = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Attested {
                proof_system: crate::agent_sdk::Hash([0xa7; 32]),
            },
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment: descriptor.identity.runtime_deployment,
            state: crate::agent_sdk::RuntimeState::default(),
            request: Box::new(crate::agent_sdk::ManagementRequest::InspectResources),
            authority: None,
            observed_slot: 1,
        };
        assert_eq!(
            apply_standard_runtime_work(work),
            Err(DecodeError::NonCanonical)
        );
    }

    #[cfg(feature = "pvm")]
    fn create_clean_management_state(
        profile: crate::agent_sdk::AgentProfile,
    ) -> (
        crate::agent_sdk::AgentDescriptor,
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::authority::AuthorityReceipt,
    ) {
        let descriptor = clean_test_descriptor(profile);
        let request = crate::agent_sdk::ManagementRequest::Create(Box::new(descriptor.clone()));
        let receipt = clean_management_receipt(&descriptor, &request, 1, 1, 10);
        let transition = apply_clean_management_test(
            crate::agent_sdk::RuntimeState::default(),
            &descriptor,
            request,
            Some(receipt.clone()),
            1,
        );
        assert_eq!(
            transition.outcome,
            crate::agent_sdk::RuntimeOutcome::Management(Ok(
                crate::agent_sdk::ManagementReply::Created(descriptor.identity.clone()),
            ))
        );
        assert!(!transition.state.is_empty());
        (descriptor, transition.state, receipt)
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_create_lane_initialization_accepts_only_empty_canonical_envelopes() {
        let (_, created, _) = create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let empty = RuntimeState::default();
        let created_legacy = clean_state_to_legacy(&created);
        assert!(clean_create_initializes_only_empty_lanes(
            &empty,
            &created_legacy
        ));
        assert!(!clean_create_initializes_only_empty_lanes(
            &created_legacy,
            &created_legacy,
        ));

        let mut nonempty = decode_standard_runtime_state(&created_legacy).unwrap();
        nonempty.lane_revisions.linear = 1;
        let nonempty = encode_standard_runtime_state(&nonempty);
        assert!(decode_standard_runtime_state(&nonempty).is_ok());
        assert!(!clean_create_initializes_only_empty_lanes(
            &empty, &nonempty,
        ));
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn clean_install_request(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        name: &str,
        parent: Option<crate::agent_sdk::ActorId>,
        marker: u8,
        lanes: crate::agent_sdk::LaneSet,
    ) -> crate::agent_sdk::InstallActor {
        let package = crate::agent_sdk::BlobRef::of_bytes(&[marker, 1]);
        let schema = crate::agent_sdk::BlobRef::of_bytes(&[marker, 2]);
        let policy = crate::agent_sdk::BlobRef::of_bytes(&[marker, 3]);
        let installation_bytes = vec![marker, 9];
        let installation_data = crate::agent_sdk::InstallationData {
            reference: crate::agent_sdk::BlobRef::of_bytes(&installation_bytes),
            bytes: installation_bytes,
        };
        let actor = parent.map_or_else(
            || crate::agent_sdk::ActorId::top_level(descriptor.identity.agent, name),
            |parent| crate::agent_sdk::ActorId::owned_child(parent, name),
        );
        let entry = crate::agent_sdk::ActorEntry {
            actor,
            name: name.into(),
            parent,
            deployment: crate::agent_sdk::DeploymentId([marker; 32]),
            program: crate::agent_sdk::ProgramId::of_pvm(&[marker, 4]),
            package: package.clone(),
            agent_schema: schema.clone(),
            method_policy: policy.clone(),
            constructor_abi: crate::agent_sdk::Hash([marker.wrapping_add(1); 32]),
            installation_data: Some(installation_data.reference.clone()),
            state_layout: crate::agent_sdk::Hash([marker.wrapping_add(2); 32]),
            lanes,
            suspended: false,
        };
        crate::agent_sdk::InstallActor {
            installation_id: crate::agent_sdk::InstallationId([marker.wrapping_add(3); 32]),
            registry_reservation: crate::agent_sdk::Hash([marker.wrapping_add(4); 32]),
            entry,
            producer: crate::agent_sdk::ProducerId([marker.wrapping_add(5); 32]),
            package,
            agent_schema: schema,
            method_policy: policy,
            constructor_abi: crate::agent_sdk::Hash([marker.wrapping_add(1); 32]),
            installation_data: Some(installation_data),
            state_layout: crate::agent_sdk::Hash([marker.wrapping_add(2); 32]),
            contract: crate::agent_sdk::contract::ActorPackageContract::canonical(),
            requirements: crate::agent_sdk::RuntimeRequirements {
                lanes,
                scheduling: false,
                proof_systems: crate::agent_sdk::ProofSystemSet::EMPTY,
            },
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_lane_boundary_covers_initialization_migration_and_denials() {
        use crate::agent_sdk::{
            LaneSet, ManagementRequest, RuntimeUpgrade, StateLane, UpgradeActor,
        };
        let descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Shared);
        let before = RuntimeState {
            control: vec![0xa1],
            linear: vec![1],
            merge: vec![2],
            local: vec![3],
        };
        for bits in 0..8 {
            let lanes = LaneSet::from_bits(bits).unwrap();
            let install = clean_install_request(&descriptor, "lane-probe", None, 0x71, lanes);
            let upgrade = UpgradeActor {
                actor: install.entry.actor,
                from_deployment: crate::agent_sdk::DeploymentId([0x70; 32]),
                to_deployment: install.entry.deployment,
                to_program: install.entry.program,
                producer: install.producer,
                package: install.package.clone(),
                agent_schema: install.agent_schema.clone(),
                method_policy: install.method_policy.clone(),
                constructor_abi: install.constructor_abi,
                state_layout: install.state_layout,
                contract: install.contract,
                requirements: install.requirements,
            };
            let mut capabilities = descriptor.capabilities;
            capabilities.lanes = lanes;
            let runtime_upgrade = RuntimeUpgrade {
                from_deployment: descriptor.identity.runtime_deployment,
                to_deployment: crate::agent_sdk::DeploymentId([0x72; 32]),
                to_program: descriptor.identity.runtime_program,
                producer: descriptor.identity.runtime_producer,
                package: descriptor.runtime_package.clone(),
                contract: descriptor.runtime_contract,
                capabilities,
            };
            for request in [
                ManagementRequest::Install(Box::new(install)),
                ManagementRequest::UpgradeActor(Box::new(upgrade)),
                ManagementRequest::UpgradeRuntime(Box::new(runtime_upgrade)),
            ] {
                for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
                    let mut after = before.clone();
                    match lane {
                        StateLane::Linear => after.linear.push(9),
                        StateLane::Merge => after.merge.push(9),
                        StateLane::Local => after.local.push(9),
                    }
                    assert_eq!(
                        clean_management_lane_changes_allowed(&request, &before, &after, true),
                        bits & LaneSet::of(lane).bits() != 0
                    );
                    assert!(!clean_management_lane_changes_allowed(
                        &request, &before, &after, false
                    ));
                }
                let mut control_only = before.clone();
                control_only.control.push(9);
                assert!(clean_management_lane_changes_allowed(
                    &request,
                    &before,
                    &control_only,
                    false
                ));
            }
        }
        let inspect = ManagementRequest::InspectResources;
        let mut control_only = before.clone();
        control_only.control.push(9);
        for success in [false, true] {
            assert!(clean_management_lane_changes_allowed(
                &inspect, &before, &before, success
            ));
            assert!(!clean_management_lane_changes_allowed(
                &inspect,
                &before,
                &control_only,
                success
            ));
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_create_and_install_preserve_exact_proof_capabilities() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };

        let proof_system = crate::agent_sdk::Hash([0x35; 32]);
        let alternate_system = crate::agent_sdk::Hash([0x36; 32]);
        let unsupported_system = crate::agent_sdk::Hash([0x37; 32]);
        let supported = crate::agent_sdk::ProofSystemSet::from_sorted(&[proof_system]).unwrap();
        let runtime_supported =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[proof_system, alternate_system])
                .unwrap();
        let mut descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Local);
        descriptor.capabilities.proof_systems = runtime_supported;
        descriptor.validate().unwrap();

        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let create_receipt = clean_management_receipt(&descriptor, &create, 1, 1, 10);
        let created = apply_clean_management_test(
            crate::agent_sdk::RuntimeState::default(),
            &descriptor,
            create,
            Some(create_receipt),
            1,
        );
        assert_eq!(
            created.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity.clone(),)))
        );
        let reopened = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&created.state)).unwrap(),
        )
        .unwrap();
        let persisted = reopened.clean_descriptor().unwrap();
        assert_eq!(persisted.runtime_package, descriptor.runtime_package);
        assert_eq!(persisted.runtime_contract, descriptor.runtime_contract);
        assert_eq!(persisted.capabilities.proof_systems, runtime_supported);

        let mut install = clean_install_request(
            &descriptor,
            "proof-capable",
            None,
            0x37,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
        );
        install.requirements.proof_systems = supported;
        let exact_install = install.clone();
        let expected_installation =
            super::super::standard::clean_installation_binding(&exact_install);
        let expected_actor = install.entry.actor;
        let expected_contract = install.contract;
        let expected_requirements = install.requirements;
        let install = ManagementRequest::Install(Box::new(install));
        let install_receipt = clean_management_receipt(&descriptor, &install, 1, 2, 10);
        let installed = apply_clean_management_test(
            created.state,
            &descriptor,
            install,
            Some(install_receipt),
            2,
        );
        assert!(matches!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));
        let persisted_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&installed.state)).unwrap();
        assert_eq!(
            persisted_state.clean_actor_packages,
            Some(vec![StandardCleanActorPackage {
                actor: expected_actor,
                contract: expected_contract,
                requirements: expected_requirements,
            }]),
            "restart state retains exact actor proof-system identities",
        );
        assert_eq!(
            persisted_state.clean_actor_installations,
            Some(vec![expected_installation]),
            "restart state retains the immutable exact install-time binding",
        );
        assert_eq!(
            encode_standard_runtime_state(&persisted_state),
            clean_state_to_legacy(&installed.state),
        );

        let mut substituted_retry = exact_install;
        substituted_retry.requirements.proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[alternate_system]).unwrap();
        let substituted_retry = ManagementRequest::Install(Box::new(substituted_retry));
        let substituted_retry_receipt =
            clean_management_receipt(&descriptor, &substituted_retry, 1, 3, 10);
        let substituted_retry = apply_clean_management_test(
            installed.state.clone(),
            &descriptor,
            substituted_retry,
            Some(substituted_retry_receipt),
            3,
        );
        assert_eq!(
            substituted_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            "an InstallationId retry cannot substitute an exact proof-system set hidden by the legacy bool projection",
        );
        let substituted_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&substituted_retry.state))
                .unwrap();
        assert_eq!(
            substituted_state.clean_actor_packages,
            persisted_state.clean_actor_packages,
        );

        let mut missing = persisted_state.clone();
        missing.clean_actor_packages = None;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&missing)),
            Err(DecodeError::NonCanonical),
            "an old clean image with no exact package table fails closed",
        );
        let mut missing_installation = persisted_state.clone();
        missing_installation.clean_actor_installations = None;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&missing_installation)),
            Err(DecodeError::NonCanonical),
            "an old clean image with no immutable exact installation table fails closed",
        );
        let mut corrupt_installation = persisted_state.clone();
        corrupt_installation
            .clean_actor_installations
            .as_mut()
            .unwrap()[0]
            .requirements
            .proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[alternate_system]).unwrap();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&corrupt_installation)),
            Err(DecodeError::NonCanonical),
            "install-time exact fields must match their durable binding commitment",
        );
        corrupt_installation
            .clean_actor_installations
            .as_mut()
            .unwrap()[0]
            .original
            .requirements = corrupt_installation
            .clean_actor_installations
            .as_ref()
            .unwrap()[0]
            .requirements;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&corrupt_installation)),
            Err(DecodeError::NonCanonical),
            "changing both exact requirement copies cannot change the original lineage",
        );
        let mut previous_format = encode_standard_runtime_state(&persisted_state);
        let marker = previous_format
            .control
            .windows(4)
            .position(|bytes| bytes == STANDARD_CLEAN_ACTOR_INSTALLATIONS_MAGIC)
            .unwrap();
        previous_format.control[marker..marker + 4].copy_from_slice(b"SCAI");
        assert_eq!(
            decode_standard_runtime_state(&previous_format),
            Err(DecodeError::NonCanonical)
        );
        let mut collapsed = persisted_state.clone();
        collapsed.clean_actor_packages.as_mut().unwrap()[0]
            .requirements
            .proof_systems = crate::agent_sdk::ProofSystemSet::EMPTY;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&collapsed)),
            Err(DecodeError::NonCanonical),
            "the exact requirements must match their legacy compatibility projection",
        );
        let mut unsupported_binding = persisted_state.clone();
        unsupported_binding.clean_actor_packages.as_mut().unwrap()[0]
            .requirements
            .proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[unsupported_system]).unwrap();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&unsupported_binding)),
            Err(DecodeError::NonCanonical),
            "the exact requirements must remain supported by the pinned runtime package",
        );
        let mut corrupt = encode_standard_runtime_state(&persisted_state);
        let extension = corrupt
            .control
            .windows(STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC.len())
            .rposition(|bytes| bytes == STANDARD_CLEAN_ACTOR_PACKAGES_MAGIC)
            .unwrap();
        corrupt.control[extension] ^= 1;
        assert_eq!(
            decode_standard_runtime_state(&corrupt),
            Err(DecodeError::NonCanonical),
        );

        let mut unsupported = clean_install_request(
            &descriptor,
            "wrong-proof-system",
            None,
            0x38,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
        );
        unsupported.requirements.proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[unsupported_system]).unwrap();
        let unsupported = ManagementRequest::Install(Box::new(unsupported));
        let unsupported_receipt = clean_management_receipt(&descriptor, &unsupported, 1, 3, 10);
        let rejected = apply_clean_management_test(
            installed.state.clone(),
            &descriptor,
            unsupported,
            Some(unsupported_receipt),
            3,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedRuntime))
        );
        let rejected = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&rejected.state)).unwrap(),
        )
        .unwrap();
        assert_eq!(rejected.snapshot().actors.len(), 1);
        let persisted = rejected.clean_descriptor().unwrap();
        assert_eq!(persisted.runtime_package, descriptor.runtime_package);
        assert_eq!(persisted.runtime_contract, descriptor.runtime_contract);
        assert_eq!(persisted.capabilities.proof_systems, runtime_supported);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_runtime_upgrade_preserves_outer_proofs_and_exact_actor_requirements() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome, RuntimeUpgrade,
            UpgradeActor,
        };

        let required_proof = crate::agent_sdk::Hash([0x39; 32]);
        let substitute_proof = crate::agent_sdk::Hash([0x3a; 32]);
        let required = crate::agent_sdk::ProofSystemSet::from_sorted(&[required_proof]).unwrap();
        let substitute =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[substitute_proof]).unwrap();
        let all_proofs =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[required_proof, substitute_proof])
                .unwrap();
        let mut descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Local);
        descriptor.capabilities.proof_systems = all_proofs;
        descriptor.validate().unwrap();

        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let created = apply_clean_management_test(
            crate::agent_sdk::RuntimeState::default(),
            &descriptor,
            create.clone(),
            Some(clean_management_receipt(&descriptor, &create, 1, 1, 10)),
            1,
        );
        let mut install = clean_install_request(
            &descriptor,
            "runtime-upgrade-proof",
            None,
            0x3b,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
        );
        install.requirements.proof_systems = required;
        let actor = install.entry.actor;
        let original_install = install.clone();
        let install = ManagementRequest::Install(Box::new(install));
        let installed = apply_clean_management_test(
            created.state,
            &descriptor,
            install.clone(),
            Some(clean_management_receipt(&descriptor, &install, 1, 2, 10)),
            2,
        );
        assert!(matches!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));

        let actor_upgrade = UpgradeActor {
            actor,
            from_deployment: original_install.entry.deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0x42; 32]),
            // Stateful actors require the same program until an explicit
            // migration ABI exists; package/artifact pins still advance.
            to_program: original_install.entry.program,
            producer: crate::agent_sdk::ProducerId([0x43; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"upgraded-proof-actor-package"),
            agent_schema: crate::agent_sdk::BlobRef::of_bytes(b"upgraded-proof-actor-schema"),
            method_policy: crate::agent_sdk::BlobRef::of_bytes(b"upgraded-proof-actor-policy"),
            constructor_abi: original_install.constructor_abi,
            state_layout: original_install.state_layout,
            contract: original_install.contract,
            requirements: crate::agent_sdk::RuntimeRequirements {
                proof_systems: substitute,
                ..original_install.requirements
            },
        };
        let actor_upgrade_request =
            ManagementRequest::UpgradeActor(Box::new(actor_upgrade.clone()));
        let actor_upgraded = apply_clean_management_test(
            installed.state,
            &descriptor,
            actor_upgrade_request.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &actor_upgrade_request,
                1,
                3,
                10,
            )),
            3,
        );
        assert!(matches!(
            actor_upgraded.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Upgraded(ref entry)))
                if entry.deployment == actor_upgrade.to_deployment
        ));

        let upgraded_actor_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&actor_upgraded.state)).unwrap();
        assert_eq!(
            upgraded_actor_state.clean_actor_packages.as_ref().unwrap()[0]
                .requirements
                .proof_systems,
            substitute,
            "the current package follows the actor upgrade",
        );
        let original_installation =
            super::super::standard::clean_installation_binding(&original_install);
        assert_eq!(
            upgraded_actor_state
                .clean_actor_installations
                .as_ref()
                .unwrap()[0],
            original_installation,
            "the immutable install-time proof requirements survive the upgrade",
        );
        let inspected = apply_clean_management_test(
            actor_upgraded.state.clone(),
            &descriptor,
            ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            },
            None,
            3,
        );
        assert_eq!(inspected.state, actor_upgraded.state);
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(directory))) = inspected.outcome
        else {
            panic!("upgraded actor must remain visible through the canonical directory ABI");
        };
        assert_eq!(directory.entries.len(), 1);
        assert_eq!(
            directory.entries[0].entry.deployment,
            actor_upgrade.to_deployment
        );
        assert_eq!(
            directory.entries[0].install_request,
            original_install.lineage_commitment()
        );

        let exact_retry = apply_clean_management_test(
            actor_upgraded.state,
            &descriptor,
            install.clone(),
            Some(clean_management_receipt(&descriptor, &install, 1, 4, 10)),
            4,
        );
        assert!(matches!(
            exact_retry.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(ref entry)))
                if entry == &original_install.entry
        ));
        let exact_retry_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&exact_retry.state)).unwrap();
        assert_eq!(
            exact_retry_state.clean_actor_packages, upgraded_actor_state.clean_actor_packages,
            "an exact retry must not roll the upgraded package back",
        );
        assert_eq!(
            exact_retry_state.clean_actor_installations,
            upgraded_actor_state.clean_actor_installations,
        );

        let mut substituted_install = original_install.clone();
        substituted_install.requirements.proof_systems = substitute;
        let substituted_install = ManagementRequest::Install(Box::new(substituted_install));
        let substituted_retry = apply_clean_management_test(
            exact_retry.state,
            &descriptor,
            substituted_install.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &substituted_install,
                1,
                5,
                10,
            )),
            5,
        );
        assert_eq!(
            substituted_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            "the current upgraded proof requirement cannot replace the original install binding",
        );
        let substituted_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&substituted_retry.state))
                .unwrap();
        assert_eq!(
            substituted_state.clean_actor_packages,
            upgraded_actor_state.clean_actor_packages,
        );
        assert_eq!(
            substituted_state.clean_actor_installations,
            upgraded_actor_state.clean_actor_installations,
        );

        let upgrade = RuntimeUpgrade {
            from_deployment: descriptor.identity.runtime_deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0x3c; 32]),
            to_program: crate::agent_sdk::ProgramId([0x3d; 32]),
            producer: crate::agent_sdk::ProducerId([0x3e; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"proof-capable-runtime-upgrade"),
            contract: descriptor.runtime_contract,
            capabilities: crate::agent_sdk::RuntimeCapabilities {
                proof_systems: substitute,
                ..descriptor.capabilities
            },
        };
        let mut reused_signer_upgrade = upgrade.clone();
        reused_signer_upgrade.producer = descriptor.identity.transition_producer;
        let reused_signer_request =
            ManagementRequest::UpgradeRuntime(Box::new(reused_signer_upgrade));
        let reused_signer = apply_clean_management_test(
            substituted_retry.state.clone(),
            &descriptor,
            reused_signer_request.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &reused_signer_request,
                1,
                6,
                10,
            )),
            6,
        );
        assert_eq!(
            reused_signer.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedRuntime)),
        );
        let request = ManagementRequest::UpgradeRuntime(Box::new(upgrade.clone()));
        let upgraded = apply_clean_management_test(
            substituted_retry.state,
            &descriptor,
            request.clone(),
            Some(clean_management_receipt(&descriptor, &request, 1, 6, 10)),
            6,
        );
        assert!(matches!(
            upgraded.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(ref identity)))
                if identity.runtime_deployment == upgrade.to_deployment
                    && identity.transition_producer
                        == descriptor.identity.transition_producer
        ));
        let restarted =
            decode_standard_runtime_state(&clean_state_to_legacy(&upgraded.state)).unwrap();
        assert_eq!(
            restarted.clean_descriptor.as_ref().unwrap().runtime_package,
            upgrade.package,
        );
        assert_eq!(
            restarted
                .clean_descriptor
                .as_ref()
                .unwrap()
                .identity
                .transition_producer,
            descriptor.identity.transition_producer,
        );
        assert_eq!(
            restarted.clean_actor_packages.as_ref().unwrap()[0],
            StandardCleanActorPackage {
                actor,
                contract: crate::agent_sdk::contract::ActorPackageContract::canonical(),
                requirements: crate::agent_sdk::RuntimeRequirements {
                    lanes: crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear),
                    scheduling: false,
                    proof_systems: substitute,
                },
            },
        );
        let current = restarted.clean_descriptor.clone().unwrap();

        let incompatible = RuntimeUpgrade {
            from_deployment: current.identity.runtime_deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0x3f; 32]),
            to_program: crate::agent_sdk::ProgramId([0x40; 32]),
            producer: crate::agent_sdk::ProducerId([0x41; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"substituted-proof-runtime"),
            contract: current.runtime_contract,
            capabilities: crate::agent_sdk::RuntimeCapabilities {
                proof_systems: required,
                ..current.capabilities
            },
        };
        let request = ManagementRequest::UpgradeRuntime(Box::new(incompatible));
        let rejected = apply_clean_management_test(
            upgraded.state,
            &current,
            request.clone(),
            Some(clean_management_receipt(&current, &request, 1, 7, 10)),
            7,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedRuntime)),
        );
        let rejected =
            decode_standard_runtime_state(&clean_state_to_legacy(&rejected.state)).unwrap();
        assert_eq!(
            rejected.clean_descriptor.as_ref().unwrap().identity,
            current.identity,
        );
        assert_eq!(
            rejected.clean_actor_packages.as_ref().unwrap()[0]
                .requirements
                .proof_systems,
            substitute,
        );
    }

    #[cfg(feature = "pvm")]
    fn private_runtime_management_request(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        sequence: u64,
        previous: Option<crate::agent_sdk::Hash>,
        mutation: crate::agent_sdk::PrivateRuntimeMutation,
    ) -> crate::agent_sdk::ManagementRequest {
        use crate::agent_sdk::private::{
            PRIVATE_SIGNATURE_BYTES, PrivateControlOperation, PrivateControlRecord,
            PrivateControlSigner,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;

        let operation = match &mutation {
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(policy) => {
                PrivateControlOperation::SetResourcePolicy {
                    policy: crate::agent_sdk::BlobRef::of_bytes(&policy.encode().unwrap()),
                }
            }
            mutation => PrivateControlOperation::ActorLifecycle {
                actor: mutation.actor().unwrap(),
                operation: mutation.lifecycle_kind().unwrap(),
                request: mutation.commitment(),
            },
        };
        let request = crate::agent_sdk::ManagementRequest::PrivateControl {
            control: Box::new(PrivateControlRecord {
                space: descriptor.identity.space,
                agent: descriptor.identity.agent,
                sequence,
                previous,
                operation,
                signer: PrivateControlSigner::Owner,
                signer_public_key: [0xa8; 32],
                signature: [0xa9; PRIVATE_SIGNATURE_BYTES],
            }),
            mutation: Box::new(mutation),
        };
        assert!(request.is_valid());
        request
    }

    #[cfg(feature = "pvm")]
    fn private_runtime_management_receipt(
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        epoch: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> crate::agent_sdk::authority::AuthorityReceipt {
        clean_management_receipt_with_sequence(
            descriptor, request, epoch, 0, 0, valid_from, expires_at,
        )
    }

    #[cfg(feature = "pvm")]
    fn private_control_commitment(
        request: &crate::agent_sdk::ManagementRequest,
    ) -> crate::agent_sdk::Hash {
        match request {
            crate::agent_sdk::ManagementRequest::PrivateControl { control, .. } => {
                control.commitment()
            }
            _ => panic!("expected a Private control request"),
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn private_installation_id_replay_keeps_pre_upgrade_exact_proof_requirements() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, PrivateRuntimeMutation,
            RuntimeOutcome, UpgradeActor,
        };

        let original_proof = crate::agent_sdk::Hash([0x71; 32]);
        let upgraded_proof = crate::agent_sdk::Hash([0x72; 32]);
        let original_set =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[original_proof]).unwrap();
        let upgraded_set =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[upgraded_proof]).unwrap();
        let mut descriptor = clean_test_descriptor(crate::agent_sdk::AgentProfile::Private);
        descriptor.capabilities.proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[original_proof, upgraded_proof])
                .unwrap();
        descriptor.validate().unwrap();

        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let created = apply_clean_management_test(
            crate::agent_sdk::RuntimeState::default(),
            &descriptor,
            create.clone(),
            Some(clean_management_receipt(&descriptor, &create, 1, 1, 10)),
            1,
        );
        let mut original_install = clean_install_request(
            &descriptor,
            "private-proof-replay",
            None,
            0x73,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Merge),
        );
        original_install.requirements.proof_systems = original_set;
        let expected_installation =
            super::super::standard::clean_installation_binding(&original_install);
        let install_request = private_runtime_management_request(
            &descriptor,
            0,
            None,
            PrivateRuntimeMutation::Install(original_install.clone()),
        );
        let install_control = private_control_commitment(&install_request);
        let installed = apply_clean_management_test(
            created.state,
            &descriptor,
            install_request.clone(),
            Some(private_runtime_management_receipt(
                &descriptor,
                &install_request,
                1,
                2,
                10,
            )),
            2,
        );
        assert!(matches!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));

        let upgrade = UpgradeActor {
            actor: original_install.entry.actor,
            from_deployment: original_install.entry.deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0x74; 32]),
            to_program: original_install.entry.program,
            producer: crate::agent_sdk::ProducerId([0x75; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"private-upgraded-package"),
            agent_schema: crate::agent_sdk::BlobRef::of_bytes(b"private-upgraded-schema"),
            method_policy: crate::agent_sdk::BlobRef::of_bytes(b"private-upgraded-policy"),
            constructor_abi: original_install.constructor_abi,
            state_layout: original_install.state_layout,
            contract: original_install.contract,
            requirements: crate::agent_sdk::RuntimeRequirements {
                proof_systems: upgraded_set,
                ..original_install.requirements
            },
        };
        let upgrade_request = private_runtime_management_request(
            &descriptor,
            1,
            Some(install_control),
            PrivateRuntimeMutation::UpgradeActor(upgrade.clone()),
        );
        let upgrade_control = private_control_commitment(&upgrade_request);
        let upgraded = apply_clean_management_test(
            installed.state,
            &descriptor,
            upgrade_request.clone(),
            Some(private_runtime_management_receipt(
                &descriptor,
                &upgrade_request,
                1,
                3,
                10,
            )),
            3,
        );
        assert!(matches!(
            upgraded.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Upgraded(ref entry)))
                if entry.deployment == upgrade.to_deployment
        ));
        let reopened =
            decode_standard_runtime_state(&clean_state_to_legacy(&upgraded.state)).unwrap();
        assert_eq!(
            reopened.clean_actor_packages.as_ref().unwrap()[0]
                .requirements
                .proof_systems,
            upgraded_set,
        );
        assert_eq!(
            reopened.clean_actor_installations.as_ref().unwrap()[0],
            expected_installation,
        );

        let retry_request = private_runtime_management_request(
            &descriptor,
            2,
            Some(upgrade_control),
            PrivateRuntimeMutation::Install(original_install.clone()),
        );
        let retry_control = private_control_commitment(&retry_request);
        let retried = apply_clean_management_test(
            upgraded.state,
            &descriptor,
            retry_request.clone(),
            Some(private_runtime_management_receipt(
                &descriptor,
                &retry_request,
                1,
                4,
                10,
            )),
            4,
        );
        assert_eq!(
            retried.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(
                original_install.entry.clone(),
            ))),
        );
        let retried_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&retried.state)).unwrap();
        assert_eq!(
            retried_state.clean_actor_packages, reopened.clean_actor_packages,
            "an exact retry must not roll back the Private actor upgrade",
        );
        assert_eq!(
            retried_state.clean_actor_installations,
            reopened.clean_actor_installations,
        );

        let mut substituted = original_install;
        substituted.requirements.proof_systems = upgraded_set;
        let substituted_request = private_runtime_management_request(
            &descriptor,
            3,
            Some(retry_control),
            PrivateRuntimeMutation::Install(substituted),
        );
        let rejected = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            substituted_request.clone(),
            Some(private_runtime_management_receipt(
                &descriptor,
                &substituted_request,
                1,
                5,
                10,
            )),
            5,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
        );
        assert_eq!(
            rejected.state, retried.state,
            "a rejected Private substitution does not consume or mutate state",
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standard_private_policy_is_active_restart_safe_and_exactly_replayable() {
        use crate::agent_sdk::contract::RuntimeResourcePolicy;
        use crate::agent_sdk::{ManagementError, ManagementReply, RuntimeOutcome};

        let (descriptor, created, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Private);
        let initial = descriptor.initial_resource_policy();
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&created)).unwrap();
        assert_eq!(decoded.active_resource_policy, Some(initial));
        assert!(decoded.private_management_dispositions.is_empty());
        let mut forged_initial_policy = decoded.clone();
        forged_initial_policy.active_resource_policy = Some(RuntimeResourcePolicy {
            max_actors: initial.max_actors - 1,
            ..initial
        });
        assert!(matches!(
            StandardAgentRuntime::restore(forged_initial_policy),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let policy = RuntimeResourcePolicy {
            max_actors: 2,
            ..initial
        };
        let request = private_runtime_management_request(
            &descriptor,
            0,
            None,
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(policy),
        );
        let receipt = private_runtime_management_receipt(&descriptor, &request, 1, 5, 10);
        let applied = apply_clean_management_test(
            created.clone(),
            &descriptor,
            request.clone(),
            Some(receipt.clone()),
            5,
        );
        assert_eq!(
            applied.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(policy)))
        );
        let applied_state = applied.state.clone();
        let decoded =
            decode_standard_runtime_state(&clean_state_to_legacy(&applied.state)).unwrap();
        assert_eq!(decoded.active_resource_policy, Some(policy));
        assert_eq!(decoded.private_management_dispositions.len(), 1);
        assert_eq!(decoded.private_runtime_control_sequence, Some(0));
        assert_eq!(decoded.private_control_slot_high_water, Some(5));
        assert_eq!(
            legacy_state_to_clean(encode_standard_runtime_state(&decoded)),
            applied.state,
            "the Private runtime disposition must survive exact state reopen"
        );

        let mut wrong_retained_reply = decoded.clone();
        wrong_retained_reply.active_resource_policy = Some(initial);
        wrong_retained_reply.private_management_dispositions[0].result =
            Ok(ManagementReply::ResourcePolicySet(initial));
        let wrong_retained_state =
            legacy_state_to_clean(encode_standard_runtime_state(&wrong_retained_reply));
        let rejected_retained_reply = apply_clean_management_test(
            wrong_retained_state.clone(),
            &descriptor,
            request.clone(),
            Some(receipt.clone()),
            5,
        );
        assert_eq!(rejected_retained_reply.state, wrong_retained_state);
        assert_eq!(
            rejected_retained_reply.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceConflict))
        );

        for retry_slot in [5, 10] {
            let retried = apply_clean_management_test(
                applied_state.clone(),
                &descriptor,
                request.clone(),
                Some(receipt.clone()),
                retry_slot,
            );
            assert_eq!(retried.state, applied_state);
            assert_eq!(retried.outcome, applied.outcome);
        }
        let regressed = apply_clean_management_test(
            applied_state.clone(),
            &descriptor,
            request,
            Some(receipt),
            4,
        );
        assert_eq!(regressed.state, applied_state);
        assert_eq!(
            regressed.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySlotRegressed))
        );

        // Controls 1 and 2 may be Invite/Revoke/Rotate operations which never
        // enter the runtime. The runtime-bearing subsequence therefore need
        // not have adjacent PCTL predecessors, and distinct controls may share
        // one authority-observed slot.
        let widened = RuntimeResourcePolicy {
            max_actors: 3,
            ..policy
        };
        let interleaved = private_runtime_management_request(
            &descriptor,
            3,
            Some(crate::agent_sdk::Hash([0xaa; 32])),
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(widened),
        );
        let interleaved_receipt =
            private_runtime_management_receipt(&descriptor, &interleaved, 1, 5, 10);
        let progressed = apply_clean_management_test(
            applied_state,
            &descriptor,
            interleaved,
            Some(interleaved_receipt),
            5,
        );
        assert_eq!(
            progressed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::ResourcePolicySet(widened)))
        );
        let decoded =
            decode_standard_runtime_state(&clean_state_to_legacy(&progressed.state)).unwrap();
        assert_eq!(decoded.private_runtime_control_sequence, Some(3));
        assert_eq!(decoded.private_control_slot_high_water, Some(5));
        assert_eq!(decoded.private_management_dispositions.len(), 2);
        assert_eq!(
            decoded.private_management_dispositions[0].observed_slot,
            decoded.private_management_dispositions[1].observed_slot
        );
        StandardAgentRuntime::restore(decoded).unwrap();

        let wrong_adjacent_link = private_runtime_management_request(
            &descriptor,
            4,
            Some(crate::agent_sdk::Hash([0xab; 32])),
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(widened),
        );
        let wrong_adjacent_receipt =
            private_runtime_management_receipt(&descriptor, &wrong_adjacent_link, 1, 5, 10);
        let rejected_link = apply_clean_management_test(
            progressed.state.clone(),
            &descriptor,
            wrong_adjacent_link,
            Some(wrong_adjacent_receipt),
            5,
        );
        assert_eq!(rejected_link.state, progressed.state);
        assert_eq!(
            rejected_link.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceConflict))
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standard_private_management_rejects_non_private_and_denials_do_not_mutate() {
        use crate::agent_sdk::contract::RuntimeResourcePolicy;
        use crate::agent_sdk::{ManagementError, RuntimeOutcome};

        for profile in [
            crate::agent_sdk::AgentProfile::Local,
            crate::agent_sdk::AgentProfile::Shared,
        ] {
            let (descriptor, created, _) = create_clean_management_state(profile);
            let initial = descriptor.initial_resource_policy();
            let mut forged_policy =
                decode_standard_runtime_state(&clean_state_to_legacy(&created)).unwrap();
            forged_policy.active_resource_policy = Some(RuntimeResourcePolicy {
                max_actors: initial.max_actors - 1,
                ..initial
            });
            assert!(matches!(
                StandardAgentRuntime::restore(forged_policy),
                Err(super::super::LifecycleError::InvalidRequest)
            ));
            let request = private_runtime_management_request(
                &descriptor,
                0,
                None,
                crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(
                    descriptor.initial_resource_policy(),
                ),
            );
            let receipt = private_runtime_management_receipt(&descriptor, &request, 1, 2, 10);
            let rejected = apply_clean_management_test(
                created.clone(),
                &descriptor,
                request,
                Some(receipt),
                2,
            );
            assert_eq!(rejected.state, created);
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
            );
        }

        let (descriptor, created, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Private);
        let too_small = RuntimeResourcePolicy {
            max_runtime_state_bytes: 1,
            ..descriptor.initial_resource_policy()
        };
        let request = private_runtime_management_request(
            &descriptor,
            0,
            None,
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(too_small),
        );
        let receipt = private_runtime_management_receipt(&descriptor, &request, 1, 2, 10);
        let denied =
            apply_clean_management_test(created.clone(), &descriptor, request, Some(receipt), 2);
        assert_eq!(denied.state, created);
        assert_eq!(
            denied.outcome,
            RuntimeOutcome::Management(Err(ManagementError::ResourceLimit))
        );
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&denied.state)).unwrap();
        assert!(decoded.private_management_dispositions.is_empty());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standard_private_policy_bounds_lifecycle_and_disposition_history() {
        use crate::agent_sdk::contract::RuntimeResourcePolicy;
        use crate::agent_sdk::{ManagementError, ManagementReply, RuntimeOutcome};

        let (descriptor, created, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Private);
        let policy = RuntimeResourcePolicy {
            max_actors: 1,
            ..descriptor.initial_resource_policy()
        };
        let policy_request = private_runtime_management_request(
            &descriptor,
            0,
            None,
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(policy),
        );
        let policy_receipt =
            private_runtime_management_receipt(&descriptor, &policy_request, 1, 2, 10);
        let narrowed = apply_clean_management_test(
            created,
            &descriptor,
            policy_request,
            Some(policy_receipt),
            2,
        );

        let first_install = clean_install_request(
            &descriptor,
            "private-first",
            None,
            0xb1,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Merge),
        );
        let first_actor = first_install.entry.actor;
        let first_deployment = first_install.entry.deployment;
        let first_request = private_runtime_management_request(
            &descriptor,
            2,
            Some(crate::agent_sdk::Hash([0xb2; 32])),
            crate::agent_sdk::PrivateRuntimeMutation::Install(first_install.clone()),
        );
        let first_receipt =
            private_runtime_management_receipt(&descriptor, &first_request, 1, 3, 10);
        let installed = apply_clean_management_test(
            narrowed.state,
            &descriptor,
            first_request,
            Some(first_receipt),
            3,
        );
        assert_eq!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(first_install.entry)))
        );

        let second_install = clean_install_request(
            &descriptor,
            "private-second",
            None,
            0xb3,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Local),
        );
        let second_request = private_runtime_management_request(
            &descriptor,
            4,
            Some(crate::agent_sdk::Hash([0xb4; 32])),
            crate::agent_sdk::PrivateRuntimeMutation::Install(second_install),
        );
        let second_receipt =
            private_runtime_management_receipt(&descriptor, &second_request, 1, 4, 10);
        let denied = apply_clean_management_test(
            installed.state.clone(),
            &descriptor,
            second_request,
            Some(second_receipt),
            4,
        );
        assert_eq!(denied.state, installed.state);
        assert_eq!(
            denied.outcome,
            RuntimeOutcome::Management(Err(ManagementError::ResourceLimit))
        );

        let mut exact_limit =
            decode_standard_runtime_state(&clean_state_to_legacy(&denied.state)).unwrap();
        let template = exact_limit.private_management_dispositions[0].clone();
        exact_limit.private_management_dispositions = (1
            ..=super::super::standard::MAX_AUTHORITY_DISPOSITIONS)
            .map(|sequence| {
                let previous = if sequence == 1 {
                    crate::agent_sdk::Hash([0xb5; 32])
                } else {
                    crate::agent_sdk::Hash::digest(
                        b"test/private/control",
                        &[&((sequence - 1) as u64).to_le_bytes()],
                    )
                };
                StandardPrivateManagementDisposition {
                    authority: crate::agent_sdk::Hash::digest(
                        b"test/private/authority",
                        &[&(sequence as u64).to_le_bytes()],
                    ),
                    control: crate::agent_sdk::Hash::digest(
                        b"test/private/control",
                        &[&(sequence as u64).to_le_bytes()],
                    ),
                    request: crate::agent_sdk::Hash::digest(
                        b"test/private/request",
                        &[&(sequence as u64).to_le_bytes()],
                    ),
                    sequence: sequence as u64,
                    previous: Some(previous),
                    epoch: template.epoch,
                    observed_slot: template.observed_slot,
                    result: if sequence == 1 {
                        template.result.clone()
                    } else {
                        Ok(ManagementReply::Removed(crate::agent_sdk::ActorId(
                            crate::agent_sdk::Hash::digest(
                                b"test/private/removed",
                                &[&(sequence as u64).to_le_bytes()],
                            )
                            .0,
                        )))
                    },
                }
            })
            .collect();
        let last = exact_limit.private_management_dispositions.last().unwrap();
        exact_limit.private_runtime_control_commitment = Some(last.control);
        exact_limit.private_runtime_control_sequence = Some(last.sequence);
        exact_limit.private_authority_epoch_high_water = Some(last.epoch);
        exact_limit.private_control_slot_high_water = Some(last.observed_slot);
        StandardAgentRuntime::restore(exact_limit.clone()).unwrap();

        let mut missing_predecessor = exact_limit.clone();
        missing_predecessor.private_management_dispositions[0].previous = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_predecessor),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let mut genesis_with_predecessor = exact_limit.clone();
        genesis_with_predecessor.private_management_dispositions[0].sequence = 0;
        assert!(matches!(
            StandardAgentRuntime::restore(genesis_with_predecessor),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let mut wrong_adjacent_predecessor = exact_limit.clone();
        wrong_adjacent_predecessor.private_management_dispositions[1].previous =
            Some(crate::agent_sdk::Hash([0xba; 32]));
        assert!(matches!(
            StandardAgentRuntime::restore(wrong_adjacent_predecessor),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let mut retained_denial = exact_limit.clone();
        retained_denial.private_management_dispositions[0].result =
            Err(ManagementError::InvalidRequest);
        assert!(matches!(
            StandardAgentRuntime::restore(retained_denial),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let mut unsupported_success = exact_limit.clone();
        unsupported_success.private_management_dispositions[0].result =
            Ok(ManagementReply::ReplicasChanged {
                generation: crate::agent_sdk::Hash([0xbb; 32]),
            });
        assert!(matches!(
            StandardAgentRuntime::restore(unsupported_success),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let retained_policy_control = exact_limit.private_management_dispositions[0].control;
        let last_control = exact_limit
            .private_management_dispositions
            .last()
            .unwrap()
            .control;
        let suspend = private_runtime_management_request(
            &descriptor,
            (super::super::standard::MAX_AUTHORITY_DISPOSITIONS + 1) as u64,
            Some(last_control),
            crate::agent_sdk::PrivateRuntimeMutation::Suspend {
                actor: first_actor,
                expected_deployment: first_deployment,
            },
        );
        let suspend_receipt =
            private_runtime_management_receipt(&descriptor, &suspend, template.epoch, 5, 10);
        let compacted = apply_clean_management_test(
            legacy_state_to_clean(encode_standard_runtime_state(&exact_limit)),
            &descriptor,
            suspend,
            Some(suspend_receipt),
            5,
        );
        assert!(matches!(
            compacted.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Suspended(_)))
        ));
        let compacted =
            decode_standard_runtime_state(&clean_state_to_legacy(&compacted.state)).unwrap();
        assert_eq!(
            compacted.private_management_dispositions.len(),
            super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert!(
            compacted
                .private_management_dispositions
                .iter()
                .any(|item| item.control == retained_policy_control)
        );
        assert_eq!(compacted.active_resource_policy, Some(policy));

        exact_limit
            .private_management_dispositions
            .push(StandardPrivateManagementDisposition {
                authority: crate::agent_sdk::Hash([0xb6; 32]),
                control: crate::agent_sdk::Hash([0xb7; 32]),
                request: crate::agent_sdk::Hash([0xb8; 32]),
                sequence: (super::super::standard::MAX_AUTHORITY_DISPOSITIONS + 1) as u64,
                previous: Some(last.control),
                epoch: last.epoch,
                observed_slot: last.observed_slot,
                result: template.result,
            });
        assert!(matches!(
            StandardAgentRuntime::restore(exact_limit),
            Err(super::super::LifecycleError::InvalidRequest)
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn standard_private_policy_provenance_survives_more_than_1024_runtime_controls() {
        use crate::agent_sdk::contract::RuntimeResourcePolicy;
        use crate::agent_sdk::{ManagementReply, RuntimeOutcome};

        const NON_POLICY_CONTROLS: u64 = 1_025;

        let (descriptor, created, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Private);
        let initial = descriptor.initial_resource_policy();
        let policy = RuntimeResourcePolicy {
            max_actors: 2,
            ..initial
        };
        let policy_request = private_runtime_management_request(
            &descriptor,
            0,
            None,
            crate::agent_sdk::PrivateRuntimeMutation::SetResourcePolicy(policy),
        );
        let policy_control = match &policy_request {
            crate::agent_sdk::ManagementRequest::PrivateControl { control, .. } => {
                control.commitment()
            }
            _ => unreachable!(),
        };
        let policy_receipt =
            private_runtime_management_receipt(&descriptor, &policy_request, 1, 2, 10);
        let mut state = apply_clean_management_test(
            created,
            &descriptor,
            policy_request,
            Some(policy_receipt),
            2,
        )
        .state;

        let install = clean_install_request(
            &descriptor,
            "provenance-churn",
            None,
            0xc1,
            crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Merge),
        );
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let mut previous = policy_control;
        for sequence in 1..=NON_POLICY_CONTROLS {
            let mutation = if sequence == 1 {
                crate::agent_sdk::PrivateRuntimeMutation::Install(install.clone())
            } else if sequence % 2 == 0 {
                crate::agent_sdk::PrivateRuntimeMutation::Suspend {
                    actor,
                    expected_deployment: deployment,
                }
            } else {
                crate::agent_sdk::PrivateRuntimeMutation::Resume {
                    actor,
                    expected_deployment: deployment,
                }
            };
            let request =
                private_runtime_management_request(&descriptor, sequence, Some(previous), mutation);
            previous = match &request {
                crate::agent_sdk::ManagementRequest::PrivateControl { control, .. } => {
                    control.commitment()
                }
                _ => unreachable!(),
            };
            let receipt = private_runtime_management_receipt(&descriptor, &request, 1, 3, 10);
            let applied =
                apply_clean_management_test(state, &descriptor, request, Some(receipt), 3);
            assert!(matches!(
                applied.outcome,
                RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)
                    | ManagementReply::Suspended(_)
                    | ManagementReply::Resumed(_)))
            ));
            state = applied.state;
        }

        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        assert_eq!(
            decoded.private_management_dispositions.len(),
            super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(decoded.active_resource_policy, Some(policy));
        let retained_policy_rows = decoded
            .private_management_dispositions
            .iter()
            .filter(|item| {
                matches!(
                    &item.result,
                    Ok(ManagementReply::ResourcePolicySet(retained)) if *retained == policy
                )
            })
            .count();
        assert_eq!(retained_policy_rows, 1);
        assert_eq!(
            legacy_state_to_clean(encode_standard_runtime_state(&decoded)),
            state,
            "policy provenance and the bounded disposition selection survive reopen"
        );
        StandardAgentRuntime::restore(decoded.clone()).unwrap();

        let mut altered_policy = decoded.clone();
        altered_policy.active_resource_policy = Some(initial);
        assert!(matches!(
            StandardAgentRuntime::restore(altered_policy),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let policy_index = decoded
            .private_management_dispositions
            .iter()
            .position(|item| matches!(&item.result, Ok(ManagementReply::ResourcePolicySet(_))))
            .unwrap();
        let mut altered_provenance = decoded.clone();
        altered_provenance.private_management_dispositions[policy_index].result =
            Ok(ManagementReply::ResourcePolicySet(initial));
        assert!(matches!(
            StandardAgentRuntime::restore(altered_provenance),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let mut missing_provenance = decoded;
        missing_provenance
            .private_management_dispositions
            .remove(policy_index);
        assert!(matches!(
            StandardAgentRuntime::restore(missing_provenance),
            Err(super::super::LifecycleError::InvalidRequest)
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_retries_expiry_restart_and_authority_checks_are_exact() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };

        let (descriptor, created, create_receipt) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&created)).unwrap();
        assert_eq!(
            decoded.clean_creation_descriptor.as_ref(),
            Some(&descriptor)
        );
        assert_eq!(decoded.clean_descriptor.as_ref(), Some(&descriptor));
        assert_eq!(decoded.clean_management_dispositions.len(), 1);
        let projected =
            super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap();
        let image = super::super::driver::AgentImage {
            clean_descriptor: Some(descriptor.clone()),
            clean_management: Some(
                super::super::local_management::LocalManagementHistory::from_standard_fixture(
                    &decoded,
                ),
            ),
            revision: 1,
            runtime_program: crate::service::ProgramId(descriptor.identity.runtime_program.0),
            config: projected,
            runtime_state: clean_state_to_legacy(&created),
        };
        assert_eq!(
            super::super::driver::AgentImage::decode(&image.encode()).unwrap(),
            image,
            "a clean image must survive the durable host envelope"
        );
        let mut mismatched_image = image.clone();
        mismatched_image.config.identity.owner = crate::service::PrincipalId([0x7f; 32]);
        assert!(
            super::super::driver::AgentImage::decode(&mismatched_image.encode()).is_err(),
            "the envelope cannot substitute a legacy projection for the clean descriptor"
        );
        assert_eq!(
            legacy_state_to_clean(encode_standard_runtime_state(&decoded)),
            created,
            "restart must preserve the exact clean state bytes"
        );

        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let retried = apply_clean_management_test(
            created.clone(),
            &descriptor,
            create,
            Some(create_receipt),
            20,
        );
        assert_eq!(
            retried.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity.clone(),))),
            "an already committed exact retry survives receipt expiry"
        );
        assert_eq!(retried.state, created, "exact retry is byte-identical");

        let inspected = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            ManagementRequest::InspectResources,
            None,
            u64::MAX,
        );
        assert_eq!(inspected.state, retried.state);
        assert!(matches!(
            inspected.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Resources(_)))
        ));

        let request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0x61; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0x62; 32]),
        };
        let expired = clean_management_receipt(&descriptor, &request, 1, 1, 10);
        let rejected = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            request.clone(),
            Some(expired),
            21,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            "an unseen receipt is rejected after expiry"
        );
        assert_eq!(rejected.state, retried.state);

        let live = clean_management_receipt(&descriptor, &request, 1, 0, 100);
        let assert_invalid = |receipt| {
            let rejected = apply_clean_management_test(
                retried.state.clone(),
                &descriptor,
                request.clone(),
                Some(receipt),
                21,
            );
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
            );
            assert_eq!(rejected.state, retried.state);
        };

        let mut wrong_signature = live.clone();
        wrong_signature.signature[0] ^= 1;
        assert_invalid(wrong_signature);

        let mut wrong_policy = live.clone();
        wrong_policy.selector.policy = crate::agent_sdk::Hash([0x63; 32]);
        wrong_policy.signature = authority_key()
            .sign(&wrong_policy.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_policy);

        let mut wrong_issuer = live.clone();
        wrong_issuer.selector.issuer.principal = crate::agent_sdk::PrincipalId([0x64; 32]);
        wrong_issuer.signature = authority_key()
            .sign(&wrong_issuer.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_issuer);

        let mut wrong_operation = live.clone();
        wrong_operation.selector.operation =
            crate::agent_sdk::authority::AuthorityOperationKind::ResumeActor;
        wrong_operation.signature = authority_key()
            .sign(&wrong_operation.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_operation);

        let mut wrong_request = live.clone();
        wrong_request.selector.request = crate::agent_sdk::Hash([0x65; 32]);
        wrong_request.signature = authority_key()
            .sign(&wrong_request.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_request);

        let mut wrong_runtime = live.clone();
        wrong_runtime.selector.runtime_deployment = crate::agent_sdk::DeploymentId([0x66; 32]);
        wrong_runtime.signature = authority_key()
            .sign(&wrong_runtime.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_runtime);

        let mut wrong_space = live.clone();
        wrong_space.selector.space = crate::agent_sdk::SpaceId([0x68; 32]);
        wrong_space.signature = authority_key()
            .sign(&wrong_space.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_space);

        let mut wrong_agent = live.clone();
        wrong_agent.selector.agent = crate::agent_sdk::AgentId([0x69; 32]);
        wrong_agent.signature = authority_key()
            .sign(&wrong_agent.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_agent);

        let mut wrong_actor = live.clone();
        wrong_actor.selector.actor = Some(crate::agent_sdk::ActorId([0x67; 32]));
        wrong_actor.signature = authority_key()
            .sign(&wrong_actor.signing_bytes())
            .to_bytes();
        assert_invalid(wrong_actor);

        let alternate = SigningKey::from_bytes(&[0x42; 32]);
        let mut wrong_key = live.clone();
        wrong_key.public_key = alternate.verifying_key().to_bytes();
        wrong_key.selector.issuer.producer =
            crate::agent_sdk::ProducerId::of_public_key(&wrong_key.public_key);
        wrong_key.signature = alternate.sign(&wrong_key.signing_bytes()).to_bytes();
        assert_invalid(wrong_key);

        let divergent = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            request.clone(),
            Some(live.clone()),
            1,
        );
        assert_eq!(
            divergent.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceConflict))
        );
        assert_eq!(divergent.state, retried.state);

        let regressed = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            request.clone(),
            Some(live),
            0,
        );
        assert_eq!(
            regressed.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySlotRegressed))
        );
        assert_eq!(regressed.state, retried.state);

        let replacement = vec![crate::agent_sdk::AgentReplica {
            node: crate::agent_sdk::NodeId([0x70; 32]),
            principal: descriptor.identity.owner,
            role: crate::agent_sdk::ReplicaRole::Voter,
        }];
        let change = ManagementRequest::ChangeReplicas {
            expected_generation: descriptor.replica_generation(),
            replicas: replacement,
        };
        let changed = apply_clean_management_test(
            retried.state,
            &descriptor,
            change.clone(),
            Some(clean_management_receipt(&descriptor, &change, 2, 21, 30)),
            21,
        );
        assert!(matches!(
            changed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::ReplicasChanged { .. }))
        ));
        let current = decode_standard_runtime_state(&clean_state_to_legacy(&changed.state))
            .unwrap()
            .clean_descriptor
            .unwrap();
        let old_epoch = clean_management_receipt(&current, &request, 1, 22, 30);
        let rejected = apply_clean_management_test(
            changed.state.clone(),
            &current,
            request,
            Some(old_epoch),
            22,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceRegressed))
        );
        assert_eq!(rejected.state, changed.state);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_install_expiry_fences_without_actor_mutation_and_replays() {
        use crate::agent_sdk::{
            AgentProfile, LaneSet, ManagementError, ManagementRequest, RuntimeOutcome,
        };
        for profile in [AgentProfile::Local, AgentProfile::Shared] {
            let (descriptor, created, _) = create_clean_management_state(profile);
            let request = ManagementRequest::Install(Box::new(clean_install_request(
                &descriptor,
                "expired",
                None,
                0x71,
                LaneSet::of(crate::agent_sdk::StateLane::Linear),
            )));
            let receipt =
                clean_management_receipt_with_sequence(&descriptor, &request, 1, 2, 0, 2, 10);
            let mut forged = receipt.clone();
            forged.signature[0] ^= 1;
            let rejected = apply_clean_management_test(
                created.clone(),
                &descriptor,
                request.clone(),
                Some(forged),
                11,
            );
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
            );
            assert_eq!(rejected.state, created);
            let fenced = apply_clean_management_test(
                created.clone(),
                &descriptor,
                request.clone(),
                Some(receipt.clone()),
                11,
            );
            assert_eq!(
                fenced.outcome,
                RuntimeOutcome::Management(Err(ManagementError::ExpiredBeforeApplication))
            );
            assert_ne!(fenced.state, created);
            let before = decode_standard_runtime_state(&clean_state_to_legacy(&created)).unwrap();
            let after =
                decode_standard_runtime_state(&clean_state_to_legacy(&fenced.state)).unwrap();
            assert_eq!(after.actors, before.actors);
            assert_eq!(
                after.clean_actor_installations,
                before.clean_actor_installations
            );
            assert_eq!(after.clean_descriptor, before.clean_descriptor);
            assert_eq!(
                after.clean_management_dispositions.len(),
                before.clean_management_dispositions.len() + 1
            );
            let reopened = legacy_state_to_clean(encode_standard_runtime_state(&after));
            assert_eq!(reopened, fenced.state);
            let retry = apply_clean_management_test(
                reopened,
                &descriptor,
                request.clone(),
                Some(receipt),
                20,
            );
            assert_eq!(retry, fenced);
            let next =
                clean_management_receipt_with_sequence(&descriptor, &request, 1, 3, 2, 12, 30);
            let installed =
                apply_clean_management_test(retry.state, &descriptor, request, Some(next), 21);
            assert!(matches!(
                installed.outcome,
                RuntimeOutcome::Management(Ok(_))
            ));
            let installed =
                decode_standard_runtime_state(&clean_state_to_legacy(&installed.state)).unwrap();
            assert_eq!(installed.actors.len(), before.actors.len() + 1);
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_full_journal_acknowledges_and_pruned_retries_fail_closed() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };

        let (descriptor, mut state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let install = clean_install_request(
            &descriptor,
            "retained-target",
            None,
            0x51,
            crate::agent_sdk::LaneSet::NONE,
        );
        let actor = install.entry.actor;
        let deployment = install.entry.deployment;
        let capacity = super::super::standard::MAX_AUTHORITY_DISPOSITIONS as u64;

        let retained_request = ManagementRequest::Suspend {
            actor,
            expected_deployment: deployment,
        };
        let retained_receipt = clean_management_receipt_with_sequence(
            &descriptor,
            &retained_request,
            1,
            2,
            0,
            2,
            1_000,
        );
        let refused = apply_clean_management_test(
            state,
            &descriptor,
            retained_request.clone(),
            Some(retained_receipt.clone()),
            2,
        );
        assert_eq!(
            refused.outcome,
            RuntimeOutcome::Management(Err(ManagementError::NotFound))
        );
        state = refused.state;

        let install_request = ManagementRequest::Install(Box::new(install));
        let installed = apply_clean_management_test(
            state,
            &descriptor,
            install_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &descriptor,
                &install_request,
                1,
                3,
                0,
                3,
                1_000,
            )),
            3,
        );
        assert!(matches!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));
        state = installed.state;

        let absent_request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0x71; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0x72; 32]),
        };
        for sequence in 4..=capacity {
            let transition = apply_clean_management_test(
                state,
                &descriptor,
                absent_request.clone(),
                Some(clean_management_receipt_with_sequence(
                    &descriptor,
                    &absent_request,
                    1,
                    sequence,
                    0,
                    sequence,
                    1_000,
                )),
                sequence,
            );
            assert_eq!(
                transition.outcome,
                RuntimeOutcome::Management(Err(ManagementError::NotFound))
            );
            state = transition.state;
        }

        let saturated = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        assert_eq!(
            saturated.clean_management_dispositions.len(),
            super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(saturated.clean_decision_sequence_high_water, Some(capacity));
        assert_eq!(saturated.clean_acknowledged_through, 0);

        let restored = StandardAgentRuntime::restore(saturated).unwrap().snapshot();
        let restarted = legacy_state_to_clean(encode_standard_runtime_state(&restored));
        assert_eq!(restarted, state, "restart preserves the saturated journal");
        state = restarted;

        let overflow = apply_clean_management_test(
            state.clone(),
            &descriptor,
            absent_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &descriptor,
                &absent_request,
                1,
                capacity + 1,
                0,
                capacity + 1,
                1_000,
            )),
            capacity + 1,
        );
        assert_eq!(
            overflow.outcome,
            RuntimeOutcome::Management(Err(ManagementError::ResourceLimit))
        );
        assert_eq!(
            overflow.state, state,
            "a full journal with no advancing acknowledgement is unconsumed"
        );

        let acknowledged_through = capacity / 2;
        let progressed = apply_clean_management_test(
            state.clone(),
            &descriptor,
            absent_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &descriptor,
                &absent_request,
                1,
                capacity + 1,
                acknowledged_through,
                capacity + 1,
                1_000,
            )),
            capacity + 1,
        );
        assert_eq!(
            progressed.outcome,
            RuntimeOutcome::Management(Err(ManagementError::NotFound))
        );
        let compacted =
            decode_standard_runtime_state(&clean_state_to_legacy(&progressed.state)).unwrap();
        assert_eq!(compacted.clean_acknowledged_through, acknowledged_through);
        assert_eq!(
            compacted.clean_decision_sequence_high_water,
            Some(capacity + 1)
        );
        assert_eq!(
            compacted.clean_management_dispositions.len(),
            (capacity - acknowledged_through + 1) as usize
        );
        assert_eq!(
            compacted.clean_creation_descriptor.as_ref(),
            Some(&descriptor),
            "immutable creation survives acknowledgement of the Create result"
        );
        let mut invalid_watermark = compacted.clone();
        invalid_watermark.clean_acknowledged_through = capacity + 1;
        assert!(StandardAgentRuntime::restore(invalid_watermark).is_err());
        let mut invalid_order = compacted.clone();
        invalid_order.clean_management_dispositions.swap(0, 1);
        assert!(StandardAgentRuntime::restore(invalid_order).is_err());
        let restored = StandardAgentRuntime::restore(compacted).unwrap().snapshot();
        state = legacy_state_to_clean(encode_standard_runtime_state(&restored));
        assert_eq!(state, progressed.state);

        let live_retry = apply_clean_management_test(
            state.clone(),
            &descriptor,
            retained_request.clone(),
            Some(retained_receipt.clone()),
            capacity + 2,
        );
        assert_eq!(
            live_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceRegressed)),
            "an acknowledged live refusal is consumed and cannot execute again"
        );
        assert_eq!(live_retry.state, state, "live retry is byte-identical");
        state = live_retry.state;
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        assert!(
            !decoded
                .actors
                .iter()
                .find(|item| item.record.entry.actor.0 == actor.0)
                .unwrap()
                .record
                .entry
                .suspended,
            "re-executing the old Suspend would have changed this actor"
        );

        let expired_retry = apply_clean_management_test(
            state.clone(),
            &descriptor,
            retained_request.clone(),
            Some(retained_receipt.clone()),
            1_001,
        );
        assert_eq!(
            expired_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceRegressed)),
            "expiry cannot turn an acknowledged receipt back into unseen work"
        );
        assert_eq!(
            expired_retry.state, state,
            "expired exact retry is byte-identical"
        );
        let ack_beyond_high_water = apply_clean_management_test(
            state.clone(),
            &descriptor,
            absent_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &descriptor,
                &absent_request,
                1,
                capacity + 3,
                capacity + 2,
                capacity + 2,
                2_000,
            )),
            capacity + 2,
        );
        assert_eq!(
            ack_beyond_high_water.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceConflict))
        );
        assert_eq!(ack_beyond_high_water.state, state);

        let decreasing_ack = apply_clean_management_test(
            state.clone(),
            &descriptor,
            absent_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &descriptor,
                &absent_request,
                1,
                capacity + 2,
                acknowledged_through - 1,
                capacity + 2,
                2_000,
            )),
            capacity + 2,
        );
        assert_eq!(
            decreasing_ack.outcome,
            RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceRegressed))
        );
        assert_eq!(decreasing_ack.state, state);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_periodic_acknowledgements_cross_twice_capacity_and_restart() {
        use crate::agent_sdk::{ManagementError, ManagementRequest, RuntimeOutcome};

        let (descriptor, mut state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xd1; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xd2; 32]),
        };
        let capacity = super::super::standard::MAX_AUTHORITY_DISPOSITIONS as u64;
        let last_sequence = 2 * capacity + 37;
        let mut acknowledged_through = 0;
        for sequence in 2..=last_sequence {
            if sequence % 64 == 0 {
                acknowledged_through = sequence - 1;
            }
            let transition = apply_clean_management_test(
                state,
                &descriptor,
                request.clone(),
                Some(clean_management_receipt_with_sequence(
                    &descriptor,
                    &request,
                    1,
                    sequence,
                    acknowledged_through,
                    sequence,
                    last_sequence + 10,
                )),
                sequence,
            );
            assert_eq!(
                transition.outcome,
                RuntimeOutcome::Management(Err(ManagementError::NotFound))
            );
            state = transition.state;
            if sequence % 73 == 0 {
                let decoded =
                    decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
                state = legacy_state_to_clean(encode_standard_runtime_state(
                    &StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
                ));
            }
        }

        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        assert_eq!(
            decoded.clean_decision_sequence_high_water,
            Some(last_sequence)
        );
        assert_eq!(decoded.clean_acknowledged_through, acknowledged_through);
        assert!(
            decoded.clean_management_dispositions.len()
                < super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert!(
            decoded
                .clean_management_dispositions
                .iter()
                .all(|item| item.sequence > acknowledged_through)
        );
        assert_eq!(
            decoded.clean_creation_descriptor.as_ref(),
            Some(&descriptor)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_state_ceiling_refuses_before_consuming_authority() {
        use crate::agent_sdk::{ManagementError, ManagementRequest, RuntimeOutcome};

        let (_descriptor, state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let mut constrained =
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        let exact_bytes = clean_state_to_legacy(&state).encoded_len().unwrap() as u32;
        let mut current = constrained.clean_descriptor.clone().unwrap();
        current.runtime_contract.resources.max_runtime_state_bytes = exact_bytes;
        constrained.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(&current).unwrap());
        constrained.active_resource_policy = Some(current.initial_resource_policy());
        constrained.clean_descriptor = Some(current.clone());
        let state = legacy_state_to_clean(encode_standard_runtime_state(&constrained));
        assert_eq!(state.encoded_len(), Some(exact_bytes as usize));
        StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();

        let request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xc1; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xc2; 32]),
        };
        let receipt = clean_management_receipt(&current, &request, 1, 2, 10);
        for observed_slot in [2, 3] {
            let rejected = apply_clean_management_test(
                state.clone(),
                &current,
                request.clone(),
                Some(receipt.clone()),
                observed_slot,
            );
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Management(Err(ManagementError::ResourceLimit))
            );
            assert_eq!(
                rejected.state, state,
                "no authority is consumed when a durable disposition cannot fit"
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_historical_retries_survive_two_runtime_upgrades_and_restart() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };

        let (descriptor, mut state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let old_request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0x91; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0x92; 32]),
        };
        let old_receipt = clean_management_receipt(&descriptor, &old_request, 1, 2, 2);
        let refused = apply_clean_management_test(
            state,
            &descriptor,
            old_request.clone(),
            Some(old_receipt.clone()),
            2,
        );
        assert_eq!(
            refused.outcome,
            RuntimeOutcome::Management(Err(ManagementError::NotFound))
        );
        state = refused.state;

        let first_upgrade = crate::agent_sdk::RuntimeUpgrade {
            from_deployment: descriptor.identity.runtime_deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0xa1; 32]),
            to_program: crate::agent_sdk::ProgramId([0xa2; 32]),
            producer: crate::agent_sdk::ProducerId([0xa3; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"first-runtime-package"),
            contract: crate::agent_sdk::contract::RuntimePackageContract::canonical(),
            capabilities: crate::agent_sdk::RuntimeCapabilities::standard(),
        };
        let first_request = ManagementRequest::UpgradeRuntime(Box::new(first_upgrade.clone()));
        let first_receipt = clean_management_receipt(&descriptor, &first_request, 1, 3, 3);
        let upgraded = apply_clean_management_test(
            state,
            &descriptor,
            first_request.clone(),
            Some(first_receipt.clone()),
            3,
        );
        assert!(matches!(
            upgraded.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(ref identity)))
                if identity.runtime_deployment == first_upgrade.to_deployment
        ));
        state = upgraded.state;
        let after_first = decode_standard_runtime_state(&clean_state_to_legacy(&state))
            .unwrap()
            .clean_descriptor
            .unwrap();

        let second_upgrade = crate::agent_sdk::RuntimeUpgrade {
            from_deployment: after_first.identity.runtime_deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0xb1; 32]),
            to_program: crate::agent_sdk::ProgramId([0xb2; 32]),
            producer: crate::agent_sdk::ProducerId([0xb3; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"second-runtime-package"),
            contract: crate::agent_sdk::contract::RuntimePackageContract::canonical(),
            capabilities: crate::agent_sdk::RuntimeCapabilities::standard(),
        };
        let second_request = ManagementRequest::UpgradeRuntime(Box::new(second_upgrade.clone()));
        let upgraded = apply_clean_management_test(
            state,
            &after_first,
            second_request.clone(),
            Some(clean_management_receipt(
                &after_first,
                &second_request,
                1,
                4,
                4,
            )),
            4,
        );
        assert!(matches!(
            upgraded.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(ref identity)))
                if identity.runtime_deployment == second_upgrade.to_deployment
        ));
        let after_second = decode_standard_runtime_state(&clean_state_to_legacy(&upgraded.state))
            .unwrap()
            .clean_descriptor
            .unwrap();

        let decoded =
            decode_standard_runtime_state(&clean_state_to_legacy(&upgraded.state)).unwrap();
        let restarted = legacy_state_to_clean(encode_standard_runtime_state(
            &StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
        ));

        let old_retry = apply_clean_management_test(
            restarted.clone(),
            &after_second,
            old_request.clone(),
            Some(old_receipt.clone()),
            100,
        );
        assert_eq!(
            old_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::NotFound)),
            "a pre-upgrade lifecycle disposition remains authoritative after restart"
        );
        assert_eq!(old_retry.state, restarted);
        assert_eq!(
            decode_standard_runtime_state(&clean_state_to_legacy(&old_retry.state))
                .unwrap()
                .clean_descriptor
                .as_ref(),
            Some(&after_second)
        );

        let first_upgrade_retry = apply_clean_management_test(
            old_retry.state.clone(),
            &after_second,
            first_request.clone(),
            Some(first_receipt.clone()),
            101,
        );
        assert!(matches!(
            first_upgrade_retry.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(ref identity)))
                if identity.runtime_deployment == first_upgrade.to_deployment
                    && identity.runtime_program == first_upgrade.to_program
        ));
        assert_eq!(first_upgrade_retry.state, old_retry.state);
        assert_eq!(
            decode_standard_runtime_state(&clean_state_to_legacy(&first_upgrade_retry.state))
                .unwrap()
                .clean_descriptor
                .as_ref(),
            Some(&after_second),
            "recovering the first upgrade must not roll back the active runtime"
        );

        let stale_unseen = clean_management_receipt(&descriptor, &old_request, 1, 102, 110);
        let rejected = apply_clean_management_test(
            first_upgrade_retry.state.clone(),
            &after_second,
            old_request.clone(),
            Some(stale_unseen),
            102,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            "an unseen receipt cannot select a retired runtime deployment"
        );
        assert_eq!(rejected.state, first_upgrade_retry.state);

        let stale_upgrade = clean_management_receipt(&descriptor, &first_request, 1, 103, 110);
        let rejected = apply_clean_management_test(
            first_upgrade_retry.state.clone(),
            &after_second,
            first_request.clone(),
            Some(stale_upgrade),
            103,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::InvalidRequest)),
            "a newly signed upgrade cannot reuse a retired from-deployment"
        );
        assert_eq!(rejected.state, first_upgrade_retry.state);

        let divergent = crate::agent_sdk::RuntimeWork::Manage {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            space: after_second.identity.space,
            agent: after_second.identity.agent,
            runtime_deployment: old_receipt.selector.runtime_deployment,
            state: first_upgrade_retry.state.clone(),
            request: Box::new(ManagementRequest::Resume {
                actor: crate::agent_sdk::ActorId([0x91; 32]),
                expected_deployment: crate::agent_sdk::DeploymentId([0x92; 32]),
            }),
            authority: Some(Box::new(old_receipt.clone())),
            observed_slot: 104,
        };
        assert_eq!(
            divergent.encode(),
            Err(crate::agent_sdk::wire::WireError::InvalidValue),
            "a retained receipt cannot be paired with a divergent typed request"
        );

        let acknowledgement_request = ManagementRequest::Suspend {
            actor: crate::agent_sdk::ActorId([0xc1; 32]),
            expected_deployment: crate::agent_sdk::DeploymentId([0xc2; 32]),
        };
        let acknowledged = apply_clean_management_test(
            first_upgrade_retry.state.clone(),
            &after_second,
            acknowledgement_request.clone(),
            Some(clean_management_receipt_with_sequence(
                &after_second,
                &acknowledgement_request,
                1,
                5,
                3,
                5,
                200,
            )),
            5,
        );
        assert_eq!(
            acknowledged.outcome,
            RuntimeOutcome::Management(Err(ManagementError::NotFound))
        );
        let compacted =
            decode_standard_runtime_state(&clean_state_to_legacy(&acknowledged.state)).unwrap();
        assert_eq!(compacted.clean_acknowledged_through, 3);
        assert!(
            compacted
                .clean_management_dispositions
                .iter()
                .all(|item| item.sequence > 3)
        );

        for (request, receipt) in [(old_request, old_receipt), (first_request, first_receipt)] {
            let pruned_retry = apply_clean_management_test(
                acknowledged.state.clone(),
                &after_second,
                request,
                Some(receipt),
                201,
            );
            assert_eq!(
                pruned_retry.outcome,
                RuntimeOutcome::Management(Err(ManagementError::AuthoritySequenceRegressed))
            );
            assert_eq!(
                pruned_retry.state, acknowledged.state,
                "acknowledged historical decisions cannot run again"
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_runs_full_lifecycle_paging_runtime_and_replica_changes() {
        use crate::agent_sdk::{
            ManagementError, ManagementReply, ManagementRequest, RuntimeOutcome,
        };

        let (descriptor, mut state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Local);
        let parent = clean_install_request(
            &descriptor,
            "parent",
            None,
            0x21,
            crate::agent_sdk::LaneSet::NONE,
        );
        let parent_actor = parent.entry.actor;
        let parent_deployment = parent.entry.deployment;
        let install_parent = ManagementRequest::Install(Box::new(parent.clone()));
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            install_parent.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &install_parent,
                1,
                2,
                2,
            )),
            2,
        );
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(parent.entry.clone())))
        );
        state = transition.state;

        let child = clean_install_request(
            &descriptor,
            "child",
            Some(parent_actor),
            0x31,
            crate::agent_sdk::LaneSet::NONE,
        );
        let child_actor = child.entry.actor;
        let child_deployment = child.entry.deployment;
        let install_child = ManagementRequest::Install(Box::new(child.clone()));
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            install_child.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &install_child,
                1,
                3,
                3,
            )),
            3,
        );
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(child.entry.clone())))
        );
        state = transition.state;

        let first = apply_clean_management_test(
            state.clone(),
            &descriptor,
            ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            },
            None,
            0,
        );
        assert_eq!(first.state, state);
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(first_page))) = first.outcome
        else {
            panic!("expected first actor page")
        };
        assert_eq!(first_page.entries.len(), 1);
        let cursor = first_page.next.expect("two actors require a second page");
        let second = apply_clean_management_test(
            state.clone(),
            &descriptor,
            ManagementRequest::InspectActors {
                after: Some(cursor),
                limit: 1,
            },
            None,
            0,
        );
        assert_eq!(second.state, state);
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(second_page))) = second.outcome
        else {
            panic!("expected second actor page")
        };
        assert_eq!(second_page.entries.len(), 1);
        assert_eq!(second_page.next, None);
        assert_ne!(
            first_page.entries[0].entry.actor,
            second_page.entries[0].entry.actor
        );

        let upgraded_deployment = crate::agent_sdk::DeploymentId([0x41; 32]);
        let upgraded_package = crate::agent_sdk::BlobRef::of_bytes(b"upgraded-package");
        let upgraded_schema = crate::agent_sdk::BlobRef::of_bytes(b"upgraded-schema");
        let upgraded_policy = crate::agent_sdk::BlobRef::of_bytes(b"upgraded-policy");
        let upgrade = crate::agent_sdk::UpgradeActor {
            actor: parent_actor,
            from_deployment: parent_deployment,
            to_deployment: upgraded_deployment,
            to_program: crate::agent_sdk::ProgramId::of_pvm(b"upgraded-program"),
            producer: crate::agent_sdk::ProducerId([0x42; 32]),
            package: upgraded_package,
            agent_schema: upgraded_schema,
            method_policy: upgraded_policy,
            constructor_abi: parent.constructor_abi,
            state_layout: parent.state_layout,
            contract: parent.contract,
            requirements: parent.requirements,
        };
        let upgrade_request = ManagementRequest::UpgradeActor(Box::new(upgrade.clone()));
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            upgrade_request.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &upgrade_request,
                1,
                4,
                4,
            )),
            4,
        );
        assert!(matches!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Upgraded(ref entry)))
                if entry.actor == parent_actor && entry.deployment == upgraded_deployment
        ));
        state = transition.state;

        let suspend = ManagementRequest::Suspend {
            actor: parent_actor,
            expected_deployment: upgraded_deployment,
        };
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            suspend.clone(),
            Some(clean_management_receipt(&descriptor, &suspend, 1, 5, 5)),
            5,
        );
        assert!(matches!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Suspended(ref entry)))
                if entry.suspended
        ));
        state = transition.state;

        let resume = ManagementRequest::Resume {
            actor: parent_actor,
            expected_deployment: upgraded_deployment,
        };
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            resume.clone(),
            Some(clean_management_receipt(&descriptor, &resume, 1, 6, 6)),
            6,
        );
        assert!(matches!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Resumed(ref entry)))
                if !entry.suspended
        ));
        state = transition.state;

        let remove_parent = ManagementRequest::RemoveLeaf {
            actor: parent_actor,
            expected_deployment: upgraded_deployment,
        };
        let remove_parent_receipt = clean_management_receipt(&descriptor, &remove_parent, 1, 7, 7);
        let busy = apply_clean_management_test(
            state,
            &descriptor,
            remove_parent.clone(),
            Some(remove_parent_receipt.clone()),
            7,
        );
        assert!(matches!(
            busy.outcome,
            RuntimeOutcome::Management(Err(ManagementError::Busy(debt))) if debt.children == 1
        ));
        let busy_retry = apply_clean_management_test(
            busy.state,
            &descriptor,
            remove_parent.clone(),
            Some(remove_parent_receipt),
            50,
        );
        assert!(matches!(
            busy_retry.outcome,
            RuntimeOutcome::Management(Err(ManagementError::Busy(debt))) if debt.children == 1
        ));
        state = busy_retry.state;

        let remove_child = ManagementRequest::RemoveLeaf {
            actor: child_actor,
            expected_deployment: child_deployment,
        };
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            remove_child.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &remove_child,
                1,
                51,
                51,
            )),
            51,
        );
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Removed(child_actor)))
        );
        state = transition.state;

        let transition = apply_clean_management_test(
            state,
            &descriptor,
            remove_parent.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &remove_parent,
                1,
                52,
                52,
            )),
            52,
        );
        assert_eq!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Removed(parent_actor)))
        );
        state = transition.state;

        let runtime_upgrade = crate::agent_sdk::RuntimeUpgrade {
            from_deployment: descriptor.identity.runtime_deployment,
            to_deployment: crate::agent_sdk::DeploymentId([0x81; 32]),
            to_program: crate::agent_sdk::ProgramId([0x82; 32]),
            producer: crate::agent_sdk::ProducerId([0x83; 32]),
            package: crate::agent_sdk::BlobRef::of_bytes(b"new-runtime-package"),
            contract: crate::agent_sdk::contract::RuntimePackageContract::canonical(),
            capabilities: crate::agent_sdk::RuntimeCapabilities::standard(),
        };
        let upgrade_runtime = ManagementRequest::UpgradeRuntime(Box::new(runtime_upgrade.clone()));
        let transition = apply_clean_management_test(
            state,
            &descriptor,
            upgrade_runtime.clone(),
            Some(clean_management_receipt(
                &descriptor,
                &upgrade_runtime,
                1,
                53,
                53,
            )),
            53,
        );
        assert!(matches!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::RuntimeUpgraded(ref identity)))
                if identity.runtime_deployment == runtime_upgrade.to_deployment
                    && identity.runtime_program == runtime_upgrade.to_program
        ));
        state = transition.state;
        let current = decode_standard_runtime_state(&clean_state_to_legacy(&state))
            .unwrap()
            .clean_descriptor
            .unwrap();

        let replacements = vec![crate::agent_sdk::AgentReplica {
            node: crate::agent_sdk::NodeId([0x84; 32]),
            principal: current.identity.owner,
            role: crate::agent_sdk::ReplicaRole::Voter,
        }];
        let change = ManagementRequest::ChangeReplicas {
            expected_generation: current.replica_generation(),
            replicas: replacements,
        };
        let transition = apply_clean_management_test(
            state,
            &current,
            change.clone(),
            Some(clean_management_receipt(&current, &change, 1, 54, 54)),
            54,
        );
        assert!(matches!(
            transition.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::ReplicasChanged { .. }))
        ));
        let inspected = apply_clean_management_test(
            transition.state.clone(),
            &current,
            ManagementRequest::InspectResources,
            None,
            0,
        );
        assert_eq!(inspected.state, transition.state);
        assert!(matches!(
            inspected.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Resources(usage)))
                if usage.actors == 0 && usage.continuations == 0
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_management_private_profile_refuses_linear_install_and_retains_error() {
        use crate::agent_sdk::{ManagementError, ManagementRequest, RuntimeOutcome, StateLane};

        let (descriptor, state, _) =
            create_clean_management_state(crate::agent_sdk::AgentProfile::Private);
        let install = clean_install_request(
            &descriptor,
            "linear",
            None,
            0x51,
            crate::agent_sdk::LaneSet::of(StateLane::Linear),
        );
        let request = ManagementRequest::Install(Box::new(install));
        let receipt = clean_management_receipt(&descriptor, &request, 1, 2, 2);
        let rejected = apply_clean_management_test(
            state,
            &descriptor,
            request.clone(),
            Some(receipt.clone()),
            2,
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedLane))
        );
        let retried =
            apply_clean_management_test(rejected.state, &descriptor, request, Some(receipt), 100);
        assert_eq!(
            retried.outcome,
            RuntimeOutcome::Management(Err(ManagementError::UnsupportedLane))
        );
        let inspected = apply_clean_management_test(
            retried.state.clone(),
            &descriptor,
            ManagementRequest::InspectActors {
                after: None,
                limit: 1,
            },
            None,
            0,
        );
        assert_eq!(inspected.state, retried.state);
        assert!(matches!(
            inspected.outcome,
            RuntimeOutcome::Management(Ok(crate::agent_sdk::ManagementReply::Actors(page)))
                if page.entries.is_empty()
        ));
    }

    #[cfg(feature = "pvm")]
    fn clean_pending_fixture() -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::authority::AuthorityReceipt,
        crate::agent_sdk::YieldedInvocation,
    ) {
        clean_pending_fixture_with_origin(None)
    }

    #[cfg(feature = "pvm")]
    fn clean_pending_fixture_with_origin(
        origin: Option<crate::agent_sdk::InvocationOrigin>,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::authority::AuthorityReceipt,
        crate::agent_sdk::YieldedInvocation,
    ) {
        let (mut runtime, mut work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        if let Some(origin) = origin {
            work.origin = origin;
        }
        let state = runtime.snapshot();
        let config = state.config.as_ref().unwrap().clone();
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let authority = clean_authority_receipt(&config, &work);
        let authorization =
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority.clone());
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa1]);
        runtime
            .commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before,
                after,
                1,
                None,
                portable_continuation(&invocation, 1, 3).continuation,
                Some((
                    super::super::standard::StandardAcceptedInvocation::from_work(&work),
                    authorization.clone(),
                )),
            )
            .unwrap();
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, 1)
            .unwrap()
            .unwrap();
        (
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            work,
            authority,
            yielded,
        )
    }

    #[cfg(feature = "pvm")]
    fn clean_resume(
        yielded: &crate::agent_sdk::YieldedInvocation,
        availability: Vec<crate::agent_sdk::RuntimeBlob>,
    ) -> crate::agent_sdk::ResumeWork {
        crate::agent_sdk::ResumeWork {
            invocation: yielded.invocation,
            actor: yielded.actor,
            incarnation: yielded.incarnation,
            deployment: yielded.deployment,
            program: yielded.program,
            mode: yielded.mode,
            continuation: yielded.continuation.clone(),
            ready_sequence: yielded.ready_sequence,
            installation_data: yielded.installation_data.clone(),
            availability,
            input: None,
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_resolvable_fixture(
        alias_artifact_roles: bool,
    ) -> (StandardAgentRuntime, crate::agent_sdk::InvocationWork) {
        clean_resolvable_fixture_with_program(alias_artifact_roles, b"clean-program".to_vec())
    }

    #[cfg(feature = "pvm")]
    fn clean_resolvable_fixture_with_program(
        alias_artifact_roles: bool,
        program_bytes: Vec<u8>,
    ) -> (StandardAgentRuntime, crate::agent_sdk::InvocationWork) {
        let mut state = clean_sparse_standard_state();
        let config = state.config.as_ref().unwrap().clone();
        let actor = &mut state.actors[0].record;
        let schema_bytes = if alias_artifact_roles {
            program_bytes.clone()
        } else {
            b"clean-schema".to_vec()
        };
        let policy_bytes = if alias_artifact_roles {
            program_bytes.clone()
        } else {
            b"clean-policy".to_vec()
        };
        actor.entry.program =
            crate::service::ProgramId(crate::agent_sdk::ProgramId::of_pvm(&program_bytes).0);
        let schema = crate::agent_sdk::BlobRef::of_bytes(&schema_bytes);
        actor.entry.agent_schema = crate::service::BlobRef {
            hash: crate::service::Hash(schema.hash.0),
            len: schema.len,
        };
        let policy = crate::agent_sdk::BlobRef::of_bytes(&policy_bytes);
        actor.entry.role_policies = crate::service::BlobRef {
            hash: crate::service::Hash(policy.hash.0),
            len: policy.len,
        };
        actor.agent_schema = actor.entry.agent_schema.clone();
        actor.role_policies = actor.entry.role_policies.clone();
        let mut availability = [program_bytes, schema_bytes, policy_bytes]
            .into_iter()
            .map(|bytes| crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
                bytes,
            })
            .collect::<Vec<_>>();
        availability.sort_unstable_by_key(|blob| blob.reference.clone());
        availability.dedup_by(|left, right| left.reference == right.reference);
        let work = crate::agent_sdk::InvocationWork {
            space: crate::agent_sdk::SpaceId(config.identity.space.0),
            agent: crate::agent_sdk::AgentId(config.identity.agent.0),
            runtime_deployment: crate::agent_sdk::DeploymentId(
                config.identity.runtime_deployment.0,
            ),
            invocation: crate::agent_sdk::InvocationId([0xd4; 32]),
            actor: crate::agent_sdk::ActorId(actor.entry.actor.0),
            incarnation: crate::agent_sdk::Hash(actor.state_generation.0),
            deployment: crate::agent_sdk::DeploymentId(actor.entry.deployment.0),
            program: crate::agent_sdk::ProgramId(actor.entry.program.0),
            mode: crate::agent_sdk::MethodMode::Linear,
            origin: crate::agent_sdk::InvocationOrigin::anonymous(),
            roles: crate::agent_sdk::InvocationRoleClaims::none(),
            message: vec![1],
            installation_data: None,
            availability,
            gas: 100,
            recovery_only: false,
        };
        (StandardAgentRuntime::restore(state).unwrap(), work)
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_resolver_accepts_sdk_message_limit_and_separates_caller_blobs() {
        let (runtime, mut work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        work.message = vec![1; crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES];
        let bytes = vec![0x61; 36 * 1024];
        let caller = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
            bytes: bytes.clone(),
        };
        work.availability.push(caller);
        work.availability
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        assert!(work.validate());
        let (inner, program, schema, policy, _) = runtime.resolve_clean_invocation(&work).unwrap();
        assert_eq!(inner.message, work.message);
        assert_eq!(inner.availability.len(), 1);
        assert_eq!(inner.availability[0].bytes, bytes);
        assert_ne!(program, bytes);
        assert_ne!(schema.bytes, bytes);
        assert_ne!(policy.bytes, bytes);
        let reference = crate::service::BlobRef::of_bytes(&bytes);
        assert_eq!(
            inner.available_preimage(&reference),
            Ok(Some(bytes.as_slice()))
        );

        let mut missing_program = work.clone();
        missing_program
            .availability
            .retain(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) != work.program);
        assert!(matches!(
            runtime.resolve_clean_invocation(&missing_program),
            Err(crate::agent_sdk::InvocationError::InvalidAvailability)
        ));
        work.message.push(1);
        assert!(!work.validate());
        assert!(matches!(
            runtime.resolve_clean_invocation(&work),
            Err(crate::agent_sdk::InvocationError::InvalidInput)
        ));
    }

    /// Declared actors may exceed the standard program size up to the
    /// runtime's hard maximum; nothing larger is ever resolved as a program.
    #[cfg(feature = "pvm")]
    #[test]
    fn clean_resolver_executes_declared_programs_up_to_the_hard_maximum() {
        let standard = crate::agent_sdk::STANDARD_ACTOR_PROGRAM_BYTES;
        let maximum = crate::agent_sdk::MAX_RUNTIME_PROGRAM_BYTES;
        assert_eq!(
            super::super::execution::MAX_EXECUTION_PROGRAM_BYTES,
            maximum
        );
        for (len, resolves) in [
            (standard, true),
            (standard + 1, true),
            (maximum, true),
            (maximum + 1, false),
        ] {
            let program = vec![0x6b; len];
            let (runtime, work) = clean_resolvable_fixture_with_program(false, program.clone());
            // The work is well formed either way; only the runtime decides
            // what may be executed as the actor's program.
            assert!(work.validate(), "{len} B");
            match runtime.resolve_clean_invocation(&work) {
                Ok((_, resolved, ..)) => {
                    assert!(resolves, "{len} B resolved");
                    assert_eq!(resolved, program);
                }
                Err(error) => {
                    assert!(!resolves, "{len} B refused: {error:?}");
                    assert!(matches!(
                        error,
                        crate::agent_sdk::InvocationError::InvalidAvailability
                            | crate::agent_sdk::InvocationError::InvalidInput
                    ));
                }
            }
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_policy_fixture(
        selector: crate::agent_sdk::method_policy::AuthorizationPolicySelector,
    ) -> (StandardAgentRuntime, crate::agent_sdk::InvocationWork) {
        clean_policy_fixture_with_attestation(
            selector,
            crate::agent_sdk::method_policy::AttestationRequirement::None,
        )
    }

    #[cfg(feature = "pvm")]
    fn enable_clean_test_proof_system(
        state: &mut StandardRuntimeState,
        proof_system: crate::agent_sdk::Hash,
    ) {
        state.actors[0].record.requirements.proofs = true;
        let proof_systems = crate::agent_sdk::ProofSystemSet::from_sorted(&[proof_system]).unwrap();
        state.clean_actor_packages.as_mut().unwrap()[0]
            .requirements
            .proof_systems = proof_systems;
        state.clean_actor_installations.as_mut().unwrap()[0]
            .requirements
            .proof_systems = proof_systems;
        let installation = &mut state.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.requirements = installation.requirements;
        installation.commitment = installation.original.lineage_commitment();
        state
            .clean_creation_descriptor
            .as_mut()
            .unwrap()
            .capabilities
            .proof_systems = proof_systems;
        let descriptor = state.clean_descriptor.as_mut().unwrap();
        descriptor.capabilities.proof_systems = proof_systems;
        state.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(descriptor).unwrap());
        state.active_resource_policy = Some(descriptor.initial_resource_policy());
    }

    #[cfg(feature = "pvm")]
    fn clean_policy_fixture_with_attestation(
        selector: crate::agent_sdk::method_policy::AuthorizationPolicySelector,
        attestation: crate::agent_sdk::method_policy::AttestationRequirement,
    ) -> (StandardAgentRuntime, crate::agent_sdk::InvocationWork) {
        clean_policy_fixture_with_storage(selector, attestation, false)
    }

    #[cfg(feature = "pvm")]
    fn clean_policy_fixture_with_storage(
        selector: crate::agent_sdk::method_policy::AuthorizationPolicySelector,
        attestation: crate::agent_sdk::method_policy::AttestationRequirement,
        storage: bool,
    ) -> (StandardAgentRuntime, crate::agent_sdk::InvocationWork) {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::agent_sdk::method_policy::{
            ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
            IdempotencyRequirement,
        };
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;

        let (runtime, mut work) = clean_resolvable_fixture(false);
        let mut schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields: vec![ParsedField::Inline(ParsedInlineField {
                source_index: 0,
                name: "value".into(),
                type_identity: "core::primitive::u8".into(),
                persistence: crate::agent_sdk::FieldPersistence::State(
                    crate::agent_sdk::StateLane::Linear,
                ),
            })],
            methods: vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: crate::agent_sdk::MethodMode::Linear,
                explicit: true,
            }],
        };
        if storage {
            schema.fields.push(ParsedField::Storage(
                crate::agent_sdk::schema::ParsedStorageField {
                    source_index: 1,
                    name: "rows".into(),
                    type_identity: "test::StorageMap<u32,u64>".into(),
                    prefix: b"s/rows/".to_vec(),
                    lane: crate::agent_sdk::StateLane::Linear,
                    committed: false,
                    leaf_domain: None,
                    node_domain: None,
                },
            ));
        }
        let schema_bytes = schema.encode().unwrap();
        let schema_blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&schema_bytes),
            bytes: schema_bytes,
        };
        let policy_bytes = ActorMethodPolicyArtifact {
            actor_schema: schema_blob.reference.clone(),
            methods: vec![ActorMethodPolicy {
                name: "write".into(),
                mode: crate::agent_sdk::MethodMode::Linear,
                arguments: Vec::new(),
                return_type_identity: "core::primitive::u8".into(),
                authorization_policy: selector,
                idempotency: IdempotencyRequirement::Required,
                attestation,
            }],
        }
        .encode()
        .unwrap();
        let policy_blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&policy_bytes),
            bytes: policy_bytes,
        };
        let program_blob = work
            .availability
            .iter()
            .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
            .unwrap()
            .clone();
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("write").encode());
        work.message = message;
        work.availability = vec![program_blob, schema_blob.clone(), policy_blob.clone()];
        work.availability
            .sort_unstable_by_key(|blob| blob.reference.clone());

        let mut state = runtime.snapshot();
        let actor = &mut state.actors[0].record;
        actor.entry.agent_schema = crate::service::BlobRef {
            hash: Hash(schema_blob.reference.hash.0),
            len: schema_blob.reference.len,
        };
        actor.agent_schema = actor.entry.agent_schema.clone();
        actor.entry.role_policies = crate::service::BlobRef {
            hash: Hash(policy_blob.reference.hash.0),
            len: policy_blob.reference.len,
        };
        actor.role_policies = actor.entry.role_policies.clone();
        let state_layout = Hash(schema.state_layout_hash().unwrap().0);
        actor.entry.state_layout = state_layout;
        actor.state_layout = state_layout;
        actor.entry.lanes = LaneSet::of(StateLane::Linear);
        actor.requirements.lanes = LaneSet::of(StateLane::Linear);
        state.clean_actor_packages.as_mut().unwrap()[0]
            .requirements
            .lanes = crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear);
        state.clean_actor_installations.as_mut().unwrap()[0]
            .requirements
            .lanes = crate::agent_sdk::LaneSet::of(crate::agent_sdk::StateLane::Linear);
        if let AttestationRequirement::Required { proof_system } = attestation {
            enable_clean_test_proof_system(&mut state, proof_system);
        }
        // This fixture synthesizes a new initial installation rather than
        // applying an upgrade. Keep its original compact plan consistent
        // with the schema/policy/requirements selected above.
        let record = &state.actors[0].record;
        let installation = &mut state.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.entry =
            super::super::standard::legacy_actor_record_to_clean(record, installation.commitment)
                .entry;
        installation.original.contract = installation.contract;
        installation.original.requirements = installation.requirements;
        installation.commitment = installation.original.lineage_commitment();
        (StandardAgentRuntime::restore(state).unwrap(), work)
    }

    #[cfg(feature = "pvm")]
    fn attested_test_route(
        state: &crate::agent_sdk::RuntimeState,
        work: &crate::agent_sdk::InvocationWork,
        proof_system: crate::agent_sdk::Hash,
    ) -> super::super::transition_proof_host::AttestedTransitionRoute {
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        let runtime = StandardAgentRuntime::restore(decoded).unwrap();
        let descriptor = runtime.clean_descriptor().unwrap();
        assert_eq!(work.space, descriptor.identity.space);
        assert_eq!(work.agent, descriptor.identity.agent);
        assert_eq!(
            work.runtime_deployment,
            descriptor.identity.runtime_deployment
        );
        let route = super::super::transition_proof_host::AttestedTransitionRoute::for_descriptor(
            descriptor,
            proof_system,
            crate::agent_sdk::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        )
        .unwrap();
        assert_eq!(route.producer(), descriptor.identity.transition_producer);
        assert_ne!(route.producer(), descriptor.identity.runtime_producer);
        route
    }

    #[cfg(feature = "pvm")]
    fn attested_test_admission(
        route: &super::super::transition_proof_host::AttestedTransitionRoute,
        work: &crate::agent_sdk::RuntimeWork,
        method: &str,
    ) -> super::super::transition_proof_host::AttestedTransitionAdmission {
        let (state, actor) = match work {
            crate::agent_sdk::RuntimeWork::Invoke {
                state, invocation, ..
            } => (state, invocation.actor),
            crate::agent_sdk::RuntimeWork::Resume { state, resume, .. } => (state, resume.actor),
            crate::agent_sdk::RuntimeWork::Manage { .. }
            | crate::agent_sdk::RuntimeWork::Acknowledge { .. } => unreachable!(),
            #[cfg(feature = "experimental-state-blocks")]
            crate::agent_sdk::RuntimeWork::InspectInvocation { .. } => unreachable!(),
        };
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        let package = decoded
            .clean_actor_packages
            .as_ref()
            .and_then(|packages| packages.iter().find(|package| package.actor == actor))
            .copied()
            .unwrap();
        let runtime = StandardAgentRuntime::restore(decoded).unwrap();
        let descriptor = runtime.clean_descriptor().unwrap();
        let actor = runtime
            .actor(crate::service::ActorId(actor.0))
            .map(super::super::standard::legacy_entry_to_clean)
            .unwrap();
        super::super::transition_proof_host::AttestedTransitionAdmission {
            space: route.space,
            agent: route.agent,
            runtime_deployment: route.runtime_deployment,
            runtime_program: route.runtime_program,
            runtime_package: route.runtime_package.clone(),
            max_proof_material_bytes: route.max_proof_material_bytes,
            runtime_contract: descriptor.runtime_contract,
            runtime_capabilities: descriptor.capabilities,
            actor_entry: actor.clone(),
            actor_contract: package.contract,
            actor_requirements: package.requirements,
            method: method.into(),
        }
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn completed_clean_policy_fixture(
        proof_system: crate::agent_sdk::Hash,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::InvocationAuthorization,
    ) {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight};

        let (mut runtime, work) = clean_policy_fixture_with_attestation(
            AuthorizationPolicySelector::Public,
            crate::agent_sdk::method_policy::AttestationRequirement::Required { proof_system },
        );
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        runtime
            .verify_clean_invocation_authorization(&work, &authorization, 1)
            .unwrap();
        let (invocation, _, schema, policy, _) = runtime.resolve_clean_invocation(&work).unwrap();
        assert!(matches!(
            runtime.authorize_clean_execution(&work, &authorization, &schema, &policy),
            Err(ActorExecutionError::InvalidAuthorization),
        ));
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa7]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        (
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            work,
            authorization,
        )
    }

    #[cfg(feature = "pvm")]
    fn yielded_clean_policy_fixture(
        proof_system: crate::agent_sdk::Hash,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::YieldedInvocation,
    ) {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight};

        let (mut runtime, work) = clean_policy_fixture_with_attestation(
            AuthorizationPolicySelector::Public,
            crate::agent_sdk::method_policy::AttestationRequirement::Required { proof_system },
        );
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        runtime
            .commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before,
                before.clone(),
                1,
                None,
                portable_continuation(&invocation, 1, 3).continuation,
                Some((
                    super::super::standard::StandardAcceptedInvocation::from_work(&work),
                    authorization.clone(),
                )),
            )
            .unwrap();
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, 1)
            .unwrap()
            .unwrap();
        (
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            work,
            yielded,
        )
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn authenticated_attested_standard_invoke_restart_requires_the_exact_capability() {
        use crate::agent::transition_proof_host::AuthenticatedAttestedTransition;
        use crate::agent_sdk::{
            InvocationError, RuntimeExecutionContext, RuntimeOutcome, RuntimeWork,
        };

        let proof_system = crate::agent_sdk::Hash([0x93; 32]);
        let (state, invocation, authorization) = completed_clean_policy_fixture(proof_system);
        let reopened_state = legacy_state_to_clean(encode_standard_runtime_state(
            &decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        ));
        assert_eq!(reopened_state, state);
        let route = attested_test_route(&state, &invocation, proof_system);
        let exact = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Attested { proof_system },
            state,
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 9,
        };
        let authenticated = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            attested_test_admission(&route, &exact, "write"),
        )
        .unwrap();
        assert_eq!(authenticated.runtime_package(), &route.runtime_package);
        let mut direct = exact.clone();
        let RuntimeWork::Invoke { context, .. } = &mut direct else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Direct;
        let RuntimeWork::Invoke { state: prior, .. } = &direct else {
            unreachable!()
        };
        let prior = prior.clone();
        let rejected = apply_standard_runtime_work(direct).unwrap();
        assert_eq!(rejected.state, prior);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
        );
        assert!(!InvocationError::InvalidAuthorization.is_durable_exact_outcome());
        let applied =
            apply_authenticated_attested_standard_runtime_work(&authenticated, exact.clone())
                .unwrap();
        assert!(matches!(applied.outcome, RuntimeOutcome::Completed(Ok(_))));
        assert_eq!(
            apply_standard_runtime_work(exact.clone()),
            Err(DecodeError::NonCanonical),
            "the public Direct executor must not bypass proof hosting",
        );

        let mut wrong_route = exact.clone();
        let RuntimeWork::Invoke { invocation, .. } = &mut wrong_route else {
            unreachable!()
        };
        invocation.runtime_deployment = crate::agent_sdk::DeploymentId([0x94; 32]);
        assert_eq!(
            apply_authenticated_attested_standard_runtime_work(&authenticated, wrong_route),
            Err(DecodeError::NonCanonical),
        );

        let mut wrong_system = exact.clone();
        let RuntimeWork::Invoke { context, .. } = &mut wrong_system else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Attested {
            proof_system: crate::agent_sdk::Hash([0x95; 32]),
        };
        assert_eq!(
            apply_authenticated_attested_standard_runtime_work(&authenticated, wrong_system),
            Err(DecodeError::NonCanonical),
        );

        let mut wrong_package = attested_test_admission(&route, &exact, "write");
        wrong_package.runtime_package = crate::agent_sdk::BlobRef::of_bytes(b"substitution");
        assert!(
            AuthenticatedAttestedTransition::authenticate_for_test(&route, &exact, wrong_package,)
                .is_none()
        );
        assert!(
            AuthenticatedAttestedTransition::authenticate_for_test(
                &route,
                &exact,
                attested_test_admission(&route, &exact, "read"),
            )
            .is_none()
        );

        let mut missing_runtime_system = attested_test_admission(&route, &exact, "write");
        missing_runtime_system.runtime_capabilities.proof_systems =
            crate::agent_sdk::ProofSystemSet::EMPTY;
        assert!(
            AuthenticatedAttestedTransition::authenticate_for_test(
                &route,
                &exact,
                missing_runtime_system,
            )
            .is_none()
        );

        let mut missing_actor_system = attested_test_admission(&route, &exact, "write");
        missing_actor_system.actor_requirements.proof_systems =
            crate::agent_sdk::ProofSystemSet::EMPTY;
        assert!(
            AuthenticatedAttestedTransition::authenticate_for_test(
                &route,
                &exact,
                missing_actor_system,
            )
            .is_none()
        );

        let mut substituted_capabilities = attested_test_admission(&route, &exact, "write");
        substituted_capabilities.runtime_capabilities.proof_systems =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[
                proof_system,
                crate::agent_sdk::Hash([0x94; 32]),
            ])
            .unwrap();
        let substituted_capabilities = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            substituted_capabilities,
        )
        .unwrap();
        assert!(matches!(
            apply_authenticated_attested_standard_runtime_work(
                &substituted_capabilities,
                exact.clone(),
            )
            .unwrap()
            .outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAvailability)),
        ));

        let mut substituted_actor = attested_test_admission(&route, &exact, "write");
        substituted_actor.actor_entry.package =
            crate::agent_sdk::BlobRef::of_bytes(b"substituted-actor-package");
        let substituted_actor = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            substituted_actor,
        )
        .unwrap();
        assert!(matches!(
            apply_authenticated_attested_standard_runtime_work(&substituted_actor, exact.clone())
                .unwrap()
                .outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAvailability)),
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn authenticated_attested_standard_rejects_an_amp2_none_method() {
        use crate::agent::transition_proof_host::AuthenticatedAttestedTransition;
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, PublicPreflight, RuntimeExecutionContext,
            RuntimeOutcome, RuntimeWork,
        };

        let proof_system = crate::agent_sdk::Hash([0x95; 32]);
        let (runtime, invocation) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 1));
        let mut snapshot = runtime.snapshot();
        enable_clean_test_proof_system(&mut snapshot, proof_system);
        let reopened = StandardAgentRuntime::restore(snapshot).unwrap();
        let state = legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot()));
        let route = attested_test_route(&state, &invocation, proof_system);
        let exact = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Attested { proof_system },
            state,
            invocation: Box::new(invocation),
            authorization: Box::new(authorization),
            observed_slot: 1,
        };
        let authenticated = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            attested_test_admission(&route, &exact, "write"),
        )
        .unwrap();
        assert!(matches!(
            apply_authenticated_attested_standard_runtime_work(&authenticated, exact.clone())
                .unwrap()
                .outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization)),
        ));

        let mut direct = exact;
        let RuntimeWork::Invoke { context, .. } = &mut direct else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Direct;
        assert!(!matches!(
            apply_standard_runtime_work(direct).unwrap().outcome,
            RuntimeOutcome::Completed(Err(InvocationError::UnsupportedMethod)),
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn authenticated_attested_standard_resume_restart_recovers_the_exact_method() {
        use crate::agent::transition_proof_host::AuthenticatedAttestedTransition;
        use crate::agent_sdk::{
            InvocationError, RuntimeExecutionContext, RuntimeOutcome, RuntimeWork,
        };

        let proof_system = crate::agent_sdk::Hash([0x96; 32]);
        let (state, invocation, yielded) = yielded_clean_policy_fixture(proof_system);
        let route = attested_test_route(&state, &invocation, proof_system);
        let exact = RuntimeWork::Resume {
            context: RuntimeExecutionContext::Attested { proof_system },
            state,
            resume: Box::new(clean_resume(&yielded, invocation.availability.clone())),
        };
        let authenticated = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            attested_test_admission(&route, &exact, "write"),
        )
        .unwrap();
        let mut direct = exact.clone();
        let RuntimeWork::Resume { context, .. } = &mut direct else {
            unreachable!()
        };
        *context = RuntimeExecutionContext::Direct;
        let RuntimeWork::Resume { state: prior, .. } = &direct else {
            unreachable!()
        };
        let prior = prior.clone();
        let rejected = apply_standard_runtime_work(direct).unwrap();
        assert_eq!(
            rejected.state, prior,
            "missing proof must preserve the pending continuation"
        );
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
        );
        let applied =
            apply_authenticated_attested_standard_runtime_work(&authenticated, exact.clone())
                .unwrap();
        assert!(!matches!(
            applied.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::UnsupportedMethod)),
        ));
        assert_eq!(
            apply_standard_runtime_work(exact.clone()),
            Err(DecodeError::NonCanonical),
        );

        // Even when the current runtime package supports a strict superset,
        // Resume remains bound to the actor package requirements persisted
        // with the original accepted Invoke.
        let substitute_proof = crate::agent_sdk::Hash([0x97; 32]);
        let supported =
            crate::agent_sdk::ProofSystemSet::from_sorted(&[proof_system, substitute_proof])
                .unwrap();
        let mut substituted = exact.clone();
        let RuntimeWork::Resume { state, .. } = &mut substituted else {
            unreachable!()
        };
        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        let descriptor = decoded.clean_descriptor.as_mut().unwrap();
        descriptor.capabilities.proof_systems = supported;
        decoded.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(descriptor).unwrap());
        decoded.active_resource_policy = Some(descriptor.initial_resource_policy());
        *state = legacy_state_to_clean(encode_standard_runtime_state(&decoded));
        let substituted_route = attested_test_route(state, &invocation, proof_system);
        let mut substituted_admission =
            attested_test_admission(&substituted_route, &substituted, "write");
        substituted_admission.actor_requirements.proof_systems = supported;
        let substituted_capability = AuthenticatedAttestedTransition::authenticate_for_test(
            &substituted_route,
            &substituted,
            substituted_admission,
        )
        .unwrap();
        assert!(matches!(
            apply_authenticated_attested_standard_runtime_work(
                &substituted_capability,
                substituted,
            )
            .unwrap()
            .outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAvailability)),
        ));

        let wrong_method = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &exact,
            attested_test_admission(&route, &exact, "read"),
        )
        .unwrap();
        assert_eq!(
            apply_authenticated_attested_standard_runtime_work(&wrong_method, exact.clone()),
            Err(DecodeError::NonCanonical),
            "Resume must recover the original Invoke method from durable state",
        );

        let mut wrong_slice = exact;
        let RuntimeWork::Resume { resume, .. } = &mut wrong_slice else {
            unreachable!()
        };
        resume.ready_sequence += 1;
        assert_eq!(
            apply_authenticated_attested_standard_runtime_work(&authenticated, wrong_slice),
            Err(DecodeError::NonCanonical),
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn resolved_clean_commit_preserves_binding_and_rejects_changed_provenance() {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight};
        let (mut runtime, work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        let resolved = runtime
            .resolve_clean_invocation_for_execution(&work)
            .unwrap();
        let invocation = &resolved.parts().0;
        let before = runtime.prepare_execution_state(invocation).unwrap();
        let original = runtime.snapshot();
        let mut changed = original.clone();
        changed.actors[0].record.producer = crate::service::ProducerId([0x93; 32]);
        let mut stale = StandardAgentRuntime::restore(changed.clone()).unwrap();
        let mut reply = exact_reply(invocation, ActorExecutionStatus::Done);
        let original_reply = reply.clone();
        assert_eq!(
            stale.commit_resolved_clean_execution(
                &resolved,
                &authorization,
                &mut reply,
                &before,
                before.clone(),
                1,
                None,
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        );
        assert_eq!(stale.snapshot(), changed);
        assert_eq!(reply, original_reply);

        let mut substituted_authorization = authorization.clone();
        let InvocationAuthorization::PublicPreflight(preflight) = &mut substituted_authorization
        else {
            unreachable!()
        };
        preflight.observed_slot = 2;
        assert_eq!(
            runtime.commit_resolved_clean_execution(
                &resolved,
                &substituted_authorization,
                &mut reply,
                &before,
                before.clone(),
                1,
                None,
            ),
            Err(ActorExecutionError::InvalidAuthorization)
        );
        assert_eq!(runtime.snapshot(), original);
        assert_eq!(reply, original_reply);

        let mut reference = StandardAgentRuntime::restore(original).unwrap();
        let mut reference_reply = original_reply;
        reference
            .commit_clean_execution(
                &work,
                &authorization,
                invocation,
                &mut reference_reply,
                &before,
                before.clone(),
                1,
                None,
            )
            .unwrap();
        runtime
            .commit_resolved_clean_execution(
                &resolved,
                &authorization,
                &mut reply,
                &before,
                before.clone(),
                1,
                None,
            )
            .unwrap();
        assert_eq!(runtime.snapshot(), reference.snapshot());
        assert_eq!(reply, reference_reply);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_success_commit_rejects_substituted_execution_without_mutation() {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight};
        let (mut runtime, work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let snapshot = runtime.snapshot();
        let mut variants = vec![invocation.clone(); 4];
        variants[0].message.push(0x91);
        variants[1].gas -= 1;
        variants[2].auth.principal = Some(crate::service::PrincipalId([0x91; 32]));
        let bytes = b"unaccepted application input".to_vec();
        variants[3]
            .availability
            .push(super::super::execution::RuntimeBlob {
                reference: crate::service::BlobRef::of_bytes(&bytes),
                bytes,
            });
        for substituted in variants {
            let mut after = before.clone();
            after.linear = Some(vec![0xa7]);
            let mut reply = exact_reply(&substituted, ActorExecutionStatus::Done);
            let original_reply = reply.clone();
            assert_eq!(
                runtime.commit_clean_execution(
                    &work,
                    &authorization,
                    &substituted,
                    &mut reply,
                    &before,
                    after,
                    1,
                    None,
                ),
                Err(ActorExecutionError::InvalidActorOutput)
            );
            assert_eq!(runtime.snapshot(), snapshot);
            assert_eq!(reply, original_reply);
        }
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                before.clone(),
                1,
                None,
            )
            .unwrap();
        let committed = runtime.snapshot();
        assert_eq!(committed.invocation_results.len(), 1);
        assert_eq!(
            committed.invocation_results[0].request.0,
            work.commitment().0
        );
        assert_eq!(
            runtime.recover_execution(&invocation, 1),
            Err(ActorExecutionError::DivergentInvocation)
        );
        assert_eq!(runtime.snapshot(), committed);
        let mut substituted = committed.clone();
        substituted.invocation_results[0].request = invocation.commitment();
        assert_ne!(
            substituted.invocation_results[0].request,
            committed.invocation_results[0].request
        );
        assert!(
            StandardAgentRuntime::restore(substituted).is_err(),
            "r19 clean result identity must not accept the old execution commitment"
        );
        let mut reopened = StandardAgentRuntime::restore(committed).unwrap();
        assert!(
            reopened
                .recover_clean_execution(&work, &authorization, 1)
                .unwrap()
                .is_some()
        );
        let compact = crate::agent_sdk::InvocationRetirement::from_work(&work);
        assert_eq!(
            reopened.recover_clean_retirement(&compact, &authorization),
            Ok(None)
        );
        let mut full_work_path = StandardAgentRuntime::restore(reopened.snapshot()).unwrap();
        let expected = full_work_path
            .acknowledge_clean_invocation(&work, &authorization)
            .unwrap();
        let before_retirement = reopened.snapshot();
        let mut unseen = compact.clone();
        unseen.invocation = crate::agent_sdk::InvocationId([0xa9; 32]);
        let unseen_auth = InvocationAuthorization::PublicPreflight(PublicPreflight {
            work: unseen.commitment(),
            origin: unseen.origin,
            observed_slot: 1,
        });
        assert_eq!(
            reopened.acknowledge_clean_retirement_with_status(&unseen, &unseen_auth),
            Err(crate::agent_sdk::InvocationError::NotFound)
        );
        assert_eq!(reopened.snapshot(), before_retirement);
        let (acknowledgement, applied) = reopened
            .acknowledge_clean_retirement_with_status(&compact, &authorization)
            .unwrap();
        assert!(applied);
        assert_eq!(acknowledgement, expected);
        assert_eq!(reopened.snapshot(), full_work_path.snapshot());
        assert_eq!(
            reopened.acknowledge_clean_retirement_with_status(&compact, &authorization),
            Ok((acknowledgement, false))
        );
        assert!(reopened.snapshot().invocation_results.is_empty());
        let retired = reopened.snapshot();
        let reopened = StandardAgentRuntime::restore(retired.clone()).unwrap();
        assert_eq!(
            reopened.recover_clean_retirement(&compact, &authorization),
            Ok(Some(acknowledgement))
        );
        let mut changed = compact.clone();
        changed.message.push(0x91);
        assert_eq!(
            reopened.recover_clean_retirement(&changed, &authorization),
            Err(crate::agent_sdk::InvocationError::InvalidAuthorization)
        );
        let mut changed_authorization = authorization.clone();
        let InvocationAuthorization::PublicPreflight(preflight) = &mut changed_authorization else {
            unreachable!()
        };
        preflight.observed_slot += 1;
        assert!(changed_authorization.matches_retirement(&compact));
        assert_eq!(
            reopened.recover_clean_retirement(&compact, &changed_authorization),
            Err(crate::agent_sdk::InvocationError::DivergentInvocation)
        );
        assert_eq!(reopened.snapshot(), retired);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn public_preflight_is_policy_gated_and_persists_exact_retry_ack_and_continuation_binding() {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, PublicPreflight, RuntimeOutcome, RuntimeWork,
        };

        let (mut runtime, work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        runtime
            .verify_clean_invocation_authorization(&work, &authorization, 1)
            .unwrap();
        let (invocation, _, schema, policy, _) = runtime.resolve_clean_invocation(&work).unwrap();
        assert_eq!(
            runtime.authorize_clean_execution(&work, &authorization, &schema, &policy),
            Ok(true),
        );
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa7]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        let committed = legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()));
        let reopened = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&committed)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
            committed,
        );
        #[cfg(feature = "experimental-state-blocks")]
        {
            use super::super::standard::RetainedCleanTerminal;
            let retirement = crate::agent_sdk::InvocationRetirement::from_work(&work);
            assert_eq!(
                reopened.inspect_clean_retained_terminal(&retirement, &authorization, 2),
                Ok(Some(RetainedCleanTerminal::Completed(Ok(reply.clone())))),
            );
            let mut unseen = work.clone();
            unseen.invocation = crate::agent_sdk::InvocationId([0xb8; 32]);
            let unseen_authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&unseen, 1));
            assert_eq!(
                reopened.inspect_clean_retained_terminal(
                    &crate::agent_sdk::InvocationRetirement::from_work(&unseen),
                    &unseen_authorization,
                    2,
                ),
                Ok(None),
            );
            assert_eq!(
                reopened.snapshot(),
                decode_standard_runtime_state(&clean_state_to_legacy(&committed)).unwrap(),
                "inspection must not advance the retained result clock",
            );
            let inspected = apply_standard_runtime_work(RuntimeWork::InspectInvocation {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: committed.clone(),
                invocation: Box::new(retirement),
                authorization: Box::new(authorization.clone()),
                observed_slot: 2,
            })
            .unwrap();
            assert_eq!(inspected.state, committed);
            assert_eq!(
                inspected.outcome,
                RuntimeOutcome::Completed(Ok(clean_reply(reply.clone())))
            );
        }

        let retried = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: committed.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 1,
        })
        .unwrap();
        assert!(matches!(retried.outcome, RuntimeOutcome::Completed(Ok(_))));
        assert_eq!(retried.state, committed);

        let different_slot = RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: committed.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 2,
        };
        let retried_later = apply_standard_runtime_work(different_slot).unwrap();
        assert!(matches!(
            &retried_later.outcome,
            RuntimeOutcome::Completed(Ok(_))
        ));

        let (runtime, unseen_work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let unseen_state =
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()));
        let stale_unseen = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: unseen_state.clone(),
            authorization: Box::new(InvocationAuthorization::PublicPreflight(
                PublicPreflight::for_work(&unseen_work, 1),
            )),
            invocation: Box::new(unseen_work),
            observed_slot: 2,
        })
        .unwrap();
        assert_eq!(stale_unseen.state, unseen_state);
        assert_eq!(
            stale_unseen.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::AuthorityExpired)),
        );

        let acknowledged = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: retried_later.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        })
        .unwrap();
        let RuntimeOutcome::Acknowledged(Ok(acknowledgement)) = acknowledged.outcome else {
            panic!("exact PublicPreflight result was not acknowledged")
        };
        assert_eq!(acknowledgement.work, work.commitment());
        assert_eq!(acknowledgement.authorization, authorization.commitment());
        #[cfg(feature = "experimental-state-blocks")]
        {
            use super::super::standard::RetainedCleanTerminal;
            let retired = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&acknowledged.state)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                retired.inspect_clean_retained_terminal(
                    &crate::agent_sdk::InvocationRetirement::from_work(&work),
                    &authorization,
                    2,
                ),
                Ok(Some(RetainedCleanTerminal::Acknowledged(acknowledgement))),
            );
            let inspected = apply_standard_runtime_work(RuntimeWork::InspectInvocation {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: acknowledged.state.clone(),
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
                authorization: Box::new(authorization.clone()),
                observed_slot: 2,
            })
            .unwrap();
            assert_eq!(inspected.state, acknowledged.state);
            assert_eq!(
                inspected.outcome,
                RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
            );
        }

        let mut tampered =
            decode_standard_runtime_state(&clean_state_to_legacy(&committed)).unwrap();
        let InvocationAuthorization::PublicPreflight(preflight) = &mut tampered.invocation_results
            [0]
        .clean
        .as_mut()
        .unwrap()
        .authorization
        else {
            unreachable!()
        };
        preflight.origin.principal = Some(crate::agent_sdk::PrincipalId([0xa8; 32]));
        preflight.origin.transport_node = Some(crate::agent_sdk::NodeId([0xa9; 32]));
        preflight.origin.credential = Some(crate::agent_sdk::CredentialId([0xaa; 32]));
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&tampered)),
            Err(DecodeError::NonCanonical),
        );

        let (runtime, work) = clean_policy_fixture(AuthorizationPolicySelector::Capability(
            crate::agent_sdk::CapabilityId([0xab; 32]),
        ));
        let state = legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()));
        let public = InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
        let denied = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(work),
            authorization: Box::new(public),
            observed_slot: 1,
        })
        .unwrap();
        assert_eq!(denied.state, state);
        assert_eq!(
            denied.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization)),
        );

        let (mut runtime, work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 3));
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        runtime
            .commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before,
                before.clone(),
                3,
                None,
                portable_continuation(&invocation, 1, 3).continuation,
                Some((
                    super::super::standard::StandardAcceptedInvocation::from_work(&work),
                    authorization.clone(),
                )),
            )
            .unwrap();
        let encoded = encode_standard_runtime_state(&runtime.snapshot());
        let reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&encoded).unwrap())
                .unwrap();
        assert!(
            reopened
                .recover_clean_yield(&work, &authorization, 3)
                .unwrap()
                .is_some()
        );
        assert!(
            reopened
                .recover_clean_yield(&work, &authorization, 4)
                .unwrap()
                .is_some(),
            "an exact yielded retry may be observed after its immutable acceptance slot",
        );
        let mut substituted_request = decode_standard_runtime_state(&encoded).unwrap();
        substituted_request.machine_continuations[0].request = Hash([0xac; 32]);
        let substituted_request = StandardAgentRuntime::restore(substituted_request).unwrap();
        assert_eq!(
            substituted_request.recover_clean_yield(&work, &authorization, 4),
            Err(InvocationError::DivergentInvocation),
            "yield recovery must bind the resolved legacy execution commitment",
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_resolution_preserves_exact_origin_for_aic1_and_rejects_artifact_role_aliases() {
        use crate::agent_sdk::InvocationError;

        let (runtime, work) = clean_resolvable_fixture(false);
        let resolved = runtime.resolve_clean_invocation(&work).unwrap();
        assert_eq!(
            resolved.0.auth,
            super::super::execution::ActorInvocationAuth::anonymous(),
            "clean identity must not be projected into the legacy auth frame"
        );

        let mut actor_origin = work.clone();
        actor_origin.origin.actor = Some(crate::agent_sdk::ActorId([0xd5; 32]));
        assert!(runtime.resolve_clean_invocation(&actor_origin).is_ok());
        let mut transport_origin = work.clone();
        transport_origin.origin.transport_node = Some(crate::agent_sdk::NodeId([0xd6; 32]));
        assert!(runtime.resolve_clean_invocation(&transport_origin).is_ok());
        let mut credential_origin = work;
        credential_origin.origin.principal = Some(crate::agent_sdk::PrincipalId([0xd7; 32]));
        credential_origin.origin.credential = Some(crate::agent_sdk::CredentialId([0xd8; 32]));
        assert!(runtime.resolve_clean_invocation(&credential_origin).is_ok());

        let (runtime, aliased) = clean_resolvable_fixture(true);
        assert_eq!(
            runtime.resolve_clean_invocation(&aliased),
            Err(InvocationError::InvalidAvailability)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_resolution_length_filter_still_hashes_matching_roles() {
        use crate::agent_sdk::InvocationError;

        let (runtime, work) = clean_resolvable_fixture(false);
        let expected = runtime.resolve_clean_invocation(&work).unwrap();
        // Schema and policy deliberately have the same length; length alone
        // must never select a role. Supplied references remain unchanged.
        assert_eq!(expected.2.bytes.len(), expected.3.bytes.len());
        for role in [&expected.2, &expected.3] {
            let index = work
                .availability
                .iter()
                .position(|blob| blob == role)
                .unwrap();
            for change_length in [false, true] {
                let mut corrupted = work.clone();
                if change_length {
                    corrupted.availability[index].bytes.push(0xff);
                } else {
                    corrupted.availability[index].bytes[0] ^= 1;
                }
                assert_eq!(
                    runtime.resolve_clean_invocation(&corrupted),
                    Err(InvocationError::InvalidAvailability),
                );
            }
            let mut duplicated = work.clone();
            duplicated.availability.push(role.clone());
            assert_eq!(
                runtime.resolve_clean_invocation(&duplicated),
                Err(InvocationError::InvalidAvailability),
            );
        }
        assert_eq!(runtime.resolve_clean_invocation(&work).unwrap(), expected);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_pending_retry_and_resume_validation_are_exact_and_state_preserving() {
        use crate::actors::codec::Encode as _;
        use crate::agent_sdk::{InvocationError, ResumeInput, RuntimeOutcome, RuntimeWork};

        let (state, work, authority, yielded) = clean_pending_fixture();
        let retried = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )),
            observed_slot: 99,
        })
        .unwrap();
        assert_eq!(retried.state, state);
        assert_eq!(retried.outcome, RuntimeOutcome::Yielded(yielded.clone()));

        let assert_rejected = |resume: crate::agent_sdk::ResumeWork, expected| {
            let transition = apply_standard_runtime_work(RuntimeWork::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: state.clone(),
                resume: Box::new(resume),
            })
            .unwrap();
            assert_eq!(transition.state, state);
            assert_eq!(transition.outcome, RuntimeOutcome::Completed(Err(expected)));
            assert!(!expected.is_durable_exact_outcome());
        };

        let mut wrong_actor = clean_resume(&yielded, work.availability.clone());
        wrong_actor.actor = crate::agent_sdk::ActorId([0xe1; 32]);
        assert_rejected(wrong_actor, InvocationError::StaleContinuation);
        let mut wrong_incarnation = clean_resume(&yielded, work.availability.clone());
        wrong_incarnation.incarnation = crate::agent_sdk::Hash([0xe2; 32]);
        assert_rejected(wrong_incarnation, InvocationError::StaleContinuation);
        let mut wrong_deployment = clean_resume(&yielded, work.availability.clone());
        wrong_deployment.deployment = crate::agent_sdk::DeploymentId([0xe3; 32]);
        assert_rejected(wrong_deployment, InvocationError::StaleContinuation);
        let mut wrong_program = clean_resume(&yielded, work.availability.clone());
        wrong_program.program = crate::agent_sdk::ProgramId([0xe4; 32]);
        assert_rejected(wrong_program, InvocationError::StaleContinuation);
        let mut wrong_mode = clean_resume(&yielded, work.availability.clone());
        wrong_mode.mode = crate::agent_sdk::MethodMode::Merge;
        assert_rejected(wrong_mode, InvocationError::StaleContinuation);

        let mut wrong_reference = clean_resume(&yielded, work.availability.clone());
        wrong_reference.continuation.hash.0[0] ^= 1;
        assert_rejected(wrong_reference, InvocationError::StaleContinuation);

        let mut wrong_sequence = clean_resume(&yielded, work.availability.clone());
        wrong_sequence.ready_sequence += 1;
        assert_rejected(wrong_sequence, InvocationError::NotReady);

        let mut missing = clean_resume(&yielded, work.availability.clone());
        missing.availability.pop();
        assert_rejected(missing, InvocationError::InvalidAvailability);
        let mut extra = clean_resume(&yielded, work.availability.clone());
        extra.availability.push(crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(b"extra"),
            bytes: b"extra".to_vec(),
        });
        extra
            .availability
            .sort_unstable_by_key(|blob| blob.reference.clone());
        assert_rejected(extra, InvocationError::InvalidAvailability);
        let mut aliased = clean_resume(&yielded, work.availability.clone());
        aliased.availability[0].bytes[0] ^= 1;
        assert_rejected(aliased, InvocationError::InvalidAvailability);

        let mut ready = clean_resume(&yielded, work.availability.clone());
        ready.input = Some(ResumeInput::Ready(vec![1]));
        assert_rejected(ready, InvocationError::StaleContinuation);
        let mut failed = clean_resume(&yielded, work.availability.clone());
        failed.input = Some(ResumeInput::Failed(7));
        assert_rejected(failed, InvocationError::StaleContinuation);

        let mut divergent = work.clone();
        let mut divergent_message = vec![crate::actors::value::TAG_DYNAMIC];
        divergent_message.extend_from_slice(
            &crate::actors::value::Msg::new("write")
                .with("divergent", crate::actors::value::Value::Bool(true))
                .encode(),
        );
        divergent.message = divergent_message;
        let divergent_authority = clean_authority_receipt(
            clean_sparse_standard_state().config.as_ref().unwrap(),
            &divergent,
        );
        let rejected = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(divergent),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                divergent_authority,
            )),
            observed_slot: 1,
        })
        .unwrap();
        assert_eq!(rejected.state, state);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation))
        );
    }

    #[cfg(feature = "pvm")]
    fn clean_terminal_fixture() -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::authority::AuthorityReceipt,
        crate::agent_sdk::InvocationReply,
    ) {
        clean_terminal_fixture_with_program_size(0)
    }

    #[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
    fn rebind_external_test_runtime(
        seed: &mut StandardRuntimeState,
        admitted: &super::super::package_admission::AdmittedStateRuntimePackage,
    ) {
        for descriptor in [
            &mut seed.clean_descriptor,
            &mut seed.clean_creation_descriptor,
        ] {
            let descriptor = descriptor.as_mut().unwrap();
            descriptor.identity.runtime_deployment = admitted.deployment();
            descriptor.identity.runtime_producer = admitted.manifest().signing.producer;
            descriptor.identity.runtime_program =
                crate::agent_sdk::ProgramId::of_pvm(admitted.program_bytes());
            descriptor.runtime_contract = admitted.manifest().contract.clone();
            descriptor.capabilities = admitted.manifest().capabilities;
            descriptor.runtime_package = admitted.package_ref().clone();
        }
        let descriptor = seed.clean_descriptor.as_ref().unwrap();
        seed.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(descriptor).unwrap());
        seed.active_resource_policy = Some(descriptor.initial_resource_policy());
    }

    #[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
    pub(crate) fn external_invocation_fixture(
        admitted: &super::super::package_admission::AdmittedStateRuntimePackage,
        yielded: bool,
    ) -> crate::agent_sdk::RuntimeWork {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let (runtime, mut work) = clean_policy_fixture_with_storage(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
            crate::agent_sdk::method_policy::AttestationRequirement::None,
            true,
        );
        let key = b"s/rows/value";
        let delta =
            super::super::actor_storage::encode_row_delta(&[(key.to_vec(), Some(vec![7; 8]))])
                .unwrap();
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        let mut output = vec![0; 30];
        output[0] = if yielded {
            crate::actors::STATUS_YIELDED
        } else {
            crate::actors::STATUS_DONE
        };
        output[1..5].copy_from_slice(&1u32.to_le_bytes());
        output[13] = 0xee;
        output.extend_from_slice(&delta);
        let key_at = base + output.len() as u32;
        output.extend_from_slice(key);
        let buffer = base + output.len() as u32;
        output.extend_from_slice(&[0; 8]);
        let mut program = Assembler::new();
        program.set_rw_data(output);
        if yielded {
            program.ecalli(crate::abi::hostcall::SUSPEND);
        }
        program
            .load_imm_64(Reg::A0, key_at as u64)
            .load_imm_64(Reg::A1, key.len() as u64)
            .load_imm_64(Reg::A2, buffer as u64)
            .load_imm_64(Reg::A3, 8)
            .ecalli(crate::abi::hostcall::STORAGE_R)
            .store_u64(Reg::A0, base + 14)
            .load_imm_64(Reg::A0, buffer as u64)
            .load_ind_u64(Reg::A1, Reg::A0, 0)
            .store_u64(Reg::A1, base + 22)
            .load_imm_64(Reg::A0, (base + 30) as u64)
            .load_imm_64(Reg::A1, delta.len() as u64)
            .ecalli(crate::abi::hostcall::ACTOR_EFFECT_EXPORT)
            .load_imm_64(Reg::A0, base as u64)
            .load_imm_64(Reg::A1, if yielded { 14 } else { 30 })
            .jump_ind(Reg::RA, 0);
        let bytes = program.build_standard();
        let blob = work
            .availability
            .iter_mut()
            .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
            .unwrap();
        work.program = crate::agent_sdk::ProgramId::of_pvm(&bytes);
        *blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
            bytes,
        };
        work.availability
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        work.gas = 100_000;
        work.runtime_deployment = admitted.deployment();
        let mut seed = runtime.snapshot();
        rebind_external_test_runtime(&mut seed, admitted);
        seed.actors[0].record.entry.program = crate::service::ProgramId(work.program.0);
        let installation = &mut seed.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.entry.program = work.program;
        installation.commitment = installation.original.lineage_commitment();
        for entry in &mut seed.lane_state.linear {
            entry.rows.clear();
        }
        seed.lane_state.linear[0]
            .rows
            .insert(key.to_vec(), vec![9; 8]);
        let runtime = StandardAgentRuntime::restore(seed).unwrap();
        let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(runtime.config().unwrap(), &work),
        );
        crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: 1,
        }
    }

    #[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
    pub(crate) fn external_test_metadata_only(
        state: &crate::agent_sdk::RuntimeState,
    ) -> crate::agent_sdk::RuntimeState {
        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        for entries in [
            &mut decoded.lane_state.linear,
            &mut decoded.lane_state.merge,
            &mut decoded.lane_state.local,
        ] {
            for entry in entries {
                entry.rows.clear();
            }
        }
        legacy_state_to_clean(encode_standard_runtime_state(&decoded))
    }

    /// Native retained-result seed for physical ACK conformance, not evidence
    /// of an external guest Invoke or authenticated journal genesis.
    #[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
    pub(crate) fn external_retirement_fixture(
        admitted: &super::super::package_admission::AdmittedStateRuntimePackage,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationRetirement,
        crate::agent_sdk::InvocationAuthorization,
    ) {
        let (runtime, mut work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        let mut seed = runtime.snapshot();
        rebind_external_test_runtime(&mut seed, admitted);
        let mut runtime = StandardAgentRuntime::restore(seed).unwrap();
        work.runtime_deployment = admitted.deployment();
        let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(runtime.config().unwrap(), &work),
        );
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa1]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        (
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            crate::agent_sdk::InvocationRetirement::from_work(&work),
            authorization,
        )
    }

    /// A valid retained-result ACK predecessor close to the signed external
    /// metadata ceiling. Historical lane images are reachable through normal
    /// actor removal and remain authenticated until explicit compaction; they
    /// must not make retirement of an unrelated live result unpublishable.
    #[cfg(all(feature = "std", feature = "experimental-state-blocks"))]
    pub(crate) fn external_retirement_fixture_near_state_limit(
        admitted: &super::super::package_admission::AdmittedStateRuntimePackage,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationRetirement,
        crate::agent_sdk::InvocationAuthorization,
    ) {
        use super::super::standard::{StandardAgentRuntime, StandardLaneEntry};
        let (state, retirement, authorization) = external_retirement_fixture(admitted);
        let mut snapshot = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        let ceiling = admitted
            .manifest()
            .contract
            .resources
            .max_runtime_state_bytes as usize;
        assert_eq!(
            ceiling,
            crate::agent_sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES
        );
        let target = ceiling - 16 * 1024;
        for index in 0u16..128 {
            let current = legacy_state_to_clean(encode_standard_runtime_state(&snapshot))
                .encoded_len()
                .unwrap();
            if current >= target {
                break;
            }
            let mut actor = [0u8; 32];
            actor[0] = 0xfe;
            actor[1..3].copy_from_slice(&index.to_be_bytes());
            let actor = super::ActorId(actor);
            assert!(
                snapshot
                    .actors
                    .iter()
                    .all(|entry| entry.record.entry.actor != actor)
            );
            snapshot.lane_state.linear.push(StandardLaneEntry {
                actor,
                state_generation: super::Hash([0x7c; 32]),
                value: vec![0x5a; (target - current).min(32 * 1024)],
                rows: Default::default(),
            });
            snapshot
                .lane_state
                .linear
                .sort_unstable_by_key(|entry| (entry.actor, entry.state_generation));
            snapshot.lane_revisions.linear = snapshot.lane_revisions.linear.max(1);
        }
        let runtime = StandardAgentRuntime::restore(snapshot).unwrap();
        let state = legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()));
        let bytes = state.encoded_len().unwrap();
        assert!(bytes >= ceiling - 48 * 1024, "state only {bytes} bytes");
        assert!(bytes <= ceiling, "state exceeds signed ceiling: {bytes}");
        eprintln!("near-ceiling external ACK predecessor metadata_bytes={bytes}");
        (state, retirement, authorization)
    }

    #[cfg(feature = "pvm")]
    fn clean_terminal_fixture_with_program_size(
        program_size: usize,
    ) -> (
        crate::agent_sdk::RuntimeState,
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::authority::AuthorityReceipt,
        crate::agent_sdk::InvocationReply,
    ) {
        let (mut runtime, mut work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        if program_size != 0 {
            // ACK consumes a retained result and never executes these
            // synthetic program bytes. Application attachments have a
            // separate smaller size limit; model the installed program here.
            let program = work
                .availability
                .iter_mut()
                .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
                .unwrap();
            let bytes = vec![0xa7; program_size];
            work.program = crate::agent_sdk::ProgramId::of_pvm(&bytes);
            *program = crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
                bytes,
            };
            work.availability
                .sort_by(|a, b| a.reference.cmp(&b.reference));
            let mut state = runtime.snapshot();
            state.actors[0].record.entry.program = crate::service::ProgramId(work.program.0);
            runtime = StandardAgentRuntime::restore(state).unwrap();
        }
        let authority = clean_authority_receipt(runtime.config().unwrap(), &work);
        let authorization =
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority.clone());
        runtime
            .validate_clean_unseen_invocation_slot(&authorization, 1)
            .unwrap();
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa1]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        (
            legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            work,
            authority,
            clean_reply(reply),
        )
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn required_attested_result_is_directly_acknowledged_only_by_its_exact_binding() {
        use crate::agent::transition_proof_host::AuthenticatedAttestedTransition;
        use crate::agent_sdk::{
            InvocationAcknowledgement, InvocationAuthorization, InvocationError, PublicPreflight,
            RuntimeExecutionContext, RuntimeOutcome, RuntimeWork,
        };

        let proof_system = crate::agent_sdk::Hash([0xe1; 32]);
        let (retained_state, work, authorization) = completed_clean_policy_fixture(proof_system);
        let route = attested_test_route(&retained_state, &work, proof_system);
        let attested_retry = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Attested { proof_system },
            state: retained_state,
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 9,
        };
        let authenticated = AuthenticatedAttestedTransition::authenticate_for_test(
            &route,
            &attested_retry,
            attested_test_admission(&route, &attested_retry, "write"),
        )
        .unwrap();
        let delivered =
            apply_authenticated_attested_standard_runtime_work(&authenticated, attested_retry)
                .unwrap();
        assert!(matches!(
            delivered.outcome,
            RuntimeOutcome::Completed(Ok(_))
        ));
        let state = delivered.state;
        let expected = InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: work.commitment(),
            authorization: authorization.commitment(),
        };
        let exact = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        })
        .unwrap();
        assert_eq!(
            exact.outcome,
            RuntimeOutcome::Acknowledged(Ok(expected)),
            "Direct acknowledgement retires retained Required work without re-executing its method",
        );
        assert!(
            decode_standard_runtime_state(&clean_state_to_legacy(&exact.state))
                .unwrap()
                .invocation_results
                .is_empty(),
        );

        let assert_ack_error = |work: crate::agent_sdk::InvocationWork,
                                authorization: InvocationAuthorization,
                                expected: InvocationError| {
            let rejected = apply_standard_runtime_work(RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Direct,
                state: state.clone(),
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
                authorization: Box::new(authorization),
            })
            .unwrap();
            assert_eq!(rejected.state, state);
            assert_eq!(
                rejected.outcome,
                RuntimeOutcome::Acknowledged(Err(expected)),
            );
        };

        let mut substituted_work = work.clone();
        substituted_work.gas += 1;
        assert_ack_error(
            substituted_work,
            authorization.clone(),
            InvocationError::InvalidAuthorization,
        );
        let InvocationAuthorization::PublicPreflight(original_preflight) = authorization.clone()
        else {
            unreachable!()
        };
        assert_ack_error(
            work.clone(),
            InvocationAuthorization::PublicPreflight(PublicPreflight {
                observed_slot: original_preflight.observed_slot + 1,
                ..original_preflight
            }),
            InvocationError::InvalidAuthorization,
        );
        assert_eq!(
            apply_standard_runtime_work(RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Attested { proof_system },
                state,
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
                authorization: Box::new(authorization),
            }),
            Err(DecodeError::NonCanonical),
            "Acknowledge has no attested execution route",
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn acknowledgement_slot_recheck_matches_full_authorization_verification() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        let (receipt_state, receipt_work, receipt, _) = clean_terminal_fixture();
        let receipt_authorization = InvocationAuthorization::AuthorityReceipt(receipt);
        let (preflight_state, preflight_work, preflight_authorization) =
            completed_clean_policy_fixture(crate::agent_sdk::Hash([0xe1; 32]));
        for (state, work, authorization) in [
            (receipt_state, receipt_work, receipt_authorization),
            (preflight_state, preflight_work, preflight_authorization),
        ] {
            let runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
            )
            .unwrap();
            let initial_slot = match &authorization {
                InvocationAuthorization::AuthorityReceipt(_) => 0,
                InvocationAuthorization::PublicPreflight(preflight) => preflight.observed_slot,
            };
            runtime
                .verify_clean_invocation_authorization(&work, &authorization, initial_slot)
                .unwrap();
            for slot in [
                0,
                initial_slot.saturating_sub(1),
                initial_slot,
                initial_slot.saturating_add(1),
                u64::MAX,
            ] {
                let rechecked = if authorization.matches_invoke(&work, slot) {
                    Ok(())
                } else {
                    Err(InvocationError::InvalidAuthorization)
                };
                assert_eq!(
                    runtime.verify_clean_invocation_authorization(&work, &authorization, slot),
                    rechecked,
                    "slot-only recheck must match full validation after immutable admission",
                );
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_acknowledgement_status_preserves_exact_retry_and_rejection() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        let (state, work, receipt, _) = clean_terminal_fixture_with_program_size(4096);
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        let mut runtime = StandardAgentRuntime::restore(decoded).unwrap();
        let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
        let before = encode_standard_runtime_state(&runtime.snapshot());
        let mut corrupted_blob = work.clone();
        corrupted_blob.availability[0].bytes[0] ^= 1;
        assert_eq!(
            runtime.acknowledge_clean_invocation_with_status(&corrupted_blob, &authorization),
            Err(InvocationError::InvalidAuthorization),
            "fresh ACK must authenticate preimages even when their references are unchanged",
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);
        let mut bad_signature = authorization.clone();
        let InvocationAuthorization::AuthorityReceipt(receipt) = &mut bad_signature else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;
        assert_eq!(
            runtime.acknowledge_clean_invocation_with_status(&work, &bad_signature),
            Err(InvocationError::InvalidAuthorization),
            "validated work does not authenticate the receipt signature",
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);
        let (acknowledgement, applied) = runtime
            .acknowledge_clean_invocation_with_status(&work, &authorization)
            .unwrap();
        assert!(applied);
        let after = encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(
            runtime.acknowledge_clean_invocation_with_status(&work, &authorization),
            Ok((acknowledgement, false)),
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), after);

        let mut substituted = work.clone();
        substituted.message.push(0xff);
        assert_eq!(
            runtime.acknowledge_clean_invocation_with_status(&substituted, &authorization),
            Err(InvocationError::InvalidAuthorization),
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), after);
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "fixed-work CPU profiling probe; runs the same validated ACK eight times"]
    fn profile_bundled_runtime_large_acknowledgement() {
        for _ in 0..8 {
            bundled_runtime_large_acknowledgement_validation_cost();
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_invoke_recovery_validation_preserves_rejection_and_retirement() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        let (state, work, receipt, _) = clean_terminal_fixture_with_program_size(4096);
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
        let mut corrupted = work.clone();
        corrupted.availability[0].bytes[0] ^= 1;
        let mut substituted = work.clone();
        substituted.message.push(0xff);
        let mut forged = authorization.clone();
        let InvocationAuthorization::AuthorityReceipt(receipt) = &mut forged else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;

        for retired in [false, true] {
            if retired {
                runtime
                    .acknowledge_clean_invocation(&work, &authorization)
                    .unwrap();
            }
            let before = encode_standard_runtime_state(&runtime.snapshot());
            for (input, auth) in [
                (&corrupted, &authorization),
                (&substituted, &authorization),
                (&work, &forged),
            ] {
                assert_eq!(
                    runtime.recover_clean_execution(input, auth, 1).map(|_| ()),
                    Err(InvocationError::InvalidAuthorization),
                );
                assert_eq!(
                    runtime.recover_clean_invocation_error(input, auth, 1),
                    Err(InvocationError::InvalidAuthorization),
                );
                assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);
            }
            if retired {
                assert_eq!(
                    runtime
                        .recover_clean_execution(&work, &authorization, 1)
                        .map(|_| ()),
                    Err(InvocationError::DivergentInvocation),
                );
                assert_eq!(
                    runtime.recover_clean_invocation_error(&work, &authorization, 1),
                    Err(InvocationError::DivergentInvocation),
                );
                assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);
            } else {
                assert!(
                    runtime
                        .recover_clean_execution(&work, &authorization, 1)
                        .unwrap()
                        .is_some()
                );
                assert_eq!(
                    runtime.recover_clean_invocation_error(&work, &authorization, 1),
                    Ok(None)
                );
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn decoded_runtime_input_preserves_fresh_retry_ack_and_retired_transitions() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{RuntimeOutcome, RuntimeWork};

        let fresh = clean_actor_fixture_with_padding(Some(crate::actors::STATUS_DONE), 4096);
        let mut attested = fresh.clone();
        if let RuntimeWork::Invoke { context, .. } = &mut attested {
            *context = crate::agent_sdk::RuntimeExecutionContext::Attested {
                proof_system: crate::agent_sdk::Hash([0xb9; 32]),
            };
        }
        assert_eq!(
            apply_standard_runtime_input(&attested.encode().unwrap()),
            Err(DecodeError::NonCanonical),
            "native callers cannot use decoded input as attested admission",
        );
        let compare = |work: &RuntimeWork| {
            let expected = apply_standard_runtime_work(work.clone()).unwrap();
            let actual = apply_standard_runtime_input(&work.encode().unwrap()).unwrap();
            assert_eq!(actual.encode().unwrap(), expected.encode().unwrap());
            actual
        };
        let completed = compare(&fresh);
        assert!(matches!(
            completed.outcome,
            RuntimeOutcome::Completed(Ok(_))
        ));
        let RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            observed_slot,
            ..
        } = fresh
        else {
            unreachable!()
        };
        let retry = RuntimeWork::Invoke {
            context,
            state: completed.state.clone(),
            invocation: invocation.clone(),
            authorization: authorization.clone(),
            observed_slot,
        };
        compare(&retry);
        let mut ack = RuntimeWork::Acknowledge {
            context,
            state: completed.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization,
        };
        let retired = compare(&ack);
        assert!(matches!(
            retired.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let RuntimeWork::Acknowledge { state, .. } = &mut ack else {
            unreachable!()
        };
        *state = retired.state.clone();
        compare(&ack);
        // Rebuild with the retired state: Invoke must remain divergent, not
        // execute a second time just because decode supplied validation.
        let mut retired_invoke = retry;
        if let RuntimeWork::Invoke { state, .. } = &mut retired_invoke {
            *state = retired.state;
        }
        assert!(matches!(
            compare(&retired_invoke).outcome,
            RuntimeOutcome::Completed(Err(_))
        ));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn decoded_runtime_input_rejects_corruption_and_still_authenticates_receipts() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext, RuntimeWork};

        let (state, invocation, receipt, _) = clean_terminal_fixture_with_program_size(4096);
        for acknowledge in [false, true] {
            let authorization =
                Box::new(InvocationAuthorization::AuthorityReceipt(receipt.clone()));
            let work = if acknowledge {
                RuntimeWork::Acknowledge {
                    context: RuntimeExecutionContext::Direct,
                    state: state.clone(),
                    invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                        &invocation,
                    )),
                    authorization,
                }
            } else {
                RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: state.clone(),
                    invocation: Box::new(invocation.clone()),
                    authorization,
                    observed_slot: 1,
                }
            };
            let input = work.encode().unwrap();
            let largest = invocation
                .availability
                .iter()
                .max_by_key(|blob| blob.bytes.len())
                .unwrap();
            let transported = if acknowledge {
                assert!(
                    !input
                        .windows(largest.bytes.len())
                        .any(|bytes| bytes == largest.bytes)
                );
                largest.reference.hash.as_bytes().as_slice()
            } else {
                largest.bytes.as_slice()
            };
            let offset = input
                .windows(transported.len())
                .position(|bytes| bytes == transported)
                .unwrap();
            let mut corrupt = input.clone();
            corrupt[offset] ^= 1;
            assert!(apply_standard_runtime_input(&corrupt).is_err());
            assert!(apply_standard_runtime_input(&input[..input.len() - 1]).is_err());
            let mut trailing = input;
            trailing.push(0);
            assert!(apply_standard_runtime_input(&trailing).is_err());

            let mut forged = work.clone();
            let (RuntimeWork::Invoke { authorization, .. }
            | RuntimeWork::Acknowledge { authorization, .. }) = &mut forged
            else {
                unreachable!()
            };
            let InvocationAuthorization::AuthorityReceipt(receipt) = authorization.as_mut() else {
                unreachable!()
            };
            receipt.signature[0] ^= 1;
            let expected = apply_standard_runtime_work(forged.clone()).unwrap();
            let actual = apply_standard_runtime_input(&forged.encode().unwrap()).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual.state, state);
            assert!(matches!(
                actual.outcome,
                crate::agent_sdk::RuntimeOutcome::Completed(Err(_))
                    | crate::agent_sdk::RuntimeOutcome::Acknowledged(Err(_))
            ));
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_public_preflight_matching_cost() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, PublicPreflight, RuntimeOutcome, RuntimeTransition,
            RuntimeWork,
        };

        let mut fresh = clean_actor_fixture_with_padding(Some(crate::actors::STATUS_DONE), 4096);
        let RuntimeWork::Invoke {
            invocation,
            authorization,
            observed_slot,
            ..
        } = &mut fresh
        else {
            unreachable!()
        };
        invocation.origin.capability = None;
        invocation.roles = crate::agent_sdk::InvocationRoleClaims::none();
        *authorization = Box::new(InvocationAuthorization::PublicPreflight(
            PublicPreflight::for_work(invocation, *observed_slot),
        ));
        let completed = apply_standard_runtime_work(fresh.clone()).unwrap();
        assert!(matches!(
            completed.outcome,
            RuntimeOutcome::Completed(Ok(_))
        ));
        let RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            ..
        } = fresh.clone()
        else {
            unreachable!()
        };
        let ack = RuntimeWork::Acknowledge {
            context,
            state: completed.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization,
        };
        let mut programs = vec![(
            "bundled",
            include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec(),
        )];
        if let Some(path) = std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE") {
            programs.push(("candidate", std::fs::read(path).unwrap()));
        }
        for (operation, work) in [("invoke", fresh), ("ack", ack)] {
            let expected = apply_standard_runtime_work(work.clone()).unwrap();
            if operation == "ack" {
                assert!(matches!(
                    expected.outcome,
                    RuntimeOutcome::Acknowledged(Ok(_))
                ));
            }
            let input = work.encode().unwrap();
            let mut baseline_gas = None;
            for (label, program) in &programs {
                let execution =
                    vos_pvm::refine_host::RefineContext::load(program, &input, 2_000_000_000)
                        .unwrap()
                        .run();
                assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
                assert_eq!(
                    execution
                        .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                        .unwrap(),
                    expected.encode().unwrap(),
                    "{label} {operation} changed exact transition bytes",
                );
                eprintln!(
                    "public-preflight operation={operation} label={label} gas_used={}",
                    execution.gas_used
                );
                if let Some(prior) = baseline_gas {
                    assert!(
                        execution.gas_used < prior,
                        "candidate must reduce deterministic gas"
                    );
                } else {
                    baseline_gas = Some(execution.gas_used);
                }
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_large_fresh_invoke_validation_cost() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationStatus, RuntimeOutcome, RuntimeTransition, RuntimeWork};

        // A real, tiny actor with inert read-only padding exercises fresh
        // validation and execution, not a retained reply or malformed program.
        let work = clean_actor_fixture_with_padding(Some(crate::actors::STATUS_DONE), 768 * 1024);
        let RuntimeWork::Invoke { state, .. } = &work else {
            unreachable!()
        };
        let before = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        assert!(before.invocation_results.is_empty());
        let expected = apply_standard_runtime_work(work.clone()).unwrap();
        let RuntimeOutcome::Completed(Ok(reply)) = &expected.outcome else {
            panic!("fresh invocation did not succeed: {:?}", expected.outcome);
        };
        assert_eq!(reply.status, InvocationStatus::Done);
        let after = decode_standard_runtime_state(&clean_state_to_legacy(&expected.state)).unwrap();
        assert_eq!(after.invocation_results.len(), 1);
        assert_ne!(after.lane_state, before.lane_state);
        let expected_bytes = expected.encode().unwrap();
        let input = work.encode().unwrap();
        let mut programs = vec![(
            "bundled",
            include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec(),
        )];
        if let Some(path) = std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE") {
            programs.push(("candidate", std::fs::read(path).unwrap()));
        }
        let mut baseline_gas = None;
        for (label, program) in programs {
            let started = std::time::Instant::now();
            let execution =
                vos_pvm::refine_host::RefineContext::load(&program, &input, 2_000_000_000)
                    .unwrap()
                    .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            assert_eq!(
                output, expected_bytes,
                "entire fresh transition must match source"
            );
            eprintln!(
                "large-fresh-invoke label={label} input_bytes={} gas_used={} elapsed_us={}",
                input.len(),
                execution.gas_used,
                started.elapsed().as_micros()
            );
            if let Some(prior_gas) = baseline_gas {
                assert!(
                    execution.gas_used < prior_gas,
                    "candidate must reduce deterministic gas"
                );
            } else {
                baseline_gas = Some(execution.gas_used);
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_large_invoke_retry_validation_cost() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, RuntimeExecutionContext, RuntimeOutcome, RuntimeTransition,
            RuntimeWork,
        };

        // A retained result isolates outer-runtime validation/recovery from
        // actor execution. This is not fresh actor execution throughput.
        let (state, work, receipt, reply) = clean_terminal_fixture_with_program_size(768 * 1024);
        let input = RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(work),
            authorization: Box::new(InvocationAuthorization::AuthorityReceipt(receipt)),
            observed_slot: 1,
        }
        .encode()
        .unwrap();
        let mut programs = vec![(
            "bundled",
            include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec(),
        )];
        if let Some(path) = std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE") {
            programs.push(("candidate", std::fs::read(path).unwrap()));
        }
        let mut baseline = None;
        for (label, program) in programs {
            let started = std::time::Instant::now();
            let execution =
                vos_pvm::refine_host::RefineContext::load(&program, &input, 2_000_000_000)
                    .unwrap()
                    .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            let transition = RuntimeTransition::decode(&output).unwrap();
            assert_eq!(
                transition.outcome,
                RuntimeOutcome::Completed(Ok(reply.clone()))
            );
            eprintln!(
                "large-invoke-retry label={label} input_bytes={} gas_used={} elapsed_us={}",
                input.len(),
                execution.gas_used,
                started.elapsed().as_micros()
            );
            if let Some((prior_output, prior_gas)) = &baseline {
                assert_eq!(&output, prior_output);
                assert!(
                    execution.gas_used < *prior_gas,
                    "candidate must reduce deterministic gas"
                );
            } else {
                baseline = Some((output, execution.gas_used));
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_large_acknowledgement_validation_cost() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, RuntimeExecutionContext, RuntimeOutcome, RuntimeTransition,
            RuntimeWork,
        };
        let (state, work, receipt, _) = clean_terminal_fixture_with_program_size(768 * 1024);
        let input = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(InvocationAuthorization::AuthorityReceipt(receipt)),
        }
        .encode()
        .unwrap();
        let mut programs = vec![(
            "bundled",
            include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec(),
        )];
        if let Some(path) = std::env::var_os("VOS_AGENT_RUNTIME_COST_CANDIDATE") {
            programs.push(("candidate", std::fs::read(path).unwrap()));
        }
        let mut baseline = None;
        for (label, program) in programs {
            let started = std::time::Instant::now();
            let execution =
                vos_pvm::refine_host::RefineContext::load(&program, &input, 2_000_000_000)
                    .unwrap()
                    .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            let transition = RuntimeTransition::decode(&output).unwrap();
            assert!(matches!(
                transition.outcome,
                RuntimeOutcome::Acknowledged(Ok(_))
            ));
            eprintln!(
                "large-ack label={label} input_bytes={} gas_used={} elapsed_us={}",
                input.len(),
                execution.gas_used,
                started.elapsed().as_micros()
            );
            if let Some((prior_output, prior_gas)) = &baseline {
                assert_eq!(&output, prior_output);
                assert!(
                    execution.gas_used < *prior_gas,
                    "candidate must reduce deterministic gas"
                );
            } else {
                baseline = Some((output, execution.gas_used));
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_rejects_retired_invocation_without_reexecution() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, RuntimeExecutionContext, RuntimeOutcome,
            RuntimeTransition, RuntimeWork,
        };

        let candidate = std::env::var_os("VOS_AGENT_RUNTIME_ACK_CANDIDATE")
            .map(|path| std::fs::read(path).expect("read acknowledgement candidate"));
        let run = |work: RuntimeWork| {
            let input = work.encode().unwrap();
            let execution = vos_pvm::refine_host::RefineContext::load(
                candidate
                    .as_deref()
                    .unwrap_or(include_bytes!("../../../vosx/blobs/agent_runtime.pvm")),
                &input,
                1_000_000_000,
            )
            .unwrap()
            .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            RuntimeTransition::decode(&output).unwrap()
        };
        let (state, work, receipt, reply) = clean_terminal_fixture();
        let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
        let retried = run(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: state.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 1,
        });
        assert_eq!(retried.outcome, RuntimeOutcome::Completed(Ok(reply)));
        let acknowledged = run(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: retried.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        });
        assert!(matches!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        // Each run loads a new physical VM from the committed artifact. The
        // guest must recover its retirement fact solely from serialized state.
        for observed_slot in [1, 99] {
            let replayed = run(RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: acknowledged.state.clone(),
                invocation: Box::new(work.clone()),
                authorization: Box::new(authorization.clone()),
                observed_slot,
            });
            assert_eq!(replayed.state, acknowledged.state);
            assert_eq!(
                replayed.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation))
            );
        }
        let repeated_ack = run(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: acknowledged.state.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization),
        });
        assert_eq!(repeated_ack, acknowledged);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_acknowledgement_rejects_malformed_frames() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext, RuntimeWork};

        let candidate = std::env::var_os("VOS_AGENT_RUNTIME_ACK_CANDIDATE")
            .map(|path| std::fs::read(path).expect("read acknowledgement candidate"));
        let program = candidate
            .as_deref()
            .unwrap_or(include_bytes!("../../../vosx/blobs/agent_runtime.pvm"));
        let (state, work, receipt, _) = clean_terminal_fixture();
        let input = RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(InvocationAuthorization::AuthorityReceipt(receipt)),
        }
        .encode()
        .unwrap();
        let valid = vos_pvm::refine_host::RefineContext::load(program, &input, 2_000_000_000)
            .unwrap()
            .run();
        assert_eq!(valid.exit, vos_pvm::ExitReason::Halt);
        let mut trailing = input.clone();
        trailing.push(0);
        for malformed in [&input[..input.len() - 1], trailing.as_slice()] {
            assert!(RuntimeWork::decode(malformed).is_err());
            let execution =
                vos_pvm::refine_host::RefineContext::load(program, malformed, 2_000_000_000)
                    .unwrap()
                    .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Panic);
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_runtime_terminal_failure_lifecycle_matches_source() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            RuntimeExecutionContext, RuntimeOutcome, RuntimeTransition, RuntimeWork,
        };
        let program = match std::env::var_os("VOS_AGENT_RUNTIME_FAILURE_CANDIDATE") {
            Some(path) => std::fs::read(path).unwrap(),
            None => include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec(),
        };
        let execute = |work: RuntimeWork| {
            let expected = apply_standard_runtime_work(work.clone()).unwrap();
            let input = work.encode().unwrap();
            let execution = vos_pvm::refine_host::RefineContext::load(
                &program,
                &input,
                super::super::driver::DEFAULT_MANAGEMENT_GAS,
            )
            .unwrap()
            .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            assert_eq!(
                output,
                expected.encode().unwrap(),
                "physical guest must match the entire source transition"
            );
            eprintln!(
                "failure-lifecycle input_bytes={} gas_used={}",
                input.len(),
                execution.gas_used
            );
            RuntimeTransition::decode(&output).unwrap()
        };
        let cases = [
            clean_failing_actor_fixture(Some(crate::actors::STATUS_FORBIDDEN)),
            clean_failing_actor_fixture(Some(crate::actors::STATUS_PANICKED)),
            clean_failing_actor_fixture(Some(crate::actors::STATUS_OOG)),
            clean_failing_actor_fixture(None),
            clean_failing_resume_fixture(),
        ];
        for work in cases {
            let (invocation, authorization) = match &work {
                RuntimeWork::Invoke {
                    invocation,
                    authorization,
                    ..
                } => ((**invocation).clone(), (**authorization).clone()),
                RuntimeWork::Resume { state, resume, .. } => {
                    let runtime = StandardAgentRuntime::restore(
                        decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap(),
                    )
                    .unwrap();
                    let (record, invocation) = runtime.resolve_clean_resume(resume).unwrap();
                    (invocation, record.authorization.unwrap())
                }
                _ => unreachable!(),
            };
            let first = execute(work);
            assert!(matches!(first.outcome, RuntimeOutcome::Completed(Ok(_))));
            let reopened = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&first.state)).unwrap(),
            )
            .unwrap();
            let retry = execute(RuntimeWork::Invoke {
                context: RuntimeExecutionContext::Direct,
                state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
                invocation: Box::new(invocation.clone()),
                authorization: Box::new(authorization.clone()),
                observed_slot: 99,
            });
            assert_eq!(retry.outcome, first.outcome);
            let ack_work = RuntimeWork::Acknowledge {
                context: RuntimeExecutionContext::Direct,
                state: retry.state,
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                    &invocation,
                )),
                authorization: Box::new(authorization),
            };
            let ack = execute(ack_work.clone());
            assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
            let RuntimeWork::Acknowledge {
                context,
                invocation,
                authorization,
                ..
            } = ack_work
            else {
                unreachable!()
            };
            let repeated = execute(RuntimeWork::Acknowledge {
                context,
                state: ack.state.clone(),
                invocation,
                authorization,
            });
            assert_eq!(repeated, ack);
        }
    }

    #[cfg(feature = "pvm")]
    fn assert_typed_error_retirement(stale_target: bool, bundled: bool) {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAcknowledgement, InvocationAuthorization, InvocationError, RuntimeOutcome,
            RuntimeTransition, RuntimeWork,
        };
        let mut work = clean_failing_actor_fixture(Some(0xff));
        let RuntimeWork::Invoke {
            state,
            invocation,
            authorization,
            ..
        } = &mut work
        else {
            unreachable!()
        };
        let before = decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap();
        if stale_target {
            invocation.incarnation = crate::agent_sdk::Hash([0x91; 32]);
            *authorization = Box::new(InvocationAuthorization::AuthorityReceipt(
                clean_authority_receipt(before.config.as_ref().unwrap(), invocation),
            ));
        }
        let expected_ack = InvocationAcknowledgement {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            work: invocation.commitment(),
            authorization: authorization.commitment(),
        };
        let execute = |work: &RuntimeWork| {
            if !bundled {
                return apply_standard_runtime_work(work.clone()).unwrap();
            }
            let candidate = std::env::var_os("VOS_AGENT_RUNTIME_TYPED_ERROR_CANDIDATE")
                .map(|path| std::fs::read(path).expect("read typed-error runtime candidate"));
            let execution = vos_pvm::refine_host::RefineContext::load(
                candidate
                    .as_deref()
                    .unwrap_or(include_bytes!("../../../vosx/blobs/agent_runtime.pvm")),
                &work.encode().unwrap(),
                super::super::driver::DEFAULT_MANAGEMENT_GAS,
            )
            .unwrap()
            .run();
            assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
            let output = execution
                .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                .unwrap();
            assert_eq!(
                output,
                apply_standard_runtime_work(work.clone())
                    .unwrap()
                    .encode()
                    .unwrap()
            );
            RuntimeTransition::decode(&output).unwrap()
        };
        let failed = execute(&work);
        assert_eq!(
            failed.outcome,
            RuntimeOutcome::Completed(Err(if stale_target {
                InvocationError::StaleIncarnation
            } else {
                InvocationError::InvalidActorOutput
            }))
        );
        let restored = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&failed.state)).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.snapshot().lane_state, before.lane_state);
        let RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            ..
        } = work
        else {
            unreachable!()
        };
        let acknowledged = execute(&RuntimeWork::Acknowledge {
            context,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization,
            state: legacy_state_to_clean(encode_standard_runtime_state(&restored.snapshot())),
        });
        assert_eq!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(expected_ack)),
            "durable typed errors need guest-owned exact retirement after restore"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_typed_error_invalid_output_requires_retirement() {
        assert_typed_error_retirement(false, true);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_typed_error_stale_target_requires_retirement() {
        assert_typed_error_retirement(true, true);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn bundled_unseen_expired_invocation_preserves_state_after_restore() {
        for missing_availability in [false, true] {
            assert_unseen_expired_invocation_retirement(true, missing_availability);
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn source_unseen_expired_invocation_retires_after_restore() {
        for missing_availability in [false, true] {
            assert_unseen_expired_invocation_retirement(false, missing_availability);
        }
    }

    #[cfg(feature = "pvm")]
    fn assert_unseen_expired_invocation_retirement(bundled: bool, missing_availability: bool) {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, RuntimeOutcome, RuntimeTransition,
            RuntimeWork,
        };
        let mut work = clean_failing_actor_fixture(Some(0xff));
        let candidate = std::env::var_os("VOS_AGENT_RUNTIME_EXPIRY_CANDIDATE")
            .map(|path| std::fs::read(path).unwrap());
        let runtime_pvm = candidate
            .as_deref()
            .unwrap_or(include_bytes!("../../../vosx/blobs/agent_runtime.pvm"));
        let execute = |work: RuntimeWork| {
            let expected = apply_standard_runtime_work(work.clone()).unwrap();
            if bundled {
                let execution = vos_pvm::refine_host::RefineContext::load(
                    runtime_pvm,
                    &work.encode().unwrap(),
                    super::super::driver::DEFAULT_MANAGEMENT_GAS,
                )
                .unwrap()
                .run();
                assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
                assert_eq!(
                    execution
                        .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                        .unwrap(),
                    expected.encode().unwrap()
                );
            }
            expected
        };
        let RuntimeWork::Invoke {
            authorization,
            observed_slot,
            state,
            invocation,
            ..
        } = &mut work
        else {
            unreachable!()
        };
        if missing_availability {
            invocation.availability.clear();
            let runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap(),
            )
            .unwrap();
            **authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
                runtime.config().unwrap(),
                invocation,
            ));
        }
        let InvocationAuthorization::AuthorityReceipt(receipt) = authorization.as_ref() else {
            unreachable!()
        };
        *observed_slot = receipt.selector.expires_at.checked_add(1).unwrap();
        for _ in 0..2 {
            let RuntimeWork::Invoke { state: prior, .. } = &work else {
                unreachable!()
            };
            let before = decode_standard_runtime_state(&clean_state_to_legacy(prior)).unwrap();
            let expected = execute(work.clone());
            assert_eq!(
                expected.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::ExpiredBeforeExecution))
            );
            assert!(!InvocationError::AuthorityExpired.is_durable_exact_outcome());
            let restored = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&expected.state)).unwrap(),
            )
            .unwrap();
            assert!(restored.snapshot().invocation_results.is_empty());
            assert_eq!(restored.snapshot().clean_invocation_errors.len(), 1);
            assert_eq!(restored.snapshot().lane_state, before.lane_state);
            let revisions = restored.snapshot().lane_revisions;
            assert_eq!(revisions.linear, before.lane_revisions.linear);
            assert_eq!(revisions.merge, before.lane_revisions.merge);
            assert_eq!(revisions.local, before.lane_revisions.local);
            let RuntimeWork::Invoke { state, .. } = &mut work else {
                unreachable!()
            };
            *state = legacy_state_to_clean(encode_standard_runtime_state(&restored.snapshot()));
        }
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            ..
        } = work.clone()
        else {
            unreachable!()
        };
        let ack = execute(RuntimeWork::Acknowledge {
            context,
            state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization,
        });
        assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
        let restored = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&ack.state)).unwrap(),
        )
        .unwrap();
        assert!(restored.snapshot().clean_invocation_errors.is_empty());
        let RuntimeWork::Invoke {
            state,
            observed_slot,
            ..
        } = &mut work
        else {
            unreachable!()
        };
        *state = legacy_state_to_clean(encode_standard_runtime_state(&restored.snapshot()));
        *observed_slot = 1;
        let late = execute(work);
        assert_eq!(late.state, ack.state);
        assert_eq!(
            late.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation))
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_expiry_fence_survives_restore_and_positive_retirement() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError, RuntimeWork};
        let RuntimeWork::Invoke {
            state,
            invocation,
            authorization,
            ..
        } = clean_failing_actor_fixture(Some(0xff))
        else {
            unreachable!()
        };
        let InvocationAuthorization::AuthorityReceipt(receipt) = authorization.as_ref() else {
            unreachable!()
        };
        let expired_slot = receipt.selector.expires_at.checked_add(1).unwrap();
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let before = runtime.snapshot();
        let error = InvocationError::ExpiredBeforeExecution;
        assert!(error.is_durable_exact_outcome());
        assert!(!InvocationError::AuthorityExpired.is_durable_exact_outcome());
        assert_eq!(
            runtime.retain_clean_invocation_error(
                &invocation,
                &authorization,
                error,
                receipt.selector.expires_at,
                None,
            ),
            Err(InvocationError::AuthorityExpired)
        );
        let mut corrupt_authorization = (*authorization).clone();
        let InvocationAuthorization::AuthorityReceipt(corrupt) = &mut corrupt_authorization else {
            unreachable!()
        };
        corrupt.signature[0] ^= 1;
        assert_eq!(
            runtime.retain_clean_invocation_error(
                &invocation,
                &corrupt_authorization,
                error,
                expired_slot,
                None,
            ),
            Err(InvocationError::InvalidAuthorization)
        );
        assert_eq!(runtime.snapshot(), before);
        runtime
            .retain_clean_invocation_error(&invocation, &authorization, error, expired_slot, None)
            .unwrap();
        let retained = runtime.snapshot();
        assert_only_result_component_changed(
            &encode_standard_runtime_state(&before),
            &encode_standard_runtime_state(&retained),
            clean_mode_as_legacy_for_test(invocation.mode),
        );
        assert!(retained.invocation_results.is_empty());
        assert_eq!(retained.clean_invocation_errors.len(), 1);
        let mut corrupt = retained.clone();
        corrupt.clean_invocation_errors[0].binding.observed_slot = receipt.selector.expires_at;
        assert!(StandardAgentRuntime::restore(corrupt).is_err());
        let mut corrupt = retained.clone();
        corrupt.clean_invocation_errors[0].error = InvocationError::InvalidActorOutput;
        assert!(StandardAgentRuntime::restore(corrupt).is_err());
        let mut reopened = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&encode_standard_runtime_state(&retained)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened.recover_clean_invocation_error(&invocation, &authorization, expired_slot,),
            Ok(Some(error))
        );
        assert_eq!(
            reopened.recover_clean_invocation_error(
                &invocation,
                &authorization,
                receipt.selector.expires_at,
            ),
            Err(InvocationError::DivergentInvocation)
        );
        let ack = reopened
            .acknowledge_clean_invocation(&invocation, &authorization)
            .unwrap();
        assert_eq!(ack.work, invocation.commitment());
        assert_eq!(ack.authorization, authorization.commitment());
        let mut retired = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&encode_standard_runtime_state(&reopened.snapshot()))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            retired.acknowledge_clean_invocation(&invocation, &authorization),
            Ok(ack)
        );
        assert_eq!(
            retired.recover_clean_invocation_error(&invocation, &authorization, expired_slot + 1,),
            Err(InvocationError::DivergentInvocation)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_expiry_fence_rejects_clock_regression_and_shared_capacity_exhaustion() {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, PublicPreflight, RuntimeWork,
        };
        let RuntimeWork::Invoke {
            state,
            mut invocation,
            authorization,
            ..
        } = clean_failing_actor_fixture(None)
        else {
            unreachable!()
        };
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let before = runtime.snapshot();
        let error = InvocationError::ExpiredBeforeExecution;
        let public =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 3));
        assert_eq!(
            runtime.retain_clean_invocation_error(&invocation, &public, error, 3, None,),
            Err(InvocationError::AuthorityExpired)
        );
        assert_eq!(runtime.snapshot(), before);
        runtime
            .retain_clean_invocation_error(&invocation, &authorization, error, 4, None)
            .unwrap();
        let retained = runtime.snapshot();
        invocation.invocation = crate::agent_sdk::InvocationId([0xa0; 32]);
        let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
            runtime.config().unwrap(),
            &invocation,
        ));
        assert_eq!(
            runtime.retain_clean_invocation_error(&invocation, &authorization, error, 3, None,),
            Err(InvocationError::AuthoritySlotRegressed)
        );
        assert_eq!(runtime.snapshot(), retained);
        for index in 1..super::super::standard::MAX_INVOCATION_RESULTS_PER_LANE {
            invocation.invocation = crate::agent_sdk::InvocationId([0x60 + index as u8; 32]);
            let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
                runtime.config().unwrap(),
                &invocation,
            ));
            runtime
                .retain_clean_invocation_error(&invocation, &authorization, error, 4, None)
                .unwrap();
        }
        let full = runtime.snapshot();
        invocation.invocation = crate::agent_sdk::InvocationId([0xa0; 32]);
        assert_eq!(
            runtime.retain_clean_invocation_error(&invocation, &authorization, error, 4, None,),
            Err(InvocationError::ResultCapacity)
        );
        assert_eq!(runtime.snapshot(), full);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_expiry_fence_cannot_replace_accepted_continuation() {
        use crate::agent_sdk::{InvocationError, RuntimeWork};
        let RuntimeWork::Resume { state, resume, .. } = clean_failing_resume_fixture() else {
            unreachable!()
        };
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let (record, invocation) = runtime.resolve_clean_resume(&resume).unwrap();
        let authorization = record.authorization.unwrap();
        let before = runtime.snapshot();
        for terminal in [None, Some(record.ready_sequence)] {
            assert_eq!(
                runtime.retain_clean_invocation_error(
                    &invocation,
                    &authorization,
                    InvocationError::ExpiredBeforeExecution,
                    99,
                    terminal,
                ),
                Err(InvocationError::StaleContinuation)
            );
            assert_eq!(runtime.snapshot(), before);
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn source_typed_error_retirement() {
        assert_typed_error_retirement(false, false);
        assert_typed_error_retirement(true, false);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_invoke_recovery_authentication_rejects_substitution_without_mutation() {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, RuntimeOutcome, RuntimeWork,
        };
        for mutation in 0..3 {
            let mut input = clean_failing_actor_fixture(Some(0xff));
            let RuntimeWork::Invoke {
                state,
                invocation,
                authorization,
                observed_slot,
                ..
            } = &mut input
            else {
                unreachable!()
            };
            let before = state.clone();
            match mutation {
                0 => {
                    let InvocationAuthorization::AuthorityReceipt(receipt) = authorization.as_mut()
                    else {
                        unreachable!()
                    };
                    receipt.signature[0] ^= 1;
                }
                1 => invocation.space.0[0] ^= 1,
                2 => invocation.availability[0].bytes[0] ^= 1,
                _ => unreachable!(),
            }
            let runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                runtime.verify_clean_invocation_authorization(
                    invocation,
                    authorization,
                    *observed_slot
                ),
                Err(InvocationError::InvalidAuthorization)
            );
            let returned = apply_standard_runtime_work(input).unwrap();
            assert_eq!(returned.state, before);
            assert_eq!(
                returned.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn unsupported_method_is_retained_and_acknowledged_without_actor_writes() {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, PublicPreflight, RuntimeExecutionContext,
            RuntimeOutcome, RuntimeWork,
        };
        let (runtime, mut invocation) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        invocation.message = vec![0xff];
        let authorization =
            InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&invocation, 1));
        let before = runtime.snapshot();
        let failed = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&before)),
            invocation: Box::new(invocation.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 1,
        })
        .unwrap();
        assert_eq!(
            failed.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::UnsupportedMethod))
        );
        let retained =
            decode_standard_runtime_state(&clean_state_to_legacy(&failed.state)).unwrap();
        assert_eq!(retained.clean_invocation_errors.len(), 1);
        assert_eq!(retained.lane_state, before.lane_state);
        let reopened = StandardAgentRuntime::restore(retained).unwrap();
        let ack = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &invocation,
            )),
            authorization: Box::new(authorization),
        })
        .unwrap();
        assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_typed_error_ledger_round_trips_and_retires_stale_work() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError, RuntimeWork};
        for (mode, error) in [
            (
                crate::agent_sdk::MethodMode::Query,
                InvocationError::StaleIncarnation,
            ),
            (
                crate::agent_sdk::MethodMode::Linear,
                InvocationError::InvalidActorOutput,
            ),
        ] {
            let RuntimeWork::Invoke {
                state,
                mut invocation,
                ..
            } = clean_failing_actor_fixture(None)
            else {
                unreachable!()
            };
            let mut runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
            )
            .unwrap();
            invocation.mode = mode;
            if error == InvocationError::StaleIncarnation {
                invocation.incarnation = crate::agent_sdk::Hash([0x91; 32]);
            }
            let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
                runtime.config().unwrap(),
                &invocation,
            ));
            let before = runtime.snapshot();
            runtime
                .retain_clean_invocation_error(&invocation, &authorization, error, 1, None)
                .unwrap();
            let retained = runtime.snapshot();
            assert_eq!(retained.clean_invocation_errors.len(), 1);
            assert_eq!(retained.lane_state, before.lane_state);
            assert_eq!(retained.lane_revisions.linear, before.lane_revisions.linear);
            assert_only_result_component_changed(
                &encode_standard_runtime_state(&before),
                &encode_standard_runtime_state(&retained),
                clean_mode_as_legacy_for_test(mode),
            );
            let encoded = encode_standard_runtime_state(&retained);
            let decoded = decode_standard_runtime_state(&encoded).unwrap();
            assert_eq!(decoded, retained);
            let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
            #[cfg(feature = "experimental-state-blocks")]
            assert_eq!(
                reopened.inspect_clean_retained_terminal(
                    &crate::agent_sdk::InvocationRetirement::from_work(&invocation),
                    &authorization,
                    99,
                ),
                Ok(Some(
                    super::super::standard::RetainedCleanTerminal::Completed(Err(error),)
                )),
                "a durable guest rejection is distinct from an unseen input",
            );
            assert_eq!(
                reopened.recover_clean_invocation_error(&invocation, &authorization, 99),
                Ok(Some(error))
            );
            let mut different = (*invocation).clone();
            different.message.push(0xff);
            let before_rejection = reopened.snapshot();
            assert!(
                reopened
                    .acknowledge_clean_invocation(&different, &authorization)
                    .is_err()
            );
            assert_eq!(reopened.snapshot(), before_rejection);
            let ack = reopened
                .acknowledge_clean_invocation(&invocation, &authorization)
                .unwrap();
            assert_eq!(ack.work, invocation.commitment());
            assert!(reopened.snapshot().clean_invocation_errors.is_empty());
            let mut restarted = StandardAgentRuntime::restore(reopened.snapshot()).unwrap();
            assert_eq!(
                restarted.acknowledge_clean_invocation(&invocation, &authorization),
                Ok(ack)
            );
            assert_eq!(
                restarted.recover_clean_invocation_error(&invocation, &authorization, 99),
                Err(InvocationError::DivergentInvocation)
            );
            let mut corrupt = retained.clone();
            corrupt.clean_invocation_errors[0].error = InvocationError::ResultCapacity;
            assert!(
                decode_standard_runtime_state(&encode_standard_runtime_state(&corrupt)).is_err()
            );
            let mut corrupt = retained.clone();
            corrupt.clean_invocation_errors[0].binding.work = crate::agent_sdk::Hash([0xff; 32]);
            assert!(StandardAgentRuntime::restore(corrupt).is_err());
            let mut conflicting = retained;
            conflicting.clean_invocation_acknowledgements.push(ack);
            assert!(StandardAgentRuntime::restore(conflicting).is_err());
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_mode_as_legacy_for_test(mode: crate::agent_sdk::MethodMode) -> MethodMode {
        match mode {
            crate::agent_sdk::MethodMode::Query => MethodMode::Query,
            crate::agent_sdk::MethodMode::Linear => MethodMode::Linear,
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_typed_error_ledger_is_bounded_and_failed_admission_is_atomic() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError, RuntimeWork};
        let RuntimeWork::Invoke {
            state,
            mut invocation,
            ..
        } = clean_failing_actor_fixture(None)
        else {
            unreachable!()
        };
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
            runtime.config().unwrap(),
            &invocation,
        ));
        let before = runtime.snapshot();
        assert_eq!(
            runtime.retain_clean_invocation_error(
                &invocation,
                &authorization,
                InvocationError::ResultCapacity,
                1,
                None
            ),
            Err(InvocationError::InvalidInput)
        );
        assert!(
            runtime
                .retain_clean_invocation_error(
                    &invocation,
                    &authorization,
                    InvocationError::InvalidActorOutput,
                    1,
                    Some(999)
                )
                .is_err()
        );
        assert_eq!(runtime.snapshot(), before);
        for index in 0..super::super::standard::MAX_INVOCATION_RESULTS_PER_LANE {
            invocation.invocation = crate::agent_sdk::InvocationId([0x60 + index as u8; 32]);
            let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
                runtime.config().unwrap(),
                &invocation,
            ));
            runtime
                .retain_clean_invocation_error(
                    &invocation,
                    &authorization,
                    InvocationError::InvalidActorOutput,
                    1,
                    None,
                )
                .unwrap();
        }
        let retained = runtime.snapshot();
        invocation.invocation = crate::agent_sdk::InvocationId([0xa0; 32]);
        let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
            runtime.config().unwrap(),
            &invocation,
        ));
        assert_eq!(
            runtime.retain_clean_invocation_error(
                &invocation,
                &authorization,
                InvocationError::InvalidActorOutput,
                1,
                None
            ),
            Err(InvocationError::ResultCapacity)
        );
        assert_eq!(runtime.snapshot(), retained);
        let mut reopened = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&encode_standard_runtime_state(&retained)).unwrap(),
        )
        .unwrap();
        let (resolved, ..) = reopened.resolve_clean_invocation(&invocation).unwrap();
        assert_eq!(
            reopened.prepare_execution_state(&resolved),
            Err(ActorExecutionError::ResultCapacity)
        );
        let before = StandardAgentRuntime::restore(before)
            .unwrap()
            .prepare_execution_state(&resolved)
            .unwrap();
        let mut reply = exact_reply(&resolved, ActorExecutionStatus::Done);
        assert_eq!(
            reopened.commit_clean_execution(
                &invocation,
                &authorization,
                &resolved,
                &mut reply,
                &before,
                before.clone(),
                1,
                None
            ),
            Err(ActorExecutionError::ResultCapacity)
        );
        assert_eq!(
            reopened.snapshot(),
            retained,
            "errors and actor replies share the result budget"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_typed_error_ledger_consumes_resumed_work_and_rejects_noncanonical_sections() {
        use crate::agent_sdk::{InvocationError, RuntimeWork};
        let RuntimeWork::Resume { state, resume, .. } = clean_failing_resume_fixture() else {
            unreachable!()
        };
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let (record, work) = runtime.resolve_clean_resume(&resume).unwrap();
        let authorization = record.authorization.unwrap();
        let before = runtime.snapshot();
        assert!(
            runtime
                .retain_clean_invocation_error(
                    &work,
                    &authorization,
                    InvocationError::InvalidActorOutput,
                    record.observed_slot,
                    None
                )
                .is_err()
        );
        assert_eq!(runtime.snapshot(), before);
        runtime
            .retain_clean_invocation_error(
                &work,
                &authorization,
                InvocationError::InvalidActorOutput,
                record.observed_slot,
                Some(record.ready_sequence),
            )
            .unwrap();
        let retained = runtime.snapshot();
        assert_eq!(retained.lane_state, before.lane_state);
        assert!(retained.machine_continuations.is_empty());
        let mut reopened = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&encode_standard_runtime_state(&retained)).unwrap(),
        )
        .unwrap();
        reopened
            .acknowledge_clean_invocation(&work, &authorization)
            .unwrap();
        assert!(reopened.snapshot().clean_invocation_errors.is_empty());

        let mut overlap = retained.clone();
        overlap.machine_continuations = before.machine_continuations;
        assert!(StandardAgentRuntime::restore(overlap).is_err());
        let mut duplicate = retained.clone();
        duplicate
            .clean_invocation_errors
            .push(retained.clean_invocation_errors[0].clone());
        assert!(decode_standard_runtime_state(&encode_standard_runtime_state(&duplicate)).is_err());
        let mut section = Vec::new();
        encode_clean_invocation_errors(
            &mut Encoder(&mut section),
            &retained,
            super::super::InvocationResultStorage::Lane(StateLane::Linear),
        );
        assert!(
            decode_clean_invocation_errors(
                &mut Decoder::new(&section),
                super::super::InvocationResultStorage::Control
            )
            .is_err()
        );
        section[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert!(
            decode_clean_invocation_errors(
                &mut Decoder::new(&section),
                super::super::InvocationResultStorage::Lane(StateLane::Linear)
            )
            .is_err()
        );
        let mut empty = STANDARD_CLEAN_INVOCATION_ERRORS_MAGIC.to_vec();
        let mut encoder = Encoder(&mut empty);
        encoder.u16(1);
        encoder.list::<u8>(&[], |encoder, value| encoder.u8(*value));
        assert!(
            decode_clean_invocation_errors(
                &mut Decoder::new(&empty),
                super::super::InvocationResultStorage::Control
            )
            .is_err(),
            "empty ledgers have only the absent-section encoding"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_terminal_failure_retention_survives_restart_and_exact_acknowledgement() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        for status in [
            ActorExecutionStatus::Forbidden,
            ActorExecutionStatus::Panicked,
            ActorExecutionStatus::OutOfGas,
        ] {
            let (mut runtime, work) = clean_policy_fixture(
                crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
            );
            let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
                runtime.config().unwrap(),
                &work,
            ));
            let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
            let reply = exact_reply(&invocation, status);
            let before = runtime.snapshot();
            runtime
                .retain_clean_terminal_failure(&work, &authorization, &invocation, &reply, 1, None)
                .unwrap();
            let retained = runtime.snapshot();
            assert_eq!(retained.lane_state, before.lane_state);
            assert_eq!(
                (
                    retained.lane_revisions.linear,
                    retained.lane_revisions.merge,
                    retained.lane_revisions.local
                ),
                (
                    before.lane_revisions.linear,
                    before.lane_revisions.merge,
                    before.lane_revisions.local
                ),
                "a failed slice never commits actor writes or revisions"
            );
            assert_only_result_component_changed(
                &encode_standard_runtime_state(&before),
                &encode_standard_runtime_state(&retained),
                invocation.mode,
            );
            let mut runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(&encode_standard_runtime_state(&retained)).unwrap(),
            )
            .unwrap();
            assert_eq!(runtime.snapshot(), retained);
            assert_eq!(
                runtime
                    .recover_clean_execution(&work, &authorization, 99)
                    .unwrap(),
                Some(reply),
                "the exact failure remains recoverable after receipt expiry"
            );

            let mut divergent = work.clone();
            divergent.message.push(0xff);
            let before_rejected_ack = runtime.snapshot();
            assert!(
                runtime
                    .acknowledge_clean_invocation(&divergent, &authorization)
                    .is_err()
            );
            assert_eq!(runtime.snapshot(), before_rejected_ack);

            let ack = runtime
                .acknowledge_clean_invocation(&work, &authorization)
                .unwrap();
            assert!(runtime.snapshot().invocation_results.is_empty());
            let mut reopened = StandardAgentRuntime::restore(runtime.snapshot()).unwrap();
            assert_eq!(
                reopened.acknowledge_clean_invocation(&work, &authorization),
                Ok(ack)
            );
            assert_eq!(
                reopened.recover_clean_execution(&work, &authorization, 99),
                Err(InvocationError::DivergentInvocation),
                "acknowledgement never permits re-execution of failed work"
            );

            let mut unbound = retained.clone();
            unbound.invocation_results[0].clean = None;
            assert!(StandardAgentRuntime::restore(unbound).is_err());
            let mut yielded = retained;
            yielded.invocation_results[0].reply.status = ActorExecutionStatus::Yielded;
            assert!(StandardAgentRuntime::restore(yielded).is_err());
        }
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn clean_failing_actor_fixture(status: Option<u8>) -> crate::agent_sdk::RuntimeWork {
        clean_actor_fixture_with_padding(status, 0)
    }

    #[cfg(feature = "pvm")]
    fn clean_actor_fixture_with_padding(
        status: Option<u8>,
        padding_bytes: usize,
    ) -> crate::agent_sdk::RuntimeWork {
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let (runtime, mut work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        let mut program = Assembler::new();
        program.set_ro_data(vec![0xa7; padding_bytes]);
        let zone = u64::from(vos_pvm::PVM_ZONE_SIZE);
        let output_address = 2 * zone + (padding_bytes as u64).div_ceil(zone) * zone;
        if let Some(status) = status {
            let mut output = vec![0; 14];
            output[0] = status;
            output[1..5].copy_from_slice(&1_u32.to_le_bytes());
            output[13] = 0xee; // Only a successful actor may commit this lane image.
            program
                .set_rw_data(output)
                .load_imm_64(Reg::A0, output_address)
                .load_imm_64(Reg::A1, 14)
                .jump_ind(Reg::RA, 0);
        } else {
            program.trap();
        }
        let bytes = program.build_standard();
        let blob = work
            .availability
            .iter_mut()
            .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
            .unwrap();
        work.program = crate::agent_sdk::ProgramId::of_pvm(&bytes);
        *blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
            bytes,
        };
        work.availability
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        work.gas = 100_000;
        let mut state = runtime.snapshot();
        state.actors[0].record.entry.program = crate::service::ProgramId(work.program.0);
        let record = &state.actors[0].record;
        let installation = &mut state.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.entry =
            super::super::standard::legacy_actor_record_to_clean(record, installation.commitment)
                .entry;
        installation.commitment = installation.original.lineage_commitment();
        let runtime = StandardAgentRuntime::restore(state).unwrap();
        let authority = clean_authority_receipt(runtime.config().unwrap(), &work);
        crate::agent_sdk::RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            invocation: Box::new(work),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority,
            )),
            observed_slot: 1,
        }
    }

    #[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
    #[test]
    fn clean_external_storage_uses_installed_identity_schema_and_scope() {
        use super::super::actor_storage::{ActorRowStorage, tests::TestBlocks};
        use crate::agent_sdk::{
            method_policy::{AttestationRequirement, AuthorizationPolicySelector},
            state_blocks::{BlockRef, BlockScope, ReadBudget},
            state_rows::ActorRows,
            state_tree::{BlockReader, StateTree, TreeError, WriteBudget},
        };
        struct Observed {
            reads: alloc::rc::Rc<core::cell::Cell<usize>>,
            blocks: TestBlocks,
        }
        impl BlockReader for Observed {
            fn read(&mut self, reference: BlockRef, bytes: &mut [u8]) -> Result<bool, TreeError> {
                self.reads.set(self.reads.get() + 1);
                self.blocks.read(reference, bytes)
            }
        }
        let (mut runtime, work) = clean_policy_fixture_with_storage(
            AuthorizationPolicySelector::Public,
            AttestationRequirement::None,
            true,
        );
        let (_, _, schema, _, _) = runtime.resolve_clean_invocation(&work).unwrap();
        let scope = BlockScope::new(
            work.space,
            work.agent,
            crate::agent_sdk::Hash([7; 32]),
            crate::agent_sdk::StateLane::Linear,
        )
        .unwrap();
        let mut blocks = TestBlocks::default();
        let batch = ActorRows::new(StateTree::empty(scope), work.actor, work.incarnation)
            .unwrap()
            .update_accounted_batch(
                &[(b"s/rows/value".to_vec(), Some(vec![9]))],
                crate::agent_sdk::contract::ExternalStateResourceLimits {
                    max_rows_per_lane: 100,
                    max_row_bytes_per_lane: 100000,
                },
                &mut blocks,
                &mut ReadBudget::new(100, 100000),
                &mut WriteBudget::new(100, 100000),
            )
            .unwrap();
        let tree = batch.update.tree;
        for (reference, bytes) in batch.update.blocks {
            blocks.blocks.insert(reference.hash().0, bytes);
        }
        let reads = alloc::rc::Rc::new(core::cell::Cell::new(0));
        let lanes = |tree| {
            [
                Some((
                    tree,
                    Observed {
                        reads: reads.clone(),
                        blocks: blocks.clone(),
                    },
                )),
                None,
                None,
            ]
        };
        for field in 0..8 {
            let mut bad = work.clone();
            match field {
                0 => bad.space.0[0] ^= 1,
                1 => bad.agent.0[0] ^= 1,
                2 => bad.runtime_deployment.0[0] ^= 1,
                3 => bad.actor.0[0] ^= 1,
                4 => bad.incarnation.0[0] ^= 1,
                5 => bad.deployment.0[0] ^= 1,
                6 => bad.program.0[0] ^= 1,
                _ => bad.mode = crate::agent_sdk::MethodMode::Query,
            }
            assert!(
                runtime
                    .resolve_clean_external_storage_reader(
                        &bad,
                        &schema,
                        lanes(tree),
                        &mut ReadBudget::new(100, 100000)
                    )
                    .is_err()
            );
        }
        let mut bad_schema = schema.clone();
        bad_schema.bytes.push(0);
        assert!(
            runtime
                .resolve_clean_external_storage_reader(
                    &work,
                    &bad_schema,
                    lanes(tree),
                    &mut ReadBudget::new(100, 100000)
                )
                .is_err()
        );
        let alien = StateTree::empty(
            BlockScope::new(
                crate::agent_sdk::SpaceId([0xf1; 32]),
                work.agent,
                crate::agent_sdk::Hash([7; 32]),
                crate::agent_sdk::StateLane::Linear,
            )
            .unwrap(),
        );
        assert!(
            runtime
                .resolve_clean_external_storage_reader(
                    &work,
                    &schema,
                    lanes(alien),
                    &mut ReadBudget::new(100, 100000)
                )
                .is_err()
        );
        assert_eq!(reads.get(), 0);
        let mut budget = ReadBudget::new(100, 100000);
        let reader = runtime
            .resolve_clean_external_storage_reader(&work, &schema, lanes(tree), &mut budget)
            .unwrap();
        assert!(reader.read(b"undeclared/value").is_err());
        assert_eq!(reads.get(), 0);
        assert_eq!(
            reader.read(b"s/rows/value").unwrap().as_deref(),
            Some(&[9][..])
        );
        assert!(reads.get() > 0);
        drop(reader);
        assert!(!runtime.has_image_rows());
        runtime
            .commit_clean_row_batch(
                &work,
                &schema,
                vec![],
                vec![(b"s/rows/legacy".to_vec(), Some(vec![1]))],
                |_| Ok(()),
            )
            .unwrap();
        let before = reads.get();
        assert!(runtime.has_image_rows());
        assert!(
            runtime
                .resolve_clean_external_storage_reader(&work, &schema, lanes(tree), &mut budget)
                .is_err()
        );
        assert_eq!(reads.get(), before);
    }

    #[cfg(all(feature = "pvm", feature = "experimental-state-blocks"))]
    #[test]
    fn clean_external_rows_metadata_and_exact_result_form_one_candidate() {
        use super::super::actor_storage::tests::TestBlocks;
        use crate::agent_sdk::MAX_RUNTIME_STATE_BYTES;
        use crate::agent_sdk::{
            method_policy::{AttestationRequirement, AuthorizationPolicySelector},
            state_blocks::{BlockScope, ReadBudget},
            state_metadata::{RuntimeMetadataUpdate, read_runtime_metadata},
            state_rows::{ActorRows, RowUsage, lane_row_usage},
            state_tree::{StateTree, WriteBudget},
        };
        let (pristine, work) = clean_policy_fixture_with_storage(
            AuthorizationPolicySelector::Public,
            AttestationRequirement::None,
            true,
        );
        let (invocation, _, schema, _, _) = pristine.resolve_clean_invocation(&work).unwrap();
        let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(pristine.config().unwrap(), &work),
        );
        let before = pristine.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa1]);
        let encoded = encode_standard_runtime_state(&pristine.snapshot());
        let scope = BlockScope::new(
            work.space,
            work.agent,
            crate::agent_sdk::Hash([7; 32]),
            crate::agent_sdk::StateLane::Linear,
        )
        .unwrap();
        let limits = crate::agent_sdk::contract::ExternalStateResourceLimits {
            max_rows_per_lane: 10,
            max_row_bytes_per_lane: 100,
        };
        let mut blocks = TestBlocks::default();
        let seed = ActorRows::new(StateTree::empty(scope), work.actor, work.incarnation)
            .unwrap()
            .update_accounted_with_metadata(
                &[],
                limits,
                RuntimeMetadataUpdate::new(&encoded.linear, MAX_RUNTIME_STATE_BYTES).unwrap(),
                &mut blocks,
                (
                    &mut ReadBudget::new(1000, 1000000),
                    &mut WriteBudget::new(1000, 1000000),
                ),
            )
            .unwrap();
        let base = seed.update.tree;
        for (reference, bytes) in seed.update.blocks {
            blocks.blocks.insert(reference.hash().0, bytes);
        }
        let snapshot = blocks.blocks.clone();
        let changes = vec![(b"s/rows/value".to_vec(), Some(vec![9]))];
        let commit = |candidate: &mut StandardAgentRuntime| {
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            candidate.commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after.clone(),
                1,
                None,
            )?;
            Ok(reply)
        };
        let (candidate, update, _) = pristine
            .prepare_clean_external_row_batch(
                &work,
                &schema,
                &changes,
                limits,
                [Some((base, blocks.clone())), None, None],
                (
                    &mut ReadBudget::new(1000, 1000000),
                    &mut WriteBudget::new(1000, 1000000),
                ),
                &commit,
            )
            .unwrap();
        assert_eq!(blocks.blocks, snapshot);
        assert_eq!(encode_standard_runtime_state(&pristine.snapshot()), encoded);
        let context = crate::agent_sdk::state_root::RootContext::new(
            scope,
            crate::agent_sdk::Hash([8; 32]),
            crate::agent_sdk::Hash([9; 32]),
        )
        .unwrap();
        let descriptor =
            crate::agent_sdk::state_root::StateRootDescriptor::new(context, base.root());
        let tree = update.tree;
        let change = crate::agent_sdk::state_change::StateChange::from_update(
            descriptor.commitment(),
            context,
            update,
        )
        .unwrap();
        change
            .verify_reuse(
                descriptor,
                context,
                &mut blocks,
                &mut ReadBudget::new(1000, 1000000),
            )
            .unwrap();
        for (reference, bytes) in change.blocks() {
            blocks.blocks.insert(reference.hash().0, bytes.clone());
        }
        let metadata = read_runtime_metadata(
            tree,
            MAX_RUNTIME_STATE_BYTES,
            &mut blocks,
            &mut ReadBudget::new(1000, 1000000),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            metadata,
            encode_standard_runtime_state(&candidate.snapshot()).linear
        );
        let mut restored = encoded.clone();
        restored.linear = metadata;
        let mut reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&restored).unwrap())
                .unwrap();
        assert_eq!(reopened.snapshot(), candidate.snapshot());
        assert!(
            reopened
                .recover_clean_execution(&work, &authorization, 1)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            lane_row_usage(tree, &mut blocks, &mut ReadBudget::new(1000, 1000000)).unwrap(),
            RowUsage { rows: 1, bytes: 13 }
        );
        assert_eq!(
            ActorRows::new(tree, work.actor, work.incarnation)
                .unwrap()
                .get(
                    b"s/rows/value",
                    &mut blocks,
                    &mut ReadBudget::new(1000, 1000000)
                )
                .unwrap(),
            Some(vec![9])
        );
        for late in [false, true] {
            assert!(
                pristine
                    .prepare_clean_external_row_batch(
                        &work,
                        &schema,
                        &changes,
                        limits,
                        [Some((base, blocks.clone())), None, None],
                        (
                            &mut ReadBudget::new(1000, 1000000),
                            &mut WriteBudget::new(0, 0)
                        ),
                        |candidate| {
                            let reply = commit(candidate)?;
                            if late {
                                Err(ActorExecutionError::ResultCapacity)
                            } else {
                                Ok(reply)
                            }
                        },
                    )
                    .is_err()
            );
            assert_eq!(encode_standard_runtime_state(&pristine.snapshot()), encoded);
        }
        let wrong = ActorRows::new(StateTree::empty(scope), work.actor, work.incarnation)
            .unwrap()
            .update_accounted_with_metadata(
                &[],
                limits,
                RuntimeMetadataUpdate::new(b"other runtime metadata", MAX_RUNTIME_STATE_BYTES)
                    .unwrap(),
                &mut blocks,
                (
                    &mut ReadBudget::new(1000, 1000000),
                    &mut WriteBudget::new(1000, 1000000),
                ),
            )
            .unwrap();
        let wrong_tree = wrong.update.tree;
        for (reference, bytes) in wrong.update.blocks {
            blocks.blocks.insert(reference.hash().0, bytes);
        }
        assert!(
            pristine
                .prepare_clean_external_row_batch(
                    &work,
                    &schema,
                    &changes,
                    limits,
                    [Some((wrong_tree, blocks.clone())), None, None],
                    (
                        &mut ReadBudget::new(1000, 1000000),
                        &mut WriteBudget::new(1000, 1000000)
                    ),
                    |_| -> Result<(), ActorExecutionError> {
                        panic!("mismatched metadata reached commit")
                    },
                )
                .is_err()
        );
        assert!(
            pristine
                .prepare_clean_external_row_batch(
                    &work,
                    &schema,
                    &[(b"undeclared/row".to_vec(), None)],
                    limits,
                    [Some((base, blocks)), None, None],
                    (
                        &mut ReadBudget::new(1000, 1000000),
                        &mut WriteBudget::new(1000, 1000000)
                    ),
                    |_| -> Result<(), ActorExecutionError> {
                        panic!("unauthorized namespace reached commit")
                    },
                )
                .is_err()
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_row_batch_commits_with_result_and_rolls_back_late_failures() {
        use crate::agent_sdk::method_policy::{
            AttestationRequirement, AuthorizationPolicySelector,
        };
        let (pristine, work) = clean_policy_fixture_with_storage(
            AuthorizationPolicySelector::Public,
            AttestationRequirement::None,
            true,
        );
        let (invocation, _, schema, _, _) = pristine.resolve_clean_invocation(&work).unwrap();
        let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(pristine.config().unwrap(), &work),
        );
        let before = pristine.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xa1]);
        let row = vec![0x74; crate::actors::storage::MAX_VALUE_BYTES];
        let changes = || vec![(b"s/rows/value".to_vec(), Some(row.clone()))];
        let commit = |candidate: &mut StandardAgentRuntime| {
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            candidate.commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after.clone(),
                1,
                None,
            )?;
            Ok(reply)
        };
        let mut runtime = pristine.clone();
        let reply = runtime
            .commit_clean_row_batch(&work, &schema, vec![0xa1], changes(), &commit)
            .unwrap();
        assert_eq!(reply.status, ActorExecutionStatus::Done);
        assert_eq!(runtime.snapshot().invocation_results.len(), 1);
        assert_eq!(runtime.snapshot().lane_state.linear[0].value, vec![0xa1]);
        assert_eq!(
            runtime
                .resolve_clean_storage_reader(&work, &schema)
                .unwrap()
                .read(b"s/rows/value"),
            Ok(Some(row.as_slice()))
        );
        let encoded = encode_standard_runtime_state(&runtime.snapshot());
        let reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&encoded).unwrap())
                .unwrap();
        assert!(reopened.snapshot() == runtime.snapshot());

        // A late refusal after the result was staged must roll back both.
        let mut runtime = pristine.clone();
        let failed =
            runtime.commit_clean_row_batch(&work, &schema, vec![0xa1], changes(), |candidate| {
                commit(candidate)?;
                Err::<(), _>(ActorExecutionError::ResultCapacity)
            });
        assert_eq!(failed, Err(ActorExecutionError::ResultCapacity));
        assert!(runtime.snapshot() == pristine.snapshot());

        // Namespace rejection occurs before the terminal transition runs.
        let failed = runtime.commit_clean_row_batch(
            &work,
            &schema,
            vec![0xa1],
            vec![
                (b"s/rows/value".to_vec(), Some(vec![1])),
                (b"undeclared/value".to_vec(), None),
            ],
            |_candidate| -> Result<(), ActorExecutionError> {
                panic!("invalid delta reached commit")
            },
        );
        assert_eq!(failed, Err(ActorExecutionError::InvalidActorOutput));
        assert!(runtime.snapshot() == pristine.snapshot());

        // A coherently constrained descriptor admits existing state, but not
        // row plus result. This is a fixture, not a live policy mutation.
        let mut limited = pristine.snapshot();
        let limit = encode_standard_runtime_state(&limited)
            .encoded_len()
            .unwrap();
        let descriptor = limited.clean_descriptor.as_mut().unwrap();
        descriptor
            .runtime_contract
            .resources
            .max_runtime_state_bytes = limit as u32;
        limited.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(descriptor).unwrap());
        limited.active_resource_policy = Some(descriptor.initial_resource_policy());
        let mut runtime = StandardAgentRuntime::restore(limited).unwrap();
        let limited_before = runtime.snapshot();
        assert_eq!(
            runtime
                .commit_clean_row_batch(&work, &schema, vec![0xa1], changes(), &commit)
                .err(),
            Some(ActorExecutionError::ResultCapacity)
        );
        assert!(
            runtime.snapshot() == limited_before,
            "resource refusal must retain neither rows nor result"
        );

        let mut runtime = pristine.clone();
        runtime
            .commit_clean_row_batch(&work, &schema, vec![0xa1], changes(), |candidate| {
                candidate.commit_yielded_execution(
                    &invocation,
                    &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                    &before,
                    after.clone(),
                    1,
                    None,
                    portable_continuation(&invocation, 1, 3).continuation,
                    Some((
                        super::super::standard::StandardAcceptedInvocation::from_work(&work),
                        authorization.clone(),
                    )),
                )
            })
            .unwrap();
        let yielded = runtime.snapshot();
        assert_eq!(yielded.machine_continuations.len(), 1);
        assert!(yielded.invocation_results.is_empty());
        assert_eq!(
            yielded.lane_state.linear[0]
                .rows
                .get(b"s/rows/value".as_slice()),
            Some(&row)
        );
        let mut resumed = StandardAgentRuntime::restore(yielded.clone()).unwrap();
        let sequence = yielded.machine_continuations[0].ready_sequence;
        let before_resume = resumed.prepare_execution_state(&invocation).unwrap();
        let mut after_resume = before_resume.clone();
        after_resume.linear = Some(vec![0xa2]);
        let complete = |candidate: &mut StandardAgentRuntime| {
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            candidate.commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before_resume,
                after_resume.clone(),
                2,
                Some(sequence),
            )?;
            Ok(reply)
        };
        let replacement = || vec![(b"s/rows/value".to_vec(), Some(vec![0x75; row.len()]))];
        assert_eq!(
            resumed.commit_clean_row_batch(
                &work,
                &schema,
                vec![0xa2],
                replacement(),
                |candidate| {
                    complete(candidate)?;
                    Err::<(), _>(ActorExecutionError::ResultCapacity)
                }
            ),
            Err(ActorExecutionError::ResultCapacity)
        );
        assert!(
            resumed.snapshot() == yielded,
            "a refused terminal slice must preserve its continuation and rows"
        );
        resumed
            .commit_clean_row_batch(&work, &schema, vec![0xa2], replacement(), complete)
            .unwrap();
        let completed = resumed.snapshot();
        assert!(completed.machine_continuations.is_empty());
        assert_eq!(completed.invocation_results.len(), 1);
        assert_eq!(completed.lane_state.linear[0].value, vec![0xa2]);
        assert_eq!(
            completed.lane_state.linear[0]
                .rows
                .get(b"s/rows/value".as_slice())
                .unwrap(),
            &vec![0x75; row.len()]
        );
        assert!(
            StandardAgentRuntime::restore(completed.clone())
                .unwrap()
                .snapshot()
                == completed
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_dispatch_reads_persisted_rows_and_retains_exact_result_after_restore() {
        clean_storage_dispatch_fixture(false, crate::actors::STATUS_DONE, None, 0);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_dispatch_commits_exported_rows_only_for_successful_actor_output() {
        for status in [
            crate::actors::STATUS_DONE,
            crate::actors::STATUS_PANICKED,
            crate::actors::STATUS_FORBIDDEN,
            crate::actors::STATUS_OOG,
        ] {
            clean_storage_dispatch_fixture(true, status, None, 0);
        }
    }

    #[cfg(feature = "pvm")]
    fn clean_availability_work(size: usize) -> crate::agent_sdk::RuntimeWork {
        use crate::agent_sdk::method_policy::AuthorizationPolicySelector;
        use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext, RuntimeWork};
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let (runtime, mut work) = clean_policy_fixture(AuthorizationPolicySelector::Public);
        let mut payload = vec![0x61; size];
        payload[size - 8..].fill(0x7b);
        let reference = crate::agent_sdk::BlobRef::of_bytes(&payload);
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        let mut data = vec![0; 30];
        data[0] = crate::actors::STATUS_DONE;
        data[1..5].copy_from_slice(&1u32.to_le_bytes());
        data[13] = 0xee;
        data.extend_from_slice(&reference.hash.0);
        let buffer = base + data.len() as u32;
        data.resize(data.len() + size, 0);
        let mut program = Assembler::new();
        program
            .set_rw_data(data)
            .load_imm_64(Reg::A0, u64::from(base + 30))
            .load_imm_64(Reg::A1, u64::from(buffer))
            .load_imm_64(Reg::A2, size as u64)
            .ecalli(crate::abi::hostcall::PREIMAGE_LOOKUP)
            .store_u64(Reg::A0, base + 14)
            .load_imm_64(Reg::A0, u64::from(buffer) + size as u64 - 8)
            .load_ind_u64(Reg::A1, Reg::A0, 0)
            .store_u64(Reg::A1, base + 22)
            .load_imm_64(Reg::A0, u64::from(base))
            .load_imm_64(Reg::A1, 30)
            .jump_ind(Reg::RA, 0);
        let bytes = program.build_standard();
        let blob = work
            .availability
            .iter_mut()
            .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
            .unwrap();
        work.program = crate::agent_sdk::ProgramId::of_pvm(&bytes);
        *blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
            bytes,
        };
        work.availability.push(crate::agent_sdk::RuntimeBlob {
            reference,
            bytes: payload,
        });
        work.availability
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        work.gas = 100_000;
        let mut state = runtime.snapshot();
        state.actors[0].record.entry.program = crate::service::ProgramId(work.program.0);
        let record = &state.actors[0].record;
        let installation = &mut state.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.entry =
            super::super::standard::legacy_actor_record_to_clean(record, installation.commitment)
                .entry;
        installation.commitment = installation.original.lineage_commitment();
        let runtime = StandardAgentRuntime::restore(state).unwrap();
        let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
            runtime.config().unwrap(),
            &work,
        ));
        RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: 1,
        }
    }

    #[cfg(feature = "pvm")]
    fn check_clean_maximum_availability(runtime_program: Option<&[u8]>) {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationStatus, RuntimeOutcome, RuntimeTransition, RuntimeWork};
        let mut work =
            clean_availability_work(super::super::execution::MAX_EXECUTION_AVAILABILITY_BYTES);
        let mut first_outcome = None;
        for phase in 0..2 {
            let input = work.encode().unwrap();
            let decoded = RuntimeWork::decode(&input).unwrap();
            let expected = apply_standard_runtime_work(decoded).unwrap();
            if let Some(program) = runtime_program {
                let execution = vos_pvm::refine_host::RefineContext::load(
                    program,
                    &input,
                    super::super::driver::DEFAULT_MANAGEMENT_GAS,
                )
                .unwrap()
                .run();
                assert_eq!(execution.exit, vos_pvm::ExitReason::Halt, "phase={phase}");
                let output = execution
                    .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
                    .unwrap();
                assert_eq!(
                    output,
                    expected.encode().unwrap(),
                    "outer guest/source transition phase={phase}"
                );
                std::eprintln!(
                    "maximum availability phase={phase} input_bytes={} gas_used={}",
                    input.len(),
                    execution.gas_used
                );
            }
            let RuntimeOutcome::Completed(Ok(reply)) = &expected.outcome else {
                panic!("maximum availability refused: {:?}", expected.outcome)
            };
            assert_eq!(reply.status, InvocationStatus::Done);
            assert_eq!(
                &reply.reply[..8],
                &(super::super::execution::MAX_EXECUTION_AVAILABILITY_BYTES as u64).to_le_bytes()
            );
            assert_eq!(&reply.reply[8..], &[0x7b; 8]);
            if let Some(first) = &first_outcome {
                assert_eq!(&expected.outcome, first);
            }
            first_outcome = Some(expected.outcome);
            let reopened =
                decode_standard_runtime_state(&clean_state_to_legacy(&expected.state)).unwrap();
            let reopened = StandardAgentRuntime::restore(reopened).unwrap();
            let RuntimeWork::Invoke {
                state,
                observed_slot,
                ..
            } = &mut work
            else {
                unreachable!()
            };
            *state = legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot()));
            *observed_slot = 99;
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_maximum_availability_survives_wire_dispatch_and_exact_retry() {
        check_clean_maximum_availability(None);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_dispatch_rejects_signed_availability_above_caller_window() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeWork};
        let work =
            clean_availability_work(super::super::execution::MAX_EXECUTION_AVAILABILITY_BYTES + 1);
        // Overall wire availability also carries code/schema/policy artifacts;
        // fitting that larger envelope must not bypass the caller-only window.
        let encoded = work.encode().unwrap();
        let decoded = RuntimeWork::decode(&encoded).unwrap();
        let result = apply_standard_runtime_work(decoded).unwrap();
        assert_eq!(
            result.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::InvalidInput))
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AGENT_RUNTIME_CANDIDATE_ELF built from current runtime source"]
    fn compiled_runtime_maximum_availability_matches_source_and_retry() {
        let elf = std::fs::read(
            std::env::var("AGENT_RUNTIME_CANDIDATE_ELF").expect("set current runtime ELF"),
        )
        .unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        vos_pvm::spi::validate_refine_host_calls(&program).unwrap();
        check_clean_maximum_availability(Some(&program));
    }

    #[cfg(feature = "pvm")]
    fn clean_storage_dispatch_fixture(
        export: bool,
        status: u8,
        runtime_program: Option<&[u8]>,
        padding_rows: usize,
    ) {
        use crate::agent_sdk::method_policy::{
            AttestationRequirement, AuthorizationPolicySelector,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationStatus, RuntimeExecutionContext, RuntimeOutcome,
            RuntimeWork,
        };
        use vos_pvm_compiler::assembler::{Assembler, Reg};
        let (runtime, mut work) = clean_policy_fixture_with_storage(
            AuthorizationPolicySelector::Public,
            AttestationRequirement::None,
            true,
        );
        let key = b"s/rows/value";
        let yields = status == crate::actors::STATUS_YIELDED;
        assert!(!yields || export);
        let mut row = vec![0x73; crate::actors::storage::MAX_VALUE_BYTES];
        let base = 2 * vos_pvm::PVM_ZONE_SIZE;
        let mut output = vec![0; 30];
        output[0] = status;
        output[1..5].copy_from_slice(&1u32.to_le_bytes());
        output[13] = 0xee;
        let mut program = Assembler::new();
        let buffer;
        if export {
            let delta =
                super::super::actor_storage::encode_row_delta(&[(key.to_vec(), Some(row.clone()))])
                    .unwrap();
            output.extend_from_slice(&delta);
            buffer = base + (output.len() - row.len()) as u32;
            program.set_rw_data(output);
            if yields {
                // The runtime captures before finalization. Export only after
                // SUSPEND returns; restoration returns1 and replaces the row.
                assert_eq!(crate::actors::STATUS_YIELDED, 1);
                program
                    .ecalli(crate::abi::hostcall::SUSPEND)
                    .load_imm_64(Reg::A1, 1)
                    .sub_64(Reg::A0, Reg::A1, Reg::A0)
                    .store_u8(Reg::A0, base)
                    .load_imm_64(Reg::A1, 0x74)
                    .sub_64(Reg::A1, Reg::A1, Reg::A0)
                    .store_u8(Reg::A1, buffer);
            }
            program
                .load_imm_64(Reg::A0, u64::from(base + 30))
                .load_imm_64(Reg::A1, delta.len() as u64)
                .ecalli(crate::abi::hostcall::ACTOR_EFFECT_EXPORT)
                .load_imm_64(Reg::A0, row.len() as u64);
        } else {
            output.extend_from_slice(key);
            buffer = base + output.len() as u32;
            output.resize(output.len() + row.len(), 0);
            program
                .set_rw_data(output)
                .load_imm_64(Reg::A0, u64::from(base + 30))
                .load_imm_64(Reg::A1, key.len() as u64)
                .load_imm_64(Reg::A2, u64::from(buffer))
                .load_imm_64(Reg::A3, row.len() as u64)
                .ecalli(crate::abi::hostcall::STORAGE_R);
        }
        program
            .store_u64(Reg::A0, base + 14)
            .load_imm_64(Reg::A0, u64::from(buffer))
            .load_ind_u64(Reg::A1, Reg::A0, 0)
            .store_u64(Reg::A1, base + 22)
            .load_imm_64(Reg::A0, u64::from(base))
            .load_imm_64(Reg::A1, if yields { 14 } else { 30 })
            .jump_ind(Reg::RA, 0);
        let bytes = program.build_standard();
        let blob = work
            .availability
            .iter_mut()
            .find(|blob| crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == work.program)
            .unwrap();
        work.program = crate::agent_sdk::ProgramId::of_pvm(&bytes);
        *blob = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&bytes),
            bytes,
        };
        work.availability
            .sort_by(|a, b| a.reference.cmp(&b.reference));
        work.gas = 100_000;
        let mut state = runtime.snapshot();
        state.actors[0].record.entry.program = crate::service::ProgramId(work.program.0);
        let record = &state.actors[0].record;
        let installation = &mut state.clean_actor_installations.as_mut().unwrap()[0];
        installation.original.entry =
            super::super::standard::legacy_actor_record_to_clean(record, installation.commitment)
                .entry;
        installation.commitment = installation.original.lineage_commitment();
        for index in 0..padding_rows {
            state.lane_state.linear[0].rows.insert(
                alloc::format!("s/rows/padding/{index:04}").into_bytes(),
                vec![0x45; crate::actors::storage::MAX_VALUE_BYTES],
            );
        }
        if !export {
            state.lane_state.linear[0]
                .rows
                .insert(key.to_vec(), row.clone());
        }
        let runtime = StandardAgentRuntime::restore(state).unwrap();
        let (inner, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let inline = runtime.prepare_execution_state(&inner).unwrap();
        assert_eq!(inline.linear.as_deref(), Some(&[0x89][..]));
        assert!(inline.encoded_len().unwrap() < row.len());
        let authorization = InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(
            runtime.config().unwrap(),
            &work,
        ));
        let initial = legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot()));
        let execute = |input: RuntimeWork| {
            let operation = match &input {
                RuntimeWork::Acknowledge { .. } => "ack",
                RuntimeWork::Resume { .. } => "resume",
                RuntimeWork::Manage { .. } => "manage",
                _ => "invoke",
            };
            let encoded = input.encode().unwrap();
            let decoded = RuntimeWork::decode(&encoded).unwrap();
            let expected = apply_standard_runtime_work(decoded).unwrap();
            if let Some(program) = runtime_program {
                let execution = vos_pvm::refine_host::RefineContext::load(
                    program,
                    &encoded,
                    super::super::driver::DEFAULT_MANAGEMENT_GAS,
                )
                .unwrap()
                .run();
                if execution.exit != vos_pvm::ExitReason::Halt {
                    std::eprintln!(
                        "row fixture failure pc={} gas_used={} registers={:?}",
                        execution.pc,
                        execution.gas_used,
                        execution.registers
                    );
                }
                assert_eq!(
                    execution.exit,
                    vos_pvm::ExitReason::Halt,
                    "row fixture export={export} status={status} padding_rows={padding_rows}"
                );
                let output = execution
                    .output_bounded(crate::agent_sdk::RuntimeTransition::MAX_ENCODED_BYTES)
                    .unwrap();
                assert!(
                    output == expected.encode().unwrap(),
                    "physical row transition differs from source"
                );
                std::eprintln!(
                    "row fixture operation={operation} export={export} status={status} padding_rows={padding_rows} input_bytes={} gas_used={}",
                    encoded.len(),
                    execution.gas_used
                );
            }
            expected
        };
        let mut result = execute(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: initial,
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 1,
        });
        if yields {
            let RuntimeOutcome::Yielded(yielded) = &result.outcome else {
                panic!("row slice did not yield: {:?}", result.outcome)
            };
            let decoded =
                decode_standard_runtime_state(&clean_state_to_legacy(&result.state)).unwrap();
            assert_eq!(decoded.machine_continuations.len(), 1);
            assert_eq!(
                decoded.lane_state.linear[0].rows.get(key.as_slice()),
                Some(&row)
            );
            let reopened = StandardAgentRuntime::restore(decoded).unwrap();
            result = execute(RuntimeWork::Resume {
                context: RuntimeExecutionContext::Direct,
                state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
                resume: Box::new(clean_resume(yielded, work.availability.clone())),
            });
            row[0] = 0x74;
        }
        let RuntimeOutcome::Completed(Ok(reply)) = &result.outcome else {
            panic!("row read failed: {:?}", result.outcome)
        };
        let expected_status = match status {
            crate::actors::STATUS_DONE | crate::actors::STATUS_YIELDED => InvocationStatus::Done,
            crate::actors::STATUS_PANICKED => InvocationStatus::Panicked,
            crate::actors::STATUS_FORBIDDEN => InvocationStatus::Forbidden,
            crate::actors::STATUS_OOG => InvocationStatus::OutOfGas,
            _ => unreachable!(),
        };
        assert_eq!(reply.status, expected_status);
        if yields {
            assert!(reply.reply.is_empty());
        } else if expected_status == InvocationStatus::Done {
            assert_eq!(&reply.reply[..8], &(row.len() as u64).to_le_bytes());
            assert_eq!(&reply.reply[8..], &[0x73; 8]);
        }
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&result.state)).unwrap();
        assert!(decoded.machine_continuations.is_empty());
        if expected_status == InvocationStatus::Done {
            assert_eq!(decoded.lane_state.linear[0].value, vec![0xee]);
            assert_eq!(
                decoded.lane_state.linear[0].rows.get(key.as_slice()),
                Some(&row)
            );
        } else {
            assert_eq!(decoded.lane_state.linear[0].value, vec![0x89]);
            assert!(
                !decoded.lane_state.linear[0]
                    .rows
                    .contains_key(key.as_slice()),
                "a failed actor must not publish exported rows"
            );
        }
        assert_eq!(
            decoded.lane_state.linear[0].rows.len(),
            padding_rows + usize::from(expected_status == InvocationStatus::Done)
        );
        for index in 0..padding_rows {
            assert_eq!(
                decoded.lane_state.linear[0]
                    .rows
                    .get(alloc::format!("s/rows/padding/{index:04}").as_bytes()),
                Some(&vec![0x45; row.len()])
            );
        }
        let reopened = StandardAgentRuntime::restore(decoded).unwrap();
        let mut expected_retry_state = reopened.snapshot();
        // Exact delivery retries advance the existing result-lane authority
        // clock, but must not reexecute or change rows, inline state or result.
        expected_retry_state.lane_revisions.linear_authority_slot = Some(99);
        let retry = execute(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
            invocation: Box::new(work.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: 99,
        });
        assert_eq!(retry.outcome, result.outcome);
        assert!(
            decode_standard_runtime_state(&clean_state_to_legacy(&retry.state)).unwrap()
                == expected_retry_state,
            "retry may advance only the result-lane authority clock"
        );
        let acknowledged = execute(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: retry.state,
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        });
        assert!(matches!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let retired =
            decode_standard_runtime_state(&clean_state_to_legacy(&acknowledged.state)).unwrap();
        assert!(retired.invocation_results.is_empty());
        assert!(
            retired.lane_state == expected_retry_state.lane_state,
            "retirement changed actor rows or inline state"
        );
        let reopened = StandardAgentRuntime::restore(retired).unwrap();
        let repeated_ack = execute(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(authorization.clone()),
        });
        assert!(
            repeated_ack == acknowledged,
            "exact acknowledgement retry changed transition"
        );
        let replayed = execute(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state: repeated_ack.state,
            invocation: Box::new(work),
            authorization: Box::new(authorization),
            observed_slot: 99,
        });
        assert_eq!(
            replayed.outcome,
            RuntimeOutcome::Completed(Err(crate::agent_sdk::InvocationError::DivergentInvocation))
        );
        assert!(
            replayed.state == acknowledged.state,
            "retired invocation changed state"
        );
        if padding_rows != 0 {
            use crate::agent_sdk::{ManagementReply, ManagementRequest};
            let config = runtime.config().unwrap();
            for request in [
                ManagementRequest::InspectActors {
                    after: None,
                    limit: 1,
                },
                ManagementRequest::InspectResources,
            ] {
                let inspected = execute(RuntimeWork::Manage {
                    context: RuntimeExecutionContext::Direct,
                    space: crate::agent_sdk::SpaceId(config.identity.space.0),
                    agent: crate::agent_sdk::AgentId(config.identity.agent.0),
                    runtime_deployment: crate::agent_sdk::DeploymentId(
                        config.identity.runtime_deployment.0,
                    ),
                    state: replayed.state.clone(),
                    request: Box::new(request),
                    authority: None,
                    observed_slot: 99,
                });
                match &inspected.outcome {
                    RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) => {
                        assert_eq!(page.entries.len(), 1)
                    }
                    RuntimeOutcome::Management(Ok(ManagementReply::Resources(usage))) => {
                        assert_eq!(
                            usage.state_bytes as usize,
                            clean_state_to_legacy(&replayed.state)
                                .encoded_len()
                                .unwrap()
                        );
                    }
                    other => panic!("large-state inspection failed: {other:?}"),
                }
                assert!(
                    inspected.state == replayed.state,
                    "inspection changed row-backed state"
                );
            }
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_multi_megabyte_rows_preserve_unrelated_state_and_retry() {
        clean_storage_dispatch_fixture(true, crate::actors::STATUS_DONE, None, 60);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_multi_megabyte_rows_yield_resume_and_retire() {
        clean_storage_dispatch_fixture(true, crate::actors::STATUS_YIELDED, None, 60);
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AGENT_RUNTIME_CANDIDATE_ELF built from current runtime source"]
    fn compiled_runtime_rows_commit_rollback_and_retry_match_source() {
        let elf = std::fs::read(
            std::env::var("AGENT_RUNTIME_CANDIDATE_ELF").expect("set current runtime ELF"),
        )
        .unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        vos_pvm::spi::validate_refine_host_calls(&program).unwrap();
        clean_storage_dispatch_fixture(false, crate::actors::STATUS_DONE, Some(&program), 0);
        for status in [
            crate::actors::STATUS_DONE,
            crate::actors::STATUS_PANICKED,
            crate::actors::STATUS_FORBIDDEN,
            crate::actors::STATUS_OOG,
        ] {
            clean_storage_dispatch_fixture(true, status, Some(&program), 0);
        }
        clean_storage_dispatch_fixture(true, crate::actors::STATUS_DONE, Some(&program), 60);
    }

    #[cfg(feature = "pvm")]
    #[test]
    #[ignore = "requires AGENT_RUNTIME_CANDIDATE_ELF built from current runtime source"]
    fn compiled_runtime_rows_yield_resume_and_retire_match_source() {
        let elf = std::fs::read(
            std::env::var("AGENT_RUNTIME_CANDIDATE_ELF").expect("set current runtime ELF"),
        )
        .unwrap();
        let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
        vos_pvm::spi::validate_refine_host_calls(&program).unwrap();
        clean_storage_dispatch_fixture(true, crate::actors::STATUS_YIELDED, Some(&program), 60);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_terminal_failure_dispatch_rolls_back_writes_and_retires_after_restart() {
        use crate::agent_sdk::{InvocationStatus, RuntimeOutcome, RuntimeWork};
        for (status, expected) in [
            (
                Some(crate::actors::STATUS_FORBIDDEN),
                InvocationStatus::Forbidden,
            ),
            (
                Some(crate::actors::STATUS_PANICKED),
                InvocationStatus::Panicked,
            ),
            (Some(crate::actors::STATUS_OOG), InvocationStatus::OutOfGas),
            (None, InvocationStatus::Panicked),
        ] {
            let work = clean_failing_actor_fixture(status);
            let RuntimeWork::Invoke {
                state,
                invocation,
                authorization,
                ..
            } = work.clone()
            else {
                unreachable!()
            };
            let before = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
            let transition = apply_standard_runtime_work(work).unwrap();
            let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
                panic!(
                    "failure did not produce a retained terminal reply: {:?}",
                    transition.outcome
                )
            };
            assert_eq!(reply.status, expected);
            let retained =
                decode_standard_runtime_state(&clean_state_to_legacy(&transition.state)).unwrap();
            assert_eq!(retained.invocation_results.len(), 1);
            assert_eq!(retained.lane_state, before.lane_state);
            assert_eq!(retained.lane_revisions.linear, before.lane_revisions.linear);
            let reopened = StandardAgentRuntime::restore(retained).unwrap();
            let reopened =
                legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot()));
            let retry = apply_standard_runtime_work(RuntimeWork::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: reopened,
                invocation: invocation.clone(),
                authorization: authorization.clone(),
                observed_slot: 99,
            })
            .unwrap();
            assert_eq!(retry.outcome, transition.outcome);
            let ack = apply_standard_runtime_work(RuntimeWork::Acknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: retry.state,
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                    &invocation,
                )),
                authorization,
            })
            .unwrap();
            assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
        }
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn clean_failing_resume_fixture() -> crate::agent_sdk::RuntimeWork {
        clean_failing_resume_fixture_with_status(None)
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn clean_failing_resume_fixture_with_status(
        status: Option<u8>,
    ) -> crate::agent_sdk::RuntimeWork {
        use crate::agent_sdk::{RuntimeExecutionContext, RuntimeWork};
        let RuntimeWork::Invoke {
            state,
            invocation: work,
            authorization,
            observed_slot,
            ..
        } = clean_failing_actor_fixture(status)
        else {
            unreachable!()
        };
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let (invocation, actor_pvm, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut continuation = portable_continuation(&invocation, 1, 0).continuation;
        continuation.machine = super::super::machine::ActorMachine::load(&actor_pvm, &[0])
            .unwrap()
            .capture()
            .unwrap();
        continuation.machine.gas_remaining = if status.is_some() { 100_000 } else { 100 };
        runtime
            .commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before,
                before.clone(),
                observed_slot,
                None,
                continuation,
                Some((
                    super::super::standard::StandardAcceptedInvocation::from_work(&work),
                    (*authorization).clone(),
                )),
            )
            .unwrap();
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, observed_slot)
            .unwrap()
            .unwrap();
        RuntimeWork::Resume {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&runtime.snapshot())),
            resume: Box::new(clean_resume(&yielded, work.availability)),
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_terminal_failure_resume_dispatch_consumes_continuation_and_can_acknowledge() {
        use crate::agent_sdk::{
            InvocationStatus, RuntimeExecutionContext, RuntimeOutcome, RuntimeWork,
        };
        let work = clean_failing_resume_fixture();
        let RuntimeWork::Resume { state, resume, .. } = &work else {
            unreachable!()
        };
        let runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(state)).unwrap(),
        )
        .unwrap();
        let (record, accepted) = runtime.resolve_clean_resume(resume).unwrap();
        let before = runtime.snapshot();
        let transition = apply_standard_runtime_work(work).unwrap();
        assert!(
            matches!(&transition.outcome, RuntimeOutcome::Completed(Ok(reply)) if reply.status == InvocationStatus::Panicked),
            "{:?}",
            transition.outcome
        );
        let retained =
            decode_standard_runtime_state(&clean_state_to_legacy(&transition.state)).unwrap();
        assert!(retained.machine_continuations.is_empty());
        assert_eq!(retained.invocation_results.len(), 1);
        assert_eq!(retained.lane_state, before.lane_state);
        assert_eq!(retained.lane_revisions.linear, before.lane_revisions.linear);
        let reopened = StandardAgentRuntime::restore(retained).unwrap();
        let ack = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: legacy_state_to_clean(encode_standard_runtime_state(&reopened.snapshot())),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&accepted)),
            authorization: Box::new(record.authorization.unwrap()),
        })
        .unwrap();
        assert!(matches!(ack.outcome, RuntimeOutcome::Acknowledged(Ok(_))));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_terminal_failure_retention_consumes_only_its_resumed_continuation() {
        let (state, work, _) = yielded_clean_policy_fixture(crate::agent_sdk::Hash([0x93; 32]));
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap(),
        )
        .unwrap();
        let before = runtime.snapshot();
        assert_eq!(before.machine_continuations.len(), 1);
        let record = &before.machine_continuations[0];
        let authorization = record.authorization.as_ref().unwrap();
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let reply = exact_reply(&invocation, ActorExecutionStatus::Panicked);
        runtime
            .retain_clean_terminal_failure(
                &work,
                authorization,
                &invocation,
                &reply,
                record.observed_slot,
                Some(record.ready_sequence),
            )
            .unwrap();
        let retained = runtime.snapshot();
        assert!(retained.machine_continuations.is_empty());
        assert_eq!(retained.lane_state, before.lane_state);
        assert_eq!(
            (
                retained.lane_revisions.linear,
                retained.lane_revisions.merge,
                retained.lane_revisions.local
            ),
            (
                before.lane_revisions.linear,
                before.lane_revisions.merge,
                before.lane_revisions.local
            ),
        );
        let mut reopened = StandardAgentRuntime::restore(retained).unwrap();
        reopened
            .acknowledge_clean_invocation(&work, authorization)
            .unwrap();
        assert!(reopened.snapshot().invocation_results.is_empty());
        assert!(reopened.snapshot().machine_continuations.is_empty());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_terminal_failure_retention_rejects_invalid_or_unbounded_results_atomically() {
        let (mut runtime, work) = clean_policy_fixture(
            crate::agent_sdk::method_policy::AuthorizationPolicySelector::Public,
        );
        let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(runtime.config().unwrap(), &work),
        );
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let reply = exact_reply(&invocation, ActorExecutionStatus::Panicked);
        let before = runtime.snapshot();
        for status in [ActorExecutionStatus::Done, ActorExecutionStatus::Yielded] {
            let mut invalid = reply.clone();
            invalid.status = status;
            assert!(
                runtime
                    .retain_clean_terminal_failure(
                        &work,
                        &authorization,
                        &invocation,
                        &invalid,
                        1,
                        None,
                    )
                    .is_err()
            );
            assert_eq!(runtime.snapshot(), before);
        }
        let mut oversized = reply.clone();
        oversized.reply = vec![0; super::super::standard::MAX_INVOCATION_RESULT_BYTES_PER_LANE + 1];
        assert_eq!(
            runtime.retain_clean_terminal_failure(
                &work,
                &authorization,
                &invocation,
                &oversized,
                1,
                None,
            ),
            Err(ActorExecutionError::ResultCapacity)
        );
        assert_eq!(runtime.snapshot(), before);
        assert!(
            runtime
                .retain_clean_terminal_failure(
                    &work,
                    &authorization,
                    &invocation,
                    &reply,
                    1,
                    Some(999),
                )
                .is_err()
        );
        assert_eq!(
            runtime.snapshot(),
            before,
            "a missing continuation cannot partially retain a result"
        );
        runtime
            .retain_clean_terminal_failure(&work, &authorization, &invocation, &reply, 1, None)
            .unwrap();
        let retained = runtime.snapshot();
        assert!(
            runtime
                .retain_clean_terminal_failure(&work, &authorization, &invocation, &reply, 1, None,)
                .is_err()
        );
        assert_eq!(
            runtime.snapshot(),
            retained,
            "an existing result cannot be overwritten"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_done_retries_restarts_and_requires_exact_acknowledgement() {
        use crate::agent_sdk::{
            InvocationAcknowledgement, InvocationError, RuntimeOutcome, RuntimeWork,
        };

        let (committed, work, authority, reply) = clean_terminal_fixture();
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&committed)).unwrap();
        assert_eq!(decoded.invocation_results.len(), 1);
        assert!(decoded.invocation_results[0].clean.is_some());
        let restarted = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            legacy_state_to_clean(encode_standard_runtime_state(&restarted.snapshot())),
            committed,
            "the clean result binding survives restart byte-identically"
        );

        let retried = apply_standard_runtime_work(RuntimeWork::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: committed.clone(),
            invocation: Box::new(work.clone()),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )),
            observed_slot: 99,
        })
        .unwrap();
        assert_eq!(
            retried.outcome,
            RuntimeOutcome::Completed(Ok(reply)),
            "an exact retry remains recoverable after the original receipt expires"
        );
        assert_eq!(
            decode_standard_runtime_state(&clean_state_to_legacy(&retried.state))
                .unwrap()
                .invocation_results
                .len(),
            1,
            "retry retains the result until explicit acknowledgement"
        );

        let acknowledged = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: retried.state.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )),
        })
        .unwrap();
        let acknowledgement = InvocationAcknowledgement {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            mode: work.mode,
            work: work.commitment(),
            authorization: crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )
            .commitment(),
        };
        assert_eq!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(acknowledgement))
        );
        let acknowledged_state =
            decode_standard_runtime_state(&clean_state_to_legacy(&acknowledged.state)).unwrap();
        assert!(acknowledged_state.invocation_results.is_empty());
        assert_eq!(
            acknowledged_state.clean_invocation_acknowledgements,
            vec![acknowledgement],
            "the positive retirement fact is guest-owned durable state"
        );

        let restarted = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&clean_state_to_legacy(&acknowledged.state)).unwrap(),
        )
        .unwrap();
        let after_restart =
            legacy_state_to_clean(encode_standard_runtime_state(&restarted.snapshot()));
        for state in [&acknowledged.state, &after_restart] {
            let late_invoke = apply_standard_runtime_work(RuntimeWork::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: state.clone(),
                invocation: Box::new(work.clone()),
                authorization: Box::new(
                    crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority.clone()),
                ),
                observed_slot: 99,
            })
            .unwrap();
            assert_eq!(
                late_invoke.state, *state,
                "retired work cannot mutate again"
            );
            assert_eq!(
                late_invoke.outcome,
                RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation)),
                "retirement consumes the invocation key before and after restart"
            );
        }
        let replayed = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: after_restart.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                authority.clone(),
            )),
        })
        .unwrap();
        assert_eq!(replayed.state, after_restart);
        assert_eq!(
            replayed.outcome,
            RuntimeOutcome::Acknowledged(Ok(acknowledgement)),
            "response loss/restart replays the exact positive acknowledgement"
        );

        let mut divergent = work;
        divergent.message.push(0xff);
        let divergent_authority = clean_authority_receipt(
            clean_sparse_standard_state().config.as_ref().unwrap(),
            &divergent,
        );
        let rejected = apply_standard_runtime_work(RuntimeWork::Acknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            state: after_restart.clone(),
            invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(
                &divergent,
            )),
            authorization: Box::new(crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                divergent_authority,
            )),
        })
        .unwrap();
        assert_eq!(rejected.state, after_restart);
        assert_eq!(
            rejected.outcome,
            RuntimeOutcome::Acknowledged(Err(InvocationError::DivergentInvocation))
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_acknowledgement_errors_are_byte_identical_and_fail_closed() {
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationError, RuntimeOutcome, RuntimeWork};

        let candidate = std::env::var_os("VOS_AGENT_RUNTIME_ACK_CANDIDATE")
            .map(|path| std::fs::read(path).expect("read acknowledgement candidate"));
        let (state, work, authority, _) = clean_terminal_fixture();
        let assert_error = |work: crate::agent_sdk::InvocationWork,
                            authority: crate::agent_sdk::authority::AuthorityReceipt,
                            expected| {
            let request = RuntimeWork::Acknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                state: state.clone(),
                invocation: Box::new(crate::agent_sdk::InvocationRetirement::from_work(&work)),
                authorization: Box::new(
                    crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority),
                ),
            };
            let transition = apply_standard_runtime_work(request.clone()).unwrap();
            if let Some(program) = &candidate {
                let execution = vos_pvm::refine_host::RefineContext::load(
                    program,
                    &request.encode().unwrap(),
                    2_000_000_000,
                )
                .unwrap()
                .run();
                assert_eq!(execution.exit, vos_pvm::ExitReason::Halt);
                assert_eq!(
                    execution
                        .output_bounded(crate::agent_sdk::RuntimeTransition::MAX_ENCODED_BYTES)
                        .unwrap(),
                    transition.encode().unwrap(),
                    "candidate must preserve the entire rejection transition",
                );
            }
            assert_eq!(transition.state, state);
            assert_eq!(
                transition.outcome,
                RuntimeOutcome::Acknowledged(Err(expected))
            );
        };

        let mut forged = authority.clone();
        forged.signature[0] ^= 1;
        assert_error(work.clone(), forged, InvocationError::InvalidAuthorization);

        let mut divergent = work.clone();
        divergent.message.push(0xff);
        let divergent_authority = clean_authority_receipt(
            clean_sparse_standard_state().config.as_ref().unwrap(),
            &divergent,
        );
        assert_error(
            divergent,
            divergent_authority,
            InvocationError::DivergentInvocation,
        );

        let mut wrong_route = work.clone();
        wrong_route.actor = crate::agent_sdk::ActorId([0xe5; 32]);
        let wrong_route_authority = clean_authority_receipt(
            clean_sparse_standard_state().config.as_ref().unwrap(),
            &wrong_route,
        );
        assert_error(
            wrong_route,
            wrong_route_authority,
            InvocationError::DivergentInvocation,
        );

        let mut cross_invocation = work.clone();
        cross_invocation.invocation = crate::agent_sdk::InvocationId([0xe6; 32]);
        let cross_authority = clean_authority_receipt(
            clean_sparse_standard_state().config.as_ref().unwrap(),
            &cross_invocation,
        );
        assert_error(cross_invocation, cross_authority, InvocationError::NotFound);

        let mut different_window = authority;
        different_window.selector.valid_from = 2;
        different_window.selector.expires_at = 3;
        different_window.signature = authority_key()
            .sign(&different_window.signing_bytes())
            .to_bytes();
        assert_error(work, different_window, InvocationError::DivergentInvocation);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_acknowledgement_capacity_preserves_facts_and_result_across_restart() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        let (mut runtime, template) = clean_resolvable_fixture(false);
        let config = runtime.config().unwrap().clone();
        let capacity = super::super::standard::MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE;
        let mut retained = Vec::with_capacity(capacity);
        for discriminator in 1..=capacity as u8 {
            let mut work = template.clone();
            work.invocation = crate::agent_sdk::InvocationId([discriminator; 32]);
            let authorization =
                InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(&config, &work));
            runtime
                .validate_clean_unseen_invocation_slot(&authorization, 1)
                .unwrap();
            let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
            let before = runtime.prepare_execution_state(&invocation).unwrap();
            let mut after = before.clone();
            after.linear = Some(vec![discriminator]);
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            runtime
                .commit_clean_execution(
                    &work,
                    &authorization,
                    &invocation,
                    &mut reply,
                    &before,
                    after,
                    1,
                    None,
                )
                .unwrap();
            let acknowledgement = runtime
                .acknowledge_clean_invocation(&work, &authorization)
                .unwrap();
            assert_eq!(
                runtime.recover_clean_execution(&work, &authorization, 1),
                Err(InvocationError::DivergentInvocation),
                "even a still-live receipt cannot execute retired work again"
            );
            retained.push((work, authorization, acknowledgement));
        }

        let mut overflow_work = template;
        overflow_work.invocation = crate::agent_sdk::InvocationId([(capacity + 1) as u8; 32]);
        let overflow_authorization = InvocationAuthorization::AuthorityReceipt(
            clean_authority_receipt(&config, &overflow_work),
        );
        runtime
            .validate_clean_unseen_invocation_slot(&overflow_authorization, 1)
            .unwrap();
        let (overflow_invocation, ..) = runtime.resolve_clean_invocation(&overflow_work).unwrap();
        let before = runtime
            .prepare_execution_state(&overflow_invocation)
            .unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![(capacity + 1) as u8]);
        let mut overflow_reply = exact_reply(&overflow_invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &overflow_work,
                &overflow_authorization,
                &overflow_invocation,
                &mut overflow_reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        let before_full_acknowledgement = encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(
            runtime.acknowledge_clean_invocation(&overflow_work, &overflow_authorization),
            Err(InvocationError::ResultCapacity)
        );
        assert_eq!(
            encode_standard_runtime_state(&runtime.snapshot()),
            before_full_acknowledgement,
            "a full acknowledgement component fails before retiring the result or any fact"
        );

        let encoded = encode_standard_runtime_state(&runtime.snapshot());
        let decoded = decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded.clean_invocation_acknowledgements.len(), capacity);
        assert_eq!(decoded.invocation_results.len(), 1);
        assert_eq!(
            decoded.invocation_results[0].invocation.0,
            overflow_work.invocation.0
        );
        let mut reopened = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            encode_standard_runtime_state(&reopened.snapshot()),
            encoded,
            "checkpoint/reopen retains all facts and the unretired result byte-identically"
        );

        for (work, authorization, acknowledgement) in &retained {
            assert_eq!(
                reopened.recover_clean_execution(work, authorization, 1),
                Err(InvocationError::DivergentInvocation),
                "restart must preserve the consumed invocation identity"
            );
            assert_eq!(
                reopened
                    .recover_clean_acknowledgement(work, authorization)
                    .unwrap(),
                Some(*acknowledgement),
                "every positive acknowledgement remains exactly replayable"
            );
        }
        assert_eq!(
            reopened
                .recover_clean_execution(&overflow_work, &overflow_authorization, 1)
                .unwrap(),
            Some(overflow_reply),
            "the result whose acknowledgement could not be retained remains exactly retryable"
        );
        assert_eq!(
            reopened.acknowledge_clean_invocation(&overflow_work, &overflow_authorization),
            Err(InvocationError::ResultCapacity)
        );
        assert_eq!(
            encode_standard_runtime_state(&reopened.snapshot()),
            encoded,
            "retries at acknowledgement capacity are stable and mutation-free"
        );

        let mut hostile = reopened.snapshot();
        hostile
            .clean_invocation_acknowledgements
            .push(retained[0].2);
        assert!(StandardAgentRuntime::restore(hostile).is_err());
    }

    /// One sequenced clean Linear invocation of the resolvable fixture:
    /// accept, commit a `Done` result, and return its work and authorization.
    #[cfg(feature = "pvm")]
    fn commit_sequenced_linear(
        runtime: &mut StandardAgentRuntime,
        config: &AgentConfig,
        template: &crate::agent_sdk::InvocationWork,
        sequence: u64,
    ) -> (
        crate::agent_sdk::InvocationWork,
        crate::agent_sdk::InvocationAuthorization,
    ) {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationResultStorage, SequencedInvocation,
        };
        let mut work = template.clone();
        work.invocation = SequencedInvocation::new(
            InvocationResultStorage::Lane(crate::agent_sdk::StateLane::Linear),
            core::num::NonZeroU64::new(sequence).unwrap(),
        )
        .invocation_id();
        let authorization =
            InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(config, &work));
        assert_eq!(
            runtime.recover_clean_execution(&work, &authorization, 1),
            Ok(None),
            "sequence {sequence} is unseen"
        );
        runtime
            .validate_clean_unseen_invocation_slot(&authorization, 1)
            .unwrap();
        let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.clone();
        after.linear = Some(sequence.to_le_bytes().to_vec());
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &work,
                &authorization,
                &invocation,
                &mut reply,
                &before,
                after,
                1,
                None,
            )
            .unwrap();
        (work, authorization)
    }

    #[cfg(feature = "pvm")]
    fn reopen_checkpoint(runtime: &StandardAgentRuntime) -> StandardAgentRuntime {
        let encoded = encode_standard_runtime_state(&runtime.snapshot());
        let reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&encoded).unwrap())
                .unwrap();
        assert_eq!(
            encode_standard_runtime_state(&reopened.snapshot()),
            encoded,
            "checkpoint/reopen is byte-identical"
        );
        reopened
    }

    /// T-025-01: an Agent takes 10 000 acknowledged Linear invocations. Today
    /// the 33rd acknowledgement and the 65th invocation are refused; with
    /// sequenced identities the oldest contiguous retirement facts become a
    /// watermark, which keeps every retired identity consumed.
    #[cfg(feature = "pvm")]
    #[test]
    fn sequenced_acknowledgements_compact_past_capacity_without_readmitting_work() {
        use crate::agent_sdk::{InvocationAuthorization, InvocationError};

        const INVOCATIONS: u64 = 10_000;
        let (mut runtime, template) = clean_resolvable_fixture(false);
        let config = runtime.config().unwrap().clone();
        let capacity = super::super::standard::MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE;
        let linear = crate::agent::InvocationResultStorage::Lane(crate::agent::StateLane::Linear);
        let mut first = None;
        let mut acknowledgements = Vec::new();
        for sequence in 1..=INVOCATIONS {
            let (work, authorization) =
                commit_sequenced_linear(&mut runtime, &config, &template, sequence);
            let acknowledgement = runtime
                .acknowledge_clean_invocation(&work, &authorization)
                .unwrap_or_else(|error| panic!("acknowledgement {sequence}: {error:?}"));
            assert_eq!(
                runtime.recover_clean_execution(&work, &authorization, 1),
                Err(InvocationError::DivergentInvocation),
                "retired work {sequence} never executes again"
            );
            let snapshot = runtime.snapshot();
            assert!(snapshot.invocation_results.is_empty());
            assert_eq!(
                snapshot.clean_invocation_acknowledgements.len(),
                (sequence as usize).min(capacity)
            );
            assert_eq!(
                snapshot.sequenced_retired_through.get(linear),
                sequence.saturating_sub(capacity as u64)
            );
            if sequence == 1 {
                first = Some((work, authorization));
            }
            acknowledgements.push(acknowledgement);
            if sequence % 1_000 == 0 {
                runtime = reopen_checkpoint(&runtime);
            }
        }

        // The oldest identity is compacted: Invoke and ACK retries are both
        // refused as divergent, and neither the recovery nor the unseen path
        // can execute it, even under a fresh receipt for the same work.
        let (first_work, first_authorization) = first.unwrap();
        let before = encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(
            runtime.recover_clean_execution(&first_work, &first_authorization, 1),
            Err(InvocationError::DivergentInvocation)
        );
        assert_eq!(
            runtime.acknowledge_clean_invocation(&first_work, &first_authorization),
            Err(InvocationError::DivergentInvocation)
        );
        let mut resigned = clean_authority_receipt(&config, &first_work);
        resigned.selector.expires_at = 5;
        resigned.signature = authority_key().sign(&resigned.signing_bytes()).to_bytes();
        let resigned = InvocationAuthorization::AuthorityReceipt(resigned);
        assert_eq!(
            runtime.recover_clean_execution(&first_work, &resigned, 1),
            Err(InvocationError::DivergentInvocation),
            "re-authorizing a retired identity cannot make it unseen"
        );
        assert_eq!(
            runtime.retain_clean_unseen_expiry(&first_work, &resigned, 6),
            Err(InvocationError::DivergentInvocation),
            "nor can it mint an expiry fence claiming it never ran"
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);

        // The most recent `capacity` retirements keep exact ACK retries.
        let last = SequencedLinear::work(&template, &config, INVOCATIONS);
        assert_eq!(
            runtime
                .acknowledge_clean_invocation(&last.0, &last.1)
                .unwrap(),
            *acknowledgements.last().unwrap()
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), before);

        // An unsequenced fact is always kept exactly; the watermark never
        // absorbs it. At capacity it takes the room of the next position.
        let mut plain = template.clone();
        plain.invocation = crate::agent_sdk::InvocationId([0x77; 32]);
        let plain_authorization =
            InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(&config, &plain));
        let (invocation, ..) = runtime.resolve_clean_invocation(&plain).unwrap();
        let prior = runtime.prepare_execution_state(&invocation).unwrap();
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_clean_execution(
                &plain,
                &plain_authorization,
                &invocation,
                &mut reply,
                &prior,
                prior.clone(),
                1,
                None,
            )
            .unwrap();
        let full = encode_standard_runtime_state(&runtime.snapshot());
        // The oldest retained fact (sequence INVOCATIONS - capacity + 1) is the
        // next position, so the plain fact may replace it.
        runtime
            .acknowledge_clean_invocation(&plain, &plain_authorization)
            .unwrap();
        assert_ne!(encode_standard_runtime_state(&runtime.snapshot()), full);
        let reopened = reopen_checkpoint(&runtime);
        assert_eq!(
            reopened.snapshot().sequenced_retired_through.get(linear),
            INVOCATIONS - capacity as u64 + 1
        );

        // A hostile image may not retain a fact at or below its watermark.
        let mut hostile = reopened.snapshot();
        hostile.sequenced_retired_through.linear = INVOCATIONS;
        assert!(StandardAgentRuntime::restore(hostile).is_err());
        let mut legacy = sparse_standard_state();
        assert!(StandardAgentRuntime::restore(legacy.clone()).is_ok());
        legacy.sequenced_retired_through.control = 1;
        assert!(
            StandardAgentRuntime::restore(legacy).is_err(),
            "only a clean-generation image may carry a watermark"
        );
    }

    /// Helper namespace so a test can rebuild the exact work of a sequence.
    #[cfg(feature = "pvm")]
    struct SequencedLinear;

    #[cfg(feature = "pvm")]
    impl SequencedLinear {
        fn work(
            template: &crate::agent_sdk::InvocationWork,
            config: &AgentConfig,
            sequence: u64,
        ) -> (
            crate::agent_sdk::InvocationWork,
            crate::agent_sdk::InvocationAuthorization,
        ) {
            let mut work = template.clone();
            work.invocation = crate::agent_sdk::SequencedInvocation::new(
                crate::agent_sdk::InvocationResultStorage::Lane(
                    crate::agent_sdk::StateLane::Linear,
                ),
                core::num::NonZeroU64::new(sequence).unwrap(),
            )
            .invocation_id();
            let authorization = crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(
                clean_authority_receipt(config, &work),
            );
            (work, authorization)
        }
    }

    /// Compaction only takes the next position: a gap keeps the component
    /// fail-closed until it is filled, and filling it may retire the new fact
    /// itself straight into the watermark.
    #[cfg(feature = "pvm")]
    #[test]
    fn sequenced_compaction_waits_for_gaps_and_refuses_foreign_identities() {
        use crate::agent_sdk::{
            InvocationAuthorization, InvocationError, InvocationResultStorage,
            SEQUENCED_INVOCATION_PREFIX, SequencedInvocation,
        };

        let (mut runtime, template) = clean_resolvable_fixture(false);
        let config = runtime.config().unwrap().clone();
        let capacity = super::super::standard::MAX_INVOCATION_ACKNOWLEDGEMENTS_PER_LANE as u64;
        let linear = crate::agent::InvocationResultStorage::Lane(crate::agent::StateLane::Linear);
        // Sequence 1 stays unacknowledged while 2..=capacity+1 fill the component.
        let (first_work, first_authorization) =
            commit_sequenced_linear(&mut runtime, &config, &template, 1);
        for sequence in 2..=capacity + 1 {
            let (work, authorization) =
                commit_sequenced_linear(&mut runtime, &config, &template, sequence);
            runtime
                .acknowledge_clean_invocation(&work, &authorization)
                .unwrap();
        }
        let (next_work, next_authorization) =
            commit_sequenced_linear(&mut runtime, &config, &template, capacity + 2);
        let full = encode_standard_runtime_state(&runtime.snapshot());
        assert_eq!(
            runtime.acknowledge_clean_invocation(&next_work, &next_authorization),
            Err(InvocationError::ResultCapacity),
            "a gap at the next position keeps today's refusal"
        );
        assert_eq!(encode_standard_runtime_state(&runtime.snapshot()), full);

        // Filling the gap retires sequence 1 directly into the watermark.
        runtime
            .acknowledge_clean_invocation(&first_work, &first_authorization)
            .unwrap();
        assert_eq!(runtime.snapshot().sequenced_retired_through.get(linear), 1);
        assert_eq!(
            runtime.snapshot().clean_invocation_acknowledgements.len(),
            capacity as usize
        );
        assert_eq!(
            runtime.acknowledge_clean_invocation(&first_work, &first_authorization),
            Err(InvocationError::DivergentInvocation)
        );
        runtime
            .acknowledge_clean_invocation(&next_work, &next_authorization)
            .unwrap();
        assert_eq!(runtime.snapshot().sequenced_retired_through.get(linear), 2);
        let mut runtime = reopen_checkpoint(&runtime);

        // A Linear-component identity cannot be used from another component,
        // and a malformed sequenced prefix is never admitted.
        let mut foreign = template.clone();
        foreign.mode = crate::agent_sdk::MethodMode::Query;
        foreign.invocation = SequencedInvocation::new(
            InvocationResultStorage::Lane(crate::agent_sdk::StateLane::Linear),
            core::num::NonZeroU64::new(capacity + 10).unwrap(),
        )
        .invocation_id();
        let foreign_authorization =
            InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(&config, &foreign));
        assert_eq!(
            runtime.recover_clean_execution(&foreign, &foreign_authorization, 1),
            Err(InvocationError::DivergentInvocation)
        );
        let mut malformed = template.clone();
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&SEQUENCED_INVOCATION_PREFIX);
        bytes[16] = 1;
        malformed.invocation = crate::agent_sdk::InvocationId(bytes);
        let malformed_authorization =
            InvocationAuthorization::AuthorityReceipt(clean_authority_receipt(&config, &malformed));
        assert_eq!(
            runtime.recover_clean_execution(&malformed, &malformed_authorization, 1),
            Err(InvocationError::DivergentInvocation)
        );
    }

    #[test]
    fn sequenced_retirement_section_is_absent_until_used_and_canonical() {
        let state = sparse_standard_state();
        let plain = encode_standard_runtime_state(&state);
        assert!(
            !plain
                .control
                .windows(4)
                .any(|window| window == STANDARD_SEQUENCED_RETIREMENT_MAGIC)
        );
        let mut decoder_input = plain.clone();
        decoder_input
            .linear
            .extend_from_slice(&STANDARD_SEQUENCED_RETIREMENT_MAGIC);
        decoder_input.linear.extend_from_slice(&1u16.to_le_bytes());
        decoder_input.linear.extend_from_slice(&0u64.to_le_bytes());
        assert!(
            decode_standard_runtime_components(&decoder_input).is_err(),
            "a zero watermark is not canonical"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn more_than_32_system_projection_queries_restart_without_lifecycle_or_proof_capacity() {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::agent_sdk::authority::{
            AuthorityActorTarget, AuthorityIngressAuthentication, AuthorityProjectionQuery,
            AuthorityProjectionSelector,
        };
        use crate::agent_sdk::wire::CanonicalWire as _;
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight};

        let (runtime, template) = clean_resolvable_fixture(false);
        let mut state = runtime.snapshot();
        let actor = &state.actors[0].record;
        let mut descriptor = state.clean_descriptor.clone().unwrap();
        descriptor.authority.issuer.actor = crate::agent_sdk::ActorId(actor.entry.actor.0);
        descriptor.authority.issuer.deployment =
            crate::agent_sdk::DeploymentId(actor.entry.deployment.0);
        descriptor.authority.issuer.program = crate::agent_sdk::ProgramId(actor.entry.program.0);
        descriptor.validate().unwrap();
        state.config =
            Some(super::super::standard::clean_descriptor_to_legacy_config(&descriptor).unwrap());
        state.clean_creation_descriptor = Some(descriptor.clone());
        state.clean_descriptor = Some(descriptor.clone());
        let mut runtime = StandardAgentRuntime::restore(state).unwrap();
        let target = AuthorityActorTarget {
            space: descriptor.identity.space,
            system_agent: descriptor.identity.agent,
            system_runtime_deployment: descriptor.identity.runtime_deployment,
            binding: descriptor.authority,
        };
        let public_key = [0xd1; 32];

        let apply = |runtime: &mut StandardAgentRuntime, ordinal: u16| {
            let mut nonce = [0u8; 32];
            nonce[..2].copy_from_slice(&ordinal.to_be_bytes());
            nonce[31] = 1;
            let query = AuthorityProjectionQuery {
            recovery: None,
                authority: target,
                credential: crate::agent_sdk::CredentialId::of_public_key(&public_key),
                nonce: crate::agent_sdk::Hash(nonce),
                selector: AuthorityProjectionSelector::Credential,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [0xd2; 64],
                },
            };
            query.validate_shape().unwrap();
            let mut work = template.clone();
            work.invocation = crate::agent_sdk::InvocationId(
                crate::agent_sdk::Hash::digest(
                    b"vos/system-authority/projection-invocation/v2",
                    &[query.commitment().as_bytes()],
                )
                .0,
            );
            work.mode = crate::agent_sdk::MethodMode::Query;
            let mut message = vec![TAG_DYNAMIC];
            message.extend_from_slice(
                &Msg::new("credential_projection")
                    .with("query", query.encode().unwrap())
                    .encode(),
            );
            work.message = message;
            let authorization =
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(&work, 1));
            runtime
                .validate_clean_unseen_invocation_slot(&authorization, 1)
                .unwrap();
            let (invocation, ..) = runtime.resolve_clean_invocation(&work).unwrap();
            let before = runtime.prepare_execution_state(&invocation).unwrap();
            let after = before.clone();
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            runtime
                .commit_clean_execution(
                    &work,
                    &authorization,
                    &invocation,
                    &mut reply,
                    &before,
                    after,
                    1,
                    None,
                )
                .unwrap();
            runtime
                .acknowledge_clean_invocation(&work, &authorization)
                .unwrap();
            let snapshot = runtime.snapshot();
            assert!(snapshot.invocation_results.is_empty());
            assert!(snapshot.clean_invocation_acknowledgements.is_empty());
            assert!(matches!(
                authorization,
                InvocationAuthorization::PublicPreflight(_)
            ));
        };

        for ordinal in 1..=40 {
            apply(&mut runtime, ordinal);
        }
        let checkpoint = encode_standard_runtime_state(&runtime.snapshot());
        let mut reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&checkpoint).unwrap())
                .unwrap();
        assert_eq!(
            encode_standard_runtime_state(&reopened.snapshot()),
            checkpoint
        );
        for ordinal in 41..=80 {
            apply(&mut reopened, ordinal);
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn clean_result_restore_rejects_tampered_acceptance() {
        let (state, _, _, _) = clean_terminal_fixture();
        let decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();

        let mut wrong_origin = decoded.clone();
        wrong_origin.invocation_results[0]
            .clean
            .as_mut()
            .unwrap()
            .accepted
            .origin
            .actor = Some(crate::agent_sdk::ActorId([0xf3; 32]));
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&wrong_origin)),
            Err(DecodeError::NonCanonical),
            "terminal results must reconstruct the signed invocation metadata too"
        );

        let mut wrong_slot = decoded.clone();
        wrong_slot.invocation_results[0]
            .clean
            .as_mut()
            .unwrap()
            .observed_slot = 3;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&wrong_slot)),
            Err(DecodeError::NonCanonical),
            "the persisted acceptance slot must remain inside the signed window"
        );

        let mut forged_receipt = decoded.clone();
        let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) =
            &mut forged_receipt.invocation_results[0]
                .clean
                .as_mut()
                .unwrap()
                .authorization
        else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&forged_receipt)),
            Err(DecodeError::NonCanonical),
            "restore re-verifies the signature committed by the exact receipt"
        );

        let mut missing_high_water = decoded;
        missing_high_water.lane_revisions.linear_authority_slot = None;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&missing_high_water)),
            Err(DecodeError::NonCanonical),
            "a result binding cannot outrun its owning authority high-water"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn present_empty_installation_data_yields_persists_and_resumes_exactly() {
        let (runtime, mut work) = clean_resolvable_fixture(false);
        let mut snapshot = runtime.snapshot();
        let empty = crate::agent_sdk::RuntimeBlob {
            reference: crate::agent_sdk::BlobRef::of_bytes(&[]),
            bytes: Vec::new(),
        };
        let stored_empty = crate::service::BlobRef {
            hash: crate::service::Hash(empty.reference.hash.0),
            len: empty.reference.len,
        };
        snapshot.actors[0].record.entry.installation_data = Some(stored_empty.clone());
        snapshot.actors[0].record.installation_data = Some(stored_empty);
        let mut runtime = StandardAgentRuntime::restore(snapshot).unwrap();
        work.installation_data = Some(empty.reference.clone());
        work.availability.push(empty);
        work.availability
            .sort_unstable_by_key(|blob| blob.reference.clone());
        assert!(work.validate());
        let config = runtime.config().unwrap().clone();
        let authority = clean_authority_receipt(&config, &work);
        let authorization =
            crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority.clone());
        let (invocation, _, _, _, installation_data) =
            runtime.resolve_clean_invocation(&work).unwrap();
        runtime
            .validate_clean_execution_installation_data(&work, installation_data.as_ref())
            .unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        runtime
            .commit_yielded_execution(
                &invocation,
                &exact_reply(&invocation, ActorExecutionStatus::Yielded),
                &before,
                before.clone(),
                1,
                None,
                portable_continuation(&invocation, 1, 3).continuation,
                Some((
                    super::super::standard::StandardAcceptedInvocation::from_work(&work),
                    authorization.clone(),
                )),
            )
            .unwrap();
        let yielded = runtime
            .recover_clean_yield(&work, &authorization, 1)
            .unwrap()
            .unwrap();
        assert_eq!(yielded.installation_data, work.installation_data);
        assert!(yielded.validate());

        let mut missing_persisted_role = runtime.snapshot();
        missing_persisted_role.machine_continuations[0]
            .accepted
            .as_mut()
            .unwrap()
            .installation_data = None;
        assert!(matches!(
            StandardAgentRuntime::restore(missing_persisted_role),
            Err(super::super::LifecycleError::InvalidRequest)
        ));

        let encoded = encode_standard_runtime_state(&runtime.snapshot());
        let restarted =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&encoded).unwrap())
                .unwrap();
        assert_eq!(
            encode_standard_runtime_state(&restarted.snapshot()),
            encoded
        );
        let resume = clean_resume(&yielded, work.availability.clone());
        let (_, restored_work) = restarted.resolve_clean_resume(&resume).unwrap();
        assert_eq!(restored_work, work);

        let mut missing_role = resume;
        missing_role.installation_data = None;
        assert!(!missing_role.validate());
        assert_eq!(
            restarted.resolve_clean_resume(&missing_role),
            Err(crate::agent_sdk::InvocationError::StaleContinuation)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn restored_clean_continuation_rejects_a_forged_accepted_receipt() {
        let (state, _, _, _) = clean_pending_fixture();
        let (_, original, _, _) = clean_pending_fixture();
        let mut actor_origin = original.origin;
        actor_origin.actor = Some(crate::agent_sdk::ActorId([0xf1; 32]));
        let (legitimate, _, _, _) = clean_pending_fixture_with_origin(Some(actor_origin));
        assert!(
            StandardAgentRuntime::restore(
                decode_standard_runtime_state(&clean_state_to_legacy(&legitimate)).unwrap()
            )
            .is_ok(),
            "an actor origin bound by the original signature remains supported"
        );
        let mutations: &[fn(&mut super::super::standard::StandardAcceptedInvocation)] = &[
            |accepted| accepted.origin.principal = Some(crate::agent_sdk::PrincipalId([0xf2; 32])),
            |accepted| accepted.origin.transport_node = Some(crate::agent_sdk::NodeId([0xf2; 32])),
            |accepted| {
                accepted.origin.credential = Some(crate::agent_sdk::CredentialId([0xf2; 32]))
            },
            |accepted| accepted.message.push(0xf2),
            |accepted| accepted.gas += 1,
            |accepted| accepted.required[0].hash = crate::agent_sdk::Hash([0xf2; 32]),
        ];
        for mutate in mutations {
            let mut decoded =
                decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
            mutate(decoded.machine_continuations[0].accepted.as_mut().unwrap());
            assert!(
                matches!(
                    StandardAgentRuntime::restore(decoded),
                    Err(super::super::LifecycleError::InvalidRequest)
                ),
                "persisted metadata must reconstruct the signed invocation commitment"
            );
        }
        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        decoded.machine_continuations[0]
            .accepted
            .as_mut()
            .unwrap()
            .origin
            .actor = Some(crate::agent_sdk::ActorId([0xf1; 32]));
        assert!(
            matches!(
                StandardAgentRuntime::restore(decoded),
                Err(super::super::LifecycleError::InvalidRequest)
            ),
            "unsupported clean provenance cannot be smuggled through persisted state"
        );

        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(receipt) = decoded
            .machine_continuations[0]
            .authorization
            .as_mut()
            .unwrap()
        else {
            unreachable!()
        };
        receipt.signature[0] ^= 1;
        let encoded = encode_standard_runtime_state(&decoded);
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::NonCanonical)
        );

        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        decoded.machine_continuations[0].observed_slot = 3;
        let encoded = encode_standard_runtime_state(&decoded);
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::NonCanonical),
            "the immutable acceptance slot must remain inside its signed window"
        );

        let mut decoded = decode_standard_runtime_state(&clean_state_to_legacy(&state)).unwrap();
        decoded.lane_revisions.linear_authority_slot = None;
        let encoded = encode_standard_runtime_state(&decoded);
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::NonCanonical),
            "a clean continuation cannot outrun its owning authority high-water"
        );
    }

    #[cfg(feature = "pvm")]
    fn assert_only_result_component_changed(
        before: &RuntimeState,
        after: &RuntimeState,
        mode: MethodMode,
    ) {
        let changed = [
            before.control != after.control,
            before.linear != after.linear,
            before.merge != after.merge,
            before.local != after.local,
        ];
        let expected = match mode.result_storage() {
            super::super::InvocationResultStorage::Control => [true, false, false, false],
            super::super::InvocationResultStorage::Lane(StateLane::Linear) => {
                [false, true, false, false]
            }
            super::super::InvocationResultStorage::Lane(StateLane::Merge) => {
                [false, false, true, false]
            }
            super::super::InvocationResultStorage::Lane(StateLane::Local) => {
                [false, false, false, true]
            }
        };
        assert_eq!(changed, expected, "{mode:?}");
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn portable_continuations_restart_byte_identically_and_preserve_fifo() {
        let mut state = sparse_standard_state();
        let first = sparse_invocation(MethodMode::Linear, 0xd1);
        let second = sparse_invocation(MethodMode::Linear, 0xd2);
        state.machine_continuations = vec![
            portable_continuation(&first, 7, 3),
            portable_continuation(&second, 8, 4),
        ];

        let encoded = encode_standard_runtime_state(&state);
        let decoded = decode_standard_runtime_state(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(encode_standard_runtime_state(&decoded), encoded);

        let mut restarted = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            restarted.machine_continuation(&second),
            Err(ActorExecutionError::ContinuationNotReady)
        );
        let (sequence, restored_first) = restarted
            .machine_continuation(&first)
            .unwrap()
            .expect("FIFO head is ready after restart");
        assert_eq!(sequence, 7);
        assert_eq!(
            restored_first,
            portable_continuation(&first, 7, 3).continuation
        );
        let before = restarted.prepare_execution_state(&first).unwrap();
        let mut after = before.clone();
        after.linear = Some(vec![0xe1]);
        restarted
            .commit_yielded_execution(
                &first,
                &exact_reply(&first, ActorExecutionStatus::Yielded),
                &before,
                after,
                20,
                Some(sequence),
                portable_continuation(&first, 1, 5).continuation,
                None,
            )
            .unwrap();
        assert_eq!(
            restarted.machine_continuation(&first),
            Err(ActorExecutionError::ContinuationNotReady),
            "a repeatedly-yielded slice moves to its component's FIFO tail"
        );
        assert_eq!(
            restarted
                .machine_continuation(&second)
                .unwrap()
                .map(|(sequence, _)| sequence),
            Some(8)
        );
        assert_eq!(
            restarted
                .snapshot()
                .machine_continuations
                .iter()
                .map(|record| (record.invocation, record.ready_sequence))
                .collect::<Vec<_>>(),
            vec![(second.invocation, 8), (first.invocation, 9)]
        );
        let restarted_bytes = encode_standard_runtime_state(&restarted.snapshot());
        assert_eq!(
            encode_standard_runtime_state(
                &decode_standard_runtime_state(&restarted_bytes).unwrap()
            ),
            restarted_bytes
        );
    }

    #[cfg(feature = "pvm")]
    fn exact_clock_successor(
        before: &StandardRuntimeState,
        mode: MethodMode,
        observed_slot: u64,
    ) -> StandardRuntimeState {
        let mut expected = before.clone();
        match mode.result_storage() {
            super::super::InvocationResultStorage::Control => {
                expected.control_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Linear) => {
                expected.lane_revisions.linear_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Merge) => {
                expected.lane_revisions.merge_authority_slot = Some(observed_slot);
            }
            super::super::InvocationResultStorage::Lane(StateLane::Local) => {
                expected.lane_revisions.local_authority_slot = Some(observed_slot);
            }
        }
        expected
    }

    #[cfg(feature = "pvm")]
    fn signed_invocation_receipt(
        config: &AgentConfig,
        invocation: &ActorInvocation,
        valid_from: u64,
        valid_until: u64,
    ) -> crate::agent::authority::ActorInvocationReceipt {
        let claim = crate::agent::authority::ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from,
            valid_until,
        };
        crate::agent::authority::ActorInvocationReceipt {
            signature: authority_key()
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        }
    }

    #[cfg(feature = "pvm")]
    fn forbidden_execution_call(observed_slot: u64, valid_until: u64) -> RuntimeExecutionCall {
        use crate::actors::codec::Encode as _;
        use crate::actors::value::{Msg, TAG_DYNAMIC};
        use crate::service::{MethodPolicy, method_authorization_policy_hash};

        let mut state = sparse_standard_state();
        let actor_pvm = vec![0x21, 0x22, 0x23];
        let program = ProgramId::of_pvm(&actor_pvm);
        let (schema, schema_len) =
            crate::agent::schema::encode::<512>(&crate::agent::schema::SchemaMeta {
                uses_storage: false,
                fields: &[],
                methods: &[crate::agent::schema::MethodMeta {
                    name: "private_call",
                    mode: MethodMode::Linear,
                    explicit: true,
                }],
            });
        let schema = schema[..schema_len].to_vec();
        let parsed = crate::agent::schema::decode(&schema).unwrap();
        let capability = CapabilityId::named("private.call");
        let policies = crate::service::PackageRolePolicies {
            methods: vec![MethodPolicy {
                method: "private_call".into(),
                schema: Hash([0x91; 32]),
                policy: method_authorization_policy_hash(Some(capability), None, None).unwrap(),
                public: false,
                attested: false,
                space_role: None,
                capability: Some(capability),
                actor_role: None,
            }],
            task_dependencies: Vec::new(),
        }
        .encode();
        let schema_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(&schema),
            bytes: schema,
        };
        let policy_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(&policies),
            bytes: policies,
        };
        let actor = &mut state.actors[0].record;
        actor.entry.program = program;
        actor.entry.agent_schema = schema_blob.reference.clone();
        actor.agent_schema = schema_blob.reference.clone();
        actor.entry.role_policies = policy_blob.reference.clone();
        actor.role_policies = policy_blob.reference.clone();
        actor.entry.state_layout = parsed.state_layout_hash();
        actor.state_layout = parsed.state_layout_hash();
        actor.entry.lanes = parsed.lanes();
        actor.requirements.lanes = parsed.lanes();
        let mut message = vec![TAG_DYNAMIC];
        message.extend_from_slice(&Msg::new("private_call").encode());
        let invocation = ActorInvocation {
            invocation: crate::service::InvocationId([0x92; 32]),
            actor: actor.entry.actor,
            incarnation: actor.state_generation,
            deployment: actor.entry.deployment,
            program,
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message,
            availability: Vec::new(),
            gas: 100,
        };
        let authority =
            signed_invocation_receipt(state.config.as_ref().unwrap(), &invocation, 0, valid_until);
        RuntimeExecutionCall {
            state: encode_standard_runtime_state(&state),
            invocation,
            authority,
            observed_slot,
            recovery_only: false,
            actor_pvm,
            actor_schema: schema_blob,
            actor_policies: policy_blob,
            installation_data: None,
        }
    }

    #[cfg(feature = "pvm")]
    fn unsupported_result_storage_call(observed_slot: u64) -> RuntimeExecutionCall {
        let mut call = forbidden_execution_call(observed_slot, observed_slot.saturating_add(10));
        let mut state = decode_standard_runtime_state(&call.state).unwrap();
        {
            let config = state.config.as_mut().unwrap();
            config.identity.profile = AgentProfile::Private;
            config.capabilities.lanes =
                LaneSet::of(StateLane::Merge).union(LaneSet::of(StateLane::Local));
            for replica in &mut config.replicas {
                replica.principal = config.identity.owner;
                replica.role = ReplicaRole::Observer;
            }
        }
        let actor = &mut state.actors[0].record;
        actor.entry.lanes = LaneSet::of(StateLane::Merge);
        actor.requirements.lanes = LaneSet::of(StateLane::Merge);
        state.lane_state.linear.clear();
        state.lane_revisions = Default::default();
        call.invocation.mode = MethodMode::LinearizableQuery;
        call.authority = signed_invocation_receipt(
            state.config.as_ref().unwrap(),
            &call.invocation,
            0,
            observed_slot.saturating_add(10),
        );
        call.state = encode_standard_runtime_state(&state);
        call
    }

    #[test]
    fn sparse_lane_state_persists_rows_outside_inline_and_rejects_old_framing() {
        let mut state = sparse_standard_state();
        let entry = &mut state.lane_state.linear[0];
        entry.value.clear();
        entry.rows.insert(
            b"s/rows/a".to_vec(),
            vec![7; crate::actors::storage::MAX_VALUE_BYTES],
        );
        entry.rows.insert(b"s/rows/b".to_vec(), Vec::new());
        let encoded = encode_standard_runtime_state(&state);
        assert!(encoded.linear.len() > super::super::execution::MAX_EXECUTION_STATE_BYTES);
        assert_eq!(decode_standard_runtime_state(&encoded).unwrap(), state);
        let restored =
            super::super::standard::StandardAgentRuntime::restore(state.clone()).unwrap();
        assert_eq!(restored.snapshot().lane_state, state.lane_state);

        let mut old = encoded.clone();
        old.linear.drain(32..36);
        assert_eq!(
            decode_standard_runtime_state(&old),
            Err(DecodeError::InvalidPlatform)
        );
        // Keeping the new lane marker cannot turn an old inline payload into
        // a row image. Neither wrong magic nor wrong inner ABI has a fallback.
        let image_start = 32 + 4 + 1 + 8 + 1 + 4 + 32 + 32 + 4;
        for offset in [image_start, image_start + 4] {
            let mut corrupt = encoded.clone();
            corrupt.linear[offset] ^= 1;
            assert!(decode_standard_runtime_state(&corrupt).is_err());
        }
        state.lane_state.linear[0].rows.insert(
            b"s/rows/c".to_vec(),
            vec![0; crate::actors::storage::MAX_VALUE_BYTES + 1],
        );
        assert!(decode_standard_runtime_state(&encode_standard_runtime_state(&state)).is_err());
        assert!(super::super::standard::StandardAgentRuntime::restore(state).is_err());
    }

    #[test]
    fn sparse_lane_state_round_trips_and_missing_is_the_only_empty_encoding() {
        let state = sparse_standard_state();
        let encoded = encode_standard_runtime_state(&state);
        assert_eq!(decode_standard_runtime_state(&encoded).unwrap(), state);

        let mut missing = state.clone();
        missing.lane_state.linear.clear();
        let encoded_missing = encode_standard_runtime_state(&missing);
        assert_eq!(
            decode_standard_runtime_state(&encoded_missing).unwrap(),
            missing,
            "a supported missing entry is canonical fresh-empty state"
        );

        let mut explicit_empty = state.clone();
        explicit_empty.lane_state.linear[0].value.clear();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&explicit_empty)),
            Err(DecodeError::NonCanonical),
            "explicit empty and missing must never encode the same logical state"
        );
    }

    #[test]
    fn install_commitments_and_retired_ids_are_canonical_durable_state() {
        let mut state = sparse_standard_state();
        let active_id = state.actors[0].record.installation_id;
        state.retired_installation_ids = vec![
            crate::service::InstallationId([0x91; 32]),
            crate::service::InstallationId([0x92; 32]),
        ];
        let encoded = encode_standard_runtime_state(&state);
        assert_eq!(decode_standard_runtime_state(&encoded).unwrap(), state);

        let mut zero_commitment = state.clone();
        zero_commitment.actors[0].record.install_request_commitment = Hash::ZERO;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&zero_commitment)),
            Err(DecodeError::NonCanonical)
        );

        let mut zero_tombstone = state.clone();
        zero_tombstone.retired_installation_ids[0] = crate::service::InstallationId::ZERO;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&zero_tombstone)),
            Err(DecodeError::NonCanonical)
        );

        let mut duplicate_tombstone = state.clone();
        duplicate_tombstone.retired_installation_ids[1] =
            duplicate_tombstone.retired_installation_ids[0];
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&duplicate_tombstone)),
            Err(DecodeError::NonCanonical)
        );

        let mut unsorted_tombstones = state.clone();
        unsorted_tombstones.retired_installation_ids.reverse();
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&unsorted_tombstones)),
            Err(DecodeError::NonCanonical)
        );

        let mut active_and_retired = state;
        active_and_retired.retired_installation_ids = vec![active_id];
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&active_and_retired)),
            Err(DecodeError::NonCanonical),
            "one installation identity cannot be both live and retired"
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn exact_terminal_and_error_outcomes_commit_only_the_result_clock() {
        let base = sparse_standard_state();
        let before = encode_standard_runtime_state(&base);
        let modes = [
            MethodMode::Query,
            MethodMode::LinearizableQuery,
            MethodMode::Linear,
            MethodMode::Merge,
            MethodMode::LocalQuery,
            MethodMode::Local,
        ];

        for (index, status) in [
            ActorExecutionStatus::Forbidden,
            ActorExecutionStatus::Panicked,
            ActorExecutionStatus::OutOfGas,
        ]
        .into_iter()
        .enumerate()
        {
            let mode = modes[index * 2];
            let invocation = sparse_invocation(mode, 0xa0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Ok(exact_reply(&invocation, status));
            assert!(finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                40,
                None,
                &mut result,
            ));
            let snapshot = runtime.snapshot();
            assert_eq!(snapshot, exact_clock_successor(&base, mode, 40));
            assert!(snapshot.invocation_results.is_empty());
            assert_eq!(snapshot.lane_state, base.lane_state);
            assert_eq!(
                (
                    snapshot.lane_revisions.linear,
                    snapshot.lane_revisions.merge,
                    snapshot.lane_revisions.local,
                ),
                (
                    base.lane_revisions.linear,
                    base.lane_revisions.merge,
                    base.lane_revisions.local,
                )
            );
            let after = encode_standard_runtime_state(&snapshot);
            assert_only_result_component_changed(&before, &after, mode);
            let reopened =
                StandardAgentRuntime::restore(decode_standard_runtime_state(&after).unwrap())
                    .unwrap();
            assert_eq!(reopened.snapshot(), snapshot);
        }

        let durable_errors = [
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ];
        for (index, error) in durable_errors.into_iter().enumerate() {
            let mode = modes[index % modes.len()];
            let invocation = sparse_invocation(mode, 0xb0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Err(error);
            assert!(finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                41,
                None,
                &mut result,
            ));
            let snapshot = runtime.snapshot();
            assert_eq!(
                snapshot,
                exact_clock_successor(&base, mode, 41),
                "{error:?}"
            );
            assert!(snapshot.invocation_results.is_empty(), "{error:?}");
            assert_eq!(snapshot.lane_state, base.lane_state, "{error:?}");
            assert_only_result_component_changed(
                &before,
                &encode_standard_runtime_state(&snapshot),
                mode,
            );
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn done_keeps_its_guest_result_and_lane_commit() {
        let base = sparse_standard_state();
        let before_encoded = encode_standard_runtime_state(&base);
        let invocation = sparse_invocation(MethodMode::Linear, 0xaf);
        let mut runtime = StandardAgentRuntime::restore(base.clone()).unwrap();
        let before = runtime.prepare_execution_state(&invocation).unwrap();
        let mut after = before.visible_for(invocation.mode);
        after.linear = Some(vec![0xd0]);
        let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
        runtime
            .commit_execution(&invocation, &mut reply, &before, after, 40)
            .unwrap();

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.invocation_results.len(), 1);
        assert_eq!(snapshot.invocation_results[0].reply, reply);
        assert_eq!(
            snapshot.lane_revisions.linear,
            base.lane_revisions.linear + 1
        );
        assert_eq!(snapshot.lane_revisions.linear_authority_slot, Some(40));
        assert_eq!(snapshot.lane_state.linear[0].value, vec![0xd0]);
        assert_only_result_component_changed(
            &before_encoded,
            &encode_standard_runtime_state(&snapshot),
            MethodMode::Linear,
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_execution_refuses_a_candidate_past_the_signed_state_ceiling() {
        fn done_candidate(
            state: StandardRuntimeState,
        ) -> (
            RuntimeState,
            StandardAgentRuntime,
            Result<ActorExecutionReply, ActorExecutionError>,
        ) {
            let original = encode_standard_runtime_state(&state);
            let invocation = sparse_invocation(MethodMode::Linear, 0x90);
            let mut runtime = StandardAgentRuntime::restore(state).unwrap();
            let before = runtime.prepare_execution_state(&invocation).unwrap();
            let mut after = before.visible_for(invocation.mode);
            after.linear = Some(vec![0x2a]);
            let mut reply = exact_reply(&invocation, ActorExecutionStatus::Done);
            runtime
                .commit_execution(&invocation, &mut reply, &before, after, 50)
                .unwrap();
            (original, runtime, Ok(reply))
        }

        let hard_limit = super::super::execution::MAX_RUNTIME_STATE_BYTES;
        let base = sparse_standard_state();
        let (hard_before, hard_candidate, mut accepted_result) = done_candidate(base.clone());
        let hard_before_len = hard_before.encoded_len().unwrap();
        let accepted = finish_standard_execution_candidate(
            hard_before,
            &hard_candidate,
            true,
            hard_limit,
            &mut accepted_result,
        );
        assert!(matches!(
            accepted_result,
            Ok(ActorExecutionReply {
                status: ActorExecutionStatus::Done,
                ..
            })
        ));
        let candidate_len = accepted.encoded_len().unwrap();
        assert!(candidate_len > hard_before_len);
        assert!(candidate_len <= hard_limit);
        let accepted_state = decode_standard_runtime_state(&accepted).unwrap();
        assert_eq!(accepted_state.invocation_results.len(), 1);
        assert_eq!(accepted_state.lane_state.linear[0].value, vec![0x2a]);

        let signed_limit = u32::try_from(candidate_len - 1).unwrap();
        let mut constrained_state = base;
        constrained_state
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = signed_limit;
        let (before, constrained_candidate, mut constrained_result) =
            done_candidate(constrained_state);
        assert_eq!(before.encoded_len(), Some(hard_before_len));
        assert!(hard_before_len <= signed_limit as usize);
        let before_decoded = decode_standard_runtime_state(&before).unwrap();
        assert_eq!(
            before_decoded
                .config
                .as_ref()
                .unwrap()
                .runtime_contract
                .resources
                .max_runtime_state_bytes,
            signed_limit
        );

        let returned = finish_standard_execution_candidate(
            before.clone(),
            &constrained_candidate,
            true,
            signed_limit as usize,
            &mut constrained_result,
        );
        assert_eq!(constrained_result, Err(ActorExecutionError::ResultCapacity));
        assert_eq!(returned, before);
        assert_eq!(
            decode_standard_runtime_state(&returned).unwrap(),
            before_decoded
        );
        assert_eq!(before_decoded.lane_revisions.linear_authority_slot, None);
        assert!(before_decoded.invocation_results.is_empty());
        assert_eq!(before_decoded.lane_state.linear[0].value, vec![0x89]);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn unavailable_admission_and_inconsistent_errors_commit_nothing() {
        let base = sparse_standard_state();
        for (index, error) in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
        ]
        .into_iter()
        .enumerate()
        {
            let invocation = sparse_invocation(MethodMode::Linear, 0xc0 + index as u8);
            let pristine = StandardAgentRuntime::restore(base.clone()).unwrap();
            let mut runtime = pristine.clone();
            runtime.commit_exact_outcome_clock(&invocation, 99).unwrap();
            let mut result = Err(error);
            assert!(!finalize_unseen_standard_outcome(
                &mut runtime,
                pristine,
                &invocation,
                42,
                None,
                &mut result,
            ));
            assert_eq!(runtime.snapshot(), base, "{error:?}");
        }
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn unsupported_result_storage_is_pre_admission_and_never_commits_a_clock() {
        let call = unsupported_result_storage_call(43);
        let before = call.state.clone();
        let returned = apply_standard_execution(call).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::UnsupportedResultStorage)
        );
        assert_eq!(returned.state, before);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(decoded.control_authority_slot, None);
        assert_eq!(decoded.lane_revisions.linear_authority_slot, None);
        assert_eq!(decoded.lane_revisions.merge_authority_slot, None);
        assert_eq!(decoded.lane_revisions.local_authority_slot, None);
        assert!(decoded.invocation_results.is_empty());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn forbidden_checks_freshness_then_persists_its_clock_across_restart() {
        let expired = forbidden_execution_call(31, 30);
        let original = expired.state.clone();
        let returned = apply_standard_execution(expired).unwrap();
        assert_eq!(returned.result, Err(ActorExecutionError::AuthorityExpired));
        assert_eq!(returned.state, original);

        let admitted = forbidden_execution_call(30, 100);
        let before = admitted.state.clone();
        let returned = apply_standard_execution(admitted.clone()).unwrap();
        assert!(matches!(
            returned.result,
            Ok(ActorExecutionReply {
                status: ActorExecutionStatus::Forbidden,
                ..
            })
        ));
        assert_only_result_component_changed(&before, &returned.state, MethodMode::Linear);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(
            decoded,
            exact_clock_successor(
                &decode_standard_runtime_state(&before).unwrap(),
                MethodMode::Linear,
                30,
            )
        );
        assert_eq!(decoded.lane_revisions.linear_authority_slot, Some(30));
        assert!(decoded.invocation_results.is_empty());

        let reopened = encode_standard_runtime_state(
            &StandardAgentRuntime::restore(decoded).unwrap().snapshot(),
        );
        assert_eq!(reopened, returned.state);
        let mut regressed = admitted;
        regressed.state = reopened;
        regressed.observed_slot = 29;
        regressed.invocation.invocation = crate::service::InvocationId([0x93; 32]);
        regressed.authority = signed_invocation_receipt(
            sparse_standard_state().config.as_ref().unwrap(),
            &regressed.invocation,
            0,
            100,
        );
        let prior = regressed.state.clone();
        let returned = apply_standard_execution(regressed).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::AuthoritySlotRegressed)
        );
        assert_eq!(returned.state, prior);
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn durable_target_errors_commit_a_clock_but_unavailable_and_auth_failures_do_not() {
        let mut missing = forbidden_execution_call(20, 100);
        missing.invocation.actor = ActorId([0xe1; 32]);
        missing.authority = signed_invocation_receipt(
            sparse_standard_state().config.as_ref().unwrap(),
            &missing.invocation,
            0,
            100,
        );
        let before = missing.state.clone();
        let returned = apply_standard_execution(missing).unwrap();
        assert_eq!(returned.result, Err(ActorExecutionError::NotFound));
        assert_only_result_component_changed(&before, &returned.state, MethodMode::Linear);
        let decoded = decode_standard_runtime_state(&returned.state).unwrap();
        assert_eq!(
            decoded,
            exact_clock_successor(
                &decode_standard_runtime_state(&before).unwrap(),
                MethodMode::Linear,
                20,
            )
        );
        assert_eq!(decoded.lane_revisions.linear_authority_slot, Some(20));
        assert!(decoded.invocation_results.is_empty());

        let mut unavailable = forbidden_execution_call(21, 100);
        unavailable.recovery_only = true;
        unavailable.actor_pvm.clear();
        unavailable.actor_schema = RuntimeBlob {
            reference: BlobRef {
                hash: Hash::ZERO,
                len: 0,
            },
            bytes: Vec::new(),
        };
        unavailable.actor_policies = unavailable.actor_schema.clone();
        let before = unavailable.state.clone();
        let returned = apply_standard_execution(unavailable).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::InvalidAvailability)
        );
        assert_eq!(returned.state, before);

        let mut forged = forbidden_execution_call(22, 100);
        forged.authority.signature[0] ^= 1;
        let before = forged.state.clone();
        let returned = apply_standard_execution(forged).unwrap();
        assert_eq!(
            returned.result,
            Err(ActorExecutionError::InvalidAuthorization)
        );
        assert_eq!(returned.state, before);
    }

    #[test]
    fn sparse_lane_state_rejects_duplicate_unsorted_and_oversized_cardinality() {
        let state = sparse_standard_state();
        let mut duplicate = state.clone();
        duplicate
            .lane_state
            .linear
            .push(duplicate.lane_state.linear[0].clone());
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&duplicate)),
            Err(DecodeError::NonCanonical)
        );

        let mut unsorted = state.clone();
        unsorted.lane_state.linear = vec![
            StandardLaneEntry {
                actor: ActorId([2; 32]),
                state_generation: Hash([1; 32]),
                value: vec![1],
                rows: Default::default(),
            },
            StandardLaneEntry {
                actor: ActorId([1; 32]),
                state_generation: Hash([1; 32]),
                value: vec![2],
                rows: Default::default(),
            },
        ];
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&unsorted)),
            Err(DecodeError::NonCanonical)
        );

        let mut zero_generation = state.clone();
        zero_generation.lane_state.linear[0].state_generation = Hash::ZERO;
        assert_eq!(
            decode_standard_runtime_state(&encode_standard_runtime_state(&zero_generation)),
            Err(DecodeError::NonCanonical)
        );

        let mut encoded = encode_standard_runtime_state(&state);
        const LANE_LIST_OFFSET: usize = 32 + 4 + 1 + 8 + 1;
        encoded.linear[LANE_LIST_OFFSET..LANE_LIST_OFFSET + 4].copy_from_slice(
            &u32::try_from(super::super::standard::MAX_LANE_STATE_ENTRIES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert_eq!(
            decode_standard_runtime_state(&encoded),
            Err(DecodeError::LimitExceeded),
            "declared lane cardinality is rejected before entry allocation"
        );
    }

    #[test]
    fn lifecycle_call_round_trips_with_opaque_runtime_state() {
        let call = RuntimeCall::new(
            RuntimeState {
                control: vec![11],
                linear: vec![12],
                merge: vec![13],
                local: vec![14],
            },
            LifecycleRequest::Create(config()),
        );
        let encoded = call.encode();
        assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
    }

    #[test]
    fn install_wire_requires_and_preserves_exact_registry_identity() {
        let state = sparse_standard_state();
        let record = &state.actors[0].record;
        let install = super::super::InstallActor {
            installation_id: record.installation_id,
            registry_reservation: record.registry_reservation,
            entry: record.entry.clone(),
            producer: record.producer,
            package: record.package.clone(),
            agent_schema: record.agent_schema.clone(),
            role_policies: record.role_policies.clone(),
            constructor_abi: record.constructor_abi,
            installation_data: None,
            state_layout: record.state_layout,
            contract: record.contract,
            requirements: record.requirements,
        };
        let call = RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Install(install.clone()),
        );
        assert_eq!(RuntimeCall::decode(&call.encode()), Ok(call.clone()));

        let empty_reference = BlobRef::of_bytes(&[]);
        let mut present_empty_install = install;
        present_empty_install.entry.installation_data = Some(empty_reference.clone());
        present_empty_install.installation_data = Some(super::super::InstallationData {
            reference: empty_reference,
            bytes: Vec::new(),
        });
        let present_empty = RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Install(present_empty_install.clone()),
        );
        assert_eq!(
            RuntimeCall::decode(&present_empty.encode()),
            Ok(present_empty.clone())
        );
        assert_ne!(
            present_empty.request.commitment(),
            call.request.commitment()
        );

        let mut mismatched = present_empty;
        let LifecycleRequest::Install(install) = &mut mismatched.request else {
            unreachable!()
        };
        install.installation_data.as_mut().unwrap().reference = BlobRef::of_bytes(&[1]);
        install.entry.installation_data = install
            .installation_data
            .as_ref()
            .map(|data| data.reference.clone());
        assert_eq!(
            RuntimeCall::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut zero_id = call.clone();
        let LifecycleRequest::Install(install) = &mut zero_id.request else {
            unreachable!()
        };
        install.installation_id = crate::service::InstallationId::ZERO;
        assert_eq!(
            RuntimeCall::decode(&zero_id.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut zero_reservation = call;
        let LifecycleRequest::Install(install) = &mut zero_reservation.request else {
            unreachable!()
        };
        install.registry_reservation = Hash::ZERO;
        assert_eq!(
            RuntimeCall::decode(&zero_reservation.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn installation_data_decoder_rejects_hostile_declared_lengths_before_copying() {
        let mut declared_oversize = Vec::new();
        encode_blob(
            &mut Encoder(&mut declared_oversize),
            &BlobRef {
                hash: Hash([0x71; 32]),
                len: (super::super::MAX_INSTALLATION_DATA_BYTES + 1) as u64,
            },
        );
        Encoder(&mut declared_oversize).u32((super::super::MAX_INSTALLATION_DATA_BYTES + 1) as u32);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&declared_oversize)),
            Err(DecodeError::LimitExceeded)
        );

        let mut truncated = Vec::new();
        encode_blob(&mut Encoder(&mut truncated), &BlobRef::of_bytes(&[0x72]));
        Encoder(&mut truncated).u32(1);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&truncated)),
            Err(DecodeError::Truncated)
        );

        let mut mismatched = Vec::new();
        encode_blob(&mut Encoder(&mut mismatched), &BlobRef::of_bytes(&[]));
        Encoder(&mut mismatched).bytes(&[0x73]);
        assert_eq!(
            decode_installation_data(&mut Decoder::new(&mismatched)),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn journal_context_round_trips_but_zero_ids_are_noncanonical() {
        let scope = super::super::system_authority::SystemAuthorityJournalScope::for_test(
            super::super::journal::AgentJournalGenesisId::new([0x31; 32]),
            super::super::genesis::AgentGenesisAdmissionId::from_bytes([0x32; 32]),
        )
        .unwrap();
        let call = RuntimeCall::scoped_system_authority(
            RuntimeState::default(),
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
            scope,
        );
        let encoded = call.encode();
        let decoded = RuntimeCall::decode(&encoded).unwrap();
        assert_eq!(decoded, call);
        assert!(
            decoded
                .journal_context()
                .unwrap()
                .matches_system_authority_scope(scope)
        );

        // ServiceWire header (36) + runtime ABI (32) + Some tag (1).
        let mut zero_genesis = encoded.clone();
        zero_genesis[69..101].fill(0);
        assert_eq!(
            RuntimeCall::decode(&zero_genesis),
            Err(DecodeError::NonCanonical)
        );
        let mut zero_admission = encoded;
        zero_admission[101..133].fill(0);
        assert_eq!(
            RuntimeCall::decode(&zero_admission),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn direct_system_authority_payloads_are_bounded_before_nested_decode() {
        for (tag, maximum) in [
            (
                10,
                super::super::system_authority::MAX_SYSTEM_AUTHORITY_FINALIZE_BYTES,
            ),
            (
                11,
                super::super::system_authority::MAX_SYSTEM_AUTHORITY_ROTATION_BYTES,
            ),
            (
                12,
                super::super::system_authority::MAX_SYSTEM_AUTHORITY_CATALOG_FINALIZE_BYTES,
            ),
        ] {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&RuntimeCall::MAGIC);
            encoded.extend_from_slice(&crate::service::PLATFORM_ID.0);
            {
                let mut encoder = Encoder(&mut encoded);
                encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
                encoder.bool(false);
                encode_runtime_state(&mut encoder, &RuntimeState::default());
                encoder.u8(tag);
                encoder.u32(u32::try_from(maximum + 1).unwrap());
            }
            encoded.resize(encoded.len() + maximum + 1, 0);
            assert_eq!(
                RuntimeCall::decode(&encoded),
                Err(DecodeError::LimitExceeded)
            );
        }
    }

    #[test]
    fn system_authority_genesis_and_state_are_bounded_before_nested_decode() {
        let config = config();
        let genesis_maximum = super::super::system_authority::MAX_SYSTEM_AUTHORITY_GENESIS_BYTES;
        let mut encoded_config = Vec::new();
        encoded_config.extend_from_slice(&AgentConfig::MAGIC);
        encoded_config.extend_from_slice(&crate::service::PLATFORM_ID.0);
        {
            let mut encoder = Encoder(&mut encoded_config);
            encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
            encode_identity(&mut encoder, &config.identity);
            encoder.fixed(&config.creation_nonce.0);
            super::super::authority::encode_binding(&mut encoder, &config.authority);
            encoder.bool(true);
            encoder.u32(u32::try_from(genesis_maximum + 1).unwrap());
        }
        encoded_config.resize(encoded_config.len() + genesis_maximum + 1, 0);
        assert_eq!(
            AgentConfig::decode(&encoded_config),
            Err(DecodeError::LimitExceeded),
            "an oversized nested genesis is rejected before its body is decoded"
        );

        let state_maximum = super::super::system_authority::MAX_SYSTEM_AUTHORITY_STATE_BYTES;
        let mut control = Vec::new();
        {
            let mut encoder = Encoder(&mut control);
            encoder.fixed(&super::super::RUNTIME_ABI_ID.0);
            // Absent config, clean creation/current descriptors, and clean
            // epoch/sequence high-water marks precede system authority.
            for _ in 0..5 {
                encoder.bool(false);
            }
            encoder.u64(0); // clean acknowledged-through
            encoder.u32(0); // clean management dispositions
            // Active policy and four Private control/high-water options.
            for _ in 0..5 {
                encoder.bool(false);
            }
            encoder.u32(0); // Private management dispositions
            encoder.bool(true);
            encoder.u32(u32::try_from(state_maximum + 1).unwrap());
        }
        control.resize(control.len() + state_maximum + 1, 0);
        let state = RuntimeState {
            control,
            linear: vec![1],
            merge: vec![1],
            local: vec![1],
        };
        assert_eq!(
            decode_standard_runtime_state(&state),
            Err(DecodeError::LimitExceeded),
            "an oversized nested authority state is rejected before its body is decoded"
        );
    }

    #[test]
    fn suspend_and_resume_wire_bind_the_expected_deployment() {
        let state = RuntimeState {
            control: vec![11],
            linear: vec![12],
            merge: vec![13],
            local: vec![14],
        };
        let actor = ActorId([0x31; 32]);
        let expected_deployment = DeploymentId([0x32; 32]);
        for request in [
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            },
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            },
        ] {
            let call = RuntimeCall::new(state.clone(), request);
            let encoded = call.encode();
            assert_eq!(RuntimeCall::decode(&encoded).unwrap(), call);
            assert_eq!(
                RuntimeCall::decode(&encoded[..encoded.len() - 32]),
                Err(DecodeError::Truncated),
                "the retired ActorId-only lifecycle wire is not accepted"
            );
        }
    }

    #[test]
    fn lifecycle_wire_rejects_nested_authorized_envelopes() {
        let config = config();
        let request = LifecycleRequest::Suspend {
            actor: ActorId([0x35; 32]),
            expected_deployment: DeploymentId([0x36; 32]),
        };
        let admission = super::super::LifecycleAuthorityAdmission {
            receipt: crate::agent::authority::AgentAuthorityReceipt {
                claim: crate::agent::authority::AgentAuthorityClaim {
                    authority: config.authority,
                    space: config.identity.space,
                    agent: config.identity.agent,
                    principal: config.identity.owner,
                    credential: crate::service::CredentialId([0x32; 32]),
                    capability: CapabilityId::named("actor.lifecycle"),
                    operation: request.commitment(),
                    sequence: 1,
                    valid_from: 0,
                    valid_until: 20,
                },
                signature: vec![0; crate::agent::authority::ED25519_SIGNATURE_BYTES],
            },
            observed_slot: 10,
        };
        let call = RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Authorized {
                admission: admission.clone(),
                request: alloc::boxed::Box::new(LifecycleRequest::Authorized {
                    admission,
                    request: alloc::boxed::Box::new(request),
                }),
            },
        );
        assert_eq!(
            RuntimeCall::decode(&call.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn directory_round_trip_preserves_schema_provenance() {
        let package = BlobRef {
            hash: Hash([0x26; 32]),
            len: 124,
        };
        let role_policies = BlobRef {
            hash: Hash([0x27; 32]),
            len: 125,
        };
        let entry = ActorEntry {
            actor: ActorId([0x21; 32]),
            name: "counter".into(),
            parent: None,
            deployment: DeploymentId([0x22; 32]),
            program: ProgramId([0x23; 32]),
            package,
            agent_schema: BlobRef {
                hash: Hash([0x24; 32]),
                len: 123,
            },
            role_policies,
            constructor_abi: Hash([0x28; 32]),
            installation_data: None,
            state_layout: Hash([0x25; 32]),
            lanes: LaneSet::of(StateLane::Linear),
            suspended: false,
        };
        let returned = RuntimeReturn {
            state: RuntimeState {
                control: vec![1],
                linear: vec![2],
                merge: vec![3],
                local: vec![4],
            },
            result: Ok(LifecycleReply::Directory(ActorDirectoryPage {
                entries: vec![ActorDirectoryRecord {
                    entry: entry.clone(),
                    incarnation: Hash([0x44; 32]),
                    installation_id: crate::service::InstallationId([0x45; 32]),
                    registry_reservation: Hash([0x46; 32]),
                }],
                next: Some(entry.actor),
            })),
        };
        assert_eq!(RuntimeReturn::decode(&returned.encode()).unwrap(), returned);
    }

    #[test]
    fn actor_execution_call_round_trips_with_content_addressed_inputs() {
        let actor_pvm = vec![0x21, 0x22, 0x23];
        let state = vec![0x31, 0x32];
        let (schema, schema_len) =
            crate::agent::schema::encode::<512>(&crate::agent::schema::SchemaMeta {
                uses_storage: false,
                fields: &[],
                methods: &[crate::agent::schema::MethodMeta {
                    name: "call",
                    mode: MethodMode::Linear,
                    explicit: true,
                }],
            });
        let schema = schema[..schema_len].to_vec();
        let policies = crate::service::PackageRolePolicies {
            methods: vec![],
            task_dependencies: vec![],
        }
        .encode();
        let invocation = ActorInvocation {
            invocation: crate::service::InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([0x45; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId::of_pvm(&actor_pvm),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![0x41],
            availability: vec![RuntimeBlob {
                reference: BlobRef::of_bytes(&state),
                bytes: state,
            }],
            gas: 1_000_000,
        };
        let call = RuntimeExecutionCall {
            state: RuntimeState {
                control: vec![0x11],
                linear: vec![0x12],
                merge: vec![0x13],
                local: vec![0x14],
            },
            recovery_only: false,
            authority: crate::agent::authority::ActorInvocationReceipt {
                claim: crate::agent::authority::ActorInvocationClaim {
                    authority: authority_binding(),
                    space: SpaceId([0x61; 32]),
                    agent: AgentId([0x62; 32]),
                    principal: None,
                    credential: None,
                    authorization: invocation.authorization_message(),
                    auth: invocation.auth.clone(),
                    valid_from: 0,
                    valid_until: 20,
                },
                signature: vec![0; crate::agent::authority::ED25519_SIGNATURE_BYTES],
            },
            observed_slot: 10,
            invocation,
            actor_pvm,
            actor_schema: RuntimeBlob {
                reference: BlobRef::of_bytes(&schema),
                bytes: schema,
            },
            actor_policies: RuntimeBlob {
                reference: BlobRef::of_bytes(&policies),
                bytes: policies,
            },
            installation_data: None,
        };
        assert_eq!(RuntimeExecutionCall::decode(&call.encode()).unwrap(), call);

        let absent = call.encode();
        let mut present_empty = call.clone();
        present_empty.installation_data = Some(RuntimeBlob {
            reference: BlobRef::of_bytes(&[]),
            bytes: Vec::new(),
        });
        assert_eq!(
            RuntimeExecutionCall::decode(&present_empty.encode()),
            Ok(present_empty.clone())
        );
        assert_ne!(present_empty.encode(), absent);

        let mut mismatch = present_empty.clone();
        mismatch.installation_data.as_mut().unwrap().bytes.push(1);
        assert_eq!(
            RuntimeExecutionCall::decode(&mismatch.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut oversized = present_empty;
        let bytes = vec![0; super::super::MAX_INSTALLATION_DATA_BYTES + 1];
        oversized.installation_data = Some(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        assert_eq!(
            RuntimeExecutionCall::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn execution_errors_round_trip_every_tag_and_a_wide_host_identifier() {
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ] {
            let returned = RuntimeExecutionReturn {
                state: RuntimeState::default(),
                result: Err(error),
            };
            assert_eq!(
                RuntimeExecutionReturn::decode(&returned.encode()).unwrap(),
                returned,
                "{error:?}"
            );
        }
    }

    #[test]
    fn private_dispatch_wire_rejects_anonymous_role_claims() {
        let control = ActorDispatchControl {
            invocation: crate::service::InvocationId([0x41; 32]),
            actor: ActorId([0x42; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth {
                origin: crate::service::Origin::Anonymous,
                principal: None,
                origin_service: None,
                space_role: None,
                actor_role: Some(1),
                capability: None,
            },
        };
        assert_eq!(
            ActorDispatchControl::decode(&control.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn runtime_state_wire_enforces_its_aggregate_guest_budget() {
        let exact = RuntimeCall::new(
            RuntimeState {
                control: vec![1; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                linear: vec![2; super::super::execution::MAX_RUNTIME_STATE_BYTES / 2],
                merge: Vec::new(),
                local: Vec::new(),
            },
            LifecycleRequest::Inspect {
                after: None,
                limit: 1,
            },
        );
        assert_eq!(RuntimeCall::decode(&exact.encode()).unwrap(), exact);

        let oversized = RuntimeCall::new(
            RuntimeState {
                local: vec![3],
                ..exact.state
            },
            exact.request,
        );
        assert_eq!(
            RuntimeCall::decode(&oversized.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn standard_state_decoder_bounds_the_aggregate_before_component_decoding() {
        let oversized = RuntimeState {
            control: vec![0; super::super::execution::MAX_RUNTIME_STATE_BYTES],
            linear: vec![0],
            merge: vec![0],
            local: vec![0],
        };
        assert_eq!(
            decode_standard_runtime_state(&oversized),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn busy_reply_preserves_every_removal_blocker() {
        let debt = ActorLifecycleDebt {
            children: 1,
            continuations: 2,
            inbox: 3,
            outbox: 4,
            schedules: 5,
            proof_artifacts: 6,
            lifecycle_operations: 7,
        };
        let output = RuntimeReturn {
            state: RuntimeState {
                control: vec![8],
                linear: vec![9],
                merge: vec![10],
                local: vec![11],
            },
            result: Err(LifecycleError::Busy(debt)),
        };
        assert_eq!(RuntimeReturn::decode(&output.encode()).unwrap(), output);
    }

    #[test]
    fn resource_limit_uses_new_canonical_error_tag_and_unknown_tags_fail_closed() {
        let mut bytes = Vec::new();
        encode_error(&mut Encoder(&mut bytes), LifecycleError::ResourceLimit);
        assert_eq!(bytes, vec![13]);
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(
            decode_error(&mut decoder),
            Ok(LifecycleError::ResourceLimit)
        );
        assert!(decoder.exhausted());

        let mut decoder = Decoder::new(&[15]);
        assert_eq!(decode_error(&mut decoder), Err(DecodeError::InvalidTag));

        let output = RuntimeReturn {
            state: RuntimeState {
                control: vec![1],
                linear: vec![2],
                merge: vec![3],
                local: vec![4],
            },
            result: Err(LifecycleError::ResourceLimit),
        };
        assert_eq!(RuntimeReturn::decode(&output.encode()).unwrap(), output);

        use super::super::catalog_finality::CatalogFinalityError as CatalogError;
        use super::super::committee::AuthorityCommitteeError as CommitteeError;
        use super::super::genesis::AgentGenesisError as GenesisError;
        use super::super::system_authority::SystemAuthorityError as AuthorityError;

        let mut errors = vec![
            AuthorityError::InvalidGenesis,
            AuthorityError::InvalidScope,
            AuthorityError::InvalidState,
            AuthorityError::InvalidDecisionFact,
            AuthorityError::InvalidDecisionNode,
            AuthorityError::InvalidDecisionProof,
            AuthorityError::InvalidRotationNode,
            AuthorityError::InvalidRotationProof,
            AuthorityError::InvalidCatalogRecord,
            AuthorityError::InvalidCatalogNode,
            AuthorityError::InvalidCatalogProof,
            AuthorityError::InvalidCatalogFinalize,
            AuthorityError::InvalidFinalize,
            AuthorityError::InvalidProvision,
            AuthorityError::WrongSystemAgent,
            AuthorityError::StaleCommittee,
            AuthorityError::StaleAuthorityGeneration,
            AuthorityError::StaleCatalogHead,
            AuthorityError::CatalogOperationConflict,
            AuthorityError::SequenceConflict,
            AuthorityError::RotationFirstSequencePending,
            AuthorityError::Capacity,
            AuthorityError::LimitExceeded,
        ];
        errors.extend(
            [
                CatalogError::InvalidBinding,
                CatalogError::InvalidMutation,
                CatalogError::InvalidResult,
                CatalogError::InvalidIntent,
                CatalogError::InvalidFact,
                CatalogError::InvalidReceipt,
                CatalogError::WrongSpace,
                CatalogError::LimitExceeded,
                CatalogError::Authority(CommitteeError::WrongClaim),
            ]
            .map(AuthorityError::Catalog),
        );
        errors.extend(
            [
                CommitteeError::InvalidBinding,
                CommitteeError::InvalidMember,
                CommitteeError::InvalidSigner,
                CommitteeError::InvalidEpoch,
                CommitteeError::InvalidPreviousCommittee,
                CommitteeError::CommitteeTooLarge,
                CommitteeError::CertificateTooLarge,
                CommitteeError::NoVoters,
                CommitteeError::DuplicateNode,
                CommitteeError::NonCanonicalOrder,
                CommitteeError::InvalidClaim,
                CommitteeError::WrongAuthorityBinding,
                CommitteeError::WrongEpoch,
                CommitteeError::WrongCommittee,
                CommitteeError::WrongClaim,
                CommitteeError::UnknownSigner,
                CommitteeError::ObserverSignature,
                CommitteeError::InsufficientQuorum,
                CommitteeError::InvalidSignature,
                CommitteeError::InvalidRotationEpoch,
                CommitteeError::InvalidRotationLink,
                CommitteeError::InvalidRotationSequence,
                CommitteeError::InvalidRootAnchor,
                CommitteeError::RootAnchorTooLarge,
                CommitteeError::InvalidGenesisIntent,
                CommitteeError::InvalidGenesisExpectation,
                CommitteeError::InvalidGenesisClaim,
                CommitteeError::GenesisEvidenceTooLarge,
                CommitteeError::InvalidGenesisAdmission,
                CommitteeError::GenesisAdmissionTooLarge,
                CommitteeError::InvalidBootstrapAnchor,
                CommitteeError::WrongBootstrapAnchor,
                CommitteeError::WrongGenesisIntent,
                CommitteeError::WrongGenesisExpectation,
            ]
            .map(AuthorityError::Authority),
        );
        errors.extend(
            [
                GenesisError::InvalidLocator,
                GenesisError::InvalidExpectations,
                GenesisError::InvalidProposal,
                GenesisError::InvalidReplicaCommittee,
                GenesisError::InvalidClaim,
                GenesisError::InvalidEvidence,
                GenesisError::InvalidDecision,
                GenesisError::InvalidAdmission,
                GenesisError::InvalidProvision,
                GenesisError::InvalidCatalog,
                GenesisError::LimitExceeded,
                GenesisError::Authority(CommitteeError::WrongCommittee),
            ]
            .map(AuthorityError::Genesis),
        );
        for authority_error in errors {
            let error = LifecycleError::SystemAuthority(authority_error);
            let mut bytes = Vec::new();
            encode_error(&mut Encoder(&mut bytes), error);
            let mut decoder = Decoder::new(&bytes);
            assert_eq!(decode_error(&mut decoder), Ok(error));
            assert!(decoder.exhausted());
        }
    }

    #[test]
    fn catalog_finalize_outcomes_round_trip_without_expanding_conflicts() {
        use super::super::system_authority::{
            SystemAuthorityCatalogFinalizeOutcome, SystemAuthorityCatalogRecordId,
        };

        let operation = crate::service::OperationId([0x81; 32]);
        let outcomes = [
            SystemAuthorityCatalogFinalizeOutcome::Finalized {
                operation,
                result: Hash([0x82; 32]),
                catalog_head: Hash([0x83; 32]),
                authority_generation: Hash([0x84; 32]),
                sequence: 17,
            },
            SystemAuthorityCatalogFinalizeOutcome::ExactRetry {
                operation,
                result: Hash([0x82; 32]),
                catalog_head: Hash([0x83; 32]),
                authority_generation: Hash([0x84; 32]),
                sequence: 17,
            },
            SystemAuthorityCatalogFinalizeOutcome::OperationConflict {
                operation,
                occupied_record: SystemAuthorityCatalogRecordId::from_bytes([0x85; 32]),
            },
        ];
        for outcome in outcomes {
            let output = RuntimeReturn {
                state: RuntimeState::default(),
                result: Ok(LifecycleReply::CatalogFinalized(outcome)),
            };
            assert_eq!(RuntimeReturn::decode(&output.encode()), Ok(output));
        }
    }

    #[test]
    fn immediate_prior_runtime_abi_is_rejected_without_a_compatibility_decoder() {
        let mut bytes =
            RuntimeCall::new(RuntimeState::default(), LifecycleRequest::Create(config())).encode();
        bytes[36..68].copy_from_slice(b"vos-agent-runtime-abi-20260906r9");
        assert_eq!(
            RuntimeCall::decode(&bytes),
            Err(DecodeError::InvalidPlatform)
        );
    }

    #[test]
    fn unsorted_replica_configuration_is_noncanonical() {
        let mut call =
            RuntimeCall::new(RuntimeState::default(), LifecycleRequest::Create(config()));
        let LifecycleRequest::Create(config) = &mut call.request else {
            unreachable!()
        };
        config.replicas.swap(0, 1);
        assert_eq!(
            RuntimeCall::decode(&call.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn replica_count_is_bounded_before_list_allocation() {
        let mut config = config();
        config.replicas = (0..=super::super::MAX_AGENT_REPLICAS)
            .map(|index| {
                let mut node = [0u8; 32];
                node[..2].copy_from_slice(&(index as u16 + 1).to_le_bytes());
                AgentReplica {
                    node: NodeId(node),
                    principal: PrincipalId([0x61; 32]),
                    role: ReplicaRole::Voter,
                }
            })
            .collect();
        assert_eq!(
            AgentConfig::decode(&config.encode()),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn standard_runtime_state_survives_independent_calls() {
        let config = config();
        let request = LifecycleRequest::Create(config.clone());
        let claim = crate::agent::authority::AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: crate::service::CredentialId([0x72; 32]),
            capability: CapabilityId::named(
                crate::agent::authority::CAPABILITY_AGENT_CREATE_SHARED,
            ),
            operation: request.commitment(),
            sequence: 1,
            valid_from: 0,
            valid_until: 10,
        };
        let signature = authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        let created = apply_standard(RuntimeCall::new(
            RuntimeState::default(),
            LifecycleRequest::Authorized {
                admission: super::super::LifecycleAuthorityAdmission {
                    receipt: crate::agent::authority::AgentAuthorityReceipt { claim, signature },
                    observed_slot: 1,
                },
                request: Box::new(request),
            },
        ))
        .unwrap();
        assert!(matches!(created.result, Ok(LifecycleReply::Created(_))));
        let inspected = apply_standard(RuntimeCall::new(
            created.state,
            LifecycleRequest::Inspect {
                after: None,
                limit: 16,
            },
        ))
        .unwrap();
        assert_eq!(
            inspected.result,
            Ok(LifecycleReply::Directory(ActorDirectoryPage {
                entries: Vec::new(),
                next: None,
            }))
        );
    }
}
