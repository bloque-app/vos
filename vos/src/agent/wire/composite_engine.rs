//! The composite engine (`runtime-composite`): runs a composite's steps after
//! its primary, inside the primary's one invocation and transition.
//!
//! Called from the clean invoke path once the primary has run. The primary's
//! `Done` reply and lanes are already committed in `runtime`, a candidate that
//! becomes durable only when the invocation finishes. A failed Atomic
//! composite turns the primary's reply into a terminal failure, which the
//! caller's `finalize_unseen_clean_outcome` retains on the pristine runtime:
//! nothing of the primary or of any step survives, and the failure is the
//! invocation's exact, retained outcome.
//!
//! What each step gets, and what it cannot change:
//!
//! - the actor, incarnation, deployment and program are the directory's;
//! - its schema, method policy and installation data are matched by reference
//!   against the directory's record, among blobs the work decoder has already
//!   authenticated;
//! - its program is the primary's bytes when the ProgramId is the same,
//!   otherwise the bytes bound to the actor's program reference, otherwise
//!   (VOS-native) the host's natively verified preimage;
//! - its method must be Linear, declared in its schema and admitted by its
//!   own method policy for the primary's origin and role claims, under the
//!   primary's authority receipt, which binds the composite blob's reference;
//! - its gas is drawn from what the primary left, within the Agent's bounds.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::super::composite::{
    COMPOSITE_MAGIC, Composite, CompositeMode, CompositeReply, MAX_COMPOSITE_STEPS, StepOutcome,
    StepReport, refusal, step_invocation,
};
use super::super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation,
    ActorInvocationAuth, ActorObservation, ActorRunOutcome, ExecutionBounds,
};
use super::super::standard::{CompositeActorView, StandardAgentRuntime};
use super::super::{MethodMode, StateLane};
use super::{CleanExecutionAdmission, CleanInvocationStorage};
use crate::service::{ActorId, Hash, InvocationId, ProgramId};

/// What a runtime built on this engine admits, beyond the engine's own rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompositeRules {
    /// Most steps of one composite.
    pub max_steps: u16,
    /// Most steps of one Atomic composite.
    pub max_atomic_steps: u16,
    /// Every step must carry an order key or a stream.
    pub require_order_or_stream: bool,
}

impl CompositeRules {
    /// The engine's own bounds and nothing more.
    pub const OPEN: Self = Self {
        max_steps: MAX_COMPOSITE_STEPS as u16,
        max_atomic_steps: MAX_COMPOSITE_STEPS as u16,
        require_order_or_stream: false,
    };

    fn admit(&self, composite: &Composite) -> bool {
        let count = composite.steps.len();
        count <= usize::from(self.max_steps)
            && (composite.mode != CompositeMode::Atomic
                || count <= usize::from(self.max_atomic_steps))
            && (!self.require_order_or_stream
                || composite
                    .steps
                    .iter()
                    .all(|step| step.order.is_some() || step.stream.is_some()))
    }
}

// The guest is one thread, and the runtime program fixes its rules once, at
// its entry, before applying any work.
static mut RULES: CompositeRules = CompositeRules::OPEN;

/// Fix this runtime program's composite rules. Call once, at the guest's
/// entry, before applying work.
pub fn set_rules(rules: CompositeRules) {
    // SAFETY: single-threaded guest; written once before any read.
    unsafe { RULES = rules }
}

fn rules() -> CompositeRules {
    // SAFETY: as above; a copy, never a reference.
    unsafe { RULES }
}

fn refusal_of(error: ActorExecutionError) -> u8 {
    match error {
        ActorExecutionError::NotFound | ActorExecutionError::NotCreated => refusal::NOT_INSTALLED,
        ActorExecutionError::Suspended => refusal::SUSPENDED,
        ActorExecutionError::UnsupportedMethod => refusal::UNSUPPORTED_METHOD,
        ActorExecutionError::InvalidAvailability | ActorExecutionError::MissingState => {
            refusal::ARTIFACT_UNAVAILABLE
        }
        ActorExecutionError::InvalidAuthorization
        | ActorExecutionError::AuthorityExpired
        | ActorExecutionError::AuthoritySlotRegressed => refusal::NOT_AUTHORIZED,
        ActorExecutionError::InvalidActorOutput => refusal::INVALID_OUTPUT,
        ActorExecutionError::ResultCapacity => refusal::CAPACITY,
        _ => refusal::OTHER,
    }
}

const fn status_code(status: ActorExecutionStatus) -> u8 {
    match status {
        ActorExecutionStatus::Done => 0,
        ActorExecutionStatus::Forbidden => 1,
        ActorExecutionStatus::Panicked => 2,
        ActorExecutionStatus::OutOfGas => 3,
        ActorExecutionStatus::Yielded => 4,
    }
}

type StepResult = Result<(Vec<u8>, u64), (StepOutcome, u64)>;

/// Run the composite attached to a primary that ended `Done`, if any.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_tail<S: CleanInvocationStorage>(
    runtime: &mut StandardAgentRuntime,
    work: &crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    admission: &CleanExecutionAdmission<'_>,
    primary: &ActorInvocation,
    primary_pvm: &[u8],
    work_validated: bool,
    observed_slot: u64,
    limits: crate::agent_sdk::contract::ExecutionLimits,
    storage_backend: &mut S,
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
) {
    let Ok(reply) = result else {
        return;
    };
    if reply.status != ActorExecutionStatus::Done {
        return;
    }
    let mut blobs = primary
        .availability
        .iter()
        .filter(|blob| blob.bytes.starts_with(&COMPOSITE_MAGIC));
    let Some(blob) = blobs.next() else {
        return;
    };
    let mut reply = reply.clone();
    let mut report = CompositeReply {
        digested: false,
        primary: core::mem::take(&mut reply.reply),
        steps: Vec::new(),
    };
    let composite = match Composite::decode(&blob.bytes) {
        Ok(composite)
            if blobs.next().is_none()
                && matches!(admission, CleanExecutionAdmission::Direct(_))
                && primary.mode == MethodMode::Linear =>
        {
            composite
        }
        _ => {
            return fail(result, reply, report, ActorExecutionStatus::Panicked);
        }
    };
    if !rules().admit(&composite) {
        return fail(result, reply, report, ActorExecutionStatus::Forbidden);
    }
    let atomic = composite.mode == CompositeMode::Atomic;
    let mut remaining = reply.gas_remaining;
    let mut blocked = BTreeSet::new();
    let mut programs: Vec<(ProgramId, &[u8])> = Vec::new();
    for (index, step) in composite.steps.iter().enumerate() {
        let short_of_gas = step.gas > remaining;
        let outcome = if step.order.is_some_and(|order| blocked.contains(&order)) {
            Err((StepOutcome::Deferred, 0))
        } else if let Some((stream, sequence)) = step.stream
            && sequence <= runtime.stream_head(&stream)
        {
            Err((StepOutcome::Duplicate, 0))
        } else if let Some((stream, sequence)) = step.stream
            && Some(sequence) != runtime.stream_head(&stream).checked_add(1)
        {
            Err((StepOutcome::Waiting, 0))
        } else if short_of_gas {
            Err((StepOutcome::Deferred, 0))
        } else {
            run_step(
                runtime,
                work,
                authorization,
                admission,
                primary,
                primary_pvm,
                &mut programs,
                work_validated,
                observed_slot,
                limits,
                storage_backend,
                index as u16,
                step,
            )
        };
        let (line, used) = match outcome {
            Ok((bytes, used)) => (
                StepReport {
                    outcome: StepOutcome::Applied,
                    gas_used: used,
                    reply: bytes,
                },
                used,
            ),
            Err((outcome, used)) => (
                StepReport {
                    outcome,
                    gas_used: used,
                    reply: Vec::new(),
                },
                used,
            ),
        };
        remaining = remaining.saturating_sub(used);
        let applied = line.outcome.is_applied();
        let out_of_gas = line.outcome == StepOutcome::Deferred && short_of_gas;
        report.steps.push(line);
        if !applied {
            if atomic {
                reply.gas_remaining = remaining;
                let status = if out_of_gas {
                    ActorExecutionStatus::OutOfGas
                } else {
                    ActorExecutionStatus::Panicked
                };
                return fail(result, reply, report, status);
            }
            if let Some(order) = step.order {
                blocked.insert(order);
            }
        }
    }
    reply.gas_remaining = remaining;
    reply.reply = fit(report);
    match runtime.replace_retained_reply(primary, &mut reply) {
        Ok(()) => *result = Ok(reply),
        Err(error) => *result = Err(error),
    }
}

/// A failed composite: the primary's reply becomes a terminal failure whose
/// bytes report how far it got. The caller retains it on the pristine
/// runtime.
fn fail(
    result: &mut Result<ActorExecutionReply, ActorExecutionError>,
    mut reply: ActorExecutionReply,
    report: CompositeReply,
    status: ActorExecutionStatus,
) {
    reply.status = status;
    reply.observation = ActorObservation::default();
    reply.reply = fit(report);
    *result = Ok(reply);
}

/// The report's bytes, within the retained reply's bound: step replies (and
/// the primary's) become digests when the whole would not fit.
fn fit(mut report: CompositeReply) -> Vec<u8> {
    let bytes = report.encode();
    if bytes.len() <= super::super::execution::MAX_EXECUTION_REPLY_BYTES {
        return bytes;
    }
    let digest = |bytes: &[u8]| Hash::digest(b"vos/composite/reply/v1", &[bytes]).0.to_vec();
    report.digested = true;
    report.primary = digest(&report.primary);
    for step in &mut report.steps {
        step.reply = digest(&step.reply);
    }
    report.encode()
}

#[allow(clippy::too_many_arguments)]
fn run_step<'w, S: CleanInvocationStorage>(
    runtime: &mut StandardAgentRuntime,
    work: &'w crate::agent_sdk::InvocationWork,
    authorization: &crate::agent_sdk::InvocationAuthorization,
    admission: &CleanExecutionAdmission<'_>,
    primary: &ActorInvocation,
    primary_pvm: &'w [u8],
    programs: &mut Vec<(ProgramId, &'w [u8])>,
    work_validated: bool,
    observed_slot: u64,
    limits: crate::agent_sdk::contract::ExecutionLimits,
    storage_backend: &mut S,
    index: u16,
    step: &super::super::composite::CompositeStep,
) -> StepResult {
    let refused = |reason| Err((StepOutcome::Refused(reason), 0));
    let Some(view) = runtime.composite_actor(ActorId(step.actor)) else {
        return refused(refusal::NOT_INSTALLED);
    };
    if view.suspended {
        return refused(refusal::SUSPENDED);
    }
    if !view.linear {
        return refused(refusal::NOT_LINEAR);
    }
    let Some(program) = step_program(
        runtime,
        &view,
        primary,
        primary_pvm,
        work,
        work_validated,
        programs,
    ) else {
        return refused(refusal::PROGRAM_UNAVAILABLE);
    };
    let artifact = |expected: &crate::service::BlobRef| {
        work.availability.iter().find(|blob| {
            super::super::standard::clean_reference_matches_record(&blob.reference, expected)
        })
    };
    let (Some(schema), Some(policies)) =
        (artifact(&view.agent_schema), artifact(&view.role_policies))
    else {
        return refused(refusal::ARTIFACT_UNAVAILABLE);
    };
    let installation = match &view.installation_data {
        None => None,
        Some(expected) => match artifact(expected) {
            Some(blob) => Some(blob),
            None => return refused(refusal::ARTIFACT_UNAVAILABLE),
        },
    };
    let step_id = step_invocation(&work.invocation.0, index);
    let sub = crate::agent_sdk::InvocationWork {
        space: work.space,
        agent: work.agent,
        runtime_deployment: work.runtime_deployment,
        invocation: crate::agent_sdk::InvocationId(step_id),
        actor: crate::agent_sdk::ActorId(view.actor.0),
        incarnation: crate::agent_sdk::Hash(view.incarnation.0),
        deployment: crate::agent_sdk::DeploymentId(view.deployment.0),
        program: crate::agent_sdk::ProgramId(view.program.0),
        mode: crate::agent_sdk::MethodMode::Linear,
        origin: work.origin,
        roles: work.roles,
        message: step.message.clone(),
        installation_data: view.installation_data.as_ref().map(|reference| {
            crate::agent_sdk::BlobRef {
                hash: crate::agent_sdk::Hash(reference.hash.0),
                len: reference.len,
            }
        }),
        // Storage scope, schema and policy checks read identity and message
        // only; the step's caller blobs are the primary's (below).
        availability: Vec::new(),
        gas: step.gas,
        recovery_only: false,
    };
    if let Err(error) = runtime
        .validate_clean_execution_installation_data(&sub, installation)
        .and_then(|()| runtime.validate_clean_execution_schema(&sub, schema))
    {
        return refused(refusal_of(error));
    }
    match super::authorize_clean_execution_context(
        runtime,
        admission,
        &sub,
        authorization,
        schema,
        policies,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StepOutcome::Failed(status_code(ActorExecutionStatus::Forbidden)),
                0,
            ));
        }
        Err(error) => return refused(refusal_of(error)),
    }
    let invocation = ActorInvocation {
        invocation: InvocationId(step_id),
        actor: view.actor,
        incarnation: view.incarnation,
        deployment: view.deployment,
        program: view.program,
        mode: MethodMode::Linear,
        auth: ActorInvocationAuth::anonymous(),
        message: step.message.clone(),
        availability: primary.availability.clone(),
        gas: step.gas,
    };
    let before = match runtime.prepare_execution_state(&invocation) {
        Ok(before) => before,
        Err(error) => return refused(refusal_of(error)),
    };
    let visible = before.visible_for(invocation.mode);
    let outcome = storage_backend.execute(runtime, &sub, schema, |storage| {
        super::super::execution::run_inner_actor_with_bounds(
            &invocation,
            Some(crate::agent_sdk::InvocationContext::from_work(
                &sub,
                observed_slot,
            )),
            program,
            installation.map(|data| data.bytes.as_slice()),
            &visible,
            None,
            Some(storage),
            &ExecutionBounds::of(limits),
        )
    });
    let (reply, state, rows) = match outcome {
        // The gas an aborted execution used is not reported: charge all of it.
        Err(error) => return Err((StepOutcome::Refused(refusal_of(error)), step.gas)),
        Ok(ActorRunOutcome::Yielded { reply, .. }) => {
            let used = step.gas.saturating_sub(reply.gas_remaining);
            return Err((
                StepOutcome::Failed(status_code(ActorExecutionStatus::Yielded)),
                used,
            ));
        }
        Ok(ActorRunOutcome::Completed { reply, state, rows }) => (reply, state, rows),
    };
    let used = step.gas.saturating_sub(reply.gas_remaining);
    if reply.status != ActorExecutionStatus::Done {
        return Err((StepOutcome::Failed(status_code(reply.status)), used));
    }
    let inline = if rows.is_empty() {
        Vec::new()
    } else {
        state.get(StateLane::Linear).unwrap_or_default().to_vec()
    };
    let stream = step.stream;
    let committed = storage_backend.commit(runtime, &sub, schema, inline, rows, |runtime| {
        // Check the stream before any lane moves, so a refused advance leaves
        // the runtime as it was (a commit without rows mutates in place).
        if let Some((stream, sequence)) = stream
            && Some(sequence) != runtime.stream_head(&stream).checked_add(1)
        {
            return Err(ActorExecutionError::InvalidInput);
        }
        runtime.commit_composite_step(&invocation, &reply, &before, state)?;
        if let Some((stream, sequence)) = stream {
            runtime.advance_stream(stream, sequence)?;
        }
        Ok(())
    });
    match committed {
        Ok(()) => Ok((reply.reply, used)),
        Err(error) => Err((StepOutcome::Refused(refusal_of(error)), used)),
    }
}

/// The step's program bytes, authenticated without hashing them again when
/// the guest already has: the primary's own program, an earlier step's, or the
/// availability blob bound to the actor's program. Otherwise the guest hashes
/// candidates to the ProgramId once and binds the match (JAM-native), or asks
/// the host for the preimage it verified natively (VOS-native).
fn step_program<'w>(
    runtime: &mut StandardAgentRuntime,
    view: &CompositeActorView,
    primary: &ActorInvocation,
    primary_pvm: &'w [u8],
    work: &'w crate::agent_sdk::InvocationWork,
    work_validated: bool,
    programs: &mut Vec<(ProgramId, &'w [u8])>,
) -> Option<&'w [u8]> {
    if view.program == primary.program {
        return Some(primary_pvm);
    }
    if let Some((_, bytes)) = programs
        .iter()
        .find(|(program, _)| *program == view.program)
    {
        return Some(bytes);
    }
    #[cfg(all(feature = "runtime-program-lookup", target_arch = "riscv64"))]
    {
        let _ = (runtime, work, work_validated);
        let bytes =
            super::super::standard::lookup_program(&crate::agent_sdk::ProgramId(view.program.0))
                .ok()?;
        programs.push((view.program, bytes));
        Some(bytes)
    }
    #[cfg(not(all(feature = "runtime-program-lookup", target_arch = "riscv64")))]
    {
        if let Some(bound) = &view.bound_program
            && let Some(blob) = work
                .availability
                .iter()
                .find(|blob| blob.reference == *bound && blob.bytes.len() as u64 == bound.len)
        {
            programs.push((view.program, &blob.bytes));
            return Some(&blob.bytes);
        }
        let expected = crate::agent_sdk::ProgramId(view.program.0);
        let blob = work.availability.iter().find(|blob| {
            blob.bytes.len() <= super::super::execution::MAX_EXECUTION_PROGRAM_BYTES
                && crate::agent_sdk::ProgramId::of_pvm(&blob.bytes) == expected
        })?;
        if work_validated {
            runtime.bind_program(view.actor, blob.reference.clone());
        }
        programs.push((view.program, &blob.bytes));
        Some(&blob.bytes)
    }
}
