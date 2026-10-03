//! Composite invocations through the standard runtime's code, natively
//! (`runtime-composite`): one Linear transition across several of an Agent's
//! own actors, ordered and exactly-once steps, and the primary's one result.
//!
//! The runtime runs as its PVM guest, as a host runs it: build it first.
//!
//!     (cd services/agent-runtime && CARGO_TARGET_DIR=../../target/rt-composite \
//!         cargo actor --features composite)
//!     cargo test -p vos --no-default-features --features std,pvm,runtime-composite \
//!         --test agent_runtime_composite
//!
//! `VOS_COMPOSITE_RUNTIME_ELF` names another build.
#![cfg(feature = "runtime-composite")]

use ed25519_dalek::{Signer as _, SigningKey};
use vos::Encode as _;
use vos::agent::composite::{
    Composite, CompositeMode, CompositeReply, CompositeStep, StepOutcome, refusal, stream_id,
};
use vos::agent::package_admission::{
    AdmittedActorPackage, AdmittedRuntimePackage, admit_actor_package, admit_runtime_package,
};
use vos::agent_sdk as sdk;
use vos::agent_sdk::authority::{
    AgentAuthorityBinding, AuthorityEvidence, AuthorityIssuer, AuthorityLaneRoots,
    AuthorityOperationKind, AuthorityReceipt, AuthorityReceiptSelector,
};
use vos::agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
use vos::agent_sdk::introspection::{
    ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
};
use vos::agent_sdk::method_policy::{
    ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
    AuthorizationPolicySelector, IdempotencyRequirement,
};
use vos::agent_sdk::package::{
    ActorPackageManifest, AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope,
    PackageManifest, PackageSigning,
};
use vos::agent_sdk::schema::{
    ConstructorContract, ParsedField, ParsedInlineField, ParsedMethod, ParsedSchema,
};
use vos::agent_sdk::task::TaskDependencySetArtifact;
use vos::agent_sdk::wire::CanonicalWire as _;
use vos::agent_sdk::{
    ActorEntry, ActorId, AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica,
    BlobRef, DeploymentId, Hash, InstallationId, InvocationAuthorization, InvocationId,
    InvocationReply, InvocationStatus, InvocationWork, LaneSet, ManagementReply, ManagementRequest,
    MethodMode, NodeId, PrincipalId, ProducerId, ProgramId, ReplicaRole, RuntimeBlob,
    RuntimeCapabilities, RuntimeExecutionContext, RuntimeOutcome, RuntimeRequirements,
    RuntimeState, RuntimeTransition, RuntimeWork, SpaceId, StateLane,
};
use vos_pvm_compiler::assembler::{Assembler, Reg};

const GAS: u64 = 5_000_000_000;

/// The composite runtime's PVM, linked once from its guest ELF.
fn runtime_pvm() -> &'static [u8] {
    static PVM: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    PVM.get_or_init(|| {
        let path = std::env::var_os("VOS_COMPOSITE_RUNTIME_ELF")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../target/rt-composite/riscv64em-vos/release/agent_runtime.elf")
            });
        let elf = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("build the composite runtime first ({path:?}): {error}")
        });
        vos_pvm_compiler::link_elf_spi(&elf).expect("link the composite runtime")
    })
}
const PACKAGE_SEED: [u8; 32] = [0x71; 32];
const AUTHORITY_SEED: [u8; 32] = [0x72; 32];
const STEP_GAS: u64 = 1_000_000;

fn package_signing() -> PackageSigning {
    let key = SigningKey::from_bytes(&PACKAGE_SEED);
    let public_key = key.verifying_key().to_bytes();
    PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
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
    let bytes = sign_package(PackageEnvelope {
        manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: "composite-local-runtime".into(),
            external_state_limits: None,
            outer_program: BlobRef::of_bytes(runtime_pvm()),
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            signing: package_signing(),
        }),
        artifacts: vec![artifact(runtime_pvm())],
    })
    .encode()
    .unwrap();
    admit_runtime_package(&bytes).unwrap()
}

fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&AUTHORITY_SEED)
}

fn descriptor(runtime: &AdmittedRuntimePackage, discriminator: u8) -> AgentDescriptor {
    let space = SpaceId([0x11; 32]);
    let owner = PrincipalId([discriminator; 32]);
    let creation_nonce = Hash([discriminator.wrapping_add(0x30); 32]);
    let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
    let public_key = authority_key().verifying_key().to_bytes();
    AgentDescriptor {
        identity: AgentIdentity {
            space,
            agent,
            owner,
            profile: AgentProfile::Local,
            runtime_deployment: runtime.deployment(),
            runtime_program: runtime.program(),
            runtime_producer: runtime.producer(),
            transition_producer: ProducerId([discriminator.wrapping_add(0x60); 32]),
        },
        creation_nonce,
        authority: AgentAuthorityBinding {
            policy: Hash([0x81; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0x82; 32]),
                actor: ActorId([0x83; 32]),
                deployment: DeploymentId([0x84; 32]),
                program: ProgramId([0x85; 32]),
                producer: ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 1,
        },
        private_recovery: None,
        runtime_package: runtime.package_ref().clone(),
        runtime_contract: runtime.manifest().contract,
        capabilities: runtime.capabilities(),
        replicas: vec![AgentReplica {
            node: NodeId([0x22; 32]),
            principal: owner,
            role: ReplicaRole::Voter,
        }],
    }
}

fn receipt(
    descriptor: &AgentDescriptor,
    operation: AuthorityOperationKind,
    runtime_deployment: DeploymentId,
    actor: Option<(ActorId, DeploymentId)>,
    decision_sequence: u64,
    (valid_from, expires_at): (u64, u64),
    request: Hash,
) -> AuthorityReceipt {
    let mut receipt = AuthorityReceipt {
        selector: AuthorityReceiptSelector {
            policy: descriptor.authority.policy,
            issuer: descriptor.authority.issuer,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            operation,
            runtime_deployment,
            actor: actor.map(|(actor, _)| actor),
            actor_deployment: actor.map(|(_, deployment)| deployment),
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
            request,
        },
        public_key: descriptor.authority.public_key,
        signature: [0; sdk::authority::AUTHORITY_SIGNATURE_BYTES],
    };
    receipt.signature = authority_key().sign(&receipt.signing_bytes()).to_bytes();
    receipt
}

thread_local! {
    static LAST_GAS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// One execution of the runtime's PVM; every transition persisted and
/// restored, as a host does.
fn apply(work: RuntimeWork) -> RuntimeTransition {
    let input = work.encode().unwrap();
    let invocation = vos_pvm::refine_host::RefineContext::load(runtime_pvm(), &input, GAS)
        .expect("load the composite runtime")
        .run();
    LAST_GAS.with(|gas| gas.set(invocation.gas_used));
    assert_eq!(
        invocation.exit,
        vos_pvm::ExitReason::Halt,
        "the runtime trapped at {}",
        invocation.pc
    );
    RuntimeTransition::decode(
        &invocation
            .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
            .expect("an output window"),
    )
    .unwrap()
}

fn manage(
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> RuntimeTransition {
    apply(RuntimeWork::Manage {
        context: RuntimeExecutionContext::Direct,
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        state,
        request: Box::new(request),
        authority: authority.map(Box::new),
        observed_slot,
    })
}

/// An actor that writes `linear` to its Linear lane and replies `reply`.
fn writing_actor(linear: u8, reply: u8) -> Vec<u8> {
    let mut output = vec![vos::actors::STATUS_DONE];
    output.extend_from_slice(&1u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.push(linear);
    output.push(reply);
    let mut actor = Assembler::new();
    actor
        .set_rw_data(output.clone())
        .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
        .load_imm_64(Reg::A1, output.len() as u64)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

fn faulting_actor() -> Vec<u8> {
    let mut actor = Assembler::new();
    actor
        .load_imm_64(Reg::A2, 0x1000_0000)
        .load_ind_u64(Reg::A0, Reg::A2, 0)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

fn spinning_actor() -> Vec<u8> {
    let mut actor = Assembler::new();
    actor.jump(0);
    actor.build_standard()
}

fn package(program: Vec<u8>) -> AdmittedActorPackage {
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
    let policy_bytes = ActorMethodPolicyArtifact {
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
    }
    .encode()
    .unwrap();
    let introspection_bytes = ActorIntrospectionArtifact {
        actor_schema: BlobRef::of_bytes(&schema_bytes),
        method_policy: BlobRef::of_bytes(&policy_bytes),
        actor_doc: "composite fixture".into(),
        methods: vec![ActorMethodIntrospection {
            name: "write".into(),
            doc: String::new(),
            cli_exposure: CliExposure::Exposed,
            timeout_ms: 0,
            dispatch: MethodDispatch::Sync,
        }],
    }
    .encode()
    .unwrap();
    let task_bytes = TaskDependencySetArtifact {
        dependencies: Vec::new(),
    }
    .encode()
    .unwrap();
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
            name: "fixture".into(),
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

#[derive(Clone)]
struct Installed {
    actor: ActorId,
    incarnation: Hash,
    package: AdmittedActorPackage,
}

/// One Agent and its actors, driven through management and invocations.
struct Agent {
    descriptor: AgentDescriptor,
    state: RuntimeState,
    actors: Vec<Installed>,
    sequence: u64,
    slot: u64,
}

impl Agent {
    fn new(discriminator: u8) -> Self {
        let runtime = admitted_runtime();
        let descriptor = descriptor(&runtime, discriminator);
        let request = ManagementRequest::Create(Box::new(descriptor.clone()));
        let authority = receipt(
            &descriptor,
            AuthorityOperationKind::CreateAgent,
            descriptor.identity.runtime_deployment,
            None,
            1,
            (1, 2),
            request.commitment(),
        );
        let created = manage(
            &descriptor,
            RuntimeState::default(),
            request,
            Some(authority),
            1,
        );
        assert!(matches!(
            created.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(_)))
        ));
        Self {
            descriptor,
            state: created.state,
            actors: Vec::new(),
            sequence: 1,
            slot: 2,
        }
    }

    fn install(&mut self, name: &str, program: Vec<u8>) -> usize {
        let package = package(program);
        let schema = sdk::schema::decode(package.state_lane_schema_bytes()).unwrap();
        let actor = ActorId::top_level(self.descriptor.identity.agent, name);
        let entry = ActorEntry {
            actor,
            name: name.into(),
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
        self.sequence += 1;
        let request = ManagementRequest::Install(Box::new(sdk::InstallActor {
            installation_id: InstallationId([0x90 + self.actors.len() as u8; 32]),
            registry_reservation: Hash([0xa0 + self.actors.len() as u8; 32]),
            entry: entry.clone(),
            producer: package.producer(),
            package: package.package_ref().clone(),
            agent_schema: package.manifest().state_lane_schema.clone(),
            method_policy: package.manifest().method_policy.clone(),
            constructor_abi: schema.constructor_abi().unwrap(),
            installation_data: None,
            state_layout: schema.state_layout_hash().unwrap(),
            contract: package.manifest().contract,
            requirements: package.requirements(),
        }));
        let authority = receipt(
            &self.descriptor,
            AuthorityOperationKind::InstallActor,
            self.descriptor.identity.runtime_deployment,
            Some((actor, entry.deployment)),
            self.sequence,
            (self.slot, self.slot),
            request.commitment(),
        );
        let installed = manage(
            &self.descriptor,
            self.state.clone(),
            request,
            Some(authority),
            self.slot,
        );
        assert!(
            matches!(
                installed.outcome,
                RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
            ),
            "install refused: {:?}",
            installed.outcome
        );
        self.slot += 1;
        self.state = installed.state.clone();
        let inspected = manage(
            &self.descriptor,
            self.state.clone(),
            ManagementRequest::InspectActors {
                after: None,
                limit: 16,
            },
            None,
            u64::MAX,
        );
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = inspected.outcome
        else {
            panic!("no actor page")
        };
        let record = page
            .entries
            .iter()
            .find(|record| record.entry.actor == actor)
            .expect("installed actor in the directory");
        self.actors.push(Installed {
            actor,
            incarnation: record.incarnation,
            package,
        });
        self.actors.len() - 1
    }

    fn message() -> Vec<u8> {
        let mut message = vec![vos::value::TAG_DYNAMIC];
        message.extend_from_slice(&vos::value::Msg::new("write").encode());
        message
    }

    /// The primary's work: `primary.write`, with every installed actor's
    /// artifacts available and the composite, if any, as a caller blob.
    fn work(
        &self,
        id: u8,
        primary: usize,
        composite: Option<&Composite>,
        gas: u64,
    ) -> InvocationWork {
        let target = &self.actors[primary];
        let mut availability: Vec<RuntimeBlob> = Vec::new();
        for installed in &self.actors {
            for bytes in [
                installed.package.program_bytes(),
                installed.package.state_lane_schema_bytes(),
                installed.package.method_policy_bytes(),
            ] {
                let reference = BlobRef::of_bytes(bytes);
                if availability.iter().all(|blob| blob.reference != reference) {
                    availability.push(RuntimeBlob {
                        reference,
                        bytes: bytes.to_vec(),
                    });
                }
            }
        }
        if let Some(composite) = composite {
            let bytes = composite.encode();
            availability.push(RuntimeBlob {
                reference: BlobRef::of_bytes(&bytes),
                bytes,
            });
        }
        availability.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
        InvocationWork {
            space: self.descriptor.identity.space,
            agent: self.descriptor.identity.agent,
            runtime_deployment: self.descriptor.identity.runtime_deployment,
            invocation: InvocationId([id; 32]),
            actor: target.actor,
            incarnation: target.incarnation,
            deployment: target.package.deployment(),
            program: target.package.program(),
            mode: MethodMode::Linear,
            origin: sdk::InvocationOrigin::anonymous(),
            roles: sdk::InvocationRoleClaims::none(),
            message: Self::message(),
            installation_data: None,
            availability,
            gas,
            recovery_only: false,
        }
    }

    /// Invoke, and keep the successor state.
    fn invoke(&mut self, work: &InvocationWork) -> RuntimeTransition {
        let transition = self.invoke_at(work, self.state.clone());
        self.state = transition.state.clone();
        transition
    }

    fn invoke_at(&mut self, work: &InvocationWork, state: RuntimeState) -> RuntimeTransition {
        let authority = receipt(
            &self.descriptor,
            AuthorityOperationKind::InvokeActor,
            work.runtime_deployment,
            Some((work.actor, work.deployment)),
            0,
            (self.slot, self.slot + 100),
            work.commitment(),
        );
        apply(RuntimeWork::Invoke {
            context: RuntimeExecutionContext::Direct,
            state,
            invocation: Box::new(work.clone()),
            authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority)),
            observed_slot: self.slot,
        })
    }

    fn acknowledge(&mut self, work: &InvocationWork) -> RuntimeTransition {
        let authority = receipt(
            &self.descriptor,
            AuthorityOperationKind::InvokeActor,
            work.runtime_deployment,
            Some((work.actor, work.deployment)),
            0,
            (self.slot, self.slot + 100),
            work.commitment(),
        );
        let acknowledged = apply(RuntimeWork::Acknowledge {
            context: RuntimeExecutionContext::Direct,
            state: self.state.clone(),
            invocation: Box::new(sdk::InvocationRetirement::from_work(work)),
            authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority)),
        });
        self.state = acknowledged.state.clone();
        acknowledged
    }

    fn step(&self, actor: usize) -> CompositeStep {
        CompositeStep {
            actor: self.actors[actor].actor.0,
            gas: STEP_GAS,
            order: None,
            stream: None,
            message: Self::message(),
        }
    }
}

fn reply_of(transition: &RuntimeTransition) -> &InvocationReply {
    match &transition.outcome {
        RuntimeOutcome::Completed(Ok(reply)) => reply,
        other => panic!("no reply: {other:?}"),
    }
}

fn report_of(transition: &RuntimeTransition) -> CompositeReply {
    CompositeReply::decode(&reply_of(transition).reply).expect("a composite reply")
}

fn outcomes(report: &CompositeReply) -> Vec<StepOutcome> {
    report.steps.iter().map(|step| step.outcome).collect()
}

#[test]
fn the_plain_path_is_the_standard_one() {
    let mut agent = Agent::new(1);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let installed = agent.state.clone();
    let done = agent.invoke(&agent.work(0x01, a, None, 10_000_000));
    let reply = reply_of(&done);
    assert_eq!(reply.status, InvocationStatus::Done);
    assert_eq!(reply.reply, [0x63]);
    assert_ne!(done.state.linear, installed.linear);
}

/// (a) Every step and the primary commit in one transition, retried exactly.
#[test]
fn an_atomic_composite_commits_every_actor_in_one_transition() {
    let mut agent = Agent::new(2);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let c = agent.install("c", writing_actor(0x2a, 0x63));
    let composite = Composite {
        mode: CompositeMode::Atomic,
        steps: vec![agent.step(b), agent.step(c)],
    };
    let installed = agent.state.clone();
    let work = agent.work(0x02, a, Some(&composite), 10_000_000);
    let done = agent.invoke(&work);
    let reply = reply_of(&done);
    assert_eq!(reply.status, InvocationStatus::Done);
    assert_eq!(reply.observation.linear_revision, Some(3));
    let report = report_of(&done);
    assert_eq!(report.primary, [0x63]);
    assert_eq!(
        outcomes(&report),
        [StepOutcome::Applied, StepOutcome::Applied]
    );
    assert_eq!(report.steps[0].reply, [0x64]);
    assert_eq!(report.steps[1].reply, [0x63]);
    assert!(report.steps.iter().all(|step| step.gas_used > 0));
    assert!(reply.gas_remaining < work.gas);
    assert_ne!(done.state.linear, installed.linear);

    // Exact retry: the retained composite reply, and no step runs again.
    let retried = agent.invoke_at(&work, done.state.clone());
    assert_eq!(retried.outcome, done.outcome);
    assert_eq!(retried.state, done.state);

    // One acknowledgement retires the whole composite.
    let acknowledged = agent.acknowledge(&work);
    assert!(
        matches!(acknowledged.outcome, RuntimeOutcome::Acknowledged(Ok(_))),
        "{:?}",
        acknowledged.outcome
    );
}

#[test]
fn composite_wire_round_trips_and_is_strict() {
    let composite = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![
            CompositeStep {
                actor: [1; 32],
                gas: 10,
                order: Some([2; 32]),
                stream: None,
                message: vec![0xd0, 1, 2],
            },
            CompositeStep {
                actor: [3; 32],
                gas: 20,
                order: None,
                stream: Some(([4; 32], 7)),
                message: Vec::new(),
            },
        ],
    };
    let bytes = composite.encode();
    assert_eq!(Composite::decode(&bytes), Ok(composite.clone()));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Composite::decode(&trailing).is_err());
    assert!(Composite::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut bad_flags = bytes.clone();
    bad_flags[4 + 2 + 1 + 2 + 32 + 8] = 0x80;
    assert!(Composite::decode(&bad_flags).is_err());
    let mut zero = composite.clone();
    zero.steps[1].stream = Some(([4; 32], 0));
    assert!(Composite::decode(&zero.encode()).is_err());
    let mut zero = composite.clone();
    zero.steps[0].gas = 0;
    assert!(Composite::decode(&zero.encode()).is_err());
    let empty = Composite {
        mode: CompositeMode::Atomic,
        steps: Vec::new(),
    };
    assert!(Composite::decode(&empty.encode()).is_err());

    let reply = CompositeReply {
        digested: false,
        primary: vec![9, 9],
        steps: vec![
            vos::agent::composite::StepReport {
                outcome: StepOutcome::Applied,
                gas_used: 5,
                reply: vec![1],
            },
            vos::agent::composite::StepReport {
                outcome: StepOutcome::Refused(refusal::NOT_AUTHORIZED),
                gas_used: 0,
                reply: Vec::new(),
            },
        ],
    };
    assert_eq!(CompositeReply::decode(&reply.encode()), Ok(reply));
}

/// A composite whose replies would overflow the retained result reports
/// digests instead, and still commits.
#[test]
fn a_large_composite_reports_digests() {
    let mut agent = Agent::new(8);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let composite = Composite {
        mode: CompositeMode::Isolated,
        steps: (0..vos::agent::composite::MAX_COMPOSITE_STEPS)
            .map(|_| agent.step(b))
            .collect(),
    };
    let done = agent.invoke(&agent.work(0x0f, a, Some(&composite), 1_000_000_000));
    let report = report_of(&done);
    assert_eq!(
        report.steps.len(),
        vos::agent::composite::MAX_COMPOSITE_STEPS
    );
    assert!(
        report
            .steps
            .iter()
            .all(|step| step.outcome == StepOutcome::Applied)
    );
    assert!(reply_of(&done).reply.len() <= 8 * 1024);
}

/// (a) A step that fails undoes every step and the primary; the failure is
/// the invocation's retained outcome.
#[test]
fn an_atomic_composite_that_fails_commits_nothing() {
    let mut agent = Agent::new(3);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let f = agent.install("f", faulting_actor());
    let composite = Composite {
        mode: CompositeMode::Atomic,
        steps: vec![agent.step(b), agent.step(f), agent.step(b)],
    };
    let installed = agent.state.clone();
    let work = agent.work(0x03, a, Some(&composite), 10_000_000);
    let failed = agent.invoke(&work);
    let reply = reply_of(&failed);
    assert_eq!(reply.status, InvocationStatus::Panicked);
    let report = report_of(&failed);
    assert_eq!(report.steps.len(), 2, "stops at the failing step");
    assert_eq!(report.steps[0].outcome, StepOutcome::Applied);
    assert!(!report.steps[1].outcome.is_applied());
    // No actor's lane moved: only the retained failure is new.
    let plain = agent.invoke_at(&agent.work(0x04, a, None, 10_000_000), installed.clone());
    assert_eq!(reply_of(&plain).observation.linear_revision, Some(1));
    let retried = agent.invoke_at(&work, failed.state.clone());
    assert_eq!(retried.outcome, failed.outcome);
}

/// (c) Isolated steps: a failure is rolled back alone, the steps behind it
/// with its order key are deferred, every other step applies.
#[test]
fn an_isolated_composite_defers_behind_a_failure_by_order_key() {
    let mut agent = Agent::new(4);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let f = agent.install("f", faulting_actor());
    let payer = Some([0x50; 32]);
    let other = Some([0x51; 32]);
    let mut steps = vec![agent.step(f), agent.step(b), agent.step(b), agent.step(b)];
    steps[0].order = payer;
    steps[1].order = payer;
    steps[2].order = other;
    let composite = Composite {
        mode: CompositeMode::Isolated,
        steps,
    };
    let done = agent.invoke(&agent.work(0x05, a, Some(&composite), 10_000_000));
    assert_eq!(reply_of(&done).status, InvocationStatus::Done);
    let report = report_of(&done);
    let outcomes = outcomes(&report);
    assert!(matches!(
        outcomes[0],
        StepOutcome::Failed(_) | StepOutcome::Refused(_)
    ));
    assert_eq!(
        outcomes[1..],
        [
            StepOutcome::Deferred,
            StepOutcome::Applied,
            StepOutcome::Applied
        ]
    );
    // Primary and two applied steps: three Linear revisions.
    assert_eq!(reply_of(&done).observation.linear_revision, Some(3));
}

/// (c) A batch never loses its applied prefix to the gas cap: steps the
/// invocation has no gas left for are deferred, and their order key with
/// them.
#[test]
fn an_isolated_composite_defers_what_its_gas_cannot_cover() {
    let mut agent = Agent::new(5);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let s = agent.install("s", spinning_actor());
    let mut steps = vec![agent.step(b), agent.step(s), agent.step(b), agent.step(b)];
    steps[1].gas = 2_000_000;
    steps[2].gas = 5_000_000;
    steps[2].order = Some([0x60; 32]);
    steps[3].order = Some([0x60; 32]);
    let composite = Composite {
        mode: CompositeMode::Isolated,
        steps,
    };
    let done = agent.invoke(&agent.work(0x06, a, Some(&composite), 3_500_000));
    assert_eq!(reply_of(&done).status, InvocationStatus::Done);
    let report = report_of(&done);
    assert_eq!(report.steps[0].outcome, StepOutcome::Applied);
    assert!(matches!(report.steps[1].outcome, StepOutcome::Failed(3)));
    assert_eq!(report.steps[2].outcome, StepOutcome::Deferred);
    assert_eq!(report.steps[3].outcome, StepOutcome::Deferred);

    // Atomic: a step the remaining gas cannot cover fails the whole
    // composite as out of gas.
    let mut steps = vec![agent.step(b), agent.step(b)];
    steps[1].gas = 2_000_000;
    let composite = Composite {
        mode: CompositeMode::Atomic,
        steps,
    };
    let failed = agent.invoke(&agent.work(0x07, a, Some(&composite), 1_500_000));
    assert_eq!(reply_of(&failed).status, InvocationStatus::OutOfGas);
    assert_eq!(
        outcomes(&report_of(&failed)),
        [StepOutcome::Applied, StepOutcome::Deferred]
    );
}

/// Numbered messages: each applies once, in its stream's sequence, and the
/// heads survive restart.
#[test]
fn streams_apply_each_message_once_and_in_sequence() {
    let mut agent = Agent::new(6);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2b, 0x64));
    let credits = stream_id(b"credit", &[7; 32]);
    let numbered = |agent: &Agent, sequence| {
        let mut step = agent.step(b);
        step.stream = Some((credits, sequence));
        step
    };
    let first = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![numbered(&agent, 1)],
    };
    let done = agent.invoke(&agent.work(0x08, a, Some(&first), 10_000_000));
    assert_eq!(outcomes(&report_of(&done)), [StepOutcome::Applied]);

    let second = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![
            numbered(&agent, 1),
            numbered(&agent, 2),
            numbered(&agent, 4),
        ],
    };
    let done = agent.invoke(&agent.work(0x09, a, Some(&second), 10_000_000));
    assert_eq!(
        outcomes(&report_of(&done)),
        [
            StepOutcome::Duplicate,
            StepOutcome::Applied,
            StepOutcome::Waiting
        ]
    );

    let third = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![
            numbered(&agent, 4),
            numbered(&agent, 3),
            numbered(&agent, 4),
        ],
    };
    let done = agent.invoke(&agent.work(0x0a, a, Some(&third), 10_000_000));
    assert_eq!(
        outcomes(&report_of(&done)),
        [
            StepOutcome::Waiting,
            StepOutcome::Applied,
            StepOutcome::Applied
        ]
    );

    // Atomic: a gap fails the whole composite, and nothing advances.
    let gap = Composite {
        mode: CompositeMode::Atomic,
        steps: vec![numbered(&agent, 5), numbered(&agent, 7)],
    };
    let failed = agent.invoke(&agent.work(0x0b, a, Some(&gap), 10_000_000));
    assert_eq!(reply_of(&failed).status, InvocationStatus::Panicked);
    let after = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![numbered(&agent, 5)],
    };
    let done = agent.invoke(&agent.work(0x0c, a, Some(&after), 10_000_000));
    assert_eq!(outcomes(&report_of(&done)), [StepOutcome::Applied]);
}

/// Steps name only the Agent's own installed actors.
#[test]
fn a_step_on_an_actor_that_is_not_installed_is_refused() {
    let mut agent = Agent::new(7);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let mut stranger = agent.step(a);
    stranger.actor = [0xee; 32];
    let composite = Composite {
        mode: CompositeMode::Isolated,
        steps: vec![stranger.clone(), agent.step(a)],
    };
    let done = agent.invoke(&agent.work(0x0d, a, Some(&composite), 10_000_000));
    assert_eq!(
        outcomes(&report_of(&done)),
        [
            StepOutcome::Refused(refusal::NOT_INSTALLED),
            StepOutcome::Applied
        ]
    );
    let composite = Composite {
        mode: CompositeMode::Atomic,
        steps: vec![agent.step(a), stranger],
    };
    let failed = agent.invoke(&agent.work(0x0e, a, Some(&composite), 10_000_000));
    assert_eq!(reply_of(&failed).status, InvocationStatus::Panicked);
}

/// Gas of one invocation of the runtime against the steps it carries, with
/// actors that do nearly nothing: what the runtime itself costs a step.
/// `cargo test ... -- --ignored --nocapture measure_`
#[test]
#[ignore = "a measurement"]
fn measure_runtime_gas_per_step() {
    let mut agent = Agent::new(9);
    let a = agent.install("a", writing_actor(0x2a, 0x63));
    let b = agent.install("b", writing_actor(0x2a, 0x63));
    let c = agent.install("c", writing_actor(0x2c, 0x65));
    let mut id = 0x40u8;
    let mut run = |agent: &mut Agent, composite: Option<Composite>| {
        id += 1;
        let work = agent.work(id, a, composite.as_ref(), 1_000_000_000);
        let done = agent.invoke(&work);
        assert_eq!(reply_of(&done).status, InvocationStatus::Done);
        let used = work.gas - reply_of(&done).gas_remaining;
        (LAST_GAS.with(|gas| gas.get()), used)
    };
    // Warm the program binding, as every later invocation finds it.
    run(&mut agent, None);
    let (plain, actor) = run(&mut agent, None);
    eprintln!("plain: runtime gas {} (actor {actor})", plain - actor);
    for (label, actor_index) in [("same program", b), ("other program", c)] {
        for steps in [1usize, 8, 32] {
            let composite = Composite {
                mode: CompositeMode::Isolated,
                steps: (0..steps).map(|_| agent.step(actor_index)).collect(),
            };
            let (total, actor) = run(&mut agent, Some(composite));
            let runtime = total - actor;
            eprintln!(
                "{label}, {steps} steps: runtime gas {runtime}, {} per step over plain",
                (runtime - (plain - actor.min(plain))) / steps as u64
            );
        }
    }
}
