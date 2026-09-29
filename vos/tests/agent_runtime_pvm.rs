use ed25519_dalek::{Signer as _, SigningKey};
use vos::Encode as _;
use vos::agent::STANDARD_RUNTIME_PROGRAM_ID;
use vos::agent::package_admission::{
    AdmittedActorPackage, AdmittedRuntimePackage, PackageAdmissionError, admit_actor_package,
    admit_runtime_package,
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
    ActorDirectoryRecord, ActorEntry, ActorId, AgentDescriptor, AgentId, AgentIdentity,
    AgentProfile, AgentReplica, BlobRef, DeploymentId, Hash, InstallationId,
    InvocationAcknowledgement, InvocationAuthorization, InvocationError, InvocationId,
    InvocationStatus, InvocationWork, LaneSet, ManagementError, ManagementReply, ManagementRequest,
    MethodMode, NodeId, PrincipalId, ProducerId, ProgramId, ReplicaRole, ResumeWork, RuntimeBlob,
    RuntimeCapabilities, RuntimeExecutionContext, RuntimeOutcome, RuntimeRequirements,
    RuntimeState, RuntimeTransition, RuntimeWork, SpaceId, StateLane, YieldReason,
};
use vos_pvm::ExitReason;
use vos_pvm::refine::{MemoryModel, PreparedProgram};
use vos_pvm::refine_host::RefineContext;
use vos_pvm_compiler::assembler::{Assembler, Reg};

const AGENT_RUNTIME_PVM: &[u8] = include_bytes!("../../vosx/blobs/agent_runtime.pvm");
const GAS: u64 = 1_000_000_000;
const PACKAGE_SEED: [u8; 32] = [0x71; 32];
const AUTHORITY_SEED: [u8; 32] = [0x72; 32];

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "agent_runtime_pvm/custom_linear.rs"]
mod custom_linear;

thread_local! {
    static COMPARISON_PROGRAM: std::cell::RefCell<Option<(Vec<u8>, PreparedProgram)>> =
        const { std::cell::RefCell::new(None) };
    static COMPARISON_REFERENCE: std::cell::RefCell<Option<(Vec<u8>, PreparedProgram)>> =
        const { std::cell::RefCell::new(None) };
}

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
    let bytes = package
        .signing_bytes()
        .expect("canonical package signing bytes");
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

fn runtime_package_bytes() -> Vec<u8> {
    runtime_package_bytes_for(AGENT_RUNTIME_PVM)
}

fn runtime_package_bytes_for(runtime_pvm: &[u8]) -> Vec<u8> {
    sign_package(PackageEnvelope {
        manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: "standard-local-runtime".into(),
            external_state_limits: None,
            outer_program: BlobRef::of_bytes(runtime_pvm),
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            signing: package_signing(),
        }),
        artifacts: vec![artifact(runtime_pvm)],
    })
    .encode()
    .expect("encode signed VOS3 runtime package")
}

fn admitted_runtime() -> AdmittedRuntimePackage {
    admit_runtime_package(&runtime_package_bytes()).expect("admit bundled VOS3 runtime")
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
    let value = AgentDescriptor {
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
    };
    value.validate().expect("valid clean Agent descriptor");
    value
}

fn operation_for(
    request: &ManagementRequest,
) -> (
    AuthorityOperationKind,
    Option<ActorId>,
    Option<DeploymentId>,
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
        ManagementRequest::PrivateControl { .. } => {
            panic!("private control is not a generic Local/Shared management request")
        }
        ManagementRequest::InspectActors { .. }
        | ManagementRequest::InspectResources
        | ManagementRequest::InspectManagementHistory => {
            panic!("read-only management does not carry authority")
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
            space: invocation.space,
            agent: invocation.agent,
            operation: AuthorityOperationKind::InvokeActor,
            runtime_deployment: invocation.runtime_deployment,
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

fn apply_runtime(work: RuntimeWork) -> RuntimeTransition {
    apply_runtime_program(AGENT_RUNTIME_PVM, work, GAS)
}

fn apply_runtime_program(runtime_pvm: &[u8], work: RuntimeWork, gas: u64) -> RuntimeTransition {
    let input = work.encode().expect("encode canonical r7 RuntimeWork");
    let comparing = std::env::var_os("VOS_AGENT_COMPARE_BACKENDS").is_some();
    let started = std::time::Instant::now();
    let invocation = if comparing {
        // Warm comparisons must cache both preparations, not compare a cold
        // interpreter load to warm native code. The first call is cold for both.
        COMPARISON_REFERENCE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_none_or(|(bytes, _)| bytes != runtime_pvm) {
                *slot = Some((
                    runtime_pvm.to_vec(),
                    PreparedProgram::new(runtime_pvm).expect("prepare reference interpreter"),
                ));
            }
            RefineContext::load_prepared(&slot.as_ref().unwrap().1, &input, gas, MemoryModel::Auto)
                .expect("load prepared reference interpreter")
        })
    } else {
        RefineContext::load(runtime_pvm, &input, gas).expect("load bundled AgentRuntime")
    };
    let reference_preparation = started.elapsed();
    let started = std::time::Instant::now();
    let invocation = invocation.run();
    let reference_execution = started.elapsed();
    if comparing {
        // This switch runs the exact physical work through both backends; it
        // must never turn a missing recompiler into a passing interpreter-only
        // test. Preparation is bounded to one exact program per test thread.
        let started = std::time::Instant::now();
        let (native, cold) = COMPARISON_PROGRAM.with(|slot| {
            let mut slot = slot.borrow_mut();
            let cold = slot.as_ref().is_none_or(|(bytes, _)| bytes != runtime_pvm);
            if cold {
                *slot = Some((
                    runtime_pvm.to_vec(),
                    PreparedProgram::new_with_backend(
                        runtime_pvm,
                        vos_pvm::PvmBackend::ForceRecompiler,
                    )
                    .expect("prepare selected recompiler"),
                ));
            }
            (
                RefineContext::load_prepared(
                    &slot.as_ref().unwrap().1,
                    &input,
                    gas,
                    MemoryModel::Auto,
                )
                .expect("load recompiled AgentRuntime"),
                cold,
            )
        });
        let native_preparation = started.elapsed();
        let started = std::time::Instant::now();
        let native = native.try_run().expect("execute recompiled AgentRuntime");
        let native_execution = started.elapsed();
        assert_eq!(native.exit, invocation.exit, "backend exit differs");
        assert_eq!(native.pc, invocation.pc, "backend PC differs");
        assert_eq!(native.gas_used, invocation.gas_used, "backend gas differs");
        assert_eq!(
            native.registers, invocation.registers,
            "backend registers differ"
        );
        assert_eq!(
            native.output_bounded(RuntimeTransition::MAX_ENCODED_BYTES),
            invocation.output_bounded(RuntimeTransition::MAX_ENCODED_BYTES),
            "canonical transition bytes/commitments differ",
        );
        let operation = match &work {
            RuntimeWork::Manage { request, .. } => match request.as_ref() {
                ManagementRequest::Create(_) => "create",
                ManagementRequest::Install(_) => "install",
                _ => "management",
            },
            RuntimeWork::Invoke { .. } => "invoke",
            RuntimeWork::Resume { .. } => "resume",
            RuntimeWork::Acknowledge { .. } => "ack",
            #[cfg(feature = "experimental-state-blocks")]
            RuntimeWork::InspectInvocation { .. } => "inspect-invocation",
        };
        eprintln!(
            "backend_comparison operation={operation} cold={cold} input_bytes={} interpreter_prepare_us={} interpreter_execute_us={} recompiler_prepare_us={} recompiler_execute_us={} gas_used={}",
            input.len(),
            reference_preparation.as_micros(),
            reference_execution.as_micros(),
            native_preparation.as_micros(),
            native_execution.as_micros(),
            invocation.gas_used,
        );
    }
    assert_eq!(
        invocation.exit,
        ExitReason::Halt,
        "bundled AgentRuntime exited at instruction {} with registers {:?}",
        invocation.pc,
        invocation.registers,
    );
    RuntimeTransition::decode(
        &invocation
            .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
            .expect("bundled AgentRuntime published an output window"),
    )
    .expect("decode canonical r7 RuntimeTransition")
}

fn apply_management(
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> RuntimeTransition {
    apply_management_program(
        AGENT_RUNTIME_PVM,
        descriptor,
        state,
        request,
        authority,
        observed_slot,
    )
}

fn apply_management_program(
    runtime_pvm: &[u8],
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> RuntimeTransition {
    let runtime_deployment = authority
        .as_ref()
        .map_or(descriptor.identity.runtime_deployment, |receipt| {
            receipt.selector.runtime_deployment
        });
    apply_runtime_program(
        runtime_pvm,
        RuntimeWork::Manage {
            context: RuntimeExecutionContext::Direct,
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            runtime_deployment,
            state,
            request: Box::new(request),
            authority: authority.map(Box::new),
            observed_slot,
        },
        GAS,
    )
}

fn restart(transition: &RuntimeTransition) -> RuntimeTransition {
    RuntimeTransition::decode(
        &transition
            .encode()
            .expect("persist canonical RuntimeTransition bytes"),
    )
    .expect("restore canonical RuntimeTransition bytes")
}

fn create_agent(discriminator: u8) -> (AdmittedRuntimePackage, AgentDescriptor, RuntimeState) {
    let runtime = admitted_runtime();
    let (descriptor, state) = create_agent_with_runtime(AGENT_RUNTIME_PVM, &runtime, discriminator);
    (runtime, descriptor, state)
}

fn create_agent_with_runtime(
    runtime_pvm: &[u8],
    runtime: &AdmittedRuntimePackage,
    discriminator: u8,
) -> (AgentDescriptor, RuntimeState) {
    let descriptor = descriptor(&runtime, discriminator);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let receipt = management_receipt(&descriptor, &request, 1, 1, 2);
    let created = apply_management_program(
        runtime_pvm,
        &descriptor,
        RuntimeState::default(),
        request,
        Some(receipt),
        1,
    );
    assert_eq!(
        created.outcome,
        RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity.clone())))
    );
    assert!(!created.state.is_empty());
    (descriptor, restart(&created).state)
}

fn static_actor_program() -> Vec<u8> {
    // Actor output: status, three little-endian lane lengths, Linear bytes,
    // then reply bytes.
    let mut output = vec![vos::actors::STATUS_DONE];
    output.extend_from_slice(&1u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.push(0x2a);
    output.push(0x63);
    let mut actor = Assembler::new();
    actor
        .set_rw_data(output.clone())
        .load_imm_64(Reg::A0, 2 * u64::from(vos_pvm::PVM_ZONE_SIZE))
        .load_imm_64(Reg::A1, output.len() as u64)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

fn yielding_actor_program() -> Vec<u8> {
    let yielded = [
        vos::actors::STATUS_YIELDED,
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
        vos::actors::STATUS_DONE,
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
        .ecalli(vos::abi::hostcall::SUSPEND)
        .branch_eq_imm(Reg::A0, 0, FIRST_YIELD - FIRST_BRANCH)
        .ecalli(vos::abi::hostcall::SUSPEND)
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
    let schema_bytes = schema.encode().expect("encode actor schema");
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
    let policy_bytes = policies.encode().expect("encode actor method policy");
    let introspection = ActorIntrospectionArtifact {
        actor_schema: BlobRef::of_bytes(&schema_bytes),
        method_policy: BlobRef::of_bytes(&policy_bytes),
        actor_doc: "physical clean AgentRuntime fixture".into(),
        methods: vec![ActorMethodIntrospection {
            name: "write".into(),
            doc: String::new(),
            cli_exposure: CliExposure::Exposed,
            timeout_ms: 0,
            dispatch: MethodDispatch::Sync,
        }],
    };
    let introspection_bytes = introspection.encode().expect("encode actor introspection");
    let task_bytes = TaskDependencySetArtifact {
        dependencies: Vec::new(),
    }
    .encode()
    .expect("encode empty task closure");
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
            signing: package_signing(),
        }),
        artifacts,
    });
    admit_actor_package(&envelope.encode().expect("encode signed VOS3 actor package"))
        .expect("admit VOS3 actor package")
}

fn install_request(
    descriptor: &AgentDescriptor,
    package: &AdmittedActorPackage,
) -> ManagementRequest {
    let schema = sdk::schema::decode(package.state_lane_schema_bytes())
        .expect("decode admitted actor schema");
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
        constructor_abi: schema.constructor_abi().expect("actor constructor ABI"),
        installation_data: None,
        state_layout: schema.state_layout_hash().expect("actor state layout"),
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
        constructor_abi: schema.constructor_abi().expect("actor constructor ABI"),
        installation_data: None,
        state_layout: schema.state_layout_hash().expect("actor state layout"),
        contract: package.manifest().contract,
        requirements: package.requirements(),
    }))
}

fn inspect_actor(descriptor: &AgentDescriptor, state: RuntimeState) -> ActorDirectoryRecord {
    inspect_actor_with_runtime(AGENT_RUNTIME_PVM, descriptor, state)
}

fn inspect_actor_with_runtime(
    runtime_pvm: &[u8],
    descriptor: &AgentDescriptor,
    state: RuntimeState,
) -> ActorDirectoryRecord {
    let inspected = apply_management_program(
        runtime_pvm,
        descriptor,
        state,
        ManagementRequest::InspectActors {
            after: None,
            limit: 4,
        },
        None,
        u64::MAX,
    );
    let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = inspected.outcome else {
        panic!("physical inspection did not return an actor page")
    };
    assert_eq!(page.entries.len(), 1);
    page.entries[0].clone()
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

fn actor_invocation(
    descriptor: &AgentDescriptor,
    record: &ActorDirectoryRecord,
    package: &AdmittedActorPackage,
    id: u8,
) -> InvocationWork {
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&vos::value::Msg::new("write").encode());
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

fn install_actor(
    runtime: &AdmittedRuntimePackage,
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    package: &AdmittedActorPackage,
) -> (RuntimeState, ManagementRequest, RuntimeOutcome) {
    install_actor_with_runtime(AGENT_RUNTIME_PVM, runtime, descriptor, state, package)
}

fn install_actor_with_runtime(
    runtime_pvm: &[u8],
    runtime: &AdmittedRuntimePackage,
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    package: &AdmittedActorPackage,
) -> (RuntimeState, ManagementRequest, RuntimeOutcome) {
    package
        .require_runtime(AgentProfile::Local, runtime)
        .expect("actor package is compatible with the admitted runtime");
    let request = install_request(descriptor, package);
    let receipt = management_receipt(descriptor, &request, 2, 2, 2);
    let installed = apply_management_program(
        runtime_pvm,
        descriptor,
        state,
        request.clone(),
        Some(receipt.clone()),
        2,
    );
    assert!(matches!(
        installed.outcome,
        RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
    ));

    let retried = apply_management_program(
        runtime_pvm,
        descriptor,
        restart(&installed).state,
        request.clone(),
        Some(receipt),
        50,
    );
    assert_eq!(retried.outcome, installed.outcome);
    assert_eq!(retried.state, installed.state);
    (retried.state, request, retried.outcome)
}

fn resume_work(yielded: &sdk::YieldedInvocation, availability: Vec<RuntimeBlob>) -> ResumeWork {
    ResumeWork {
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

#[test]
fn bundled_runtime_identity_and_vos3_package_are_exactly_pinned() {
    let bytes = runtime_package_bytes();
    assert_eq!(&bytes[..4], b"VOS3");
    let runtime = admit_runtime_package(&bytes).expect("admit exact runtime package");
    assert_eq!(runtime.exact_bytes(), bytes);
    assert_eq!(runtime.program(), ProgramId::of_pvm(AGENT_RUNTIME_PVM));
    assert_eq!(runtime.program().0, STANDARD_RUNTIME_PROGRAM_ID.0);
    assert_eq!(
        runtime.manifest().outer_program,
        BlobRef::of_bytes(AGENT_RUNTIME_PVM)
    );
    assert_eq!(
        sdk::RUNTIME_ABI_ID,
        Hash(*b"vos-agent-runtime-abi-260920-r19")
    );

    let mut previous_generation = bytes;
    previous_generation[..4].copy_from_slice(b"VOS2");
    assert!(matches!(
        admit_runtime_package(&previous_generation),
        Err(PackageAdmissionError::PreviousGeneration)
    ));
}

#[test]
fn bundled_runtime_creates_restarts_and_recovers_the_exact_management_result() {
    let runtime = admitted_runtime();
    let descriptor = descriptor(&runtime, 1);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let receipt = management_receipt(&descriptor, &request, 1, 1, 2);

    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    let rejected = apply_management(
        &descriptor,
        RuntimeState::default(),
        request.clone(),
        Some(forged),
        1,
    );
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Management(Err(ManagementError::InvalidRequest))
    );
    let rejected_state = rejected.state;
    let inspected_rejection = apply_management(
        &descriptor,
        rejected_state.clone(),
        ManagementRequest::InspectResources,
        None,
        u64::MAX,
    );
    assert_eq!(
        inspected_rejection.outcome,
        RuntimeOutcome::Management(Err(ManagementError::NotCreated))
    );
    assert_eq!(inspected_rejection.state, rejected_state);

    let created = apply_management(
        &descriptor,
        RuntimeState::default(),
        request.clone(),
        Some(receipt.clone()),
        1,
    );
    assert_eq!(
        created.outcome,
        RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity.clone())))
    );
    let restarted = restart(&created);
    assert_eq!(restarted, created);

    let retried = apply_management(&descriptor, restarted.state, request, Some(receipt), 100);
    assert_eq!(retried.outcome, created.outcome);
    assert_eq!(retried.state, created.state);

    let inspected = apply_management(
        &descriptor,
        retried.state.clone(),
        ManagementRequest::InspectActors {
            after: None,
            limit: 16,
        },
        None,
        u64::MAX,
    );
    assert_eq!(inspected.state, retried.state);
    assert_eq!(
        inspected.outcome,
        RuntimeOutcome::Management(Ok(ManagementReply::Actors(sdk::ActorDirectoryPage {
            entries: Vec::new(),
            next: None,
        })))
    );
}

#[test]
fn bundled_runtime_installs_exact_catalog_executes_retries_and_acknowledges() {
    let (runtime, descriptor, created) = create_agent(2);
    let actor_package = admitted_actor_program(static_actor_program());
    assert_eq!(&actor_package.exact_bytes()[..4], b"VOS3");
    let (installed, install, _) = install_actor(&runtime, &descriptor, created, &actor_package);
    let record = inspect_actor(&descriptor, installed.clone());
    let ManagementRequest::Install(expected) = &install else {
        unreachable!("fixture is an Install request")
    };
    assert_eq!(record.entry, expected.entry);

    let work = actor_invocation(&descriptor, &record, &actor_package, 0xa1);
    let authority = invocation_receipt(&descriptor, &work, 3, 3);

    let mut missing_catalog = work.clone();
    missing_catalog
        .availability
        .retain(|blob| blob.reference != BlobRef::of_bytes(actor_package.program_bytes()));
    let missing_authority = invocation_receipt(&descriptor, &missing_catalog, 3, 3);
    let rejected = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed.clone(),
        invocation: Box::new(missing_catalog),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(missing_authority)),
        observed_slot: 3,
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::InvalidAvailability))
    );
    assert_eq!(rejected.state, installed);

    let mut forged = authority.clone();
    forged.signature[0] ^= 1;
    let rejected = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed.clone(),
        invocation: Box::new(work.clone()),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(forged)),
        observed_slot: 3,
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
    );
    assert_eq!(rejected.state, installed);

    let mut wrong_route = work.clone();
    wrong_route.agent = AgentId([0xe1; 32]);
    let wrong_route_authority = invocation_receipt(&descriptor, &wrong_route, 3, 3);
    let rejected = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed.clone(),
        invocation: Box::new(wrong_route),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(
            wrong_route_authority,
        )),
        observed_slot: 3,
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::InvalidAuthorization))
    );
    assert_eq!(rejected.state, installed);

    let completed = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed.clone(),
        invocation: Box::new(work.clone()),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority.clone())),
        observed_slot: 3,
    });
    let RuntimeOutcome::Completed(Ok(reply)) = &completed.outcome else {
        panic!(
            "physical clean invocation did not complete: {:?}",
            completed.outcome
        )
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    assert_eq!(reply.lane, Some(StateLane::Linear));
    assert_eq!(reply.reply, [0x63]);
    assert_eq!(reply.observation.linear_revision, Some(1));
    assert_eq!(completed.state.control, installed.control);
    assert_ne!(completed.state.linear, installed.linear);
    assert_eq!(completed.state.merge, installed.merge);
    assert_eq!(completed.state.local, installed.local);

    let restarted = restart(&completed);
    let retried = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: restarted.state,
        invocation: Box::new(work.clone()),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority.clone())),
        observed_slot: 100,
    });
    assert_eq!(retried.outcome, completed.outcome);

    let mut divergent = work.clone();
    let mut divergent_message = vec![vos::value::TAG_DYNAMIC];
    divergent_message.extend_from_slice(
        &vos::value::Msg::new("write")
            .with("divergent", vos::value::Value::Bool(true))
            .encode(),
    );
    divergent.message = divergent_message;
    let divergent_authority = invocation_receipt(&descriptor, &divergent, 3, 100);
    let rejected = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: retried.state.clone(),
        invocation: Box::new(divergent),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(
            divergent_authority,
        )),
        observed_slot: 100,
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation))
    );
    assert_eq!(rejected.state, retried.state);

    let mut forged_ack = authority.clone();
    forged_ack.signature[0] ^= 1;
    let rejected = apply_runtime(RuntimeWork::Acknowledge {
        context: RuntimeExecutionContext::Direct,
        state: retried.state.clone(),
        invocation: Box::new(sdk::InvocationRetirement::from_work(&work)),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(forged_ack)),
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Acknowledged(Err(InvocationError::InvalidAuthorization))
    );
    assert_eq!(rejected.state, retried.state);

    let mut wrong_actor = work.clone();
    wrong_actor.actor = ActorId([0xe2; 32]);
    let wrong_actor_authority = invocation_receipt(&descriptor, &wrong_actor, 3, 3);
    let rejected = apply_runtime(RuntimeWork::Acknowledge {
        context: RuntimeExecutionContext::Direct,
        state: retried.state.clone(),
        invocation: Box::new(sdk::InvocationRetirement::from_work(&wrong_actor)),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(
            wrong_actor_authority,
        )),
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Acknowledged(Err(InvocationError::DivergentInvocation))
    );
    assert_eq!(rejected.state, retried.state);

    let acknowledged = apply_runtime(RuntimeWork::Acknowledge {
        context: RuntimeExecutionContext::Direct,
        state: retried.state,
        invocation: Box::new(sdk::InvocationRetirement::from_work(&work)),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority.clone())),
    });
    let expected_acknowledgement = InvocationAcknowledgement {
        invocation: work.invocation,
        actor: work.actor,
        incarnation: work.incarnation,
        deployment: work.deployment,
        mode: work.mode,
        work: work.commitment(),
        authorization: InvocationAuthorization::AuthorityReceipt(authority.clone()).commitment(),
    };
    assert_eq!(
        acknowledged.outcome,
        RuntimeOutcome::Acknowledged(Ok(expected_acknowledgement.clone()))
    );

    let restarted = restart(&acknowledged);
    let replayed = apply_runtime(RuntimeWork::Acknowledge {
        context: RuntimeExecutionContext::Direct,
        state: restarted.state.clone(),
        invocation: Box::new(sdk::InvocationRetirement::from_work(&work)),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority.clone())),
    });
    assert_eq!(
        replayed.outcome,
        RuntimeOutcome::Acknowledged(Ok(expected_acknowledgement))
    );
    assert_eq!(replayed.state, restarted.state);

    // Retirement wins over later expiry: replaying an acknowledged invocation
    // must never reopen its result lifecycle or execute the actor again.
    let retired = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: restarted.state.clone(),
        invocation: Box::new(work),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority)),
        observed_slot: 100,
    });
    assert_eq!(
        retired.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::DivergentInvocation))
    );
    assert_eq!(retired.state, restarted.state);
}

#[test]
fn bundled_runtime_persists_and_resumes_fifo_continuations() {
    let (runtime, descriptor, created) = create_agent(3);
    let actor_package = admitted_actor_program(yielding_actor_program());
    let (installed, _, _) = install_actor(&runtime, &descriptor, created, &actor_package);
    let record = inspect_actor(&descriptor, installed.clone());
    let work = actor_invocation(&descriptor, &record, &actor_package, 0xb1);
    let authority = invocation_receipt(&descriptor, &work, 3, 3);

    let first_transition = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed,
        invocation: Box::new(work.clone()),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority.clone())),
        observed_slot: 3,
    });
    let RuntimeOutcome::Yielded(first) = &first_transition.outcome else {
        panic!("initial physical execution did not yield")
    };
    assert_eq!(first.reason, YieldReason::Cooperative);
    assert_eq!(first.ready_sequence, 1);

    let retried = apply_runtime(RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: restart(&first_transition).state,
        invocation: Box::new(work.clone()),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority)),
        observed_slot: 100,
    });
    assert_eq!(retried, first_transition);

    let mut wrong_sequence = resume_work(first, work.availability.clone());
    wrong_sequence.ready_sequence += 1;
    let rejected = apply_runtime(RuntimeWork::Resume {
        context: RuntimeExecutionContext::Direct,
        state: retried.state.clone(),
        resume: Box::new(wrong_sequence),
    });
    assert_eq!(
        rejected.outcome,
        RuntimeOutcome::Completed(Err(InvocationError::NotReady))
    );
    assert_eq!(rejected.state, retried.state);

    let second_transition = apply_runtime(RuntimeWork::Resume {
        context: RuntimeExecutionContext::Direct,
        state: retried.state,
        resume: Box::new(resume_work(first, work.availability.clone())),
    });
    let RuntimeOutcome::Yielded(second) = &second_transition.outcome else {
        panic!("first physical Resume did not yield")
    };
    assert_eq!(second.reason, YieldReason::Cooperative);
    assert_eq!(second.ready_sequence, 2);

    let completed = apply_runtime(RuntimeWork::Resume {
        context: RuntimeExecutionContext::Direct,
        state: restart(&second_transition).state,
        resume: Box::new(resume_work(second, work.availability)),
    });
    let RuntimeOutcome::Completed(Ok(reply)) = completed.outcome else {
        panic!("second physical Resume did not complete")
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    assert_eq!(reply.reply, [2]);
}

/// This regression consumes a freshly compiled `agent-runtime` PVM rather
/// than the checked-in pin. Keeping it ignored makes the source/guest ABI
/// check explicit without silently blessing or rewriting the release pin.
/// Both backends, prepared once per test thread, run the exact same
/// AgentRuntime work at `gas` and must agree on every observable: load
/// refusal, exit, counter, registers, gas to the unit and output bytes.
/// Independent of `VOS_AGENT_COMPARE_BACKENDS`, which only instruments
/// `apply_runtime_program`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn assert_backends_agree(runtime_pvm: &[u8], input: &[u8], gas: u64) {
    use vos_pvm::PvmBackend;
    type Prepared = (Vec<u8>, PreparedProgram, PreparedProgram);
    thread_local! {
        static PAIR: std::cell::RefCell<Option<Prepared>> = const { std::cell::RefCell::new(None) };
    }
    PAIR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_none_or(|(bytes, _, _)| bytes != runtime_pvm)
        {
            *slot = Some((
                runtime_pvm.to_vec(),
                PreparedProgram::new_with_backend(runtime_pvm, PvmBackend::ForceInterpreter)
                    .unwrap(),
                PreparedProgram::new_with_backend(runtime_pvm, PvmBackend::ForceRecompiler)
                    .unwrap(),
            ));
        }
        let (_, reference, native) = slot.as_ref().unwrap();
        let run = |prepared: &PreparedProgram| {
            RefineContext::load_prepared(prepared, input, gas, MemoryModel::Auto)
                .and_then(RefineContext::try_run)
                .map(|invocation| {
                    (
                        invocation.exit.clone(),
                        invocation.pc,
                        invocation.gas_used,
                        invocation.registers,
                        invocation.output_bounded(RuntimeTransition::MAX_ENCODED_BYTES),
                    )
                })
        };
        assert_eq!(
            run(native),
            run(reference),
            "the backends diverge on the AgentRuntime at gas {gas}"
        );
    });
}

fn faulting_actor_program() -> Vec<u8> {
    // Load from 256 MiB, far above any region of a standard actor image.
    let mut actor = Assembler::new();
    actor
        .load_imm_64(Reg::A2, 0x1000_0000)
        .load_ind_u64(Reg::A0, Reg::A2, 0)
        .jump_ind(Reg::RA, 0);
    actor.build_standard()
}

fn spinning_actor_program() -> Vec<u8> {
    // A one-instruction block that jumps to itself until the actor's gas is
    // spent: out-of-gas at a block boundary, inside an inner machine.
    let mut actor = Assembler::new();
    actor.jump(0);
    actor.build_standard()
}

fn invoke_once(
    program: Vec<u8>,
    discriminator: u8,
    gas: Option<u64>,
) -> (RuntimeWork, RuntimeTransition) {
    let (runtime, descriptor, created) = create_agent(discriminator);
    let actor_package = admitted_actor_program(program);
    let (installed, _, _) = install_actor(&runtime, &descriptor, created, &actor_package);
    let record = inspect_actor(&descriptor, installed.clone());
    let mut work = actor_invocation(&descriptor, &record, &actor_package, discriminator);
    if let Some(gas) = gas {
        work.gas = gas;
    }
    let authority = invocation_receipt(&descriptor, &work, 3, 3);
    let work = RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state: installed,
        invocation: Box::new(work),
        authorization: Box::new(InvocationAuthorization::AuthorityReceipt(authority)),
        observed_slot: 3,
    };
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    assert_backends_agree(AGENT_RUNTIME_PVM, &work.encode().unwrap(), GAS);
    let transition = apply_runtime(work.clone());
    (work, transition)
}

/// Actor page faults and actor out-of-gas cross the inner-machine boundary
/// as exits the runtime must handle; on Linux x86-64 both backends must
/// report them identically.
#[test]
fn faulting_and_spinning_actors_fail_identically_on_both_backends() {
    fn failed(transition: &RuntimeTransition) -> bool {
        match &transition.outcome {
            RuntimeOutcome::Completed(Ok(reply)) => reply.status != InvocationStatus::Done,
            _ => true,
        }
    }
    let (_, faulted) = invoke_once(faulting_actor_program(), 0x51, None);
    assert!(
        failed(&faulted),
        "a faulting actor cannot complete: {:?}",
        faulted.outcome
    );
    for gas in [1, 2, 3, 1_000, 10_000, 100_000] {
        let (_, spun) = invoke_once(spinning_actor_program(), 0x52, Some(gas));
        assert!(
            failed(&spun),
            "a spinning actor cannot complete: {:?}",
            spun.outcome
        );
    }
}

/// The whole Agent path at many gas budgets: one yielding invocation, with
/// the runtime's budget cut at 65 evenly spaced points and at every unit
/// around the total, so out-of-gas lands in the runtime's own blocks, in the
/// machine calls and inside the actor.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn agent_executions_match_across_backends_at_sampled_gas_budgets() {
    let (work, _) = invoke_once(yielding_actor_program(), 0x53, None);
    let input = work.encode().unwrap();
    let used = RefineContext::load(AGENT_RUNTIME_PVM, &input, GAS)
        .unwrap()
        .run()
        .gas_used;
    let mut budgets: std::collections::BTreeSet<u64> = (0..=64).map(|i| used * i / 64).collect();
    budgets.extend(used.saturating_sub(8)..=used + 2);
    for gas in &budgets {
        assert_backends_agree(AGENT_RUNTIME_PVM, &input, *gas);
    }
    eprintln!("{} budgets up to {used} gas matched", budgets.len());
}

#[test]
#[ignore = "set VOS_AGENT_RUNTIME_PVM to a freshly compiled bundled guest PVM"]
fn compiled_runtime_directory_reports_exact_install_lineage_after_restart() {
    let path = std::env::var_os("VOS_AGENT_RUNTIME_PVM").expect("candidate PVM path");
    let pvm = std::fs::read(path).expect("read candidate PVM");
    let runtime = admit_runtime_package(&runtime_package_bytes_for(&pvm)).unwrap();
    let (descriptor, created) = create_agent_with_runtime(&pvm, &runtime, 8);
    let actor_package = admitted_actor_program(static_actor_program());
    // This helper also round-trips the installed transition and retries the
    // exact install, requiring unchanged state and the same retained reply.
    let (installed, request, _) =
        install_actor_with_runtime(&pvm, &runtime, &descriptor, created, &actor_package);
    let ManagementRequest::Install(install) = request else {
        unreachable!()
    };
    let record = inspect_actor_with_runtime(&pvm, &descriptor, installed);
    assert_eq!(record.entry, install.entry);
    assert_eq!(record.installation_id, install.installation_id);
    assert_eq!(record.registry_reservation, install.registry_reservation);
    assert_eq!(record.install_request, install.lineage_commitment());
}
