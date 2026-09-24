//! Physical standard-runtime lifecycle with a compiled macro-generated actor.
//! Test-only issuer and in-memory staging: not journal finality or node recovery.
use super::MultiLaneStateBlockHost;
use crate::actors::{
    codec::{Decode, Encode},
    value::{Args, Msg, TAG_DYNAMIC, Value},
};
use crate::agent::{
    journal::ReplayOperation,
    journal_store::{AgentJournalStore, MemoryAgentJournalStore},
    package_admission::{AdmittedStateRuntimePackage, tests::admitted_state_fixture},
    state_block_store::{StateBlockStaging, journal_create_state_work},
};
use crate::agent_sdk::{
    self as sdk,
    state_blocks::ReadBudget,
    state_execution::{ExternalLaneWork, StateExecutionOutput, StateExecutionWork},
    state_root::{RootContext, StateRootDescriptor},
};
use ed25519_dalek::{Signer, SigningKey};
use sdk::wire::CanonicalWire as _;

fn target() -> std::path::PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"))
}

struct Fixture {
    runtime: AdmittedStateRuntimePackage,
    descriptor: sdk::AgentDescriptor,
    store: MemoryAgentJournalStore,
    state: sdk::RuntimeState,
    roots: Vec<StateRootDescriptor>,
    revision: u64,
}

impl Fixture {
    fn create() -> Self {
        let elf = std::fs::read(
            target().join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
        )
        .unwrap();
        let runtime = admitted_state_fixture(vos_pvm_compiler::link_elf_spi(&elf).unwrap());
        let (create, replica, _) = crate::agent::replay::tests::external_create_fixture(&runtime);
        let ReplayOperation::CleanManage {
            request: sdk::ManagementRequest::Create(descriptor),
            ..
        } = &create.operation
        else {
            unreachable!()
        };
        let work = journal_create_state_work(&runtime, &create, replica).unwrap();
        let store = MemoryAgentJournalStore::new(
            create.runtime.agent,
            crate::service::NodeId(replica.node.0),
        )
        .unwrap();
        let capture = MultiLaneStateBlockHost {
            store: &store,
            budget: &mut ReadBudget::new(0, 0),
        }
        .execute_admitted_create(&runtime, &create, replica, 1_000_000_000)
        .unwrap();
        let mut fixture = Self {
            runtime,
            descriptor: descriptor.as_ref().clone(),
            store,
            state: sdk::RuntimeState::default(),
            roots: work.lanes().iter().map(|lane| lane.base).collect(),
            revision: 1,
        };
        fixture.stage(&work, capture.output());
        fixture
    }

    fn stage(&mut self, work: &StateExecutionWork, output: &StateExecutionOutput) {
        for change in output.changes() {
            let index = self
                .roots
                .iter()
                .position(|root| {
                    root.context().scope().lane() == change.next().context().scope().lane()
                })
                .unwrap();
            let base = self.roots[index];
            let selected = work.lanes().iter().find(|lane| lane.base == base).unwrap();
            let mut staging = StateBlockStaging::audit_base(
                &mut self.store,
                base,
                base.context(),
                base.commitment(),
                &mut ReadBudget::new(10000, 10000000),
            )
            .unwrap();
            staging
                .stage_next(change, selected.next, &mut ReadBudget::new(10000, 10000000))
                .unwrap();
            self.roots[index] = change.next();
        }
        self.state = output.transition().state.clone();
        assert!(self.store.heads().unwrap().is_none());
        assert!(self.store.genesis().unwrap().is_none());
    }

    fn run(&mut self, mut inner: sdk::RuntimeWork) -> StateExecutionOutput {
        // Supported management here changes Control only; data roots are reads.
        let read_only = matches!(&inner, sdk::RuntimeWork::Manage { .. });
        match &mut inner {
            sdk::RuntimeWork::Manage { state, .. }
            | sdk::RuntimeWork::Invoke { state, .. }
            | sdk::RuntimeWork::Acknowledge { state, .. } => *state = self.state.clone(),
            _ => unreachable!(),
        }
        self.revision += 1;
        let lanes = self
            .roots
            .iter()
            .map(|base| ExternalLaneWork {
                base: *base,
                next: if read_only {
                    base.context()
                } else {
                    RootContext::new(
                        base.context().scope(),
                        sdk::Hash([0x81; 32]),
                        sdk::Hash::digest(
                            b"fixture/lifecycle/revision",
                            &[&self.revision.to_le_bytes()],
                        ),
                    )
                    .unwrap()
                },
            })
            .collect();
        let work =
            StateExecutionWork::new(inner, lanes, self.runtime.external_state_limits()).unwrap();
        let started = std::time::Instant::now();
        let output = MultiLaneStateBlockHost {
            store: &self.store,
            budget: &mut ReadBudget::new(10000, 10000000),
        }
        .execute_admitted_work(&self.runtime, &work, 10_000_000_000)
        .unwrap();
        if matches!(work.work(), sdk::RuntimeWork::Manage { request, .. } if matches!(request.as_ref(), sdk::ManagementRequest::Install(_)))
        {
            self.check_install_handoff(&work, &output);
        }
        eprintln!(
            "physical lifecycle operation {}: {:?}",
            self.revision,
            started.elapsed()
        );
        self.stage(&work, &output);
        output
    }

    fn manage(
        &mut self,
        request: sdk::ManagementRequest,
        authority: Option<sdk::authority::AuthorityReceipt>,
        slot: u64,
    ) -> StateExecutionOutput {
        self.run(sdk::RuntimeWork::Manage {
            context: sdk::RuntimeExecutionContext::Direct,
            space: self.descriptor.identity.space,
            agent: self.descriptor.identity.agent,
            runtime_deployment: self.runtime.deployment(),
            state: sdk::RuntimeState::default(),
            request: Box::new(request),
            authority: authority.map(Box::new),
            observed_slot: slot,
        })
    }

    fn check_install_handoff(&self, work: &StateExecutionWork, output: &StateExecutionOutput) {
        use crate::agent::{
            journal::{MergeFrontierId, MergeSealId, OrderedEntryId, ReplayInput},
            replay::{ReplayExternalExecution, ReplayPosition},
        };
        let sdk::RuntimeWork::Manage {
            request,
            authority,
            observed_slot,
            ..
        } = work.work()
        else {
            unreachable!()
        };
        let input = ReplayInput {
            runtime: self
                .runtime
                .binding(
                    crate::service::SpaceId(self.descriptor.identity.space.0),
                    crate::service::AgentId(self.descriptor.identity.agent.0),
                )
                .unwrap(),
            operation: ReplayOperation::CleanManage {
                request: request.as_ref().clone(),
                authority: authority.as_ref().unwrap().as_ref().clone(),
                observed_slot: *observed_slot,
            },
        };
        let before = crate::agent::wire::RuntimeState {
            control: self.state.control.clone(),
            linear: self.state.linear.clone(),
            merge: self.state.merge.clone(),
            local: self.state.local.clone(),
        };
        // Position-shape evidence only: publication must authenticate the actual
        // journal fence. A physical handoff is deliberately not a publication seal.
        let position = |fenced: bool| ReplayPosition::Ordered {
            id: OrderedEntryId([0x91; 32]),
            index: 1,
            merge_frontier: MergeFrontierId([0x92; 32]),
            merge_seal: fenced.then_some(MergeSealId([0x93; 32])),
        };
        let captured = ReplayExternalExecution::from_physical_response(
            &input,
            &before,
            position(true),
            work,
            output.clone(),
        )
        .unwrap();
        assert!(captured.owning_lane().is_none());
        assert!(captured.output().changes().is_empty());
        let sdk::RuntimeOutcome::Management(result) = &output.transition().outcome else {
            unreachable!()
        };
        assert_eq!(
            captured.management_result_for(&input, captured.transition()),
            Some(result.clone())
        );
        let mut unrelated = input.clone();
        let ReplayOperation::CleanManage { observed_slot, .. } = &mut unrelated.operation else {
            unreachable!()
        };
        *observed_slot += 1;
        assert!(
            captured
                .management_result_for(&unrelated, captured.transition())
                .is_none()
        );
        assert_eq!(
            captured.transition().state.control,
            output.transition().state.control
        );
        assert!(
            ReplayExternalExecution::from_physical_response(
                &input,
                &before,
                position(false),
                work,
                output.clone(),
            )
            .is_err()
        );
        let mut wrong_reply = output.transition().clone();
        let sdk::RuntimeOutcome::Management(Ok(sdk::ManagementReply::Installed(entry))) =
            &mut wrong_reply.outcome
        else {
            unreachable!()
        };
        entry.deployment.0[0] ^= 1;
        let substituted = StateExecutionOutput::new(work, wrong_reply, vec![]).unwrap();
        assert!(
            ReplayExternalExecution::from_physical_response(
                &input,
                &before,
                position(true),
                work,
                substituted,
            )
            .is_err()
        );
        let mut advanced = work.lanes().to_vec();
        advanced[0].next = RootContext::new(
            advanced[0].base.context().scope(),
            sdk::Hash([0x81; 32]),
            sdk::Hash([0x94; 32]),
        )
        .unwrap();
        let advanced_work =
            StateExecutionWork::new(work.work().clone(), advanced, work.limits()).unwrap();
        let rebound =
            StateExecutionOutput::new(&advanced_work, output.transition().clone(), vec![]).unwrap();
        assert!(
            ReplayExternalExecution::from_physical_response(
                &input,
                &before,
                position(true),
                &advanced_work,
                rebound,
            )
            .is_err()
        );
    }
}

pub(crate) fn compiled_install_fixture(
    descriptor: &sdk::AgentDescriptor,
) -> (sdk::InstallActor, [Vec<u8>; 4], Vec<u8>) {
    use sdk::introspection::{
        ActorIntrospectionArtifact, ActorMethodIntrospection, CliExposure, MethodDispatch,
    };
    use sdk::method_policy::{
        ActorMethodPolicy, ActorMethodPolicyArtifact, AttestationRequirement,
        AuthorizationPolicySelector, IdempotencyRequirement,
    };
    use sdk::package::{
        ActorPackageManifest, PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
    };
    use sdk::task::TaskDependencySetArtifact;
    let elf = std::fs::read(
        target().join("agent-state-actor/riscv64em-vos/release/agent_state_actor.elf"),
    )
    .unwrap();
    let program = vos_pvm_compiler::link_elf_spi(&elf).unwrap();
    let schema_bytes = crate::metadata::raw_named_section_from_elf(&elf, b".vos_agent").unwrap();
    let schema = sdk::schema::decode(&schema_bytes).unwrap();
    assert!(matches!(
        schema.constructor,
        sdk::schema::ConstructorContract::RequiredNamed(_)
    ));
    assert_eq!(schema.lanes(), sdk::LaneSet::of(sdk::StateLane::Linear));
    let schema_ref = sdk::BlobRef::of_bytes(&schema_bytes);
    // Both generated methods are Public, no-argument u64 methods. Verify the
    // emitted authorization surface rather than inventing a permissive policy.
    let authorizations = crate::metadata::decode_agent_authorizations(
        &crate::metadata::raw_agent_authorizations_from_elf(&elf).unwrap(),
    )
    .unwrap();
    assert_eq!(authorizations.len(), 2);
    assert!(authorizations.iter().all(|method| matches!(
        method.selector,
        crate::metadata::ParsedAgentAuthorizationSelector::Public
    )));
    let mut methods: Vec<_> = schema
        .methods
        .iter()
        .map(|method| ActorMethodPolicy {
            name: method.name.clone(),
            mode: method.mode,
            arguments: Vec::new(),
            return_type_identity: "u64".into(),
            authorization_policy: AuthorizationPolicySelector::Public,
            idempotency: IdempotencyRequirement::for_mode(method.mode),
            attestation: AttestationRequirement::None,
        })
        .collect();
    methods.sort_by(|a, b| a.name.cmp(&b.name));
    let policy = ActorMethodPolicyArtifact {
        actor_schema: schema_ref.clone(),
        methods,
    };
    policy.validate_against_schema_bytes(&schema_bytes).unwrap();
    let policy_bytes = policy.encode().unwrap();
    let introspection_bytes = ActorIntrospectionArtifact {
        actor_schema: schema_ref.clone(),
        method_policy: sdk::BlobRef::of_bytes(&policy_bytes),
        actor_doc: "compiled external-state lifecycle fixture".into(),
        methods: schema
            .methods
            .iter()
            .map(|method| ActorMethodIntrospection {
                name: method.name.clone(),
                doc: String::new(),
                cli_exposure: CliExposure::Exposed,
                timeout_ms: 0,
                dispatch: MethodDispatch::Sync,
            })
            .collect(),
    }
    .encode()
    .unwrap();
    let task_bytes = TaskDependencySetArtifact {
        dependencies: Vec::new(),
    }
    .encode()
    .unwrap();
    let package_signer = SigningKey::from_bytes(&[0x72; 32]);
    let public_key = package_signer.verifying_key().to_bytes();
    let artifact = |bytes: &[u8]| PackageArtifact {
        identity: sdk::BlobRef::of_bytes(bytes),
        bytes: bytes.to_vec(),
    };
    let mut artifacts = [
        &program,
        &schema_bytes,
        &policy_bytes,
        &introspection_bytes,
        &task_bytes,
    ]
    .map(|bytes| artifact(bytes));
    artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
    let mut package = PackageEnvelope {
        manifest: PackageManifest::Actor(ActorPackageManifest {
            name: "constructed".into(),
            program: sdk::BlobRef::of_bytes(&program),
            contract: sdk::contract::ActorPackageContract::canonical(),
            state_lane_schema: schema_ref.clone(),
            method_policy: sdk::BlobRef::of_bytes(&policy_bytes),
            introspection: sdk::BlobRef::of_bytes(&introspection_bytes),
            task_dependencies: sdk::BlobRef::of_bytes(&task_bytes),
            scheduling: false,
            requirements: sdk::RuntimeRequirements {
                lanes: schema.lanes(),
                scheduling: false,
                proof_systems: sdk::ProofSystemSet::EMPTY,
            },
            resources: None,
            signing: PackageSigning {
                producer: sdk::ProducerId::of_public_key(&public_key),
                public_key,
                signature: [0; 64],
            },
        }),
        artifacts: artifacts.into(),
    };
    package.manifest.signing_mut().signature = package_signer
        .sign(&package.signing_bytes().unwrap())
        .to_bytes();
    let package_bytes = package.encode().unwrap();
    let admitted = crate::agent::package_admission::admit_actor_package(&package_bytes).unwrap();
    assert_eq!(admitted.state_lane_schema_bytes(), schema_bytes);
    assert_eq!(admitted.method_policy_bytes(), policy_bytes);
    let data = Args::new().with("seed", 41_u64).encode();
    let data_ref = sdk::BlobRef::of_bytes(&data);
    let mut install = crate::agent::wire::tests::clean_install_request(
        descriptor,
        "constructed",
        None,
        0x71,
        schema.lanes(),
    );
    install.entry.program = sdk::ProgramId::of_pvm(&program);
    install.entry.deployment = admitted.deployment();
    install.entry.package = admitted.package_ref().clone();
    install.producer = admitted.producer();
    install.package = admitted.package_ref().clone();
    install.contract = admitted.manifest().contract;
    install.requirements = admitted.requirements();
    install.entry.agent_schema = schema_ref.clone();
    install.agent_schema = schema_ref.clone();
    install.entry.method_policy = sdk::BlobRef::of_bytes(&policy_bytes);
    install.method_policy = install.entry.method_policy.clone();
    install.entry.constructor_abi = schema.constructor_abi().unwrap();
    install.constructor_abi = install.entry.constructor_abi;
    install.entry.state_layout = schema.state_layout_hash().unwrap();
    install.state_layout = install.entry.state_layout;
    install.entry.installation_data = Some(data_ref.clone());
    install.installation_data = Some(sdk::InstallationData {
        reference: data_ref.clone(),
        bytes: data.clone(),
    });
    (
        install,
        [program, schema_bytes, policy_bytes, data],
        package_bytes,
    )
}

#[test]
#[ignore = "requires just build-agent-standard-state-guest and just build-agent-state-actor"]
fn compiled_create_install_constructor_invoke_retry_and_ack() {
    let mut fixture = Fixture::create();
    let (install, [program, schema_bytes, policy_bytes, data], _package_bytes) =
        compiled_install_fixture(&fixture.descriptor);
    let data_ref = sdk::BlobRef::of_bytes(&data);
    let request = sdk::ManagementRequest::Install(Box::new(install.clone()));
    let signing = SigningKey::from_bytes(&[0x31; 32]);
    let authority = crate::agent::replay::tests::signed_opaque_clean_receipt(
        &fixture.descriptor,
        &request,
        fixture.runtime.deployment(),
        2,
        &signing,
    );
    let installed = fixture.manage(request, Some(authority.clone()), 11);
    assert!(matches!(
        installed.transition().outcome,
        sdk::RuntimeOutcome::Management(Ok(sdk::ManagementReply::Installed(_)))
    ));
    let directory = fixture.manage(
        sdk::ManagementRequest::InspectActors {
            after: None,
            limit: 16,
        },
        None,
        11,
    );
    let sdk::RuntimeOutcome::Management(Ok(sdk::ManagementReply::Actors(page))) =
        &directory.transition().outcome
    else {
        unreachable!()
    };
    let record = page.entries[0].clone();
    let mut availability: Vec<_> = [program, schema_bytes, policy_bytes, data]
        .into_iter()
        .map(|bytes| sdk::RuntimeBlob {
            reference: sdk::BlobRef::of_bytes(&bytes),
            bytes,
        })
        .collect();
    availability.sort_by(|a, b| a.reference.cmp(&b.reference));

    for (index, (method, mode, expected)) in [
        ("advance", sdk::MethodMode::Linear, 42),
        ("advance", sdk::MethodMode::Linear, 43),
        ("stored", sdk::MethodMode::LinearizableQuery, 43),
    ]
    .into_iter()
    .enumerate()
    {
        let mut message = vec![TAG_DYNAMIC];
        message.extend(Msg::new(method).encode());
        let invocation = sdk::InvocationWork {
            space: fixture.descriptor.identity.space,
            agent: fixture.descriptor.identity.agent,
            runtime_deployment: fixture.runtime.deployment(),
            invocation: sdk::InvocationId([0x90 + index as u8; 32]),
            actor: record.entry.actor,
            incarnation: record.incarnation,
            deployment: record.entry.deployment,
            program: record.entry.program,
            mode,
            origin: sdk::InvocationOrigin::anonymous(),
            roles: sdk::InvocationRoleClaims::none(),
            message,
            installation_data: Some(data_ref.clone()),
            availability: availability.clone(),
            gas: 100_000_000,
            recovery_only: false,
        };
        let slot = 12 + index as u64;
        let mut receipt = authority.clone();
        receipt.selector.operation = sdk::authority::AuthorityOperationKind::InvokeActor;
        receipt.selector.request = invocation.commitment();
        receipt.selector.decision_sequence = 0;
        receipt.signature = signing.sign(&receipt.signing_bytes()).to_bytes();
        let authorization = sdk::InvocationAuthorization::AuthorityReceipt(receipt);
        let work = sdk::RuntimeWork::Invoke {
            context: sdk::RuntimeExecutionContext::Direct,
            state: sdk::RuntimeState::default(),
            invocation: Box::new(invocation.clone()),
            authorization: Box::new(authorization.clone()),
            observed_slot: slot,
        };
        if index == 0 {
            let before = fixture.state.clone();
            let mut substituted = work.clone();
            let sdk::RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = &mut substituted
            else {
                unreachable!()
            };
            invocation.invocation = sdk::InvocationId([0xaf; 32]);
            let blob = invocation
                .availability
                .iter_mut()
                .find(|blob| blob.reference == data_ref)
                .unwrap();
            blob.bytes = Args::new().with("seed", 99_u64).encode();
            blob.reference = sdk::BlobRef::of_bytes(&blob.bytes);
            invocation.installation_data = Some(blob.reference.clone());
            invocation
                .availability
                .sort_by(|a, b| a.reference.cmp(&b.reference));
            let sdk::InvocationAuthorization::AuthorityReceipt(receipt) = authorization.as_mut()
            else {
                unreachable!()
            };
            receipt.selector.request = invocation.commitment();
            receipt.signature = signing.sign(&receipt.signing_bytes()).to_bytes();
            let denied = fixture.run(substituted);
            assert_eq!(
                denied.transition().outcome,
                sdk::RuntimeOutcome::Completed(Err(sdk::InvocationError::InvalidAvailability))
            );
            assert_eq!(fixture.state, before);
            assert!(denied.changes().is_empty());
        }
        let output = fixture.run(work.clone());
        let sdk::RuntimeOutcome::Completed(Ok(reply)) = &output.transition().outcome else {
            panic!("invoke: {:?}", output.transition().outcome)
        };
        assert_eq!(reply.status, sdk::InvocationStatus::Done);
        assert_eq!(Value::decode(&reply.reply), Value::U64(expected));
        let retry = fixture.run(work);
        assert_eq!(retry.transition(), output.transition());
        assert!(retry.changes().is_empty());
        let ack = fixture.run(sdk::RuntimeWork::Acknowledge {
            context: sdk::RuntimeExecutionContext::Direct,
            state: sdk::RuntimeState::default(),
            invocation: Box::new(sdk::InvocationRetirement::from_work(&invocation)),
            authorization: Box::new(authorization),
        });
        assert!(matches!(
            ack.transition().outcome,
            sdk::RuntimeOutcome::Acknowledged(Ok(_))
        ));
    }
}
