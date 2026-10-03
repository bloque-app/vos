//! Real Authority publication followed by three independently locked external
//! Shared journals. The file fixture isolates application/recovery; the network
//! fixture uses the candidate host, authenticated Raft and applied availability.
use super::*;
use crate::agent::clean_management_intent::{CleanManagementIntent, CleanManagementIntentSlot};
use crate::agent::genesis::VerifiedAgentGenesisProvision;
use crate::agent::journal::{CanonicalJournalRecord, JournalHeads, ReplayOperation};
use crate::agent::journal_store::{
    AgentJournalStore, CatalogBlobResolverFactory, FileAgentJournalStore,
    FileLocalAgentJournalSlot, JournalBlobClass, MemoryAgentJournalStore,
};
use crate::agent::local_journal_driver::{LocalJournalAgentDriver, StandardLocalReplayExecutor};
use crate::agent::replay::{
    NoPrunedOrderedBases, ReplaySealedExternalGenesis, ReplaySealedOrdinaryGenesis,
};
use crate::agent::shared_journal_driver::{
    CleanInvocationReplayRequest, FileSharedArtifactStager, PreparedCleanOrdered,
    SharedJournalAgentDriver, SharedPhysicalApplyOutcome,
};
use crate::agent::shared_raft::{AgentGenerationRouteKey, AgentRaftApplicationLedgerV2};
use crate::agent_sdk::state_blocks::ReadBudget;

type Driver = SharedJournalAgentDriver<FileAgentJournalStore, FileSharedArtifactStager>;

fn budget() -> ReadBudget {
    ReadBudget::new(100_000, 128_000_000)
}

struct ReplicaFiles {
    directory: TestDirectory,
    seal: Arc<ReplaySealedExternalGenesis>,
    committee: AgentReplicaCommittee,
    authority: CommitteeChangeAuthorityBinding,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    intent: HostHash,
}

impl ReplicaFiles {
    fn journal_root(&self) -> PathBuf {
        let agent = self.seal.genesis().runtime().agent;
        let leaf: String = agent.0.iter().map(|byte| format!("{byte:02x}")).collect();
        self.directory.0.join(format!("{leaf}.agent"))
    }

    fn acquire(&self) -> FileLocalAgentJournalSlot {
        let parent = std::fs::File::open(&self.directory.0).unwrap();
        FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            self.journal_root(),
            self.journal_root().with_extension("agent-lock"),
            self.merge.node(),
            self.intent,
            &parent,
            &parent,
        )
        .unwrap()
    }

    fn open(&self, fresh: bool, catalog: &[crate::agent::execution::RuntimeBlob]) -> Driver {
        let slot = self.acquire();
        let mut store = if fresh {
            let mut store = slot
                .open_external_genesis(&self.seal, false, &mut budget())
                .unwrap();
            for blob in catalog {
                store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &blob.reference,
                        &blob.bytes,
                    )
                    .unwrap();
            }
            store
                .initialize_external_local(&self.seal, &mut budget())
                .unwrap();
            store
        } else {
            slot.open_external_journal_with_executor(
                &self.seal,
                |store| {
                    Ok(StandardLocalReplayExecutor::new_shared(
                        store.catalog_blob_resolver()?,
                        self.trust.clone(),
                        self.merge.clone(),
                        vec![self.committee.clone()],
                    ))
                },
                &NoPrunedOrderedBases,
                &mut budget(),
            )
            .unwrap()
            .0
        };
        let generation = AgentGenerationRouteKey::new(
            self.committee.space(),
            self.committee.agent(),
            self.seal.genesis().id(),
            self.seal.admission_record().unwrap().id(),
        )
        .unwrap();
        let ledger = AgentRaftApplicationLedgerV2::open(
            Arc::new(redb::Database::create(self.directory.0.join("raft.redb")).unwrap()),
            generation,
            store.instance_id(),
            self.merge.node(),
            self.committee.clone(),
            self.authority,
        )
        .unwrap();
        let artifacts_path = self.directory.0.join("artifacts");
        if fresh {
            std::fs::create_dir(&artifacts_path).unwrap();
        }
        let artifacts = FileSharedArtifactStager::open(artifacts_path, generation).unwrap();
        if fresh {
            store
                .commit_external_genesis_exposure(&self.seal, self.intent, &mut budget())
                .unwrap();
        }
        SharedJournalAgentDriver::open_external(
            store,
            artifacts,
            ledger,
            self.trust.clone(),
            self.merge.clone(),
            self.seal.clone(),
        )
        .unwrap()
    }
}

fn apply(drivers: &mut [Driver], payloads: Vec<Vec<u8>>) {
    for payload in payloads {
        let mut expected = None;
        for (replica, driver) in drivers.iter_mut().enumerate() {
            let index = driver.append_command_for_test(1, payload.clone()).unwrap();
            assert_eq!(index, *expected.get_or_insert(index));
            assert_eq!(
                driver.apply_next().unwrap_or_else(|error| panic!(
                    "replica {replica} committed slot {index}: {error:?}"
                )),
                SharedPhysicalApplyOutcome::Applied { index }
            );
        }
    }
}

fn ordered(drivers: &mut [Driver], request: CleanInvocationReplayRequest) -> RuntimeOutcome {
    let mut selected = None;
    for driver in drivers.iter() {
        let PreparedCleanOrdered::Proposal { input, payload } = driver
            .prepare_clean_ordered_operation(request.clone())
            .unwrap()
        else {
            panic!("new operation unexpectedly retained");
        };
        assert_eq!(
            &(input, payload.clone()),
            selected.get_or_insert((input, payload))
        );
    }
    let (input, payload) = selected.unwrap();
    apply(drivers, vec![payload]);
    let mut result = None;
    for driver in drivers {
        let outcome = driver.take_clean_ordered_result(input).unwrap();
        assert_eq!(&outcome, result.get_or_insert(outcome.clone()));
    }
    result.unwrap()
}

struct GenesisSigner(SigningKey);
impl super::super::super::genesis_issuance::GenesisClaimSigner for GenesisSigner {
    type Error = ();
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], ()> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn enroll_replica(owner: &mut MemoryBootstrapOwner, node_key: &SigningKey, nonce: u8) {
    use crate::actors::value::Value;
    use crate::agent_sdk::InvocationAuthorization;
    use crate::agent_sdk::authority::{
        AuthorityAdminCall, AuthorityAdminOperation, AuthorityAdminResult,
    };
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let public = key.verifying_key().to_bytes();
    let credential = CredentialId::of_public_key(&public);
    let (attestor, _, _, node) = node_material();
    let mut query = AuthorityProjectionQuery {
        recovery: None,
        authority: owner.authority_target(),
        credential,
        nonce: Hash([nonce; 32]),
        selector: AuthorityProjectionSelector::Credential,
        authentication: AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: public,
            node: NodeId(node.0),
            request_binding: Hash([nonce; 32]),
            signature: [1; 64],
        },
    };
    let signature = attestor.sign(&query.signing_bytes()).to_bytes();
    query.authentication = AuthorityIngressAuthentication::SshNodeAttestation {
        credential_public_key: public,
        node: NodeId(node.0),
        request_binding: Hash([nonce; 32]),
        signature,
    };
    let current =
        AuthorityCredentialProjection::decode(&owner.invoke_authority_projection(query).unwrap())
            .unwrap();
    let target = owner.authority_target();
    let mut material = owner
        .supervisor_invocation_material(owner.pins.agent, target.binding.issuer.actor)
        .unwrap();
    material.root_provenance = false;
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut enrollment = crate::agent_sdk::private::NodeEncryptionEnrollment::from_keys(
        target.space,
        current.principal,
        node_key.verifying_key().to_bytes(),
        [nonce; 32],
        [1; 64],
    );
    enrollment.transport_signature = node_key.sign(&enrollment.signing_bytes()).to_bytes();
    let mut call = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority: target,
        administrator: current.principal,
        credential,
        request_sequence: NonZeroU64::new(current.admin_request_high_water + 1).unwrap(),
        credential_public_key: public,
        authenticated_node: owner.pins.node,
        observed_slot: material.observed_slot,
        expected_generation: current.head.administration_generation,
        operation: AuthorityAdminOperation::EnrollNode { enrollment },
        signature: [1; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    call.verify_with(&RawCredentialVerifier).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_unstable_by(|a, b| a.reference.cmp(&b.reference));
    let work = InvocationWork {
        space: target.space,
        agent: target.system_agent,
        runtime_deployment: target.system_runtime_deployment,
        invocation: call.invocation,
        actor: target.binding.issuer.actor,
        incarnation: material.actor.incarnation,
        deployment: target.binding.issuer.deployment,
        program: target.binding.issuer.program,
        mode: MethodMode::Linear,
        origin: InvocationOrigin {
            principal: Some(current.principal),
            credential: Some(credential),
            transport_node: Some(owner.pins.node),
            actor: None,
            capability: None,
        },
        roles: InvocationRoleClaims::none(),
        message: dynamic_message("administer", "call", Value::Bytes(call.encode().unwrap())),
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: owner.invocation_gas,
        recovery_only: false,
    };
    let auth = InvocationAuthorization::PublicPreflight(
        crate::agent_sdk::PublicPreflight::for_work(&work, call.observed_slot),
    );
    let result = owner
        .supervisor_invoke_terminal(identity, work.clone(), auth.clone())
        .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = result else {
        panic!("node enrollment: {result:?}")
    };
    let Some(Value::Bytes(bytes)) = Value::try_decode(&reply.reply) else {
        panic!("invalid enrollment response")
    };
    let result = AuthorityAdminResult::decode(&bytes).unwrap();
    result.verify_with(&RawCredentialVerifier).unwrap();
    assert_eq!(result.call, call);
    assert!(matches!(
        owner.supervisor_acknowledge(identity, work, auth).unwrap(),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and physical outer PVM"]
fn three_file_replicas_external_clerk_install_invoke_ack_reopen() {
    external_clerk_lifecycle(false, ExternalNetworkExercise::LostResponse);
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_install_invoke_ack_reopen() {
    external_clerk_lifecycle(true, ExternalNetworkExercise::LostResponse);
}

#[derive(Clone, Copy)]
enum ExternalNetworkExercise {
    LostResponse,
    Checkpoint(Option<crate::agent::shared_host::CommonCheckpointCrashStage>),
    RetainedCheckpoint,
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_certified_checkpoint_reopen_and_continue() {
    external_clerk_lifecycle(true, ExternalNetworkExercise::Checkpoint(None));
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_retained_reply_survives_two_checkpoints() {
    external_clerk_lifecycle(true, ExternalNetworkExercise::RetainedCheckpoint);
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_checkpoint_recovers_marker_crash() {
    external_clerk_lifecycle(
        true,
        ExternalNetworkExercise::Checkpoint(Some(
            crate::agent::shared_host::CommonCheckpointCrashStage::Marker,
        )),
    );
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_checkpoint_recovers_journal_crash() {
    external_clerk_lifecycle(
        true,
        ExternalNetworkExercise::Checkpoint(Some(
            crate::agent::shared_host::CommonCheckpointCrashStage::Journal,
        )),
    );
}

#[test]
#[ignore = "requires compiled external runtime/Authority, CLERK_AGENT_PACKAGE and authenticated loopback"]
fn three_network_replicas_external_clerk_checkpoint_recovers_ledger_crash() {
    external_clerk_lifecycle(
        true,
        ExternalNetworkExercise::Checkpoint(Some(
            crate::agent::shared_host::CommonCheckpointCrashStage::Ledger,
        )),
    );
}

fn external_clerk_lifecycle(with_network: bool, exercise: ExternalNetworkExercise) {
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::agent::driver::SdkManagementArtifacts;
    use crate::agent::package_admission::{
        admit_actor_package, tests::admitted_state_fixture_limits,
    };
    use crate::agent_sdk::{InvocationAuthorization, RuntimeExecutionContext};

    if let Ok(filter) = std::env::var("VOS_TEST_BOOTSTRAP_FILTER") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_thread_ids(true)
            .try_init();
    }
    assert!(std::env::var_os("VOS_AGENT_PROFILE_REFINE_MACHINES").is_some());
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let mut fixture = native_candidate_state_authority_fixture(&target);
    struct RejectArchive;
    impl AgentGenesisFinalityVerifier for RejectArchive {
        fn verify_finalized(
            &self,
            _: &crate::agent::genesis::AgentGenesisProvision,
        ) -> Result<(), AgentGenesisFinalityError> {
            Err(AgentGenesisFinalityError::NotFinalized)
        }
    }
    fixture.finality = Arc::new(RejectArchive);
    let mut harness =
        NativeProjectionOwnerHarness::with_real_bootstrap("external-shared-clerk", fixture);
    let owner = harness.owner.as_mut().unwrap();
    let runtime = admitted_state_fixture_limits(
        vos_pvm_compiler::link_elf_spi(
            &std::fs::read(
                target.join("agent-state-standard/riscv64em-vos/release/agent_runtime.elf"),
            )
            .unwrap(),
        )
        .unwrap(),
        LaneSet::of(StateLane::Linear),
        crate::agent_sdk::state_execution::MAX_ADMITTED_EXTERNAL_RUNTIME_STATE_BYTES as u32,
    );
    // Sign the narrowed capabilities into the package, not just the descriptor.
    // Scheduling=false alone does not exclude yield: the host's physical
    // pre-proposal validation separately requires a completed Direct result.
    let mut package = PackageEnvelope::decode(runtime.exact_bytes()).unwrap();
    let PackageManifest::AgentRuntime(manifest) = &mut package.manifest else {
        unreachable!()
    };
    manifest.capabilities.scheduling = false;
    manifest.capabilities.proof_systems = ProofSystemSet::EMPTY;
    let runtime_signer = SigningKey::from_bytes(&[0x67; 32]);
    let public_key = runtime_signer.verifying_key().to_bytes();
    *package.manifest.signing_mut() = PackageSigning {
        producer: ProducerId::of_public_key(&public_key),
        public_key,
        signature: [0; 64],
    };
    package.manifest.signing_mut().signature = runtime_signer
        .sign(&package.signing_bytes().unwrap())
        .to_bytes();
    let runtime =
        crate::agent::package_admission::admit_state_runtime_package(&package.encode().unwrap())
            .unwrap();
    let clerk = admit_actor_package(
        &std::fs::read(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(clerk.manifest().name.as_str(), "clerk-ledger");
    assert_eq!(clerk.requirements().lanes, LaneSet::of(StateLane::Linear));
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([0xd9; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.manifest().signing.producer;
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.manifest().capabilities;
    let keys: Vec<_> = [NODE_SEED, 0x61, 0x62]
        .into_iter()
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    for (index, key) in keys.iter().skip(1).enumerate() {
        enroll_replica(owner, key, 0x63 + index as u8);
    }
    let mut members: Vec<_> = keys
        .iter()
        .map(|key| {
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap();
            let peer = keypair.public().to_peer_id().to_bytes();
            let node = HostNodeId::of_authenticated_peer(&peer);
            AgentReplicaMember::new(
                HostAgentReplica {
                    node,
                    principal: HostPrincipalId(descriptor.identity.owner.0),
                    role: HostReplicaRole::Voter,
                },
                peer.clone(),
                key.verifying_key().to_bytes(),
                Some(crate::agent::genesis::derive_replica_raft_slot(&peer)),
            )
            .unwrap()
        })
        .collect();
    members.sort_by_key(|member| member.replica().node);
    let committee = AgentReplicaCommittee::new(
        HostSpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        HostAgentProfile::Shared,
        members,
    )
    .unwrap();
    descriptor.replicas = committee
        .members()
        .iter()
        .map(|member| AgentReplica {
            node: crate::agent_sdk::NodeId(member.replica().node.0),
            principal: PrincipalId(member.replica().principal.0),
            role: ReplicaRole::Voter,
        })
        .collect();
    descriptor.validate().unwrap();
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &key);
    call.request_sequence = NonZeroU64::new(2).unwrap();
    call.authority = owner.authority_target();
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    let mut slot = CleanManagementIntentSlot::open(IssuerMemoryStore::default()).unwrap();
    slot.pledge(
        CleanManagementIntent::new(
            owner.authority_target(),
            call.managed,
            request,
            call.clone(),
            &RawCredentialVerifier,
        )
        .unwrap(),
    )
    .unwrap();
    let mut issuer = DurableCleanManagementIssuer::open(
        IssuerMemoryStore::default(),
        descriptor.authority,
        descriptor.identity.space,
        descriptor.identity.agent,
    )
    .unwrap();
    assert!(crate::agent::replay::external_shared_descriptor_supported(
        &descriptor
    ));
    committee
        .validate_for_clean_descriptor(&descriptor)
        .unwrap();
    assert!(
        committee
            .member_by_node(HostNodeId(owner.pins.node.0))
            .is_some()
    );
    let mut receipt_signer = CountingSigner::new();
    let prepared = owner
        .prepare_external_shared_from_management_intent(
            &mut slot,
            call.managed,
            &runtime,
            &committee,
            &mut issuer,
            &mut receipt_signer,
        )
        .expect("enrolled signed Shared Create must receive exact Authority admission");
    assert_eq!(prepared.replicas().members().len(), 3);
    let applied = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        owner
            .prepare_external_shared_from_management_intent(
                &mut slot,
                call.managed,
                &runtime,
                &committee,
                &mut issuer,
                &mut receipt_signer,
            )
            .unwrap(),
        prepared
    );
    assert_eq!(receipt_signer.calls, 1);
    assert_eq!(owner.ordered_index_for_test().unwrap(), applied);
    let mut query = IssuerMemoryStore::default();
    let authority_committee = owner
        .query_genesis_committee(
            &prepared,
            &slot,
            &mut query,
            &mut IssuerMemoryStore::default(),
        )
        .unwrap();
    let signature = super::super::super::genesis_issuance::issue(
        &prepared,
        &authority_committee,
        &mut IssuerMemoryStore::default(),
        &mut GenesisSigner(key),
    )
    .unwrap();
    let record = super::super::super::genesis_issuance::assemble(
        &prepared,
        &authority_committee,
        vec![signature],
    )
    .unwrap();
    let mut publication = IssuerMemoryStore::default();
    let mut publication_reply = IssuerMemoryStore::default();
    assert!(
        owner
            .verify_authorized_shared_genesis_publication(
                &prepared,
                &authority_committee,
                &record,
                &mut query,
                &mut publication,
                &mut publication_reply,
            )
            .is_err(),
        "unpublished certificate must not authorize a generation"
    );
    owner
        .execute_genesis_publication(
            &prepared,
            &authority_committee,
            &record,
            &mut query,
            &mut publication,
            &mut publication_reply,
        )
        .unwrap();
    let finality = owner
        .verify_authorized_shared_genesis_publication(
            &prepared,
            &authority_committee,
            &record,
            &mut query,
            &mut publication,
            &mut publication_reply,
        )
        .unwrap();
    if with_network {
        external_network_lifecycle(
            &harness.fixture,
            &descriptor,
            &runtime,
            &clerk,
            &keys,
            record.provision(),
            prepared.catalog(),
            &finality,
            harness.network.clone(),
            exercise,
        );
        harness.stop();
        return;
    }
    let verified =
        VerifiedAgentGenesisProvision::verify(record.provision().clone(), &finality).unwrap();
    let authority = CommitteeChangeAuthorityBinding::new(
        descriptor.authority.policy,
        descriptor.authority.issuer,
        descriptor.identity.runtime_deployment,
        descriptor.authority.public_key,
        descriptor.authority.initial_epoch,
    )
    .unwrap();
    let files: Vec<_> = keys.into_iter().map(|key| {
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
            libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap(),
        ).unwrap());
        let replica = committee.member_by_node(merge.node()).unwrap().replica();
        let seal = LocalJournalAgentDriver::<MemoryAgentJournalStore>::prepare_external_shared_genesis(
            &verified, replica, prepared.catalog(), &harness.fixture.trust, merge.node(),
        ).unwrap();
        let directory = TestDirectory::new("external-shared-file-replica");
        // Preserve the full authenticated provision before acquiring a stable
        // generation slot. This fixture does not substitute a bare hash for it.
        write_operation_test_image(&directory.0.join("genesis.provision"), &record.encode()).unwrap();
        ReplicaFiles { directory, seal: Arc::new(seal), committee: committee.clone(), authority,
            trust: harness.fixture.trust.clone(), merge,
            intent: HostHash::digest(b"vos/test/external-shared/provision/v1", &[&record.encode()]) }
    }).collect();
    let mut drivers: Vec<_> = files
        .iter()
        .map(|files| files.open(true, prepared.catalog()))
        .collect();
    let install = install_request(descriptor.identity.agent, &clerk, 0x71, None);
    let ManagementRequest::Install(install_actor) = &install else {
        unreachable!()
    };
    let actor = install_actor.entry.actor;
    let mut receipt = prepared.proposal().create().operation.clone();
    let ReplayOperation::CleanManage {
        authority: ref mut install_receipt,
        ..
    } = receipt
    else {
        unreachable!()
    };
    install_receipt.selector.operation = install.authority_operation().unwrap();
    (
        install_receipt.selector.actor,
        install_receipt.selector.actor_deployment,
    ) = install.authority_actor_selector();
    install_receipt.selector.request = install.commitment();
    install_receipt.selector.decision_sequence += 1;
    install_receipt.selector.expires_at += 100;
    install_receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&install_receipt.signing_bytes())
        .to_bytes();
    let install_receipt = install_receipt.clone();
    let same_slot = drivers[0]
        .prepare_clean_management(
            install.clone(),
            install_receipt.clone(),
            SdkManagementArtifacts::Actor(&clerk),
        )
        .unwrap();
    assert!(
        matches!(
            &same_slot,
            crate::agent::shared_journal_driver::PreparedCleanManagement::Denied {
                outcome: RuntimeOutcome::Management(Err(
                    crate::agent_sdk::ManagementError::AuthoritySequenceConflict
                )),
                ..
            }
        ),
        "same-slot Install: {same_slot:?}"
    );
    // Distinct management mutations require an advancing trusted logical slot.
    harness
        .fixture
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    let mut install_plan = None;
    for driver in &mut drivers {
        let plan = driver
            .prepare_clean_management(
                install.clone(),
                install_receipt.clone(),
                SdkManagementArtifacts::Actor(&clerk),
            )
            .unwrap();
        let input = plan
            .input()
            .unwrap_or_else(|| panic!("Clerk Install admission: {plan:?}"));
        let commands = plan.into_commands();
        assert!(!commands.is_empty());
        assert_eq!(
            &(input, commands.clone()),
            install_plan.get_or_insert((input, commands))
        );
    }
    let (install_input, commands) = install_plan.unwrap();
    apply(&mut drivers, commands);
    let install_claim = drivers[0].available_ordered_claim(install_input).unwrap();
    for driver in &mut drivers {
        assert_eq!(
            driver.available_ordered_claim(install_input).unwrap(),
            install_claim
        );
        driver
            .verify_ordered_availability(
                install_claim.raft_index(),
                install_claim.raft_term(),
                install_claim.commitment(),
            )
            .unwrap();
        assert!(matches!(
            driver.take_clean_ordered_result(install_input).unwrap(),
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
        ));
    }
    let material = drivers[0].physical_invocation_material(actor).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_by(|a, b| a.reference.cmp(&b.reference));
    let mut message = vec![TAG_DYNAMIC];
    message.extend(Msg::new("journal_id").encode());
    let work = InvocationWork {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: runtime.deployment(),
        invocation: InvocationId([0xe1; 32]),
        actor,
        incarnation: material.actor.incarnation,
        deployment: clerk.deployment(),
        program: clerk.program(),
        mode: MethodMode::LinearizableQuery,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: 100_000_000,
        recovery_only: false,
    };
    let mut receipt = install_receipt;
    receipt.selector.operation = crate::agent_sdk::authority::AuthorityOperationKind::InvokeActor;
    receipt.selector.request = work.commitment();
    receipt.selector.decision_sequence = 0;
    receipt.selector.acknowledged_through = 0;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
    // Validly re-signed excessive gas must fail at admission, not poison a
    // committed Raft slot. Rejection cannot invalidate earlier availability.
    for driver in &drivers {
        let before = (driver.journal_position(), driver.capacity().unwrap());
        let claim = driver.available_ordered_claim(install_input).unwrap();
        let mut oversized = work.clone();
        oversized.invocation = InvocationId([0xe2; 32]);
        oversized.gas = crate::agent::execution::MAX_EXECUTION_GAS + 1;
        let InvocationAuthorization::AuthorityReceipt(mut receipt) = authorization.clone() else {
            unreachable!()
        };
        receipt.selector.request = oversized.commitment();
        receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&receipt.signing_bytes())
            .to_bytes();
        assert!(
            driver
                .prepare_clean_ordered(
                    oversized.clone(),
                    InvocationAuthorization::AuthorityReceipt(receipt.clone())
                )
                .is_err()
        );
        assert_eq!(
            (driver.journal_position(), driver.capacity().unwrap()),
            before
        );
        driver
            .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
            .unwrap();
        oversized.gas -= 1;
        receipt.selector.request = oversized.commitment();
        receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&receipt.signing_bytes())
            .to_bytes();
        assert!(matches!(
            driver
                .prepare_clean_ordered(
                    oversized,
                    InvocationAuthorization::AuthorityReceipt(receipt)
                )
                .unwrap(),
            PreparedCleanOrdered::Proposal { .. }
        ));
        let yielded = crate::agent_sdk::YieldedInvocation {
            invocation: work.invocation,
            actor: work.actor,
            incarnation: work.incarnation,
            deployment: work.deployment,
            program: work.program,
            mode: work.mode,
            continuation: BlobRef::of_bytes(b"unadmitted-continuation"),
            ready_sequence: 1,
            installation_data: work.installation_data.clone(),
            required: work
                .availability
                .iter()
                .map(|blob| blob.reference.clone())
                .collect(),
            reason: crate::agent_sdk::YieldReason::Cooperative,
        };
        assert!(yielded.validate());
        for unsupported in [
            CleanInvocationReplayRequest::Resume {
                context: RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
                yielded,
            },
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Attested {
                    proof_system: Hash([0x7f; 32]),
                },
                work: work.clone(),
                authorization: authorization.clone(),
            },
        ] {
            assert!(driver.prepare_clean_ordered_operation(unsupported).is_err());
            assert_eq!(
                (driver.journal_position(), driver.capacity().unwrap()),
                before
            );
            driver
                .verify_ordered_availability(
                    claim.raft_index(),
                    claim.raft_term(),
                    claim.commitment(),
                )
                .unwrap();
        }
    }
    let invoke = CleanInvocationReplayRequest::Invoke {
        context: RuntimeExecutionContext::Direct,
        work: work.clone(),
        authorization: authorization.clone(),
    };
    let result = ordered(&mut drivers, invoke.clone());
    let RuntimeOutcome::Completed(Ok(reply)) = &result else {
        panic!("Clerk query: {result:?}");
    };
    assert_eq!(Value::decode(&reply.reply), Value::Bytes(Vec::new()));
    let states: Vec<_> = drivers
        .iter()
        .map(|driver| driver.materialization().state().clone())
        .collect();
    assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
    drop(drivers);
    let mut drivers: Vec<_> = files.iter().map(|files| files.open(false, &[])).collect();
    for (driver, state) in drivers.iter_mut().zip(states) {
        assert_eq!(driver.materialization().state(), &state);
        assert_eq!(
            driver.available_ordered_claim(install_input).unwrap(),
            install_claim
        );
        driver
            .verify_ordered_availability(
                install_claim.raft_index(),
                install_claim.raft_term(),
                install_claim.commitment(),
            )
            .unwrap();
        assert_eq!(
            driver
                .replay_durable_clean_terminal(invoke.clone())
                .unwrap(),
            result
        );
    }
    let acknowledgement = ordered(
        &mut drivers,
        CleanInvocationReplayRequest::Acknowledge {
            work: work.clone(),
            authorization: authorization.clone(),
        },
    );
    assert!(matches!(
        acknowledgement,
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    drop(drivers);
    let drivers: Vec<_> = files.iter().map(|files| files.open(false, &[])).collect();
    for driver in &drivers {
        assert!(
            driver
                .retained_positive_clean_acknowledgement(&work, &authorization)
                .unwrap()
        );
    }
    // A lost block revokes this open's availability proof; read-only reopen
    // must fail instead of silently recovering/repairing it from history.
    let claim = drivers[0].available_ordered_claim(install_input).unwrap();
    let root = drivers[0]
        .materialization()
        .external_inspection_lanes()
        .unwrap()[0]
        .base;
    let block = root
        .bind(root.context(), root.commitment())
        .unwrap()
        .root()
        .unwrap();
    let name: String = block
        .hash()
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let path = files[0].journal_root().join("lane-state/blocks").join(name);
    let parked = files[0].directory.0.join("parked-state-block");
    std::fs::rename(&path, &parked).unwrap();
    let mut fresh = work.clone();
    fresh.invocation = InvocationId([0xe3; 32]);
    let InvocationAuthorization::AuthorityReceipt(mut receipt) = authorization else {
        unreachable!()
    };
    receipt.selector.request = fresh.commitment();
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    assert!(
        drivers[0]
            .prepare_clean_ordered(fresh, InvocationAuthorization::AuthorityReceipt(receipt))
            .is_err()
    );
    assert!(
        drivers[0]
            .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
            .is_err()
    );
    drop(drivers);
    let files = &files[0];
    assert!(
        files
            .acquire()
            .open_external_journal_with_executor(
                &files.seal,
                |store| Ok(StandardLocalReplayExecutor::new_shared(
                    store.catalog_blob_resolver()?,
                    files.trust.clone(),
                    files.merge.clone(),
                    vec![files.committee.clone()]
                )),
                &NoPrunedOrderedBases,
                &mut budget(),
            )
            .is_err()
    );
    assert!(
        !path.exists(),
        "failed open must not repair the missing block"
    );
    std::fs::rename(&parked, &path).unwrap();
    // A fresh full audit can re-establish availability after exact restoration.
    files
        .open(false, &[])
        .verify_ordered_availability(claim.raft_index(), claim.raft_term(), claim.commitment())
        .unwrap();
    harness.stop();
}

fn external_network_lifecycle(
    fixture: &PhysicalFixture,
    descriptor: &AgentDescriptor,
    runtime: &crate::agent::package_admission::AdmittedStateRuntimePackage,
    clerk: &crate::agent::package_admission::AdmittedActorPackage,
    keys: &[SigningKey],
    provision: &crate::agent::genesis::AgentGenesisProvision,
    catalog: &[crate::agent::execution::RuntimeBlob],
    finality: &ReplayVerifiedAgentGenesisFinality,
    authority_network: Arc<Network>,
    exercise: ExternalNetworkExercise,
) {
    use crate::actors::value::{Msg, TAG_DYNAMIC, Value};
    use crate::agent::driver::SdkManagementArtifacts;
    use crate::network::SharedAgentNetworkHost;
    use crate::network::shared_agent::CleanManagementSubmission;

    let agent = HostAgentId(descriptor.identity.agent.0);
    let authority = CommitteeChangeAuthorityBinding::new(
        descriptor.authority.policy,
        descriptor.authority.issuer,
        descriptor.identity.runtime_deployment,
        descriptor.authority.public_key,
        descriptor.authority.initial_epoch,
    )
    .unwrap();
    let directories: Vec<_> = keys
        .iter()
        .map(|_| TestDirectory::new("external-shared-network-owner"))
        .collect();
    let merges: Vec<Arc<dyn LocalMergeAuthenticator>> = keys
        .iter()
        .map(|key| {
            Arc::new(
                crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
                    libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap(),
                )
                .unwrap(),
            ) as Arc<dyn LocalMergeAuthenticator>
        })
        .collect();
    let open = |index: usize, candidate: bool| {
        let scope = crate::agent::host::AgentHostScope {
            space: HostSpaceId(descriptor.identity.space.0),
            node: merges[index].node(),
        };
        let proof: Arc<dyn AgentGenesisFinalityVerifier> = Arc::new(finality.clone());
        if candidate {
            SharedAgentHost::open_external_candidates(
                directories[index].host(),
                directories[index].lock(),
                scope,
                fixture.trust.clone(),
                merges[index].clone(),
                proof,
                None,
            )
        } else {
            SharedAgentHost::open(
                directories[index].host(),
                directories[index].lock(),
                scope,
                fixture.trust.clone(),
                merges[index].clone(),
                proof,
            )
        }
    };
    let mut hosts: Vec<_> = (0..keys.len())
        .map(|index| {
            let mut host = open(index, true).unwrap();
            let status = host
                .provision_replay_verified(provision.clone(), catalog.to_vec(), authority, finality)
                .unwrap();
            assert!(host.uses_external_state(agent).unwrap());
            assert_eq!(status.replicas.len(), 3);
            assert!(status.engines.control_raft && status.engines.linear_raft);
            assert!(!status.engines.merge && !status.engines.local);
            let route = host.physical_route(agent).unwrap();
            assert_eq!(route.generation, status.generation);
            assert_eq!(route.replication_id, status.replication_id);
            assert!(route.raft_database.is_file());
            Arc::new(std::sync::Mutex::new(host))
        })
        .collect();
    let networks: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            if index == 0 {
                // The actual Authority owner is on this voter. Attach the new
                // generation to its existing authenticated transport, not a
                // second simultaneous transport impersonating the same PeerId.
                return authority_network.clone();
            }
            let keypair = libp2p::identity::Keypair::ed25519_from_bytes(key.to_bytes()).unwrap();
            let peer = keypair.public().to_peer_id();
            Arc::new(Network::start(NetworkConfig {
                keypair,
                local_prefix: crate::network::derive_node_prefix(&peer),
                listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap: Vec::new(),
                auto_dial_mdns: false,
            }))
        })
        .collect();
    assert!(wait_until(std::time::Duration::from_secs(5), || networks
        .iter()
        .skip(1)
        .all(|network| !network.listen_addrs().is_empty())));
    let mut last_dial = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            if networks
                .iter()
                .all(|network| network.connected_peers().len() == 2)
            {
                return true;
            }
            if last_dial.is_none_or(|last: std::time::Instant| {
                last.elapsed() >= std::time::Duration::from_millis(250)
            }) {
                for (index, network) in networks.iter().enumerate() {
                    for target in networks.iter().skip(index + 1) {
                        network.connect(target.listen_addrs()[0].clone());
                    }
                }
                last_dial = Some(std::time::Instant::now());
            }
            false
        }),
        "external candidate authenticated mesh did not connect"
    );
    let attach = |hosts: &[Arc<std::sync::Mutex<SharedAgentHost>>]| -> Vec<_> {
        hosts
            .iter()
            .zip(&networks)
            .map(|(host, network)| {
                SharedAgentNetworkHost::attach(host.clone(), network.clone()).unwrap()
            })
            .collect()
    };
    let mut attached = attach(&hosts);
    let install = install_request(descriptor.identity.agent, clerk, 0x71, None);
    let ManagementRequest::Install(install_actor) = &install else {
        unreachable!()
    };
    let actor = install_actor.entry.actor;
    let ReplayOperation::CleanManage {
        authority: create_receipt,
        ..
    } = &provision.proposal().create().operation
    else {
        unreachable!()
    };
    let mut receipt = create_receipt.clone();
    receipt.selector.operation = install.authority_operation().unwrap();
    (receipt.selector.actor, receipt.selector.actor_deployment) =
        install.authority_actor_selector();
    receipt.selector.request = install.commitment();
    receipt.selector.decision_sequence += 1;
    receipt.selector.expires_at += 100;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    fixture
        .logical_slot
        .as_ref()
        .unwrap()
        .fetch_add(1, Ordering::AcqRel);
    let installed = external_network_on_leader(&attached, agent, |owner| {
        owner
            .manage_clean(
                agent,
                install.clone(),
                receipt.clone(),
                SdkManagementArtifacts::Actor(clerk),
            )
            .map(|result| match result {
                CleanManagementSubmission::Applied { outcome, .. } => outcome,
                CleanManagementSubmission::Denied { outcome, .. } => {
                    panic!("external network Install denied: {outcome:?}")
                }
                CleanManagementSubmission::CommitteeTransition { .. } => {
                    panic!("external network Install changed the committee")
                }
            })
    });
    assert!(matches!(
        installed,
        RuntimeOutcome::Management(Ok(ManagementReply::Installed(_)))
    ));
    assert!(wait_until(std::time::Duration::from_secs(15), || hosts
        .iter()
        .all(|host| {
            host.lock()
                .unwrap()
                .journal_position(agent)
                .unwrap()
                .ordered_index
                == 1
        })));
    let material = hosts[0]
        .lock()
        .unwrap()
        .supervisor_invocation_material(agent, actor)
        .unwrap();
    let identity =
        crate::agent::supervisor_adapters::physical_material_identity(&material).unwrap();
    let mut availability = vec![material.program, material.schema, material.policies];
    availability.extend(material.installation_data);
    availability.sort_by(|left, right| left.reference.cmp(&right.reference));
    let mut message = vec![TAG_DYNAMIC];
    message.extend(Msg::new("journal_id").encode());
    let work = InvocationWork {
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: runtime.deployment(),
        invocation: InvocationId([0xe1; 32]),
        actor,
        incarnation: material.actor.incarnation,
        deployment: clerk.deployment(),
        program: clerk.program(),
        mode: MethodMode::LinearizableQuery,
        origin: InvocationOrigin::anonymous(),
        roles: InvocationRoleClaims::none(),
        message,
        installation_data: material.actor.entry.installation_data,
        availability,
        gas: 100_000_000,
        recovery_only: false,
    };
    receipt.selector.operation = crate::agent_sdk::authority::AuthorityOperationKind::InvokeActor;
    receipt.selector.request = work.commitment();
    receipt.selector.decision_sequence = 0;
    receipt.selector.acknowledged_through = 0;
    receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
        .sign(&receipt.signing_bytes())
        .to_bytes();
    let authorization = InvocationAuthorization::AuthorityReceipt(receipt);
    // Use the signed package's roles for the Clerk kernel workflow. The
    // Authority receipt binds each exact call independently of the embedded
    // registrar/debit signatures, which the physical Clerk guest must verify.
    let policy = ActorMethodPolicyArtifact::decode(clerk.method_policy_bytes()).unwrap();
    let clerk_role = |method: &str| {
        let AuthorizationPolicySelector::ActorRole(role) = policy
            .methods
            .iter()
            .find(|entry| entry.name == method)
            .unwrap_or_else(|| panic!("missing signed Clerk {method} policy"))
            .authorization_policy
        else {
            panic!("Clerk {method} must require its signed actor role");
        };
        role
    };
    let operator = clerk_role("bootstrap");
    assert_eq!(clerk_role("create_account"), operator);
    assert_eq!(clerk_role("apply_transfer"), operator);
    let member = clerk_role("state_root");
    let clerk_call = |method: &str,
                      args: Vec<(&str, Value)>,
                      mode: MethodMode,
                      role: crate::agent_sdk::RoleId,
                      invocation: u8| {
        let mut call = work.clone();
        call.invocation = InvocationId([invocation; 32]);
        call.mode = mode;
        call.gas = crate::agent::execution::MAX_EXECUTION_GAS;
        call.origin.principal = Some(PrincipalId([0xe3; 32]));
        call.roles.actor = Some(role);
        let mut message = Msg::new(method);
        for (name, value) in args {
            message = message.with(name, value);
        }
        call.message = vec![TAG_DYNAMIC];
        call.message.extend(message.encode());
        let InvocationAuthorization::AuthorityReceipt(mut signed_receipt) = authorization.clone()
        else {
            unreachable!()
        };
        signed_receipt.selector.request = call.commitment();
        signed_receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&signed_receipt.signing_bytes())
            .to_bytes();
        (
            call,
            InvocationAuthorization::AuthorityReceipt(signed_receipt),
        )
    };
    use cipher_clerk::helpers::{MemLedger, MemOracle};
    use cipher_clerk::prelude::{
        Account, CreateAccount, EventStatus, Keypair, Layer, LedgerState, Transfer,
    };
    let mut reference = MemLedger::new();
    let mut reference_oracle = MemOracle::new();
    let registrar = Keypair::generate();
    let journal_id = reference.bootstrap_journal(registrar.public, 1);
    let alice_key = Keypair::generate();
    let bob_key = Keypair::generate();
    let alice = Account::asset(journal_id, alice_key.public, 840, 100);
    let bob = Account::liability(journal_id, bob_key.public, 840, 200);
    let creates = [
        CreateAccount::signed(alice.clone(), &registrar.secret),
        CreateAccount::signed(bob.clone(), &registrar.secret),
    ];
    let mut setup = vec![(
        "bootstrap",
        vec![
            ("journal_id", Value::Bytes(journal_id.0.to_vec())),
            (
                "registrar_pubkey",
                Value::Bytes(registrar.public.0.to_vec()),
            ),
            ("code", Value::U32(1)),
        ],
        0xe6,
    )];
    for (index, create) in creates.iter().enumerate() {
        let timestamp = 500_000 + index as u64;
        let expected = cipher_clerk::apply_account_creations(
            &mut reference,
            core::slice::from_ref(create),
            &mut reference_oracle,
            timestamp,
        );
        assert_eq!(expected[0].status, EventStatus::Created);
        setup.push((
            "create_account",
            vec![
                (
                    "create_account_bytes",
                    Value::Bytes(
                        crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(create)
                            .unwrap()
                            .to_vec(),
                    ),
                ),
                ("batch_seed_timestamp", Value::U64(timestamp)),
            ],
            0xe7 + index as u8,
        ));
    }
    for (method, args, invocation) in setup {
        let (call, authorization) =
            clerk_call(method, args, MethodMode::Linear, operator, invocation);
        let started = std::time::Instant::now();
        let outcome = external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(identity, call.clone(), authorization.clone())
        });
        let RuntimeOutcome::Completed(Ok(reply)) = &outcome else {
            panic!("external network Clerk {method}: {outcome:?}")
        };
        assert_eq!(
            Value::decode(&reply.reply),
            Value::Bytes(vec![0]),
            "Clerk {method} must return Status::Ok"
        );
        assert!(matches!(
            external_network_on_leader(&attached, agent, |owner| {
                owner.supervisor_acknowledge(identity, call.clone(), authorization.clone())
            }),
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        eprintln!(
            "clerk_shared_network_call method={method} invoke_ack_elapsed_us={}",
            started.elapsed().as_micros()
        );
    }
    let amount = reference_oracle.commit(17);
    let transfer = Transfer::builder(journal_id)
        .debit(&alice, Layer::Settled, amount)
        .credit(&bob, Layer::Settled, amount)
        .signed_with(&[(&alice, &alice_key.secret)]);
    let (value, blinding) = reference_oracle.openings.get(&amount.0).copied().unwrap();
    let openings = vec![cipher_clerk::state::Opening {
        amount,
        value,
        blinding,
    }];
    let expected_transfer = cipher_clerk::apply_batch(
        &mut reference,
        core::slice::from_ref(&transfer),
        &mut reference_oracle,
        1_000_000,
    );
    assert_eq!(expected_transfer[0].status, EventStatus::Created);
    // The existing lost-response/reopen lifecycle now protects a mutation:
    // retrying this exact signed debit must recover its one committed result.
    let (work, authorization) = clerk_call(
        "apply_transfer",
        vec![
            (
                "transfer_bytes",
                Value::Bytes(
                    crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(&transfer)
                        .unwrap()
                        .to_vec(),
                ),
            ),
            (
                "openings_bytes",
                Value::Bytes(
                    crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(&openings)
                        .unwrap()
                        .to_vec(),
                ),
            ),
            ("batch_seed_timestamp", Value::U64(1_000_000)),
        ],
        MethodMode::Linear,
        operator,
        0xe9,
    );
    let input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: material.observed_slot,
        },
    }
    .id();
    let ack_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(&work),
            authorization: authorization.clone(),
        },
    }
    .id();
    let before = hosts[0].lock().unwrap().journal_position(agent).unwrap();
    let invoke_started = std::time::Instant::now();
    let result = external_network_on_leader(&attached, agent, |owner| {
        owner.supervisor_invoke(identity, work.clone(), authorization.clone())
    });
    eprintln!(
        "clerk_shared_network_call method=apply_transfer invoke_elapsed_us={}",
        invoke_started.elapsed().as_micros()
    );
    let RuntimeOutcome::Completed(Ok(reply)) = &result else {
        panic!("external network Invoke: {result:?}")
    };
    assert_eq!(
        Value::decode(&reply.reply),
        Value::Bytes(vec![0]),
        "the debit-signed settled transfer must return Clerk Status::Ok"
    );
    let mut expected = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            let Some(states) = hosts
                .iter()
                .map(|host| {
                    let mut host = host.lock().unwrap();
                    let claim = host.available_ordered_claim(agent, input).ok()?;
                    Some((host.journal_position(agent).unwrap(), claim))
                })
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            if states.iter().all(|state| state == &states[0])
                && states[0].0.ordered_index > before.ordered_index
            {
                expected = Some(states[0].clone());
                true
            } else {
                false
            }
        }),
        "external Invoke did not converge on all three independently published roots"
    );
    let expected = expected.unwrap();
    drop(attached);
    drop(hosts);
    for index in 0..keys.len() {
        assert!(
            matches!(
                open(index, false),
                Err(SharedAgentHostError::InvalidProvision)
            ),
            "public image owner must not infer an external executor from persisted files"
        );
    }
    hosts = (0..keys.len())
        .map(|index| {
            let mut host = open(index, true).unwrap();
            assert!(host.uses_external_state(agent).unwrap());
            assert_eq!(
                (
                    host.journal_position(agent).unwrap(),
                    host.available_ordered_claim(agent, input).unwrap()
                ),
                expected
            );
            Arc::new(std::sync::Mutex::new(host))
        })
        .collect();
    attached = attach(&hosts);
    assert_eq!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(identity, work.clone(), authorization.clone())
        }),
        result,
        "lost response retry must recover the exact physical result"
    );
    for host in &hosts {
        assert_eq!(
            host.lock().unwrap().journal_position(agent).unwrap(),
            expected.0,
            "retained retry must not append another Ordered invocation"
        );
    }
    assert!(matches!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_acknowledge(identity, work.clone(), authorization.clone())
        }),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    assert!(wait_until(std::time::Duration::from_secs(15), || hosts
        .iter()
        .all(|host| {
            host.lock()
                .unwrap()
                .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                .unwrap()
        })));
    let (root_work, root_authorization) = clerk_call(
        "state_root",
        Vec::new(),
        MethodMode::LinearizableQuery,
        member,
        0xea,
    );
    let root_started = std::time::Instant::now();
    let root_outcome = external_network_on_leader(&attached, agent, |owner| {
        owner.supervisor_invoke(identity, root_work.clone(), root_authorization.clone())
    });
    eprintln!(
        "clerk_shared_network_call method=state_root phase=post_reopen invoke_elapsed_us={}",
        root_started.elapsed().as_micros()
    );
    let RuntimeOutcome::Completed(Ok(root_reply)) = &root_outcome else {
        panic!("external network Clerk state_root: {root_outcome:?}")
    };
    assert_eq!(
        Value::decode(&root_reply.reply),
        Value::Bytes(reference.root().to_vec()),
        "Shared Clerk must preserve the signed transfer's reference kernel root"
    );
    let root_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: root_work.clone(),
            authorization: root_authorization.clone(),
            observed_slot: material.observed_slot,
        },
    }
    .id();
    let root_ack_input = crate::agent::journal::ReplayInput {
        runtime: provision.proposal().create().runtime.clone(),
        operation: ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: crate::agent_sdk::InvocationRetirement::from_work(&root_work),
            authorization: root_authorization.clone(),
        },
    }
    .id();
    assert!(matches!(
        external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_acknowledge(identity, root_work.clone(), root_authorization.clone())
        }),
        RuntimeOutcome::Acknowledged(Ok(_))
    ));
    let mut completed = None;
    assert!(
        wait_until(std::time::Duration::from_secs(15), || {
            let Some(states) = hosts
                .iter()
                .map(|host| {
                    let mut host = host.lock().unwrap();
                    if !host
                        .retained_positive_clean_acknowledgement(
                            agent,
                            &root_work,
                            &root_authorization,
                        )
                        .ok()?
                    {
                        return None;
                    }
                    Some((
                        host.journal_position(agent).ok()?,
                        host.available_ordered_claim(agent, ack_input).ok()?,
                        host.available_ordered_claim(agent, root_input).ok()?,
                        host.available_ordered_claim(agent, root_ack_input).ok()?,
                    ))
                })
                .collect::<Option<Vec<_>>>()
            else {
                return false;
            };
            if states.iter().all(|state| state == &states[0]) {
                completed = Some(states[0].clone());
                true
            } else {
                false
            }
        }),
        "transfer/root Invoke and ACK claims must converge on all three replicas"
    );
    let mut completed = completed.unwrap();
    let retained_mode = matches!(exercise, ExternalNetworkExercise::RetainedCheckpoint);
    let mut retained_reply = None;
    if retained_mode {
        let (retained_work, authorization) = clerk_call(
            "state_root",
            Vec::new(),
            MethodMode::LinearizableQuery,
            member,
            0xed,
        );
        let InvocationAuthorization::AuthorityReceipt(mut receipt) = authorization else {
            unreachable!()
        };
        let accepted_slot = fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .load(Ordering::Acquire);
        receipt.selector.valid_from = accepted_slot;
        receipt.selector.expires_at = accepted_slot + 2;
        receipt.signature = SigningKey::from_bytes(&[RECEIPT_SEED; 32])
            .sign(&receipt.signing_bytes())
            .to_bytes();
        let retained_authorization = InvocationAuthorization::AuthorityReceipt(receipt);
        let retained_input = crate::agent::journal::ReplayInput {
            runtime: provision.proposal().create().runtime.clone(),
            operation: ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: retained_work.clone(),
                authorization: retained_authorization.clone(),
                observed_slot: accepted_slot,
            },
        }
        .id();
        let outcome = external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(
                identity,
                retained_work.clone(),
                retained_authorization.clone(),
            )
        });
        let RuntimeOutcome::Completed(Ok(reply)) = &outcome else {
            panic!("external retained invocation: {outcome:?}");
        };
        assert_eq!(
            Value::decode(&reply.reply),
            Value::Bytes(reference.root().to_vec())
        );
        let mut retained_claims = None;
        assert!(
            wait_until(std::time::Duration::from_secs(15), || {
                let Some(states) = hosts
                    .iter()
                    .map(|host| {
                        let mut host = host.lock().unwrap();
                        Some((
                            host.journal_position(agent).ok()?,
                            host.available_ordered_claim(agent, retained_input).ok()?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                if states.iter().all(|state| state == &states[0])
                    && states[0].0.ordered_index == completed.0.ordered_index + 1
                {
                    retained_claims = Some(states[0].clone());
                    true
                } else {
                    false
                }
            }),
            "fresh retained Invoke must genuinely commit identical claims on all three replicas"
        );
        completed.0 = retained_claims.unwrap().0;
        retained_reply = Some((retained_work, retained_authorization, outcome));
    }
    let checkpoint_crash = match exercise {
        ExternalNetworkExercise::Checkpoint(crash) => Some(crash),
        ExternalNetworkExercise::RetainedCheckpoint => Some(None),
        ExternalNetworkExercise::LostResponse => None,
    };
    if let Some(crash) = checkpoint_crash {
        // The existing customer calls are ACKed before retirement; the retained
        // mode adds one explicit unacknowledged result. The lost-response path
        // stays separate, and all-ACKed/crash cases do not claim old ordinary
        // replies retain availability after physical compaction.
        drop(attached);
        let leaf: String = agent.0.iter().map(|byte| format!("{byte:02x}")).collect();
        let journal_root = |index: usize| directories[index].host().join(format!("{leaf}.agent"));
        if crash.is_none() && !retained_mode {
            let mut host = hosts[0].lock().unwrap();
            let position = host.journal_position(agent).unwrap();
            let path = journal_root(0).join("heads");
            let heads = std::fs::read(&path).unwrap();
            let parked = directories[0].0.join("parked-checkpoint-heads");
            std::fs::rename(&path, &parked).unwrap();
            assert!(host.request_common_snapshot_compaction(agent).is_err());
            assert!(!path.exists(), "head refusal must not repair missing heads");
            std::fs::rename(&parked, &path).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), heads);
            assert_eq!(host.journal_position(agent).unwrap(), position);
            assert!(
                host.available_ordered_claim(agent, root_input).is_err(),
                "restoring heads must not revive a failed serving pin"
            );
            drop(host);
            drop(hosts);
            hosts = (0..keys.len())
                .map(|index| Arc::new(std::sync::Mutex::new(open(index, true).unwrap())))
                .collect();
        }
        if crash.is_none() && !retained_mode {
            let mut host = hosts[0].lock().unwrap();
            let position = host.journal_position(agent).unwrap();
            let heads = std::fs::read(journal_root(0).join("heads")).unwrap();
            let decoded = JournalHeads::decode(&heads).unwrap();
            let frontier: String = decoded
                .merge_frontier
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let path = journal_root(0)
                .join("records/merge-frontiers")
                .join(frontier);
            let parked = directories[0].0.join("parked-checkpoint-frontier");
            std::fs::rename(&path, &parked).unwrap();
            assert!(host.request_common_snapshot_compaction(agent).is_err());
            assert_eq!(host.journal_position(agent).unwrap(), position);
            assert_eq!(std::fs::read(journal_root(0).join("heads")).unwrap(), heads);
            assert!(
                !path.exists(),
                "metadata refusal must not repair missing frontier"
            );
            std::fs::rename(&parked, &path).unwrap();
            assert!(
                host.available_ordered_claim(agent, root_input).is_err(),
                "restoring frontier bytes must not revive a failed serving pin"
            );
            drop(host);
            // Metadata reads precede the root-block audit. Only a new owner
            // may establish availability again after either physical failure.
            drop(hosts);
            hosts = (0..keys.len())
                .map(|index| Arc::new(std::sync::Mutex::new(open(index, true).unwrap())))
                .collect();
        }
        if crash.is_none() && !retained_mode {
            let mut host = hosts[0].lock().unwrap();
            let block = external_current_root_block(&mut host, agent);
            let path = journal_root(0).join("lane-state/blocks").join(block);
            let parked = directories[0].0.join("parked-checkpoint-predecessor-block");
            let position = host.journal_position(agent).unwrap();
            let heads = std::fs::read(journal_root(0).join("heads")).unwrap();
            std::fs::rename(&path, &parked).unwrap();
            assert!(host.request_common_snapshot_compaction(agent).is_err());
            assert_eq!(host.journal_position(agent).unwrap(), position);
            assert_eq!(std::fs::read(journal_root(0).join("heads")).unwrap(), heads);
            assert!(
                !path.exists(),
                "candidate refusal must not repair missing state"
            );
            std::fs::rename(&parked, &path).unwrap();
            assert!(
                host.available_ordered_claim(agent, root_input).is_err(),
                "restoring predecessor bytes must not revive a failed serving pin"
            );
        }
        // Restoration requires a fresh full owner audit, not revival of a
        // serving availability token invalidated by the failed candidate.
        drop(hosts);
        hosts = (0..keys.len())
            .map(|index| Arc::new(std::sync::Mutex::new(open(index, true).unwrap())))
            .collect();
        attached = attach(&hosts);
        let (checkpoint_work, checkpoint_authorization) = clerk_call(
            "state_root",
            Vec::new(),
            MethodMode::LinearizableQuery,
            member,
            0xeb,
        );
        let committee = provision.replicas().clone();
        let mut certificate = None;
        let mut checkpoint_owner = None;
        assert!(
            wait_until(std::time::Duration::from_secs(30), || {
                let Some(index) = attached
                    .iter()
                    .position(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
                else {
                    return false;
                };
                // Logical roots alone do not establish a common physical
                // foundation: a reopened leader may have committed a no-op.
                // Every eventual recipient must reconstruct the exact same
                // current claim before collecting the real quorum.
                let Some(boundaries) = hosts
                    .iter()
                    .map(|host| {
                        host.lock()
                            .unwrap()
                            .request_common_snapshot_compaction(agent)
                            .ok()
                            .map(|candidate| candidate.claim().clone())
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                if !boundaries.iter().all(|claim| claim == &boundaries[index]) {
                    return false;
                }
                match attached[index].collect_common_checkpoint_for_admission(
                    agent,
                    &checkpoint_work,
                    &checkpoint_authorization,
                    &committee,
                    merges[index].as_ref(),
                ) {
                    Ok(certified) => {
                        certificate = Some(certified);
                        checkpoint_owner = Some(index);
                        true
                    }
                    Err(SharedAgentHostError::Unavailable) => false,
                    Err(error) => panic!("external checkpoint admission: {error:?}"),
                }
            }),
            "external checkpoint did not obtain an authenticated physical quorum"
        );
        let checkpoint_owner = checkpoint_owner.unwrap();
        let certificate = certificate.unwrap();
        certificate.verify(&committee, certificate.claim()).unwrap();
        assert_eq!(certificate.signatures().len(), 2);
        // Freeze only after a genuine authenticated network quorum. Otherwise
        // the two live followers could elect while the source publishes its
        // fully audited closure, changing the certificate's exact foundation.
        external_freeze_checkpoint_workers(&mut attached, agent, checkpoint_owner);
        drop(attached);
        {
            let mut host = hosts[checkpoint_owner].lock().unwrap();
            if let Some(stage) = crash {
                let before = std::fs::read(journal_root(checkpoint_owner).join("heads")).unwrap();
                host.set_common_checkpoint_crash_for_test(stage);
                assert!(matches!(
                    host.install_common_snapshot(agent, &certificate),
                    Err(SharedAgentHostError::Unavailable)
                ));
                assert!(host.show(agent).unwrap().is_none());
                assert!(
                    !host.common_checkpoint_crash_pending_for_test(),
                    "publication failed before the selected crash stage was consumed"
                );
                let (predecessor, target) = host
                    .common_checkpoint_install_endpoints_for_test(agent)
                    .unwrap()
                    .expect("selected crash must retain its exact ACL1 marker");
                assert_eq!(predecessor.encode(), before);
                assert_ne!(predecessor, target);
                let durable = JournalHeads::decode(
                    &std::fs::read(journal_root(checkpoint_owner).join("heads")).unwrap(),
                )
                .unwrap();
                match stage {
                    crate::agent::shared_host::CommonCheckpointCrashStage::Marker => {
                        assert_eq!(durable, predecessor)
                    }
                    crate::agent::shared_host::CommonCheckpointCrashStage::Journal
                    | crate::agent::shared_host::CommonCheckpointCrashStage::Ledger => {
                        assert_eq!(durable, target)
                    }
                }
            } else {
                host.install_common_snapshot(agent, &certificate).unwrap();
            }
        }
        if crash.is_some() {
            drop(hosts);
            hosts = (0..keys.len())
                .map(|index| Arc::new(std::sync::Mutex::new(open(index, true).unwrap())))
                .collect();
            assert_eq!(
                hosts[checkpoint_owner]
                    .lock()
                    .unwrap()
                    .common_snapshot_authority_for_test(agent)
                    .unwrap()
                    .unwrap()
                    .0,
                certificate,
            );
        }
        let target_block =
            external_current_root_block(&mut hosts[checkpoint_owner].lock().unwrap(), agent);
        for index in 0..keys.len() {
            if index != checkpoint_owner && crash.is_none() && !retained_mode {
                let mut host = hosts[index].lock().unwrap();
                // Reconstruct this voter's target closure before testing its
                // exact target block. Missing data cannot publish either head.
                host.request_common_snapshot_compaction(agent).unwrap();
                let path = journal_root(index)
                    .join("lane-state/blocks")
                    .join(&target_block);
                let parked = directories[index].0.join("parked-checkpoint-target-block");
                let position = host.journal_position(agent).unwrap();
                let heads = std::fs::read(journal_root(index).join("heads")).unwrap();
                std::fs::rename(&path, &parked).unwrap();
                assert!(host.install_common_snapshot(agent, &certificate).is_err());
                assert_eq!(host.journal_position(agent).unwrap(), position);
                assert_eq!(
                    std::fs::read(journal_root(index).join("heads")).unwrap(),
                    heads
                );
                assert!(
                    !path.exists(),
                    "installation refusal must not repair missing state"
                );
                std::fs::rename(&parked, &path).unwrap();
                assert!(
                    host.available_ordered_claim(agent, root_input).is_err(),
                    "restoring target bytes must not revive a failed serving pin"
                );
                drop(host);
                // Restored bytes do not revive the failed open's availability
                // pin. Only a fresh, independently audited owner can retry.
                drop(hosts);
                hosts = (0..keys.len())
                    .map(|replica| Arc::new(std::sync::Mutex::new(open(replica, true).unwrap())))
                    .collect();
            }
            let mut host = hosts[index].lock().unwrap();
            if let Err(error) = host.install_common_snapshot(agent, &certificate) {
                let local = host
                    .request_common_snapshot_compaction(agent)
                    .map(|candidate| candidate.claim().clone());
                panic!(
                    "external checkpoint recipient index={index} error={error:?} expected={:?} local={local:?}",
                    certificate.claim()
                );
            }
            let (actual, binding) = host
                .common_snapshot_authority_for_test(agent)
                .unwrap()
                .unwrap();
            assert_eq!(actual, certificate);
            binding.verify(&certificate, binding.claim()).unwrap();
            assert_eq!(binding.claim().local_node(), merges[index].node());
            assert_eq!(
                binding.claim().journal_store().0,
                *host
                    .journal_store_instance_for_test(agent)
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(binding.claim().ordered(), certificate.claim().ordered());
            assert_eq!(host.journal_position(agent).unwrap(), completed.0);
        }
        let raw_intent = hosts[0]
            .lock()
            .unwrap()
            .shared_genesis_intent_for_test(agent)
            .unwrap();
        drop(hosts);
        let scope = crate::agent::host::AgentHostScope {
            space: HostSpaceId(descriptor.identity.space.0),
            node: merges[0].node(),
        };
        let authority_root = crate::agent::host::agent_host_authority_root_path(
            &directories[0].host(),
            &directories[0].lock(),
            scope,
        )
        .unwrap();
        let verified = VerifiedAgentGenesisProvision::verify(provision.clone(), finality).unwrap();
        let sealed =
            LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_external_shared_genesis(
                &verified,
                committee
                    .member_by_node(merges[0].node())
                    .unwrap()
                    .replica(),
                catalog,
                &fixture.trust,
                merges[0].node(),
            )
            .unwrap();
        let heads = std::fs::read(journal_root(0).join("heads")).unwrap();
        let raw_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
            journal_root(0),
            authority_root.join(format!("{leaf}.agent-lock")),
            merges[0].node(),
            raw_intent,
            &std::fs::File::open(directories[0].host()).unwrap(),
            &std::fs::File::open(authority_root).unwrap(),
        )
        .unwrap();
        assert!(
            raw_slot
                .open_external_journal_with_executor(
                    &sealed,
                    |store| Ok(StandardLocalReplayExecutor::new_shared(
                        store.catalog_blob_resolver()?,
                        fixture.trust.clone(),
                        merges[0].clone(),
                        vec![committee.clone()],
                    )),
                    &NoPrunedOrderedBases,
                    &mut budget(),
                )
                .is_err(),
            "raw replay must not authenticate a quorum-certified external checkpoint"
        );
        assert_eq!(std::fs::read(journal_root(0).join("heads")).unwrap(), heads);
        hosts = (0..keys.len())
            .map(|index| {
                let mut host = open(index, true).unwrap();
                let (actual, binding) = host
                    .common_snapshot_authority_for_test(agent)
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, certificate);
                binding.verify(&certificate, binding.claim()).unwrap();
                assert_eq!(host.journal_position(agent).unwrap(), completed.0);
                Arc::new(std::sync::Mutex::new(host))
            })
            .collect();
        if crash.is_none() && !retained_mode {
            use crate::agent::journal::JournalStorageClass;
            use crate::agent::journal_store::{
                ExternalArchiveLimits, ExternalArchiveRecord, read_external_archive,
            };
            // This is a streamed storage closure, not transferable checkpoint
            // authority. The exact QC/local binding stays independently bound
            // to this certified source; decoding cannot activate an import.
            let mut host = hosts[checkpoint_owner].lock().unwrap();
            let position = host.journal_position(agent).unwrap();
            let heads_bytes = std::fs::read(journal_root(checkpoint_owner).join("heads")).unwrap();
            let source_heads = JournalHeads::decode(&heads_bytes).unwrap();
            let authority = host
                .common_snapshot_authority_for_test(agent)
                .unwrap()
                .unwrap();
            assert_eq!(authority.0, certificate);
            authority
                .1
                .verify(&certificate, authority.1.claim())
                .unwrap();
            assert_eq!(source_heads.id(), authority.1.claim().journal_heads());
            assert_eq!(
                source_heads.checkpoint,
                Some(authority.1.claim().checkpoint())
            );
            assert_eq!(source_heads.node, merges[checkpoint_owner].node());
            assert_eq!(
                authority.1.claim().journal_store().0,
                *host
                    .journal_store_instance_for_test(agent)
                    .unwrap()
                    .as_bytes()
            );
            let attachment = host.supervisor_attachment_status(agent).unwrap().unwrap();
            assert_eq!(
                attachment.transport,
                crate::agent::shared_host::SharedAgentTransportState::NotAttached
            );
            let limits = ExternalArchiveLimits {
                max_objects: 1_000_000,
                max_blobs: 1_000_000,
                max_history_nodes: 1_000_000,
                max_wire_bytes: 64 * 1024 * 1024 * 1024,
            };
            let archive_path = directories[checkpoint_owner]
                .0
                .join("external-common-checkpoint.axj");
            let archive_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&archive_path)
                .unwrap();
            let mut output = std::io::BufWriter::new(archive_file);
            let exported = host
                .export_external_common_checkpoint_archive(agent, limits, &mut output)
                .unwrap();
            std::io::Write::flush(&mut output).unwrap();
            drop(output);
            assert_eq!(exported.source_heads, source_heads);
            assert_eq!(
                exported.wire_bytes,
                std::fs::metadata(&archive_path).unwrap().len()
            );
            let mut input = std::io::BufReader::new(std::fs::File::open(&archive_path).unwrap());
            let mut objects = 0_u64;
            let mut blobs = 0_u64;
            let mut history_nodes = 0_u64;
            let mut state_blocks = 0_u64;
            let decoded = read_external_archive(&mut input, source_heads.id(), limits, |record| {
                match record {
                    ExternalArchiveRecord::Object { class, id, bytes } => {
                        assert_ne!(
                            class,
                            JournalStorageClass::Heads,
                            "foreign source heads must never enter an immutable staging callback"
                        );
                        assert_ne!(id, [0; 32]);
                        assert!(!bytes.is_empty());
                        objects += 1;
                        history_nodes +=
                            u64::from(class == JournalStorageClass::InvocationHistoryNode);
                    }
                    ExternalArchiveRecord::Blob {
                        class,
                        reference,
                        bytes,
                    } => {
                        assert!(reference.matches(bytes));
                        blobs += 1;
                        state_blocks += u64::from(class == JournalBlobClass::StateBlock);
                    }
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(decoded.source_heads, source_heads);
            assert_eq!(decoded.source_predecessor, exported.source_predecessor);
            let predecessor = decoded.source_predecessor.as_ref().unwrap();
            assert_eq!(Some(predecessor.id()), source_heads.previous);
            assert_eq!(
                predecessor.id(),
                authority.1.claim().checkpoint_predecessor()
            );
            assert_eq!(predecessor.node, source_heads.node);
            assert_eq!(
                decoded.objects,
                objects + u64::from(decoded.source_predecessor.is_some())
            );
            assert_eq!(decoded.blobs, blobs);
            assert_eq!(decoded.history_nodes, history_nodes);
            assert_eq!(decoded.objects, exported.objects);
            assert_eq!(decoded.blobs, exported.blobs);
            assert_eq!(decoded.history_nodes, exported.history_nodes);
            assert_eq!(decoded.wire_bytes, exported.wire_bytes);
            assert_eq!(decoded.keys, exported.keys);
            assert_eq!(decoded.identity, exported.identity);
            assert_ne!(decoded.keys, HostHash::ZERO);
            assert_ne!(decoded.identity, HostHash::ZERO);
            assert!(
                objects > 0 && state_blocks > 0,
                "signed external Clerk archive must contain real typed records and state blocks"
            );
            // Quarantine owns a genuinely different physical slot. Import
            // preflight may authenticate the foreign certificate's contents,
            // but must not impersonate its store or publish its source heads.
            let verified =
                VerifiedAgentGenesisProvision::verify(provision.clone(), finality).unwrap();
            let source_node = merges[checkpoint_owner].node();
            let source_seal =
                LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_external_shared_genesis(
                    &verified,
                    committee.member_by_node(source_node).unwrap().replica(),
                    catalog,
                    &fixture.trust,
                    source_node,
                )
                .unwrap();
            let quarantine = TestDirectory::new("external-checkpoint-archive-quarantine");
            let parent = std::fs::File::open(&quarantine.0).unwrap();
            let scratch_root = quarantine.0.join(format!("{leaf}.agent"));
            let scratch_intent = crate::agent::journal_store::external_archive_stage_intent(
                &source_seal,
                source_heads.id(),
            )
            .unwrap();
            let scratch_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
                &scratch_root,
                scratch_root.with_extension("agent-lock"),
                source_node,
                scratch_intent,
                &parent,
                &parent,
            )
            .unwrap();
            let mut scratch_input =
                std::io::BufReader::new(std::fs::File::open(&archive_path).unwrap());
            let mut scratch_budget = Driver::external_recovery_budget();
            let mut staged = crate::agent::journal_store::StagedExternalArchive::read(
                scratch_slot,
                &source_seal,
                catalog,
                source_heads.id(),
                limits,
                &mut scratch_budget,
                &mut scratch_input,
            )
            .unwrap();
            assert_eq!(staged.report().identity, exported.identity);
            assert_ne!(
                staged.instance_id().as_bytes(),
                &authority.1.claim().journal_store().0
            );
            let scratch_heads = std::fs::read(scratch_root.join("heads")).unwrap();
            assert_eq!(scratch_heads, source_seal.initial_heads().unwrap().encode());
            assert_ne!(scratch_heads, heads_bytes);
            assert!(!scratch_root.join("heads.next").exists());
            let predecessor_hex: String = predecessor
                .id()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert!(
                !scratch_root
                    .join("heads-history")
                    .join(predecessor_hex)
                    .exists(),
                "foreign predecessor must remain bounded metadata, never a disk head record"
            );
            drop(staged);
            let acquire_scratch = || {
                FileLocalAgentJournalSlot::acquire_with_pinned_parents(
                    &scratch_root,
                    scratch_root.with_extension("agent-lock"),
                    source_node,
                    scratch_intent,
                    &parent,
                    &parent,
                )
                .unwrap()
            };
            let mut wrong_identity = exported.identity;
            wrong_identity.0[0] ^= 1;
            assert!(matches!(
                crate::agent::journal_store::StagedExternalArchive::resume(
                    acquire_scratch(),
                    &source_seal,
                    catalog,
                    source_heads.id(),
                    wrong_identity,
                    limits,
                    &mut Driver::external_recovery_budget(),
                    &mut std::io::BufReader::new(std::fs::File::open(&archive_path).unwrap()),
                ),
                Err(crate::agent::journal_store::JournalStoreError::ScopeMismatch),
            ));
            assert_eq!(
                std::fs::read(scratch_root.join("heads")).unwrap(),
                scratch_heads
            );
            assert!(!scratch_root.join("heads.next").exists());
            let mut staged = crate::agent::journal_store::StagedExternalArchive::resume(
                acquire_scratch(),
                &source_seal,
                catalog,
                source_heads.id(),
                exported.identity,
                limits,
                &mut Driver::external_recovery_budget(),
                &mut std::io::BufReader::new(std::fs::File::open(&archive_path).unwrap()),
            )
            .unwrap();
            assert_eq!(staged.report().identity, exported.identity);
            assert_eq!(
                std::fs::read(scratch_root.join("heads")).unwrap(),
                scratch_heads
            );
            assert!(!scratch_root.join("heads.next").exists());
            let report = staged.report().clone();
            let resolver = staged.catalog_blob_resolver().unwrap();
            let mut source_executor = StandardLocalReplayExecutor::new_shared(
                resolver,
                fixture.trust.clone(),
                merges[checkpoint_owner].clone(),
                vec![committee.clone()],
            );
            let audited = staged
                .with_source_view(|view| {
                    assert_eq!(view.heads()?.as_ref(), Some(&source_heads));
                    assert_eq!(
                        view.historical_heads(predecessor.id())?.as_ref(),
                        Some(predecessor)
                    );
                    assert!(
                        matches!(
                            crate::agent::replay::validate_external_common_checkpoint_head(
                                view,
                                &source_seal,
                                &source_heads,
                                &mut source_executor,
                                &NoPrunedOrderedBases,
                                &authority.0,
                                &authority.1,
                                &mut Driver::external_recovery_budget(),
                            ),
                            Err(crate::agent::journal_store::JournalStoreError::ScopeMismatch),
                        ),
                        "a scratch owner must never pass the actual physical-source opener"
                    );
                    let mut substituted = source_heads.clone();
                    substituted.publication_revision += 1;
                    assert!(
                        crate::agent::replay::audit_external_archive_source(
                            view,
                            &source_seal,
                            &substituted,
                            report.source_predecessor.as_ref(),
                            &mut source_executor,
                            &NoPrunedOrderedBases,
                            &authority.0,
                            &authority.1,
                            &mut Driver::external_recovery_budget(),
                        )
                        .is_err()
                    );
                    let audited = crate::agent::replay::audit_external_archive_source(
                        view,
                        &source_seal,
                        &source_heads,
                        report.source_predecessor.as_ref(),
                        &mut source_executor,
                        &NoPrunedOrderedBases,
                        &authority.0,
                        &authority.1,
                        &mut Driver::external_recovery_budget(),
                    )?;
                    assert_eq!(audited.scratch_store(), view.instance_id());
                    assert_eq!(audited.scratch_epoch(), view.validation_epoch());
                    assert_eq!(audited.source_heads(), &source_heads);
                    assert_eq!(audited.certificate(), &authority.0);
                    assert_eq!(audited.binding(), &authority.1);
                    audited.require_source(view)?;
                    Ok(audited)
                })
                .unwrap();
            let destination_index = (checkpoint_owner + 1) % merges.len();
            let destination_node = merges[destination_index].node();
            let destination_seal =
                LocalJournalAgentDriver::<FileAgentJournalStore>::prepare_external_shared_genesis(
                    &verified,
                    committee
                        .member_by_node(destination_node)
                        .unwrap()
                        .replica(),
                    catalog,
                    &fixture.trust,
                    destination_node,
                )
                .unwrap();
            let destination_directory =
                TestDirectory::new("external-checkpoint-rebind-destination");
            let destination_parent = std::fs::File::open(&destination_directory.0).unwrap();
            let destination_root = destination_directory.0.join(format!("{leaf}.agent"));
            let destination_intent = HostHash::digest(
                b"vos/test/external-checkpoint-rebind-destination/v1",
                &[
                    destination_seal.genesis().id().as_bytes(),
                    destination_node.as_bytes(),
                ],
            );
            let destination_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
                &destination_root,
                destination_root.with_extension("agent-lock"),
                destination_node,
                destination_intent,
                &destination_parent,
                &destination_parent,
            )
            .unwrap();
            let mut destination_store = destination_slot
                .open_external_genesis(
                    &destination_seal,
                    false,
                    &mut Driver::external_recovery_budget(),
                )
                .unwrap();
            for blob in catalog {
                destination_store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &blob.reference,
                        &blob.bytes,
                    )
                    .unwrap();
            }
            destination_store
                .initialize_external_local(
                    &destination_seal,
                    &mut Driver::external_recovery_budget(),
                )
                .unwrap();
            let destination_predecessor = destination_store.heads().unwrap().unwrap();
            let rebound = crate::agent::shared_journal_driver::preflight_external_common_rebind(
                audited,
                &mut staged,
                &destination_seal,
                &destination_store,
                &destination_predecessor,
            )
            .unwrap();
            assert_eq!(rebound.predecessor(), &destination_predecessor);
            assert_eq!(rebound.heads().node, destination_node);
            assert_eq!(rebound.heads().previous, Some(destination_predecessor.id()));
            assert_eq!(rebound.heads().ordered_head, source_heads.ordered_head);
            assert_eq!(rebound.heads().ordered_index, source_heads.ordered_index);
            assert_eq!(rebound.certificate(), &authority.0);
            assert_eq!(rebound.source_binding(), &authority.1);
            assert_ne!(rebound.heads().id(), source_heads.id());
            let source_checkpoint = staged
                .with_source_view(|view| {
                    view.get::<crate::agent::journal::CheckpointManifest>(
                        source_heads.checkpoint.unwrap(),
                    )?
                    .ok_or(crate::agent::journal_store::JournalStoreError::MissingObject)
                })
                .unwrap();
            for lane in [
                crate::agent::journal::PersistedLane::Control,
                crate::agent::journal::PersistedLane::Linear,
                crate::agent::journal::PersistedLane::Merge,
            ] {
                assert_eq!(
                    rebound
                        .checkpoint()
                        .lanes
                        .iter()
                        .find(|entry| entry.lane == lane),
                    source_checkpoint
                        .lanes
                        .iter()
                        .find(|entry| entry.lane == lane),
                    "common lane declarations must not be localized or reconstructed",
                );
            }
            let destination_generation = AgentGenerationRouteKey::new(
                committee.space(),
                committee.agent(),
                destination_seal.genesis().id(),
                destination_seal.admission_record().unwrap().id(),
            )
            .unwrap();
            let destination_authority = CommitteeChangeAuthorityBinding::new(
                descriptor.authority.policy,
                descriptor.authority.issuer,
                descriptor.identity.runtime_deployment,
                descriptor.authority.public_key,
                descriptor.authority.initial_epoch,
            )
            .unwrap();
            let destination_ledger = AgentRaftApplicationLedgerV2::open(
                Arc::new(
                    redb::Database::create(destination_directory.0.join("raft.redb")).unwrap(),
                ),
                destination_generation,
                destination_store.instance_id(),
                destination_node,
                committee.clone(),
                destination_authority,
            )
            .unwrap();
            let foundation = destination_ledger
                .common_restore_foundation(rebound.certificate())
                .unwrap();
            let unsigned = rebound.physical_claim(&foundation).unwrap();
            assert_eq!(unsigned.local_node(), destination_node);
            assert_eq!(
                &unsigned.journal_store().0,
                destination_store.instance_id().as_bytes()
            );
            assert_eq!(unsigned.journal_heads(), rebound.heads().id());
            assert_eq!(unsigned.ordered(), authority.0.claim().ordered());
            rebound
                .require_current(&mut staged, &destination_store, &destination_seal)
                .unwrap();
            assert_eq!(
                destination_store.heads().unwrap().as_ref(),
                Some(&destination_predecessor)
            );
            assert!(
                destination_ledger
                    .common_snapshot_authority()
                    .unwrap()
                    .is_none()
            );
            assert!(!destination_root.join("heads.next").exists());
            // All preceding assertions are read-only preflight evidence. The
            // independently admitted destination now commits its own initial
            // exposure before typed catch-up changes any mutable head.
            destination_store
                .commit_external_genesis_exposure(
                    &destination_seal,
                    destination_intent,
                    &mut Driver::external_recovery_budget(),
                )
                .unwrap();
            staged
                .promote_authenticated_source(
                    &source_seal,
                    &destination_seal,
                    &rebound,
                    &mut destination_store,
                    limits,
                    &mut Driver::external_recovery_budget(),
                )
                .unwrap();
            rebound
                .stage_metadata(&mut staged, &mut destination_store, &destination_seal)
                .unwrap();
            crate::agent::replay::validate_external_checkpoint_heads(
                &mut destination_store,
                rebound.heads(),
                &mut Driver::external_recovery_budget(),
            )
            .unwrap();
            let candidate = crate::agent::shared_host::VerifiedSharedAgentLocalSnapshotCandidate::from_reconstructed_for_test(
                authority.0.commitment(),
                unsigned,
            );
            let destination_binding =
                crate::agent::shared_commit::SharedAgentLocalSnapshotBinding::new(
                    authority.0.commitment(),
                    candidate.claim().clone(),
                    merges[destination_index]
                        .sign_local_snapshot_candidate(&candidate)
                        .unwrap(),
                )
                .unwrap();
            destination_binding
                .verify(&authority.0, candidate.claim())
                .unwrap();
            assert_ne!(destination_binding, authority.1);
            destination_ledger
                .validate_bound_common_restore(&authority.0, &destination_binding)
                .unwrap();
            let certified_recovery = host
                .common_snapshot_recovery_manifest_for_test(agent)
                .unwrap();
            let recovery = certified_recovery.clone().unwrap_or_else(|| {
                crate::agent::shared_recovery::SharedRecoveryManifest::new(
                    destination_generation,
                    committee.clone(),
                )
                .unwrap()
            });
            recovery
                .validate_at_raft_index(authority.0.claim().ordered().raft_index())
                .unwrap();
            assert_eq!(recovery.generation(), destination_generation);
            assert_eq!(recovery.committee(), &committee);
            match authority.0.claim().recovery_manifest() {
                Some(commitment) => {
                    assert_eq!(certified_recovery.unwrap().commitment(), commitment);
                }
                None => assert!(recovery.is_empty()),
            }
            let mut destination_executor = StandardLocalReplayExecutor::new_shared(
                destination_store.catalog_blob_resolver().unwrap(),
                fixture.trust.clone(),
                merges[destination_index].clone(),
                destination_ledger.committee_history().unwrap(),
            );
            let unpublished_ledger = destination_ledger.journal_audit().unwrap();
            let unpublished_recovery = destination_ledger.recovery_manifest_if_present().unwrap();
            for (endpoint, heads) in [
                ("predecessor", &destination_predecessor),
                ("target", rebound.heads()),
            ] {
                let checkpoint = destination_store
                    .get::<crate::agent::journal::CheckpointManifest>(heads.checkpoint.unwrap())
                    .unwrap()
                    .unwrap();
                let linear = checkpoint
                    .lanes
                    .iter()
                    .find(|lane| lane.lane == crate::agent::journal::PersistedLane::Linear)
                    .unwrap();
                let manifest = destination_store
                    .get::<crate::agent::journal::LaneStateManifest>(linear.state)
                    .unwrap()
                    .unwrap();
                let descriptor = manifest.external_root.unwrap().descriptor;
                let block = descriptor
                    .bind(descriptor.context(), descriptor.commitment())
                    .unwrap()
                    .root()
                    .unwrap();
                let block_name: String = block
                    .hash()
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let path = destination_root.join("lane-state/blocks").join(block_name);
                let parked = destination_directory
                    .0
                    .join(format!("parked-restore-{endpoint}-block"));
                let original = std::fs::read(&path).unwrap();
                std::fs::rename(&path, &parked).unwrap();
                assert!(
                    crate::agent::replay::audit_external_common_restore(
                        &mut destination_store,
                        &destination_seal,
                        &destination_predecessor,
                        rebound.heads(),
                        &mut destination_executor,
                        &NoPrunedOrderedBases,
                        &authority.0,
                        &destination_binding,
                        &mut Driver::external_recovery_budget(),
                    )
                    .is_err(),
                    "missing {endpoint} closure must refuse catch-up before publication"
                );
                assert!(!path.exists(), "a refused audit must not repair state");
                assert_eq!(
                    std::fs::read(destination_root.join("heads")).unwrap(),
                    destination_predecessor.encode()
                );
                assert!(!destination_root.join("heads.next").exists());
                assert_eq!(
                    destination_ledger.journal_audit().unwrap(),
                    unpublished_ledger
                );
                assert_eq!(
                    destination_ledger.recovery_manifest_if_present().unwrap(),
                    unpublished_recovery
                );
                assert!(
                    destination_ledger
                        .common_snapshot_authority()
                        .unwrap()
                        .is_none()
                );
                std::fs::rename(&parked, &path).unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), original);
            }
            assert!(matches!(
                crate::agent::replay::audit_external_common_restore(
                    &mut destination_store,
                    &destination_seal,
                    &destination_predecessor,
                    rebound.heads(),
                    &mut destination_executor,
                    &NoPrunedOrderedBases,
                    &authority.0,
                    &destination_binding,
                    &mut Driver::external_recovery_budget(),
                )
                .unwrap()
                .publish_through_heads_stage_for_test(),
                Err(crate::agent::journal_store::JournalStoreError::Unavailable),
            ));
            assert_eq!(
                std::fs::read(destination_root.join("heads")).unwrap(),
                destination_predecessor.encode()
            );
            assert_eq!(
                std::fs::read(destination_root.join("heads.next")).unwrap(),
                rebound.heads().encode()
            );
            assert_eq!(
                destination_ledger.journal_audit().unwrap(),
                unpublished_ledger
            );
            assert_eq!(
                destination_ledger.recovery_manifest_if_present().unwrap(),
                unpublished_recovery
            );
            assert!(
                destination_ledger
                    .common_snapshot_authority()
                    .unwrap()
                    .is_none()
            );
            // This is a retry through the real typed heads.next primitive,
            // not restart through an authenticated automatic host marker.
            destination_ledger
                .validate_bound_common_restore(&authority.0, &destination_binding)
                .unwrap();
            let publication = crate::agent::replay::audit_external_common_restore(
                &mut destination_store,
                &destination_seal,
                &destination_predecessor,
                rebound.heads(),
                &mut destination_executor,
                &NoPrunedOrderedBases,
                &authority.0,
                &destination_binding,
                &mut Driver::external_recovery_budget(),
            )
            .unwrap()
            .publish()
            .unwrap();
            assert!(publication.heads_advanced);
            assert_eq!(
                destination_store.heads().unwrap().as_ref(),
                Some(rebound.heads())
            );
            assert!(!destination_root.join("heads.next").exists());
            destination_ledger
                .restore_common_snapshot(&authority.0, &destination_binding, &recovery)
                .unwrap();
            assert_eq!(
                destination_ledger.common_snapshot_authority().unwrap(),
                Some((authority.0.clone(), destination_binding.clone()))
            );
            let installed_ledger = destination_ledger.journal_audit().unwrap();
            destination_ledger
                .validate_bound_common_restore(&authority.0, &destination_binding)
                .unwrap();
            let repeated_publication = crate::agent::replay::audit_external_common_restore(
                &mut destination_store,
                &destination_seal,
                &destination_predecessor,
                rebound.heads(),
                &mut destination_executor,
                &NoPrunedOrderedBases,
                &authority.0,
                &destination_binding,
                &mut Driver::external_recovery_budget(),
            )
            .unwrap()
            .publish()
            .unwrap();
            assert!(!repeated_publication.heads_advanced);
            assert!(!repeated_publication.object_created);
            assert_eq!(
                destination_store.heads().unwrap().as_ref(),
                Some(rebound.heads())
            );
            assert!(!destination_root.join("heads.next").exists());
            assert_eq!(
                destination_ledger.journal_audit().unwrap(),
                installed_ledger
            );
            let restored_heads = rebound.heads().clone();
            drop(destination_executor);
            drop(destination_ledger);
            drop(destination_store);
            let destination_seal = Arc::new(destination_seal);
            let destination_artifacts = destination_directory.0.join("artifacts");
            std::fs::create_dir(&destination_artifacts).unwrap();
            let open_destination = || {
                let slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
                    &destination_root,
                    destination_root.with_extension("agent-lock"),
                    destination_node,
                    destination_intent,
                    &destination_parent,
                    &destination_parent,
                )
                .unwrap();
                let ledger = AgentRaftApplicationLedgerV2::open(
                    Arc::new(
                        redb::Database::create(destination_directory.0.join("raft.redb")).unwrap(),
                    ),
                    destination_generation,
                    slot.instance_id(),
                    destination_node,
                    committee.clone(),
                    destination_authority,
                )
                .unwrap();
                let (store, executor, validated) = slot
                    .open_external_shared_checkpoint_with_executor(
                        &destination_seal,
                        |store| {
                            Ok((
                                StandardLocalReplayExecutor::new_shared(
                                    store.catalog_blob_resolver()?,
                                    fixture.trust.clone(),
                                    merges[destination_index].clone(),
                                    ledger.committee_history().map_err(|_| {
                                        crate::agent::journal_store::JournalStoreError::Corrupt
                                    })?,
                                ),
                                ledger.common_snapshot_authority().map_err(|_| {
                                    crate::agent::journal_store::JournalStoreError::Corrupt
                                })?,
                            ))
                        },
                        &NoPrunedOrderedBases,
                        &mut Driver::external_recovery_budget(),
                        None,
                    )
                    .unwrap();
                let (materialization, availability) = validated
                    .into_external_common_shared_availability(
                        &store,
                        &destination_seal,
                        &authority.0,
                        &destination_binding,
                    )
                    .unwrap();
                availability
                    .require_current(&store, &materialization)
                    .unwrap();
                drop(executor);
                Driver::open_external(
                    store,
                    FileSharedArtifactStager::open(
                        destination_artifacts.clone(),
                        destination_generation,
                    )
                    .unwrap(),
                    ledger,
                    fixture.trust.clone(),
                    merges[destination_index].clone(),
                    destination_seal.clone(),
                )
                .unwrap()
            };
            let mut restored = open_destination();
            assert_eq!(restored.materialization().heads(), &restored_heads);
            assert_eq!(
                restored.common_snapshot_authority().unwrap(),
                Some((authority.0.clone(), destination_binding.clone()))
            );
            // This isolates real destination execution/application, not public
            // host-marker restart or a new network-quorum serving workflow.
            let (restored_work, restored_authorization) = clerk_call(
                "state_root",
                Vec::new(),
                MethodMode::LinearizableQuery,
                member,
                0xf4,
            );
            let mut acknowledgement = None;
            for (operation, request) in [
                CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work: restored_work.clone(),
                    authorization: restored_authorization.clone(),
                },
                CleanInvocationReplayRequest::Acknowledge {
                    work: restored_work.clone(),
                    authorization: restored_authorization.clone(),
                },
            ]
            .into_iter()
            .enumerate()
            {
                let PreparedCleanOrdered::Proposal { input, payload } =
                    restored.prepare_clean_ordered_operation(request).unwrap()
                else {
                    panic!("restored Clerk operation unexpectedly retained");
                };
                let index = restored
                    .append_command_for_test(authority.0.claim().ordered().raft_term(), payload)
                    .unwrap();
                assert_eq!(
                    index,
                    authority.0.claim().ordered().raft_index() + operation as u64 + 1
                );
                assert_eq!(
                    restored.apply_next().unwrap(),
                    SharedPhysicalApplyOutcome::Applied { index }
                );
                let outcome = restored.take_clean_ordered_result(input).unwrap();
                if operation == 0 {
                    let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
                        panic!("restored Clerk state_root failed: {outcome:?}");
                    };
                    assert_eq!(
                        Value::decode(&reply.reply),
                        Value::Bytes(reference.root().to_vec()),
                        "typed catch-up must preserve the signed transfer's kernel root"
                    );
                } else {
                    assert!(matches!(outcome, RuntimeOutcome::Acknowledged(Ok(_))));
                    acknowledgement =
                        Some((input, restored.available_ordered_claim(input).unwrap()));
                }
            }
            let evolved_heads = restored.materialization().heads().clone();
            assert_eq!(
                evolved_heads.ordered_index,
                restored_heads.ordered_index + 2
            );
            let (acknowledgement_input, acknowledgement_claim) = acknowledgement.unwrap();
            drop(restored);
            let mut reopened = open_destination();
            assert_eq!(reopened.materialization().heads(), &evolved_heads);
            assert_eq!(
                reopened
                    .available_ordered_claim(acknowledgement_input)
                    .unwrap(),
                acknowledgement_claim
            );
            assert_eq!(
                reopened.common_snapshot_authority().unwrap(),
                Some((authority.0.clone(), destination_binding))
            );
            drop(reopened);
            assert_eq!(
                std::fs::read(scratch_root.join("heads")).unwrap(),
                scratch_heads
            );
            assert!(!scratch_root.join("heads.next").exists());
            drop(source_executor);
            drop(staged);
            let scratch_slot = FileLocalAgentJournalSlot::acquire_with_pinned_parents(
                &scratch_root,
                scratch_root.with_extension("agent-lock"),
                source_node,
                scratch_intent,
                &parent,
                &parent,
            )
            .unwrap();
            assert!(
                matches!(
                    scratch_slot.open_external_genesis(
                        &source_seal,
                        true,
                        &mut Driver::external_recovery_budget(),
                    ),
                    Err(crate::agent::journal_store::JournalStoreError::Corrupt),
                ),
                "quarantine must never acquire an exposed-generation lock bit"
            );
            assert_eq!(
                std::fs::read(journal_root(checkpoint_owner).join("heads")).unwrap(),
                heads_bytes
            );
            assert_eq!(host.journal_position(agent).unwrap(), position);
            assert_eq!(
                host.common_snapshot_authority_for_test(agent)
                    .unwrap()
                    .unwrap(),
                authority
            );
            assert_eq!(
                host.supervisor_attachment_status(agent).unwrap().unwrap(),
                attachment
            );
        }
        if let Some((retained_work, retained_authorization, retained_outcome)) = retained_reply {
            let InvocationAuthorization::AuthorityReceipt(receipt) = &retained_authorization else {
                unreachable!()
            };
            fixture
                .logical_slot
                .as_ref()
                .unwrap()
                .store(receipt.selector.expires_at + 1, Ordering::Release);
            let retained_request = CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: retained_work.clone(),
                authorization: retained_authorization.clone(),
            };
            let ack_request = CleanInvocationReplayRequest::Acknowledge {
                work: retained_work.clone(),
                authorization: retained_authorization.clone(),
            };
            for host in &hosts {
                let mut host = host.lock().unwrap();
                let proof = host
                    .inspect_external_retained_reply(agent, &retained_request)
                    .unwrap()
                    .unwrap();
                assert_eq!(proof.outcome(), &retained_outcome);
                assert_eq!(proof.claim(), certificate.claim().ordered());
                assert_eq!(host.journal_position(agent).unwrap(), completed.0);
            }
            {
                let mut host = hosts[0].lock().unwrap();
                let mut altered_work = retained_work.clone();
                altered_work.gas -= 1;
                let altered = CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work: altered_work,
                    authorization: retained_authorization.clone(),
                };
                assert!(
                    host.inspect_external_retained_reply(agent, &altered)
                        .is_err()
                );
                let mut altered_authorization = retained_authorization.clone();
                let InvocationAuthorization::AuthorityReceipt(altered_receipt) =
                    &mut altered_authorization
                else {
                    unreachable!()
                };
                altered_receipt.signature[0] ^= 1;
                let altered = CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work: retained_work.clone(),
                    authorization: altered_authorization,
                };
                assert!(
                    host.inspect_external_retained_reply(agent, &altered)
                        .is_err()
                );
                assert_eq!(host.journal_position(agent).unwrap(), completed.0);
                let path = journal_root(0)
                    .join("lane-state/blocks")
                    .join(external_current_root_block(&mut host, agent));
                let parked = directories[0].0.join("parked-retained-inspection-block");
                let heads = std::fs::read(journal_root(0).join("heads")).unwrap();
                std::fs::rename(&path, &parked).unwrap();
                assert!(
                    host.inspect_external_retained_reply(agent, &retained_request)
                        .is_err()
                );
                assert_eq!(std::fs::read(journal_root(0).join("heads")).unwrap(), heads);
                assert_eq!(host.journal_position(agent).unwrap(), completed.0);
                assert!(!path.exists());
                std::fs::rename(&parked, &path).unwrap();
                assert!(
                    host.inspect_external_retained_reply(agent, &retained_request)
                        .is_err(),
                    "restoring bytes must not revive an invalidated retained-reply pin"
                );
            }
            drop(hosts);
            hosts = (0..keys.len())
                .map(|index| Arc::new(std::sync::Mutex::new(open(index, true).unwrap())))
                .collect();
            attached = attach(&hosts);
            assert_eq!(
                external_network_on_leader(&attached, agent, |owner| {
                    owner.supervisor_invoke(
                        identity,
                        retained_work.clone(),
                        retained_authorization.clone(),
                    )
                }),
                retained_outcome,
                "expired exact Invoke must return the retained reply through current-root quorum"
            );
            for host in &hosts {
                assert_eq!(
                    host.lock().unwrap().journal_position(agent).unwrap(),
                    completed.0,
                    "retained Invoke must not append a new execution"
                );
            }
            let proof_owner = attached
                .iter()
                .position(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
                .unwrap();
            let pre_ack_proof = {
                let mut host = hosts[proof_owner].lock().unwrap();
                let proof = host
                    .inspect_external_retained_reply(agent, &retained_request)
                    .unwrap()
                    .unwrap();
                assert!(
                    host.revalidate_external_retained_reply(agent, &ack_request, &proof)
                        .is_err(),
                    "an Invoke proof cannot stand in for an ACK proof"
                );
                let clock = fixture.logical_slot.as_ref().unwrap();
                let inspected_slot = clock.load(Ordering::Acquire);
                assert!(inspected_slot - 1 > receipt.selector.valid_from);
                clock.store(inspected_slot - 1, Ordering::Release);
                assert!(
                    matches!(
                        host.revalidate_external_retained_reply(agent, &retained_request, &proof),
                        Err(SharedAgentHostError::Unavailable)
                    ),
                    "trusted clock regression must require a fresh inspection"
                );
                clock.store(inspected_slot, Ordering::Release);
                assert_eq!(
                    host.revalidate_external_retained_reply(agent, &retained_request, &proof)
                        .unwrap(),
                    retained_outcome,
                );
                assert_eq!(host.journal_position(agent).unwrap(), completed.0);
                proof
            };
            let acknowledgement = external_network_on_leader(&attached, agent, |owner| {
                owner.supervisor_acknowledge(
                    identity,
                    retained_work.clone(),
                    retained_authorization.clone(),
                )
            });
            assert!(matches!(
                &acknowledgement,
                RuntimeOutcome::Acknowledged(Ok(_))
            ));
            let retirement_input = crate::agent::journal::ReplayInput {
                runtime: provision.proposal().create().runtime.clone(),
                operation: ReplayOperation::CleanAcknowledge {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    expected_live: None,
                    work: crate::agent_sdk::InvocationRetirement::from_work(&retained_work),
                    authorization: retained_authorization.clone(),
                },
            }
            .id();
            let mut acknowledged = None;
            assert!(
                wait_until(std::time::Duration::from_secs(15), || {
                    let Some(states) = hosts
                        .iter()
                        .map(|host| {
                            let mut host = host.lock().unwrap();
                            if !host
                                .retained_positive_clean_acknowledgement(
                                    agent,
                                    &retained_work,
                                    &retained_authorization,
                                )
                                .ok()?
                            {
                                return None;
                            }
                            Some((
                                host.journal_position(agent).ok()?,
                                host.available_ordered_claim(agent, retirement_input).ok()?,
                            ))
                        })
                        .collect::<Option<Vec<_>>>()
                    else {
                        return false;
                    };
                    if states.iter().all(|state| state == &states[0])
                        && states[0].0.ordered_index == completed.0.ordered_index + 1
                    {
                        acknowledged = Some(states[0].clone());
                        true
                    } else {
                        false
                    }
                }),
                "real retained-result ACK must commit exactly one slot and identical replica claims"
            );
            let acknowledged = acknowledged.unwrap();
            assert!(
                hosts[proof_owner]
                    .lock()
                    .unwrap()
                    .revalidate_external_retained_reply(agent, &retained_request, &pre_ack_proof)
                    .is_err(),
                "a real ACK root advance must revoke the previously inspected Invoke proof"
            );
            let (checkpoint_work, checkpoint_authorization) = clerk_call(
                "state_root",
                Vec::new(),
                MethodMode::LinearizableQuery,
                member,
                0xee,
            );
            let mut second_certificate = None;
            let mut second_owner = None;
            assert!(
                wait_until(std::time::Duration::from_secs(30), || {
                    let Some(index) = attached
                        .iter()
                        .position(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
                    else {
                        return false;
                    };
                    let Some(boundaries) = hosts
                        .iter()
                        .map(|host| {
                            host.lock()
                                .unwrap()
                                .request_common_snapshot_compaction(agent)
                                .ok()
                                .map(|candidate| candidate.claim().clone())
                        })
                        .collect::<Option<Vec<_>>>()
                    else {
                        return false;
                    };
                    if !boundaries.iter().all(|claim| claim == &boundaries[index]) {
                        return false;
                    }
                    match attached[index].collect_common_checkpoint_for_admission(
                        agent,
                        &checkpoint_work,
                        &checkpoint_authorization,
                        &committee,
                        merges[index].as_ref(),
                    ) {
                        Ok(certified) => {
                            second_certificate = Some(certified);
                            second_owner = Some(index);
                            true
                        }
                        Err(SharedAgentHostError::Unavailable) => false,
                        Err(error) => panic!("second retained checkpoint: {error:?}"),
                    }
                }),
                "ACK-retaining checkpoint must obtain an exact physical quorum"
            );
            let second_certificate = second_certificate.unwrap();
            second_certificate
                .verify(&committee, second_certificate.claim())
                .unwrap();
            assert_eq!(second_certificate.signatures().len(), 2);
            let second_owner = second_owner.unwrap();
            external_freeze_checkpoint_workers(&mut attached, agent, second_owner);
            drop(attached);
            hosts[second_owner]
                .lock()
                .unwrap()
                .install_common_snapshot(agent, &second_certificate)
                .unwrap();
            for (index, host) in hosts.iter().enumerate() {
                let mut host = host.lock().unwrap();
                host.install_common_snapshot(agent, &second_certificate)
                    .unwrap();
                let (actual, binding) = host
                    .common_snapshot_authority_for_test(agent)
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, second_certificate);
                binding
                    .verify(&second_certificate, binding.claim())
                    .unwrap();
                assert_eq!(binding.claim().local_node(), merges[index].node());
                assert_eq!(
                    binding.claim().journal_store().0,
                    *host
                        .journal_store_instance_for_test(agent)
                        .unwrap()
                        .as_bytes()
                );
                assert_eq!(
                    binding.claim().ordered(),
                    second_certificate.claim().ordered()
                );
                assert_eq!(host.journal_position(agent).unwrap(), acknowledged.0);
            }
            drop(hosts);
            hosts = (0..keys.len())
                .map(|index| {
                    let mut host = open(index, true).unwrap();
                    assert_eq!(
                        host.common_snapshot_authority_for_test(agent)
                            .unwrap()
                            .unwrap()
                            .0,
                        second_certificate
                    );
                    assert_eq!(host.journal_position(agent).unwrap(), acknowledged.0);
                    Arc::new(std::sync::Mutex::new(host))
                })
                .collect();
            for host in &hosts {
                let mut host = host.lock().unwrap();
                let proof = host
                    .inspect_external_retained_reply(agent, &ack_request)
                    .unwrap()
                    .unwrap();
                assert_eq!(proof.outcome(), &acknowledgement);
                assert_eq!(proof.claim(), second_certificate.claim().ordered());
                assert!(
                    host.inspect_external_retained_reply(agent, &retained_request)
                        .is_err(),
                    "retired Invoke must not be mistaken for unseen work"
                );
            }
            attached = attach(&hosts);
            assert_eq!(
                external_network_on_leader(&attached, agent, |owner| {
                    owner.supervisor_acknowledge(
                        identity,
                        retained_work.clone(),
                        retained_authorization.clone(),
                    )
                }),
                acknowledgement,
                "exact expired ACK must retain its complete positive outcome after a second checkpoint"
            );
            let mut refused = None;
            assert!(
                wait_until(std::time::Duration::from_secs(30), || {
                    let Some(owner) = attached
                        .iter()
                        .find(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
                    else {
                        return false;
                    };
                    match owner.supervisor_invoke(
                        identity,
                        retained_work.clone(),
                        retained_authorization.clone(),
                    ) {
                        Err(SharedAgentHostError::Unavailable) => false,
                        result => {
                            refused = Some(result);
                            true
                        }
                    }
                }),
                "retired Invoke must reach a terminal refusal, not merely remain unavailable"
            );
            assert!(matches!(
                refused.unwrap(),
                Err(_) | Ok(RuntimeOutcome::Completed(Err(_)))
            ));
            for host in &hosts {
                assert_eq!(
                    host.lock().unwrap().journal_position(agent).unwrap(),
                    acknowledged.0,
                    "exact ACK retry and retired Invoke must not append slots"
                );
            }
            drop(attached);
            drop(hosts);
            for network in networks.into_iter().skip(1) {
                stop_network(network);
            }
            return;
        }
        attached = attach(&hosts);
        let (continued_work, continued_authorization) = clerk_call(
            "state_root",
            Vec::new(),
            MethodMode::LinearizableQuery,
            member,
            0xec,
        );
        let continued_input = crate::agent::journal::ReplayInput {
            runtime: provision.proposal().create().runtime.clone(),
            operation: ReplayOperation::CleanInvoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: continued_work.clone(),
                authorization: continued_authorization.clone(),
                observed_slot: material.observed_slot,
            },
        }
        .id();
        let continued_ack = crate::agent::journal::ReplayInput {
            runtime: provision.proposal().create().runtime.clone(),
            operation: ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work: crate::agent_sdk::InvocationRetirement::from_work(&continued_work),
                authorization: continued_authorization.clone(),
            },
        }
        .id();
        let continued = external_network_on_leader(&attached, agent, |owner| {
            owner.supervisor_invoke(
                identity,
                continued_work.clone(),
                continued_authorization.clone(),
            )
        });
        let RuntimeOutcome::Completed(Ok(reply)) = continued else {
            panic!("external post-checkpoint Clerk invocation: {continued:?}");
        };
        assert_eq!(
            Value::decode(&reply.reply),
            Value::Bytes(reference.root().to_vec())
        );
        assert!(matches!(
            external_network_on_leader(&attached, agent, |owner| {
                owner.supervisor_acknowledge(
                    identity,
                    continued_work.clone(),
                    continued_authorization.clone(),
                )
            }),
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let mut continued_claims = None;
        assert!(
            wait_until(std::time::Duration::from_secs(15), || {
                let Some(states) = hosts
                    .iter()
                    .map(|host| {
                        let mut host = host.lock().unwrap();
                        if !host
                            .retained_positive_clean_acknowledgement(
                                agent,
                                &continued_work,
                                &continued_authorization,
                            )
                            .ok()?
                        {
                            return None;
                        }
                        Some((
                            host.journal_position(agent).ok()?,
                            host.available_ordered_claim(agent, continued_input).ok()?,
                            host.available_ordered_claim(agent, continued_ack).ok()?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return false;
                };
                if states.iter().all(|state| state == &states[0])
                    && states[0].0.ordered_index == completed.0.ordered_index + 2
                {
                    continued_claims = Some(states[0].clone());
                    true
                } else {
                    false
                }
            }),
            "fresh post-checkpoint Invoke/ACK must converge on complete replica claims"
        );
        let continued_claims = continued_claims.unwrap();
        drop(attached);
        drop(hosts);
        for index in 0..keys.len() {
            let mut host = open(index, true).unwrap();
            assert_eq!(
                host.common_snapshot_authority_for_test(agent)
                    .unwrap()
                    .unwrap()
                    .0,
                certificate
            );
            assert_eq!(
                (
                    host.journal_position(agent).unwrap(),
                    host.available_ordered_claim(agent, continued_input)
                        .unwrap(),
                    host.available_ordered_claim(agent, continued_ack).unwrap()
                ),
                continued_claims
            );
        }
        for network in networks.into_iter().skip(1) {
            stop_network(network);
        }
        return;
    }
    drop(attached);
    drop(hosts);
    for index in 0..keys.len() {
        let mut host = open(index, true).unwrap();
        assert!(host.uses_external_state(agent).unwrap());
        assert!(
            host.retained_positive_clean_acknowledgement(agent, &work, &authorization)
                .unwrap()
        );
        assert!(
            host.retained_positive_clean_acknowledgement(agent, &root_work, &root_authorization,)
                .unwrap()
        );
        let acknowledged = host.available_ordered_claim(agent, ack_input).unwrap();
        assert_eq!(
            (
                host.journal_position(agent).unwrap(),
                acknowledged.clone(),
                host.available_ordered_claim(agent, root_input).unwrap(),
                host.available_ordered_claim(agent, root_ack_input).unwrap(),
            ),
            completed,
            "reopen must preserve the complete claims binding the public Clerk root"
        );
        assert!(acknowledged.ordered().index > expected.1.ordered().index);
        assert_ne!(
            acknowledged.linear().manifest(),
            expected.1.linear().manifest()
        );
    }
    for network in networks.into_iter().skip(1) {
        stop_network(network);
    }
}

fn external_current_root_block(host: &mut SharedAgentHost, agent: HostAgentId) -> String {
    let lanes = host.external_inspection_lanes_for_test(agent).unwrap();
    assert_eq!(
        lanes.len(),
        1,
        "this fixture admits only external Linear state"
    );
    let descriptor = lanes[0].base;
    let block = descriptor
        .bind(descriptor.context(), descriptor.commitment())
        .unwrap()
        .root()
        .unwrap();
    block
        .hash()
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn external_freeze_checkpoint_workers(
    attached: &mut [crate::network::SharedAgentNetworkHost],
    agent: HostAgentId,
    source: usize,
) {
    for owner in attached.iter() {
        owner.set_raft_isolated_for_test(agent, true).unwrap();
    }
    for (index, owner) in attached.iter_mut().enumerate() {
        if index != source {
            owner.retire_attachment_for_test(agent).unwrap();
        }
    }
    attached[source].retire_attachment_for_test(agent).unwrap();
}

fn external_network_on_leader(
    attached: &[crate::network::SharedAgentNetworkHost],
    agent: HostAgentId,
    mut operation: impl FnMut(
        &crate::network::SharedAgentNetworkHost,
    ) -> Result<RuntimeOutcome, SharedAgentHostError>,
) -> RuntimeOutcome {
    let mut result = None;
    assert!(
        wait_until(std::time::Duration::from_secs(30), || {
            let Some(owner) = attached
                .iter()
                .find(|owner| owner.bootstrap_is_local_leader(agent).unwrap_or(false))
            else {
                return false;
            };
            match operation(owner) {
                Ok(outcome) => {
                    result = Some(outcome);
                    true
                }
                Err(SharedAgentHostError::Unavailable) => false,
                Err(error) => panic!("external network lifecycle admission: {error:?}"),
            }
        }),
        "external network lifecycle did not complete through its current leader"
    );
    result.unwrap()
}
