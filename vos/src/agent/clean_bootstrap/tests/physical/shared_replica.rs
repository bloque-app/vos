//! A committee member that did not originate an ordinary Shared Create admits
//! the generation from operator-carried archive bytes, and a replica-only
//! restart re-mints its replay proof. Every fixture refuses archive finality:
//! only proofs minted by the root-pinned owner's fresh Authority read count.

use super::*;
use crate::agent::genesis::{AgentGenesisArchiveRecord, AgentGenesisLocator, AgentReplicaMember};

pub(super) struct RefuseArchiveFinality;

impl AgentGenesisFinalityVerifier for RefuseArchiveFinality {
    fn verify_finalized(
        &self,
        _: &crate::agent::genesis::AgentGenesisProvision,
    ) -> Result<(), AgentGenesisFinalityError> {
        Err(AgentGenesisFinalityError::NotFinalized)
    }
}

struct RootGenesisSigner(SigningKey);

impl super::super::super::genesis_issuance::GenesisClaimSigner for RootGenesisSigner {
    type Error = ();
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_genesis_claim(&mut self, message: &[u8; 32]) -> Result<[u8; 64], ()> {
        Ok(self.0.sign(message).to_bytes())
    }
}

type ReplicaController = NativeSharedGenesisController<
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    IssuerMemoryStore,
    MixedSharedArchive,
>;

/// Identity of an admitted generation, independent of transport attachment.
fn admitted(
    status: &crate::agent::shared_host::SharedAgentStatus,
) -> (
    crate::agent::shared_raft::AgentGenerationRouteKey,
    [u8; 32],
    usize,
) {
    (
        status.generation,
        status.replication_id,
        status.replicas.len(),
    )
}

/// Recovered Shared controller with no prior entries for a running owner.
fn controller(owner: &mut MemoryBootstrapOwner) -> ReplicaController {
    let mut controller = ReplicaController::new(owner.authority_target(), vec![]).unwrap();
    controller
        .recover(owner, &mut CountingSigner::new())
        .unwrap();
    controller
}

/// Create, publish, apply and retire one ordinary image Shared Agent through
/// the owner's lifecycle controller, with every system member as a voter
/// unless `local_only`. Returns the authenticated archive record and the
/// signed application ACK; the controller keeps the reservation leases.
fn originate(
    owner: &mut MemoryBootstrapOwner,
    controller: &mut ReplicaController,
    nonce: u8,
    sequence: u64,
    local_only: bool,
) -> (
    AgentGenesisArchiveRecord,
    crate::agent_sdk::authority::ManagementApplicationAck,
) {
    let target = owner.authority_target();
    let runtime = test_runtime_package(true);
    let mut descriptor = owner.pins.descriptor.clone();
    descriptor.creation_nonce = Hash([nonce; 32]);
    descriptor.identity.agent = AgentId::derive(
        descriptor.identity.space,
        descriptor.identity.owner,
        descriptor.creation_nonce.as_bytes(),
    );
    descriptor.identity.runtime_deployment = runtime.deployment();
    descriptor.identity.runtime_program = runtime.program();
    descriptor.identity.runtime_producer = runtime.producer();
    descriptor.runtime_package = runtime.package_ref().clone();
    descriptor.runtime_contract = runtime.manifest().contract;
    descriptor.capabilities = runtime.capabilities();
    let members: Vec<_> = owner
        .pins
        .replicas
        .members()
        .iter()
        .filter(|member| !local_only || member.replica().node.0 == owner.pins.node.0)
        .map(|member| {
            let mut replica = member.replica();
            replica.principal = crate::service::PrincipalId(descriptor.identity.owner.0);
            AgentReplicaMember::new(
                replica,
                member.peer_id().to_vec(),
                *member.ed25519_public_key(),
                member.raft_slot(),
            )
            .unwrap()
        })
        .collect();
    let replicas = AgentReplicaCommittee::new(
        crate::service::SpaceId(descriptor.identity.space.0),
        HostAgentId(descriptor.identity.agent.0),
        crate::agent::AgentProfile::Shared,
        members,
    )
    .unwrap();
    descriptor.replicas = replicas
        .members()
        .iter()
        .map(|member| AgentReplica {
            node: crate::agent_sdk::NodeId(member.replica().node.0),
            principal: descriptor.identity.owner,
            role: ReplicaRole::Voter,
        })
        .collect();
    descriptor.validate().unwrap();
    let key = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32]);
    let request = ManagementRequest::Create(Box::new(descriptor.clone()));
    let (mut call, _) = credential_call_and_approval(&descriptor, &request, &key);
    call.request_sequence = NonZeroU64::new(sequence).unwrap();
    call.authority = target;
    call.invocation = call.expected_invocation();
    call.signature = key.sign(&call.signing_bytes()).to_bytes();
    let locator = AgentGenesisLocator {
        space: crate::service::SpaceId(descriptor.identity.space.0),
        agent: HostAgentId(descriptor.identity.agent.0),
    };
    let archive = MixedSharedArchive::default();
    let mut signer = CountingSigner::new();
    controller
        .reserve_create_with(&descriptor, &call, &runtime, &replicas, || {
            Ok((
                MixedSharedRecovery::reserve_create_with_replicas(
                    target,
                    locator,
                    descriptor.clone(),
                    call.clone(),
                    runtime.clone(),
                    replicas.clone(),
                    (
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                        IssuerMemoryStore::default(),
                    ),
                )?,
                Some(archive.clone()),
            ))
        })
        .unwrap();
    let prepared = controller
        .prepare_pending_create(owner, locator, &mut signer)
        .unwrap();
    let signature = prepared
        .endorse(
            &mut IssuerMemoryStore::default(),
            &mut RootGenesisSigner(key),
        )
        .unwrap();
    let record = controller
        .publish_pending_create(owner, locator, vec![signature], &mut signer)
        .unwrap();
    let acknowledgement = controller
        .complete_pending_create(owner, locator, &mut signer)
        .unwrap();
    assert_eq!(acknowledgement.credential_call, call.commitment());
    assert_eq!(
        AgentGenesisArchiveRecord::decode(&archive.0.lock().unwrap().clone().unwrap()).unwrap(),
        record
    );
    (record, acknowledgement)
}

/// Replica-only restart on a singleton system (where the root-pinned owner is
/// always able to read its Authority): the deferred generation is re-proved
/// from the host's own retained intent and a fresh decision read, without the
/// originator's lifecycle stores and under a verifier that refuses archives.
#[test]
#[ignore = "requires the bundled outer PVM; run with VOS_AGENT_PROFILE_REFINE_MACHINES=1"]
fn native_shared_replica_restart_reproves_deferred_generation_without_lifecycle() {
    let mut fixture = native_bundled_authority_fixture();
    fixture.finality = Arc::new(RefuseArchiveFinality);
    let mut harness =
        NativeProjectionOwnerHarness::with_real_bootstrap("shared-replica-restart", fixture);
    let owner = harness.owner.as_mut().unwrap();
    let target = owner.authority_target();
    let mut shared = controller(owner);
    let (record, _) = originate(owner, &mut shared, 0xc7, 2, true);
    let agent = record.provision().proposal().locator().agent;
    let status = owner.host.lock().unwrap().show(agent).unwrap().unwrap();
    let position = owner.host.lock().unwrap().journal_position(agent).unwrap();
    let state = owner
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();

    // An admitted generation is an exact no-op: no fresh read, no mutation.
    let before = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        admitted(&owner.join_shared_replica(&record).unwrap()),
        admitted(&status)
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    // Replica recovery is only a startup phase.
    assert_eq!(
        owner.recover_deferred_shared_replicas(),
        Err(SharedAgentHostError::Conflict)
    );

    // Reopen with no Shared lifecycle entries: only the system Agent opens.
    drop(shared);
    let owner = harness.owner.take().unwrap();
    let pins = owner._pins_store;
    let record_store = owner.record_store;
    let issuer = owner.issuer.into_store();
    drop(owner._network_host);
    drop(owner.host);
    let mut operations = OperationTestJournal(harness._directory.0.clone());
    let admission = NativeAuthorityOperationStartupAdmission::load(&mut operations, target, &[])
        .unwrap()
        .with_deferred_shared_genesis();
    let mut owner = CleanSystemAgentBootstrapOwner::open_or_bootstrap_with_operation_admission(
        pins,
        record_store,
        issuer,
        &mut CountingSigner::new(),
        || panic!("replica restart must not bootstrap"),
        harness._directory.host(),
        harness._directory.lock(),
        harness.fixture.plan.pins.space,
        harness.fixture.plan.pins.node,
        harness.fixture.trust.clone(),
        harness.fixture.merge.clone(),
        harness.fixture.finality.clone(),
        harness.provider.clone(),
        harness.network.clone(),
        None,
        Some(&admission),
    )
    .unwrap();
    drop(admission);
    {
        let host = owner.host.lock().unwrap();
        assert!(host.has_deferred_open());
        assert_eq!(host.deferred_agent_ids(), vec![agent]);
        assert_eq!(host.len(), 1);
    }
    assert!(matches!(
        owner.ordinary_supervisor_generations(),
        Err(SharedAgentHostError::Conflict)
    ));
    // A live join cannot bypass the deferred complete-set gate.
    assert!(owner.join_shared_replica(&record).is_err());
    owner.recover_deferred_shared_replicas().unwrap();
    {
        let host = owner.host.lock().unwrap();
        assert!(!host.has_deferred_open());
        assert_eq!(host.len(), 2);
        assert_eq!(host.journal_position(agent).unwrap(), position);
        assert_eq!(host.clean_state_commitment(agent).unwrap(), state);
    }
    let generations = owner.ordinary_supervisor_generations().unwrap();
    assert!(
        generations
            .iter()
            .any(|generation| generation.agent().0 == agent.0)
    );
    drop(generations);
    let before = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        admitted(&owner.join_shared_replica(&record).unwrap()),
        admitted(&status)
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    harness.owner = Some(owner);
    harness.stop();
}

/// Fixed-three system: the Authority leader originates a three-voter Shared
/// Create; its archive bytes are handed to the other members, which admit the
/// generation only through their own Authority. Fresh Authority reads are
/// leader-only today, so a follower's join fails closed before mutation and
/// succeeds once that member leads the system Agent.
pub(super) fn exercise(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    networks: &mut Vec<Arc<Network>>,
) {
    let system_agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let followers: Vec<_> = (0..3).filter(|index| *index != leader).collect();
    let origin = owners[leader].as_mut().unwrap();
    assert!(wait_until(std::time::Duration::from_secs(15), || origin
        ._network_host
        .bootstrap_is_local_leader(system_agent)
        .unwrap_or(false)));
    let mut shared = controller(origin);
    let (record, _) = originate(origin, &mut shared, 0xc8, 2, false);
    assert_eq!(record.provision().replicas().members().len(), 3);
    let agent = record.provision().proposal().locator().agent;
    let origin_position = origin.host.lock().unwrap().journal_position(agent).unwrap();
    let origin_state = origin
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    // A record this member is not a replica of is refused before any read.
    let (foreign, _) = originate(origin, &mut shared, 0xc9, 3, true);

    // Transported bytes alone never admit: followers refuse before mutation.
    let bytes = record.encode();
    for &index in &followers {
        let owner = owners[index].as_mut().unwrap();
        let carried = AgentGenesisArchiveRecord::decode(&bytes).unwrap();
        let before = owner.ordered_index_for_test().unwrap();
        assert_eq!(
            owner.join_shared_replica(&foreign),
            Err(SharedAgentHostError::ScopeMismatch)
        );
        if !owner
            ._network_host
            .bootstrap_is_local_leader(system_agent)
            .unwrap()
        {
            assert!(owner.join_shared_replica(&carried).is_err());
        }
        let mut host = owner.host.lock().unwrap();
        assert_eq!(host.len(), 1);
        assert!(host.show(agent).unwrap().is_none());
        assert!(host.clean_genesis_is_absent(agent).unwrap());
        drop(host);
        assert_eq!(owner.ordered_index_for_test().unwrap(), before);
    }

    // Move system leadership to a non-originating member, which then admits.
    drop(shared);
    drop(owners[leader].take());
    let mut live: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live[leader].take().unwrap());
    let mut joined = None;
    assert!(
        wait_until(std::time::Duration::from_secs(60), || {
            for &index in &followers {
                let owner = owners[index].as_mut().unwrap();
                if !owner
                    ._network_host
                    .bootstrap_is_local_leader(system_agent)
                    .unwrap_or(false)
                {
                    continue;
                }
                match owner.join_shared_replica(&AgentGenesisArchiveRecord::decode(&bytes).unwrap())
                {
                    Ok(status) => {
                        joined = Some((index, status));
                        return true;
                    }
                    Err(SharedAgentHostError::Unavailable) => {}
                    Err(error) => panic!("leader replica join failed: {error:?}"),
                }
            }
            false
        }),
        "no surviving member admitted the generation"
    );
    let (index, status) = joined.unwrap();
    assert_eq!(status.replicas.len(), 3);
    let owner = owners[index].as_mut().unwrap();
    let before = owner.ordered_index_for_test().unwrap();
    assert_eq!(
        admitted(&owner.join_shared_replica(&record).unwrap()),
        admitted(&status)
    );
    assert_eq!(
        owner.ordered_index_for_test().unwrap(),
        before,
        "exact retry must not issue another Authority read"
    );
    {
        let host = owner.host.lock().unwrap();
        let position = host.journal_position(agent).unwrap();
        assert_eq!(position.genesis, origin_position.genesis);
        assert_eq!(position.admission, origin_position.admission);
        assert_eq!(host.clean_state_commitment(agent).unwrap(), origin_state);
    }
    let generations = owner.ordinary_supervisor_generations().unwrap();
    assert!(
        generations
            .iter()
            .any(|generation| generation.agent().0 == agent.0)
    );
    drop(generations);
    *networks = live.into_iter().flatten().collect();
}
