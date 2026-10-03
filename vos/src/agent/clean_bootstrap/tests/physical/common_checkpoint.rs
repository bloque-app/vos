//! Physical fixed-three system-image checkpoint/catch-up qualification.
//!
//! Voting uses authenticated peer requests. Checkpoint bytes are transferred
//! explicitly by this fixture: this is not generic Raft InstallSnapshot or
//! automatic network image discovery/transfer qualification.

use super::*;
use crate::agent::shared_commit::SharedAgentCommonSnapshotClaim;
use crate::agent::shared_host::{
    CommonCheckpointCrashStage, SharedAgentPortableBackupLimits, SharedAgentSnapshotState,
};
use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
use crate::network::agent_protocol::AgentGenerationRoute;

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_compacts_catches_up_reopens_and_continues() {
    check_fixed_system_pending_cluster_with_checkpoint(true, None, false, Some(Exercise::Healthy));
}

#[derive(Clone, Copy)]
pub(super) enum Exercise {
    Healthy,
    Crash(CommonCheckpointCrashStage),
    Recovery(RecoveryBoundary),
    ContendedIntent,
    ExpiredContendedIntent,
    SameLeaderRetry,
    OverwrittenRegistration,
    ExpiredCustody,
    ExpiredContendedCustody,
    SharedReplicaJoin,
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_shared_replica_join_admits_generation_without_originator_proof() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::SharedReplicaJoin),
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryBoundary {
    BeforeInvoke,
    AfterAcknowledgement,
    FollowerDelivery,
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_registered_projection_is_discovered_with_origin_offline_and_survives_checkpoints() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Recovery(RecoveryBoundary::BeforeInvoke)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_registered_post_ack_projection_survives_repeated_checkpoint_import_and_reopen() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Recovery(RecoveryBoundary::AfterAcknowledgement)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_registered_follower_delivery_survives_leader_reads_and_repeated_checkpoints() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Recovery(RecoveryBoundary::FollowerDelivery)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_registered_request_precedes_competing_unadmitted_wal_after_election() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::ContendedIntent),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_expired_unadmitted_intent_cannot_acquire_custody_after_election() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::ExpiredContendedIntent),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_registered_same_leader_timeout_and_duplicate_rows_survive_reopen() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::SameLeaderRetry),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_overwritten_registration_releases_remote_exclusion_without_reattachment() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::OverwrittenRegistration),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_marker_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Marker)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_journal_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Journal)),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_common_checkpoint_recovers_source_and_destination_ledger_crashes() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(Exercise::Crash(CommonCheckpointCrashStage::Ledger)),
    );
}

pub(super) fn reopen_owner(
    fixture: &PhysicalFixture,
    directory: &TestDirectory,
    stores: &(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    ),
    provider: Arc<MemoryProvider>,
    network: Arc<Network>,
    signer: &mut CountingSigner,
) -> MemoryBootstrapOwner {
    let mut pending = PendingCleanSystemAgentBootstrap::open_with_operation_admission(
        stores.0.clone(),
        stores.1.clone(),
        stores.2.clone(),
        signer,
        || panic!("checkpoint reopen must retain its durable bootstrap plan"),
        directory.host(),
        directory.lock(),
        fixture.plan.pins.space,
        fixture.plan.pins.node,
        fixture.trust.clone(),
        fixture.merge.clone(),
        fixture.finality.clone(),
        provider,
        network,
        None,
        None,
    )
    .unwrap();
    pending.try_complete(signer).unwrap().unwrap()
}

fn query(owner: &MemoryBootstrapOwner, index: usize, nonce: u8) -> AuthorityProjectionQuery {
    let key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][index]; 32]);
    let public = SigningKey::from_bytes(&[CREDENTIAL_SEED; 32])
        .verifying_key()
        .to_bytes();
    let mut query = AuthorityProjectionQuery {
        authority: owner.authority_target(),
        credential: CredentialId::of_public_key(&public),
        nonce: Hash([nonce; 32]),
        selector: AuthorityProjectionSelector::Credential,
        recovery: None,
        authentication: AuthorityIngressAuthentication::SshNodeAttestation {
            credential_public_key: public,
            node: owner.pins.node,
            request_binding: Hash([nonce.wrapping_add(1); 32]),
            signature: [1; 64],
        },
    };
    let signature = key.sign(&query.signing_bytes()).to_bytes();
    let AuthorityIngressAuthentication::SshNodeAttestation {
        signature: actual, ..
    } = &mut query.authentication
    else {
        unreachable!()
    };
    *actual = signature;
    query
}

pub(super) fn delegated_query(
    owner: &MemoryBootstrapOwner,
    index: usize,
    nonce: u8,
) -> AuthorityProjectionQuery {
    let mut query = query(owner, index, nonce);
    let agent = HostAgentId(owner.pins.agent.0);
    let mut host = owner.host.lock().unwrap();
    let attachment = host.supervisor_attachment_status(agent).unwrap().unwrap();
    let accepted_slot = host.current_logical_slot(agent).unwrap();
    drop(host);
    query.recovery = Some(
        crate::agent_sdk::authority::AuthorityProjectionRecoveryDelegation {
            generation: Hash(attachment.replication_id),
            committee: Hash(*attachment.route.committee().as_bytes()),
            accepted_slot,
            expires_at: accepted_slot
                + crate::agent_sdk::authority::MAX_AUTHORITY_PROJECTION_RECOVERY_SLOTS,
        },
    );
    let key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][index]; 32]);
    let signature = key.sign(&query.signing_bytes()).to_bytes();
    let AuthorityIngressAuthentication::SshNodeAttestation {
        signature: actual, ..
    } = &mut query.authentication
    else {
        unreachable!()
    };
    *actual = signature;
    query
}

pub(super) fn restart_network(index: usize) -> Arc<Network> {
    let keypair =
        libp2p::identity::Keypair::ed25519_from_bytes([[NODE_SEED, 0xd2, 0xd3][index]; 32])
            .unwrap();
    let peer = keypair.public().to_peer_id();
    let network = Arc::new(Network::start(NetworkConfig {
        keypair,
        local_prefix: crate::network::derive_node_prefix(&peer),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        auto_dial_mdns: false,
    }));
    assert!(wait_until(std::time::Duration::from_secs(5), || !network
        .listen_addrs()
        .is_empty()));
    network
}

/// Forced small checkpoint cycles qualify custody retention, not the full
/// replay-window capacity or service throughput. The harness transfers only
/// certified checkpoint bytes; it never supplies the lost query to a successor.
fn exercise_contended_intent(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    networks: &mut Vec<Arc<Network>>,
    expire_other: bool,
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let mut intents = Vec::new();
    for index in 0..3 {
        let owner = owners[index].as_mut().unwrap();
        let query = delegated_query(owner, index, 0xe1 + index as u8);
        let mut pending = owner.prepare_authority_projection(query).unwrap();
        owner
            .prepare_projection_recovery_registration(&mut pending)
            .unwrap();
        let (work, authorization) = pending.invocation().unwrap();
        if index == leader {
            owner
                ._network_host
                .reserve_projection_pair(agent, work, authorization, false)
                .unwrap();
        } else {
            owner
                ._network_host
                .reserve_forwarded_projection_pair(agent, work, authorization)
                .unwrap();
        }
        owner.record.pending_projection = Some(pending.clone());
        commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
        intents.push(pending);
    }
    let admitted = &intents[leader];
    owners[leader]
        .as_ref()
        .unwrap()
        .register_pending_projection(admitted)
        .unwrap();
    let (work, authorization) = admitted.invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    for index in 0..3 {
        if index == leader {
            continue;
        }
        let owner = owners[index].as_ref().unwrap();
        let before = owner.record.encode();
        assert!(owner.register_pending_projection(&intents[index]).is_err());
        assert_eq!(owner.record.encode(), before);
    }
    drop(owners[leader].take());
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live_networks[leader].take().unwrap());
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .any(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))));
    let successor = owners
        .iter()
        .position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        })
        .unwrap();
    let owner = owners[successor].as_mut().unwrap();
    let before_record = owner.record.encode();
    let before_index = owner.ordered_index_for_test().unwrap();
    owner
        .recover_registered_projection_dependency(&intents[successor])
        .unwrap();
    assert_eq!(
        owner.record.encode(),
        before_record,
        "help must not replace or clear the losing WAL"
    );
    assert_eq!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(before_record)
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_index + 2);
    assert!(
        owner
            .host
            .lock()
            .unwrap()
            .retained_positive_clean_acknowledgement(agent, &work, &authorization)
            .unwrap()
    );
    let response = owner.committed_projection_response(&work).unwrap().unwrap();
    let projection =
        crate::agent_sdk::authority::AuthorityCredentialProjection::decode(&response).unwrap();
    let AuthorityReadRequest::Projection(expected_query) = &admitted.query else {
        unreachable!()
    };
    assert_eq!(&projection.query, expected_query);
    assert!(owner.recover_pending_authority_projection().unwrap());
    assert!(owner.record.pending_projection.is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_index + 4);
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    assert!(
        manifest
            .slot(HostNodeId(fixtures[leader].plan.pins.node.0))
            .unwrap()
            .is_acknowledged()
    );
    assert!(
        manifest
            .slot(HostNodeId(fixtures[successor].plan.pins.node.0))
            .unwrap()
            .is_acknowledged()
    );
    // The other follower's rejected local intent was never custody-admitted;
    // it remains durable until that owner explicitly retries it.
    let other = (0..3)
        .find(|index| *index != leader && *index != successor)
        .unwrap();
    assert_eq!(
        owners[other]
            .as_ref()
            .unwrap()
            .record
            .pending_projection
            .as_ref(),
        Some(&intents[other])
    );
    assert!(
        manifest
            .slot(HostNodeId(fixtures[other].plan.pins.node.0))
            .is_none()
    );
    if expire_other {
        let expired_owner = owners[other].as_ref().unwrap();
        let expired_record = expired_owner.record.encode();
        let AuthorityReadRequest::Projection(expired_query) = &intents[other].query else {
            unreachable!()
        };
        for fixture in fixtures {
            fixture.logical_slot.as_ref().unwrap().store(
                expired_query.recovery.unwrap().expires_at,
                Ordering::Release,
            );
        }
        let leader_before = owners[successor]
            .as_ref()
            .unwrap()
            ._network_host
            .projection_admission_state_for_test(agent)
            .unwrap();
        assert_eq!(leader_before.0, leader_before.1);
        assert!(leader_before.2.is_none());
        // A rejected local WAL is not shared custody. Its owner must not
        // poison the leader's admission after the signed window has closed.
        assert!(
            owners[other]
                .as_mut()
                .unwrap()
                .recover_pending_authority_projection()
                .is_err()
        );
        let leader_owner = owners[successor].as_ref().unwrap();
        assert_eq!(
            leader_owner
                ._network_host
                .projection_admission_state_for_test(agent)
                .unwrap(),
            leader_before
        );
        assert_eq!(
            leader_owner
                ._network_host
                .projection_recovery_manifest(agent)
                .unwrap(),
            manifest
        );
        let expired_owner = owners[other].as_ref().unwrap();
        assert_eq!(expired_owner.record.encode(), expired_record);
        assert_eq!(
            expired_owner
                .record_store
                .clone()
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap(),
            Some(expired_record)
        );
        let fresh = delegated_query(leader_owner, successor, 0xf1);
        let sender = leader_owner.pins.node;
        assert!(
            owners[successor]
                .as_mut()
                .unwrap()
                .invoke_peer_authority_projection(fresh.clone(), false, sender)
                .is_ok()
        );
        let after = owners[successor]
            .as_ref()
            .unwrap()
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap();
        let fresh_slot = after.slot(HostNodeId(sender.0)).unwrap();
        assert_eq!(fresh_slot.registration().query(), &fresh);
        assert!(fresh_slot.is_acknowledged());
        assert!(
            after
                .slot(HostNodeId(fixtures[other].plan.pins.node.0))
                .is_none()
        );
    }
    // The enclosing fixture needs only live handles for its normal cleanup.
    *networks = live_networks.into_iter().flatten().collect();
}

fn exercise_overwritten_registration(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    networks: &[Arc<Network>],
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let origin = (leader + 1) % 3;
    let owner = owners[origin].as_mut().unwrap();
    let query = delegated_query(owner, origin, 0xf4);
    let mut pending = owner.prepare_authority_projection(query.clone()).unwrap();
    owner
        .prepare_projection_recovery_registration(&mut pending)
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    owner
        ._network_host
        .reserve_forwarded_projection_pair(agent, work, authorization)
        .unwrap();
    owner.record.pending_projection = Some(pending.clone());
    commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
    let saved_record = owner.record.encode();
    let initial = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let registration = pending
        .registration(initial.generation(), initial.committee().id())
        .unwrap()
        .unwrap();

    let original = owners[leader].as_ref().unwrap();
    let before = original
        ._network_host
        .projection_admission_state_for_test(agent)
        .unwrap();
    assert_eq!(before.0, before.1);
    assert!(before.2.is_none());
    assert!(original.record.pending_projection.is_none());
    let (route, database) = {
        let host = original.host.lock().unwrap();
        let status = host.supervisor_attachment_status(agent).unwrap().unwrap();
        (
            AgentGenerationRoute {
                space: original.pins.space,
                agent: original.pins.agent,
                generation: Hash(status.replication_id),
            },
            host.raft_database(agent).unwrap(),
        )
    };
    // Keep the actual owner, coordinator and application RPC live. Only Raft
    // traffic is cut, so the timed-out remote append really loses an election.
    original
        ._network_host
        .set_raft_isolated_for_test(agent, true)
        .unwrap();
    let reply = networks[origin]
        .send_agent_recovery_registration(original.pins.node, route, registration.clone())
        .recv_timeout(std::time::Duration::from_secs(10));
    assert!(!matches!(reply, Ok(Ok(true))));
    let attempt = original
        ._network_host
        .pending_registration_append_for_test(agent)
        .unwrap()
        .unwrap();
    assert_eq!(attempt.0, before.0 + 1);
    let uncommitted = original
        ._network_host
        .projection_admission_state_for_test(agent)
        .unwrap();
    assert_eq!(uncommitted.0, attempt.0);
    assert_eq!(uncommitted.1, before.1);
    assert!(uncommitted.2.is_some());
    let raw = crate::raft::RaftLog::open(database.clone())
        .unwrap()
        .entries(attempt.0, attempt.0)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(raw.term, attempt.1);
    let vos_raft::EntryKind::Data { payload } =
        crate::agent::shared_raft::decode_agent_raft_entry_kind(&raw.payload).unwrap()
    else {
        panic!("registration must be a real Raft data append");
    };
    let crate::agent::shared_raft::AgentRaftCommand::RegisterRecovery {
        registration: actual,
        ..
    } = crate::agent::shared_raft::AgentRaftCommand::decode(&payload).unwrap()
    else {
        panic!("timed-out row must retain the exact registration");
    };
    assert_eq!(actual, registration);

    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .enumerate()
        .any(|(index, owner)| {
            index != leader
                && owner
                    .as_ref()
                    .unwrap()
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
        })));
    for (index, owner) in owners.iter().enumerate() {
        if index != leader {
            assert_eq!(
                owner
                    .as_ref()
                    .unwrap()
                    ._network_host
                    .projection_recovery_manifest(agent)
                    .unwrap(),
                initial
            );
        }
    }
    original
        ._network_host
        .set_raft_isolated_for_test(agent, false)
        .unwrap();
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        let state = original
            ._network_host
            .projection_admission_state_for_test(agent)
            .unwrap();
        let replacement = crate::raft::RaftLog::open(database.clone())
            .unwrap()
            .entries(attempt.0, attempt.0)
            .unwrap()
            .pop();
        state.0 == state.1
            && state.1 >= attempt.0
            && replacement
                .is_some_and(|entry| entry.term > raw.term && entry.payload != raw.payload)
    }));
    assert_eq!(
        original
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        initial
    );
    // Reconciliation must release only the remote append's volatile exclusion.
    // A fresh local WAL can progress without dropping or reattaching this owner.
    let original = owners[leader].as_mut().unwrap();
    let fresh = delegated_query(original, leader, 0xf5);
    let mut fresh_pending = original
        .prepare_authority_projection(fresh.clone())
        .unwrap();
    original
        .prepare_projection_recovery_registration(&mut fresh_pending)
        .unwrap();
    let (fresh_work, fresh_auth) = fresh_pending.invocation().unwrap();
    original
        ._network_host
        .reserve_forwarded_projection_pair(agent, fresh_work, fresh_auth)
        .unwrap();
    assert!(
        original
            ._network_host
            .pending_registration_append_for_test(agent)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        original
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        initial
    );
    original.record.pending_projection = Some(fresh_pending);
    commit_bootstrap_record(&mut original.record_store, &original.record).unwrap();

    let owner = owners[origin].as_mut().unwrap();
    assert_eq!(owner.record.encode(), saved_record);
    assert_eq!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(saved_record)
    );
    let before_ordered = owner.ordered_index_for_test().unwrap();
    // This harness has authenticated registration RPCs and real Raft traffic,
    // but no node-loop ProjectionRequest dispatcher. Use the actual elected
    // owner's peer handler, first resolving the original still-durable WAL.
    // The overwritten leader's exclusion has already been proved released.
    for (index, request) in [(origin, query), (leader, fresh)] {
        let sender = fixtures[index].plan.pins.node;
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            match owners[index].as_ref().unwrap().register_pending_projection(
                owners[index]
                    .as_ref()
                    .unwrap()
                    .record
                    .pending_projection
                    .as_ref()
                    .unwrap(),
            ) {
                Ok(()) => true,
                Err(SharedAgentHostError::Unavailable) => false,
                Err(error) => panic!("exact origin registration failed: {error:?}"),
            }
        }));
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            let Some(current) = owners.iter().position(|owner| {
                owner
                    .as_ref()
                    .unwrap()
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            }) else {
                return false;
            };
            match owners[current]
                .as_mut()
                .unwrap()
                .invoke_peer_authority_projection(request.clone(), false, sender)
            {
                Ok(response) => {
                    let projection =
                        crate::agent_sdk::authority::AuthorityCredentialProjection::decode(
                            &response,
                        )
                        .unwrap();
                    assert_eq!(projection.query, request);
                    true
                }
                Err(SharedAgentHostError::Unavailable) => false,
                Err(error) => panic!("exact peer query failed: {error:?}"),
            }
        }));
        let owner = owners[index].as_mut().unwrap();
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            match owner.recover_pending_authority_projection() {
                Ok(_) => true,
                Err(SharedAgentHostError::Unavailable) => false,
                Err(error) => panic!("exact origin cleanup failed: {error:?}"),
            }
        }));
        assert!(owner.record.pending_projection.is_none());
        assert_eq!(
            owner.ordered_index_for_test().unwrap(),
            before_ordered + if index == origin { 2 } else { 4 }
        );
    }
    let final_manifest = owners[leader]
        .as_ref()
        .unwrap()
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    for index in [leader, origin] {
        assert!(
            final_manifest
                .slot(HostNodeId(fixtures[index].plan.pins.node.0))
                .unwrap()
                .is_acknowledged()
        );
    }
}

fn exercise_same_leader_retry(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let slow = (leader + 1) % 3;
    let offline = (leader + 2) % 3;
    let owner = owners[leader].as_mut().unwrap();
    let request = delegated_query(owner, leader, 0xf2);
    let mut pending = owner.prepare_authority_projection(request).unwrap();
    owner
        .prepare_projection_recovery_registration(&mut pending)
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    owner
        ._network_host
        .reserve_projection_pair(agent, &work, &authorization, false)
        .unwrap();
    owner.record.pending_projection = Some(pending.clone());
    commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
    owner.register_pending_projection(&pending).unwrap();
    let initial = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let holder = HostNodeId(owner.pins.node.0);
    let identity = owner
        .pending_authority_projection_identity(&pending, true)
        .unwrap();
    let saved_record = owner.record.encode();
    let before_ordered = owner.ordered_index_for_test().unwrap();
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(30), || owner
            ._network_host
            .projection_recovery_manifest(agent)
            .is_ok_and(|manifest| manifest == initial)));
    }
    drop(owners[offline].take());
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live_networks[offline].take().unwrap());
    let slow_database = owners[slow]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .raft_database(agent)
        .unwrap();
    let mut canonical_invoke = None;
    for acknowledgement in [false, true] {
        let owner = owners[leader].as_mut().unwrap();
        let before = owner
            ._network_host
            .projection_admission_state_for_test(agent)
            .unwrap();
        assert_eq!(before.0, before.1);
        assert!(before.2.is_some());
        // Hold the real follower database writer, not a fake reply. With the
        // other voter offline, the first command cannot commit before its
        // response waiter expires. The blocked follower cannot start elections.
        let blocked_writer = slow_database.begin_write().unwrap();
        let started = std::time::Instant::now();
        let timed_out = if acknowledgement {
            owner.supervisor_acknowledge_reserved(identity, work.clone(), authorization.clone())
        } else {
            owner.supervisor_invoke_terminal_reserved(identity, work.clone(), authorization.clone())
        };
        assert!(timed_out.is_err());
        assert!(started.elapsed() >= std::time::Duration::from_millis(1_800));
        // Bootstrap readiness is deliberately false while this prefix is
        // uncommitted. The repeated-input append below independently requires the same
        // worker to remain the actual Raft leader, not merely route-ready.
        let uncommitted = owner
            ._network_host
            .projection_admission_state_for_test(agent)
            .unwrap();
        assert_eq!(uncommitted.0, before.0 + 1);
        assert_eq!(uncommitted.1, before.1);
        assert_eq!(uncommitted.2, before.2);
        // Reusing the key must recheck the raw prefix; so must submission by
        // a caller that already took its reservation before the timed-out call.
        assert!(
            owner
                ._network_host
                .reserve_projection_pair(agent, &work, &authorization, true,)
                .is_err()
        );
        let retry = if acknowledgement {
            owner.supervisor_acknowledge_reserved(identity, work.clone(), authorization.clone())
        } else {
            owner.supervisor_invoke_terminal_reserved(identity, work.clone(), authorization.clone())
        };
        assert!(retry.is_err());
        assert_eq!(
            owner
                ._network_host
                .projection_admission_state_for_test(agent)
                .unwrap(),
            uncommitted
        );
        assert_eq!(owner.record.encode(), saved_record);
        assert_eq!(
            owner
                .record_store
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap(),
            Some(saved_record.clone())
        );
        drop(blocked_writer);
        for owner in owners.iter().flatten() {
            assert!(wait_until(std::time::Duration::from_secs(30), || {
                owner
                    .host
                    .lock()
                    .unwrap()
                    .capacity(agent)
                    .is_ok_and(|capacity| capacity.0 >= before.0 + 1)
            }));
        }
        // Admission now prevents an append while the original is uncommitted.
        // Independently qualify committed replay of the same input at a new
        // valid Ordered position. Reassigning the original immutable Ordered
        // entry to another Raft index would violate its publication binding,
        // rather than represent a runtime retry.
        let duplicate_index = owners[leader]
            .as_ref()
            .unwrap()
            ._network_host
            .append_repeated_projection_for_test(agent, &work, &authorization, acknowledgement)
            .unwrap();
        assert_eq!(duplicate_index, before.0 + 2);
        for owner in owners.iter().flatten() {
            assert!(wait_until(std::time::Duration::from_secs(30), || {
                owner
                    ._network_host
                    .projection_recovery_manifest(agent)
                    .is_ok_and(|manifest| {
                        owner
                            .host
                            .lock()
                            .unwrap()
                            .capacity(agent)
                            .is_ok_and(|capacity| capacity.0 >= duplicate_index)
                            && manifest.slot(holder).is_some_and(|slot| {
                                slot.invoke().is_some() && slot.is_acknowledged() == acknowledgement
                            })
                    })
            }));
            let manifest = owner
                ._network_host
                .projection_recovery_manifest(agent)
                .unwrap();
            let slot = manifest.slot(holder).unwrap();
            let evidence = if acknowledgement {
                slot.acknowledgement()
            } else {
                slot.invoke()
            }
            .unwrap();
            assert_eq!(
                evidence.raft_index(),
                before.0 + 1,
                "custody must retain the first physical observation"
            );
            if acknowledgement {
                assert_eq!(slot.invoke(), canonical_invoke.as_ref());
            }
        }
        if !acknowledgement {
            canonical_invoke = owners[leader]
                .as_ref()
                .unwrap()
                ._network_host
                .projection_recovery_manifest(agent)
                .unwrap()
                .slot(holder)
                .unwrap()
                .invoke()
                .cloned();
        }
    }
    drop(slow_database);
    let owner = owners[leader].as_mut().unwrap();
    let final_duplicate_index = owner
        ._network_host
        .projection_admission_state_for_test(agent)
        .unwrap()
        .0;
    let expected = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let response = owner.committed_projection_response(&work).unwrap().unwrap();
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered + 4);
    assert!(owner.recover_pending_authority_projection().unwrap());
    assert!(owner.record.pending_projection.is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered + 4);
    live_networks[offline] = Some(restart_network(offline));
    for index in 0..3 {
        if index != offline {
            live_networks[offline]
                .as_ref()
                .unwrap()
                .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
        }
    }
    owners[offline] = Some(reopen_owner(
        &fixtures[offline],
        &directories[offline],
        &stores[offline],
        providers[offline].clone(),
        live_networks[offline].as_ref().unwrap().clone(),
        signer,
    ));
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(30), || owner
            ._network_host
            .projection_recovery_manifest(agent)
            .is_ok_and(|manifest| manifest == expected
                && owner.host.lock().unwrap().capacity(agent).is_ok_and(
                    |capacity| capacity.0 >= final_duplicate_index
                ))));
        assert_eq!(
            owner.committed_projection_response(&work).unwrap(),
            Some(response.clone())
        );
    }
    // Reopening both original active owners must reproduce first-position
    // evidence even though their latest applied rows were duplicate copies.
    for index in [slow, leader] {
        drop(owners[index].take());
        owners[index] = Some(reopen_owner(
            &fixtures[index],
            &directories[index],
            &stores[index],
            providers[index].clone(),
            live_networks[index].as_ref().unwrap().clone(),
            signer,
        ));
        let owner = owners[index].as_ref().unwrap();
        assert_eq!(
            owner
                ._network_host
                .projection_recovery_manifest(agent)
                .unwrap(),
            expected
        );
        assert!(owner.host.lock().unwrap().capacity(agent).unwrap().0 >= final_duplicate_index);
        assert_eq!(
            owner.committed_projection_response(&work).unwrap(),
            Some(response.clone())
        );
    }
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}

fn exercise_registered_recovery(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
    boundary: RecoveryBoundary,
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let origin = if boundary == RecoveryBoundary::FollowerDelivery {
        (leader + 1) % 3
    } else {
        leader
    };
    let owner = owners[origin].as_mut().unwrap();
    let request = delegated_query(owner, origin, 0xc1);
    let mut pending = owner.prepare_authority_projection(request.clone()).unwrap();
    owner
        .prepare_projection_recovery_registration(&mut pending)
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    if origin == leader {
        owner
            ._network_host
            .reserve_projection_pair(agent, &work, &authorization, false)
            .unwrap();
    } else {
        owner
            ._network_host
            .reserve_forwarded_projection_pair(agent, &work, &authorization)
            .unwrap();
    }
    owner.record.pending_projection = Some(pending.clone());
    commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
    // Until this succeeds PAP2 is a local WAL attempt, not a recoverably
    // admitted request. No survivor is expected to discover that earlier cut.
    owner.register_pending_projection(&pending).unwrap();
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let registration = pending
        .registration(manifest.generation(), manifest.committee().id())
        .unwrap()
        .unwrap();
    assert_eq!(
        manifest.slot(registration.owner()).unwrap().registration(),
        &registration
    );
    let mut expected_response = None;
    if boundary == RecoveryBoundary::AfterAcknowledgement {
        let identity = owner
            .pending_authority_projection_identity(&pending, true)
            .unwrap();
        let outcome = owner
            .supervisor_invoke_terminal_reserved(identity, work.clone(), authorization.clone())
            .unwrap();
        let RuntimeOutcome::Completed(Ok(reply)) = outcome else {
            panic!("registered Query must complete")
        };
        let Some(crate::actors::value::Value::Bytes(response)) =
            crate::actors::value::Value::try_decode(&reply.reply)
        else {
            panic!("projection bytes")
        };
        expected_response = Some(response);
        let outcome = owner
            .supervisor_acknowledge_reserved(identity, work.clone(), authorization.clone())
            .unwrap();
        let RuntimeOutcome::Acknowledged(Ok(ack)) = outcome else {
            panic!("positive exact ACK required")
        };
        assert_eq!(ack.invocation, work.invocation);
        assert_eq!(ack.work, work.commitment());
        assert_eq!(ack.authorization, authorization.commitment());
    } else if boundary == RecoveryBoundary::FollowerDelivery {
        // The forwarding node keeps its own durable delivery obligation even
        // when a different lifecycle owner executes and retires the result.
        expected_response = Some(
            owners[leader]
                .as_mut()
                .unwrap()
                .invoke_peer_authority_projection(
                    request.clone(),
                    false,
                    fixtures[origin].plan.pins.node,
                )
                .unwrap(),
        );
    }
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            owner
                ._network_host
                .projection_recovery_manifest(agent)
                .is_ok_and(|manifest| {
                    manifest.slot(registration.owner()).is_some_and(|slot| {
                        slot.registration() == &registration
                            && slot.is_acknowledged()
                                == (boundary != RecoveryBoundary::BeforeInvoke)
                    })
                })
        }));
    }
    let offline_host = owners[origin].as_ref().unwrap().host.clone();
    let saved_record = owners[origin].as_ref().unwrap().record.encode();
    drop(owners[origin].take());
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live_networks[origin].take().unwrap());
    let offline_peer =
        libp2p::identity::Keypair::ed25519_from_bytes([[NODE_SEED, 0xd2, 0xd3][origin]; 32])
            .unwrap()
            .public()
            .to_peer_id();
    assert!(wait_until(std::time::Duration::from_secs(10), || {
        live_networks
            .iter()
            .flatten()
            .all(|network| !network.connected_peers().contains(&offline_peer))
    }));
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .any(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))));
    let mut successor = owners
        .iter()
        .position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        })
        .unwrap();
    if boundary == RecoveryBoundary::BeforeInvoke {
        assert!(
            owners[successor]
                .as_ref()
                .unwrap()
                .record
                .pending_projection
                .is_none()
        );
        // Discovery consumes the committed manifest, not a harness-supplied
        // original query or a request reconstructed at today's clock.
        let mut last_error = None;
        assert!(
            wait_until(std::time::Duration::from_secs(30), || {
                let Some(current) = owners.iter().position(|owner| {
                    owner.as_ref().is_some_and(|owner| {
                        owner
                            ._network_host
                            .bootstrap_is_local_leader(agent)
                            .unwrap_or(false)
                    })
                }) else {
                    return false;
                };
                successor = current;
                let owner = owners[current].as_mut().unwrap();
                let recovered = owner.recover_pending_authority_projection();
                if let Err(error) = &recovered {
                    let message = format!(
                        "{error:?}; pending={:?}",
                        owner.record.pending_projection.as_ref().map(|pending| (
                            &pending.query,
                            pending.recovery_registration.is_some()
                        ))
                    );
                    if last_error.as_ref() != Some(&message) {
                        eprintln!("registered recovery: {message}");
                    }
                    last_error = Some(message);
                }
                recovered.is_ok()
                    && owner
                        ._network_host
                        .projection_recovery_manifest(agent)
                        .is_ok_and(|manifest| {
                            manifest
                                .slot(registration.owner())
                                .is_some_and(|slot| slot.is_acknowledged())
                        })
            }),
            "registered recovery failed: {last_error:?}"
        );
        expected_response = owners[successor]
            .as_ref()
            .unwrap()
            .committed_projection_response(&work)
            .unwrap();
    }
    for owner in owners.iter_mut().flatten() {
        if owner.record.pending_projection.is_some() {
            assert!(wait_until(std::time::Duration::from_secs(30), || owner
                .recover_pending_authority_projection()
                .is_ok()));
            assert!(owner.record.pending_projection.is_none());
        }
    }
    let expected_response = expected_response.unwrap();
    let archived = owners[successor]
        .as_ref()
        .unwrap()
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap()
        .slot(registration.owner())
        .unwrap()
        .clone();
    assert!(archived.is_acknowledged());
    assert_eq!(archived.registration(), &registration);
    // An archived result remains recoverable after the original execution
    // delegation has expired; it does not reauthorize a new execution.
    let expired = request.recovery.unwrap().expires_at;
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .store(expired, Ordering::Release);
    }
    let limits = SharedAgentPortableBackupLimits {
        max_objects: 4096,
        max_blobs: 4096,
        max_index_nodes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let crash = match boundary {
        RecoveryBoundary::BeforeInvoke => CommonCheckpointCrashStage::Marker,
        RecoveryBoundary::AfterAcknowledgement => CommonCheckpointCrashStage::Journal,
        RecoveryBoundary::FollowerDelivery => CommonCheckpointCrashStage::Ledger,
    };
    for cycle in 0..3u8 {
        let owner = owners[successor].as_ref().unwrap();
        let next_query = delegated_query(owner, successor, 0xc3 + cycle * 2);
        let sender = owner.pins.node;
        let mut last_error = None;
        assert!(
            wait_until(std::time::Duration::from_secs(30), || {
                let Some(current) = owners.iter().position(|owner| {
                    owner.as_ref().is_some_and(|owner| {
                        owner
                            ._network_host
                            .bootstrap_is_local_leader(agent)
                            .unwrap_or(false)
                    })
                }) else {
                    return false;
                };
                successor = current;
                match owners[current]
                    .as_mut()
                    .unwrap()
                    .invoke_peer_authority_projection(next_query.clone(), false, sender)
                {
                    Ok(_) => true,
                    Err(error) => {
                        last_error = Some(error);
                        false
                    }
                }
            }),
            "exact next query did not complete: {last_error:?}"
        );
        for owner in owners.iter_mut().flatten() {
            if owner.record.pending_projection.is_some() {
                assert!(wait_until(std::time::Duration::from_secs(30), || owner
                    .recover_pending_authority_projection()
                    .is_ok()));
                assert!(owner.record.pending_projection.is_none());
            }
        }
        // Pending-owner cleanup and the previous checkpoint's reopen can
        // complete across an election. Choose the current leader at this
        // boundary, not the node that happened to finish the preceding read.
        // The checkpoint itself is still attempted exactly once.
        assert!(wait_until(std::time::Duration::from_secs(30), || {
            let Some(current) = owners.iter().position(|owner| {
                owner.as_ref().is_some_and(|owner| {
                    owner
                        ._network_host
                        .bootstrap_is_local_leader(agent)
                        .unwrap_or(false)
                })
            }) else {
                return false;
            };
            successor = current;
            true
        }));
        let owner = owners[successor].as_mut().unwrap();
        let checkpoint = owner
            .prepare_authority_projection(query(owner, successor, 0xd1 + cycle))
            .unwrap();
        let (checkpoint_work, checkpoint_auth) = checkpoint.invocation().unwrap();
        let committee = owner.pins.replicas.clone();
        if cycle == 0 {
            owner
                .host
                .lock()
                .unwrap()
                .set_common_checkpoint_crash_for_test(crash);
        }
        let installed = owner
            ._network_host
            .certified_common_checkpoint_for_admission(
                agent,
                checkpoint_work,
                checkpoint_auth,
                &committee,
                fixtures[successor].merge.as_ref(),
            );
        if cycle == 0 {
            assert!(
                installed.is_err(),
                "source nonempty capsule checkpoint must hit {crash:?}"
            );
            assert!(owner.host.lock().unwrap().show(agent).unwrap().is_none());
            drop(owners[successor].take());
            owners[successor] = Some(reopen_owner(
                &fixtures[successor],
                &directories[successor],
                &stores[successor],
                providers[successor].clone(),
                live_networks[successor].as_ref().unwrap().clone(),
                signer,
            ));
        } else {
            if let Err(error) = &installed {
                eprintln!(
                    "checkpoint_cycle_failure cycle={cycle} selected={successor} error={error:?}"
                );
                for (index, owner) in owners
                    .iter()
                    .enumerate()
                    .filter_map(|(index, owner)| owner.as_ref().map(|owner| (index, owner)))
                {
                    eprintln!(
                        "checkpoint_voter index={index} leader={:?}",
                        owner._network_host.bootstrap_is_local_leader(agent)
                    );
                    let mut host = owner.host.lock().unwrap();
                    match host.request_common_snapshot_compaction(agent) {
                        Ok(candidate) => {
                            let manifest = host.recovery_manifest(agent).unwrap();
                            crate::network::shared_agent::trace_common_checkpoint_material_for_test(
                                "fixture_failure",
                                HostNodeId(owner.pins.node.0),
                                candidate.claim(),
                                &manifest,
                            );
                        }
                        Err(error) => {
                            eprintln!("checkpoint_voter index={index} candidate_error={error:?}")
                        }
                    }
                }
            }
            installed.unwrap();
        }
        let owner = owners[successor].as_mut().unwrap();
        let bytes = owner
            .host
            .lock()
            .unwrap()
            .export_common_checkpoint(agent, limits)
            .unwrap();
        let source_manifest = owner
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap();
        assert_eq!(source_manifest.slot(registration.owner()), Some(&archived));
        assert_eq!(
            owner.committed_projection_response(&work).unwrap(),
            Some(expected_response.clone())
        );
        let mut destination = offline_host.lock().unwrap();
        if cycle == 2 {
            destination.set_common_checkpoint_crash_for_test(crash);
        }
        let imported = destination.restore_common_checkpoint(&bytes, limits);
        if cycle == 2 {
            assert!(
                imported.is_err(),
                "destination nonempty capsule import must hit {crash:?}"
            );
            assert!(destination.show(agent).unwrap().is_none());
        } else {
            imported.unwrap();
            assert_eq!(
                destination.recovery_manifest(agent).unwrap(),
                source_manifest
            );
            assert!(
                destination
                    .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                    .unwrap()
            );
        }
        assert_eq!(
            stores[origin]
                .1
                .clone()
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap(),
            Some(saved_record.clone())
        );
        drop(destination);
        assert!(wait_until(std::time::Duration::from_secs(30), || owners
            .iter()
            .flatten()
            .any(|owner| owner
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false))));
        successor = owners
            .iter()
            .position(|owner| {
                owner.as_ref().is_some_and(|owner| {
                    owner
                        ._network_host
                        .bootstrap_is_local_leader(agent)
                        .unwrap_or(false)
                })
            })
            .unwrap();
    }
    drop(offline_host);
    // Complete the interrupted destination journal/ledger import without
    // opening its bootstrap lifecycle or network. This captures the exact
    // restored Ordered cursor before startup is allowed to retire its PAP.
    let restored = SharedAgentHost::open_with_root(
        directories[origin].host(),
        directories[origin].lock(),
        AgentHostScope {
            space: HostSpaceId(fixtures[origin].plan.pins.space.0),
            node: HostNodeId(fixtures[origin].plan.pins.node.0),
        },
        fixtures[origin].trust.clone(),
        fixtures[origin].merge.clone(),
        fixtures[origin].finality.clone(),
        fixtures[origin].plan.pins.root.clone(),
    )
    .unwrap();
    let restored_ordered = restored.journal_position(agent).unwrap().ordered_index;
    drop(restored);
    assert!(
        stores[origin]
            .1
            .clone()
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap()
            .as_deref()
            == Some(saved_record.as_slice()),
        "detached import must preserve the exact signed pending record"
    );
    live_networks[origin] = Some(restart_network(origin));
    for index in 0..3 {
        if index != origin {
            live_networks[origin]
                .as_ref()
                .unwrap()
                .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
        }
    }
    owners[origin] = Some(reopen_owner(
        &fixtures[origin],
        &directories[origin],
        &stores[origin],
        providers[origin].clone(),
        live_networks[origin].as_ref().unwrap().clone(),
        signer,
    ));
    let owner = owners[origin].as_mut().unwrap();
    // Startup proves the retained positive ACK and durably clears PAP before
    // attaching the route. It must not leave the already-completed PAP live,
    // replace any other bootstrap field, or execute another Ordered entry.
    let mut cleared_record = CleanSystemAgentBootstrapRecord::decode(&saved_record).unwrap();
    cleared_record.pending_projection = None;
    assert!(owner.record == cleared_record);
    assert!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap()
            .as_deref()
            == Some(cleared_record.encode().as_slice()),
        "startup must durably retire only the completed pending record"
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), restored_ordered);
    assert_eq!(
        owner.committed_projection_response(&work).unwrap(),
        Some(expected_response.clone())
    );
    assert!(!owner.recover_pending_authority_projection().unwrap());
    assert!(owner.record.pending_projection.is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), restored_ordered);
    assert_eq!(
        owner.committed_projection_response(&work).unwrap(),
        Some(expected_response)
    );
    assert_eq!(
        owner
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap()
            .slot(registration.owner()),
        Some(&archived)
    );
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}

pub(super) fn exercise(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
    exercise: Exercise,
) {
    if let Exercise::ExpiredContendedCustody = exercise {
        super::recovery_expiry::exercise_contended(leader, owners, fixtures, networks);
        return;
    }
    if let Exercise::ExpiredCustody = exercise {
        super::recovery_expiry::exercise(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
        );
        return;
    }
    if let Exercise::SharedReplicaJoin = exercise {
        super::shared_replica::exercise(leader, owners, fixtures, networks);
        return;
    }
    if let Exercise::OverwrittenRegistration = exercise {
        exercise_overwritten_registration(leader, owners, fixtures, networks);
        return;
    }
    if let Exercise::SameLeaderRetry = exercise {
        exercise_same_leader_retry(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
        );
        return;
    }
    if matches!(
        exercise,
        Exercise::ContendedIntent | Exercise::ExpiredContendedIntent
    ) {
        exercise_contended_intent(
            leader,
            owners,
            fixtures,
            networks,
            matches!(exercise, Exercise::ExpiredContendedIntent),
        );
        return;
    }
    if let Exercise::Recovery(boundary) = exercise {
        exercise_registered_recovery(
            leader,
            owners,
            fixtures,
            directories,
            stores,
            providers,
            networks,
            signer,
            boundary,
        );
        return;
    }
    let crash = match exercise {
        Exercise::Healthy => None,
        Exercise::Crash(stage) => Some(stage),
        Exercise::Recovery(_) => unreachable!(),
        Exercise::ContendedIntent => unreachable!(),
        Exercise::ExpiredContendedIntent => unreachable!(),
        Exercise::SameLeaderRetry => unreachable!(),
        Exercise::OverwrittenRegistration => unreachable!(),
        Exercise::ExpiredCustody => unreachable!(),
        Exercise::ExpiredContendedCustody => unreachable!(),
        Exercise::SharedReplicaJoin => unreachable!(),
    };
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let lagger = (leader + 1) % 3;
    let voter = (leader + 2) % 3;
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    let lagging_host = Arc::clone(&owners[lagger].as_ref().unwrap().host);
    let lagging_position = lagging_host
        .lock()
        .unwrap()
        .journal_position(agent)
        .unwrap();
    drop(owners[lagger].take());
    stop_network(live_networks[lagger].take().unwrap());

    let source = owners[leader].as_mut().unwrap();
    assert!(wait_until(std::time::Duration::from_secs(15), || source
        ._network_host
        .bootstrap_is_local_leader(agent)
        .unwrap_or(false)));
    let older_query = query(source, leader, 0xaf);
    let older_pending = source
        .prepare_authority_projection(older_query.clone())
        .unwrap();
    let (older_work, older_auth) = older_pending.invocation().unwrap();
    let older_input = source
        .host
        .lock()
        .unwrap()
        .prepare_clean_ordered_operation(
            agent,
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work: older_work.clone(),
                authorization: older_auth.clone(),
            },
        )
        .unwrap()
        .input();
    source.invoke_authority_projection(older_query).unwrap();
    let request = query(source, leader, 0xb1);
    let pending = source
        .prepare_authority_projection(request.clone())
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    // A public caller may lose its result before ACK. Keep that exact live
    // result at the checkpoint boundary; do not fabricate unresolved PAP2.
    let identity = source
        .pending_authority_projection_identity(&pending, false)
        .unwrap();
    let invoked = source
        .supervisor_invoke(identity, work.clone(), authorization.clone())
        .unwrap();
    let RuntimeOutcome::Completed(Ok(reply)) = &invoked else {
        panic!("boundary Query must complete: {invoked:?}");
    };
    let Some(crate::actors::value::Value::Bytes(response)) =
        crate::actors::value::Value::try_decode(&reply.reply)
    else {
        panic!("boundary Query must return projection bytes");
    };
    let projection =
        crate::agent::sdk::authority::AuthorityCredentialProjection::decode(&response).unwrap();
    assert_eq!(projection.query, request);
    assert_ne!(projection.principal, PrincipalId::ZERO);
    assert!(source.record.pending_projection.is_none());
    let source_state = source
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let boundary_input = source
        .host
        .lock()
        .unwrap()
        .prepare_clean_ordered_operation(
            agent,
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work: work.clone(),
                authorization: authorization.clone(),
            },
        )
        .unwrap()
        .input();
    assert!(source.ordered_index_for_test().unwrap() > lagging_position.ordered_index);
    assert_eq!(
        lagging_host
            .lock()
            .unwrap()
            .journal_position(agent)
            .unwrap(),
        lagging_position
    );
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        [voter]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap()
        == source_state));

    let source = owners[leader].as_mut().unwrap();
    let (candidate, route, old_snapshot, position) = {
        let mut host = source.host.lock().unwrap();
        let candidate = host.request_common_snapshot_compaction(agent).unwrap();
        let status = host.supervisor_attachment_status(agent).unwrap().unwrap();
        let route = AgentGenerationRoute {
            space: source.pins.space,
            agent: source.pins.agent,
            generation: Hash(status.replication_id),
        };
        (
            candidate,
            route,
            host.snapshot_state_for_test(agent).unwrap(),
            host.journal_position(agent).unwrap(),
        )
    };
    let wrong_epoch = SharedAgentCommonSnapshotClaim::new(
        candidate.claim().ordered().clone(),
        candidate.claim().active_committee().clone(),
        candidate.claim().authority_epoch() + 1,
        candidate.claim().ancestry().clone(),
    )
    .unwrap();
    let outsider = crate::agent::local_journal_driver::Ed25519NodeMergeAuthenticator::new(
        libp2p::identity::Keypair::ed25519_from_bytes([0xee; 32]).unwrap(),
    )
    .unwrap();
    assert!(
        outsider
            .sign_common_snapshot_candidate(&candidate)
            .is_none()
    );
    assert_eq!(
        live_networks[leader]
            .as_ref()
            .unwrap()
            .send_agent_common_snapshot_vote(fixtures[voter].plan.pins.node, route, wrong_epoch)
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap()
            .unwrap(),
        None
    );
    let remote = live_networks[leader]
        .as_ref()
        .unwrap()
        .send_agent_common_snapshot_vote(
            fixtures[voter].plan.pins.node,
            route,
            candidate.claim().clone(),
        )
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(remote.signer().0, fixtures[voter].plan.pins.node.0);
    assert_eq!(
        source.host.lock().unwrap().journal_position(agent).unwrap(),
        position
    );
    assert_eq!(
        source
            .host
            .lock()
            .unwrap()
            .snapshot_state_for_test(agent)
            .unwrap(),
        old_snapshot
    );

    let checkpoint_pending = source
        .prepare_authority_projection(query(source, leader, 0xb3))
        .unwrap();
    let (checkpoint_work, checkpoint_auth) = checkpoint_pending.invocation().unwrap();
    let committee = source.pins.replicas.clone();
    assert_eq!(
        source
            ._network_host
            .certified_common_checkpoint_for_admission(
                agent,
                checkpoint_work,
                checkpoint_auth,
                &committee,
                &RefusingSnapshotSigner(HostNodeId(source.pins.node.0)),
            ),
        Err(SharedAgentHostError::SnapshotCertificateInvalid)
    );
    assert_eq!(
        source.host.lock().unwrap().journal_position(agent).unwrap(),
        position
    );
    assert_eq!(
        source
            .host
            .lock()
            .unwrap()
            .snapshot_state_for_test(agent)
            .unwrap(),
        old_snapshot
    );
    if let Some(stage) = crash {
        source
            .host
            .lock()
            .unwrap()
            .set_common_checkpoint_crash_for_test(stage);
    }
    let installed_result = source
        ._network_host
        .certified_common_checkpoint_for_admission(
            agent,
            checkpoint_work,
            checkpoint_auth,
            &committee,
            fixtures[leader].merge.as_ref(),
        );
    let certificate = if crash.is_some() {
        assert!(
            installed_result.is_err(),
            "injected local checkpoint boundary must interrupt"
        );
        assert!(source.host.lock().unwrap().show(agent).unwrap().is_none());
        drop(owners[leader].take());
        owners[leader] = Some(reopen_owner(
            &fixtures[leader],
            &directories[leader],
            &stores[leader],
            providers[leader].clone(),
            live_networks[leader].as_ref().unwrap().clone(),
            signer,
        ));
        owners[leader]
            .as_ref()
            .unwrap()
            .host
            .lock()
            .unwrap()
            .common_snapshot_certificate_for_test(agent)
            .unwrap()
            .unwrap()
    } else {
        installed_result.unwrap()
    };
    let source = owners[leader].as_mut().unwrap();
    certificate.verify(&committee, candidate.claim()).unwrap();
    assert_eq!(certificate.signatures().len(), 2);
    assert!(
        certificate
            .signatures()
            .iter()
            .all(|signature| signature.signer().0 != fixtures[lagger].plan.pins.node.0)
    );
    let limits = SharedAgentPortableBackupLimits {
        max_objects: 4096,
        max_blobs: 4096,
        max_index_nodes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let (bytes, installed, source_store) = {
        let mut host = source.host.lock().unwrap();
        assert_eq!(host.clean_state_commitment(agent).unwrap(), source_state);
        let installed = host.snapshot_state_for_test(agent).unwrap();
        assert_ne!(installed, old_snapshot);
        (
            host.export_common_checkpoint(agent, limits).unwrap(),
            installed,
            host.journal_store_instance_for_test(agent).unwrap(),
        )
    };
    assert!(matches!(
        installed,
        SharedAgentSnapshotState::Installed { .. }
    ));
    for index in [leader, voter] {
        let mut host = owners[index].as_ref().unwrap().host.lock().unwrap();
        let boundary = candidate.claim().ordered();
        host.verify_ordered_availability(
            agent,
            boundary.raft_index(),
            boundary.raft_term(),
            boundary.commitment(),
        )
        .unwrap();
        if index == leader {
            assert!(host.available_ordered_claim(agent, older_input).is_err());
        }
    }
    // The third replica remains detached and disconnected throughout import;
    // the live donor cannot silently fill its raw log behind this assertion.
    {
        let mut destination = lagging_host.lock().unwrap();
        let before = destination.show(agent).unwrap().unwrap();
        let mut changed = bytes.clone();
        let offset = changed.len() / 2;
        changed[offset] ^= 0x80;
        assert!(
            destination
                .restore_common_checkpoint(&changed, limits)
                .is_err()
        );
        assert_eq!(destination.show(agent).unwrap().unwrap(), before);
        assert_eq!(
            destination.journal_position(agent).unwrap(),
            lagging_position
        );
        if let Some(stage) = crash {
            destination.set_common_checkpoint_crash_for_test(stage);
        }
        let imported_result = destination.restore_common_checkpoint(&bytes, limits);
        if crash.is_some() {
            assert!(
                imported_result.is_err(),
                "injected import boundary must interrupt"
            );
            assert!(destination.show(agent).unwrap().is_none());
        } else {
            imported_result.unwrap();
            assert_eq!(
                destination.clean_state_commitment(agent).unwrap(),
                source_state
            );
            assert_eq!(destination.journal_position(agent).unwrap(), position);
            assert_ne!(
                destination.journal_store_instance_for_test(agent).unwrap(),
                source_store
            );
            assert!(
                destination
                    .retained_terminal_projection_invoke(agent, &work, &authorization)
                    .unwrap()
            );
            assert!(
                !destination
                    .retained_positive_clean_acknowledgement(agent, &work, &authorization)
                    .unwrap()
            );
            assert!(
                destination
                    .available_ordered_claim(agent, older_input)
                    .is_err()
            );
            let imported = destination.show(agent).unwrap().unwrap();
            assert_eq!(
                destination
                    .restore_common_checkpoint(&bytes, limits)
                    .unwrap(),
                imported
            );
            assert_eq!(destination.show(agent).unwrap().unwrap(), imported);
        }
    }
    drop(lagging_host);

    live_networks[lagger] = Some(restart_network(lagger));
    for index in [leader, voter] {
        live_networks[lagger]
            .as_ref()
            .unwrap()
            .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
    }
    let reopen = |index: usize, signer: &mut CountingSigner| {
        reopen_owner(
            &fixtures[index],
            &directories[index],
            &stores[index],
            providers[index].clone(),
            live_networks[index].as_ref().unwrap().clone(),
            signer,
        )
    };
    owners[lagger] = Some(reopen(lagger, signer));
    {
        let mut host = owners[lagger].as_ref().unwrap().host.lock().unwrap();
        assert_eq!(host.journal_position(agent).unwrap(), position);
        assert_eq!(host.clean_state_commitment(agent).unwrap(), source_state);
        assert_ne!(
            host.journal_store_instance_for_test(agent).unwrap(),
            source_store
        );
        assert_eq!(
            host.common_snapshot_certificate_for_test(agent).unwrap(),
            Some(certificate.clone())
        );
        assert!(host.available_ordered_claim(agent, older_input).is_err());
    }
    drop(owners[leader].take());
    owners[leader] = Some(reopen(leader, signer));
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        live_networks
            .iter()
            .flatten()
            .all(|network| network.connected_peers().len() == 2)
    }));
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .filter(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))
        .count()
        == 1));
    for owner in owners.iter().flatten() {
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .clean_state_commitment(agent)
                .unwrap(),
            source_state
        );
        let retained = owner
            .host
            .lock()
            .unwrap()
            .prepare_clean_ordered_operation(
                agent,
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
            )
            .unwrap();
        assert_eq!(retained.retained(), Some(&invoked));
        assert_eq!(retained.input(), boundary_input);
        for changed_authorization in [false, true] {
            let mut altered_work = work.clone();
            let InvocationAuthorization::PublicPreflight(preflight) = &authorization else {
                unreachable!()
            };
            if !changed_authorization {
                altered_work.gas -= 1;
            }
            let altered_auth = InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(
                    &altered_work,
                    preflight.observed_slot + u64::from(changed_authorization),
                ),
            );
            let before = owner.ordered_index_for_test().unwrap();
            let altered = owner.host.lock().unwrap().prepare_clean_ordered_operation(
                agent,
                CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work: altered_work,
                    authorization: altered_auth,
                },
            );
            assert!(
                altered
                    .as_ref()
                    .map_or(true, |prepared| prepared.retained() != Some(&invoked))
            );
            assert_eq!(owner.ordered_index_for_test().unwrap(), before);
        }
        assert!(owner.record.pending_projection.is_none());
    }
    let successor = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        })
        .unwrap();
    let owner = owners[successor].as_mut().unwrap();
    let before_retry = owner.ordered_index_for_test().unwrap();
    let identity = owner
        .pending_authority_projection_identity(&pending, false)
        .unwrap();
    assert_eq!(
        owner
            .supervisor_invoke(identity, work.clone(), authorization.clone())
            .unwrap(),
        invoked
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry);
    let acknowledged = owner
        .supervisor_acknowledge(identity, work.clone(), authorization.clone())
        .unwrap();
    let RuntimeOutcome::Acknowledged(Ok(acknowledged)) = acknowledged else {
        panic!("recovered boundary result must positively acknowledge");
    };
    assert_eq!(acknowledged.invocation, work.invocation);
    assert_eq!(acknowledged.actor, work.actor);
    assert_eq!(acknowledged.work, work.commitment());
    assert_eq!(acknowledged.authorization, authorization.commitment());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_retry + 1);
    let fresh = query(owner, successor, 0xb5);
    let before = owner.ordered_index_for_test().unwrap();
    let fresh_response = owner.invoke_authority_projection(fresh.clone()).unwrap();
    let projection =
        crate::agent::sdk::authority::AuthorityCredentialProjection::decode(&fresh_response)
            .unwrap();
    assert_eq!(projection.query, fresh);
    assert_ne!(projection.principal, PrincipalId::ZERO);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before + 2);
    let continued = owner
        .host
        .lock()
        .unwrap()
        .clean_state_commitment(agent)
        .unwrap();
    let expected_common = owner
        .host
        .lock()
        .unwrap()
        .request_common_snapshot_compaction(agent)
        .unwrap()
        .claim()
        .clone();
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(30), || owner
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap()
            == continued));
        assert_eq!(
            owner
                .host
                .lock()
                .unwrap()
                .request_common_snapshot_compaction(agent)
                .unwrap()
                .claim(),
            &expected_common,
            "source, imported replica, and uncompacted voter must derive one complete claim"
        );
    }
    // Reopen an imported owner after real post-checkpoint work. Recovery must
    // preserve the common ancestry while replaying its newly retained suffix.
    drop(owners[lagger].take());
    owners[lagger] = Some(reopen(lagger, signer));
    assert_eq!(
        owners[lagger]
            .as_ref()
            .unwrap()
            .host
            .lock()
            .unwrap()
            .clean_state_commitment(agent)
            .unwrap(),
        continued
    );
    assert!(wait_until(std::time::Duration::from_secs(30), || owners
        .iter()
        .flatten()
        .any(|owner| owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap_or(false))));
    let successor = owners
        .iter()
        .position(|owner| {
            owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        })
        .unwrap();
    // This qualification-only second compaction demonstrates the explicit
    // contract limit: acknowledged old projection bytes are not a durable
    // response archive. Production compaction stays disabled while remote
    // unresolved PAP2 metadata can still require that history.
    let owner = owners[successor].as_mut().unwrap();
    let checkpoint = owner
        .prepare_authority_projection(query(owner, successor, 0xb7))
        .unwrap();
    let (checkpoint_work, checkpoint_auth) = checkpoint.invocation().unwrap();
    owner
        ._network_host
        .certified_common_checkpoint_for_admission(
            agent,
            checkpoint_work,
            checkpoint_auth,
            &committee,
            fixtures[successor].merge.as_ref(),
        )
        .unwrap();
    assert_eq!(
        owner
            .host
            .lock()
            .unwrap()
            .retained_acknowledged_projection(agent, &work)
            .unwrap(),
        None
    );
    assert_eq!(owner.committed_projection_response(&work).unwrap(), None);
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}
