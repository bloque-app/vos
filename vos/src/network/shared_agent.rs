//! Live clean-network attachment for journal-backed Shared Agents.
//!
//! This module owns the only bridge from `/vos/agent/3.0.0` to a
//! `SharedAgentHost`. Every inbound frame has already crossed Noise PeerId
//! authentication and exact route membership in `agent_network`; this layer
//! then dispatches typed Raft, invocation, and Merge work to the durable
//! generation backend. Observers remain authenticated route/Merge members but
//! deliberately never own a `vos_raft` worker.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Condvar, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc as std_mpsc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use redb::Database;
use vos_agent_sdk::{
    Hash, InvocationAuthorization, InvocationScope, InvocationWork, MethodMode, NodeId,
    RuntimeExecutionContext, RuntimeOutcome,
};
use vos_raft::{ActiveConfigRecord, EntryKind, LogEntry, Meta, Storage, WriteBatch};

use crate::agent::genesis::AgentReplicaCommittee;
use crate::agent::host::LocalMergeAuthenticator;
use crate::agent::journal::{
    CanonicalJournalRecord, MAX_IMPORT_BYTES, MAX_IMPORT_EVENTS, MAX_JOURNAL_RECORD_BYTES,
    MAX_MERGE_FRONTIER_ENTRIES, MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent,
    MergeEventId, ReplayInputId,
};
use crate::agent::shared_commit::{
    SharedAgentCommonSnapshotCertificate, SharedAgentSnapshotCertificate,
};
use crate::agent::shared_host::{
    SharedAgentApplyOutcome, SharedAgentHost, SharedAgentHostError, SharedAgentRuntimeProjection,
    SharedAgentStatus, SharedAgentTransportState,
};
use crate::agent::shared_journal_driver::SharedMergeObject;
use crate::agent::shared_raft::{
    ACTIVE_CONFIG_MAGIC, META_AGENT_ACTIVE_CONFIG, META_AGENT_VOTED_FOR, META_LEGACY_ACTIVE_CONFIG,
};
use crate::agent::shared_recovery::{
    SharedRecoveryExpiryCertificate, SharedRecoveryExpiryClaim, SharedRecoveryExpiryTerminal,
    SharedRecoveryManifest, SharedRecoveryRegistration,
};
use crate::agent::{ReplicaRole, shared_raft};
use crate::commit::CommitError;
use crate::raft::{RAFT_META, RaftLog, RaftMeta};
use crate::service::wire::ServiceWire;

use super::Network;
use super::agent_network::{AGENT_REQUEST_TIMEOUT, AgentHandlerError, AgentRouteHandler};
use super::agent_protocol::{
    AgentGenerationRoute, AgentMessage, AppliedAvailabilityRequest, AuthenticatedAgentFrame,
    InvocationRedirect, InvocationReply, MergeMessage, RaftLogEntryKind, RaftMessage, RaftRole,
    RaftStatus, RaftVotePhase, invocation_request_correlation,
};
use super::agent_raft_transport::AgentRaftTransport;

const MAX_AGENT_VOTERS: usize = crate::agent::MAX_AGENT_REPLICAS;
const MAX_PENDING_ORDERED_REPLIES: usize = 1_024;
const MAX_MERGE_SYNC_SCAN_EVENTS: usize = MAX_REPLAY_SUFFIX_ENTRIES + MAX_MERGE_FRONTIER_ENTRIES;
const MAX_MERGE_SYNC_EVENTS: usize = MAX_IMPORT_EVENTS;
const MAX_MERGE_SYNC_BYTES: usize = MAX_IMPORT_BYTES;
const ORDERED_REPLY_WAIT: Duration = Duration::from_millis(1_800);

// Host scheduling policy, not a protocol capacity or retention limit. Keep
// ordinary system projections from accumulating a large cold-replay suffix.
// Thirty large runtime calls in a below-threshold suffix took about30s in
// release recovery. Schedule earlier at idle boundaries; this does not change
// protocol capacity, snapshot authentication, or pending-operation exclusion.
const SYSTEM_PROJECTION_CHECKPOINT_SUFFIX: u64 = 8;

fn projection_checkpoint_due(remaining_slots: u64, committee_members: usize) -> bool {
    // Automatic certificate collection currently supports only one voter.
    // Do not turn optional early maintenance into a multi-voter serving gate.
    // Mandatory admission/checkpoint paths still enforce capacity and require
    // a valid complete certificate; this grants no extra replay headroom.
    committee_members == 1
        && (shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64)
            .saturating_sub(remaining_slots)
            >= SYSTEM_PROJECTION_CHECKPOINT_SUFFIX
}

fn system_promotion_barrier(
    role: impl Fn() -> vos_raft::Role,
    snapshot: impl FnOnce() -> Option<(vos_raft::Role, u64, u64)>,
    hint_wait: Duration,
) -> Result<u64, SharedAgentHostError> {
    let deadline = Instant::now() + hint_wait;
    while role() != vos_raft::Role::Leader {
        if Instant::now() >= deadline {
            // The atomic role is only a hint: promotion may still be inside
            // a durable worker event. Consult serialized state once before
            // refusing attachment, queued behind that event. This is not a
            // hard timeout for the blocking snapshot query.
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let (role, committed, last) = snapshot().ok_or(SharedAgentHostError::Unavailable)?;
    if role != vos_raft::Role::Leader || committed != last {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(committed)
}
const MERGE_SYNC_BUDGET: Duration = Duration::from_millis(1_500);
const MERGE_PUMP_REPLY_WAIT: Duration = Duration::from_millis(350);
const MERGE_PUMP_INTERVAL: Duration = Duration::from_millis(250);
// Reserve fixed Agent-frame/route fields plus conservative per-entry Raft
// metadata. The worker applies this count before materializing the storage
// suffix, so a batch of maximum-size legal commands remains frame-bounded.
const AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES: usize = 1_024;
const AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES: usize = 64;
const MAX_SHARED_RAFT_APPEND_ENTRIES: usize = (super::agent_protocol::MAX_FRAME_BYTES
    - AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES)
    / (shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES + AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES);

const _: () = assert!(super::agent_protocol::MAX_MERGE_HEADS == MAX_MERGE_FRONTIER_ENTRIES);
const _: () = assert!(super::agent_protocol::MAX_RAFT_MEMBERS == MAX_AGENT_VOTERS);
const _: () =
    assert!(super::agent_protocol::MAX_FRAME_BYTES > AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES);
const _: () = assert!(MAX_SHARED_RAFT_APPEND_ENTRIES > 0);
const _: () = assert!(MAX_SHARED_RAFT_APPEND_ENTRIES <= super::agent_protocol::MAX_RAFT_ENTRIES);
const _: () = assert!(
    MAX_SHARED_RAFT_APPEND_ENTRIES
        * (shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES + AGENT_RAFT_APPEND_ENTRY_ENVELOPE_BYTES)
        + AGENT_RAFT_APPEND_FRAME_ENVELOPE_BYTES
        <= super::agent_protocol::MAX_FRAME_BYTES
);
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES < shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES);
const _: () = assert!(
    shared_raft::MAX_AGENT_RAFT_COMMAND_BYTES <= super::agent_protocol::MAX_RAFT_COMMAND_BYTES
);
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES <= super::agent_protocol::MAX_MERGE_NODE_BYTES);

fn storage_error(message: impl Into<String>) -> CommitError {
    CommitError::Config(message.into())
}

fn valid_nodes(nodes: &[NodeId]) -> bool {
    !nodes.is_empty()
        && nodes.len() <= MAX_AGENT_VOTERS
        && nodes.iter().all(|node| *node != NodeId::ZERO)
        && nodes.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_nodes(output: &mut Vec<u8>, nodes: &[NodeId]) -> Result<(), CommitError> {
    if !valid_nodes(nodes) {
        return Err(storage_error("invalid full-NodeId Raft configuration"));
    }
    let count = u16::try_from(nodes.len())
        .map_err(|_| storage_error("full-NodeId Raft configuration exceeds bound"))?;
    output.extend_from_slice(&count.to_le_bytes());
    for node in nodes {
        output.extend_from_slice(node.as_bytes());
    }
    Ok(())
}

fn decode_nodes(bytes: &[u8], position: &mut usize) -> Result<Vec<NodeId>, CommitError> {
    let count_bytes = bytes
        .get(*position..position.saturating_add(2))
        .ok_or_else(|| storage_error("truncated full-NodeId Raft configuration"))?;
    *position += 2;
    let count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]) as usize;
    if count == 0 || count > MAX_AGENT_VOTERS {
        return Err(storage_error(
            "invalid full-NodeId Raft configuration count",
        ));
    }
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let end = position
            .checked_add(32)
            .ok_or_else(|| storage_error("full-NodeId configuration overflow"))?;
        let raw: [u8; 32] = bytes
            .get(*position..end)
            .ok_or_else(|| storage_error("truncated full-NodeId Raft member"))?
            .try_into()
            .map_err(|_| storage_error("invalid full-NodeId Raft member width"))?;
        *position = end;
        nodes.push(NodeId(raw));
    }
    if !valid_nodes(&nodes) {
        return Err(storage_error(
            "non-canonical full-NodeId Raft configuration",
        ));
    }
    Ok(nodes)
}

fn encode_active_config(record: &ActiveConfigRecord<NodeId>) -> Result<Vec<u8>, CommitError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ACTIVE_CONFIG_MAGIC);
    match record.log_index {
        Some(index) => {
            bytes.push(1);
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        None => bytes.push(0),
    }
    match &record.joint_old {
        Some(nodes) => {
            bytes.push(1);
            encode_nodes(&mut bytes, nodes)?;
        }
        None => bytes.push(0),
    }
    encode_nodes(&mut bytes, &record.current)?;
    Ok(bytes)
}

fn decode_active_config(bytes: &[u8]) -> Result<ActiveConfigRecord<NodeId>, CommitError> {
    if !bytes.starts_with(ACTIVE_CONFIG_MAGIC) {
        return Err(storage_error(
            "invalid full-NodeId Raft configuration magic",
        ));
    }
    let mut position = ACTIVE_CONFIG_MAGIC.len();
    let log_index = match bytes.get(position).copied() {
        Some(0) => {
            position += 1;
            None
        }
        Some(1) => {
            position += 1;
            let end = position
                .checked_add(8)
                .ok_or_else(|| storage_error("full-NodeId config index overflow"))?;
            let raw: [u8; 8] = bytes
                .get(position..end)
                .ok_or_else(|| storage_error("truncated full-NodeId config index"))?
                .try_into()
                .map_err(|_| storage_error("invalid full-NodeId config index"))?;
            position = end;
            Some(u64::from_le_bytes(raw))
        }
        _ => return Err(storage_error("invalid full-NodeId config index tag")),
    };
    let joint_old = match bytes.get(position).copied() {
        Some(0) => {
            position += 1;
            None
        }
        Some(1) => {
            position += 1;
            Some(decode_nodes(bytes, &mut position)?)
        }
        _ => return Err(storage_error("invalid full-NodeId joint config tag")),
    };
    let current = decode_nodes(bytes, &mut position)?;
    if position != bytes.len() {
        return Err(storage_error(
            "trailing full-NodeId Raft configuration bytes",
        ));
    }
    Ok(ActiveConfigRecord {
        log_index,
        current,
        joint_old,
    })
}

/// Redb storage for the clean full-NodeId worker. It deliberately refuses
/// generic Raft snapshots: Shared-Agent snapshots require the separately
/// authenticated journal certificate/install path.
struct AgentNodeStorage {
    database: Arc<Database>,
    log: RaftLog,
    authenticated_snapshot: (u64, u64),
    #[cfg(test)]
    timing_node: NodeId,
}

impl AgentNodeStorage {
    fn open(
        database: Arc<Database>,
        authenticated_snapshot: (u64, u64),
    ) -> Result<Self, CommitError> {
        let log = RaftLog::open(Arc::clone(&database))?;
        let meta = RaftMeta::load(&database)?;
        if meta.voted_for.is_some()
            || (meta.snap_last_index, meta.snap_last_term) != authenticated_snapshot
            || (log.snap_last_index(), log.snap_last_term()) != authenticated_snapshot
            || (authenticated_snapshot.0 == 0) != (authenticated_snapshot.1 == 0)
        {
            return Err(storage_error(
                "legacy vote or mismatched authenticated snapshot in clean Agent Raft database",
            ));
        }
        let transaction = database.begin_read()?;
        if let Ok(table) = transaction.open_table(RAFT_META)
            && table.get(META_LEGACY_ACTIVE_CONFIG)?.is_some()
        {
            return Err(storage_error(
                "legacy compact Raft configuration in clean Agent database",
            ));
        }
        let storage = Self {
            database,
            log,
            authenticated_snapshot,
            #[cfg(test)]
            timing_node: NodeId::ZERO,
        };
        let _ = storage.load_exact_vote()?;
        let _ = storage.load_active_config_sync()?;
        Ok(storage)
    }

    fn load_exact_vote(&self) -> Result<Option<NodeId>, CommitError> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(RAFT_META)?;
        let value = table
            .get(META_AGENT_VOTED_FOR)?
            .map(|value| value.value().to_vec());
        match value {
            None => Ok(None),
            Some(bytes) => {
                let raw: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| storage_error("invalid clean Agent voted_for width"))?;
                let node = NodeId(raw);
                if node == NodeId::ZERO {
                    return Err(storage_error("zero clean Agent voted_for"));
                }
                Ok(Some(node))
            }
        }
    }

    fn load_active_config_sync(&self) -> Result<Option<ActiveConfigRecord<NodeId>>, CommitError> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(RAFT_META)?;
        let value = table
            .get(META_AGENT_ACTIVE_CONFIG)?
            .map(|value| value.value().to_vec());
        value.map(|bytes| decode_active_config(&bytes)).transpose()
    }
}

impl Storage<NodeId> for AgentNodeStorage {
    type Error = CommitError;

    fn last_index(&self) -> u64 {
        self.log.last_index()
    }

    fn last_term(&self) -> u64 {
        self.log.last_term()
    }

    fn snap_last_index(&self) -> u64 {
        self.log.snap_last_index()
    }

    fn snap_last_term(&self) -> u64 {
        self.log.snap_last_term()
    }

    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        self.log.term_at(index)
    }

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<NodeId>>, Self::Error> {
        self.log
            .entries(start, end)?
            .into_iter()
            .map(|entry| {
                let kind = shared_raft::decode_agent_raft_entry_kind(&entry.payload)
                    .map_err(|error| storage_error(format!("invalid clean Raft slot: {error}")))?;
                Ok(LogEntry {
                    index: entry.index,
                    term: entry.term,
                    kind,
                })
            })
            .collect()
    }

    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::new())
    }

    async fn applied_index(&self) -> Result<Option<u64>, Self::Error> {
        Ok(Some(RaftMeta::load(&self.database)?.last_applied))
    }

    async fn load_meta(&self) -> Result<Meta<NodeId>, Self::Error> {
        let durable = RaftMeta::load(&self.database)?;
        if durable.voted_for.is_some()
            || (durable.snap_last_index, durable.snap_last_term) != self.authenticated_snapshot
        {
            return Err(storage_error("non-clean Agent Raft metadata"));
        }
        Ok(Meta {
            current_term: durable.current_term,
            voted_for: self.load_exact_vote()?,
            commit_index: durable.commit_index,
            snap_last_index: self.authenticated_snapshot.0,
            snap_last_term: self.authenticated_snapshot.1,
        })
    }

    async fn active_config(&self) -> Result<Option<ActiveConfigRecord<NodeId>>, Self::Error> {
        self.load_active_config_sync()
    }

    async fn commit_batch(&mut self, batch: WriteBatch<NodeId>) -> Result<(), Self::Error> {
        if batch.state.is_some() || batch.compact_to.is_some() {
            return Err(storage_error(
                "generic snapshot rejected for authenticated Shared-Agent journal",
            ));
        }
        let touches = batch.truncate_after.is_some()
            || !batch.appends.is_empty()
            || batch.meta.is_some()
            || batch.active_config.is_some();
        if !touches {
            return Ok(());
        }
        let cache = self.log.cache_snapshot();
        let new_meta = batch.meta.clone();
        let new_config = batch.active_config.clone();
        #[cfg(test)]
        let mut recovery_timing =
            std::env::var_os("VOS_SHARED_RECOVERY_TIMING").map(|_| (Instant::now(), None, None));
        let result = (|| -> Result<(), CommitError> {
            let transaction = self.database.begin_write()?;
            #[cfg(test)]
            if let Some((_, acquired, _)) = &mut recovery_timing {
                *acquired = Some(Instant::now());
            }
            if let Some(after) = batch.truncate_after {
                self.log.truncate_after_in_txn(&transaction, after)?;
            }
            for entry in &batch.appends {
                let encoded = shared_raft::encode_agent_raft_entry_kind(&entry.kind)
                    .map_err(|error| storage_error(format!("invalid clean Raft slot: {error}")))?;
                let assigned = self.log.append_in_txn(&transaction, entry.term, &encoded)?;
                if assigned != entry.index {
                    return Err(storage_error("non-contiguous clean Agent Raft append"));
                }
            }
            if let Some(meta) = &new_meta {
                if (meta.snap_last_index, meta.snap_last_term) != self.authenticated_snapshot
                    || meta.commit_index > self.log.last_index()
                    || meta.commit_index < self.authenticated_snapshot.0
                {
                    return Err(storage_error("invalid clean Agent Raft metadata advance"));
                }
                // `last_applied` belongs to the Shared journal application
                // transaction, which uses the same database but an
                // independent storage object. Reload it inside this write
                // transaction so a Raft metadata update can never regress a
                // concurrently completed application after restart.
                let current = RaftMeta::load_from_write_transaction(&transaction)?;
                if current.last_applied > meta.commit_index {
                    return Err(storage_error("clean Agent apply cursor exceeds commit"));
                }
                let durable = RaftMeta {
                    current_term: meta.current_term,
                    voted_for: None,
                    commit_index: meta.commit_index,
                    last_applied: current.last_applied,
                    snap_last_index: self.authenticated_snapshot.0,
                    snap_last_term: self.authenticated_snapshot.1,
                };
                durable.write_worker_fields_in_txn(&transaction)?;
                let mut table = transaction.open_table(RAFT_META)?;
                match meta.voted_for {
                    Some(node) if node != NodeId::ZERO => {
                        table.insert(META_AGENT_VOTED_FOR, node.as_bytes().as_slice())?;
                    }
                    Some(_) => return Err(storage_error("zero clean Agent voted_for")),
                    None => {
                        table.remove(META_AGENT_VOTED_FOR)?;
                    }
                }
            }
            if let Some(config) = &new_config {
                let encoded = encode_active_config(config)?;
                let mut table = transaction.open_table(RAFT_META)?;
                table.insert(META_AGENT_ACTIVE_CONFIG, encoded.as_slice())?;
            }
            #[cfg(test)]
            if let Some((_, _, prepared)) = &mut recovery_timing {
                *prepared = Some(Instant::now());
            }
            transaction.commit()?;
            Ok(())
        })();
        #[cfg(test)]
        if let Some((started, acquired, prepared)) = recovery_timing {
            let finished = Instant::now();
            eprintln!(
                "raft_write node={:?} term={:?} commit={:?} appends={} first={:?} last={:?} truncate={:?} wait_us={:?} prepare_us={:?} commit_us={:?} total_us={} success={}",
                self.timing_node,
                new_meta.as_ref().map(|meta| meta.current_term),
                new_meta.as_ref().map(|meta| meta.commit_index),
                batch.appends.len(),
                batch.appends.first().map(|entry| entry.index),
                batch.appends.last().map(|entry| entry.index),
                batch.truncate_after,
                acquired.map(|time| time.duration_since(started).as_micros()),
                acquired
                    .zip(prepared)
                    .map(|(start, end)| end.duration_since(start).as_micros()),
                prepared.map(|time| finished.duration_since(time).as_micros()),
                finished.duration_since(started).as_micros(),
                result.is_ok(),
            );
        }
        if let Err(error) = result {
            self.log.cache_restore(cache);
            return Err(error);
        }
        Ok(())
    }
}

fn protocol_route_from(
    generation: crate::agent::shared_raft::AgentGenerationRouteKey,
    replication_id: [u8; 32],
) -> AgentGenerationRoute {
    AgentGenerationRoute {
        space: vos_agent_sdk::SpaceId(generation.space().0),
        agent: vos_agent_sdk::AgentId(generation.agent().0),
        generation: Hash(replication_id),
    }
}

fn route_members_from(
    replicas: &[crate::agent::shared_host::SharedReplicaRoute],
    transition: Option<&crate::agent::shared_host::SharedCommitteeTransitionRoute>,
) -> Result<Vec<(NodeId, PeerId)>, SharedAgentHostError> {
    let mut by_node = BTreeMap::new();
    let replicas = replicas.iter().chain(
        transition
            .iter()
            .flat_map(|transition| transition.next_replicas.iter()),
    );
    for replica in replicas {
        let peer = PeerId::from_bytes(&replica.peer_id)
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let peer_bytes = peer.to_bytes();
        let node = NodeId(replica.node.0);
        if peer_bytes != replica.peer_id || node != NodeId::of_authenticated_peer(&peer_bytes) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Some(existing) = by_node.insert(node, peer)
            && existing != peer
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
    }
    Ok(by_node.into_iter().collect())
}

fn voter_nodes(replicas: &[crate::agent::shared_host::SharedReplicaRoute]) -> Vec<NodeId> {
    let mut voters = replicas
        .iter()
        .filter(|replica| replica.role == ReplicaRole::Voter)
        .map(|replica| NodeId(replica.node.0))
        .collect::<Vec<_>>();
    voters.sort_unstable();
    voters
}

fn raft_configuration_from(
    replicas: &[crate::agent::shared_host::SharedReplicaRoute],
    transition: Option<&crate::agent::shared_host::SharedCommitteeTransitionRoute>,
) -> (Vec<NodeId>, Option<Vec<NodeId>>) {
    let active = voter_nodes(replicas);
    match transition {
        Some(transition) if transition.joint => {
            (voter_nodes(&transition.next_replicas), Some(active))
        }
        _ => (active, None),
    }
}

fn reply_for_outcome(request: Hash, outcome: RuntimeOutcome) -> AgentMessage {
    AgentMessage::InvokeReply(InvocationReply { request, outcome })
}

fn has_applied_availability_quorum(voters: &[NodeId], available: &BTreeSet<NodeId>) -> bool {
    matches!(voters.len(), 1 | 3)
        && valid_nodes(voters)
        && voters
            .iter()
            .filter(|voter| available.contains(voter))
            .count()
            > voters.len() / 2
}

enum OrderedReplyState {
    Waiting,
    Ready(RuntimeOutcome),
    Failed,
}

#[derive(Default)]
struct OrderedReplyWaiters {
    replies: Mutex<BTreeMap<ReplayInputId, OrderedReplyState>>,
    changed: Condvar,
}

impl OrderedReplyWaiters {
    fn register(&self, input: ReplayInputId) -> Result<(), AgentHandlerError> {
        let mut replies = self.replies.lock().map_err(|_| AgentHandlerError)?;
        if replies.len() == MAX_PENDING_ORDERED_REPLIES || replies.contains_key(&input) {
            return Err(AgentHandlerError);
        }
        replies.insert(input, OrderedReplyState::Waiting);
        Ok(())
    }

    fn cancel(&self, input: ReplayInputId) {
        if let Ok(mut replies) = self.replies.lock() {
            replies.remove(&input);
            self.changed.notify_all();
        }
    }

    fn collect_from(
        &self,
        host: &mut SharedAgentHost,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        let inputs = self
            .replies
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .iter()
            .filter_map(|(input, state)| {
                matches!(state, OrderedReplyState::Waiting).then_some(*input)
            })
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            return Ok(());
        }
        let mut completed = Vec::new();
        for input in inputs {
            if let Some(outcome) = host.try_take_clean_ordered_result(agent, input)? {
                completed.push((input, outcome));
            }
        }
        if completed.is_empty() {
            return Ok(());
        }
        let mut replies = self
            .replies
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        for (input, outcome) in completed {
            if matches!(replies.get(&input), Some(OrderedReplyState::Waiting)) {
                replies.insert(input, OrderedReplyState::Ready(outcome));
            }
        }
        self.changed.notify_all();
        Ok(())
    }

    fn fail_all(&self) {
        if let Ok(mut replies) = self.replies.lock() {
            for state in replies.values_mut() {
                if matches!(state, OrderedReplyState::Waiting) {
                    *state = OrderedReplyState::Failed;
                }
            }
            self.changed.notify_all();
        }
    }

    fn wait(&self, input: ReplayInputId) -> Result<RuntimeOutcome, AgentHandlerError> {
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let mut replies = self.replies.lock().map_err(|_| AgentHandlerError)?;
        loop {
            match replies.get(&input) {
                Some(OrderedReplyState::Ready(_)) => {
                    let Some(OrderedReplyState::Ready(outcome)) = replies.remove(&input) else {
                        unreachable!("reply state was checked while holding the same lock")
                    };
                    return Ok(outcome);
                }
                Some(OrderedReplyState::Failed) | None => {
                    replies.remove(&input);
                    return Err(AgentHandlerError);
                }
                Some(OrderedReplyState::Waiting) => {}
            }
            let now = Instant::now();
            if now >= deadline {
                replies.remove(&input);
                return Err(AgentHandlerError);
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(replies, deadline.saturating_duration_since(now))
                .map_err(|_| AgentHandlerError)?;
            replies = next;
            if timeout.timed_out()
                && matches!(replies.get(&input), Some(OrderedReplyState::Waiting))
            {
                replies.remove(&input);
                return Err(AgentHandlerError);
            }
        }
    }
}

fn drain_committed(
    host: &mut SharedAgentHost,
    agent: crate::service::AgentId,
    waiters: &OrderedReplyWaiters,
) -> Result<(), SharedAgentHostError> {
    loop {
        match host.apply_next(agent)? {
            SharedAgentApplyOutcome::Applied { .. } | SharedAgentApplyOutcome::Duplicate { .. } => {
            }
            SharedAgentApplyOutcome::Idle => break,
        }
    }
    waiters.collect_from(host, agent)
}

fn merge_object_needs_staging(object: &SharedMergeObject) -> bool {
    matches!(object, SharedMergeObject::Missing)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttachmentFingerprint {
    protocol_route: AgentGenerationRoute,
    durable_route: crate::agent::shared_raft::AgentRouteKey,
    members: Vec<(NodeId, PeerId)>,
    next_committee: Option<crate::agent::genesis::AgentReplicaCommitteeId>,
    next_voters: Option<Vec<NodeId>>,
    voters: Vec<NodeId>,
    joint_old: Option<Vec<NodeId>>,
    local_role: ReplicaRole,
}

impl AttachmentFingerprint {
    fn from_attachment_status(
        status: &crate::agent::shared_host::SharedAgentAttachmentStatus,
    ) -> Result<Self, SharedAgentHostError> {
        let members = route_members_from(&status.replicas, status.committee_transition.as_ref())?;
        let (voters, joint_old) =
            raft_configuration_from(&status.replicas, status.committee_transition.as_ref());
        let next_voters = status
            .committee_transition
            .as_ref()
            .map(|transition| voter_nodes(&transition.next_replicas));
        if !valid_nodes(&voters)
            || joint_old.as_ref().is_some_and(|nodes| !valid_nodes(nodes))
            || next_voters
                .as_ref()
                .is_some_and(|nodes| !valid_nodes(nodes))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(Self {
            protocol_route: protocol_route_from(status.generation, status.replication_id),
            durable_route: status.route,
            members,
            next_committee: status
                .committee_transition
                .as_ref()
                .map(|transition| transition.next_committee),
            next_voters,
            voters,
            joint_old,
            local_role: status
                .local_role
                .ok_or(SharedAgentHostError::ScopeMismatch)?,
        })
    }

    fn validates_local(&self, local: NodeId) -> bool {
        if self.next_committee.is_some() != self.next_voters.is_some() {
            return false;
        }
        let member = self
            .members
            .binary_search_by_key(&local, |(node, _)| *node)
            .is_ok();
        let voter = self.voters.binary_search(&local).is_ok();
        let joint_voter = self
            .joint_old
            .as_ref()
            .is_some_and(|nodes| nodes.binary_search(&local).is_ok());
        let next_voter = self
            .next_voters
            .as_ref()
            .is_some_and(|nodes| nodes.binary_search(&local).is_ok());
        member
            && match self.local_role {
                ReplicaRole::Voter => voter || joint_voter,
                // An authenticated observer stays a non-worker unless an
                // already-authorized next committee promotes it. Such a node
                // must start as a follower before the joint entry can reach
                // and activate it.
                ReplicaRole::Observer => !joint_voter && (!voter || next_voter),
            }
    }

    fn requires_promotion_barrier(
        &self,
        explicit: bool,
        implicit_system: bool,
        recovering: bool,
        pending_management: bool,
        management_retirement: bool,
    ) -> bool {
        let fixed_three = self.members.len() == 3
            && self.voters.len() == 3
            && self
                .members
                .iter()
                .map(|(node, _)| *node)
                .eq(self.voters.iter().copied())
            && self.local_role == ReplicaRole::Voter
            && self.next_committee.is_none()
            && self.next_voters.is_none()
            && self.joint_old.is_none();
        explicit
            || pending_management
            || management_retirement
            || (implicit_system && (recovering || !fixed_three))
    }

    /// Whether `next` only advances an authorized committee transition this
    /// attachment already serves: same generation, same active committee
    /// and local role, a transition is now prepared or joint, and no route
    /// member is dropped. Such a change must not restart the Raft worker: a
    /// new leader term would append its no-op between the Prepare and its
    /// adjacent joint/stable configuration legs, which the ledger refuses.
    /// The route member set may only grow (by authenticated next members).
    fn continues_transition(&self, next: &Self, local: NodeId) -> bool {
        self.protocol_route == next.protocol_route
            && self.durable_route == next.durable_route
            && self.local_role == next.local_role
            && next.next_committee.is_some()
            && (self.next_committee.is_none() || self.next_committee == next.next_committee)
            && self.runs_worker(local)
            && next.runs_worker(local)
            && next.validates_local(local)
            && self
                .members
                .iter()
                .all(|member| next.members.contains(member))
    }

    /// Voters own their consensus worker. An observer runs a passive,
    /// non-member worker: vos-raft never lets it campaign, and no leader
    /// replicates to it until an authorized joint configuration names it.
    /// Without that worker a promoted observer could never receive the
    /// Prepare entry that tells it it is being promoted.
    fn runs_worker(&self, local: NodeId) -> bool {
        self.owns_raft_worker(local) || self.local_role == ReplicaRole::Observer
    }

    fn owns_raft_worker(&self, local: NodeId) -> bool {
        self.voters.binary_search(&local).is_ok()
            || self
                .joint_old
                .as_ref()
                .is_some_and(|nodes| nodes.binary_search(&local).is_ok())
            || self
                .next_voters
                .as_ref()
                .is_some_and(|nodes| nodes.binary_search(&local).is_ok())
    }
}

struct SharedRouteHandler {
    projection_dispatch: Arc<Mutex<Option<ProjectionDispatch>>>,
    host: Arc<Mutex<SharedAgentHost>>,
    network: Arc<Network>,
    route: AgentGenerationRoute,
    agent: crate::service::AgentId,
    route_nodes: Vec<NodeId>,
    worker: Option<vos_raft::WorkerHandle<NodeId>>,
    proposal: Mutex<ProposalAdmission>,
    /// Set from appending a committee Prepare until this replica has applied
    /// it. Until then the driver cannot see the pending transition, so every
    /// ordinary proposal on this owner is refused instead.
    committee_fence: AtomicBool,
    // RPC timeouts do not cancel a coordinator already collecting votes.
    // Reject concurrent retries instead of queuing duplicate full audits.
    // This excludes only expiry coordination for this Agent, not execution.
    expiry: Mutex<()>,
    ordered_replies: Arc<OrderedReplyWaiters>,
    lifecycle: Arc<RwLock<bool>>,
    #[cfg(test)]
    raft_isolated: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectionPairKey {
    invocation: crate::agent_sdk::InvocationId,
    work: Hash,
    authorization: Hash,
}

impl ProjectionPairKey {
    fn new(work: &InvocationWork, authorization: &InvocationAuthorization) -> Self {
        Self {
            invocation: work.invocation,
            work: work.commitment(),
            authorization: authorization.commitment(),
        }
    }
}

fn management_retirement_keys(
    agent: crate::service::AgentId,
    envelopes: [&crate::agent_sdk::RuntimeWork; 2],
) -> Result<[ProjectionPairKey; 2], SharedAgentHostError> {
    let keys = [
        management_envelope_key(agent, envelopes[0])?,
        management_envelope_key(agent, envelopes[1])?,
    ];
    if keys[0].invocation == keys[1].invocation {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(keys)
}

fn management_envelope_key(
    agent: crate::service::AgentId,
    envelope: &crate::agent_sdk::RuntimeWork,
) -> Result<ProjectionPairKey, SharedAgentHostError> {
    let crate::agent_sdk::RuntimeWork::Invoke {
        context,
        state,
        invocation,
        authorization,
        observed_slot,
    } = envelope
    else {
        return Err(SharedAgentHostError::ScopeMismatch);
    };
    if crate::service::AgentId(invocation.agent.0) != agent
        || *context != RuntimeExecutionContext::Direct
        || *state != crate::agent_sdk::RuntimeState::default()
        || !invocation.validate()
        // A retained lifecycle may query Authority before its next mutation.
        // Both modes use the ordered journal and the same exact reservation.
        || !matches!(invocation.mode, crate::agent_sdk::MethodMode::Linear | crate::agent_sdk::MethodMode::Query)
        || **authorization
            != InvocationAuthorization::PublicPreflight(
                crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
            )
    {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    Ok(ProjectionPairKey::new(invocation, authorization))
}

type PendingManagement = (
    crate::agent::clean_management_intent::ManagementJournalAnchor,
    crate::agent_sdk::RuntimeWork,
);
type PendingManagementKey = (
    ProjectionPairKey,
    crate::agent::clean_management_intent::ManagementJournalAnchor,
);

fn pending_management_keys(
    agent: crate::service::AgentId,
    pending: &[PendingManagement],
) -> Result<Vec<PendingManagementKey>, SharedAgentHostError> {
    if pending.is_empty() || pending.len() > MAX_REPLAY_SUFFIX_ENTRIES {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut seen = BTreeSet::new();
    pending
        .iter()
        .map(|(anchor, work)| {
            let key = management_envelope_key(agent, work)?;
            if !seen.insert(key.invocation) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok((key, anchor.clone()))
        })
        .collect()
}

fn pending_management_refs(
    pending: &[PendingManagement],
) -> Vec<(
    &crate::agent::clean_management_intent::ManagementJournalAnchor,
    &crate::agent_sdk::RuntimeWork,
)> {
    pending
        .iter()
        .map(|(anchor, work)| (anchor, work))
        .collect()
}

#[derive(Default)]
struct ProposalAdmission {
    projection_pair: Option<ProjectionPairKey>,
    registration_append: Option<PendingRegistrationAppend>,
    management_retirement: Option<Vec<[ProjectionPairKey; 2]>>,
    management_pending: Option<Vec<PendingManagementKey>>,
}

/// Only volatile append bookkeeping, never custody or execution authority.
/// Remember whether registration introduced the key or inherited a WAL owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRegistrationAppend {
    key: ProjectionPairKey,
    prior_pair: Option<ProjectionPairKey>,
    route: shared_raft::AgentRouteKey,
    command: crate::service::Hash,
    index: u64,
    term: u64,
}

impl PendingRegistrationAppend {
    fn overwritten_by(&self, row: &crate::raft::LogEntry) -> Result<bool, SharedAgentHostError> {
        if row.index != self.index || row.term <= self.term {
            return Ok(false);
        }
        match shared_raft::decode_agent_raft_entry_kind(&row.payload)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?
        {
            EntryKind::Data { payload } if payload.is_empty() => Ok(true),
            EntryKind::Data { payload } => {
                let command = shared_raft::AgentRaftCommand::decode(&payload)
                    .map_err(|_| SharedAgentHostError::CorruptResidue)?;
                Ok(command.encode() == payload && command.commitment() != self.command)
            }
            _ => Ok(false),
        }
    }
}

impl ProposalAdmission {
    fn finish_registration_reconciliation(
        &mut self,
        pending: PendingRegistrationAppend,
        admitted: bool,
        overwritten: bool,
    ) -> Result<(), SharedAgentHostError> {
        if self.registration_append != Some(pending) || self.projection_pair != Some(pending.key) {
            return Err(SharedAgentHostError::Conflict);
        }
        if admitted {
            self.registration_append = None;
        } else if overwritten {
            self.projection_pair = pending.prior_pair;
            self.registration_append = None;
        } else {
            return Err(SharedAgentHostError::Unavailable);
        }
        Ok(())
    }

    fn begin_recovery_registration(
        &mut self,
        key: ProjectionPairKey,
    ) -> Result<Option<ProjectionPairKey>, SharedAgentHostError> {
        if self.management_pending.is_some()
            || self.management_retirement.is_some()
            || self.projection_pair.is_some_and(|held| held != key)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let prior = self.projection_pair;
        self.projection_pair = Some(key);
        Ok(prior)
    }

    fn reconcile_completed_dependency(
        &mut self,
        intent: ProjectionPairKey,
        manifest: &SharedRecoveryManifest,
    ) {
        let Some(held) = self.projection_pair else {
            return;
        };
        if held != intent
            && manifest.slots().iter().any(|slot| {
                slot.is_terminal()
                    && ProjectionPairKey::new(
                        slot.registration().work(),
                        slot.registration().authorization(),
                    ) == held
            })
        {
            self.projection_pair = None;
        }
    }

    fn reserve_idle_checkpoint(&mut self, key: ProjectionPairKey) -> bool {
        if self.projection_pair.is_some()
            || self.management_retirement.is_some()
            || self.management_pending.is_some()
        {
            return false;
        }
        self.projection_pair = Some(key);
        true
    }
}

fn management_retirement_set_keys(
    agent: crate::service::AgentId,
    pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
) -> Result<Vec<[ProjectionPairKey; 2]>, SharedAgentHostError> {
    if pairs.is_empty() || pairs.len() > MAX_REPLAY_SUFFIX_ENTRIES / 2 {
        return Err(SharedAgentHostError::ScopeMismatch);
    }
    let mut seen = BTreeSet::new();
    pairs
        .iter()
        .map(|pair| {
            let keys = management_retirement_keys(agent, *pair)?;
            if keys.iter().any(|key| !seen.insert(key.invocation)) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(keys)
        })
        .collect()
}

fn retirement_pair_refs(
    pairs: &[[crate::agent_sdk::RuntimeWork; 2]],
) -> Vec<[&crate::agent_sdk::RuntimeWork; 2]> {
    pairs.iter().map(|pair| [&pair[0], &pair[1]]).collect()
}

impl ProposalAdmission {
    fn is_reserved(&self) -> bool {
        self.projection_pair.is_some()
            || self.management_retirement.is_some()
            || self.management_pending.is_some()
    }
}

#[derive(Clone, Copy)]
enum ReservedSubmission {
    Projection(ProjectionPairKey),
    ManagementRetirement(ProjectionPairKey),
    ManagementResult(ProjectionPairKey),
}

#[derive(Clone, Copy)]
enum InvocationClock<'a> {
    Current,
    Bootstrap,
    PersistedManagement(&'a crate::agent::clean_management_intent::ManagementJournalAnchor),
}

#[derive(Clone, Copy)]
enum SupervisorAdmission<'a> {
    Ordinary,
    ReservedProjection,
    ReservedManagementRetirement,
    ReservedManagementResult,
    PersistedManagement(&'a crate::agent::clean_management_intent::ManagementJournalAnchor),
}

struct RecoveringProjectionAdmission<'a> {
    agent: crate::service::AgentId,
    work: &'a InvocationWork,
    authorization: &'a InvocationAuthorization,
    expected_committee: &'a AgentReplicaCommittee,
    signer: &'a dyn LocalMergeAuthenticator,
}

#[cfg(test)]
pub(crate) fn trace_common_checkpoint_material_for_test(
    label: &str,
    node: crate::service::NodeId,
    claim: &crate::agent::shared_commit::SharedAgentCommonSnapshotClaim,
    manifest: &SharedRecoveryManifest,
) {
    eprintln!(
        "common_material label={label} node={node:?} claim={:?} ordered={:?} raft={}/{} ancestry={:?} claim_recovery={:?} manifest={:?}",
        claim.commitment().0,
        claim.ordered().commitment().0,
        claim.ordered().raft_index(),
        claim.ordered().raft_term(),
        claim.ancestry(),
        claim.recovery_manifest().map(|root| root.0),
        manifest.commitment().0
    );
    for slot in manifest.slots() {
        let observed = |observation: &crate::agent::shared_recovery::SharedRecoveryObservation| {
            (
                observation.input_id(),
                observation.claim_commitment().0,
                crate::service::Hash::digest(
                    b"vos/test/recovery-observation/v1",
                    &[&observation.encode()],
                )
                .0,
            )
        };
        eprintln!(
            "common_slot label={label} node={node:?} owner={:?} sequence={} acquisition={}/{} slot={:?} registration={:?} invoke={:?} ack={:?}",
            slot.owner(),
            slot.sequence(),
            slot.raft_index(),
            slot.raft_term(),
            slot.commitment().0,
            slot.registration().commitment().0,
            slot.invoke().map(observed),
            slot.acknowledgement().map(observed)
        );
    }
}

/// Result of one authenticated clean Ordered submission through the live
/// Raft worker. A retained external response is proved against the current
/// authenticated root, not assigned a fabricated historical input identity.
pub(crate) struct CleanOrderedSubmission {
    pub(crate) input: Option<ReplayInputId>,
    pub(crate) outcome: RuntimeOutcome,
    pub(crate) new_slot: bool,
}

/// Result of clean management admission through the live Raft worker.
/// Guest denial is explicitly nondurable; every successful unseen request is
/// applied from a real committed Ordered slot.
pub(crate) enum CleanManagementSubmission {
    Denied {
        outcome: RuntimeOutcome,
        observed_slot: u64,
    },
    Applied {
        outcome: RuntimeOutcome,
        observed_slot: u64,
        new_slot: bool,
    },
    /// The committee leg of a `ChangeReplicas` was appended with its adjacent
    /// joint configuration. `stable` reports whether this replica applied the
    /// stable leg before returning. Either way the caller refreshes the
    /// attachment and resubmits the identical request: once the committee
    /// runs the roster, the ordinary ordered path updates the descriptor.
    #[allow(dead_code)] // Read by the operator replica-change command once wired.
    CommitteeTransition { observed_slot: u64, stable: bool },
}

fn has_projection_recovery_custody(
    manifest: &SharedRecoveryManifest,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
) -> bool {
    manifest.slots().iter().any(|slot| {
        slot.registration().work() == work && slot.registration().authorization() == authorization
    })
}

fn quiescent_projection_commit(
    role: vos_raft::Role,
    committed: u64,
    last: u64,
    retaining_existing_pair: bool,
) -> Result<u64, SharedAgentHostError> {
    if committed != last
        || !(role == vos_raft::Role::Leader
            || (retaining_existing_pair && role == vos_raft::Role::Follower))
    {
        return Err(SharedAgentHostError::Unavailable);
    }
    Ok(committed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectionBarrier {
    role: vos_raft::Role,
    term: u64,
    committed: u64,
    last: u64,
}

impl From<&vos_raft::WorkerSnapshot<NodeId>> for ProjectionBarrier {
    fn from(snapshot: &vos_raft::WorkerSnapshot<NodeId>) -> Self {
        Self {
            role: snapshot.role,
            term: snapshot.current_term,
            committed: snapshot.commit_index,
            last: snapshot.last_log_index,
        }
    }
}

impl ProjectionBarrier {
    fn validate_applied(self, current: Self, applied: u64) -> Result<(), SharedAgentHostError> {
        // Raft can advance while the caller waits for the host or drains its
        // committed rows. Such progress invalidates the sample, not the store.
        if self != current {
            return Err(SharedAgentHostError::Unavailable);
        }
        if applied != self.committed {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(())
    }
}

impl SharedRouteHandler {
    fn sign_projection_expiry(
        &self,
        claim: &SharedRecoveryExpiryClaim,
    ) -> Result<crate::agent::shared_commit::ReplicaCommitSignature, SharedAgentHostError> {
        #[cfg(test)]
        let started = Instant::now();
        #[cfg(test)]
        let trace = |phase: &str| {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "recovery_expiry_vote_phase node={:?} request={:?} phase={phase} elapsed_ms={}",
                    self.network.agent_node_id(),
                    claim.request(),
                    started.elapsed().as_millis(),
                );
            }
        };
        let _proposal = self.proposal.try_lock().map_err(|error| {
            #[cfg(test)]
            trace(&format!("proposal_lock_error={error:?}"));
            #[cfg(not(test))]
            let _ = error;
            SharedAgentHostError::Unavailable
        })?;
        #[cfg(test)]
        trace("proposal_acquired");
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_projection_commit(
            before.role,
            before.commit_index,
            before.last_log_index,
            true,
        )
        .map_err(|error| {
            #[cfg(test)]
            trace(&format!(
                "initial_barrier_error={error:?} snapshot={before:?}"
            ));
            error
        })?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        #[cfg(test)]
        trace("host_acquired_and_drained");
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || protocol_route_from(status.generation, status.replication_id) != self.route
            || status.route.generation() != claim.generation()
            || status.route.committee() != claim.committee().id()
            || status.committee_transition.is_some()
        {
            #[cfg(test)]
            trace("attachment_scope_error");
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let signature = host
            .sign_recovery_expiry(self.agent, claim)
            .map_err(|error| {
                #[cfg(test)]
                trace(&format!("host_sign_error={error:?}"));
                error
            })?;
        #[cfg(test)]
        trace("host_signed");
        // Signing independently audited this exact committed/applied prefix
        // while the host remains exclusively held. Re-auditing capacity here
        // adds no protection to the fresh worker barrier below.
        let applied = claim.prefix_index();
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&before)
            .validate_applied(ProjectionBarrier::from(&after), applied).map_err(|error| {
                #[cfg(test)]
                trace(&format!("final_barrier_error={error:?} before={before:?} after={after:?} applied={applied}"));
                error
            })?;
        #[cfg(test)]
        trace("success");
        Ok(signature)
    }

    fn expire_projection_recovery(
        &self,
        request: crate::service::Hash,
    ) -> Result<SharedRecoveryExpiryTerminal, SharedAgentHostError> {
        #[cfg(test)]
        let started = Instant::now();
        #[cfg(test)]
        let trace = |phase: &str| {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "recovery_expiry_phase node={:?} request={request:?} phase={phase} elapsed_ms={}",
                    self.network.agent_node_id(),
                    started.elapsed().as_millis(),
                );
            }
        };
        #[cfg(test)]
        trace("start");
        let _expiry = self
            .expiry
            .try_lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let (claim, signature, fingerprint, key) = {
            let mut proposal = self
                .proposal
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            #[cfg(test)]
            trace("proposal_acquired");
            self.reconcile_registration_append(&mut proposal)
                .map_err(|error| {
                    #[cfg(test)]
                    trace(&format!("registration_reconcile_error={error:?}"));
                    error
                })?;
            let before = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            quiescent_projection_commit(
                before.role,
                before.commit_index,
                before.last_log_index,
                false,
            )
            .map_err(|error| {
                #[cfg(test)]
                trace(&format!(
                    "initial_barrier_error={error:?} snapshot={before:?}"
                ));
                error
            })?;
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            #[cfg(test)]
            trace("host_acquired_and_drained");
            if let Some(terminal) = host.recovery_expiry_terminal(self.agent, request)? {
                Self::release_expired_projection_key(
                    &mut proposal,
                    &mut host,
                    self.agent,
                    &terminal,
                )?;
                return Ok(terminal);
            }
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if status.transport != SharedAgentTransportState::Attached
                || fingerprint.protocol_route != self.route
                || fingerprint.voters.len() != 3
                || fingerprint.members.len() != 3
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
            {
                #[cfg(test)]
                trace("attachment_scope_error");
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let manifest = host.recovery_manifest(self.agent)?;
            let registration = manifest
                .slots()
                .iter()
                .find(|slot| slot.registration().request().request_commitment() == request)
                .ok_or(SharedAgentHostError::ScopeMismatch)?
                .registration();
            let key = ProjectionPairKey::new(registration.work(), registration.authorization());
            if proposal.management_pending.is_some()
                || proposal.management_retirement.is_some()
                || proposal.projection_pair.is_some_and(|held| held != key)
            {
                #[cfg(test)]
                trace("proposal_scope_conflict");
                return Err(SharedAgentHostError::Conflict);
            }
            let (candidate, signature) = host
                .prepare_signed_recovery_expiry(self.agent, request)
                .map_err(|error| {
                #[cfg(test)]
                trace(&format!("host_prepare_error={error:?}"));
                error
            })?;
            #[cfg(test)]
            trace("host_prepared_and_signed");
            let claim = candidate.claim().clone();
            let applied = claim.prefix_index();
            let after = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            ProjectionBarrier::from(&before)
                .validate_applied(ProjectionBarrier::from(&after), applied).map_err(|error| {
                    #[cfg(test)]
                    trace(&format!("prepared_barrier_error={error:?} before={before:?} after={after:?} applied={applied}"));
                    error
                })?;
            proposal.begin_recovery_registration(key)?;
            (claim, signature, fingerprint, key)
        };
        // Votes are collected without holding either the host or proposal
        // mutex. A later exact-prefix check invalidates any intervening work.
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        #[cfg(test)]
        trace("votes_start");
        let mut pending = BTreeMap::new();
        for &voter in &fingerprint.voters {
            if voter != self.network.agent_node_id() {
                pending.insert(
                    voter,
                    self.network
                        .send_agent_recovery_expiry_vote(voter, self.route, claim.clone()),
                );
            }
        }
        let certificate = loop {
            let mut finished = Vec::new();
            let mut verified = None;
            for (&voter, response) in &pending {
                match response.try_recv() {
                    Ok(Ok(Some(remote))) if remote.signer().0 == voter.0 => {
                        #[cfg(test)]
                        trace(&format!(
                            "vote_received voter={voter:?} signer={:?}",
                            remote.signer()
                        ));
                        let mut signatures = vec![signature.clone(), remote];
                        signatures.sort_unstable_by_key(|signature| signature.signer());
                        if let Ok(certificate) =
                            SharedRecoveryExpiryCertificate::new(claim.clone(), signatures)
                            && certificate
                                .verify(claim.generation(), claim.committee(), &claim)
                                .is_ok()
                        {
                            verified = Some(certificate);
                            #[cfg(test)]
                            trace(&format!("certificate_verified voter={voter:?}"));
                        } else {
                            #[cfg(test)]
                            trace(&format!("certificate_refused voter={voter:?}"));
                        }
                        finished.push(voter);
                    }
                    result @ (Ok(_) | Err(std_mpsc::TryRecvError::Disconnected)) => {
                        #[cfg(test)]
                        trace(&format!("vote_refused voter={voter:?} result={result:?}"));
                        #[cfg(not(test))]
                        let _ = result;
                        finished.push(voter);
                    }
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
            }
            if let Some(certificate) = verified {
                break certificate;
            }
            for voter in finished {
                pending.remove(&voter);
            }
            if pending.is_empty() || Instant::now() >= deadline {
                #[cfg(test)]
                trace(&format!("vote_wait_unavailable pending={}", pending.len()));
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        #[cfg(test)]
        trace("final_proposal_acquired");
        if proposal.projection_pair != Some(key)
            || proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
        {
            #[cfg(test)]
            trace("final_proposal_scope_conflict");
            return Err(SharedAgentHostError::Conflict);
        }
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_projection_commit(
            before.role,
            before.commit_index,
            before.last_log_index,
            false,
        )
        .map_err(|error| {
            #[cfg(test)]
            trace(&format!(
                "final_initial_barrier_error={error:?} snapshot={before:?}"
            ));
            error
        })?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        if let Some(terminal) = host.recovery_expiry_terminal(self.agent, request)? {
            Self::release_expired_projection_key(&mut proposal, &mut host, self.agent, &terminal)?;
            return Ok(terminal);
        }
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != fingerprint
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        host.verify_recovery_expiry(self.agent, &claim)
            .map_err(|error| {
                #[cfg(test)]
                trace(&format!("host_final_verify_error={error:?}"));
                error
            })?;
        #[cfg(test)]
        trace("host_final_verified");
        if !host.fixed_roster_recovery_admissible(self.agent)? {
            return Err(SharedAgentHostError::Conflict);
        }
        let command = shared_raft::AgentRaftCommand::ExpireRecovery {
            route: status.route,
            certificate,
        };
        command
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let payload = command.encode();
        let applied = claim.prefix_index();
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&before)
            .validate_applied(ProjectionBarrier::from(&after), applied).map_err(|error| {
                #[cfg(test)]
                trace(&format!("final_barrier_error={error:?} before={before:?} after={after:?} applied={applied}"));
                error
            })?;
        drop(host);
        let index = futures_executor::block_on(worker.propose_if_prefix(
            payload,
            after.current_term,
            after.last_log_index,
            after.commit_index,
        ))
        .map_err(|error| {
            #[cfg(test)]
            trace(&format!("conditional_append_error={error:?}"));
            #[cfg(not(test))]
            let _ = error;
            SharedAgentHostError::Unavailable
        })?;
        #[cfg(test)]
        trace(&format!("appended index={index}"));
        if claim.prefix_index().checked_add(1) != Some(index) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        loop {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != fingerprint
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if let Some(terminal) = host.recovery_expiry_terminal(self.agent, request)? {
                Self::release_expired_projection_key(
                    &mut proposal,
                    &mut host,
                    self.agent,
                    &terminal,
                )?;
                return Ok(terminal);
            }
            drop(host);
            if Instant::now() >= deadline {
                #[cfg(test)]
                trace("apply_wait_unavailable");
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_expired_projection_key(
        proposal: &mut ProposalAdmission,
        host: &mut SharedAgentHost,
        agent: crate::service::AgentId,
        terminal: &SharedRecoveryExpiryTerminal,
    ) -> Result<(), SharedAgentHostError> {
        let manifest = host.recovery_manifest(agent)?;
        let slot = manifest
            .slots()
            .iter()
            .find(|slot| slot.expiry() == Some(terminal))
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let key = ProjectionPairKey::new(
            slot.registration().work(),
            slot.registration().authorization(),
        );
        // Applied expiry ends execution admission, not the owner's durable
        // delivery obligation. PAP cleanup independently verifies this terminal
        // and clears its exact durable record even when no volatile key remains.
        if proposal.projection_pair == Some(key) {
            proposal.projection_pair = None;
        }
        if proposal
            .registration_append
            .is_some_and(|pending| pending.key == key)
        {
            proposal.registration_append = None;
        }
        Ok(())
    }

    fn reconcile_expired_projection_key(
        &self,
        proposal: &mut ProposalAdmission,
    ) -> Result<(), SharedAgentHostError> {
        let Some(key) = proposal.projection_pair else {
            return Ok(());
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        if host.recovery_expiry_floor(self.agent)? == 0 {
            // No positive-window expiry has ever applied to this live owner.
            // Keep ordinary/legacy admission free of an extra manifest audit.
            return Ok(());
        }
        let manifest = host.recovery_manifest(self.agent)?;
        let request = manifest
            .slots()
            .iter()
            .find(|slot| {
                slot.expiry().is_some()
                    && ProjectionPairKey::new(
                        slot.registration().work(),
                        slot.registration().authorization(),
                    ) == key
            })
            .map(|slot| slot.registration().request().request_commitment());
        if let Some(request) = request {
            let terminal = host
                .recovery_expiry_terminal(self.agent, request)?
                .ok_or(SharedAgentHostError::CorruptResidue)?;
            Self::release_expired_projection_key(proposal, &mut host, self.agent, &terminal)?;
        }
        Ok(())
    }

    fn reconcile_registration_append(
        &self,
        proposal: &mut ProposalAdmission,
    ) -> Result<(), SharedAgentHostError> {
        self.reconcile_expired_projection_key(proposal)?;
        let Some(pending) = proposal.registration_append else {
            return Ok(());
        };
        if proposal.projection_pair != Some(pending.key) {
            // A later lifecycle transition owns the current key. Old append
            // bookkeeping cannot release or replace it.
            proposal.registration_append = None;
            return Ok(());
        }
        if proposal.management_pending.is_some() || proposal.management_retirement.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_projection_commit(
            before.role,
            before.commit_index,
            before.last_log_index,
            true,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let applied = host.capacity(self.agent)?.0;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
        if status.transport != SharedAgentTransportState::Attached
            || fingerprint.protocol_route != self.route
            || status.route != pending.route
            || fingerprint.members.len() != 3
            || fingerprint.voters.len() != 3
            || fingerprint.next_committee.is_some()
            || fingerprint.joint_old.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let manifest = host.recovery_manifest(self.agent)?;
        let admitted = manifest.slots().iter().any(|slot| {
            ProjectionPairKey::new(
                slot.registration().work(),
                slot.registration().authorization(),
            ) == pending.key
        });
        let overwritten = if !admitted && before.commit_index >= pending.index {
            let log = RaftLog::open(host.raft_database(self.agent)?)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let entries = log
                .entries(pending.index, pending.index)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            match entries.as_slice() {
                [entry] => pending.overwritten_by(entry)?,
                _ => false,
            }
        } else {
            false
        };
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&before)
            .validate_applied(ProjectionBarrier::from(&after), applied)?;
        // Missing/compacted rows prove no overwrite. Applied same-work custody
        // keeps its key; only a proven overwrite restores the exact prior key.
        proposal.finish_registration_reconciliation(pending, admitted, overwritten)
    }

    fn register_projection_recovery(
        &self,
        registration: &SharedRecoveryRegistration,
    ) -> Result<(), SharedAgentHostError> {
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.reconcile_registration_append(&mut proposal)?;
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        if proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
            || proposal.projection_pair.is_some_and(|held| held != key)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_projection_commit(
            barrier.role,
            barrier.commit_index,
            barrier.last_log_index,
            false,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let applied = host.capacity(self.agent)?.0;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&barrier)
            .validate_applied(ProjectionBarrier::from(&current), applied)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
        if status.transport != SharedAgentTransportState::Attached
            || fingerprint.protocol_route != self.route
            || fingerprint.members.len() != 3
            || fingerprint.voters.len() != 3
            || fingerprint.next_committee.is_some()
            || fingerprint.joint_old.is_some()
            || registration.generation() != status.route.generation()
            || registration.committee() != status.route.committee()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        host.validate_recovery_registration(self.agent, registration)?;
        let manifest = host.recovery_manifest(self.agent)?;
        if manifest
            .slot(registration.owner())
            .is_some_and(|slot| slot.registration() == registration)
        {
            return Ok(());
        }
        self.validate_delegated_projection_locked(
            &mut host,
            registration.query(),
            registration.work(),
            registration.authorization(),
            NodeId(registration.owner().0),
        )?;
        if !has_projection_recovery_custody(
            &manifest,
            registration.work(),
            registration.authorization(),
        ) && (host.retained_terminal_projection_invoke(
            self.agent,
            registration.work(),
            registration.authorization(),
        )? || host.retained_positive_clean_acknowledgement(
            self.agent,
            registration.work(),
            registration.authorization(),
        )?) {
            // A first holder cannot inherit an Invoke that predates custody.
            // Recheck under proposal exclusion after draining committed work;
            // a stale staging decision must not append an invalid ACK capsule.
            // Do not mutate the caller's durable intent or volatile exclusion.
            return Err(SharedAgentHostError::Conflict);
        }
        let required = host
            .projection_admission_requirement(
                self.agent,
                registration.work(),
                registration.authorization(),
                true,
            )?
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        let (_, remaining, _) = host.capacity(self.agent)?;
        // Registration itself, the remaining Invoke/ACK, one possible
        // execution-owner hold, and a current-term reopen no-op are bounded
        // before any new custody obligation becomes durable.
        let extra = 2 + u64::from(registration.owner().0 != self.network.agent_node_id().0);
        if remaining < required as u64 + extra {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        if !host.fixed_roster_recovery_admissible(self.agent)? {
            return Err(SharedAgentHostError::Conflict);
        }
        let command = shared_raft::AgentRaftCommand::RegisterRecovery {
            route: status.route,
            registration: registration.clone(),
        };
        command
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let payload = command.encode();
        // Capacity and proof validation may cross the signed time window.
        // Only exact execution evidence, not a custody-only slot or old WAL,
        // permits acquiring a new owner hold after that window has closed.
        self.validate_delegated_projection_locked(
            &mut host,
            registration.query(),
            registration.work(),
            registration.authorization(),
            NodeId(registration.owner().0),
        )?;
        let append_index = barrier
            .last_log_index
            .checked_add(1)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let database = host.raft_database(self.agent)?;
        let held_pair = proposal.begin_recovery_registration(key)?;
        proposal.registration_append = Some(PendingRegistrationAppend {
            key,
            prior_pair: held_pair,
            route: status.route,
            command: command.commitment(),
            index: append_index,
            term: barrier.current_term,
        });
        drop(host);
        let appended = match futures_executor::block_on(worker.propose_if_prefix(
            payload,
            barrier.current_term,
            barrier.last_log_index,
            barrier.commit_index,
        )) {
            Ok(index) => index,
            Err(vos_raft::ProposeError::PrefixChanged) => {
                // Mailbox validation guarantees this command never appended.
                proposal.projection_pair = held_pair;
                proposal.registration_append = None;
                return Err(SharedAgentHostError::Unavailable);
            }
            Err(_) => return Err(SharedAgentHostError::Unavailable),
        };
        proposal.registration_append.as_mut().unwrap().index = appended;
        // The worker can change term between our admission sample and append.
        // Capture the actual row term when it still contains this exact command.
        let log = RaftLog::open(database).map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let appended_rows = log
            .entries(appended, appended)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        if let [row] = appended_rows.as_slice()
            && let EntryKind::Data { payload } =
                shared_raft::decode_agent_raft_entry_kind(&row.payload)
                    .map_err(|_| SharedAgentHostError::CorruptResidue)?
            && payload == command.encode()
        {
            proposal.registration_append.as_mut().unwrap().term = row.term;
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        loop {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let current = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if current.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&current)? != fingerprint
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            let manifest = host.recovery_manifest(self.agent)?;
            if let Some(slot) = manifest.slot(registration.owner())
                && slot.registration() == registration
            {
                proposal.registration_append = None;
                if slot.is_terminal() {
                    proposal.projection_pair = held_pair;
                }
                return Ok(());
            }
            drop(host);
            if Instant::now() >= deadline {
                // Appended is not committed. Keep the same pair excluded;
                // a retry must reconcile the raw suffix at the barrier above.
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Collect a fixed-three common checkpoint certificate. Callers retain
    /// the checkpoint admission gate, but neither host nor proposal locks may
    /// cross peer I/O. Every signature is checked over the same exact claim.
    fn collect_common_snapshot_certificate(
        &self,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        let (fingerprint, candidate, signature) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if status.transport != SharedAgentTransportState::Attached
                || fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || fingerprint.voters.len() != 3
                || fingerprint
                    .voters
                    .binary_search(&self.network.agent_node_id())
                    .is_err()
                || signer.node().0 != self.network.agent_node_id().0
            {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let candidate = host.request_common_snapshot_compaction(self.agent)?;
            if candidate.claim().active_committee() != expected_committee {
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let signature = signer
                .sign_common_snapshot_candidate(&candidate)
                .filter(|signature| signature.signer() == signer.node())
                .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                if let Ok(manifest) = host.recovery_manifest(self.agent) {
                    trace_common_checkpoint_material_for_test(
                        "expected",
                        signer.node(),
                        candidate.claim(),
                        &manifest,
                    );
                }
            }
            (fingerprint, candidate, signature)
        };
        let local = self.network.agent_node_id();
        #[cfg(test)]
        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
            eprintln!(
                "common_vote expected node={local:?} claim={:?} ordered={:?} raft={}/{} ancestry={:?} recovery={:?}",
                candidate.claim().commitment(),
                candidate.claim().ordered().commitment(),
                candidate.claim().ordered().raft_index(),
                candidate.claim().ordered().raft_term(),
                candidate.claim().ancestry(),
                candidate.claim().recovery_manifest()
            );
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let mut pending = BTreeMap::new();
        for &voter in &fingerprint.voters {
            if voter != local {
                pending.insert(
                    voter,
                    self.network.send_agent_common_snapshot_vote(
                        voter,
                        self.route,
                        candidate.claim().clone(),
                    ),
                );
            }
        }
        let certificate = loop {
            let mut finished = Vec::new();
            let mut verified = None;
            for (&voter, response) in &pending {
                match response.try_recv() {
                    Ok(Ok(Some(remote))) if remote.signer().0 == voter.0 => {
                        let mut signatures = vec![signature.clone(), remote];
                        signatures.sort_unstable_by_key(|signature| signature.signer());
                        if let Ok(certificate) = SharedAgentCommonSnapshotCertificate::new(
                            candidate.claim().clone(),
                            signatures,
                        ) {
                            if certificate
                                .verify(expected_committee, candidate.claim())
                                .is_ok()
                            {
                                verified = Some(certificate);
                            }
                        }
                        finished.push(voter);
                    }
                    Ok(response) => {
                        #[cfg(test)]
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!("common_vote refused node={local:?} voter={voter:?} response={response:?}");
                        }
                        finished.push(voter);
                    }
                    Err(std_mpsc::TryRecvError::Disconnected) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
            }
            if let Some(certificate) = verified {
                break certificate;
            }
            for voter in finished {
                pending.remove(&voter);
            }
            if pending.is_empty() || Instant::now() >= deadline {
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!("common_vote unavailable node={local:?} pending={} expired={}", pending.len(), Instant::now() >= deadline);
                }
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != fingerprint
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        host.verify_common_snapshot_candidate(self.agent, candidate.claim())?;
        Ok(certificate)
    }

    /// Result delivery requires applied *state* on a majority, not merely a
    /// committed Raft command on a majority. This evidence is ephemeral and
    /// recollected after restart; it is not snapshot/compaction authority.
    fn require_ordered_availability(
        &self,
        input: ReplayInputId,
    ) -> Result<(), SharedAgentHostError> {
        let started = Instant::now();
        #[cfg(test)]
        let trace = |phase: &str| {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "availability_phase node={:?} input={input:?} phase={phase} elapsed_us={}",
                    self.network.agent_node_id(),
                    started.elapsed().as_micros()
                );
            }
        };
        let (fingerprint, local, request) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            if fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || !matches!(fingerprint.voters.len(), 1 | 3)
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            let local = NodeId(host.scope().node.0);
            if fingerprint.voters.binary_search(&local).is_err() {
                return Err(SharedAgentHostError::Unavailable);
            }
            // Callers already obtained this exact result from a durable
            // application or verified retained-result path. For an image
            // singleton that is its entire quorum, including results now
            // retained in an authenticated snapshot whose old anchor was
            // compacted. Preserve that existing path; external generations
            // still require exact block-availability evidence below.
            if fingerprint.voters.len() == 1 && !host.uses_external_state(self.agent)? {
                return Ok(());
            }
            let claim = host
                .available_ordered_claim(self.agent, input)
                .map_err(|error| {
                    #[cfg(test)]
                    trace(&format!("local_claim_error={error:?}"));
                    error
                })?;
            if claim.committee() != fingerprint.durable_route.committee() {
                return Err(SharedAgentHostError::Unavailable);
            }
            let request = AppliedAvailabilityRequest {
                raft_index: claim.raft_index(),
                raft_term: claim.raft_term(),
                claim: Hash(claim.commitment().0),
            };
            (fingerprint, local, request)
        };
        #[cfg(test)]
        trace("local_material");
        self.collect_applied_availability(fingerprint, local, request, false, started)
    }

    /// The current-root mode is additive: historical replies still attest
    /// their original publications, while retained inspection needs this exact
    /// current state available on a voter majority.
    fn collect_applied_availability(
        &self,
        fingerprint: AttachmentFingerprint,
        local: NodeId,
        request: AppliedAvailabilityRequest,
        current_root: bool,
        started: Instant,
    ) -> Result<(), SharedAgentHostError> {
        // No host/proposal mutex may cross peer I/O: each voter needs its
        // independent apply handler to reach and attest this exact state.
        let mut available = BTreeSet::from([local]);
        let deadline = started + ORDERED_REPLY_WAIT;
        let mut pending = BTreeMap::new();
        while !has_applied_availability_quorum(&fingerprint.voters, &available) {
            if Instant::now() >= deadline {
                return Err(SharedAgentHostError::Unavailable);
            }
            for &voter in &fingerprint.voters {
                if !available.contains(&voter) && !pending.contains_key(&voter) {
                    let reply = if current_root {
                        self.network
                            .send_agent_current_applied_availability(voter, self.route, request)
                    } else {
                        self.network
                            .send_agent_applied_availability(voter, self.route, request)
                    };
                    pending.insert(voter, reply);
                }
            }
            let mut finished = Vec::new();
            for (&voter, response) in &pending {
                match response.try_recv() {
                    Ok(Ok(true)) => {
                        available.insert(voter);
                        finished.push(voter);
                    }
                    Ok(_) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Disconnected) => finished.push(voter),
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
            }
            for voter in finished {
                pending.remove(&voter);
            }
            if !has_applied_availability_quorum(&fingerprint.voters, &available) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // A committee/attachment change during collection invalidates these
        // votes. Missing local data cannot be hidden by two remote replies.
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if AttachmentFingerprint::from_attachment_status(&status)? != fingerprint {
            return Err(SharedAgentHostError::Unavailable);
        }
        if current_root {
            #[cfg(feature = "experimental-state-blocks")]
            host.verify_current_ordered_availability(
                self.agent,
                request.raft_index,
                request.raft_term,
                crate::service::Hash(request.claim.0),
            )?;
            #[cfg(not(feature = "experimental-state-blocks"))]
            return Err(SharedAgentHostError::Unavailable);
        } else {
            host.verify_ordered_availability(
                self.agent,
                request.raft_index,
                request.raft_term,
                crate::service::Hash(request.claim.0),
            )?;
        }
        tracing::debug!(
            agent = ?self.agent, ?request, current_root, voters = available.len(),
            elapsed_us = started.elapsed().as_micros(),
            "Shared result applied-availability quorum"
        );
        Ok(())
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn require_retained_external_availability(
        &self,
        request: &crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        proof: &crate::agent::shared_journal_driver::RetainedExternalReplyProof,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let started = Instant::now();
        let (fingerprint, local, availability) = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(self.agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            let local = NodeId(host.scope().node.0);
            if fingerprint.protocol_route != self.route
                || fingerprint.next_committee.is_some()
                || fingerprint.joint_old.is_some()
                || fingerprint.voters.len() != 3
                || fingerprint.voters.binary_search(&local).is_err()
                || proof.claim().committee() != fingerprint.durable_route.committee()
            {
                return Err(SharedAgentHostError::Unavailable);
            }
            host.revalidate_external_retained_reply(self.agent, request, proof)?;
            let availability = AppliedAvailabilityRequest {
                raft_index: proof.claim().raft_index(),
                raft_term: proof.claim().raft_term(),
                claim: Hash(proof.claim().commitment().0),
            };
            (fingerprint, local, availability)
        };
        self.collect_applied_availability(fingerprint, local, availability, true, started)?;
        // The same guest-proved head and exact request must still be live at
        // delivery. Root advancement during peer I/O is a retry, not a new read.
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .revalidate_external_retained_reply(self.agent, request, proof)
    }

    fn has_local_proposer(&self, worker: &vos_raft::WorkerHandle<NodeId>) -> bool {
        if self.committee_fence.load(Ordering::Acquire) {
            return false;
        }
        if worker.role() == vos_raft::Role::Leader {
            return true;
        }
        // A freshly reopened one-voter generation has no remote leader to
        // redirect to. Give its real Raft worker one bounded election window
        // before reporting unavailability to the bootstrap state machine.
        if self.route_nodes.len() != 1 {
            return false;
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        while worker.role() != vos_raft::Role::Leader {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    fn reserve_projection_pair(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        recovering: bool,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.reconcile_registration_append(&mut proposal)?;
        if proposal.management_retirement.is_some() || proposal.management_pending.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        let already_reserved = match proposal.projection_pair {
            Some(existing) if existing == key => true,
            Some(_) => return Err(SharedAgentHostError::Conflict),
            None => false,
        };
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !already_reserved && !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        quiescent_projection_commit(
            barrier.role,
            barrier.commit_index,
            barrier.last_log_index,
            already_reserved,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&barrier)
            .validate_applied(ProjectionBarrier::from(&current), applied_slots)?;
        if already_reserved {
            // An old exclusion is not proof that its previous append applied.
            // Preserve it on any barrier failure; followers may retain the
            // exact key but still cannot submit locally without leadership.
            return Ok(());
        }
        if let Some(query) = crate::agent::clean_bootstrap::projection_query_from_work(work)
            && query.recovery.is_some()
        {
            self.validate_delegated_projection_locked(
                &mut host,
                &query,
                work,
                authorization,
                self.network.agent_node_id(),
            )?;
        }
        let Some(required) =
            host.projection_admission_requirement(self.agent, work, authorization, recovering)?
        else {
            return Err(SharedAgentHostError::CapacityExhausted);
        };
        // Keep one physical slot beyond every non-empty exact lifecycle.
        // A crash can leave its final record committed while the next
        // one-voter reopen must still append the mandatory current-term
        // leader no-op before recovery may publish the route.
        let required_with_reopen = (required as u64).saturating_add(u64::from(required != 0));
        if remaining_slots < required_with_reopen {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.projection_pair = Some(key);
        Ok(())
    }

    /// Called only with the proposal guard held. A retained exact Invoke/ACK
    /// is retry evidence; a PAP2 record or an old preflight clock is not.
    fn validate_delegated_projection_locked(
        &self,
        host: &mut SharedAgentHost,
        query: &crate::agent_sdk::authority::AuthorityProjectionQuery,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        sender: NodeId,
    ) -> Result<(), SharedAgentHostError> {
        if !crate::agent::clean_bootstrap::projection_query_matches_work(query, work, authorization)
            || crate::service::AgentId(work.agent.0) != self.agent
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let scope = query.recovery.ok_or(SharedAgentHostError::ScopeMismatch)?;
        if host.retained_positive_clean_acknowledgement(self.agent, work, authorization)?
            || host.retained_terminal_projection_invoke(self.agent, work, authorization)?
        {
            return Ok(());
        }
        let status = host
            .supervisor_attachment_status(self.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        let local = self.network.agent_node_id();
        let current_voter = |node: NodeId| {
            status
                .replicas
                .iter()
                .any(|member| member.node.0 == node.0 && member.role == ReplicaRole::Voter)
        };
        if status.transport != SharedAgentTransportState::Attached
            || status.committee_transition.is_some()
            || protocol_route_from(status.generation, status.replication_id) != self.route
            || scope.generation != Hash(status.replication_id)
            || scope.committee != Hash(*status.route.committee().as_bytes())
            || !current_voter(local)
            || !current_voter(sender)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // The first delegated SSH profile is deliberately committee-local:
        // the authenticated admitted roster supplies the original attestor's
        // key even when a different voter relays its exact signed read.
        // None/legacy queries retain their existing ingress contract.
        let verifier = crate::agent::clean_bootstrap::RawCredentialVerifier;
        let signature = match query.attesting_node() {
            Some(attestor) => {
                let member = status
                    .replicas
                    .iter()
                    .find(|member| member.node.0 == attestor.0 && member.role == ReplicaRole::Voter)
                    .ok_or(SharedAgentHostError::ScopeMismatch)?;
                query.verify_ssh_node_attestation_with(&member.ed25519_public_key, &verifier)
            }
            None => query.verify_api_with(&verifier),
        };
        signature.map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let now = host
            .current_logical_slot(self.agent)?
            .max(host.recovery_expiry_floor(self.agent)?);
        if !scope.admits_at(now) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_delegated_projection(
        &self,
        query: &crate::agent_sdk::authority::AuthorityProjectionQuery,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        sender: NodeId,
    ) -> Result<(), SharedAgentHostError> {
        let _proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        self.validate_delegated_projection_locked(&mut host, query, work, authorization, sender)
    }

    /// Capture and durably record a pre-dispatch anchor while proposals and
    /// checkpoint selection are excluded. The callback may only write the
    /// independent intent store; it must not re-enter this host or coordinator.
    fn record_management_anchor<F, T>(
        &self,
        envelope: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(
            crate::agent::clean_management_intent::ManagementJournalAnchor,
        ) -> Result<T, SharedAgentHostError>,
    {
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.is_reserved() {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        if host.capacity(self.agent)?.0 != barrier.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let position = host.journal_position(self.agent)?;
        // Validate envelope scope without executing policy or the runtime.
        host.management_invocation_after(self.agent, &position, envelope)?;
        record(
            crate::agent::clean_management_intent::ManagementJournalAnchor {
                genesis: position.genesis,
                admission: position.admission,
                runtime: position.runtime.commitment(),
                ordered: crate::agent::journal::OrderedBase {
                    index: position.ordered_index,
                    head: position.ordered_head,
                },
            },
        )
    }

    /// Extend an existing recovery reservation before publishing an intent
    /// image. A failed callback may have committed: retain the exact candidate
    /// in both admission and the attachment's refresh image even on failure.
    fn extend_management_pending<F, T>(
        &self,
        pending: &mut Vec<PendingManagement>,
        retiring: &[[crate::agent_sdk::RuntimeWork; 2]],
        predecessor: Option<&PendingManagement>,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let key = management_envelope_key(self.agent, proposed)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let pending_keys = if pending.is_empty() {
            None
        } else {
            Some(pending_management_keys(self.agent, pending)?)
        };
        if proposal.projection_pair.is_some() || proposal.management_pending != pending_keys {
            return Err(SharedAgentHostError::Conflict);
        }
        if let Some(predecessor) = predecessor {
            if !pending.contains(predecessor)
                || management_envelope_key(self.agent, &predecessor.1)?.invocation == key.invocation
            {
                return Err(SharedAgentHostError::Conflict);
            }
        } else if !retiring.is_empty()
            || (!pending.is_empty()
                && (pending.len() != 1
                    || management_envelope_key(self.agent, &pending[0].1)?.invocation
                        != key.invocation))
        {
            // Initial capture may only retry its own single reserved member.
            // It cannot append another request or bypass a retirement gate.
            return Err(SharedAgentHostError::Conflict);
        }
        let retiring_keys = if retiring.is_empty() {
            None
        } else {
            Some(management_retirement_set_keys(
                self.agent,
                &retirement_pair_refs(retiring),
            )?)
        };
        if proposal.management_retirement != retiring_keys
            || retiring_keys.as_ref().is_some_and(|pairs| {
                pairs
                    .iter()
                    .flatten()
                    .any(|old| old.invocation == key.invocation)
            })
        {
            return Err(SharedAgentHostError::Conflict);
        }
        // After an ambiguous write, the caller may propose a later clock.
        // Reuse the reserved envelope, never replace its signed-call identity
        // or authorization clock. Canonical envelope validation is above and
        // in pending_management_keys for both candidates.
        let existing = pending.iter().find(|(_, work)| {
            management_envelope_key(self.agent, work)
                .is_ok_and(|old| old.invocation == key.invocation)
        });
        if let Some((_, saved)) = existing {
            let (
                crate::agent_sdk::RuntimeWork::Invoke {
                    invocation: saved, ..
                },
                crate::agent_sdk::RuntimeWork::Invoke {
                    invocation: proposed,
                    ..
                },
            ) = (saved, proposed)
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            if saved != proposed {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
        if applied_slots != barrier.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let candidate = if let Some(existing) = existing {
            existing.clone()
        } else {
            let position = host.journal_position(self.agent)?;
            (
                crate::agent::clean_management_intent::ManagementJournalAnchor {
                    genesis: position.genesis,
                    admission: position.admission,
                    runtime: position.runtime.commitment(),
                    ordered: crate::agent::journal::OrderedBase {
                        index: position.ordered_index,
                        head: position.ordered_head,
                    },
                },
                proposed.clone(),
            )
        };
        let mut combined = pending.clone();
        if existing.is_none() {
            combined.push(candidate.clone());
        }
        let keys = pending_management_keys(self.agent, &combined)?;
        let required = if predecessor.is_none() {
            host.management_initial_admission_requirement(self.agent, &candidate.0, &candidate.1)?
        } else {
            host.management_recovery_admission_requirement(
                self.agent,
                &pending_management_refs(&combined),
                &retiring.iter().flatten().collect::<Vec<_>>(),
            )?
        };
        let Some(required) = required else {
            tracing::warn!(
                agent = ?self.agent,
                initial = predecessor.is_none(),
                retained = existing.is_some(),
                applied_slots,
                remaining_slots,
                pending_members = combined.len(),
                retiring_pairs = retiring.len(),
                limit = "replay_headroom",
                "management admission capacity exhausted"
            );
            return Err(SharedAgentHostError::CapacityExhausted);
        };
        if remaining_slots < required as u64 + 1 {
            tracing::warn!(
                agent = ?self.agent,
                initial = predecessor.is_none(),
                retained = existing.is_some(),
                applied_slots,
                remaining_slots,
                required_slots = required as u64 + 1,
                pending_members = combined.len(),
                retiring_pairs = retiring.len(),
                limit = "ordered_slots",
                "management admission capacity exhausted"
            );
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.management_pending = Some(keys);
        *pending = combined;
        // Like anchor publication, the callback may only write the independent
        // intent store and must not re-enter the host/coordinator.
        record(&candidate)
    }

    fn reserve_management_retirement_set(
        &self,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        self.transition_management_retirement_set(pairs, None)
    }

    fn transition_management_retirement_set(
        &self,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
        remaining_pending: Option<&[PendingManagement]>,
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_set_keys(self.agent, pairs)?;
        let remaining_keys = match remaining_pending {
            Some(pending) if !pending.is_empty() => pending_management_keys(self.agent, pending)?,
            _ => Vec::new(),
        };
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        if remaining_pending.is_none()
            && proposal
                .management_retirement
                .as_ref()
                .is_some_and(|existing| keys.iter().all(|pair| existing.contains(pair)))
        {
            return Ok(());
        }
        // Preserve every reservation exactly once. Remaining work also keeps
        // its original anchor; already-retiring pairs cannot be regrouped.
        match (&proposal.management_pending, remaining_pending) {
            (None, None) => {}
            (Some(pending), Some(_))
                if pending.len()
                    + proposal
                        .management_retirement
                        .as_ref()
                        .map_or(0, |set| set.len() * 2)
                    == keys.len() * 2 + remaining_keys.len()
                    && proposal
                        .management_retirement
                        .as_ref()
                        .is_none_or(|set| set.iter().all(|pair| keys.contains(pair)))
                    && remaining_keys.iter().all(|entry| pending.contains(entry))
                    && remaining_keys
                        .iter()
                        .all(|(key, _)| !keys.iter().flatten().any(|expected| expected == key))
                    && pending.iter().all(|entry| {
                        remaining_keys.contains(entry)
                            || keys.iter().flatten().any(|expected| expected == &entry.0)
                    }) => {}
            _ => return Err(SharedAgentHostError::Conflict),
        }
        match &proposal.management_retirement {
            Some(existing) if keys.iter().all(|pair| existing.contains(pair)) => return Ok(()),
            Some(_) if remaining_pending.is_none() => return Err(SharedAgentHostError::Conflict),
            Some(_) => {}
            None => {}
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
        if applied_slots != barrier.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        let required = host
            .management_recovery_admission_requirement(
                self.agent,
                &pending_management_refs(remaining_pending.unwrap_or(&[])),
                &pairs.iter().flatten().copied().collect::<Vec<_>>(),
            )?
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        if remaining_slots < required as u64 + u64::from(required != 0) {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        proposal.management_retirement = Some(keys);
        proposal.management_pending = (!remaining_keys.is_empty()).then_some(remaining_keys);
        Ok(())
    }

    fn complete_management_retirement<F>(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let keys = management_retirement_keys(self.agent, envelopes)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !proposal
            .management_retirement
            .as_ref()
            .is_some_and(|set| set.contains(&keys))
            || proposal.projection_pair.is_some()
        {
            return Err(SharedAgentHostError::Conflict);
        }
        if self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .management_retirement_admission_requirement(self.agent, envelopes)?
            != Some(0)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        // Durable handoff must commit while all suffix-consuming ingress is
        // still excluded. An ambiguous/failed handoff retains the reservation.
        complete()?;
        let pending = proposal.management_retirement.as_mut().unwrap();
        pending.retain(|pair| *pair != keys);
        if pending.is_empty() {
            proposal.management_retirement = None;
        }
        Ok(())
    }

    /// Caller has reopened and verified the durable host completion marker.
    /// No journal lookup is needed: its bounded suffix may already be pruned.
    fn release_completed_management_retirement(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(self.agent, envelopes)?;
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        match &mut proposal.management_retirement {
            None => Ok(()),
            Some(expected) if expected.contains(&keys) => {
                expected.retain(|pair| *pair != keys);
                if expected.is_empty() {
                    proposal.management_retirement = None;
                }
                Ok(())
            }
            Some(_) => Err(SharedAgentHostError::Conflict),
        }
    }

    fn release_projection_pair(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair != Some(key) {
            return Err(SharedAgentHostError::Conflict);
        }
        proposal.projection_pair = None;
        Ok(())
    }

    fn complete_projection_pair<F>(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.projection_pair != Some(key) {
            return Err(SharedAgentHostError::Conflict);
        }
        // Keep every suffix-consuming ingress path excluded through the
        // durable pending-record clear. A failed clear leaves the exact key
        // reserved; a successful clear and volatile release are one critical
        // section, so neither an ingress gap nor an unrecoverable post-clear
        // release failure exists.
        complete()?;
        proposal.projection_pair = None;
        Ok(())
    }

    fn reserve_checkpoint_gate(
        &self,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let key = ProjectionPairKey::new(work, authorization);
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.reconcile_registration_append(&mut proposal)?;
        if proposal.management_retirement.is_some() || proposal.management_pending.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        match proposal.projection_pair {
            None => proposal.projection_pair = Some(key),
            Some(existing) if existing == key => {}
            Some(_) => return Err(SharedAgentHostError::Conflict),
        }
        Ok(())
    }

    fn submit_clean_ordered(
        &self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation(
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
        )
    }

    fn submit_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_policy(request, false)
    }

    fn submit_terminal_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_policy(request, true)
    }

    fn submit_clean_ordered_operation_with_policy(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        self.submit_clean_ordered_operation_with_admission(
            request,
            terminal_only,
            None,
            InvocationClock::Current,
        )
    }

    fn submit_reserved_clean_ordered_operation(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let key = ProjectionPairKey::new(request.work(), request.authorization());
        self.submit_clean_ordered_operation_with_admission(
            request,
            terminal_only,
            Some(ReservedSubmission::Projection(key)),
            InvocationClock::Current,
        )
    }

    fn submit_clean_ordered_operation_with_admission(
        &self,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        reservation: Option<ReservedSubmission>,
        clock: InvocationClock<'_>,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let mut proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        self.reconcile_registration_append(&mut proposal)?;
        let pending_invoke = if let (Some(pending), InvocationClock::PersistedManagement(anchor)) =
            (&proposal.management_pending, clock)
        {
            let key = ProjectionPairKey::new(request.work(), request.authorization());
            pending
                .iter()
                .any(|(expected, saved)| *expected == key && saved == anchor)
                && matches!(
                    &request,
                    crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke { .. }
                )
        } else {
            false
        };
        match (proposal.projection_pair, &proposal.management_retirement, reservation) {
            (None, _, None) if pending_invoke => {},
            (None, None, None) => {}
            (Some(expected), None, Some(ReservedSubmission::Projection(actual))) if expected == actual => {}
            (None, Some(expected), Some(ReservedSubmission::ManagementRetirement(actual)))
                if expected.iter().any(|pair| pair.contains(&actual))
                    && matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }) => {}
            (None, _, Some(ReservedSubmission::ManagementResult(actual)))
                if proposal.management_pending.as_ref().is_some_and(|pending| pending.iter().any(|(key, _)| *key == actual))
                    && matches!(&request, crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }) => {}
            _ => return Err(SharedAgentHostError::CapacityExhausted),
        }
        if proposal.management_pending.is_some()
            && !pending_invoke
            && !matches!(
                reservation,
                Some(
                    ReservedSubmission::ManagementRetirement(_)
                        | ReservedSubmission::ManagementResult(_)
                )
            )
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let ordered_barrier = if matches!(clock, InvocationClock::PersistedManagement(_))
            || matches!(reservation, Some(ReservedSubmission::Projection(_)))
        {
            let barrier = futures_executor::block_on(worker.snapshot())
                .ok_or(SharedAgentHostError::Unavailable)?;
            quiescent_projection_commit(
                barrier.role,
                barrier.commit_index,
                barrier.last_log_index,
                false,
            )?;
            Some(ProjectionBarrier::from(&barrier))
        } else {
            None
        };
        let input = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            if let Some(barrier) = ordered_barrier {
                let applied = host.capacity(self.agent)?.0;
                let current = futures_executor::block_on(worker.snapshot())
                    .ok_or(SharedAgentHostError::Unavailable)?;
                barrier.validate_applied(ProjectionBarrier::from(&current), applied)?;
            }
            let delegated_projection =
                crate::agent::clean_bootstrap::projection_query_from_work(request.work())
                    .filter(|query| query.recovery.is_some())
                    .map(|query| {
                        (
                            query,
                            request.work().clone(),
                            request.authorization().clone(),
                        )
                    });
            if let Some((query, work, authorization)) = &delegated_projection {
                if !matches!(reservation, Some(ReservedSubmission::Projection(_))) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
                self.validate_delegated_projection_locked(
                    &mut host,
                    query,
                    work,
                    authorization,
                    self.network.agent_node_id(),
                )?;
            }
            let anchored_input = if let InvocationClock::PersistedManagement(anchor) = clock {
                let (applied_slots, remaining_slots, _) = host.capacity(self.agent)?;
                if applied_slots != ordered_barrier.unwrap().committed {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
                let crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    work,
                    authorization:
                        authorization @ InvocationAuthorization::PublicPreflight(preflight),
                } = &request
                else {
                    return Err(SharedAgentHostError::ScopeMismatch);
                };
                let envelope = crate::agent_sdk::RuntimeWork::Invoke {
                    context: RuntimeExecutionContext::Direct,
                    state: crate::agent_sdk::RuntimeState::default(),
                    invocation: Box::new(work.clone()),
                    authorization: Box::new(authorization.clone()),
                    observed_slot: preflight.observed_slot,
                };
                let required = host
                    .management_pending_admission_requirement(self.agent, &[(anchor, &envelope)])?
                    .ok_or(SharedAgentHostError::CapacityExhausted)?;
                if remaining_slots < required as u64 + 1 {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                Some(host.management_invocation_after_anchor(self.agent, anchor, &envelope)?)
            } else {
                None
            };
            #[cfg(feature = "experimental-state-blocks")]
            if matches!(clock, InvocationClock::Current)
                && reservation.is_none()
                && let Some(proof) = host.inspect_external_retained_reply(self.agent, &request)?
            {
                drop(host);
                drop(proposal);
                let outcome = self.require_retained_external_availability(&request, &proof)?;
                return Ok(CleanOrderedSubmission {
                    input: None,
                    outcome,
                    new_slot: false,
                });
            }
            let prepared = if matches!(clock, InvocationClock::Bootstrap) {
                host.prepare_bootstrap_invocation(self.agent, request)?
            } else if matches!(clock, InvocationClock::PersistedManagement(_)) {
                host.prepare_persisted_management_invocation(self.agent, request)?
            } else if matches!(reservation, Some(ReservedSubmission::Projection(_))) {
                host.prepare_reserved_projection_operation(self.agent, request, terminal_only)?
            } else if terminal_only {
                host.prepare_terminal_clean_ordered_operation(self.agent, request)?
            } else {
                host.prepare_clean_ordered_operation(self.agent, request)?
            };
            let input = prepared.input();
            if let Some(observed) = anchored_input {
                // Preparation must agree with the authenticated interval. A
                // result predating a substituted late anchor is not a retry
                // proved by that anchor, even if another cache can find it.
                if observed != prepared.retained().map(|_| input) {
                    return Err(SharedAgentHostError::CorruptResidue);
                }
            }
            if let Some(outcome) = prepared.retained().cloned() {
                drop(host);
                drop(proposal);
                self.require_ordered_availability(input)?;
                return Ok(CleanOrderedSubmission {
                    input: Some(input),
                    outcome,
                    new_slot: false,
                });
            }
            // A terminal guest preview can cross a clock boundary. Check
            // again immediately before proposing; the signed accepted slot
            // remains immutable, while admission time remains independently
            // fresh. No locks are released between this check and propose.
            if let Some((query, work, authorization)) = &delegated_projection {
                self.validate_delegated_projection_locked(
                    &mut host,
                    query,
                    work,
                    authorization,
                    self.network.agent_node_id(),
                )?;
            }
            self.ordered_replies
                .register(input)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            let payload = prepared
                .into_payload()
                .ok_or(SharedAgentHostError::Conflict)?;
            if let Err(error) = futures_executor::block_on(worker.propose(payload)) {
                tracing::debug!(?error, "clean ordered proposal did not commit");
                self.ordered_replies.cancel(input);
                return Err(SharedAgentHostError::Unavailable);
            }
            input
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        drop(host);
        let outcome = self.ordered_replies.wait(input).map_err(|_| {
            tracing::debug!("clean ordered committed-result wait failed");
            SharedAgentHostError::Unavailable
        })?;
        drop(proposal);
        self.require_ordered_availability(input)?;
        Ok(CleanOrderedSubmission {
            input: Some(input),
            outcome,
            new_slot: true,
        })
    }

    fn submit_clean_management(
        &self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
        joining: &[Vec<u8>],
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let proposal = self
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.is_reserved() {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if !self.has_local_proposer(worker) {
            return Err(SharedAgentHostError::Unavailable);
        }
        let input = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, self.agent, &self.ordered_replies)?;
            if let Some(change) =
                host.prepare_clean_committee_change(self.agent, &request, &authority, joining)?
            {
                drop(host);
                let submission = self.submit_committee_change(worker, change);
                drop(proposal);
                return submission;
            }
            let prepared =
                host.prepare_clean_management(self.agent, request, authority, artifacts)?;
            let observed_slot = prepared.observed_slot();
            if let Some(outcome) = prepared.denied().cloned() {
                return Ok(CleanManagementSubmission::Denied {
                    outcome,
                    observed_slot,
                });
            }
            if let Some(outcome) = prepared.retained().cloned() {
                let input = prepared.input().ok_or(SharedAgentHostError::Conflict)?;
                drop(host);
                drop(proposal);
                self.require_ordered_availability(input)?;
                return Ok(CleanManagementSubmission::Applied {
                    outcome,
                    observed_slot,
                    new_slot: false,
                });
            }
            let input = prepared.input().ok_or(SharedAgentHostError::Conflict)?;
            let commands = prepared.into_commands();
            if commands.is_empty() {
                return Err(SharedAgentHostError::Conflict);
            }
            self.ordered_replies
                .register(input)
                .map_err(|_| SharedAgentHostError::Conflict)?;
            for payload in commands {
                if futures_executor::block_on(worker.propose(payload)).is_err() {
                    self.ordered_replies.cancel(input);
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
            (input, observed_slot)
        };
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, self.agent, &self.ordered_replies)?;
        drop(host);
        let outcome = self
            .ordered_replies
            .wait(input.0)
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drop(proposal);
        self.require_ordered_availability(input.0)?;
        Ok(CleanManagementSubmission::Applied {
            outcome,
            observed_slot: input.1,
            new_slot: true,
        })
    }

    /// Append one authorized committee Prepare and, in the same leader term
    /// and with nothing between them, its joint configuration. The caller
    /// holds proposal exclusion; the fence keeps every other proposal on
    /// this owner out until the Prepare is applied here, after which the
    /// driver itself refuses ordinary commands while the change is pending.
    /// Every wait is bounded by `ORDERED_REPLY_WAIT`.
    fn submit_committee_change(
        &self,
        worker: &vos_raft::WorkerHandle<NodeId>,
        change: crate::agent::shared_journal_driver::PreparedCommitteeChange,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let crate::agent::shared_journal_driver::PreparedCommitteeChange {
            observed_slot,
            command,
            next_voters,
            next_committee,
        } = change;
        self.committee_fence.store(true, Ordering::Release);
        let Ok(prepare) = futures_executor::block_on(worker.propose(command)) else {
            // Nothing was appended.
            self.committee_fence.store(false, Ordering::Release);
            return Err(SharedAgentHostError::Unavailable);
        };
        match futures_executor::block_on(worker.change_membership(next_voters)) {
            Ok(joint) if Some(joint) == prepare.checked_add(1) => {}
            // The Prepare is appended without its adjacent joint leg (lost
            // leadership or an interleaved append). The fence stays up: no
            // ordinary command may follow it from this owner. A new leader's
            // no-op cannot complete the transition either; see the barrier
            // note on `PrepareCommitteeChange`.
            _ => return Err(SharedAgentHostError::Conflict),
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        let mut visible = false;
        loop {
            let (pending, active) = {
                let mut host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                // A route retired by its stable leg may no longer own the
                // apply notifier; draining here is the same exact apply.
                let _ = drain_committed(&mut host, self.agent, &self.ordered_replies);
                let status = host
                    .supervisor_attachment_status(self.agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                (
                    status
                        .committee_transition
                        .as_ref()
                        .map(|transition| transition.next_committee),
                    status.route.committee(),
                )
            };
            if active == next_committee {
                self.committee_fence.store(false, Ordering::Release);
                return Ok(CleanManagementSubmission::CommitteeTransition {
                    observed_slot,
                    stable: true,
                });
            }
            if !visible && pending == Some(next_committee) {
                visible = true;
                self.committee_fence.store(false, Ordering::Release);
            }
            if Instant::now() >= deadline {
                return if visible {
                    Ok(CleanManagementSubmission::CommitteeTransition {
                        observed_slot,
                        stable: false,
                    })
                } else {
                    Err(SharedAgentHostError::Unavailable)
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn pump_merge_once(&self, local: NodeId, stop: &AtomicBool, cursor: &mut usize) {
        let Ok(live) = self.lifecycle.read() else {
            return;
        };
        if !*live {
            return;
        }
        // One remote member per tick keeps the total work of a pump pass
        // bounded independently of committee size. The cursor gives every
        // authenticated member a fair pull opportunity across ticks.
        for _ in 0..self.route_nodes.len() {
            let peer = self.route_nodes[*cursor % self.route_nodes.len()];
            *cursor = cursor.wrapping_add(1);
            if peer == local {
                continue;
            }
            if stop.load(Ordering::Acquire) {
                return;
            }
            let Ok(Ok(heads)) = self
                .network
                .send_agent_merge_fetch_heads(peer, self.route)
                .recv_timeout(MERGE_PUMP_REPLY_WAIT)
            else {
                continue;
            };
            // A disconnected or partially-synchronized peer is ordinary.
            // `sync_merge_heads` still fails closed for malformed, unbounded,
            // or unverifiable DAG data and the next bounded pump retries from
            // the durable local frontier.
            let _ = self.sync_merge_heads(peer, heads);
            return;
        }
    }

    fn handle_invocation(
        &self,
        sender: NodeId,
        request: super::agent_protocol::InvocationRequest,
    ) -> Result<AgentMessage, AgentHandlerError> {
        // Delegated Authority reads require the exact PAP2 reservation and
        // its fresh proposal-time checks, never generic invocation ingress.
        if crate::agent::clean_bootstrap::projection_query_from_work(&request.work)
            .is_some_and(|query| query.recovery.is_some())
        {
            return Err(AgentHandlerError);
        }
        if request
            .work
            .origin
            .transport_node
            .is_some_and(|node| node != sender)
        {
            return Err(AgentHandlerError);
        }
        let correlation = invocation_request_correlation(&request);
        let work = request.work;
        let authorization = request.authorization;
        match work.mode {
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::Linear => {
                // One leader handler admits at most one uncommitted Ordered
                // invocation. This keeps the journal parent constructed below
                // exact while the independent apply thread is free to commit
                // and deliver its keyed result.
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let worker = self.worker.as_ref().ok_or(AgentHandlerError)?;
                if worker.role() != vos_raft::Role::Leader {
                    let leader = worker
                        .cached_snapshot()
                        .and_then(|snapshot| snapshot.leader_hint)
                        .filter(|leader| self.route_nodes.binary_search(leader).is_ok())
                        .ok_or(AgentHandlerError)?;
                    return Ok(AgentMessage::InvokeRedirect(InvocationRedirect {
                        request: correlation,
                        leader,
                    }));
                }
                let input = {
                    // Holding the host across preparation and local Raft
                    // append prevents an apply notification from changing the
                    // journal parent between those two boundaries.
                    let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                    drain_committed(&mut host, self.agent, &self.ordered_replies)
                        .map_err(|_| AgentHandlerError)?;
                    #[cfg(feature = "experimental-state-blocks")]
                    {
                        let exact = crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                            context: RuntimeExecutionContext::Direct,
                            work: work.clone(),
                            authorization: authorization.clone(),
                        };
                        if let Some(proof) = host
                            .inspect_external_retained_reply(self.agent, &exact)
                            .map_err(|_| AgentHandlerError)?
                        {
                            drop(host);
                            drop(proposal);
                            let outcome = self
                                .require_retained_external_availability(&exact, &proof)
                                .map_err(|_| AgentHandlerError)?;
                            return Ok(reply_for_outcome(correlation, outcome));
                        }
                    }
                    let prepared = host
                        .prepare_clean_ordered(self.agent, work.clone(), authorization)
                        .map_err(|_| AgentHandlerError)?;
                    if let Some(outcome) = prepared.retained().cloned() {
                        let input = prepared.input();
                        drop(host);
                        drop(proposal);
                        self.require_ordered_availability(input).map_err(|_| AgentHandlerError)?;
                        return Ok(reply_for_outcome(correlation, outcome));
                    }
                    let input = prepared.input();
                    self.ordered_replies.register(input)?;
                    let payload = prepared.into_payload().ok_or(AgentHandlerError)?;
                    if futures_executor::block_on(worker.propose(payload)).is_err() {
                        self.ordered_replies.cancel(input);
                        return Err(AgentHandlerError);
                    }
                    input
                };
                // Catch a single-node commit whose notification raced the
                // waiter after the host lock was released.
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                drain_committed(&mut host, self.agent, &self.ordered_replies)
                    .map_err(|_| AgentHandlerError)?;
                drop(host);
                let outcome = self.ordered_replies.wait(input)?;
                drop(proposal);
                self.require_ordered_availability(input).map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
            MethodMode::Merge => {
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let outcome = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .apply_clean_merge(self.agent, work, authorization)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
            MethodMode::LocalQuery | MethodMode::Local => {
                let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
                if proposal.is_reserved() {
                    return Err(AgentHandlerError);
                }
                let outcome = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .apply_clean_local(self.agent, work, authorization)
                    .map_err(|_| AgentHandlerError)?;
                Ok(reply_for_outcome(correlation, outcome))
            }
        }
    }

    fn handle_raft(
        &self,
        sender: NodeId,
        message: RaftMessage,
    ) -> Result<AgentMessage, AgentHandlerError> {
        let worker = self.worker.as_ref().ok_or(AgentHandlerError)?;
        let response = match message {
            RaftMessage::AppendRequest {
                term,
                leader,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                let entries = entries
                    .into_iter()
                    .map(|entry| LogEntry {
                        term: entry.term,
                        index: entry.index,
                        kind: match entry.kind {
                            RaftLogEntryKind::Command(payload) => EntryKind::Data { payload },
                            RaftLogEntryKind::Configuration { members, joint_old } => {
                                EntryKind::ConfigChange { members, joint_old }
                            }
                        },
                    })
                    .collect();
                let reply = futures_executor::block_on(worker.handle_authenticated_inbound_append(
                    sender,
                    vos_raft::AppendEntriesReq {
                        term,
                        leader,
                        prev_log_index,
                        prev_log_term,
                        entries,
                        leader_commit,
                    },
                ));
                RaftMessage::AppendReply {
                    term: reply.term,
                    success: reply.success,
                    match_index: reply.match_index,
                }
            }
            RaftMessage::VoteRequest {
                phase,
                term,
                candidate,
                last_log_index,
                last_log_term,
            } => match phase {
                RaftVotePhase::Vote => {
                    let reply =
                        futures_executor::block_on(worker.handle_authenticated_inbound_vote(
                            sender,
                            vos_raft::RequestVoteReq {
                                term,
                                candidate,
                                last_log_index,
                                last_log_term,
                            },
                        ));
                    RaftMessage::VoteReply {
                        phase,
                        term: reply.term,
                        granted: reply.vote_granted,
                    }
                }
                RaftVotePhase::PreVote => {
                    let reply =
                        futures_executor::block_on(worker.handle_authenticated_inbound_prevote(
                            sender,
                            vos_raft::PreVoteReq {
                                next_term: term,
                                candidate,
                                last_log_index,
                                last_log_term,
                            },
                        ));
                    RaftMessage::VoteReply {
                        phase,
                        term: reply.term,
                        granted: reply.vote_granted,
                    }
                }
            },
            // Generic snapshot bytes are never an authenticated Shared-Agent
            // journal certificate. Refuse before the worker/storage mutates.
            RaftMessage::InstallSnapshotRequest { .. } => {
                return Err(AgentHandlerError);
            }
            RaftMessage::StatusRequest => {
                let snapshot = futures_executor::block_on(worker.snapshot());
                let last_applied = self
                    .host
                    .lock()
                    .ok()
                    .and_then(|host| host.show(self.agent).ok().flatten())
                    .map(|status| status.applied_slots)
                    .unwrap_or(0);
                return Ok(AgentMessage::Raft(RaftMessage::StatusReply(snapshot.map(
                    |snapshot| RaftStatus {
                        role: match snapshot.role {
                            vos_raft::Role::Follower => RaftRole::Follower,
                            vos_raft::Role::PreCandidate => RaftRole::PreCandidate,
                            vos_raft::Role::Candidate => RaftRole::Candidate,
                            vos_raft::Role::Leader => RaftRole::Leader,
                        },
                        current_term: snapshot.current_term,
                        commit_index: snapshot.commit_index,
                        last_applied,
                        last_log_index: snapshot.last_log_index,
                        members: snapshot.members,
                        joint_old: snapshot.joint_old,
                        active_config_index: snapshot.active_config_index,
                        leader: if snapshot.role == vos_raft::Role::Leader {
                            Some(self.network.agent_node_id())
                        } else {
                            snapshot.leader_hint
                        },
                    },
                ))));
            }
            _ => return Err(AgentHandlerError),
        };
        Ok(AgentMessage::Raft(response))
    }

    fn local_merge_heads(&self) -> Result<AgentMessage, AgentHandlerError> {
        let mut heads = self
            .host
            .lock()
            .map_err(|_| AgentHandlerError)?
            .merge_roots(self.agent)
            .map_err(|_| AgentHandlerError)?
            .into_iter()
            .map(Hash)
            .collect::<Vec<_>>();
        heads.sort_unstable();
        Ok(AgentMessage::Merge(MergeMessage::Heads(heads)))
    }

    fn sync_merge_heads(&self, sender: NodeId, heads: Vec<Hash>) -> Result<(), AgentHandlerError> {
        // An empty frontier cannot import anything. The independent apply
        // thread owns committed-log draining; this no-op must not compete
        // with projection or checkpoint admission for either mutex.
        if heads.is_empty() {
            return Ok(());
        }
        // Imported Merge events consume the same authenticated composite
        // suffix budget as the reserved projection pair. Hold admission for
        // the complete sync/import pass so neither ingress nor the background
        // pump can race the exact headroom check.
        let proposal = self.proposal.lock().map_err(|_| AgentHandlerError)?;
        if proposal.is_reserved() {
            return Err(AgentHandlerError);
        }
        // First bring every already-committed Ordered base into the journal;
        // a Merge event may never synthesize or outrun that boundary.
        if let Ok(mut host) = self.host.lock() {
            drain_committed(&mut host, self.agent, &self.ordered_replies)
                .map_err(|_| AgentHandlerError)?;
        } else {
            return Err(AgentHandlerError);
        }

        let mut pending = heads;
        let mut seen = BTreeSet::new();
        let mut fetched = BTreeMap::<MergeEventId, MergeEvent>::new();
        let mut scanned_bytes = 0usize;
        let mut fetched_events = 0usize;
        let mut fetched_bytes = 0usize;
        let deadline = Instant::now() + MERGE_SYNC_BUDGET;
        while let Some(hash) = pending.pop() {
            if !seen.insert(hash) {
                continue;
            }
            if seen.len() > MAX_MERGE_SYNC_SCAN_EVENTS {
                return Err(AgentHandlerError);
            }
            let event_id = MergeEventId(hash.0);
            let local = self
                .host
                .lock()
                .map_err(|_| AgentHandlerError)?
                .merge_object(self.agent, event_id)
                .map_err(|_| AgentHandlerError)?;
            let needs_staging = merge_object_needs_staging(&local);
            let bytes = match local {
                SharedMergeObject::Published(_) => continue,
                SharedMergeObject::Staged(bytes) => bytes,
                SharedMergeObject::Missing => {
                    if fetched_events >= MAX_MERGE_SYNC_EVENTS {
                        break;
                    }
                    let Some(remaining) = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                    else {
                        break;
                    };
                    let bytes = self
                        .network
                        .send_agent_merge_fetch_node(sender, self.route, hash)
                        .recv_timeout(remaining.min(AGENT_REQUEST_TIMEOUT))
                        .map_err(|_| AgentHandlerError)?
                        .map_err(|_| AgentHandlerError)?
                        .ok_or(AgentHandlerError)?;
                    let next_bytes = fetched_bytes
                        .checked_add(bytes.len())
                        .ok_or(AgentHandlerError)?;
                    // Leave this object missing and retry it in the next pump
                    // rather than exceeding a declared per-pass fetch budget.
                    // Already staged ancestors do not consume the next pass's
                    // network budget, so this still makes forward progress.
                    if next_bytes > MAX_MERGE_SYNC_BYTES {
                        break;
                    }
                    fetched_events += 1;
                    fetched_bytes = next_bytes;
                    bytes
                }
            };
            if bytes.is_empty() || bytes.len() > MAX_JOURNAL_RECORD_BYTES {
                return Err(AgentHandlerError);
            }
            scanned_bytes = scanned_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_REPLAY_SUFFIX_BYTES)
                .ok_or(AgentHandlerError)?;
            let event = MergeEvent::decode(&bytes).map_err(|_| AgentHandlerError)?;
            if event.id() != event_id || event.encode() != bytes {
                return Err(AgentHandlerError);
            }
            if needs_staging {
                self.host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .stage_merge(self.agent, &event)
                    .map_err(|_| AgentHandlerError)?;
            }
            pending.extend(event.parents.iter().map(|parent| Hash(*parent.as_bytes())));
            fetched.insert(event_id, event);
        }

        let mut ordered = fetched.into_values().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|event| (event.causal_height, event.id()));
        let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
        let mut imported_events = 0usize;
        let mut imported_bytes = 0usize;
        for event in ordered {
            if imported_events == MAX_MERGE_SYNC_EVENTS || Instant::now() >= deadline {
                break;
            }
            let mut parents_published = true;
            for parent in &event.parents {
                if !matches!(
                    host.merge_object(self.agent, *parent)
                        .map_err(|_| AgentHandlerError)?,
                    SharedMergeObject::Published(_)
                ) {
                    parents_published = false;
                    break;
                }
            }
            if !parents_published {
                continue;
            }
            let event_bytes = event.encode().len();
            let Some(next_bytes) = imported_bytes.checked_add(event_bytes) else {
                return Err(AgentHandlerError);
            };
            if next_bytes > MAX_MERGE_SYNC_BYTES {
                break;
            }
            match host
                .import_merge(self.agent, &event)
                .map_err(|_| AgentHandlerError)?
            {
                SharedAgentApplyOutcome::Applied { .. }
                | SharedAgentApplyOutcome::Duplicate { .. } => {}
                SharedAgentApplyOutcome::Idle => return Err(AgentHandlerError),
            }
            imported_events += 1;
            imported_bytes = next_bytes;
        }
        Ok(())
    }

    fn handle_merge(
        &self,
        sender: NodeId,
        message: MergeMessage,
    ) -> Result<AgentMessage, AgentHandlerError> {
        match message {
            MergeMessage::FetchHeads => self.local_merge_heads(),
            MergeMessage::AnnounceHeads(heads) => {
                self.sync_merge_heads(sender, heads)?;
                self.local_merge_heads()
            }
            MergeMessage::FetchNode(hash) => {
                let bytes = self
                    .host
                    .lock()
                    .map_err(|_| AgentHandlerError)?
                    .merge_node(self.agent, MergeEventId(hash.0))
                    .map_err(|_| AgentHandlerError)?;
                if let Some(bytes) = &bytes {
                    let event = MergeEvent::decode(bytes).map_err(|_| AgentHandlerError)?;
                    if event.id().as_bytes() != hash.as_bytes() || event.encode() != *bytes {
                        return Err(AgentHandlerError);
                    }
                }
                Ok(AgentMessage::Merge(MergeMessage::Node { hash, bytes }))
            }
            _ => Err(AgentHandlerError),
        }
    }
}

impl AgentRouteHandler for SharedRouteHandler {
    fn handle(&self, request: AuthenticatedAgentFrame) -> Result<AgentMessage, AgentHandlerError> {
        // Hold a shared generation lease through the complete bounded handler
        // call. Retirement takes the exclusive side before removing the route,
        // so a registration cloned by the network loop cannot mutate after
        // its exact generation has been revoked.
        let live = self.lifecycle.read().map_err(|_| AgentHandlerError)?;
        if !*live {
            return Err(AgentHandlerError);
        }
        let sender = request.sender();
        let frame = request.into_frame();
        if frame.route != self.route {
            return Err(AgentHandlerError);
        }
        #[cfg(test)]
        if self.raft_isolated.load(Ordering::Acquire)
            && matches!(&frame.message, AgentMessage::Raft(_))
        {
            return Err(AgentHandlerError);
        }
        let recovering = matches!(&frame.message, AgentMessage::ProjectionRecoveryRequest(_));
        match frame.message {
            AgentMessage::RecoveryExpiryVoteRequest(claim) => {
                let commitment = Hash(claim.commitment().0);
                let result = self.sign_projection_expiry(&claim);
                #[cfg(test)]
                if let Err(error) = &result
                    && std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some()
                {
                    eprintln!(
                        "recovery_expiry_vote node={:?} request={:?} error={error:?}",
                        self.network.agent_node_id(),
                        claim.request(),
                    );
                }
                let signature = result.ok();
                Ok(AgentMessage::RecoveryExpiryVoteReply {
                    claim: commitment,
                    signature,
                })
            }
            AgentMessage::RecoveryExpiryRequest { request } => {
                let result = self.expire_projection_recovery(crate::service::Hash(request.0));
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "recovery_expiry_request node={:?} request={request:?} result={:?}",
                        self.network.agent_node_id(),
                        result.as_ref().map(|_| ()),
                    );
                }
                let applied = result.is_ok();
                Ok(AgentMessage::RecoveryExpiryReply { request, applied })
            }
            AgentMessage::RecoveryRegistrationRequest(registration) => {
                let commitment = Hash(registration.commitment().0);
                let applied = self.route_nodes.binary_search(&sender).is_ok()
                    && self.register_projection_recovery(&registration).is_ok();
                Ok(AgentMessage::RecoveryRegistrationReply { registration: commitment, applied })
            }
            AgentMessage::CommonSnapshotVoteRequest(claim) => {
                let commitment = Hash(claim.commitment().0);
                let signature = (|| {
                    #[cfg(test)]
                    let trace_refusal = |reason: &str| {
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!("common_vote early_refusal node={:?} reason={reason} expected={:?}", self.network.agent_node_id(), claim.commitment().0);
                        }
                    };
                    let _proposal = self.proposal.try_lock().map_err(|error| {
                        #[cfg(test)]
                        trace_refusal(match error {
                            std::sync::TryLockError::WouldBlock => "proposal_busy",
                            std::sync::TryLockError::Poisoned(_) => "proposal_poisoned",
                        });
                        #[cfg(not(test))]
                        let _ = error;
                    }).ok()?;
                    let mut host = self.host.lock().map_err(|_| {
                        #[cfg(test)]
                        trace_refusal("host_poisoned");
                    }).ok()?;
                    drain_committed(&mut host, self.agent, &self.ordered_replies).map_err(|_| {
                        #[cfg(test)]
                        trace_refusal("drain_committed");
                    }).ok()?;
                    let status = host.supervisor_attachment_status(self.agent).map_err(|_| {
                        #[cfg(test)]
                        trace_refusal("attachment_status");
                    }).ok()?.or_else(|| {
                        #[cfg(test)]
                        trace_refusal("missing_attachment");
                        None
                    })?;
                    let fingerprint = AttachmentFingerprint::from_attachment_status(&status).map_err(|_| {
                        #[cfg(test)]
                        trace_refusal("attachment_fingerprint");
                    }).ok()?;
                    if status.transport != SharedAgentTransportState::Attached
                        || fingerprint.protocol_route != self.route
                        || fingerprint.next_committee.is_some()
                        || fingerprint.joint_old.is_some()
                        || fingerprint.voters.len() != 3
                        || fingerprint.voters.binary_search(&sender).is_err()
                        || fingerprint
                            .voters
                            .binary_search(&self.network.agent_node_id())
                            .is_err()
                    {
                        #[cfg(test)]
                        trace_refusal("attachment_scope");
                        return None;
                    }
                    let signed = host.sign_common_snapshot_candidate(self.agent, &claim);
                    #[cfg(test)]
                    if let Err(error) = &signed
                        && std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some()
                    {
                        eprintln!("common_vote local_refusal node={:?} error={error:?} expected={:?}", self.network.agent_node_id(), claim.commitment().0);
                        match host.request_common_snapshot_compaction(self.agent) {
                            Ok(actual) => if let Ok(manifest) = host.recovery_manifest(self.agent) {
                                trace_common_checkpoint_material_for_test("refusing_voter", crate::service::NodeId(self.network.agent_node_id().0), actual.claim(), &manifest);
                            },
                            Err(error) => eprintln!("common_vote local_candidate_error node={:?} error={error:?}", self.network.agent_node_id()),
                        }
                    }
                    signed.ok()
                })();
                Ok(AgentMessage::CommonSnapshotVoteReply {
                    claim: commitment,
                    signature,
                })
            }
            AgentMessage::CurrentAppliedAvailabilityRequest(request) => {
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                let status = host
                    .supervisor_attachment_status(self.agent)
                    .map_err(|_| AgentHandlerError)?
                    .ok_or(AgentHandlerError)?;
                let fingerprint = AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|_| AgentHandlerError)?;
                let local = NodeId(host.scope().node.0);
                let current_voter = fingerprint.protocol_route == self.route
                    && fingerprint.next_committee.is_none()
                    && fingerprint.joint_old.is_none()
                    && fingerprint.voters.len() == 3
                    && fingerprint.voters.binary_search(&sender).is_ok()
                    && fingerprint.voters.binary_search(&local).is_ok();
                #[cfg(feature = "experimental-state-blocks")]
                let available = current_voter
                    && host
                        .verify_current_ordered_availability(
                            self.agent,
                            request.raft_index,
                            request.raft_term,
                            crate::service::Hash(request.claim.0),
                        )
                        .is_ok();
                #[cfg(not(feature = "experimental-state-blocks"))]
                let available = {
                    let _ = current_voter;
                    false
                };
                Ok(AgentMessage::CurrentAppliedAvailabilityReply { request, available })
            }
            AgentMessage::AppliedAvailabilityRequest(request) => {
                #[cfg(test)]
                let started = Instant::now();
                let mut host = self.host.lock().map_err(|_| AgentHandlerError)?;
                let status = host.supervisor_attachment_status(self.agent)
                    .map_err(|_| AgentHandlerError)?.ok_or(AgentHandlerError)?;
                let fingerprint = AttachmentFingerprint::from_attachment_status(&status)
                    .map_err(|_| AgentHandlerError)?;
                let local = NodeId(host.scope().node.0);
                let available = fingerprint.protocol_route == self.route
                    && fingerprint.next_committee.is_none()
                    && fingerprint.joint_old.is_none()
                    && matches!(fingerprint.voters.len(), 1 | 3)
                    && fingerprint.voters.binary_search(&sender).is_ok()
                    && fingerprint.voters.binary_search(&local).is_ok()
                    && host.verify_ordered_availability(
                        self.agent, request.raft_index, request.raft_term,
                        crate::service::Hash(request.claim.0),
                    ).map_err(|error| {
                        #[cfg(test)]
                        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                            eprintln!("availability_remote node={local:?} raft={}/{} claim={:?} error={error:?} elapsed_us={}", request.raft_index, request.raft_term, request.claim, started.elapsed().as_micros());
                        }
                        #[cfg(not(test))]
                        let _ = error;
                    }).is_ok();
                #[cfg(test)]
                if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                    eprintln!("availability_remote node={local:?} raft={}/{} claim={:?} available={available} elapsed_us={}", request.raft_index, request.raft_term, request.claim, started.elapsed().as_micros());
                }
                Ok(AgentMessage::AppliedAvailabilityReply { request, available })
            }
            AgentMessage::ProjectionRequest(query)
            | AgentMessage::ProjectionRecoveryRequest(query) => {
                let request = query.commitment();
                let accepted = self
                    .worker
                    .as_ref()
                    .is_some_and(|worker| worker.role() == vos_raft::Role::Leader)
                    && self
                        .projection_dispatch
                        .lock()
                        .map_err(|_| AgentHandlerError)?
                        .as_ref()
                        .is_some_and(|dispatch| dispatch(query, recovering, sender));
                Ok(AgentMessage::ProjectionAccepted { request, accepted })
            }
            AgentMessage::InvokeRequest(request) => self.handle_invocation(sender, request),
            AgentMessage::Raft(message) => self.handle_raft(sender, message),
            AgentMessage::Merge(message) => self.handle_merge(sender, message),
            _ => Err(AgentHandlerError),
        }
    }
}

struct AttachedGeneration {
    fingerprint: AttachmentFingerprint,
    handler: Arc<dyn AgentRouteHandler>,
    coordinator: Arc<SharedRouteHandler>,
    worker: Option<vos_raft::Worker<NodeId>>,
    apply_thread: Option<JoinHandle<()>>,
    merge_stop: Arc<AtomicBool>,
    merge_thread: Option<JoinHandle<()>>,
    stale: Arc<AtomicBool>,
    lifecycle: Arc<RwLock<bool>>,
}

struct SharedGenerationAccess<'a> {
    coordinator: &'a SharedRouteHandler,
    fingerprint: &'a AttachmentFingerprint,
    stale: &'a AtomicBool,
}

/// Non-owning, exact-generation access for an ordinary supervisor route.
/// Closed handles cannot retain the physical host or network worker. Each
/// operation upgrades the coordinator and takes its generation lifecycle lease.
#[derive(Clone)]
pub(crate) struct SharedAgentRouteHandle {
    coordinator: std::sync::Weak<SharedRouteHandler>,
    fingerprint: AttachmentFingerprint,
    stale: Arc<AtomicBool>,
}

impl SharedAgentRouteHandle {
    pub(crate) fn agent(&self) -> vos_agent_sdk::AgentId {
        vos_agent_sdk::AgentId(self.fingerprint.durable_route.agent().0)
    }

    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.coordinator.ptr_eq(&other.coordinator) && self.fingerprint == other.fingerprint
    }

    fn with_generation<T>(
        &self,
        operation: impl FnOnce(
            &SharedAgentHost,
            crate::service::AgentId,
            &crate::agent::shared_host::SharedAgentAttachmentStatus,
        ) -> Result<T, SharedAgentHostError>,
    ) -> Result<T, SharedAgentHostError> {
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = coordinator
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || self.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let host = coordinator
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(coordinator.agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != self.fingerprint
        {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let result = operation(&host, coordinator.agent, &status)?;
        if self.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(result)
    }

    pub(crate) fn projection(&self) -> Result<SharedAgentRuntimeProjection, SharedAgentHostError> {
        self.with_generation(|host, agent, status| {
            let projection = host.clean_runtime_projection(agent)?;
            if !projection_matches_attachment_status(&projection, status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(projection)
        })
    }

    pub(crate) fn material(
        &self,
        actor: vos_agent_sdk::ActorId,
    ) -> Result<
        crate::agent::invocation_preparation::PhysicalInvocationMaterial,
        SharedAgentHostError,
    > {
        self.with_generation(|host, agent, status| {
            let material = host.supervisor_invocation_material(agent, actor)?;
            let projection = SharedAgentRuntimeProjection {
                descriptor: material.descriptor.clone(),
                actors: vec![material.actor.clone()],
            };
            if !projection_matches_attachment_status(&projection, status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            Ok(material)
        })
    }

    pub(crate) fn execute(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        use crate::agent::shared_journal_driver::CleanInvocationReplayRequest;
        if matches!(
            &request,
            CleanInvocationReplayRequest::Invoke { context, .. }
                | CleanInvocationReplayRequest::Resume { context, .. }
                if !context.is_direct()
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        SharedAgentNetworkHost::execute_generation(
            SharedGenerationAccess {
                coordinator: &coordinator,
                fingerprint: &self.fingerprint,
                stale: &self.stale,
            },
            expected,
            request,
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn audit(
        &self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.with_generation(|host, agent, _| {
            host.audit_agent_authority_projection(agent, head, projected)
        })
    }
}

fn acquire_route_activation<'a>(
    lifecycle: &'a RwLock<bool>,
    stale: &AtomicBool,
) -> Option<std::sync::RwLockReadGuard<'a, bool>> {
    let live = lifecycle.read().ok()?;
    if !*live || stale.load(Ordering::Acquire) {
        // Return only after the rejected read lease has left scope. Cleanup
        // takes the exclusive side and must never self-deadlock on this guard.
        return None;
    }
    Some(live)
}

fn retire_route_with_lease(
    network: &Network,
    route: AgentGenerationRoute,
    handler: &Arc<dyn AgentRouteHandler>,
    lifecycle: &RwLock<bool>,
) {
    // Remove the directory entry first so the finite ingress permit set is a
    // hard upper bound on registrations which could already have cloned this
    // owner. Then take the exclusive lease and drain those in-flight calls.
    network.retire_agent_route(route, handler);
    let mut live = lifecycle
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *live = false;
    // Attachment activation holds a read lease while publishing its route.
    // If this retirement raced that activation, the first removal may have
    // happened before the route existed. Once the exclusive lease is ours,
    // activation has finished and a second pointer-qualified removal closes
    // that race without reopening ingress starvation.
    network.retire_agent_route(route, handler);
}

/// Owning live attachment for every generation currently opened by a Shared
/// host. Dropping it retires exact route owners before stopping workers.
pub struct SharedAgentNetworkHost {
    projection_dispatch: Arc<Mutex<Option<ProjectionDispatch>>>,
    host: Arc<Mutex<SharedAgentHost>>,
    network: Arc<Network>,
    generations: BTreeMap<crate::service::AgentId, AttachedGeneration>,
    // Retain system identity across refresh/checkpoint reattachment so the
    // applicable promotion and recovery barriers still guard route exposure.
    // Audited stable-three followers may register before leader promotion.
    system_agents: BTreeSet<crate::service::AgentId>,
    // Exact pending envelopes outlive a volatile route/worker generation.
    // Startup callers must seed these from independently verified durable
    // lifecycle stores before any system route is activated.
    management_retirements:
        BTreeMap<crate::service::AgentId, Vec<[crate::agent_sdk::RuntimeWork; 2]>>,
    management_pending: BTreeMap<crate::service::AgentId, Vec<PendingManagement>>,
    #[cfg(test)]
    force_checkpoint_once: bool,
    #[cfg(test)]
    fail_reattach_once: bool,
}

pub(crate) type ProjectionDispatch = Arc<
    dyn Fn(crate::agent_sdk::authority::AuthorityProjectionQuery, bool, NodeId) -> bool
        + Send
        + Sync,
>;

/// Reserves the host's storage boundary before any worker database handle,
/// route, or background thread is created. Failed setup releases the
/// `Attaching` state only after all later-declared resources have dropped.
struct TransportAttachReservation {
    host: Arc<Mutex<SharedAgentHost>>,
    agent: crate::service::AgentId,
    armed: bool,
}

impl TransportAttachReservation {
    fn reserve(
        host: Arc<Mutex<SharedAgentHost>>,
        agent: crate::service::AgentId,
    ) -> Result<Self, SharedAgentHostError> {
        host.lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .reserve_transport_attachment(agent)?;
        Ok(Self {
            host,
            agent,
            armed: true,
        })
    }

    fn mark_attached(&mut self) -> Result<(), SharedAgentHostError> {
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .mark_transport_attached(self.agent)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TransportAttachReservation {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut host) = self.host.lock() {
                let _ = host.release_transport_attachment(self.agent);
            }
        }
    }
}

impl SharedAgentNetworkHost {
    pub(crate) fn retained_projection_expiry(
        &self,
        agent: crate::service::AgentId,
        request: crate::service::Hash,
    ) -> Result<Option<SharedRecoveryExpiryTerminal>, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        let terminal = host.recovery_expiry_terminal(agent, request)?;
        if let Some(terminal) = &terminal {
            SharedRouteHandler::release_expired_projection_key(
                &mut proposal,
                &mut host,
                agent,
                terminal,
            )?;
        }
        Ok(terminal)
    }

    pub(crate) fn expire_projection_recovery(
        &self,
        agent: crate::service::AgentId,
        request: crate::service::Hash,
    ) -> Result<SharedRecoveryExpiryTerminal, SharedAgentHostError> {
        if let Some(terminal) = self.retained_projection_expiry(agent, request)? {
            return Ok(terminal);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::Unavailable)?;
        if attached.coordinator.has_local_proposer(worker) {
            return attached.coordinator.expire_projection_recovery(request);
        }
        let leader = worker
            .cached_snapshot()
            .and_then(|snapshot| snapshot.leader_hint)
            .filter(|node| {
                *node != self.network.agent_node_id()
                    && attached.fingerprint.voters.binary_search(node).is_ok()
            })
            .ok_or(SharedAgentHostError::Unavailable)?;
        if !self
            .network
            .send_agent_recovery_expiry(
                leader,
                attached.fingerprint.protocol_route,
                Hash(request.0),
            )
            .recv_timeout(ORDERED_REPLY_WAIT)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        loop {
            if let Some(terminal) = self.retained_projection_expiry(agent, request)? {
                return Ok(terminal);
            }
            if Instant::now() >= deadline {
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn complete_expired_projection_pair<F>(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        request: crate::service::Hash,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let key = ProjectionPairKey::new(work, authorization);
        if proposal.projection_pair.is_some_and(|held| held != key)
            || proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        let terminal = host
            .recovery_expiry_terminal(agent, request)?
            .ok_or(SharedAgentHostError::Unavailable)?;
        let manifest = host.recovery_manifest(agent)?;
        if !manifest.slots().iter().any(|slot| {
            slot.expiry() == Some(&terminal)
                && slot.registration().request().request_commitment() == request
                && slot.registration().work() == work
                && slot.registration().authorization() == authorization
        }) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // The exact applied terminal, never local time or a peer's boolean,
        // authorizes cleanup. Failed durable clear retains the caller's key.
        complete()?;
        if proposal.projection_pair == Some(key) {
            proposal.projection_pair = None;
        }
        if proposal
            .registration_append
            .is_some_and(|pending| pending.key == key)
        {
            proposal.registration_append = None;
        }
        Ok(())
    }

    /// Isolate only the actual Raft transport; keep the live owner, worker,
    /// admission keys and authenticated application RPCs for election tests.
    #[cfg(test)]
    pub(crate) fn set_raft_isolated_for_test(
        &self,
        agent: crate::service::AgentId,
        isolated: bool,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .raft_isolated
            .store(isolated, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pending_registration_append_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<Option<(u64, u64, [u8; 32])>, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(proposal
            .registration_append
            .map(|pending| (pending.index, pending.term, pending.command.0)))
    }

    #[cfg(test)]
    pub(crate) fn projection_admission_state_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<(u64, u64, Option<([u8; 32], [u8; 32], [u8; 32])>), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let snapshot = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        Ok((
            snapshot.last_log_index,
            snapshot.commit_index,
            proposal
                .projection_pair
                .map(|key| (key.invocation.0, key.work.0, key.authorization.0)),
        ))
    }

    /// Qualification only: repeat an applied input in a new, valid Ordered
    /// successor. Reusing the old immutable entry at another Raft position
    /// would violate its publication binding instead of exercising replay.
    #[cfg(test)]
    pub(crate) fn append_repeated_projection_for_test(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        acknowledgement: bool,
    ) -> Result<u64, SharedAgentHostError> {
        use crate::agent::journal::{OrderedEntry, ReplayOperation};
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let _proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let snapshot = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        let committed = quiescent_projection_commit(
            snapshot.role,
            snapshot.commit_index,
            snapshot.last_log_index,
            false,
        )?;
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        if host.capacity(agent)?.0 != committed {
            return Err(SharedAgentHostError::Unavailable);
        }
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let position = host.journal_position(agent)?;
        let database = host.raft_database(agent)?;
        let log = RaftLog::open(database).map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let end = snapshot
            .last_log_index
            .checked_add(1)
            .ok_or(SharedAgentHostError::CorruptResidue)?;
        let entries = log
            .entries(snapshot.last_log_index, end)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let [entry] = entries.as_slice() else {
            return Err(SharedAgentHostError::CorruptResidue);
        };
        let EntryKind::Data { payload } = shared_raft::decode_agent_raft_entry_kind(&entry.payload)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        let command = shared_raft::AgentRaftCommand::decode(&payload)
            .map_err(|_| SharedAgentHostError::CorruptResidue)?;
        let shared_raft::AgentRaftCommand::Ordered {
            route,
            artifact_batch: None,
            entry,
        } = &command
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if *route != attached.fingerprint.durable_route || command.encode() != payload {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let matches = match &entry.input.operation {
            ReplayOperation::CleanInvoke {
                work: original,
                authorization: original_auth,
                ..
            } if !acknowledgement => original == work && original_auth == authorization,
            ReplayOperation::CleanAcknowledge {
                work: original,
                authorization: original_auth,
                ..
            } if acknowledgement => {
                *original == crate::agent_sdk::InvocationRetirement::from_work(work)
                    && original_auth == authorization
            }
            _ => false,
        };
        if !matches
            || position.genesis != entry.genesis
            || position.ordered_index != entry.index
            || position.ordered_head != Some(entry.id())
            || position.merge_frontier != entry.merge_frontier
            || entry.merge_seal.is_some()
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let repeated = shared_raft::AgentRaftCommand::Ordered {
            route: *route,
            artifact_batch: None,
            entry: OrderedEntry {
                genesis: entry.genesis,
                index: entry
                    .index
                    .checked_add(1)
                    .ok_or(SharedAgentHostError::CorruptResidue)?,
                parent: Some(entry.id()),
                merge_frontier: entry.merge_frontier,
                merge_seal: None,
                input: entry.input.clone(),
            },
        };
        repeated
            .validate()
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let payload = repeated.encode();
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if after.current_term != snapshot.current_term
            || after.role != snapshot.role
            || after.commit_index != snapshot.commit_index
            || after.last_log_index != snapshot.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        drop(host);
        futures_executor::block_on(worker.propose(payload))
            .map_err(|_| SharedAgentHostError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn assert_late_registration_refused_for_test(
        &self,
        agent: crate::service::AgentId,
        registration: &SharedRecoveryRegistration,
    ) {
        let coordinator = &self.generations.get(&agent).unwrap().coordinator;
        let worker = coordinator.worker.as_ref().unwrap();
        let before = futures_executor::block_on(worker.snapshot()).unwrap();
        let pair = coordinator.proposal.lock().unwrap().projection_pair;
        let manifest = self.projection_recovery_manifest(agent).unwrap();
        assert_eq!(
            coordinator.register_projection_recovery(registration),
            Err(SharedAgentHostError::Conflict)
        );
        let after = futures_executor::block_on(worker.snapshot()).unwrap();
        assert_eq!(after.current_term, before.current_term);
        assert_eq!(after.commit_index, before.commit_index);
        assert_eq!(after.last_log_index, before.last_log_index);
        assert_eq!(coordinator.proposal.lock().unwrap().projection_pair, pair);
        assert_eq!(self.projection_recovery_manifest(agent).unwrap(), manifest);
    }

    /// Reconcile a locally retained legacy lifecycle, never admit custody.
    /// The quiescent prefix excludes a still-uncommitted registration tail;
    /// exact existing custody always requires the owner's normal durable hold.
    pub(crate) fn legacy_projection_without_custody(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live
            || attached.stale.load(Ordering::Acquire)
            || attached.fingerprint.members.len() != 3
            || attached.fingerprint.voters.len() != 3
            || attached.fingerprint.next_committee.is_some()
            || attached.fingerprint.joint_old.is_some()
            || work.agent.0 != agent.0
            || !authorization.matches_work(work)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let coordinator = &attached.coordinator;
        let mut proposal = coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        coordinator.reconcile_registration_append(&mut proposal)?;
        let key = ProjectionPairKey::new(work, authorization);
        if proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
            || proposal.projection_pair.is_some_and(|held| held != key)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let before = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if before.commit_index != before.last_log_index {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &coordinator.ordered_replies)?;
        if host.capacity(agent)?.0 != before.commit_index {
            return Err(SharedAgentHostError::Unavailable);
        }
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let manifest = host.recovery_manifest(agent)?;
        let legacy = !has_projection_recovery_custody(&manifest, work, authorization)
            && (host.retained_terminal_projection_invoke(agent, work, authorization)?
                || host.retained_positive_clean_acknowledgement(agent, work, authorization)?);
        let after = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if after.current_term != before.current_term
            || after.role != before.role
            || after.commit_index != before.commit_index
            || after.last_log_index != before.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        Ok(legacy)
    }

    pub(crate) fn projection_recovery_manifest(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<SharedRecoveryManifest, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        host.recovery_manifest(agent)
    }

    pub(crate) fn register_projection_recovery(
        &self,
        agent: crate::service::AgentId,
        registration: &SharedRecoveryRegistration,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.coordinator.has_local_proposer(worker) {
            return attached
                .coordinator
                .register_projection_recovery(registration);
        }
        let leader = worker
            .cached_snapshot()
            .and_then(|snapshot| snapshot.leader_hint)
            .filter(|node| {
                *node != self.network.agent_node_id()
                    && attached.coordinator.route_nodes.binary_search(node).is_ok()
            })
            .ok_or(SharedAgentHostError::Unavailable)?;
        if !self
            .network
            .send_agent_recovery_registration(
                leader,
                attached.fingerprint.protocol_route,
                registration.clone(),
            )
            .recv_timeout(ORDERED_REPLY_WAIT)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map_err(|_| SharedAgentHostError::Unavailable)?
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        // A positive peer reply is not this replica's materialization. Require
        // the exact registration to apply locally before forwarding the read.
        let deadline = Instant::now() + ORDERED_REPLY_WAIT;
        loop {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
            if host
                .recovery_manifest(agent)?
                .slot(registration.owner())
                .is_some_and(|slot| slot.registration() == registration)
            {
                return Ok(());
            }
            drop(host);
            if Instant::now() >= deadline {
                return Err(SharedAgentHostError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A follower retains its own durable delivery obligation while another
    /// admitted owner executes the read. This does not grant local proposal
    /// authority or bypass the leader's normal invocation admission.
    pub(crate) fn reserve_forwarded_projection_pair(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live
            || attached.stale.load(Ordering::Acquire)
            || attached.fingerprint.voters.len() != 3
            || attached.fingerprint.next_committee.is_some()
            || attached.fingerprint.joint_old.is_some()
            || work.agent.0 != agent.0
            || !authorization.matches_work(work)
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        attached
            .coordinator
            .reconcile_registration_append(&mut proposal)?;
        let key = ProjectionPairKey::new(work, authorization);
        if proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
            || proposal.projection_pair.is_some_and(|held| held != key)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        proposal.projection_pair = Some(key);
        Ok(())
    }

    /// Temporarily serve a committed custody dependency while preserving a
    /// different, not-yet-admitted local WAL intent. No durable slot is cleared
    /// or replaced here; the exact committed/applied barrier proves which
    /// registration won admission before switching the volatile execution key.
    pub(crate) fn reserve_registered_projection_dependency(
        &self,
        agent: crate::service::AgentId,
        intent: &SharedRecoveryRegistration,
        dependency: &SharedRecoveryRegistration,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live
            || attached.stale.load(Ordering::Acquire)
            || attached.fingerprint.members.len() != 3
            || attached.fingerprint.voters.len() != 3
            || attached.fingerprint.next_committee.is_some()
            || attached.fingerprint.joint_old.is_some()
            || intent.owner().0 != self.network.agent_node_id().0
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let coordinator = &attached.coordinator;
        let mut proposal = coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let intent_key = ProjectionPairKey::new(intent.work(), intent.authorization());
        let dependency_key = ProjectionPairKey::new(dependency.work(), dependency.authorization());
        if intent_key == dependency_key
            || proposal.management_pending.is_some()
            || proposal.management_retirement.is_some()
            || proposal
                .projection_pair
                .is_some_and(|key| key != intent_key && key != dependency_key)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let worker = coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            return Err(SharedAgentHostError::Unavailable);
        }
        let mut host = coordinator
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &coordinator.ordered_replies)?;
        let applied = host.capacity(agent)?.0;
        let current = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        ProjectionBarrier::from(&barrier)
            .validate_applied(ProjectionBarrier::from(&current), applied)?;
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let manifest = host.recovery_manifest(agent)?;
        intent
            .verify(manifest.generation(), manifest.committee())
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        dependency
            .verify(manifest.generation(), manifest.committee())
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        let intent_unregistered = match manifest.slot(intent.owner()) {
            None => intent.sequence() == 1 && intent.previous().is_none(),
            Some(previous) => {
                previous.is_terminal()
                    && previous.sequence().checked_add(1) == Some(intent.sequence())
                    && intent.previous() == Some(previous.commitment())
            }
        };
        if !intent_unregistered
            || !manifest
                .slot(dependency.owner())
                .is_some_and(|slot| slot.registration() == dependency && !slot.is_terminal())
        {
            return Err(SharedAgentHostError::Conflict);
        }
        proposal.projection_pair = Some(dependency_key);
        Ok(())
    }

    pub(crate) fn reconcile_completed_projection_dependency(
        &self,
        agent: crate::service::AgentId,
        intent: &SharedRecoveryRegistration,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live
            || attached.stale.load(Ordering::Acquire)
            || intent.owner().0 != self.network.agent_node_id().0
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let coordinator = &attached.coordinator;
        let mut proposal = coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let Some(held) = proposal.projection_pair else {
            return Ok(());
        };
        if held == ProjectionPairKey::new(intent.work(), intent.authorization()) {
            return Ok(());
        }
        let mut host = coordinator
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &coordinator.ordered_replies)?;
        let manifest = host.recovery_manifest(agent)?;
        intent
            .verify(manifest.generation(), manifest.committee())
            .map_err(|_| SharedAgentHostError::ScopeMismatch)?;
        // A prior helper may have lost leadership before observing ACK.
        // Exact durable terminal evidence allows only that volatile key
        // to retire, on followers too. The local intent WAL stays intact.
        proposal.reconcile_completed_dependency(
            ProjectionPairKey::new(intent.work(), intent.authorization()),
            &manifest,
        );
        Ok(())
    }

    /// Verify only one exact signed delegated read against this live route.
    /// This grants no reservation; submit repeats the check under its guard.
    pub(crate) fn validate_delegated_projection(
        &self,
        pending: &crate::agent::clean_bootstrap::PendingAuthorityProjection,
        sender: NodeId,
    ) -> Result<(), SharedAgentHostError> {
        let (query, work, authorization) = pending
            .delegated_projection()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        let attached = self
            .generations
            .get(&crate::service::AgentId(work.agent.0))
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .validate_delegated_projection(query, work, authorization, sender)
    }

    pub(crate) fn install_projection_dispatch(
        &mut self,
        dispatch: ProjectionDispatch,
    ) -> Result<(), SharedAgentHostError> {
        let mut current = self
            .projection_dispatch
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if current.is_some() {
            return Err(SharedAgentHostError::Conflict);
        }
        *current = Some(dispatch);
        Ok(())
    }

    pub(crate) fn forward_projection(
        &self,
        agent: crate::service::AgentId,
        query: crate::agent_sdk::authority::AuthorityProjectionQuery,
        recovering: bool,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let leader = worker
            .cached_snapshot()
            .and_then(|snapshot| snapshot.leader_hint)
            .filter(|node| {
                *node != self.network.agent_node_id()
                    && attached.coordinator.route_nodes.binary_search(node).is_ok()
            })
            .ok_or(SharedAgentHostError::Unavailable)?;
        self.network
            .send_agent_projection(
                leader,
                attached.fingerprint.protocol_route,
                query,
                recovering,
            )
            .recv_timeout(ORDERED_REPLY_WAIT)
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .map_err(|_| SharedAgentHostError::Unavailable)
    }

    pub(crate) fn retained_projection(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
    ) -> Result<Option<RuntimeOutcome>, SharedAgentHostError> {
        #[cfg(test)]
        let started = Instant::now();
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        let retained = host.retained_acknowledged_projection_with_input(agent, work).map_err(|error| {
            #[cfg(test)]
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!("retained_projection node={:?} invocation={:?} phase=local_error error={error:?} elapsed_us={}", self.network.agent_node_id(), work.invocation, started.elapsed().as_micros());
            }
            error
        })?;
        drop(host);
        #[cfg(test)]
        if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
            eprintln!(
                "retained_projection node={:?} invocation={:?} phase=local_result present={} elapsed_us={}",
                self.network.agent_node_id(),
                work.invocation,
                retained.is_some(),
                started.elapsed().as_micros()
            );
        }
        let Some((input, outcome)) = retained else {
            return Ok(None);
        };
        attached.coordinator.require_ordered_availability(input)?;
        Ok(Some(outcome))
    }

    pub(crate) fn projection_acknowledged(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        host.retained_positive_clean_acknowledgement(agent, work, authorization)
    }
    pub fn attach(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_internal(host, network, None, None, None, None)
    }

    /// Retain consensus transport while a fixed-roster system bootstrap waits
    /// for election. No serving owner exists at this stage. Ordinary recovered
    /// generations must continue through their admission-aware attachment path.
    pub(crate) fn attach_pending_system(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
    ) -> Result<Self, SharedAgentHostError> {
        let statuses = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .list()?;
        if statuses.len() != 1 || statuses[0].generation.agent() != agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // The synchronous promotion barrier cannot run until peers can reach
        // our registered route. Pending completion checks it after attachment.
        let mut attachment = Self::attach_internal(host, network, None, None, None, None)?;
        attachment.system_agents.insert(agent);
        Ok(attachment)
    }

    /// Attach the one-voter clean system Agent. With no durable pending
    /// projection, checkpoint before a mandatory leader no-op could combine
    /// with one retained uncommitted physical row and overrun the evidence
    /// suffix. Snapshot installation preserves that tail but resets its
    /// authenticated capacity domain at the applied boundary.
    pub(crate) fn attach_system(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<Self, SharedAgentHostError> {
        let needs_checkpoint = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .show(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?
            .remaining_slots
            <= 1;
        if needs_checkpoint {
            let mut locked = host.lock().map_err(|_| SharedAgentHostError::Unavailable)?;
            Self::install_detached_checkpoint(&mut locked, agent, expected_committee, signer)?;
        }
        Self::attach_internal(host, network, None, Some(agent), None, None)
    }

    /// Reopen a system host with the exact durable pending projection pair
    /// already excluded before its route is activated. No ingress or Merge
    /// pump can consume replay headroom in the attach-to-recovery window.
    pub(crate) fn attach_recovering_projection(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<Self, SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let deferred_promotion = expected_committee.members().len() > 1;
        if deferred_promotion {
            let statuses = host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .list()?;
            if expected_committee.members().len() != 3
                || expected_committee.voter_count() != 3
                || statuses.len() != 1
                || statuses[0].generation.agent() != agent
                || statuses[0].route.committee() != expected_committee.id()
                || statuses[0].committee_transition.is_some()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        // Multi-voter election needs the route that attachment registers.
        // Seed the same exact projection reservation and audit its capacity
        // (including the election no-op) before registration, but defer the
        // leader wait until the retained owner attempts execution. This is
        // not ordinary admission and grants no follower execution authority.
        let mut attachment = Self::attach_internal(
            host,
            network,
            Some(RecoveringProjectionAdmission {
                agent,
                work,
                authorization,
                expected_committee,
                signer,
            }),
            (!deferred_promotion).then_some(agent),
            None,
            None,
        )?;
        attachment.system_agents.insert(agent);
        Ok(attachment)
    }

    /// Restore an independently verified pending retirement before publishing
    /// the system route. Unlike Query recovery, do not checkpoint away missing
    /// Linear invocation/acknowledgement evidence to make this attachment fit.
    pub(crate) fn attach_recovering_management_retirement(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        envelopes: [crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<Self, SharedAgentHostError> {
        Self::attach_recovering_management_retirement_set(host, network, agent, vec![envelopes])
    }

    /// All pairs must come from independently verified durable intents. Keep
    /// the whole set reserved before publishing any worker route; completing
    /// one pair must not expose capacity retained for another pending intent.
    pub(crate) fn attach_recovering_management_retirement_set(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pairs: Vec<[crate::agent_sdk::RuntimeWork; 2]>,
    ) -> Result<Self, SharedAgentHostError> {
        if pairs.is_empty() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Self::attach_recovering_management_set(host, network, agent, vec![], pairs)
    }

    /// The caller must independently verify the durable intent set and its
    /// pre-dispatch anchors before supplying it. This publishes no unguarded
    /// generation between attachment and exact pending-work recovery.
    pub(crate) fn attach_recovering_management_pending(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pending: Vec<PendingManagement>,
    ) -> Result<Self, SharedAgentHostError> {
        pending_management_keys(agent, &pending)?;
        Self::attach_recovering_management_set(host, network, agent, pending, vec![])
    }

    /// Seed both independently verified recovery classes before route
    /// publication. No identity may belong to both admission classes.
    pub(crate) fn attach_recovering_management_set(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        agent: crate::service::AgentId,
        pending: Vec<PendingManagement>,
        retiring: Vec<[crate::agent_sdk::RuntimeWork; 2]>,
    ) -> Result<Self, SharedAgentHostError> {
        if pending.is_empty() && retiring.is_empty() {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let mut seen = BTreeSet::new();
        if !pending.is_empty() {
            for (key, _) in pending_management_keys(agent, &pending)? {
                seen.insert(key.invocation);
            }
        }
        if !retiring.is_empty() {
            for key in management_retirement_set_keys(agent, &retirement_pair_refs(&retiring))?
                .into_iter()
                .flatten()
            {
                if !seen.insert(key.invocation) {
                    return Err(SharedAgentHostError::ScopeMismatch);
                }
            }
        }
        if seen.len() > MAX_REPLAY_SUFFIX_ENTRIES {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        Self::attach_internal(
            host,
            network,
            None,
            Some(agent),
            (!retiring.is_empty()).then_some((agent, retiring)),
            (!pending.is_empty()).then_some((agent, pending)),
        )
    }

    fn attach_internal<'a>(
        host: Arc<Mutex<SharedAgentHost>>,
        network: Arc<Network>,
        recovering: Option<RecoveringProjectionAdmission<'a>>,
        promotion_barrier: Option<crate::service::AgentId>,
        retirement: Option<(
            crate::service::AgentId,
            Vec<[crate::agent_sdk::RuntimeWork; 2]>,
        )>,
        pending: Option<(crate::service::AgentId, Vec<PendingManagement>)>,
    ) -> Result<Self, SharedAgentHostError> {
        let statuses = host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .list()?;
        let mut attachment = Self {
            projection_dispatch: Arc::new(Mutex::new(None)),
            host,
            network,
            generations: BTreeMap::new(),
            system_agents: promotion_barrier.into_iter().collect(),
            management_retirements: retirement.into_iter().collect(),
            management_pending: pending.into_iter().collect(),
            #[cfg(test)]
            force_checkpoint_once: false,
            #[cfg(test)]
            fail_reattach_once: false,
        };
        for status in statuses {
            if status.local_role.is_some() {
                let pending = recovering
                    .as_ref()
                    .filter(|pending| pending.agent == status.generation.agent())
                    .map(|pending| pending);
                let barrier = promotion_barrier == Some(status.generation.agent());
                attachment.attach_status(status, pending, barrier)?;
            }
        }
        if recovering
            .as_ref()
            .is_some_and(|pending| !attachment.generations.contains_key(&pending.agent))
        {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        if attachment
            .management_retirements
            .keys()
            .chain(attachment.management_pending.keys())
            .any(|agent| !attachment.generations.contains_key(agent))
        {
            return Err(SharedAgentHostError::AgentNotFound);
        }
        Ok(attachment)
    }

    fn install_detached_projection_checkpoint(
        host: &mut SharedAgentHost,
        recovering: &RecoveringProjectionAdmission<'_>,
    ) -> Result<(), SharedAgentHostError> {
        Self::install_detached_checkpoint(
            host,
            recovering.agent,
            recovering.expected_committee,
            recovering.signer,
        )
    }

    fn install_detached_checkpoint(
        host: &mut SharedAgentHost,
        agent: crate::service::AgentId,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        if expected_committee.members().len() != 1
            || expected_committee.voter_count() != 1
            || expected_committee
                .member_by_node(signer.node())
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let candidate = host.request_snapshot_compaction(agent)?;
        if candidate.claim().active_committee() != expected_committee {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let signature = signer
            .sign_snapshot_candidate(&candidate)
            .ok_or(SharedAgentHostError::SnapshotCertificateInvalid)?;
        let certificate =
            SharedAgentSnapshotCertificate::new(candidate.claim().clone(), vec![signature])
                .map_err(|_| SharedAgentHostError::SnapshotCertificateInvalid)?;
        host.install_snapshot(agent, &certificate)?;

        Ok(())
    }

    /// Repair a missing/stale live transport attachment from durable host
    /// status before any projection capacity decision. This also closes the
    /// same-process retry edge after snapshot installation succeeded but its
    /// first reattachment attempt failed.
    pub(crate) fn ensure_reattached(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        self.refresh()?;
        self.generations
            .contains_key(&agent)
            .then_some(())
            .ok_or(SharedAgentHostError::TransportNotAttached)
    }

    pub(crate) fn reserve_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        recovering: bool,
    ) -> Result<(), SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if recovering {
            let stale = self
                .generations
                .get(&agent)
                .is_some_and(|attached| attached.stale.load(Ordering::Acquire));
            if stale {
                self.retire(agent)?;
            }
            if !self.generations.contains_key(&agent) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
        } else {
            self.ensure_reattached(agent)?;
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .reserve_projection_pair(work, authorization, recovering)
    }

    pub(crate) fn reserve_management_retirement(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        self.reserve_management_retirement_set(agent, &[envelopes])
    }

    pub(crate) fn record_management_anchor<F, T>(
        &self,
        agent: crate::service::AgentId,
        envelope: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(
            crate::agent::clean_management_intent::ManagementJournalAnchor,
        ) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .record_management_anchor(envelope, record)
    }

    /// The caller must authenticate the phase transition and pledge the exact
    /// returned envelope/anchor, including when retrying an ambiguous commit.
    pub(crate) fn extend_management_pending<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        predecessor: &PendingManagement,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let pending = self
            .management_pending
            .get_mut(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        attached.coordinator.extend_management_pending(
            pending,
            self.management_retirements
                .get(&agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            Some(predecessor),
            proposed,
            record,
        )
    }

    /// Scheduling hint only: never authorizes work or releases exclusion.
    /// Include retained attachment state as well as the active coordinator so
    /// refresh/recovery cannot briefly advertise a free management lane.
    pub(crate) fn management_admission_held(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::Unavailable)?;
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        Ok(self.management_pending.contains_key(&agent)
            || self.management_retirements.contains_key(&agent)
            || proposal.management_pending.is_some()
            || proposal.management_retirement.is_some())
    }

    /// Reserve the initial immutable envelope and its journal anchor before
    /// publishing the intent. Retain admission after an ambiguous store error;
    /// an exact retry receives the original clock and anchor. This reserves the
    /// authorization/ACK plus a conservative bounded finalization/ACK delta.
    pub(crate) fn capture_management_pending<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let pending = self.management_pending.entry(agent).or_default();
        let result = attached.coordinator.extend_management_pending(
            pending,
            self.management_retirements
                .get(&agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            None,
            proposed,
            record,
        );
        // Admission failures before reservation must not leave an empty root
        // refresh record. Callback failures keep the nonempty candidate.
        if pending.is_empty() {
            self.management_pending.remove(&agent);
        }
        result
    }

    /// Repair capacity only before a fresh management reservation exists.
    /// The full capture check (not the smaller projection budget) decides
    /// whether compaction is needed and rechecks both budgets afterwards.
    pub(crate) fn capture_management_pending_with_checkpoint<F, T>(
        &mut self,
        agent: crate::service::AgentId,
        proposed: &crate::agent_sdk::RuntimeWork,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        record: F,
    ) -> Result<T, SharedAgentHostError>
    where
        F: FnOnce(&PendingManagement) -> Result<T, SharedAgentHostError>,
    {
        self.ensure_reattached(agent)?;
        let mut record = Some(record);
        let result = self.capture_management_pending(agent, proposed, |pending| {
            record.take().expect("capture callback runs once")(pending)
        });
        if !matches!(result, Err(SharedAgentHostError::CapacityExhausted))
            || record.is_none()
            || self.management_pending.contains_key(&agent)
            || self.management_retirements.contains_key(&agent)
        {
            // A callback error (even CapacityExhausted) is publication
            // ambiguity, never permission to compact or retry the callback.
            return result;
        }
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = proposed
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        self.certified_checkpoint_for_admission(
            agent,
            invocation,
            authorization,
            expected_committee,
            signer,
        )?;
        self.capture_management_pending(agent, proposed, record.expect("unpublished callback"))
    }

    /// Recover an exact in-process reservation after a failed publication.
    /// This does not create admission or infer completion from a missing file.
    pub(crate) fn retained_management_pending(
        &self,
        agent: crate::service::AgentId,
        invocation: crate::agent_sdk::InvocationId,
    ) -> Result<Option<PendingManagement>, SharedAgentHostError> {
        let found = self.management_pending.get(&agent).and_then(|pending| {
            pending.iter().find(|(_, envelope)| {
                matches!(envelope, crate::agent_sdk::RuntimeWork::Invoke { invocation: work, .. }
                    if work.invocation == invocation)
            })
        });
        if let Some((anchor, envelope)) = found {
            self.ensure_management_pending_member(agent, anchor, envelope)?;
        }
        Ok(found.cloned())
    }

    /// Publish signed terminal retirement before releasing its exact pending
    /// member. A failed store callback retains both admission and refresh state.
    /// Completed signed records may release after pruning without replaying.
    pub(crate) fn finish_pending_management_result<F>(
        &mut self,
        agent: crate::service::AgentId,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
        completed: bool,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let key = (management_envelope_key(agent, envelope)?, anchor.clone());
        let Some(pending) = self.management_pending.get(&agent) else {
            return if completed {
                Ok(())
            } else {
                Err(SharedAgentHostError::Conflict)
            };
        };
        let keys = pending_management_keys(agent, pending)?;
        if !keys.contains(&key) {
            return if completed {
                Ok(())
            } else {
                Err(SharedAgentHostError::Conflict)
            };
        }
        let remaining: Vec<_> = pending
            .iter()
            .zip(&keys)
            .filter(|(_, old)| **old != key)
            .map(|(entry, _)| entry.clone())
            .collect();
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let mut proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_pending.as_ref() != Some(&keys) {
            return Err(SharedAgentHostError::Conflict);
        }
        if !completed {
            let crate::agent_sdk::RuntimeWork::Invoke {
                invocation,
                authorization,
                ..
            } = envelope
            else {
                return Err(SharedAgentHostError::ScopeMismatch);
            };
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !host.retained_positive_clean_acknowledgement(agent, invocation, authorization)? {
                return Err(SharedAgentHostError::Conflict);
            }
            // Keep host and proposal locks across the independent store write.
            complete()?;
        } else {
            complete()?;
        }
        proposal.management_pending = if remaining.is_empty() {
            None
        } else {
            Some(pending_management_keys(agent, &remaining)?)
        };
        if remaining.is_empty() {
            self.management_pending.remove(&agent);
        } else {
            self.management_pending.insert(agent, remaining);
        }
        Ok(())
    }

    /// A saved live intent may resume only under its exact restored reservation.
    /// Possession of an old envelope is not permission to dispatch unprotected.
    pub(crate) fn ensure_management_pending_member(
        &self,
        agent: crate::service::AgentId,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<(), SharedAgentHostError> {
        let key = management_envelope_key(agent, envelope)?;
        let pending = self
            .management_pending
            .get(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        let keys = pending_management_keys(agent, pending)?;
        if !keys.contains(&(key, anchor.clone())) {
            return Err(SharedAgentHostError::Conflict);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let proposal = attached
            .coordinator
            .proposal
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if proposal.management_pending.as_ref() != Some(&keys) {
            return Err(SharedAgentHostError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn reserve_management_retirement_set(
        &mut self,
        agent: crate::service::AgentId,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .reserve_management_retirement_set(pairs)?;
        self.management_retirements.entry(agent).or_insert_with(|| {
            pairs
                .iter()
                .map(|pair| [pair[0].clone(), pair[1].clone()])
                .collect()
        });
        Ok(())
    }

    /// Transfer finished pairs from the verified pending set without opening admission
    /// between invocation recovery and positive-acknowledgement retirement.
    /// Preserve existing retirement pairs and every remaining anchored pending
    /// envelope; supply only newly finished pairs, which may be a strict subset.
    pub(crate) fn handoff_management_pending_to_retirement(
        &mut self,
        agent: crate::service::AgentId,
        pairs: &[[&crate::agent_sdk::RuntimeWork; 2]],
    ) -> Result<(), SharedAgentHostError> {
        let moved = management_retirement_set_keys(agent, pairs)?;
        // A failed retirement-store publication may already have completed
        // handoff. Revalidate the exact existing pair without duplicating it.
        if self
            .management_retirements
            .get(&agent)
            .is_some_and(|existing| {
                management_retirement_set_keys(agent, &retirement_pair_refs(existing))
                    .is_ok_and(|keys| moved.iter().all(|pair| keys.contains(pair)))
            })
        {
            return self.reserve_management_retirement_set(agent, pairs);
        }
        let pending = self
            .management_pending
            .get(&agent)
            .ok_or(SharedAgentHostError::Conflict)?;
        let pending_keys = pending_management_keys(agent, pending)?;
        let remaining: Vec<_> = pending
            .iter()
            .zip(pending_keys.iter())
            .filter(|(_, (key, _))| !moved.iter().flatten().any(|expected| expected == key))
            .map(|(entry, _)| entry.clone())
            .collect();
        let mut combined = self
            .management_retirements
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        combined.extend(pairs.iter().map(|pair| [pair[0].clone(), pair[1].clone()]));
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached.coordinator.transition_management_retirement_set(
            &retirement_pair_refs(&combined),
            Some(&remaining),
        )?;
        self.management_retirements.insert(agent, combined);
        if remaining.is_empty() {
            self.management_pending.remove(&agent);
        } else {
            self.management_pending.insert(agent, remaining);
        }
        Ok(())
    }

    pub(crate) fn complete_management_retirement<F>(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .complete_management_retirement(envelopes, complete)?;
        drop(live);
        self.remove_management_retirement_pair(agent, envelopes)?;
        Ok(())
    }

    /// Only the lifecycle owner may release from a verified durable intent
    /// retirement marker, including after an ambiguous successful commit.
    pub(crate) fn release_completed_management_retirement(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(agent, envelopes)?;
        if let Some(pending) = self.management_retirements.get(&agent)
            && !management_retirement_set_keys(agent, &retirement_pair_refs(pending))?
                .contains(&keys)
        {
            return Err(SharedAgentHostError::Conflict);
        }
        let Some(attached) = self.generations.get(&agent) else {
            self.remove_management_retirement_pair(agent, envelopes)?;
            return Ok(());
        };
        attached
            .coordinator
            .release_completed_management_retirement(envelopes)?;
        self.remove_management_retirement_pair(agent, envelopes)?;
        Ok(())
    }

    fn remove_management_retirement_pair(
        &mut self,
        agent: crate::service::AgentId,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<(), SharedAgentHostError> {
        let keys = management_retirement_keys(agent, envelopes)?;
        if let Some(pending) = self.management_retirements.get_mut(&agent) {
            let all = management_retirement_set_keys(agent, &retirement_pair_refs(pending))?;
            let index = all
                .iter()
                .position(|pair| *pair == keys)
                .ok_or(SharedAgentHostError::Conflict)?;
            pending.remove(index);
            if pending.is_empty() {
                self.management_retirements.remove(&agent);
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_recovering_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        if crate::service::AgentId(work.agent.0) != agent || !authorization.matches_work(work) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let stale = self
            .generations
            .get(&agent)
            .is_some_and(|attached| attached.stale.load(Ordering::Acquire));
        if stale {
            self.retire(agent)?;
        }
        if !self.generations.contains_key(&agent) {
            let status = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .show(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            let recovering = RecoveringProjectionAdmission {
                agent,
                work,
                authorization,
                expected_committee,
                signer,
            };
            self.attach_status(status, Some(&recovering), true)?;
        }
        self.reserve_projection_pair(agent, work, authorization, true)
    }

    pub(crate) fn release_projection_pair(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
    ) -> Result<(), SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        attached
            .coordinator
            .release_projection_pair(work, authorization)
    }

    pub(crate) fn complete_projection_pair<F>(
        &self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        complete: F,
    ) -> Result<(), SharedAgentHostError>
    where
        F: FnOnce() -> Result<(), SharedAgentHostError>,
    {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        attached
            .coordinator
            .complete_projection_pair(work, authorization, complete)
    }

    /// Install a quorum-authenticated journal checkpoint before the bounded
    /// Ordered suffix can strand a projection Invoke/Ack pair. Clean system
    /// Agents are structurally one local voter; every other committee shape
    /// fails closed rather than manufacturing a partial certificate.
    pub(crate) fn certified_checkpoint_for_projection_pair(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<bool, SharedAgentHostError> {
        self.ensure_reattached(agent)?;
        let (raft_fits, replay_fits) = {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let (_, remaining_slots, _) = host.capacity(agent)?;
            let required = host.projection_admission_records(agent, work, authorization, false)?;
            (
                remaining_slots >= (required as u64).saturating_add(u64::from(required != 0)),
                host.projection_pair_fits(agent, work, authorization)?,
            )
        };
        #[cfg(test)]
        let forced = core::mem::take(&mut self.force_checkpoint_once);
        #[cfg(not(test))]
        let forced = false;
        if !forced && raft_fits && replay_fits {
            return Ok(false);
        }
        self.certified_checkpoint_for_admission(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
        )?;
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let (_, remaining, _) = host.capacity(agent)?;
        let required = host
            .projection_admission_requirement(agent, work, authorization, false)?
            .ok_or(SharedAgentHostError::CapacityExhausted)?;
        if remaining < (required as u64).saturating_add(u64::from(required != 0))
            || !host.projection_pair_fits(agent, work, authorization)?
        {
            return Err(SharedAgentHostError::CapacityExhausted);
        }
        Ok(true)
    }

    /// Shared certificate/attachment mechanics; callers retain their own
    /// exact admission predicates. The gate excludes pending management and
    /// retirement before any snapshot can replace their anchored history.
    fn certified_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<(), SharedAgentHostError> {
        self.certified_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            false,
        )
        .map(|_| ())
    }

    /// Best-effort scheduling, but never best-effort authentication: busy
    /// admission gates are skipped atomically; certificate/storage failures
    /// retain the existing fail-closed behavior.
    pub(crate) fn checkpoint_projection_if_due(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<bool, SharedAgentHostError> {
        self.ensure_reattached(agent)?;
        let (_, remaining, reservation_pending) = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .capacity(agent)?;
        if reservation_pending
            || !projection_checkpoint_due(remaining, expected_committee.members().len())
        {
            return Ok(false);
        }
        self.certified_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            true,
        )
    }

    fn certified_checkpoint_for_admission_inner(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        only_if_idle: bool,
    ) -> Result<bool, SharedAgentHostError> {
        if expected_committee.members().len() != 1
            || expected_committee.voter_count() != 1
            || expected_committee
                .member_by_node(signer.node())
                .is_none_or(|member| member.replica().role != ReplicaRole::Voter)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if only_if_idle {
            let reserved = attached
                .coordinator
                .proposal
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .reserve_idle_checkpoint(ProjectionPairKey::new(work, authorization));
            if !reserved {
                return Ok(false);
            }
        } else {
            attached
                .coordinator
                .reserve_checkpoint_gate(work, authorization)?;
        }
        let certificate = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let candidate = match host.request_snapshot_compaction(agent) {
                Ok(candidate) => candidate,
                Err(error) => {
                    drop(host);
                    let _ = attached
                        .coordinator
                        .release_projection_pair(work, authorization);
                    return Err(error);
                }
            };
            if candidate.claim().active_committee() != expected_committee {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_projection_pair(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            }
            let Some(signature) = signer.sign_snapshot_candidate(&candidate) else {
                drop(host);
                let _ = attached
                    .coordinator
                    .release_projection_pair(work, authorization);
                return Err(SharedAgentHostError::SnapshotCertificateInvalid);
            };
            match SharedAgentSnapshotCertificate::new(candidate.claim().clone(), vec![signature]) {
                Ok(certificate) => certificate,
                Err(_) => {
                    drop(host);
                    let _ = attached
                        .coordinator
                        .release_projection_pair(work, authorization);
                    return Err(SharedAgentHostError::SnapshotCertificateInvalid);
                }
            }
        };

        // Only a fully reconstructed and locally signed candidate can retire
        // the live worker. Signer refusal and candidate errors release the
        // checkpoint gate while preserving the exact existing attachment.
        self.retire(agent)?;
        let checkpoint = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .install_snapshot(agent, &certificate);

        // Restart always reconstructs this attachment from durable host
        // status. In-process failures make the same attempt here regardless
        // of whether retirement, signing, or installation failed.
        let reattachment = self.reattach_current(agent);
        match (checkpoint, reattachment) {
            (Ok(_), Ok(())) => Ok(true),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    /// Explicit qualification path only. Automatic multi-voter pruning stays
    /// disabled until authenticated catch-up and retained-result availability
    /// have been qualified end to end.
    #[cfg(test)]
    pub(crate) fn certified_common_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        self.certified_common_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            true,
        )
    }

    /// Qualification-only collection cut. The fixture retires every voter at
    /// this certified foundation before testing filesystem publication. Retiring
    /// only the source would let the other two commit a new election boundary.
    #[cfg(test)]
    pub(crate) fn collect_common_checkpoint_for_admission(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        self.certified_common_checkpoint_for_admission_inner(
            agent,
            work,
            authorization,
            expected_committee,
            signer,
            false,
        )
    }

    #[cfg(test)]
    fn certified_common_checkpoint_for_admission_inner(
        &mut self,
        agent: crate::service::AgentId,
        work: &InvocationWork,
        authorization: &InvocationAuthorization,
        expected_committee: &AgentReplicaCommittee,
        signer: &dyn LocalMergeAuthenticator,
        install: bool,
    ) -> Result<SharedAgentCommonSnapshotCertificate, SharedAgentHostError> {
        let started = Instant::now();
        if expected_committee.members().len() != 3
            || expected_committee.voter_count() != 3
            || work.agent.0 != agent.0
            || !authorization.matches_work(work)
        {
            return Err(SharedAgentHostError::SnapshotCertificateInvalid);
        }
        self.ensure_reattached(agent)?;
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::Unavailable)?;
        let barrier = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if barrier.role != vos_raft::Role::Leader || barrier.commit_index != barrier.last_log_index
        {
            if std::env::var_os("VOS_TEST_BOOTSTRAP_DIAGNOSTICS").is_some() {
                eprintln!(
                    "common_checkpoint barrier_refusal node={:?} role={:?} term={} commit={} last={}",
                    self.network.agent_node_id(),
                    barrier.role,
                    barrier.current_term,
                    barrier.commit_index,
                    barrier.last_log_index
                );
            }
            return Err(SharedAgentHostError::Unavailable);
        }
        attached
            .coordinator
            .reserve_checkpoint_gate(work, authorization)?;
        let certificate = match attached
            .coordinator
            .collect_common_snapshot_certificate(expected_committee, signer)
        {
            Ok(certificate) => certificate,
            Err(error) => {
                let _ = attached
                    .coordinator
                    .release_projection_pair(work, authorization);
                return Err(error);
            }
        };
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(),
            phase = "quorum",
            "Common checkpoint phase complete"
        );
        if !install {
            return Ok(certificate);
        }
        self.retire(agent)?;
        let installed = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .install_common_snapshot(agent, &certificate);
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(), result = ?installed,
            phase = "install", "Common checkpoint phase complete"
        );
        let reattached = self.reattach_current(agent);
        tracing::debug!(
            elapsed_us = started.elapsed().as_micros(), result = ?reattached,
            phase = "reattach", "Common checkpoint phase complete"
        );
        match (installed, reattached) {
            (Ok(_), Ok(())) => Ok(certificate),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    fn reattach_current(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_reattach_once) {
            return Err(SharedAgentHostError::Unavailable);
        }
        if self.generations.contains_key(&agent) {
            return Ok(());
        }
        let status = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .show(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        self.attach_status(status, None, false)
    }

    #[cfg(test)]
    pub(crate) fn force_checkpoint_once_for_test(&mut self) {
        self.force_checkpoint_once = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_reattach_once_for_test(&mut self) {
        self.fail_reattach_once = true;
    }

    fn attach_status(
        &mut self,
        status: SharedAgentStatus,
        recovering: Option<&RecoveringProjectionAdmission<'_>>,
        promotion_barrier: bool,
    ) -> Result<(), SharedAgentHostError> {
        self.attach_status_with_recovery_checkpoint(status, recovering, promotion_barrier, true)
    }

    fn attach_status_with_recovery_checkpoint(
        &mut self,
        status: SharedAgentStatus,
        recovering: Option<&RecoveringProjectionAdmission<'_>>,
        promotion_barrier: bool,
        allow_checkpoint: bool,
    ) -> Result<(), SharedAgentHostError> {
        let agent = status.generation.agent();
        let retirement = self.management_retirements.get(&agent).cloned();
        let pending_management = self.management_pending.get(&agent).cloned();
        if recovering.is_some() && (retirement.is_some() || pending_management.is_some()) {
            return Err(SharedAgentHostError::Conflict);
        }
        if self.generations.contains_key(&agent) {
            return Err(SharedAgentHostError::Conflict);
        }
        let mut reservation = TransportAttachReservation::reserve(Arc::clone(&self.host), agent)?;
        let ordered_replies = Arc::new(OrderedReplyWaiters::default());
        // Recovery may reopen a database with durable commit_index ahead of
        // the journal application cursor. No new Raft event is guaranteed to
        // arrive, so drain that exact suffix before exposing a route or
        // deriving its current committee fingerprint.
        let attachment_status = {
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            host.supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?
        };
        // Recovery admission below needs only audited ledger capacity. Keep
        // each fresh audit under the same host lock, but do not ask `show` to
        // query actor lanes and snapshots whose results would be discarded.
        if let Some(pending) = &pending_management {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_recovery_admission_requirement(
                    agent,
                    &pending_management_refs(pending),
                    &retirement
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .flatten()
                        .collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            // Preserve every anchor; never checkpoint to make this set fit.
            if remaining < required as u64 + 1 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
        }
        if pending_management.is_none()
            && let Some(envelopes) = &retirement
        {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_retirement_set_admission_requirement(
                    agent,
                    &envelopes.iter().flatten().collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            // The new one-voter worker must append its current-term no-op.
            if remaining < required as u64 + 1 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
        }
        if let Some(recovering) = recovering {
            let (required, remaining) = {
                let host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let (_, remaining, _) = host.capacity(agent)?;
                (
                    host.projection_admission_requirement(
                        agent,
                        recovering.work,
                        recovering.authorization,
                        true,
                    )?,
                    remaining,
                )
            };
            let needs_checkpoint = required.is_none_or(|required| {
                remaining
                    < u64::try_from(required)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1)
            });
            if needs_checkpoint {
                if !allow_checkpoint {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                drop(reservation);
                {
                    let mut host = self
                        .host
                        .lock()
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    Self::install_detached_projection_checkpoint(&mut host, recovering)?;
                }
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                return self.attach_status_with_recovery_checkpoint(
                    status,
                    Some(recovering),
                    promotion_barrier,
                    false,
                );
            }
        }
        let fingerprint = AttachmentFingerprint::from_attachment_status(&attachment_status)?;
        let local = self.network.agent_node_id();
        if !fingerprint.validates_local(local) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // A stable fixed-three system route must be reachable before election,
        // just as during pending-system attachment. Defer only the implicit
        // system barrier; explicit and durable-operation barriers remain.
        // Every subsequent ordered submission still requires a local proposer.
        let promotion_barrier = fingerprint.requires_promotion_barrier(
            promotion_barrier,
            self.system_agents.contains(&agent),
            recovering.is_some(),
            pending_management.is_some(),
            retirement.is_some(),
        );
        let authenticated_snapshot = match status.snapshots {
            crate::agent::shared_host::SharedAgentSnapshotState::None => (0, 0),
            crate::agent::shared_host::SharedAgentSnapshotState::Installed {
                raft_index,
                raft_term,
                ..
            } => (raft_index, raft_term),
        };
        let route = fingerprint.protocol_route;
        #[cfg(test)]
        let raft_isolated = Arc::new(AtomicBool::new(false));
        let (mut worker, handle, receiver) = if fingerprint.owns_raft_worker(local)
            || (!promotion_barrier && fingerprint.runs_worker(local))
        {
            let database = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .raft_database(agent)?;
            let storage = AgentNodeStorage::open(database, authenticated_snapshot)
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            #[cfg(test)]
            let storage = {
                let mut storage = storage;
                storage.timing_node = local;
                storage
            };
            let transport = AgentRaftTransport::new(Arc::clone(&self.network), route);
            #[cfg(test)]
            let transport = transport.with_isolation(Arc::clone(&raft_isolated));
            let transport = Arc::new(transport);
            let mut config = vos_raft::Config::new(
                local,
                fingerprint.voters.clone(),
                attachment_status.replication_id,
            );
            config.max_append_entries = MAX_SHARED_RAFT_APPEND_ENTRIES;
            config.max_inflight_replications = 8;
            // Generic snapshots cannot represent an authenticated Agent
            // journal. Keep automatic compaction disabled until that bridge
            // carries the snapshot certificate/evidence protocol.
            config.compact_hysteresis = u64::MAX;
            let (sender, receiver) = std_mpsc::channel();
            let worker = vos_raft::Worker::try_spawn(storage, transport, config, Some(sender))
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            worker
                .wait_init()
                .map_err(|_| SharedAgentHostError::CorruptResidue)?;
            let handle = worker.handler();
            (Some(worker), Some(handle), Some(receiver))
        } else {
            // Behind a promotion barrier an observer cannot wait for its own
            // leadership; it serves Merge/route data without a worker.
            (None, None, None)
        };
        if promotion_barrier {
            let recovery_worker = handle
                .as_ref()
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            // Serialize behind leader promotion: role publication can precede
            // its mandatory current-term no-op commit advance by one worker
            // step. The snapshot barrier proves the no-op and every recovered
            // tail row are committed before we derive admission capacity.
            let committed = system_promotion_barrier(
                || recovery_worker.role(),
                || {
                    futures_executor::block_on(recovery_worker.snapshot())
                        .map(|state| (state.role, state.commit_index, state.last_log_index))
                },
                ORDERED_REPLY_WAIT,
            )?;
            let mut host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            drain_committed(&mut host, agent, &ordered_replies)?;
            if host.capacity(agent)?.0 != committed {
                return Err(SharedAgentHostError::CorruptResidue);
            }
        }
        if let Some(recovering) = recovering {
            let (required, remaining) = {
                let host = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                let (_, remaining, _) = host.capacity(agent)?;
                (
                    host.projection_admission_requirement(
                        agent,
                        recovering.work,
                        recovering.authorization,
                        true,
                    )?,
                    remaining,
                )
            };
            let capacity = required
                .is_some_and(|required| remaining >= u64::try_from(required).unwrap_or(u64::MAX));
            if !capacity {
                if let Some(worker) = worker.take() {
                    worker.shutdown();
                }
                drop(handle);
                drop(receiver);
                drop(reservation);
                if !allow_checkpoint {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                {
                    let mut host = self
                        .host
                        .lock()
                        .map_err(|_| SharedAgentHostError::Unavailable)?;
                    Self::install_detached_projection_checkpoint(&mut host, recovering)?;
                }
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                return self.attach_status_with_recovery_checkpoint(
                    status,
                    Some(recovering),
                    promotion_barrier,
                    false,
                );
            }
        }
        let lifecycle = Arc::new(RwLock::new(true));
        let apply_worker = handle.clone();
        let initial_admission = if let Some(recovering) = recovering {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let (_, remaining, _) = host.capacity(agent)?;
            let Some(required) = host.projection_admission_requirement(
                agent,
                recovering.work,
                recovering.authorization,
                true,
            )?
            else {
                return Err(SharedAgentHostError::CapacityExhausted);
            };
            if remaining < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                projection_pair: Some(ProjectionPairKey::new(
                    recovering.work,
                    recovering.authorization,
                )),
                ..ProposalAdmission::default()
            }
        } else if let Some(pending) = &pending_management {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_recovery_admission_requirement(
                    agent,
                    &pending_management_refs(pending),
                    &retirement
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .flatten()
                        .collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            if remaining < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                management_pending: Some(pending_management_keys(agent, pending)?),
                management_retirement: retirement
                    .as_ref()
                    .map(|pairs| {
                        management_retirement_set_keys(agent, &retirement_pair_refs(pairs))
                    })
                    .transpose()?,
                ..ProposalAdmission::default()
            }
        } else if let Some(envelopes) = &retirement {
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let required = host
                .management_retirement_set_admission_requirement(
                    agent,
                    &envelopes.iter().flatten().collect::<Vec<_>>(),
                )?
                .ok_or(SharedAgentHostError::CapacityExhausted)?;
            let (_, remaining, _) = host.capacity(agent)?;
            if remaining < required as u64 {
                return Err(SharedAgentHostError::CapacityExhausted);
            }
            ProposalAdmission {
                management_retirement: Some(management_retirement_set_keys(
                    agent,
                    &retirement_pair_refs(envelopes),
                )?),
                ..ProposalAdmission::default()
            }
        } else {
            ProposalAdmission::default()
        };
        let handler_impl = Arc::new(SharedRouteHandler {
            projection_dispatch: Arc::clone(&self.projection_dispatch),
            host: Arc::clone(&self.host),
            network: Arc::clone(&self.network),
            route,
            agent,
            route_nodes: fingerprint.members.iter().map(|(node, _)| *node).collect(),
            worker: handle,
            proposal: Mutex::new(initial_admission),
            committee_fence: AtomicBool::new(false),
            expiry: Mutex::new(()),
            ordered_replies: Arc::clone(&ordered_replies),
            lifecycle: Arc::clone(&lifecycle),
            #[cfg(test)]
            raft_isolated,
        });
        let handler: Arc<dyn AgentRouteHandler> = handler_impl.clone();
        let stale = Arc::new(AtomicBool::new(false));
        let merge_stop = Arc::new(AtomicBool::new(false));
        let apply_thread = if let Some(receiver) = receiver {
            let thread_worker = apply_worker;
            let host = Arc::clone(&self.host);
            let network = Arc::clone(&self.network);
            let route_handler = Arc::clone(&handler);
            let mut attached_fingerprint = fingerprint.clone();
            let thread_stale = Arc::clone(&stale);
            let thread_merge_stop = Arc::clone(&merge_stop);
            let thread_lifecycle = Arc::clone(&lifecycle);
            match std::thread::Builder::new()
                .name(format!("shared-agent-apply-{:02x?}", &agent.0[..4]))
                .spawn(move || {
                    while receiver.recv().is_ok() {
                        let Ok(mut host) = host.lock() else {
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        };
                        if let Err(error) = drain_committed(&mut host, agent, &ordered_replies) {
                            tracing::warn!(
                                ?agent,
                                ?error,
                                "retiring Shared route after committed replay failure"
                            );
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            drop(host);
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        }
                        let current = host
                            .supervisor_attachment_status(agent)
                            .ok()
                            .flatten()
                            .and_then(|status| {
                                AttachmentFingerprint::from_attachment_status(&status).ok()
                            });
                        if let Some(next) = current.as_ref().filter(|next| {
                            *next != &attached_fingerprint
                                && attached_fingerprint.continues_transition(next, local)
                        }) {
                            // Keep the worker and its term. Only widen the
                            // exact route owner to the authenticated next
                            // members so the leader can replicate to them.
                            let next = next.clone();
                            drop(host);
                            if network
                                .install_agent_route(
                                    route,
                                    next.members.clone(),
                                    Arc::clone(&route_handler),
                                )
                                .is_ok()
                            {
                                attached_fingerprint = next;
                                continue;
                            }
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        }
                        if current.as_ref() != Some(&attached_fingerprint) {
                            ordered_replies.fail_all();
                            thread_stale.store(true, Ordering::Release);
                            thread_merge_stop.store(true, Ordering::Release);
                            if let Some(worker) = &thread_worker {
                                let _ = worker.sender().send(vos_raft::RaftMsg::Shutdown);
                            }
                            drop(host);
                            retire_route_with_lease(
                                &network,
                                route,
                                &route_handler,
                                &thread_lifecycle,
                            );
                            return;
                        }
                    }
                    // A closed notifier without an owning retirement means
                    // the worker stopped unexpectedly. Revoke the route and
                    // synchronous waiters immediately; `refresh` may then
                    // reopen the exact durable generation with a fresh
                    // worker. Pointer-qualified retirement cannot remove a
                    // newer handler owner.
                    ordered_replies.fail_all();
                    thread_stale.store(true, Ordering::Release);
                    thread_merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&network, route, &route_handler, &thread_lifecycle);
                }) {
                Ok(thread) => Some(thread),
                Err(_) => {
                    merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&self.network, route, &handler, &lifecycle);
                    if let Some(worker) = worker.take() {
                        worker.shutdown();
                    }
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
        } else {
            None
        };
        let merge_thread = {
            let merge_handler = Arc::clone(&handler_impl);
            let thread_stop = Arc::clone(&merge_stop);
            match std::thread::Builder::new()
                .name(format!("shared-agent-merge-{:02x?}", &agent.0[..4]))
                .spawn(move || {
                    let mut cursor = 0;
                    while !thread_stop.load(Ordering::Acquire) {
                        merge_handler.pump_merge_once(local, &thread_stop, &mut cursor);
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(MERGE_PUMP_INTERVAL);
                    }
                }) {
                Ok(thread) => Some(thread),
                Err(_) => {
                    merge_stop.store(true, Ordering::Release);
                    retire_route_with_lease(&self.network, route, &handler, &lifecycle);
                    if let Some(worker) = worker.take() {
                        worker.shutdown();
                    }
                    if let Some(thread) = apply_thread {
                        let _ = thread.join();
                    }
                    return Err(SharedAgentHostError::Unavailable);
                }
            }
        };
        // Expose the route only after both live backends exist. A fast inbound
        // request must never observe a handler whose apply notifier or Merge
        // pump failed to start.
        let Some(activation) = acquire_route_activation(&lifecycle, &stale) else {
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        if self
            .network
            .install_agent_route(route, fingerprint.members.clone(), Arc::clone(&handler))
            .is_err()
        {
            drop(activation);
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if let Err(error) = reservation.mark_attached() {
            drop(activation);
            merge_stop.store(true, Ordering::Release);
            retire_route_with_lease(&self.network, route, &handler, &lifecycle);
            if let Some(worker) = worker.take() {
                worker.shutdown();
            }
            if let Some(thread) = apply_thread {
                let _ = thread.join();
            }
            if let Some(thread) = merge_thread {
                let _ = thread.join();
            }
            return Err(error);
        }
        self.generations.insert(
            agent,
            AttachedGeneration {
                fingerprint,
                handler,
                coordinator: handler_impl,
                worker,
                apply_thread,
                merge_stop,
                merge_thread,
                stale,
                lifecycle: Arc::clone(&lifecycle),
            },
        );
        drop(activation);
        Ok(())
    }

    /// Reconcile newly provisioned generations and exact committee/peer
    /// changes. Removal retires the route owner and its unshared bindings.
    pub fn refresh(&mut self) -> Result<(), SharedAgentHostError> {
        let statuses = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .attachment_statuses()?;
        let live = statuses
            .iter()
            .filter(|status| status.local_role.is_some())
            .map(|status| status.generation.agent())
            .collect::<BTreeSet<_>>();
        let retired = self
            .generations
            .keys()
            .copied()
            .filter(|agent| !live.contains(agent))
            .collect::<Vec<_>>();
        for agent in retired {
            self.retire(agent)?;
        }
        for status in statuses {
            if status.local_role.is_none() {
                continue;
            }
            let agent = status.generation.agent();
            let fingerprint = AttachmentFingerprint::from_attachment_status(&status)?;
            let local = self.network.agent_node_id();
            if let Some(attached) = self.generations.get_mut(&agent)
                && !attached.stale.load(Ordering::Acquire)
                && attached.fingerprint != fingerprint
                && attached
                    .fingerprint
                    .continues_transition(&fingerprint, local)
            {
                // A prepared or joint transition advances in place; restarting
                // the worker would insert a leader no-op inside it.
                let route = fingerprint.protocol_route;
                if self
                    .network
                    .install_agent_route(
                        route,
                        fingerprint.members.clone(),
                        Arc::clone(&attached.handler),
                    )
                    .is_ok()
                {
                    attached.fingerprint = fingerprint;
                    continue;
                }
            }
            let rebuild = self.generations.get(&agent).is_some_and(|attached| {
                attached.stale.load(Ordering::Acquire) || attached.fingerprint != fingerprint
            });
            if rebuild {
                self.retire(agent)?;
            }
            if !self.generations.contains_key(&agent) {
                // Initial/rebuilt attachment still needs the complete status
                // (including its authenticated snapshot). Refreshing an
                // unchanged fingerprint must not query unrelated actor lanes.
                let status = self
                    .host
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?
                    .show(agent)?
                    .ok_or(SharedAgentHostError::AgentNotFound)?;
                self.attach_status(status, None, false)?;
            }
        }
        Ok(())
    }

    /// Reconcile transport ownership, then project every live generation from
    /// its authenticated SDK descriptor and actor directory. The per-route
    /// lifecycle lease prevents a concurrent worker failure from leaving a
    /// projection visible after its exact network attachment was revoked.
    pub(crate) fn supervisor_projections(
        &mut self,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.supervisor_projections_scoped(None)
    }

    pub(crate) fn supervisor_projection_for(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.supervisor_projections_scoped(Some(agent))
    }

    pub(crate) fn supervisor_route_handle(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<SharedAgentRouteHandle, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(SharedAgentRouteHandle {
            coordinator: Arc::downgrade(&attached.coordinator),
            fingerprint: attached.fingerprint.clone(),
            stale: Arc::clone(&attached.stale),
        })
    }

    pub(crate) fn supervisor_generation_handles(
        &mut self,
    ) -> Result<Vec<SharedAgentRouteHandle>, SharedAgentHostError> {
        self.refresh()?;
        self.generations
            .keys()
            .map(|agent| self.supervisor_route_handle(*agent))
            .collect()
    }

    fn supervisor_projections_scoped(
        &mut self,
        only: Option<crate::service::AgentId>,
    ) -> Result<Vec<SharedAgentRuntimeProjection>, SharedAgentHostError> {
        self.refresh()?;
        let agents = match only {
            Some(agent) => vec![agent],
            None => self.generations.keys().copied().collect(),
        };
        let mut projections = Vec::with_capacity(agents.len());
        for agent in agents {
            let attached = self
                .generations
                .get(&agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            // Route operations always take the generation lease before the
            // host mutex. Retirement may update the host first, but drops
            // that mutex guard before taking the exclusive generation lease,
            // so there is no host -> lifecycle lock inversion.
            let live = attached
                .lifecycle
                .read()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !*live || attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let host = self
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let projection = host.clean_runtime_projection(agent)?;
            if !projection_matches_attachment_status(&projection, &status) {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
            if attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            projections.push(projection);
        }
        Ok(projections)
    }

    /// Reconcile transport ownership, hold every selected generation lease,
    /// and authenticate a complete authority subset against the same physical
    /// host/fingerprints used by invocation dispatch. A concurrent retirement
    /// marks the generation stale and makes the audit fail before publication.
    pub(crate) fn audit_authority_projection(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&crate::agent::invocation_preparation::PhysicalRootLineage>,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.audit_authority_projection_scoped(head, projected, root, false)
    }

    pub(crate) fn audit_system_authority_projection(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: &crate::agent::invocation_preparation::PhysicalRootLineage,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.audit_authority_projection_scoped(head, projected, Some(root), true)
    }

    fn audit_authority_projection_scoped(
        &mut self,
        head: crate::agent_sdk::authority::AuthorityProjectionHead,
        projected: &[crate::agent::supervisor_adapters::AgentAuthorityRouteProjection],
        root: Option<&crate::agent::invocation_preparation::PhysicalRootLineage>,
        system_only: bool,
    ) -> Result<crate::agent::shared_host::SharedAuthorityProjectionAudit, SharedAgentHostError>
    {
        self.refresh()?;
        let leased_agents = if system_only {
            vec![crate::service::AgentId(
                root.ok_or(SharedAgentHostError::ScopeMismatch)?.agent.0,
            )]
        } else {
            self.generations.keys().copied().collect::<Vec<_>>()
        };
        let mut leases = Vec::with_capacity(leased_agents.len());
        for agent in &leased_agents {
            let attached = self
                .generations
                .get(agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            let lease = attached
                .lifecycle
                .read()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            if !*lease || attached.stale.load(Ordering::Acquire) {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            leases.push(lease);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        for agent in &leased_agents {
            let attached = self
                .generations
                .get(agent)
                .ok_or(SharedAgentHostError::TransportNotAttached)?;
            let status = host
                .supervisor_attachment_status(*agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
                || attached.stale.load(Ordering::Acquire)
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
        }
        let audit = if system_only {
            host.audit_system_authority_projection(
                head,
                projected,
                root.ok_or(SharedAgentHostError::ScopeMismatch)?,
            )?
        } else {
            host.audit_authority_projection(head, projected, root)?
        };
        if leased_agents.iter().any(|agent| {
            self.generations
                .get(agent)
                .is_none_or(|attached| attached.stale.load(Ordering::Acquire))
        }) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        drop(host);
        drop(leases);
        Ok(audit)
    }

    /// Resolve physical invocation material while holding the same
    /// generation lifecycle lease used by clean route dispatch. The catalog
    /// read and status/fingerprint checks therefore cannot be detached from
    /// the route owner which the supervisor published.
    pub(crate) fn supervisor_invocation_material(
        &self,
        agent: vos_agent_sdk::AgentId,
        actor: vos_agent_sdk::ActorId,
    ) -> Result<
        crate::agent::invocation_preparation::PhysicalInvocationMaterial,
        SharedAgentHostError,
    > {
        let agent = crate::service::AgentId(agent.0);
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        let live = attached
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        let status = host
            .supervisor_attachment_status(agent)?
            .ok_or(SharedAgentHostError::AgentNotFound)?;
        if status.transport != SharedAgentTransportState::Attached
            || AttachmentFingerprint::from_attachment_status(&status)? != attached.fingerprint
        {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let material = host.supervisor_invocation_material(agent, actor)?;
        let projection = SharedAgentRuntimeProjection {
            descriptor: material.descriptor.clone(),
            actors: vec![material.actor.clone()],
        };
        if !projection_matches_attachment_status(&projection, &status) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        Ok(material)
    }

    /// Invoke one exact clean SDK work item through this attachment's owning
    /// generation. Ordered calls use the authenticated Raft proposer; Merge
    /// and Local calls remain on their profile-defined physical lanes.
    pub(crate) fn supervisor_invoke(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_invoke_terminal(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            true,
            SupervisorAdmission::Ordinary,
        )
    }

    /// Only the lifecycle owner may submit an already durable management
    /// envelope here. Remote ingress continues to use ordinary admission.
    pub(crate) fn supervisor_invoke_persisted_management(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        if !matches!(
            work.mode,
            crate::agent_sdk::MethodMode::Linear | crate::agent_sdk::MethodMode::Query
        ) || !matches!(&authorization, InvocationAuthorization::PublicPreflight(preflight) if preflight.matches_work(&work))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            true,
            SupervisorAdmission::PersistedManagement(anchor),
        )
    }

    pub(crate) fn supervisor_invoke_terminal_reserved(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            true,
            SupervisorAdmission::ReservedProjection,
        )
    }

    pub(crate) fn supervisor_resume(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Resume {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work,
                authorization,
                yielded,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_acknowledge(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work,
                authorization,
            },
            false,
            SupervisorAdmission::Ordinary,
        )
    }

    pub(crate) fn supervisor_acknowledge_management_retirement(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work,
                authorization,
            },
            false,
            SupervisorAdmission::ReservedManagementRetirement,
        )
    }

    pub(crate) fn supervisor_acknowledge_management_denial(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::VerifiedManagementDenial,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_admin_result(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::admin_dispatch::terminal::RetainedAdminResult,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_genesis_committee(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::RetainedGenesisCommitteeReply,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_genesis_recovery_read(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::PendingAuthorityProjection,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof
            .management_envelope()
            .ok_or(SharedAgentHostError::ScopeMismatch)?;
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    pub(crate) fn supervisor_acknowledge_genesis_publication(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        proof: &crate::agent::clean_bootstrap::RetainedGenesisPublicationReply,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let (anchor, envelope) = proof.envelope();
        self.acknowledge_pending_management_result(expected, anchor, envelope)
    }

    fn acknowledge_pending_management_result(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        anchor: &crate::agent::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedAgentHostError::ScopeMismatch);
        };
        self.ensure_management_pending_member(
            crate::service::AgentId(invocation.agent.0),
            anchor,
            envelope,
        )?;
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
            },
            false,
            SupervisorAdmission::ReservedManagementResult,
        )
    }

    pub(crate) fn supervisor_acknowledge_reserved(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        work: InvocationWork,
        authorization: InvocationAuthorization,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        self.supervisor_invocation_operation(
            expected,
            crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge {
                work,
                authorization,
            },
            false,
            SupervisorAdmission::ReservedProjection,
        )
    }

    fn supervisor_invocation_operation(
        &self,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        admission: SupervisorAdmission<'_>,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let agent = crate::service::AgentId(request.work().agent.0);
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        Self::execute_generation(
            SharedGenerationAccess {
                coordinator: &attached.coordinator,
                fingerprint: &attached.fingerprint,
                stale: &attached.stale,
            },
            expected,
            request,
            terminal_only,
            admission,
        )
    }

    fn execute_generation(
        attached: SharedGenerationAccess<'_>,
        expected: crate::agent::supervisor::AgentRouteIdentity,
        request: crate::agent::shared_journal_driver::CleanInvocationReplayRequest,
        terminal_only: bool,
        admission: SupervisorAdmission<'_>,
    ) -> Result<RuntimeOutcome, SharedAgentHostError> {
        let work = request.work();
        if matches!(
            admission,
            SupervisorAdmission::ReservedManagementRetirement
                | SupervisorAdmission::ReservedManagementResult
        ) && (!(work.mode == MethodMode::Linear
            || (work.mode == MethodMode::Query
                && matches!(admission, SupervisorAdmission::ReservedManagementResult)))
            || !matches!(
                &request,
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Acknowledge { .. }
            ))
        {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let authorization = request.authorization();
        let agent = crate::service::AgentId(work.agent.0);
        if agent != attached.coordinator.agent {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        // Keep the same lifecycle -> host order as the network route handler.
        // `retire` releases its host guard before requesting the write lease.
        let live = attached
            .coordinator
            .lifecycle
            .read()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        if !*live || attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        {
            let host = attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?;
            let status = host
                .supervisor_attachment_status(agent)?
                .ok_or(SharedAgentHostError::AgentNotFound)?;
            if status.transport != SharedAgentTransportState::Attached
                || AttachmentFingerprint::from_attachment_status(&status)? != *attached.fingerprint
            {
                return Err(SharedAgentHostError::TransportNotAttached);
            }
            let material = host.supervisor_invocation_material(agent, work.actor)?;
            if !crate::agent::supervisor_adapters::physical_material_authorizes_work(
                &material,
                expected,
                RuntimeExecutionContext::Direct,
                work,
                authorization,
            ) {
                return Err(SharedAgentHostError::InvalidProvision);
            }
            let projection = SharedAgentRuntimeProjection {
                descriptor: material.descriptor,
                actors: vec![material.actor],
            };
            if !projection_matches_attachment_status(&projection, &status)
                || !work_matches_projection(work, authorization, &projection)
                || projection.descriptor.identity.space != expected.key().space()
                || projection.descriptor.identity.agent != expected.key().agent()
                || projection.descriptor.identity.profile != expected.profile()
                || projection.descriptor.identity.runtime_deployment
                    != expected.runtime_deployment()
                || projection.actors.len() != 1
                || projection.actors[0].entry.actor != expected.key().actor()
                || projection.actors[0].incarnation != expected.incarnation()
                || projection.actors[0].entry.deployment != expected.actor_deployment()
                || projection.actors[0].entry.program != expected.actor_program()
            {
                return Err(SharedAgentHostError::ScopeMismatch);
            }
        }
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let scope = work.mode.invocation_scope();
        let _nonordered_admission =
            if matches!(scope, InvocationScope::Merge | InvocationScope::Local) {
                let proposal = attached
                    .coordinator
                    .proposal
                    .lock()
                    .map_err(|_| SharedAgentHostError::Unavailable)?;
                if proposal.is_reserved() {
                    return Err(SharedAgentHostError::CapacityExhausted);
                }
                Some(proposal)
            } else {
                None
            };
        match scope {
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedManagementResult) =>
            {
                let key = ProjectionPairKey::new(request.work(), request.authorization());
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        false,
                        Some(ReservedSubmission::ManagementResult(key)),
                        InvocationClock::Current,
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedManagementRetirement) =>
            {
                let key = ProjectionPairKey::new(request.work(), request.authorization());
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        false,
                        Some(ReservedSubmission::ManagementRetirement(key)),
                        InvocationClock::Current,
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::PersistedManagement(_)) =>
            {
                let SupervisorAdmission::PersistedManagement(anchor) = admission else {
                    unreachable!()
                };
                attached
                    .coordinator
                    .submit_clean_ordered_operation_with_admission(
                        request,
                        true,
                        None,
                        InvocationClock::PersistedManagement(anchor),
                    )
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered
                if matches!(admission, SupervisorAdmission::ReservedProjection) =>
            {
                attached
                    .coordinator
                    .submit_reserved_clean_ordered_operation(request, terminal_only)
                    .map(|submission| submission.outcome)
            }
            InvocationScope::Ordered if terminal_only => attached
                .coordinator
                .submit_terminal_clean_ordered_operation(request)
                .map(|submission| submission.outcome),
            InvocationScope::Ordered => attached
                .coordinator
                .submit_clean_ordered_operation(request)
                .map(|submission| submission.outcome),
            InvocationScope::Merge => attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_merge_operation(agent, request),
            InvocationScope::Local => attached
                .coordinator
                .host
                .lock()
                .map_err(|_| SharedAgentHostError::Unavailable)?
                .apply_clean_local_operation(agent, request),
        }
    }

    /// Internal root bootstrap only; ordinary routed calls retain their exact
    /// caller-supplied authorization and use the supervisor execution path.
    pub(crate) fn invoke_bootstrap(
        &self,
        agent: crate::service::AgentId,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<CleanOrderedSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .submit_clean_ordered_operation_with_admission(
                crate::agent::shared_journal_driver::CleanInvocationReplayRequest::Invoke {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    work,
                    authorization,
                },
                false,
                None,
                InvocationClock::Bootstrap,
            )
    }

    /// Observe startup readiness without waiting for election. This does wait
    /// for the worker snapshot and committed-state drain, but grants no command
    /// publication permission on its own.
    /// Submission still rechecks leadership and all ordinary admission guards.
    pub(crate) fn bootstrap_is_local_leader(
        &self,
        agent: crate::service::AgentId,
    ) -> Result<bool, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        let worker = attached
            .coordinator
            .worker
            .as_ref()
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        #[cfg(test)]
        tracing::debug!(snapshot = ?worker.cached_snapshot(), "pending system bootstrap election observation");
        if worker.role() != vos_raft::Role::Leader {
            return Ok(false);
        }
        let snapshot = futures_executor::block_on(worker.snapshot())
            .ok_or(SharedAgentHostError::Unavailable)?;
        if snapshot.role != vos_raft::Role::Leader
            || snapshot.commit_index != snapshot.last_log_index
        {
            return Ok(false);
        }
        let mut host = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?;
        drain_committed(&mut host, agent, &attached.coordinator.ordered_replies)?;
        if host.capacity(agent)?.0 != snapshot.commit_index {
            return Err(SharedAgentHostError::CorruptResidue);
        }
        Ok(true)
    }

    /// Submit an exact clean management request, including any deterministic
    /// artifact chunk prefix, through the live Raft worker.
    pub(crate) fn manage_clean(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: crate::agent::driver::SdkManagementArtifacts<'_>,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached
            .coordinator
            .submit_clean_management(request, authority, artifacts, &[])
    }

    /// Submit a Shared `ChangeReplicas` whose roster may name nodes outside
    /// the active committee. Each such node must be given as its canonical
    /// Ed25519 PeerId; the authority-signed request binds the node, which is
    /// the digest of that PeerId. Returns `CommitteeTransition` for the
    /// committee leg and `Applied` once the descriptor adopted the roster.
    #[allow(dead_code)] // Entry point for the operator replica-change command; no ingress yet.
    pub(crate) fn manage_clean_with_replicas(
        &self,
        agent: crate::service::AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        joining: &[Vec<u8>],
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        let attached = self
            .generations
            .get(&agent)
            .ok_or(SharedAgentHostError::TransportNotAttached)?;
        if attached.stale.load(Ordering::Acquire) {
            return Err(SharedAgentHostError::TransportNotAttached);
        }
        attached.coordinator.submit_clean_management(
            request,
            authority,
            crate::agent::driver::SdkManagementArtifacts::None,
            joining,
        )
    }

    /// Drive one authorized `ChangeReplicas` on this replica to completion:
    /// the committee leg, then the descriptor leg through the ordinary
    /// ordered path. Each attempt refreshes the attachment first, so the
    /// stable leg's worker restart is observed. The whole call is bounded by
    /// `deadline`; only this replica's own leadership can make progress.
    #[allow(dead_code)] // Entry point for the operator replica-change command; no ingress yet.
    pub(crate) fn change_replicas(
        &mut self,
        agent: crate::service::AgentId,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        joining: &[Vec<u8>],
        deadline: Duration,
    ) -> Result<CleanManagementSubmission, SharedAgentHostError> {
        if !matches!(
            request,
            crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
        ) {
            return Err(SharedAgentHostError::ScopeMismatch);
        }
        let deadline = Instant::now() + deadline;
        loop {
            let result = self.refresh().and_then(|()| {
                self.manage_clean_with_replicas(agent, request.clone(), authority.clone(), joining)
            });
            match result {
                Ok(CleanManagementSubmission::CommitteeTransition { .. })
                | Err(
                    SharedAgentHostError::Unavailable | SharedAgentHostError::TransportNotAttached,
                ) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => return result,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn attachment_for_test(
        &self,
        agent: crate::service::AgentId,
    ) -> Option<(Arc<dyn AgentRouteHandler>, bool)> {
        self.generations
            .get(&agent)
            .map(|attached| (Arc::clone(&attached.handler), attached.worker.is_some()))
    }

    #[cfg(test)]
    pub(crate) fn assert_merge_noop_gate_for_test(&self, agent: crate::service::AgentId) {
        let coordinator = &self.generations.get(&agent).unwrap().coordinator;
        let sender = self.network.agent_node_id();
        let proposal = coordinator.proposal.lock().unwrap();
        let host = self.host.lock().unwrap();
        let (send, receive) = std_mpsc::channel();
        let worker = Arc::clone(coordinator);
        let thread = std::thread::spawn(move || {
            let _ = send.send(worker.sync_merge_heads(sender, Vec::new()).is_ok());
        });
        let empty = receive.recv_timeout(Duration::from_secs(1));
        drop(host);
        drop(proposal);
        thread.join().unwrap();
        assert_eq!(empty, Ok(true), "empty Merge must not wait for either lock");

        let registration = crate::agent::shared_recovery::recovery_registration_for_test(1, 9);
        let mut proposal = coordinator.proposal.lock().unwrap();
        assert!(!proposal.is_reserved());
        proposal.projection_pair = Some(ProjectionPairKey::new(
            registration.work(),
            registration.authorization(),
        ));
        drop(proposal);
        let host = self.host.lock().unwrap();
        let (send, receive) = std_mpsc::channel();
        let worker = Arc::clone(coordinator);
        let thread = std::thread::spawn(move || {
            let _ = send.send(
                worker
                    .sync_merge_heads(sender, vec![Hash([1; 32])])
                    .is_err(),
            );
        });
        let nonempty = receive.recv_timeout(Duration::from_secs(1));
        drop(host);
        thread.join().unwrap();
        coordinator.proposal.lock().unwrap().projection_pair = None;
        assert_eq!(
            nonempty,
            Ok(true),
            "nonempty Merge must honor the reservation"
        );
    }

    #[cfg(test)]
    pub(crate) fn mark_stale_for_test(&self, agent: crate::service::AgentId) -> bool {
        self.generations.get(&agent).is_some_and(|attached| {
            attached.stale.store(true, Ordering::Release);
            true
        })
    }

    #[cfg(test)]
    pub(crate) fn retire_attachment_for_test(
        &mut self,
        agent: crate::service::AgentId,
    ) -> Result<(), SharedAgentHostError> {
        self.retire(agent)
    }

    fn retire(&mut self, agent: crate::service::AgentId) -> Result<(), SharedAgentHostError> {
        let Some(mut attached) = self.generations.remove(&agent) else {
            return Ok(());
        };
        // Stop admitting work before waiting on the host mutex. The existing
        // Attached lease already blocks snapshot/GC, and removing the route
        // bounds the set of callers which can still contend for this host.
        self.network
            .retire_agent_route(attached.fingerprint.protocol_route, &attached.handler);
        // Reserve the destructive storage boundary throughout ordered route
        // revocation and worker/thread shutdown. Snapshot replacement and GC
        // remain blocked until every cached database user is gone.
        let stop_result = self
            .host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)
            .and_then(|mut host| host.mark_transport_stopping(agent));
        attached.merge_stop.store(true, Ordering::Release);
        let mut live = attached
            .lifecycle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *live = false;
        drop(live);
        if let Some(worker) = attached.worker.take() {
            worker.shutdown();
        }
        if let Some(thread) = attached.apply_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = attached.merge_thread.take() {
            let _ = thread.join();
        }
        stop_result?;
        self.host
            .lock()
            .map_err(|_| SharedAgentHostError::Unavailable)?
            .release_transport_attachment(agent)
    }
}

impl Drop for SharedAgentNetworkHost {
    fn drop(&mut self) {
        let agents = self.generations.keys().copied().collect::<Vec<_>>();
        for agent in agents {
            let _ = self.retire(agent);
        }
    }
}

fn projection_matches_attachment_status(
    projection: &SharedAgentRuntimeProjection,
    status: &crate::agent::shared_host::SharedAgentAttachmentStatus,
) -> bool {
    let identity = &projection.descriptor.identity;
    projection.descriptor.validate().is_ok()
        && identity.profile == vos_agent_sdk::AgentProfile::Shared
        && status.identity.profile == crate::agent::AgentProfile::Shared
        && identity.space.0 == status.identity.space.0
        && identity.agent.0 == status.identity.agent.0
        && identity.owner.0 == status.identity.owner.0
        && identity.runtime_deployment.0 == status.identity.runtime_deployment.0
        && identity.runtime_program.0 == status.identity.runtime_program.0
        && identity.runtime_producer.0 == status.identity.runtime_producer.0
        && identity.transition_producer.0 == status.identity.transition_producer.0
        && status.generation.space().0 == identity.space.0
        && status.generation.agent().0 == identity.agent.0
}

fn work_matches_projection(
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    projection: &SharedAgentRuntimeProjection,
) -> bool {
    let identity = &projection.descriptor.identity;
    if !work.validate()
        || !authorization.matches_work(work)
        || identity.profile != vos_agent_sdk::AgentProfile::Shared
        || work.space != identity.space
        || work.agent != identity.agent
        || work.runtime_deployment != identity.runtime_deployment
    {
        return false;
    }
    projection
        .actors
        .binary_search_by_key(&work.actor, |record| record.entry.actor)
        .ok()
        .and_then(|position| projection.actors.get(position))
        .is_some_and(|record| {
            record.validate().is_ok()
                && !record.entry.suspended
                && record.incarnation == work.incarnation
                && record.entry.deployment == work.deployment
                && record.entry.program == work.program
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::raft::RAFT_LOG;

    #[test]
    fn overwritten_registration_restores_only_its_prior_reservation() {
        let registration = crate::agent::shared_recovery::recovery_registration_for_test(1, 9);
        let generation = registration.generation();
        let route = shared_raft::AgentRouteKey::new(
            generation.space(),
            generation.agent(),
            generation.genesis(),
            generation.admission(),
            registration.committee(),
        )
        .unwrap();
        let command = shared_raft::AgentRaftCommand::RegisterRecovery {
            route,
            registration: registration.clone(),
        };
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        for prior_pair in [None, Some(key)] {
            let pending = PendingRegistrationAppend {
                key,
                prior_pair,
                route,
                command: command.commitment(),
                index: 31,
                term: 2,
            };
            let mut row = crate::raft::LogEntry {
                index: pending.index,
                term: pending.term + 1,
                payload: shared_raft::encode_agent_raft_entry_kind(&EntryKind::Data {
                    payload: Vec::new(),
                })
                .unwrap(),
            };
            assert_eq!(pending.overwritten_by(&row), Ok(true));
            row.term = pending.term;
            assert_eq!(pending.overwritten_by(&row), Ok(false));
            row.term += 1;
            row.index += 1;
            assert_eq!(pending.overwritten_by(&row), Ok(false));
            row.index = pending.index;
            row.payload = shared_raft::encode_agent_raft_entry_kind(&EntryKind::Data {
                payload: command.encode(),
            })
            .unwrap();
            assert_eq!(pending.overwritten_by(&row), Ok(false));
            row.payload = vec![0xff];
            assert_eq!(
                pending.overwritten_by(&row),
                Err(SharedAgentHostError::CorruptResidue)
            );
            let mut proposal = ProposalAdmission {
                projection_pair: Some(key),
                registration_append: Some(pending),
                ..Default::default()
            };
            assert_eq!(
                proposal.finish_registration_reconciliation(pending, false, false),
                Err(SharedAgentHostError::Unavailable)
            );
            assert_eq!(proposal.projection_pair, Some(key));
            assert_eq!(proposal.registration_append, Some(pending));
            proposal
                .finish_registration_reconciliation(pending, false, true)
                .unwrap();
            assert_eq!(proposal.projection_pair, prior_pair);
            assert_eq!(proposal.registration_append, None);

            // Even an overwritten local append cannot release custody that
            // another voter has independently admitted for this exact work.
            proposal.projection_pair = Some(key);
            proposal.registration_append = Some(pending);
            proposal
                .finish_registration_reconciliation(pending, true, true)
                .unwrap();
            assert_eq!(proposal.projection_pair, Some(key));
            assert_eq!(proposal.registration_append, None);

            let other = crate::agent::shared_recovery::recovery_registration_for_test(2, 10);
            let other_key = ProjectionPairKey::new(other.work(), other.authorization());
            proposal.projection_pair = Some(other_key);
            proposal.registration_append = Some(pending);
            assert_eq!(
                proposal.finish_registration_reconciliation(pending, false, true),
                Err(SharedAgentHostError::Conflict)
            );
            assert_eq!(proposal.projection_pair, Some(other_key));
        }
    }

    #[test]
    fn projection_retries_require_a_quiescent_prefix_without_losing_their_key() {
        let registration = crate::agent::shared_recovery::recovery_registration_for_test(1, 9);
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        let mut proposal = ProposalAdmission::default();
        proposal.begin_recovery_registration(key).unwrap();
        for role in [vos_raft::Role::Leader, vos_raft::Role::Follower] {
            assert_eq!(
                quiescent_projection_commit(role, 11, 12, true),
                Err(SharedAgentHostError::Unavailable)
            );
            assert_eq!(proposal.projection_pair, Some(key));
            assert_eq!(quiescent_projection_commit(role, 12, 12, true), Ok(12));
        }
        for role in [
            vos_raft::Role::Follower,
            vos_raft::Role::Candidate,
            vos_raft::Role::PreCandidate,
        ] {
            assert_eq!(
                quiescent_projection_commit(role, 12, 12, false),
                Err(SharedAgentHostError::Unavailable)
            );
        }
        assert_eq!(
            quiescent_projection_commit(vos_raft::Role::Leader, 12, 12, false),
            Ok(12)
        );
        assert_eq!(proposal.projection_pair, Some(key));
    }

    #[test]
    fn projection_barrier_progress_is_retryable_but_stable_mismatch_is_corrupt() {
        let registration = crate::agent::shared_recovery::recovery_registration_for_test(1, 9);
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        let mut proposal = ProposalAdmission::default();
        proposal.begin_recovery_registration(key).unwrap();
        let before = ProjectionBarrier {
            role: vos_raft::Role::Follower,
            term: 2,
            committed: 30,
            last: 30,
        };
        for current in [
            ProjectionBarrier {
                committed: 33,
                last: 33,
                ..before
            },
            ProjectionBarrier { last: 31, ..before },
            ProjectionBarrier { term: 3, ..before },
            ProjectionBarrier {
                role: vos_raft::Role::Leader,
                ..before
            },
        ] {
            // Applied rows may already reflect the newer commit, or the
            // worker may have advanced after the drain returned Idle.
            for applied in [before.committed, current.committed] {
                assert_eq!(
                    before.validate_applied(current, applied),
                    Err(SharedAgentHostError::Unavailable)
                );
                assert_eq!(proposal.projection_pair, Some(key));
            }
        }
        for applied in [before.committed - 1, before.committed + 1] {
            assert_eq!(
                before.validate_applied(before, applied),
                Err(SharedAgentHostError::CorruptResidue)
            );
            assert_eq!(proposal.projection_pair, Some(key));
        }
        assert_eq!(before.validate_applied(before, before.committed), Ok(()));
        assert_eq!(proposal.projection_pair, Some(key));
    }

    #[test]
    fn recovery_custody_requires_exact_work_and_authorization() {
        let manifest = crate::agent::shared_recovery::completed_recovery_manifest_for_test();
        let registration = manifest.slots()[0].registration();
        let work = registration.work();
        let authorization = registration.authorization();
        assert!(has_projection_recovery_custody(
            &manifest,
            work,
            authorization
        ));
        let empty =
            SharedRecoveryManifest::new(manifest.generation(), manifest.committee().clone())
                .unwrap();
        assert!(!has_projection_recovery_custody(
            &empty,
            work,
            authorization
        ));
        let mut changed = work.clone();
        changed.gas -= 1;
        assert!(!has_projection_recovery_custody(
            &manifest,
            &changed,
            authorization
        ));
        let InvocationAuthorization::PublicPreflight(preflight) = authorization else {
            unreachable!()
        };
        let changed = InvocationAuthorization::PublicPreflight(
            crate::agent_sdk::PublicPreflight::for_work(work, preflight.observed_slot + 1),
        );
        assert!(!has_projection_recovery_custody(&manifest, work, &changed));
    }

    #[test]
    fn appended_unconfirmed_recovery_registration_retains_exact_exclusion() {
        let registration = crate::agent::shared_recovery::recovery_registration_for_test(1, 9);
        let different = crate::agent::shared_recovery::recovery_registration_for_test(2, 10);
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        let other = ProjectionPairKey::new(different.work(), different.authorization());
        let common = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let empty = SharedRecoveryManifest::new(
            registration.generation(),
            common.active_committee().clone(),
        )
        .unwrap();
        let mut proposal = ProposalAdmission::default();
        assert_eq!(proposal.begin_recovery_registration(key).unwrap(), None);
        // An append return or timeout supplies no authenticated application
        // evidence. Reconciliation against the unchanged manifest cannot
        // release the held pair or admit a different projection/checkpoint.
        proposal.reconcile_completed_dependency(other, &empty);
        assert_eq!(proposal.projection_pair, Some(key));
        assert_eq!(
            proposal.begin_recovery_registration(other),
            Err(SharedAgentHostError::Conflict)
        );
        assert!(!proposal.reserve_idle_checkpoint(other));
        assert_eq!(
            proposal.begin_recovery_registration(key).unwrap(),
            Some(key)
        );
    }

    #[test]
    fn completed_dependency_reconciles_after_leadership_loss_without_releasing_intent() {
        let completed = crate::agent::shared_recovery::completed_recovery_manifest_for_test();
        let registration = completed.slots()[0].registration();
        let key = ProjectionPairKey::new(registration.work(), registration.authorization());
        let intent = crate::agent::shared_recovery::recovery_registration_for_test(2, 10);
        let intent_key = ProjectionPairKey::new(intent.work(), intent.authorization());
        let mut unfinished =
            SharedRecoveryManifest::new(completed.generation(), completed.committee().clone())
                .unwrap();
        unfinished.apply_registration(registration, 1, 1).unwrap();
        let mut proposal = ProposalAdmission {
            projection_pair: Some(key),
            ..Default::default()
        };
        proposal.reconcile_completed_dependency(intent_key, &unfinished);
        assert_eq!(proposal.projection_pair, Some(key));
        // This policy has no local-role dependency: the live caller executes
        // it under a valid follower lease too, after draining exact ACK state.
        proposal.reconcile_completed_dependency(intent_key, &completed);
        assert_eq!(proposal.projection_pair, None);
        proposal.begin_recovery_registration(intent_key).unwrap();
        proposal.reconcile_completed_dependency(intent_key, &completed);
        assert_eq!(proposal.projection_pair, Some(intent_key));
        let foreign = ProjectionPairKey {
            invocation: crate::agent_sdk::InvocationId([99; 32]),
            ..key
        };
        proposal.projection_pair = Some(foreign);
        proposal.reconcile_completed_dependency(intent_key, &completed);
        assert_eq!(proposal.projection_pair, Some(foreign));
    }

    #[test]
    fn applied_availability_counts_only_distinct_admitted_voters() {
        let voters = [NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32])];
        let observer = NodeId([4; 32]);
        let mut available = BTreeSet::new();
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[0]);
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[0]);
        available.insert(observer);
        assert!(!has_applied_availability_quorum(&voters, &available));
        available.insert(voters[2]);
        assert!(has_applied_availability_quorum(&voters, &available));
        assert!(has_applied_availability_quorum(&voters[..1], &available));
        assert!(!has_applied_availability_quorum(&[], &available));
        assert!(!has_applied_availability_quorum(&voters[..2], &available));
        assert!(!has_applied_availability_quorum(
            &[voters[0]; 3],
            &available
        ));
        assert!(!has_applied_availability_quorum(
            &[NodeId::ZERO],
            &available
        ));
    }

    #[test]
    fn opportunistic_projection_checkpoint_threshold_and_gate() {
        let maximum = shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES as u64;
        assert!(!projection_checkpoint_due(maximum, 1));
        assert!(!projection_checkpoint_due(maximum - 7, 1));
        assert!(projection_checkpoint_due(maximum - 8, 1));
        assert!(projection_checkpoint_due(0, 1));
        for members in [0, 2, 3] {
            assert!(!projection_checkpoint_due(maximum - 8, members));
            assert!(!projection_checkpoint_due(0, members));
        }
        let key = ProjectionPairKey {
            invocation: crate::agent_sdk::InvocationId([1; 32]),
            work: Hash([2; 32]),
            authorization: Hash([3; 32]),
        };
        let mut idle = ProposalAdmission::default();
        assert!(idle.reserve_idle_checkpoint(key));
        assert_eq!(idle.projection_pair, Some(key));
        assert!(!idle.reserve_idle_checkpoint(key));
        for mut busy in [
            ProposalAdmission {
                projection_pair: Some(key),
                ..Default::default()
            },
            ProposalAdmission {
                management_pending: Some(Vec::new()),
                ..Default::default()
            },
            ProposalAdmission {
                management_retirement: Some(Vec::new()),
                ..Default::default()
            },
        ] {
            let before = (
                busy.projection_pair,
                busy.management_pending.is_some(),
                busy.management_retirement.is_some(),
            );
            assert!(!busy.reserve_idle_checkpoint(key));
            assert_eq!(
                before,
                (
                    busy.projection_pair,
                    busy.management_pending.is_some(),
                    busy.management_retirement.is_some()
                )
            );
        }
    }

    struct TempDatabase(std::path::PathBuf);

    impl TempDatabase {
        fn new(label: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "vos_clean_agent_network_{label}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            )))
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn colliding_node(discriminator: u8) -> NodeId {
        let mut bytes = [0; 32];
        bytes[..2].copy_from_slice(&[0xa5, 0x5a]);
        bytes[31] = discriminator;
        NodeId(bytes)
    }

    fn initialize_database(path: &std::path::Path) -> Arc<Database> {
        let database = Arc::new(Database::create(path).unwrap());
        let transaction = database.begin_write().unwrap();
        {
            let _ = transaction.open_table(RAFT_META).unwrap();
            let _ = transaction.open_table(RAFT_LOG).unwrap();
        }
        transaction.commit().unwrap();
        database
    }

    #[test]
    fn promotion_deadline_consults_serialized_state_and_requires_full_commit() {
        let snapshot = |role, committed| (role, committed, 1);
        // The atomic hint can still expose Candidate while an in-flight
        // worker event finishes promotion. Only the serialized reply is final.
        let result = system_promotion_barrier(
            || vos_raft::Role::Candidate,
            || Some(snapshot(vos_raft::Role::Leader, 1)),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result, 1);
        for (role, committed) in [
            (vos_raft::Role::Candidate, 1),
            (vos_raft::Role::Follower, 1),
            (vos_raft::Role::Leader, 0),
        ] {
            assert!(matches!(
                system_promotion_barrier(
                    || vos_raft::Role::Candidate,
                    || Some(snapshot(role, committed)),
                    Duration::ZERO,
                ),
                Err(SharedAgentHostError::Unavailable)
            ));
        }
        assert!(matches!(
            system_promotion_barrier(|| vos_raft::Role::Leader, || None, Duration::ZERO),
            Err(SharedAgentHostError::Unavailable)
        ));
    }

    #[test]
    fn already_staged_merge_object_does_not_reenter_physical_storage() {
        assert!(!merge_object_needs_staging(&SharedMergeObject::Staged(
            vec![0x41]
        )));
        assert!(!merge_object_needs_staging(&SharedMergeObject::Published(
            vec![0x42]
        )));
        assert!(merge_object_needs_staging(&SharedMergeObject::Missing));
    }

    #[test]
    fn full_node_storage_keeps_colliding_votes_and_configuration_across_restart() {
        let path = TempDatabase::new("full_node_restart");
        let database = initialize_database(&path.0);
        let first = colliding_node(1);
        let second = colliding_node(2);
        assert_eq!(&first.as_bytes()[..2], &second.as_bytes()[..2]);
        assert_ne!(first, second);
        let mut members = vec![second, first];
        members.sort_unstable();

        let mut storage = AgentNodeStorage::open(Arc::clone(&database), (0, 0)).unwrap();
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 1,
                term: 1,
                kind: EntryKind::Data {
                    payload: vec![0x11],
                },
            }],
            meta: Some(Meta {
                current_term: 1,
                voted_for: Some(first),
                commit_index: 1,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            active_config: Some(ActiveConfigRecord {
                log_index: Some(1),
                current: members.clone(),
                joint_old: None,
            }),
            ..WriteBatch::default()
        }))
        .unwrap();

        // Simulate the journal application transaction advancing its cursor
        // between two independent worker commits.
        let transaction = database.begin_write().unwrap();
        let mut host_meta = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        host_meta.last_applied = 1;
        host_meta.write_host_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();

        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 2,
                term: 2,
                kind: EntryKind::Data {
                    payload: vec![0x22],
                },
            }],
            meta: Some(Meta {
                current_term: 2,
                voted_for: Some(second),
                commit_index: 2,
                snap_last_index: 0,
                snap_last_term: 0,
            }),
            active_config: Some(ActiveConfigRecord {
                log_index: Some(2),
                current: members.clone(),
                joint_old: Some(vec![first]),
            }),
            ..WriteBatch::default()
        }))
        .unwrap();
        drop(storage);

        let mut reopened = AgentNodeStorage::open(Arc::clone(&database), (0, 0)).unwrap();
        let meta = futures_executor::block_on(reopened.load_meta()).unwrap();
        assert_eq!(meta.current_term, 2);
        assert_eq!(meta.voted_for, Some(second));
        assert_eq!(meta.commit_index, 2);
        assert_eq!(
            futures_executor::block_on(reopened.applied_index()).unwrap(),
            Some(1)
        );
        assert_eq!(
            futures_executor::block_on(reopened.active_config()).unwrap(),
            Some(ActiveConfigRecord {
                log_index: Some(2),
                current: members,
                joint_old: Some(vec![first]),
            })
        );
        assert!(
            futures_executor::block_on(reopened.commit_batch(WriteBatch {
                state: Some(vec![1]),
                ..WriteBatch::default()
            }))
            .is_err()
        );
        drop(reopened);

        // A legacy compact vote row makes the clean storage refuse reopen;
        // it is never interpreted as either colliding full identity.
        let transaction = database.begin_write().unwrap();
        let mut legacy = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        legacy.voted_for = Some(0x5aa5);
        legacy.write_worker_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();
        assert!(AgentNodeStorage::open(database, (0, 0)).is_err());

        let legacy_config_path = TempDatabase::new("legacy_config");
        let legacy_config_database = initialize_database(&legacy_config_path.0);
        let transaction = legacy_config_database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(RAFT_META).unwrap();
            table
                .insert(META_LEGACY_ACTIVE_CONFIG, b"compact".as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        assert!(AgentNodeStorage::open(legacy_config_database, (0, 0)).is_err());
    }

    #[test]
    fn full_node_storage_accepts_only_the_authenticated_snapshot_boundary() {
        let path = TempDatabase::new("authenticated_snapshot_restart");
        let database = initialize_database(&path.0);
        let transaction = database.begin_write().unwrap();
        let mut meta = RaftMeta::load_from_write_transaction(&transaction).unwrap();
        meta.current_term = 3;
        meta.commit_index = 7;
        meta.last_applied = 7;
        meta.snap_last_index = 7;
        meta.snap_last_term = 2;
        meta.write_worker_fields_in_txn(&transaction).unwrap();
        meta.write_host_fields_in_txn(&transaction).unwrap();
        transaction.commit().unwrap();

        assert!(AgentNodeStorage::open(Arc::clone(&database), (0, 0)).is_err());
        assert!(AgentNodeStorage::open(Arc::clone(&database), (7, 3)).is_err());
        let mut storage = AgentNodeStorage::open(Arc::clone(&database), (7, 2)).unwrap();
        let recovered = futures_executor::block_on(storage.load_meta()).unwrap();
        assert_eq!(recovered.snap_last_index, 7);
        assert_eq!(recovered.snap_last_term, 2);
        assert_eq!(storage.last_index(), 7);
        assert_eq!(storage.last_term(), 2);

        assert!(
            futures_executor::block_on(storage.commit_batch(WriteBatch {
                meta: Some(Meta {
                    current_term: 3,
                    voted_for: None,
                    commit_index: 7,
                    snap_last_index: 0,
                    snap_last_term: 0,
                }),
                ..WriteBatch::default()
            }))
            .is_err()
        );
        futures_executor::block_on(storage.commit_batch(WriteBatch {
            appends: vec![LogEntry {
                index: 8,
                term: 3,
                kind: EntryKind::Data {
                    payload: vec![0x41],
                },
            }],
            meta: Some(Meta {
                current_term: 3,
                voted_for: None,
                commit_index: 8,
                snap_last_index: 7,
                snap_last_term: 2,
            }),
            ..WriteBatch::default()
        }))
        .unwrap();
        drop(storage);

        let reopened = AgentNodeStorage::open(database, (7, 2)).unwrap();
        let meta = futures_executor::block_on(reopened.load_meta()).unwrap();
        assert_eq!((meta.snap_last_index, meta.snap_last_term), (7, 2));
        assert_eq!(meta.commit_index, 8);
        assert_eq!(reopened.last_index(), 8);
    }

    #[test]
    fn ordered_reply_waiters_are_exactly_keyed_under_concurrent_delivery() {
        let waiters = Arc::new(OrderedReplyWaiters::default());
        let first = ReplayInputId([1; 32]);
        let second = ReplayInputId([2; 32]);
        waiters.register(first).unwrap();
        waiters.register(second).unwrap();
        assert_eq!(waiters.register(first), Err(AgentHandlerError));

        let barrier = Arc::new(Barrier::new(3));
        let spawn_waiter = |input| {
            let waiters = Arc::clone(&waiters);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                waiters.wait(input)
            })
        };
        let first_waiter = spawn_waiter(first);
        let second_waiter = spawn_waiter(second);
        barrier.wait();

        let first_outcome =
            RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::NotFound));
        let second_outcome =
            RuntimeOutcome::Completed(Err(vos_agent_sdk::InvocationError::StaleDeployment));
        {
            let mut replies = waiters.replies.lock().unwrap();
            // Deliberately publish in reverse order: neither caller may
            // consume or overwrite the other invocation's outcome.
            replies.insert(second, OrderedReplyState::Ready(second_outcome.clone()));
            replies.insert(first, OrderedReplyState::Ready(first_outcome.clone()));
        }
        waiters.changed.notify_all();
        assert_eq!(first_waiter.join().unwrap(), Ok(first_outcome));
        assert_eq!(second_waiter.join().unwrap(), Ok(second_outcome));
        assert!(waiters.replies.lock().unwrap().is_empty());
    }

    #[test]
    fn rejected_stale_activation_releases_its_read_lease_before_retirement() {
        let lifecycle = RwLock::new(true);
        let stale = AtomicBool::new(true);
        assert!(acquire_route_activation(&lifecycle, &stale).is_none());
        assert!(
            lifecycle.try_write().is_ok(),
            "stale activation cleanup must be able to acquire the exclusive retirement lease"
        );

        stale.store(false, Ordering::Release);
        *lifecycle.write().unwrap() = false;
        assert!(acquire_route_activation(&lifecycle, &stale).is_none());
        assert!(lifecycle.try_write().is_ok());
    }

    #[test]
    fn fixed_three_reattachment_defers_only_implicit_system_promotion() {
        let claim = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let members = claim
            .active_committee()
            .members()
            .iter()
            .map(|member| {
                (
                    NodeId(member.replica().node.0),
                    PeerId::from_bytes(member.peer_id()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let voters = members.iter().map(|(node, _)| *node).collect();
        let base = AttachmentFingerprint {
            protocol_route: AgentGenerationRoute {
                space: vos_agent_sdk::SpaceId(claim.ordered().space().0),
                agent: vos_agent_sdk::AgentId(claim.ordered().agent().0),
                generation: Hash([3; 32]),
            },
            durable_route: shared_raft::AgentRouteKey::new(
                claim.ordered().space(),
                claim.ordered().agent(),
                claim.ordered().genesis(),
                claim.ordered().admission(),
                claim.ordered().committee(),
            )
            .unwrap(),
            members,
            voters,
            next_committee: None,
            next_voters: None,
            joint_old: None,
            local_role: ReplicaRole::Voter,
        };
        assert!(!base.requires_promotion_barrier(false, true, false, false, false));
        for required in 0..4 {
            assert!(base.requires_promotion_barrier(
                required == 0,
                true,
                required == 1,
                required == 2,
                required == 3,
            ));
        }
        for invalid in 0..6 {
            let mut changed = base.clone();
            match invalid {
                0 => {
                    changed.members.truncate(1);
                    changed.voters.truncate(1);
                }
                1 => changed.joint_old = Some(changed.voters.clone()),
                2 => changed.next_committee = Some(claim.active_committee().id()),
                3 => changed.next_voters = Some(changed.voters.clone()),
                4 => changed.local_role = ReplicaRole::Observer,
                5 => {
                    changed.voters.pop();
                }
                _ => unreachable!(),
            }
            assert!(
                changed.requires_promotion_barrier(false, true, false, false, false),
                "shape {invalid}"
            );
            assert!(!changed.requires_promotion_barrier(false, false, false, false, false));
        }
    }

    #[test]
    fn attachment_fingerprint_distinguishes_role_membership_and_joint_config() {
        let local_peer = libp2p::identity::Keypair::ed25519_from_bytes([31; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let local = NodeId::of_authenticated_peer(&local_peer.to_bytes());
        let other_peer = libp2p::identity::Keypair::ed25519_from_bytes([32; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let other = NodeId::of_authenticated_peer(&other_peer.to_bytes());
        let mut members = vec![(local, local_peer), (other, other_peer)];
        members.sort_unstable_by_key(|(node, _)| *node);
        let mut voters = vec![local, other];
        voters.sort_unstable();
        let fingerprint = AttachmentFingerprint {
            protocol_route: AgentGenerationRoute {
                space: vos_agent_sdk::SpaceId([1; 32]),
                agent: vos_agent_sdk::AgentId([2; 32]),
                generation: Hash([3; 32]),
            },
            durable_route: shared_raft::AgentRouteKey::new(
                crate::service::SpaceId([1; 32]),
                crate::service::AgentId([2; 32]),
                crate::agent::journal::AgentJournalGenesisId([4; 32]),
                crate::agent::genesis::AgentGenesisAdmissionId::from_bytes([5; 32]),
                crate::agent::genesis::AgentReplicaCommitteeId::from_bytes([6; 32]),
            )
            .unwrap(),
            members,
            next_committee: None,
            next_voters: None,
            voters,
            joint_old: None,
            local_role: ReplicaRole::Voter,
        };
        assert!(fingerprint.validates_local(local));
        assert!(fingerprint.owns_raft_worker(local));

        let mut changed = fingerprint.clone();
        changed.joint_old = Some(vec![local]);
        assert_ne!(changed, fingerprint);
        let mut changed = fingerprint.clone();
        changed.next_committee = Some(crate::agent::genesis::AgentReplicaCommitteeId::from_bytes(
            [7; 32],
        ));
        assert_ne!(changed, fingerprint);
        assert!(!changed.validates_local(local));
        let mut changed = fingerprint.clone();
        changed.local_role = ReplicaRole::Observer;
        assert_ne!(changed, fingerprint);
        assert!(!changed.validates_local(local));
        assert!(changed.owns_raft_worker(local));
        changed.voters.retain(|node| *node != local);
        assert!(changed.validates_local(local));
        assert!(!changed.owns_raft_worker(local));

        let mut promoted = changed;
        promoted.next_committee = Some(crate::agent::genesis::AgentReplicaCommitteeId::from_bytes(
            [8; 32],
        ));
        promoted.next_voters = Some(vec![local]);
        assert!(promoted.validates_local(local));
        assert!(
            promoted.owns_raft_worker(local),
            "a promoted observer must receive the joint entry as a follower"
        );
    }
}
